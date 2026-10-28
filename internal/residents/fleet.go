package residents

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/miki-przygoda/veil/internal/docker"
	"github.com/miki-przygoda/veil/internal/events"
	"github.com/miki-przygoda/veil/internal/sandbox"
)

// fleetEngine is the small Docker surface Fleet needs. *docker.Client satisfies it
// via dockerFleetAdapter; a fake backs the tests (mirrors sandbox.engine).
type fleetEngine interface {
	create(ctx context.Context, spec docker.CreateSpec) (string, error)
	start(ctx context.Context, id string) error
	remove(ctx context.Context, id string, force bool) error
}

type dockerFleetAdapter struct{ c *docker.Client }

func (a dockerFleetAdapter) create(ctx context.Context, spec docker.CreateSpec) (string, error) {
	return a.c.CreateContainer(ctx, spec)
}
func (a dockerFleetAdapter) start(ctx context.Context, id string) error {
	return a.c.StartContainer(ctx, id)
}
func (a dockerFleetAdapter) remove(ctx context.Context, id string, force bool) error {
	return a.c.RemoveContainer(ctx, id, force)
}

// Fleet spawns and tears down the resident containers on veil-net.
type Fleet struct {
	eng     fleetEngine
	image   string
	gateway string
	subnet  *net.IPNet
	hosts   []Host
	ids     []string          // spawned container ids, for Down
	ipOf    map[string]net.IP // static IP per spawned Trusted id (others are absent)
}

// NewFleet builds a Fleet backed by the shared docker.Client.
func NewFleet(cli *docker.Client, image, subnet, gateway string, hosts []Host) *Fleet {
	return newFleetWithEngine(dockerFleetAdapter{c: cli}, image, subnet, gateway, hosts)
}

// newFleetWithEngine injects the engine (a fake in tests).
func newFleetWithEngine(eng fleetEngine, image, subnet, gateway string, hosts []Host) *Fleet {
	_, ipnet, _ := net.ParseCIDR(subnet)
	return &Fleet{eng: eng, image: image, gateway: gateway, subnet: ipnet, hosts: hosts}
}

// hostIP derives a host's static IP as the subnet base + offset. Returns nil if
// the subnet is unknown or the result falls outside it.
func (f *Fleet) hostIP(offset int) net.IP {
	if f.subnet == nil {
		return nil
	}
	base := f.subnet.IP.To4()
	if base == nil {
		return nil
	}
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, binary.BigEndian.Uint32(base)+uint32(offset))
	if !f.subnet.Contains(ip) {
		return nil
	}
	return ip
}

// needsIP reports whether a host must have a static IP: anything other hosts (or
// the resolver) target by name — a declared server, or any host that serves.
func needsIP(h Host) bool { return h.IsServer || h.Serve != "" }

// Validate derives every roster IP up front and errors if any server lacks a
// static IPv4 (a subnet too small for its offset, an IPv6-first network, or no
// subnet at all). A server on a dynamic IP would be unreachable at the address its
// name resolves to, so clients would fall through to the honeypot and raise false
// escapes; the fleet fails closed instead (Up starts nothing, WorldNames is empty)
// and the caller falls back to Population. Clients may still go dynamic.
func (f *Fleet) Validate() error {
	var missing []string
	for _, h := range f.hosts {
		if needsIP(h) && f.hostIP(h.Offset) == nil {
			missing = append(missing, fmt.Sprintf("%s(+%d)", h.Name, h.Offset))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("no static IPv4 for server(s) %s in subnet %v", strings.Join(missing, ", "), f.subnet)
	}
	return nil
}

// PlannedTrustedIPs is the static address of every Trusted roster host, known
// before Up.
func (f *Fleet) PlannedTrustedIPs() []net.IP {
	var ips []net.IP
	for _, h := range f.hosts {
		if ip := f.hostIP(h.Offset); ip != nil && h.Trusted {
			ips = append(ips, ip)
		}
	}
	return ips
}

// TrustedIPs is the static address of every Trusted resident currently up, in
// roster order. A resident that failed to start is absent, so its address (which
// the box may hold) is never treated as a resident's; so is one on a dynamic IP.
func (f *Fleet) TrustedIPs() []net.IP {
	var ips []net.IP
	for _, id := range f.ids {
		if ip := f.ipOf[id]; ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

// WorldNames maps each server host's FQDN (lower-case, per the resolver's key
// contract) to its derived IP, for seeding the resolver's World.Names. Empty when
// Validate fails, so the resolver never holds a name the fleet won't stand up.
func (f *Fleet) WorldNames() map[string]net.IP {
	names := map[string]net.IP{}
	if f.Validate() != nil {
		return names
	}
	for _, h := range f.hosts {
		if !h.IsServer {
			continue
		}
		if ip := f.hostIP(h.Offset); ip != nil {
			names[strings.ToLower(h.Name)] = ip
		}
	}
	return names
}

// residentSpec builds a host's container spec: the box's hardening (HardenedSpec)
// plus the resident bits — image, role Cmd, veil-net + UDP-pinned world DNS, a
// static IP, and net.ipv4.ip_unprivileged_port_start=0 so the non-root resident
// can bind standard low ports (80, 22, 25...). That is a netns-scoped sysctl, so
// it widens nothing outside the resident's own namespace. No cap is added: under
// non-root + no-new-privileges an added cap never reaches the process anyway.
// Docker (>= 20.10) already sets this per netns by default; it is set explicitly
// here so low-port binding doesn't hinge on that default. The box's HardenedSpec
// does not get it.
func (f *Fleet) residentSpec(h Host) docker.CreateSpec {
	cfg := sandbox.Config{
		Image:   f.image,
		Network: "veil-net",
		DNS:     []string{f.gateway},
		Cmd:     residentCmd(h, f.gateway),
	}
	spec := cfg.HardenedSpec("resident-" + h.Name)
	spec.HostConfig.Sysctls = map[string]string{"net.ipv4.ip_unprivileged_port_start": "0"}
	if ip := f.hostIP(h.Offset); ip != nil {
		spec.NetworkingConfig = &docker.NetworkingConfig{
			EndpointsConfig: map[string]docker.EndpointConfig{
				"veil-net": {IPAMConfig: &docker.EndpointIPAM{IPv4Address: ip.String()}},
			},
		}
	}
	if spec.Labels == nil {
		spec.Labels = map[string]string{}
	}
	spec.Labels["com.veil.role"] = "resident"
	return spec
}

// residentCmd builds the veil-resident flags. -resolver is the gateway over UDP
// (the deferred honeypot-hit seam); empty -serve/-client pairs are omitted.
func residentCmd(h Host, gateway string) []string {
	var cmd []string
	if h.Serve != "" {
		cmd = append(cmd, "-serve", h.Serve)
	}
	if h.Client != "" {
		cmd = append(cmd, "-client", h.Client)
	}
	return append(cmd, "-hostname", h.Name, "-resolver", gateway+":53")
}

// Up creates and starts every roster host, best-effort: a host's failure logs +
// emits one KindSystem and continues. Reconciles a crashed-run orphan by name
// first. Errors if every resident fails, or — before touching any container — if
// Validate fails (fail closed: one KindSystem, nothing started).
func (f *Fleet) Up(ctx context.Context, bus *events.Bus, log *slog.Logger) error {
	if err := f.Validate(); err != nil {
		log.Warn("resident fleet disabled", "err", err)
		e := events.New(events.KindSystem, "veild", "residents fallback")
		e.Detail = "fleet not started: " + err.Error()
		bus.Publish(e)
		return err
	}
	failures := 0
	for _, h := range f.hosts {
		if f.hostIP(h.Offset) == nil {
			log.Warn("client resident has no static IP, using a dynamic one", "host", h.Name, "offset", h.Offset)
		}
		spec := f.residentSpec(h)
		_ = f.eng.remove(ctx, spec.Name, true) // reconcile orphan (404 tolerated by the client)
		id, err := f.eng.create(ctx, spec)
		if err == nil {
			if serr := f.eng.start(ctx, id); serr != nil {
				// Created but failed to start: remove it so Down/teardown don't
				// leak a container still holding a veil-net endpoint.
				_ = f.eng.remove(ctx, id, true)
				err = serr
			}
		}
		if err != nil {
			failures++
			log.Warn("resident failed to start", "host", h.Name, "err", err)
			e := events.New(events.KindSystem, "veild", "resident failed")
			e.Detail = h.Name + ": " + err.Error()
			bus.Publish(e)
			continue
		}
		f.ids = append(f.ids, id)
		if ip := f.hostIP(h.Offset); ip != nil && h.Trusted {
			if f.ipOf == nil {
				f.ipOf = map[string]net.IP{}
			}
			f.ipOf[id] = ip
		}
		e := events.New(events.KindLifecycle, "resident/"+h.Name, "resident up")
		e.Detail = fmt.Sprintf("ip=%s serve=%q client=%q", f.hostIP(h.Offset), h.Serve, h.Client)
		bus.Publish(e)
	}
	if len(f.hosts) > 0 && failures == len(f.hosts) {
		return fmt.Errorf("all %d residents failed to start", failures)
	}
	return nil
}

// Down force-removes every tracked resident, concurrently, so one slow removal
// can't use up the others' share of ctx. One summary lifecycle event covers the
// removed ones. A failed removal is not quiet: that resident may still hold a
// veil-net endpoint (so the fabric teardown fails) and would outlive the run, so
// its id stays tracked for a retry, one KindSystem event names it, and Down
// returns the error.
func (f *Fleet) Down(ctx context.Context, bus *events.Bus) error {
	errs := make([]error, len(f.ids))
	var wg sync.WaitGroup
	for i, id := range f.ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = f.eng.remove(ctx, id, true)
		}()
	}
	wg.Wait()
	var left []string
	var failed []error
	for i, id := range f.ids {
		if errs[i] != nil {
			left = append(left, id)
			failed = append(failed, fmt.Errorf("%s: %w", id, errs[i]))
		} else {
			delete(f.ipOf, id)
		}
	}
	removed := len(f.ids) - len(left)
	f.ids = left
	if removed > 0 && bus != nil {
		e := events.New(events.KindLifecycle, "veild", "residents down")
		e.Detail = fmt.Sprintf("removed %d residents", removed)
		bus.Publish(e)
	}
	if len(failed) == 0 {
		return nil
	}
	err := fmt.Errorf("%d resident(s) not removed: %w", len(failed), errors.Join(failed...))
	if bus != nil {
		e := events.New(events.KindSystem, "veild", "residents teardown failed")
		e.Detail = err.Error()
		bus.Publish(e)
	}
	return err
}

package residents

import (
	"context"
	"encoding/binary"
	"net"
	"strings"

	"github.com/miki-przygoda/veil/internal/docker"
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
	ids     []string // spawned container ids, for Down
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

// WorldNames maps each server host's FQDN (lower-case, per the resolver's key
// contract) to its derived IP, for seeding the resolver's World.Names.
func (f *Fleet) WorldNames() map[string]net.IP {
	names := map[string]net.IP{}
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
// static IP, and only the NET_BIND_SERVICE cap (for standard low ports).
func (f *Fleet) residentSpec(h Host) docker.CreateSpec {
	cfg := sandbox.Config{
		Image:   f.image,
		Network: "veil-net",
		DNS:     []string{f.gateway},
		Cmd:     residentCmd(h, f.gateway),
	}
	spec := cfg.HardenedSpec("resident-" + h.Name)
	spec.HostConfig.CapAdd = []string{"NET_BIND_SERVICE"}
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

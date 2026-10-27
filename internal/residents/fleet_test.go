package residents

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miki-przygoda/veil/internal/docker"
	"github.com/miki-przygoda/veil/internal/events"
	"github.com/miki-przygoda/veil/internal/sandbox"
)

func TestHostIPAndWorldNames(t *testing.T) {
	f := newFleetWithEngine(nil, "veil-resident:dev", "172.20.0.0/16", "172.20.0.1", DefaultRoster())

	if got := f.hostIP(10); got.String() != "172.20.0.10" {
		t.Errorf("hostIP(10) = %v, want 172.20.0.10", got)
	}
	if got := f.hostIP(50); got.String() != "172.20.0.50" {
		t.Errorf("hostIP(50) = %v, want 172.20.0.50", got)
	}
	names := f.WorldNames()
	if ip := names["web.veil.local"]; ip == nil || ip.String() != "172.20.0.10" {
		t.Errorf("WorldNames[web.veil.local] = %v, want 172.20.0.10", ip)
	}
	if _, ok := names["alice-pc"]; ok {
		t.Error("clients must not appear in WorldNames (only IsServer hosts)")
	}
	if len(names) != 4 {
		t.Errorf("WorldNames has %d entries, want 4 servers", len(names))
	}
}

func TestHostIPOtherSubnet(t *testing.T) {
	f := newFleetWithEngine(nil, "img", "10.5.0.0/16", "10.5.0.1", DefaultRoster())
	if got := f.hostIP(12); got.String() != "10.5.0.12" {
		t.Errorf("hostIP(12) = %v, want 10.5.0.12", got)
	}
}

func TestResidentSpec(t *testing.T) {
	f := newFleetWithEngine(nil, "veil-resident:dev", "172.20.0.0/16", "172.20.0.1", DefaultRoster())

	web := f.residentSpec(Host{Name: "web.veil.local", Offset: 10, Serve: "http:80,ssh:22", IsServer: true})
	if web.Name != "veil-resident-web.veil.local" {
		t.Errorf("Name = %q", web.Name)
	}
	if web.Image != "veil-resident:dev" {
		t.Errorf("Image = %q", web.Image)
	}
	joined := strings.Join(web.Cmd, " ")
	for _, want := range []string{"-serve http:80,ssh:22", "-hostname web.veil.local", "-resolver 172.20.0.1:53"} {
		if !strings.Contains(joined, want) {
			t.Errorf("Cmd missing %q: %v", want, web.Cmd)
		}
	}
	if strings.Contains(joined, "-client") {
		t.Errorf("pure server must have no -client: %v", web.Cmd)
	}
	if web.HostConfig.NetworkMode != "veil-net" {
		t.Errorf("NetworkMode = %q", web.HostConfig.NetworkMode)
	}
	if len(web.HostConfig.Dns) != 1 || web.HostConfig.Dns[0] != "172.20.0.1" {
		t.Errorf("Dns = %v, want [172.20.0.1] (UDP resolver seam)", web.HostConfig.Dns)
	}
	// Residents run non-root under no-new-privileges, so an added cap never reaches
	// the process: low ports bind via the netns-scoped sysctl instead, set explicitly
	// rather than relying on Docker's per-netns default.
	if len(web.HostConfig.CapAdd) != 0 {
		t.Errorf("CapAdd = %v, want none (a cap is dead under non-root + no-new-privileges)", web.HostConfig.CapAdd)
	}
	if got, ok := web.HostConfig.Sysctls["net.ipv4.ip_unprivileged_port_start"]; !ok || got != "0" {
		t.Errorf("Sysctls = %v, want net.ipv4.ip_unprivileged_port_start=0", web.HostConfig.Sysctls)
	}
	if len(web.HostConfig.CapDrop) != 1 || web.HostConfig.CapDrop[0] != "ALL" {
		t.Errorf("CapDrop = %v, want [ALL] (inherited hardening)", web.HostConfig.CapDrop)
	}
	if web.NetworkingConfig == nil ||
		web.NetworkingConfig.EndpointsConfig["veil-net"].IPAMConfig.IPv4Address != "172.20.0.10" {
		t.Errorf("static IP not set to 172.20.0.10: %+v", web.NetworkingConfig)
	}
	if web.Labels["com.veil.role"] != "resident" {
		t.Errorf("role label = %q", web.Labels["com.veil.role"])
	}

	// a client host carries -client and no -serve
	alice := f.residentSpec(Host{Name: "alice-pc", Offset: 50, Client: "web.veil.local"})
	aj := strings.Join(alice.Cmd, " ")
	if !strings.Contains(aj, "-client web.veil.local") || strings.Contains(aj, "-serve") {
		t.Errorf("client spec Cmd wrong: %v", alice.Cmd)
	}
	// The honeypot-hit seam must hold for CLIENT hosts too (they do the DNS): both
	// -resolver <gw>:53 and Dns:[gw] so client DNS is UDP-only, never TCP to the gateway.
	if !strings.Contains(aj, "-resolver 172.20.0.1:53") {
		t.Errorf("client missing -resolver seam: %v", alice.Cmd)
	}
	if len(alice.HostConfig.Dns) != 1 || alice.HostConfig.Dns[0] != "172.20.0.1" {
		t.Errorf("client Dns = %v, want [172.20.0.1]", alice.HostConfig.Dns)
	}
	if got := alice.HostConfig.Sysctls["net.ipv4.ip_unprivileged_port_start"]; got != "0" {
		t.Errorf("client Sysctls = %v, want net.ipv4.ip_unprivileged_port_start=0", alice.HostConfig.Sysctls)
	}
	// Each spec owns its Sysctls map (no aliasing between residents).
	if web.HostConfig.Sysctls != nil {
		web.HostConfig.Sysctls["probe"] = "x"
		if _, leaked := alice.HostConfig.Sysctls["probe"]; leaked {
			t.Error("resident specs share one Sysctls map")
		}
	}
}

// The resident sysctl is layered on by the Fleet only: the box's HardenedSpec must
// stay exactly as it was — no sysctls, no added caps.
func TestResidentSysctlNotOnBoxSpec(t *testing.T) {
	f := newFleetWithEngine(nil, "veil-resident:dev", "172.20.0.0/16", "172.20.0.1", DefaultRoster())
	_ = f.residentSpec(Host{Name: "web.veil.local", Offset: 10, Serve: "http:80", IsServer: true})

	box := sandbox.Config{Image: "veil-box:dev", Network: "veil-net"}.HardenedSpec("box")
	if len(box.HostConfig.Sysctls) != 0 {
		t.Errorf("box HardenedSpec Sysctls = %v, want none", box.HostConfig.Sysctls)
	}
	if len(box.HostConfig.CapAdd) != 0 {
		t.Errorf("box HardenedSpec CapAdd = %v, want none", box.HostConfig.CapAdd)
	}
}

type fakeEngine struct {
	creates    []docker.CreateSpec
	starts     []string
	removes    []string
	failCreate map[string]bool // by spec.Name
	failStart  bool            // start always fails
	failRemove map[string]bool // by id
	removeWait time.Duration   // each remove takes this long (ctx permitting)
	ctxCut     int             // removes cut short by ctx
	n          int

	mu sync.Mutex // Down removes concurrently
}

func (e *fakeEngine) create(_ context.Context, spec docker.CreateSpec) (string, error) {
	e.creates = append(e.creates, spec)
	if e.failCreate[spec.Name] {
		return "", errors.New("boom")
	}
	e.n++
	return fmt.Sprintf("id-%d", e.n), nil
}
func (e *fakeEngine) start(_ context.Context, id string) error {
	e.starts = append(e.starts, id)
	if e.failStart {
		return errors.New("start boom")
	}
	return nil
}
func (e *fakeEngine) remove(ctx context.Context, id string, _ bool) error {
	e.mu.Lock()
	e.removes = append(e.removes, id)
	fail := e.failRemove[id]
	e.mu.Unlock()
	if e.removeWait > 0 {
		select {
		case <-time.After(e.removeWait):
		case <-ctx.Done():
			e.mu.Lock()
			e.ctxCut++
			e.mu.Unlock()
			return ctx.Err()
		}
	}
	if fail {
		return errors.New("remove boom")
	}
	return nil
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestFleetUpDown(t *testing.T) {
	fe := &fakeEngine{}
	f := newFleetWithEngine(fe, "veil-resident:dev", "172.20.0.0/16", "172.20.0.1", DefaultRoster())
	bus := events.NewBus(64)
	feed, unsub := bus.Subscribe()
	defer unsub()

	if err := f.Up(context.Background(), bus, quietLog()); err != nil {
		t.Fatalf("Up: %v", err)
	}
	n := len(DefaultRoster())
	if len(fe.creates) != n || len(fe.starts) != n {
		t.Errorf("creates/starts = %d/%d, want %d each", len(fe.creates), len(fe.starts), n)
	}
	// reconcile-by-name: every create is preceded by a remove of the same name
	if len(fe.removes) != n {
		t.Errorf("removes = %d, want %d (reconcile before create)", len(fe.removes), n)
	}
	if len(f.ids) != n {
		t.Errorf("tracked ids = %d, want %d", len(f.ids), n)
	}
	// a "resident up" lifecycle event was published
	got := drainKinds(feed, 200)
	if got[events.KindLifecycle] < n {
		t.Errorf("lifecycle events = %d, want >= %d", got[events.KindLifecycle], n)
	}

	if err := f.Down(context.Background(), bus); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if len(fe.removes) != 2*n { // n reconcile + n teardown
		t.Errorf("removes after Down = %d, want %d", len(fe.removes), 2*n)
	}
	if len(f.ids) != 0 {
		t.Error("Down must clear tracked ids")
	}
}

func TestFleetUpPartialFailure(t *testing.T) {
	fe := &fakeEngine{failCreate: map[string]bool{"veil-resident-git.veil.local": true}}
	f := newFleetWithEngine(fe, "img", "172.20.0.0/16", "172.20.0.1", DefaultRoster())
	bus := events.NewBus(64)
	feed, unsub := bus.Subscribe()
	defer unsub()

	if err := f.Up(context.Background(), bus, quietLog()); err != nil {
		t.Fatalf("Up with one failure should not error: %v", err)
	}
	if len(f.ids) != len(DefaultRoster())-1 {
		t.Errorf("tracked ids = %d, want %d", len(f.ids), len(DefaultRoster())-1)
	}
	if drainKinds(feed, 200)[events.KindSystem] < 1 {
		t.Error("a failed resident must emit a KindSystem event")
	}
}

func TestFleetUpAllFail(t *testing.T) {
	fail := map[string]bool{}
	for _, h := range DefaultRoster() {
		fail["veil-resident-"+h.Name] = true
	}
	fe := &fakeEngine{failCreate: fail}
	f := newFleetWithEngine(fe, "img", "172.20.0.0/16", "172.20.0.1", DefaultRoster())
	if err := f.Up(context.Background(), events.NewBus(64), quietLog()); err == nil {
		t.Error("Up must error when all residents fail")
	}
}

// A container that is created but fails to start must be removed, not leaked —
// otherwise Down (tracked ids only) never reaps it and it can block network teardown.
func TestFleetUpRemovesCreatedButUnstarted(t *testing.T) {
	one := DefaultRoster()[:1] // just web.veil.local
	fe := &fakeEngine{failStart: true}
	f := newFleetWithEngine(fe, "img", "172.20.0.0/16", "172.20.0.1", one)
	if err := f.Up(context.Background(), events.NewBus(8), quietLog()); err == nil {
		t.Error("Up must error when the only resident fails to start")
	}
	if len(f.ids) != 0 {
		t.Errorf("tracked ids = %d, want 0 (start failed)", len(f.ids))
	}
	// reconcile remove (by name) + cleanup remove (by id) = 2
	if len(fe.removes) != 2 {
		t.Errorf("removes = %v, want 2 (reconcile + cleanup of created-but-unstarted)", fe.removes)
	}
	if len(fe.creates) != 1 {
		t.Errorf("creates = %d, want 1", len(fe.creates))
	}
}

// drainKinds collects event kinds seen within d ms.
func drainKinds(feed <-chan events.Event, ms int) map[events.Kind]int {
	out := map[events.Kind]int{}
	to := time.After(time.Duration(ms) * time.Millisecond)
	for {
		select {
		case e := <-feed:
			out[e.Kind]++
		case <-to:
			return out
		}
	}
}

// D5: a server with no derivable static IPv4 would start on a dynamic IP (or not
// at all) while the resolver and clients still target its name — clients would
// then hit the honeypot and raise false escapes. The fleet fails closed: no
// containers, a KindSystem event, an error (caller falls back to Population), and
// no WorldNames pointing nowhere.
func TestFleetFailsClosedWithoutServerIP(t *testing.T) {
	cases := []struct {
		name     string
		subnet   string
		hosts    []Host
		wantFail bool
	}{
		{"/16 fits every offset", "172.20.0.0/16", DefaultRoster(), false},
		{"/29 too small for server offsets", "172.20.0.0/29", DefaultRoster(), true},
		{"/27 fits servers, not clients", "172.20.0.0/27", DefaultRoster(), false},
		{"IPv6-first subnet", "fd00:5e11::/64", DefaultRoster(), true},
		{"unparseable subnet", "", DefaultRoster(), true},
		{"clients only on a tiny subnet", "172.20.0.0/29", []Host{{Name: "alice-pc", Offset: 50, Client: "web.veil.local"}}, false},
		{"Serve without IsServer still needs an IP", "172.20.0.0/29", []Host{{Name: "odd", Offset: 20, Serve: "ssh:22"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fe := &fakeEngine{}
			f := newFleetWithEngine(fe, "img", tc.subnet, "172.20.0.1", tc.hosts)
			bus := events.NewBus(64)
			feed, unsub := bus.Subscribe()
			defer unsub()

			if err := f.Validate(); (err != nil) != tc.wantFail {
				t.Fatalf("Validate() = %v, wantFail %v", err, tc.wantFail)
			}
			err := f.Up(context.Background(), bus, quietLog())
			if !tc.wantFail {
				if err != nil {
					t.Fatalf("Up: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Up must error when a server has no static IPv4")
			}
			if len(fe.creates) != 0 || len(fe.starts) != 0 || len(fe.removes) != 0 {
				t.Errorf("no container may be touched: creates=%d starts=%d removes=%d",
					len(fe.creates), len(fe.starts), len(fe.removes))
			}
			if len(f.ids) != 0 {
				t.Errorf("tracked ids = %d, want 0", len(f.ids))
			}
			if drainKinds(feed, 100)[events.KindSystem] != 1 {
				t.Error("fail-closed fleet must emit exactly one KindSystem event")
			}
			if names := f.WorldNames(); len(names) != 0 {
				t.Errorf("WorldNames = %v, want empty (no names pointing nowhere)", names)
			}
		})
	}
}

// A failed removal must surface (returned + one KindSystem) and stay tracked, so
// the caller knows a resident may still hold a veil-net endpoint.
func TestFleetDownReportsFailedRemovals(t *testing.T) {
	fe := &fakeEngine{failRemove: map[string]bool{"id-2": true}}
	f := newFleetWithEngine(fe, "veil-resident:dev", "172.20.0.0/16", "172.20.0.1", DefaultRoster())
	bus := events.NewBus(64)
	if err := f.Up(context.Background(), bus, quietLog()); err != nil {
		t.Fatalf("Up: %v", err)
	}
	n := len(f.ids)
	feed, unsub := bus.Subscribe()
	defer unsub()
	err := f.Down(context.Background(), bus)
	if err == nil || !strings.Contains(err.Error(), "id-2") {
		t.Fatalf("Down = %v, want an error naming id-2", err)
	}
	if len(f.ids) != 1 || f.ids[0] != "id-2" {
		t.Errorf("ids after Down = %v, want [id-2] still tracked", f.ids)
	}
	var sys, life int
	for to := time.After(100 * time.Millisecond); ; {
		var e events.Event
		select {
		case e = <-feed:
		case <-to:
		}
		if e.Kind == "" {
			break
		}
		switch e.Kind {
		case events.KindSystem:
			sys++
		case events.KindLifecycle:
			life++
			if !strings.Contains(e.Detail, fmt.Sprintf("removed %d residents", n-1)) {
				t.Errorf("lifecycle detail = %q, want removed %d", e.Detail, n-1)
			}
		}
	}
	if sys != 1 || life != 1 {
		t.Errorf("events: system=%d lifecycle=%d, want 1 and 1", sys, life)
	}
	// A retry reaps the straggler.
	fe.failRemove = nil
	if err := f.Down(context.Background(), bus); err != nil || len(f.ids) != 0 {
		t.Errorf("retry Down = %v, ids=%v; want nil, none", err, f.ids)
	}
}

// Removals run concurrently: one slow removal must not use up the others' share
// of the teardown deadline (sequentially this roster would need n*wait).
func TestFleetDownRemovesConcurrently(t *testing.T) {
	fe := &fakeEngine{}
	f := newFleetWithEngine(fe, "veil-resident:dev", "172.20.0.0/16", "172.20.0.1", DefaultRoster())
	if err := f.Up(context.Background(), events.NewBus(64), quietLog()); err != nil {
		t.Fatalf("Up: %v", err)
	}
	fe.removeWait = 200 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 2*fe.removeWait)
	defer cancel()
	if err := f.Down(ctx, events.NewBus(64)); err != nil {
		t.Fatalf("Down with %d slow removals in %v: %v", len(DefaultRoster()), 2*fe.removeWait, err)
	}
	if fe.ctxCut != 0 {
		t.Errorf("%d removals ran out of ctx, want 0", fe.ctxCut)
	}
}

// PlannedTrustedIPs is every Trusted address the fleet will claim; TrustedIPs is
// only the Trusted residents actually up. A resident that failed to start must
// not be in TrustedIPs (the box may hold its address), and neither may an
// untrusted one: the classifier ignores these, and an exploitable host must stay
// scored.
func TestFleetTrustedIPs(t *testing.T) {
	fe := &fakeEngine{failCreate: map[string]bool{"veil-resident-bob-laptop": true}}
	roster := append(DefaultRoster(), Host{Name: "target.veil.local", Offset: 20, Serve: "http:80", IsServer: true})
	f := newFleetWithEngine(fe, "veil-resident:dev", "172.20.0.0/16", "172.20.0.1", roster)
	strs := func(ips []net.IP) string {
		var s []string
		for _, ip := range ips {
			s = append(s, ip.String())
		}
		return strings.Join(s, ",")
	}
	all := "172.20.0.10,172.20.0.11,172.20.0.12,172.20.0.13,172.20.0.50,172.20.0.51,172.20.0.52"
	if got := strs(f.PlannedTrustedIPs()); got != all {
		t.Errorf("PlannedTrustedIPs = %s, want %s", got, all)
	}
	if got := f.TrustedIPs(); len(got) != 0 {
		t.Errorf("TrustedIPs before Up = %v, want none", got)
	}
	if err := f.Up(context.Background(), events.NewBus(64), quietLog()); err != nil {
		t.Fatalf("Up: %v", err)
	}
	up := "172.20.0.10,172.20.0.11,172.20.0.12,172.20.0.13,172.20.0.50,172.20.0.52"
	if got := strs(f.TrustedIPs()); got != up {
		t.Errorf("TrustedIPs = %s, want %s (bob-laptop failed, target untrusted)", got, up)
	}
	if err := f.Down(context.Background(), nil); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if got := f.TrustedIPs(); len(got) != 0 {
		t.Errorf("TrustedIPs after Down = %v, want none", got)
	}
}

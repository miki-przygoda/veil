package residents

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/miki-przygoda/veil/internal/docker"
	"github.com/miki-przygoda/veil/internal/events"
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
	if len(web.HostConfig.CapAdd) != 1 || web.HostConfig.CapAdd[0] != "NET_BIND_SERVICE" {
		t.Errorf("CapAdd = %v, want [NET_BIND_SERVICE]", web.HostConfig.CapAdd)
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
}

type fakeEngine struct {
	creates    []docker.CreateSpec
	starts     []string
	removes    []string
	failCreate map[string]bool // by spec.Name
	failStart  bool            // start always fails
	n          int
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
func (e *fakeEngine) remove(_ context.Context, id string, _ bool) error {
	e.removes = append(e.removes, id)
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

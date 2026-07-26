package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miki-przygoda/veil/internal/events"
	"github.com/miki-przygoda/veil/internal/netfabric"
	"github.com/miki-przygoda/veil/internal/sandbox"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestSelectSandboxStub(t *testing.T) {
	box, err := selectSandbox(context.Background(), "stub", "", nil, events.NewBus(8), quietLog())
	if err != nil {
		t.Fatalf("stub backend: unexpected err %v", err)
	}
	if _, ok := box.(*sandbox.Stub); !ok {
		t.Fatalf("got %T, want *sandbox.Stub", box)
	}
}

func TestSelectSandboxContainerFailClosed(t *testing.T) {
	// Docker unreachable + container backend requested => error, no fallback.
	t.Setenv("DOCKER_HOST", "unix:///nonexistent/veil-test-does-not-exist.sock")
	box, err := selectSandbox(context.Background(), "container", "", nil, events.NewBus(8), quietLog())
	if err == nil {
		t.Fatal("container backend with no Docker: want error (fail closed), got nil")
	}
	if box != nil {
		t.Errorf("want nil sandbox on fail-closed, got %T", box)
	}
}

func TestSelectTapStub(t *testing.T) {
	tap := selectTap(context.Background(), "stub", "veil-br0", events.NewBus(8), quietLog())
	if _, ok := tap.(*netfabric.StubTap); !ok {
		t.Fatalf("got %T, want *netfabric.StubTap", tap)
	}
}

func TestSelectTapPacketFallback(t *testing.T) {
	// On this dev host capture is unsupported (non-Linux / no bridge), so the
	// packet tap must fall back to StubTap with an observable system event.
	bus := events.NewBus(8)
	feed, unsub := bus.Subscribe()
	defer unsub()
	tap := selectTap(context.Background(), "packet", "definitely-not-an-iface", bus, quietLog())
	if _, ok := tap.(*netfabric.StubTap); !ok {
		t.Fatalf("got %T, want *netfabric.StubTap (fallback)", tap)
	}
	select {
	case e := <-feed:
		if e.Kind != events.KindSystem {
			t.Errorf("fallback event kind = %s, want system", e.Kind)
		}
	default:
		t.Error("no KindSystem tap-fallback event published")
	}
}

func TestBuildWorld(t *testing.T) {
	w := buildWorld("172.20.0.0/16", "172.20.0.1", nil)
	if w.Subnet == nil || w.Subnet.String() != "172.20.0.0/16" {
		t.Errorf("subnet = %v, want 172.20.0.0/16", w.Subnet)
	}
	// 8.8.8.8 is not in 172.20.0.0/16 — off-world (cannot call unexported offWorldIP cross-pkg).
	if w.Subnet.Contains(net.ParseIP("8.8.8.8")) {
		t.Error("8.8.8.8 should be off-world (not in subnet)")
	}
	// Gateway must be recorded as an in-world address.
	if !w.Gateway.Equal(net.ParseIP("172.20.0.1")) {
		t.Errorf("gateway = %v, want 172.20.0.1", w.Gateway)
	}
}

func TestBuildWorldEmpty(t *testing.T) {
	w := buildWorld("", "", nil) // stub/no-Docker path
	if w.Subnet != nil {
		t.Error("empty subnet must yield nil Subnet (disables IP vector)")
	}
}

func TestBuildWorldSeedsNames(t *testing.T) {
	names := map[string]net.IP{"web.veil.local": net.ParseIP("172.20.0.10")}
	w := buildWorld("172.20.0.0/16", "172.20.0.1", names)
	if ip := w.Names["web.veil.local"]; ip == nil || ip.String() != "172.20.0.10" {
		t.Errorf("World.Names not seeded: %v", w.Names)
	}
}

func TestStartResolverBindFailureFallsBack(t *testing.T) {
	bus := events.NewBus(8)
	feed, unsub := bus.Subscribe()
	defer unsub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// TEST-NET-1 is not a local address, so ListenPacket must fail.
	if started := startResolver(ctx, netfabric.World{}, "192.0.2.1", bus, quietLog()); started {
		t.Error("startResolver should report not-started on bind failure")
	}
	select {
	case e := <-feed:
		if e.Kind != events.KindSystem {
			t.Errorf("fallback kind = %s, want system", e.Kind)
		}
	default:
		t.Error("no KindSystem fallback event published")
	}
}

func TestSelectSandboxStubIgnoresDNS(t *testing.T) {
	box, err := selectSandbox(context.Background(), "stub", "", []string{"1.2.3.4"}, events.NewBus(4), quietLog())
	if err != nil || box == nil {
		t.Fatalf("stub backend: box=%v err=%v", box, err)
	}
}

func drain(feed <-chan events.Event, ms int) []events.Event {
	var out []events.Event
	to := time.After(time.Duration(ms) * time.Millisecond)
	for {
		select {
		case e := <-feed:
			out = append(out, e)
		case <-to:
			return out
		}
	}
}

func drainKinds(feed <-chan events.Event, ms int) map[events.Kind]int {
	out := map[events.Kind]int{}
	for _, e := range drain(feed, ms) {
		out[e.Kind]++
	}
	return out
}

// execStub is a Sandbox (via the embedded Stub) that ALSO implements Execer,
// standing in for the container backend in gating tests.
type execStub struct {
	*sandbox.Stub
	ran [][]string
}

func (e *execStub) Exec(_ context.Context, cmd []string) (sandbox.ExecResult, error) {
	e.ran = append(e.ran, cmd)
	return sandbox.ExecResult{Output: []byte("ok"), ExitCode: 0}, nil
}

func TestMaybeStartSubjectSkipsNonExecer(t *testing.T) {
	bus := events.NewBus(16)
	feed, unsub := bus.Subscribe()
	defer unsub()
	// A plain Stub is a Sandbox but NOT an Execer.
	maybeStartSubject(context.Background(), sandbox.NewStub("box", bus), "/nonexistent", time.Millisecond, bus, quietLog())

	got := drainKinds(feed, 100)
	if got[events.KindSystem] < 1 {
		t.Error("non-Execer backend must emit a KindSystem skip note")
	}
	if got[events.KindSubject] != 0 {
		t.Error("non-Execer backend must not run subject commands")
	}
}

func TestMaybeStartSubjectRunsOnExecer(t *testing.T) {
	bus := events.NewBus(16)
	feed, unsub := bus.Subscribe()
	defer unsub()

	dir := t.TempDir()
	script := filepath.Join(dir, "s.txt")
	if err := os.WriteFile(script, []byte("# go\nwhoami\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	box := &execStub{Stub: sandbox.NewStub("box", bus)}
	maybeStartSubject(context.Background(), box, script, time.Millisecond, bus, quietLog())

	got := drainKinds(feed, 300)
	if got[events.KindSubject] < 1 {
		t.Error("Execer backend must publish a KindSubject transcript event")
	}
}

func TestMaybeStartSubjectOffWhenNoFile(t *testing.T) {
	bus := events.NewBus(8)
	feed, unsub := bus.Subscribe()
	defer unsub()
	maybeStartSubject(context.Background(), sandbox.NewStub("box", bus), "", time.Millisecond, bus, quietLog())
	if len(drain(feed, 50)) != 0 {
		t.Error("empty -subject must be a no-op")
	}
}

// shellStub is a Sandbox (via embedded Stub) that ALSO implements Sheller,
// standing in for the container backend in autonomous-subject gating tests.
type shellStub struct {
	*sandbox.Stub
}

func (s *shellStub) OpenShell(_ context.Context) (sandbox.Shell, error) {
	return &noopShell{}, nil
}

type noopShell struct{}

func (noopShell) Run(_ context.Context, _ string) (sandbox.ExecResult, error) {
	return sandbox.ExecResult{Output: []byte("ok"), ExitCode: 0}, nil
}
func (noopShell) Close() error { return nil }

func TestMaybeStartAutoSubjectSkipsNonSheller(t *testing.T) {
	bus := events.NewBus(16)
	feed, unsub := bus.Subscribe()
	defer unsub()
	// A plain Stub is a Sandbox but NOT a Sheller.
	maybeStartAutoSubject(context.Background(), sandbox.NewStub("box", bus), "g", "scripted", 5, time.Millisecond, bus, quietLog())

	got := drainKinds(feed, 150)
	if got[events.KindSystem] < 1 {
		t.Error("non-Sheller backend must emit a KindSystem skip note")
	}
	if got[events.KindSubject] != 0 {
		t.Error("non-Sheller backend must not run an autonomous subject")
	}
}

func TestMaybeStartAutoSubjectSkipsClaudeWithoutKey(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	bus := events.NewBus(16)
	feed, unsub := bus.Subscribe()
	defer unsub()
	box := &shellStub{Stub: sandbox.NewStub("box", bus)}
	maybeStartAutoSubject(context.Background(), box, "g", "claude", 5, time.Millisecond, bus, quietLog())

	got := drainKinds(feed, 150)
	if got[events.KindSystem] < 1 {
		t.Error("claude brain without ANTHROPIC_API_KEY must skip with a KindSystem note")
	}
	if got[events.KindSubject] != 0 {
		t.Error("claude brain without a key must not run")
	}
}

func TestMaybeStartAutoSubjectRunsScripted(t *testing.T) {
	bus := events.NewBus(64)
	feed, unsub := bus.Subscribe()
	defer unsub()
	box := &shellStub{Stub: sandbox.NewStub("box", bus)}
	maybeStartAutoSubject(context.Background(), box, "escape", "scripted", 3, time.Millisecond, bus, quietLog())

	got := drainKinds(feed, 400)
	if got[events.KindSubject] < 3 {
		t.Errorf("Sheller backend must publish KindSubject events (got %d)", got[events.KindSubject])
	}
}

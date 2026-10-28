package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
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

// TestStartTapOpensSynchronously: startTap must finish opening the tap (here the
// packet->stub fallback, with its KindSystem event) before it returns, so main
// can start the subject only once capture is attached. Only Run is backgrounded.
func TestStartTapOpensSynchronously(t *testing.T) {
	bus := events.NewBus(8)
	feed, unsub := bus.Subscribe()
	defer unsub()
	ctx, cancel := context.WithCancel(context.Background())
	done := startTap(ctx, "packet", "definitely-not-an-iface", bus, quietLog())

	select {
	case e := <-feed:
		if e.Kind != events.KindSystem || e.Action != "tap fallback" {
			t.Errorf("first event = %+v, want KindSystem tap fallback", e)
		}
	default:
		t.Error("tap not opened when startTap returned: no fallback event yet")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("tap Run did not stop on ctx cancel")
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
	if udp, tcp := startResolver(ctx, netfabric.World{}, "192.0.2.1:53", bus, quietLog()); udp || tcp {
		t.Errorf("startResolver = (udp %v, tcp %v), want not-started on bind failure", udp, tcp)
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

// freeLoopbackPort returns a 127.0.0.1 port with both UDP and TCP free (best-effort).
func freeLoopbackPort(t *testing.T) string {
	t.Helper()
	for i := 0; i < 20; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Listen: %v", err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()
		if pc, err := net.ListenPacket("udp", addr); err == nil {
			_ = pc.Close()
			return addr
		}
	}
	t.Fatal("no free loopback port")
	return ""
}

func TestStartResolverServesUDPAndTCP(t *testing.T) {
	bus := events.NewBus(8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := freeLoopbackPort(t)
	if udp, tcp := startResolver(ctx, netfabric.World{}, addr, bus, quietLog()); !udp || !tcp {
		t.Fatalf("startResolver = (udp %v, tcp %v), want both", udp, tcp)
	}
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("TCP resolver not listening: %v", err)
	}
	_ = c.Close()
}

func TestStartResolverTCPBindFailureKeepsUDP(t *testing.T) {
	bus := events.NewBus(8)
	feed, unsub := bus.Subscribe()
	defer unsub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := freeLoopbackPort(t)
	squat, err := net.Listen("tcp", addr) // TCP taken, UDP free
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer squat.Close()
	udp, tcp := startResolver(ctx, netfabric.World{}, addr, bus, quietLog())
	if !udp || tcp {
		t.Fatalf("startResolver = (udp %v, tcp %v), want UDP only", udp, tcp)
	}
	select {
	case e := <-feed:
		if e.Kind != events.KindSystem || !strings.Contains(e.Detail, "honeypot") {
			t.Errorf("fallback event = %+v, want KindSystem saying tcp/53 stays on the honeypot", e)
		}
	default:
		t.Error("no KindSystem event for the TCP bind failure")
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

func TestDefaultListenIsLoopback(t *testing.T) {
	// The dashboard carries the whole observer feed; by default it must not bind
	// the veil-net gateway (reachable from the box).
	if listenExposed(defaultListen) {
		t.Errorf("defaultListen = %q binds every interface, want loopback", defaultListen)
	}
}

func TestListenExposed(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{":8080", true},
		{"0.0.0.0:8080", true},
		{"[::]:8080", true},
		{"127.0.0.1:8080", false},
		{"[::1]:8080", false},
		{"localhost:8080", false},
		{"10.0.0.5:8080", false},
	}
	for _, c := range cases {
		if got := listenExposed(c.addr); got != c.want {
			t.Errorf("listenExposed(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}

// TestWarnIfObserverExposed pins the warning as log-only and hedged: it fires
// before the viz server is listening, and the Bus has no replay, so a bus event
// would reach no viewer; and whether the gateway actually serves the dashboard
// depends on the honeypot, so the wording says "may be reachable".
// It keys on the box's ACTUAL network (boxNet — "" when D7 withholds veil-net),
// and an explicit bind to the veil-net gateway IP counts as exposed too.
func TestWarnIfObserverExposed(t *testing.T) {
	cases := []struct {
		name, addr, boxNet, gateway string
		want                        bool
	}{
		{"all interfaces + veil-net", ":8080", "veil-net", "172.20.0.1", true},
		{"0.0.0.0 + veil-net", "0.0.0.0:8080", "veil-net", "172.20.0.1", true},
		{"all interfaces, no network", ":8080", "", "", false},
		{"all interfaces, veil-net withheld by D7", ":8080", "", "172.20.0.1", false},
		{"loopback + veil-net", "127.0.0.1:8080", "veil-net", "172.20.0.1", false},
		{"gateway bind + veil-net", "172.20.0.1:8080", "veil-net", "172.20.0.1", true},
		{"gateway bind, veil-net withheld by D7", "172.20.0.1:8080", "", "172.20.0.1", false},
		{"other host IP + veil-net", "10.0.0.5:8080", "veil-net", "172.20.0.1", false},
		{"gateway unknown + specific IP", "10.0.0.5:8080", "veil-net", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			log := slog.New(slog.NewTextHandler(&buf, nil))
			warnIfObserverExposed(c.addr, c.boxNet, c.gateway, log)
			out := buf.String()
			got := strings.Contains(out, "level=WARN")
			if got != c.want {
				t.Fatalf("logged warning = %v, want %v (log: %q)", got, c.want, out)
			}
			if c.want {
				if !strings.Contains(out, "may be reachable") {
					t.Errorf("warning should hedge with %q, got %q", "may be reachable", out)
				}
				if !strings.Contains(out, "127.0.0.1:8080") {
					t.Errorf("warning should name the loopback fix, got %q", out)
				}
			}
		})
	}
}

// lifecycleBox is a Sandbox whose Create/Start/Destroy can be made to fail, and
// which records whether Destroy ran and with what context.
type lifecycleBox struct {
	*sandbox.Stub
	createErr, startErr, destroyErr error
	destroyed                       bool
	destroyCtxErr                   error
	destroyHasDeadline              bool
}

func (b *lifecycleBox) Create(ctx context.Context) error {
	if b.createErr != nil {
		return b.createErr
	}
	return b.Stub.Create(ctx)
}

func (b *lifecycleBox) Start(ctx context.Context) error {
	if b.startErr != nil {
		return b.startErr
	}
	return b.Stub.Start(ctx)
}

func (b *lifecycleBox) Destroy(ctx context.Context) error {
	b.destroyed = true
	b.destroyCtxErr = ctx.Err()
	_, b.destroyHasDeadline = ctx.Deadline()
	if b.destroyErr != nil {
		return b.destroyErr
	}
	return b.Stub.Destroy(ctx)
}

func TestStartBox(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name                 string
		createErr, startErr  error
		destroyErr           error
		wantErr, wantDestroy bool
	}{
		{name: "ok", wantErr: false, wantDestroy: false},
		// Create failed: nothing was created, so there is nothing to destroy.
		{name: "create fails", createErr: boom, wantErr: true, wantDestroy: false},
		// Start failed after a successful Create: the container exists and must
		// be destroyed, or it stays attached to veil-net (F8).
		{name: "start fails", startErr: boom, wantErr: true, wantDestroy: true},
		// A failed cleanup Destroy is logged, never masks the Start error.
		{name: "start and destroy fail", startErr: boom, destroyErr: errors.New("wedged"), wantErr: true, wantDestroy: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			box := &lifecycleBox{Stub: sandbox.NewStub("t", events.NewBus(8)), createErr: tc.createErr, startErr: tc.startErr, destroyErr: tc.destroyErr}
			// A cancelled caller ctx (e.g. SIGINT mid-start) must not stop cleanup.
			ctx, cancel := context.WithCancel(context.Background())
			if tc.startErr != nil {
				cancel()
			} else {
				defer cancel()
			}
			err := startBox(ctx, box, quietLog())
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, boom) {
				t.Errorf("err = %v, want it to wrap the bring-up error", err)
			}
			if box.destroyed != tc.wantDestroy {
				t.Fatalf("destroyed = %v, want %v", box.destroyed, tc.wantDestroy)
			}
			if tc.wantDestroy {
				if box.destroyCtxErr != nil {
					t.Errorf("destroy ctx already done (%v); want a fresh background ctx", box.destroyCtxErr)
				}
				if !box.destroyHasDeadline {
					t.Error("destroy ctx has no deadline; want it bounded")
				}
			}
		})
	}
}

func TestParseEngineVersion(t *testing.T) {
	cases := []struct {
		in     string
		want   engineVersion
		wantOK bool
	}{
		{"24.0.7", engineVersion{24, 0, 7, false}, true},
		{"25.0.0", engineVersion{25, 0, 0, false}, true},
		{"29.1.3", engineVersion{29, 1, 3, false}, true},
		{"25.0.0-rc.1", engineVersion{25, 0, 0, true}, true},
		{"25.0.5+dfsg1", engineVersion{25, 0, 5, false}, true},
		{"25", engineVersion{}, false},
		{"25.0", engineVersion{}, false},
		{"", engineVersion{}, false},
		{"garbage", engineVersion{}, false},
		{"-1.0.0", engineVersion{}, false},
		{"+25.0.0", engineVersion{}, false},
		{".25.0", engineVersion{}, false},
		{"25.x.0", engineVersion{}, false},
		{"25.0.5.1", engineVersion{}, false},
	}
	for _, tc := range cases {
		got, ok := parseEngineVersion(tc.in)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("parseEngineVersion(%q) = %+v,%v, want %+v,%v", tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}

// TestEmbeddedDNSLeaks: with the world resolver down, the box falls back to
// Docker's embedded DNS, which before the CVE-2024-29018 fix (25.0.5 / 26.0.0)
// can forward to the host's real upstreams even on an --internal network.
// Unknown versions, and pre-releases of a fixed version, count as old.
func TestEmbeddedDNSLeaks(t *testing.T) {
	cases := []struct {
		resolverUp bool
		version    string
		want       bool
	}{
		{false, "23.0.11", true},
		{false, "24.0.7", true},
		{false, "25.0.0", true},
		{false, "25.0.4", true},
		{false, "25.0.0-rc.1", true},
		{false, "25.0.5-rc.1", true},
		{false, "25.0.5", false},
		{false, "25.0.14", false},
		{false, "25.1.0", false},
		{false, "26.0.0-rc3", true},
		{false, "26.0.0", false},
		{false, "26.1.4", false},
		{false, "29.1.3", false},
		{false, "", true},
		{false, "garbage", true},
		{true, "24.0.7", false},
		{true, "", false},
		{true, "garbage", false},
		{true, "29.1.3", false},
	}
	for _, tc := range cases {
		if got := embeddedDNSLeaks(tc.resolverUp, tc.version); got != tc.want {
			t.Errorf("embeddedDNSLeaks(%v, %q) = %v, want %v", tc.resolverUp, tc.version, got, tc.want)
		}
	}
}

func TestBoxNetwork(t *testing.T) {
	cases := []struct {
		name       string
		netName    string
		resolverUp bool
		version    string
		want       string
		wantEvent  bool
	}{
		{"old engine resolver down fails closed", "veil-net", false, "24.0.7", "", true},
		{"unknown engine resolver down fails closed", "veil-net", false, "", "", true},
		{"unpatched 25.0.x resolver down fails closed", "veil-net", false, "25.0.3", "", true},
		{"new engine resolver down joins", "veil-net", false, "29.1.3", "veil-net", false},
		{"old engine resolver up joins", "veil-net", true, "24.0.7", "veil-net", false},
		{"no fabric stays none silently", "", false, "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bus := events.NewBus(8)
			feed, unsub := bus.Subscribe()
			defer unsub()
			if got := boxNetwork(tc.netName, tc.resolverUp, tc.version, bus, quietLog()); got != tc.want {
				t.Errorf("boxNetwork = %q, want %q", got, tc.want)
			}
			evs := drain(feed, 20)
			if tc.wantEvent {
				if len(evs) != 1 || evs[0].Kind != events.KindSystem {
					t.Fatalf("want one KindSystem event, got %+v", evs)
				}
			} else if len(evs) != 0 {
				t.Errorf("want no event, got %+v", evs)
			}
		})
	}
}

// TestResolveBoxNetwork covers the D7 glue in main: the engine version is only
// queried when it can matter (box on veil-net with the resolver down); an old or
// unreadable engine withholds veil-net; a patched one joins but its DNS stays in
// the box's netns (127.0.0.11), so external-dns goes dark — said observably.
func TestResolveBoxNetwork(t *testing.T) {
	cases := []struct {
		name       string
		netName    string
		resolverUp bool
		version    string
		verErr     error
		want       string
		wantQuery  bool
		wantAction string // "" = no event
	}{
		{"resolver up, old engine", "veil-net", true, "24.0.7", nil, "veil-net", false, ""},
		{"resolver up, new engine", "veil-net", true, "29.1.3", nil, "veil-net", false, ""},
		{"resolver up, version error", "veil-net", true, "", errors.New("boom"), "veil-net", false, ""},
		{"resolver down, old engine", "veil-net", false, "24.0.7", nil, "", true, "box network withheld"},
		{"resolver down, new engine", "veil-net", false, "29.1.3", nil, "veil-net", true, "world dns dark"},
		{"resolver down, version error", "veil-net", false, "", errors.New("boom"), "", true, "box network withheld"},
		{"no fabric", "", false, "", nil, "", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bus := events.NewBus(8)
			feed, unsub := bus.Subscribe()
			defer unsub()
			queried := false
			getVersion := func(ctx context.Context) (string, error) {
				queried = true
				if _, ok := ctx.Deadline(); !ok {
					t.Error("version query ctx has no deadline; want it bounded")
				}
				return tc.version, tc.verErr
			}
			got := resolveBoxNetwork(context.Background(), tc.netName, tc.resolverUp, getVersion, bus, quietLog())
			if got != tc.want {
				t.Errorf("resolveBoxNetwork = %q, want %q", got, tc.want)
			}
			if queried != tc.wantQuery {
				t.Errorf("engine version queried = %v, want %v", queried, tc.wantQuery)
			}
			evs := drain(feed, 20)
			if tc.wantAction == "" {
				if len(evs) != 0 {
					t.Errorf("want no event, got %+v", evs)
				}
				return
			}
			if len(evs) != 1 || evs[0].Kind != events.KindSystem || evs[0].Action != tc.wantAction {
				t.Fatalf("want one KindSystem %q event, got %+v", tc.wantAction, evs)
			}
		})
	}
}

// TestWaitTap: shutdown waits for the tap's Run to return (closing the AF_PACKET
// handle) before the bridge is removed, but never longer than the bound.
func TestWaitTap(t *testing.T) {
	closed := make(chan struct{})
	close(closed)
	if !waitTap(closed, time.Second, quietLog()) {
		t.Error("waitTap on a closed channel = false, want true")
	}

	start := time.Now()
	if waitTap(make(chan struct{}), 50*time.Millisecond, quietLog()) {
		t.Error("waitTap on a never-closing channel = true, want false")
	}
	if el := time.Since(start); el > time.Second {
		t.Errorf("waitTap took %v, want it bounded near 50ms", el)
	}

	if !waitTap(nil, time.Second, quietLog()) {
		t.Error("waitTap(nil) = false, want true (no tap started)")
	}
}

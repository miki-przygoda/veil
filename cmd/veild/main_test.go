package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"

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
	w := buildWorld("172.20.0.0/16", "172.20.0.1")
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
	w := buildWorld("", "") // stub/no-Docker path
	if w.Subnet != nil {
		t.Error("empty subnet must yield nil Subnet (disables IP vector)")
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

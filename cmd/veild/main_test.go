package main

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/miki-przygoda/veil/internal/events"
	"github.com/miki-przygoda/veil/internal/sandbox"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestSelectSandboxStub(t *testing.T) {
	box := selectSandbox(context.Background(), "stub", events.NewBus(8), quietLog())
	if _, ok := box.(*sandbox.Stub); !ok {
		t.Fatalf("got %T, want *sandbox.Stub", box)
	}
}

func TestSelectSandboxContainerFallback(t *testing.T) {
	// Point at a socket that cannot exist so Ping fails and we fall back.
	t.Setenv("DOCKER_HOST", "unix:///nonexistent/veil-test-does-not-exist.sock")
	bus := events.NewBus(8)
	feed, unsub := bus.Subscribe()
	defer unsub()

	box := selectSandbox(context.Background(), "container", bus, quietLog())
	if _, ok := box.(*sandbox.Stub); !ok {
		t.Fatalf("got %T, want *sandbox.Stub (fallback)", box)
	}
	select {
	case e := <-feed:
		if e.Kind != events.KindSystem {
			t.Errorf("fallback event kind = %s, want system", e.Kind)
		}
	default:
		t.Error("no KindSystem fallback event published")
	}
}

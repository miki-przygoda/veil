package sandbox

import (
	"context"
	"os"
	"testing"

	"github.com/miki-przygoda/veil/internal/events"
)

// TestContainerIntegration exercises the real Docker engine end to end. It is
// skipped unless VEIL_DOCKER_IT is set; it needs a reachable daemon and a local
// alpine:3.20 image (docker pull alpine:3.20). Keeps `make test` green offline.
func TestContainerIntegration(t *testing.T) {
	if os.Getenv("VEIL_DOCKER_IT") == "" {
		t.Skip("set VEIL_DOCKER_IT=1 to run (needs Docker + alpine:3.20)")
	}

	bus := events.NewBus(64)
	c, err := NewContainer("it-01", bus, DefaultConfig())
	if err != nil {
		t.Fatalf("NewContainer: %v", err)
	}
	ctx := context.Background()

	if err := c.Create(ctx); err != nil {
		t.Fatalf("Create (is alpine:3.20 pulled?): %v", err)
	}
	t.Cleanup(func() { _ = c.Destroy(context.Background()) })

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if c.Status() != StatusRunning {
		t.Fatalf("status = %s, want running", c.Status())
	}
	if err := c.Snapshot(ctx); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := c.Reset(ctx); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if err := c.Destroy(ctx); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if c.Status() != StatusDestroyed {
		t.Fatalf("status = %s, want destroyed", c.Status())
	}
}

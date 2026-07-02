package netfabric

import (
	"context"
	"os"
	"testing"

	"github.com/miki-przygoda/veil/internal/docker"
)

func TestFabricIntegration(t *testing.T) {
	if os.Getenv("VEIL_DOCKER_IT") == "" {
		t.Skip("set VEIL_DOCKER_IT=1 to run (needs Docker)")
	}
	cli, err := docker.New(os.Getenv("DOCKER_HOST"))
	if err != nil {
		t.Fatal(err)
	}
	f := NewFabric(cli, "veil-net-it")
	ctx := context.Background()
	n, err := f.Ensure(ctx)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	// Sole owner of teardown (best-effort, asserted). RemoveNetwork is
	// 404-tolerant, so this is safe even if the network is already gone.
	t.Cleanup(func() {
		if err := f.Teardown(context.Background()); err != nil {
			t.Errorf("Teardown: %v", err)
		}
	})
	if !n.Internal {
		t.Errorf("network Internal = false, want true (no egress)")
	}
}

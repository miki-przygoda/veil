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
	t.Cleanup(func() { _ = f.Teardown(context.Background()) })
	if !n.Internal {
		t.Errorf("network Internal = false, want true (no egress)")
	}
	if err := f.Teardown(ctx); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
}

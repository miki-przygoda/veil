package netfabric

import (
	"context"

	"github.com/miki-przygoda/veil/internal/docker"
)

// networkClient is the small Docker surface Fabric needs (satisfied by
// *docker.Client; a fake backs the tests).
type networkClient interface {
	CreateNetwork(ctx context.Context, spec docker.NetworkSpec) (string, error)
	InspectNetwork(ctx context.Context, id string) (docker.Network, error)
	RemoveNetwork(ctx context.Context, id string) error
}

// Fabric owns the world's internal Docker network. An internal network has no
// route to the host or internet, so the box on it cannot egress (host-side
// enforcement).
type Fabric struct {
	cli    networkClient
	name   string
	bridge string
	id     string
}

// NewFabric returns a Fabric for the named network (e.g. "veil-net").
func NewFabric(cli networkClient, name string) *Fabric {
	return &Fabric{cli: cli, name: name, bridge: "veil-br0"}
}

// Ensure creates the internal network and returns the inspected result, with the
// deterministic host bridge interface name resolved. Idempotency against a
// pre-existing network (Docker returns 409 on a duplicate) is handled by the
// integration task, not here.
func (f *Fabric) Ensure(ctx context.Context) (docker.Network, error) {
	id, err := f.cli.CreateNetwork(ctx, docker.NetworkSpec{
		Name:       f.name,
		Internal:   true,
		Labels:     map[string]string{"com.veil.managed": "true"},
		BridgeName: f.bridge,
	})
	if err != nil {
		return docker.Network{}, err
	}
	f.id = id
	return f.cli.InspectNetwork(ctx, id)
}

// Teardown removes the network (best-effort idempotent via RemoveNetwork).
func (f *Fabric) Teardown(ctx context.Context) error {
	if f.id == "" {
		return nil
	}
	return f.cli.RemoveNetwork(ctx, f.id)
}

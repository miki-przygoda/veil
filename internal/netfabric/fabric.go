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

// Ensure returns the world's internal network, creating it if absent. If the
// network already exists (e.g. left by an unclean prior run), it is reused
// rather than recreated — the analogue of the container backend's
// reconcile-on-restart. The resolved host bridge interface name comes back on
// the returned docker.Network.
func (f *Fabric) Ensure(ctx context.Context) (docker.Network, error) {
	if n, err := f.cli.InspectNetwork(ctx, f.name); err == nil {
		f.id = n.ID
		return n, nil
	}
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

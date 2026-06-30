package sandbox

import (
	"context"
	"errors"
	"fmt"
)

// Sentinel errors let callers branch with errors.Is instead of string matching.
var (
	// ErrEngineUnavailable means the Docker daemon could not be reached.
	ErrEngineUnavailable = errors.New("docker engine unavailable")
	// ErrImageMissing means the base image is not present locally (no auto-pull).
	ErrImageMissing = errors.New("base image not present locally")
)

// engineError wraps a non-2xx Docker API response.
type engineError struct {
	status  int
	message string
}

func (e *engineError) Error() string {
	return fmt.Sprintf("docker api: status %d: %s", e.status, e.message)
}

// hostConfig is the subset of Docker's HostConfig we set, all for hardening.
type hostConfig struct {
	ReadonlyRootfs bool              `json:"ReadonlyRootfs"`
	Tmpfs          map[string]string `json:"Tmpfs,omitempty"`
	CapDrop        []string          `json:"CapDrop,omitempty"`
	SecurityOpt    []string          `json:"SecurityOpt,omitempty"`
	PidsLimit      int64             `json:"PidsLimit,omitempty"`
	Memory         int64             `json:"Memory,omitempty"`
	NetworkMode    string            `json:"NetworkMode,omitempty"`
}

// createSpec is the body for POST /containers/create. The unexported name is
// sent as the ?name= query parameter, not in the JSON body.
type createSpec struct {
	name string

	Image           string            `json:"Image"`
	Cmd             []string          `json:"Cmd,omitempty"`
	Labels          map[string]string `json:"Labels,omitempty"`
	NetworkDisabled bool              `json:"NetworkDisabled"`
	HostConfig      hostConfig        `json:"HostConfig"`
}

// engine is the only Docker surface Container touches. dockerEngine is the real
// implementation; fakeEngine backs the unit tests.
type engine interface {
	ping(ctx context.Context) error
	imageExists(ctx context.Context, ref string) (bool, error)
	create(ctx context.Context, spec createSpec) (id string, err error)
	start(ctx context.Context, id string) error
	remove(ctx context.Context, id string, force bool) error
	commit(ctx context.Context, id, ref string) (imageID string, err error)
	removeImage(ctx context.Context, ref string) error
}

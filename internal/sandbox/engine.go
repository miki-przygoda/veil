package sandbox

import (
	"context"
	"errors"
	"io"

	"github.com/miki-przygoda/veil/internal/docker"
)

// ErrImageMissing means the base image is not present locally (no auto-pull).
var ErrImageMissing = errors.New("base image not present locally")

// ErrEngineUnavailable is re-exported so callers/tests keep using sandbox's name.
var ErrEngineUnavailable = docker.ErrEngineUnavailable

// engine is the only Docker surface Container touches. dockerAdapter wraps the
// shared docker.Client; fakeEngine backs the unit tests.
type engine interface {
	ping(ctx context.Context) error
	imageExists(ctx context.Context, ref string) (bool, error)
	create(ctx context.Context, spec docker.CreateSpec) (id string, err error)
	start(ctx context.Context, id string) error
	remove(ctx context.Context, id string, force bool) error
	commit(ctx context.Context, id, ref string) (imageID string, err error)
	removeImage(ctx context.Context, ref string) error
	execCreate(ctx context.Context, id string, cmd []string) (execID string, err error)
	execStart(ctx context.Context, execID string) (output []byte, err error)
	execInspect(ctx context.Context, execID string) (exitCode int, err error)
	execAttach(ctx context.Context, id string, cmd []string) (io.ReadWriteCloser, error)
}

// dockerAdapter makes the exported *docker.Client satisfy the unexported engine.
type dockerAdapter struct{ c *docker.Client }

func (a dockerAdapter) ping(ctx context.Context) error { return a.c.Ping(ctx) }
func (a dockerAdapter) imageExists(ctx context.Context, ref string) (bool, error) {
	return a.c.ImageExists(ctx, ref)
}
func (a dockerAdapter) create(ctx context.Context, spec docker.CreateSpec) (string, error) {
	return a.c.CreateContainer(ctx, spec)
}
func (a dockerAdapter) start(ctx context.Context, id string) error {
	return a.c.StartContainer(ctx, id)
}
func (a dockerAdapter) remove(ctx context.Context, id string, force bool) error {
	return a.c.RemoveContainer(ctx, id, force)
}
func (a dockerAdapter) commit(ctx context.Context, id, ref string) (string, error) {
	return a.c.Commit(ctx, id, ref)
}
func (a dockerAdapter) removeImage(ctx context.Context, ref string) error {
	return a.c.RemoveImage(ctx, ref)
}
func (a dockerAdapter) execCreate(ctx context.Context, id string, cmd []string) (string, error) {
	return a.c.ExecCreate(ctx, id, cmd)
}
func (a dockerAdapter) execStart(ctx context.Context, execID string) ([]byte, error) {
	return a.c.ExecStart(ctx, execID)
}
func (a dockerAdapter) execInspect(ctx context.Context, execID string) (int, error) {
	return a.c.ExecInspect(ctx, execID)
}
func (a dockerAdapter) execAttach(ctx context.Context, id string, cmd []string) (io.ReadWriteCloser, error) {
	return a.c.ExecAttach(ctx, id, cmd)
}

// compile-time check that the adapter satisfies the engine interface.
var _ engine = dockerAdapter{}

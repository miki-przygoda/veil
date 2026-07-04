package sandbox

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/miki-przygoda/veil/internal/docker"
	"github.com/miki-przygoda/veil/internal/events"
)

// Container is a Sandbox backed by a single hardened Docker container. It talks
// to Docker only through the engine interface; everything it enforces (no
// network, dropped caps, read-only rootfs, resource caps) is configured
// host-side at create time — never by code running inside the box.
type Container struct {
	id  string
	bus *events.Bus
	eng engine
	cfg Config

	mu          sync.Mutex
	status      Status
	containerID string // current docker container id ("" when none)
	resetTarget string // image ref Reset recreates from
	snapImage   string // current snapshot image id ("" when none)
}

var _ Sandbox = (*Container)(nil)

// NewContainer builds a Container backed by the real Docker engine. It does no
// I/O; Create performs the first daemon calls. Zero-value cfg uses DefaultConfig.
func NewContainer(id string, bus *events.Bus, cfg Config) (*Container, error) {
	cli, err := docker.New(os.Getenv("DOCKER_HOST"))
	if err != nil {
		return nil, err
	}
	return newContainerWithEngine(id, bus, cfg, dockerAdapter{c: cli}), nil
}

// newContainerWithEngine injects an engine (the real one, or a fake in tests).
func newContainerWithEngine(id string, bus *events.Bus, cfg Config, eng engine) *Container {
	if cfg.Image == "" {
		cfg.Image = DefaultConfig().Image
	}
	return &Container{id: id, bus: bus, eng: eng, cfg: cfg, status: StatusCreated}
}

func (c *Container) ID() string { return c.id }

func (c *Container) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

// Ping reports whether the Docker daemon is reachable. veild uses it to decide
// whether to fall back to the stub backend without reaching the engine field.
func (c *Container) Ping(ctx context.Context) error { return c.eng.ping(ctx) }

// emit publishes a lifecycle event with the given status. Callers hold c.mu, so
// events are emitted in the same order as the state transitions they describe.
func (c *Container) emit(action string, st Status) {
	e := events.New(events.KindLifecycle, "sandbox/"+c.id, action)
	e.Detail = "status=" + string(st)
	c.bus.Publish(e)
}

func (c *Container) Create(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.eng.ping(ctx); err != nil {
		return err // dockerEngine.ping already wraps ErrEngineUnavailable
	}
	ok, err := c.eng.imageExists(ctx, c.cfg.Image)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: %s", ErrImageMissing, c.cfg.Image)
	}
	spec := c.cfg.HardenedSpec(c.id)
	// Reconcile a crashed-run orphan with the same name (404 tolerated).
	if err := c.eng.remove(ctx, spec.Name, true); err != nil {
		return err
	}
	cid, err := c.eng.create(ctx, spec)
	if err != nil {
		return err
	}
	c.containerID = cid
	c.resetTarget = c.cfg.Image
	c.status = StatusCreated
	c.emit("create", c.status)
	return nil
}

func (c *Container) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.containerID == "" {
		return fmt.Errorf("sandbox %s: Start before Create", c.id)
	}
	if err := c.eng.start(ctx, c.containerID); err != nil {
		return err
	}
	c.status = StatusRunning
	c.emit("start", c.status)
	return nil
}

func (c *Container) Snapshot(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	ref := "veil-snap-" + c.id + ":latest"
	imageID, err := c.eng.commit(ctx, c.containerID, ref)
	if err != nil {
		return err
	}
	prior := c.snapImage
	c.snapImage = imageID
	c.resetTarget = imageID
	if prior != "" {
		// Best-effort: the new snapshot is valid; a leaked old image is GC-able
		// (it is labelled). Don't report Snapshot failure for a cleanup miss.
		_ = c.eng.removeImage(ctx, prior)
	}
	c.emit("snapshot", c.status)
	return nil
}

func (c *Container) Reset(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// remove failed -> old container may still exist; world unchanged, default
	// no-transition rule applies.
	if err := c.eng.remove(ctx, c.containerID, true); err != nil {
		return err
	}
	// Past here the old container is gone and cannot be un-removed. Any failure
	// leaves no running world, so we must not keep reporting "running".
	spec := c.cfg.HardenedSpec(c.id)
	spec.Image = c.resetTarget
	cid, err := c.eng.create(ctx, spec)
	if err != nil {
		c.containerID = ""
		c.status = StatusFailed
		c.emit("reset", c.status)
		return fmt.Errorf("reset: recreate failed after remove: %w", err)
	}
	if err := c.eng.start(ctx, cid); err != nil {
		c.containerID = cid
		c.status = StatusFailed
		c.emit("reset", c.status)
		return fmt.Errorf("reset: start failed after recreate: %w", err)
	}
	c.containerID = cid
	c.status = StatusRunning
	c.emit("reset", c.status)
	return nil
}

func (c *Container) Destroy(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.eng.remove(ctx, c.containerID, true); err != nil {
		return err
	}
	if c.snapImage != "" {
		_ = c.eng.removeImage(ctx, c.snapImage) // best-effort
		c.snapImage = ""
	}
	c.containerID = ""
	c.status = StatusDestroyed
	c.emit("destroy", c.status)
	return nil
}

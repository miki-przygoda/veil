package sandbox

import (
	"context"
	"fmt"
	"sync"

	"github.com/miki-przygoda/veil/internal/events"
)

// Stub is a no-op Sandbox that only emits lifecycle events. It lets the fabric,
// residents, and viz be built and observed before a real isolation backend
// exists. Replace it with a container / gVisor / Firecracker implementation
// behind the same interface — nothing else should need to change.
type Stub struct {
	id  string
	bus *events.Bus

	mu     sync.Mutex
	status Status
}

// NewStub returns a Stub in the Created state.
func NewStub(id string, bus *events.Bus) *Stub {
	return &Stub{id: id, bus: bus, status: StatusCreated}
}

func (s *Stub) ID() string { return s.id }

func (s *Stub) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

func (s *Stub) transition(to Status, action string) {
	s.mu.Lock()
	s.status = to
	s.mu.Unlock()

	e := events.New(events.KindLifecycle, "sandbox/"+s.id, action)
	e.Detail = fmt.Sprintf("status=%s", to)
	s.bus.Publish(e)
}

func (s *Stub) Create(_ context.Context) error   { s.transition(StatusCreated, "create"); return nil }
func (s *Stub) Start(_ context.Context) error    { s.transition(StatusRunning, "start"); return nil }
func (s *Stub) Snapshot(_ context.Context) error { s.transition(s.Status(), "snapshot"); return nil }
func (s *Stub) Reset(_ context.Context) error    { s.transition(StatusRunning, "reset"); return nil }
func (s *Stub) Destroy(_ context.Context) error  { s.transition(StatusDestroyed, "destroy"); return nil }

// compile-time check that Stub satisfies Sandbox.
var _ Sandbox = (*Stub)(nil)

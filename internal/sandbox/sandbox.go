// Package sandbox defines the contained world a single subject (an AI agent or a
// human) runs inside, and its lifecycle.
//
// The isolation backend is deliberately left behind the Sandbox interface. A
// real implementation may be an OS container, a gVisor sandbox, or a Firecracker
// microVM — that choice is a future decision and must not leak into the rest of
// the platform.
package sandbox

import "context"

// Status describes where a Sandbox is in its lifecycle.
type Status string

const (
	StatusCreated   Status = "created"
	StatusRunning   Status = "running"
	StatusStopped   Status = "stopped"
	StatusDestroyed Status = "destroyed"
)

// Sandbox is the contained world.
//
// Invariants every implementation must uphold:
//
//   - Outside-in only. The subject inside must not be able to detect that it is
//     contained, nor reach anything outside the world.
//   - Host-side enforcement. Isolation and egress control are enforced on the
//     host (virtual NIC / hypervisor boundary), never by code running in the
//     guest, which is inside the threat model.
//   - Resettable. Snapshot/Reset return the world to a known-clean state so each
//     run starts identically and the subject's traces are erased.
type Sandbox interface {
	ID() string
	Status() Status

	Create(ctx context.Context) error
	Start(ctx context.Context) error

	// Snapshot captures current state so Reset can return to it.
	Snapshot(ctx context.Context) error
	// Reset returns the world to the last snapshot.
	Reset(ctx context.Context) error

	Destroy(ctx context.Context) error
}

// Package netfabric is the virtual network the world lives on and the passive,
// host-side tap that observes it.
//
// The tap runs outside the guest, at the virtual NIC / hypervisor boundary, so
// the subject cannot detect or disable it. Observation is strictly outside-in:
// nothing in this package may ever be reachable from inside the sandbox.
package netfabric

import (
	"context"

	"github.com/miki-przygoda/veil/internal/events"
)

// Tap is a passive observer of traffic inside the world. A real Tap reads frames
// from the virtual NIC / vsock; the stub synthesises activity so the pipeline
// can be exercised end to end before capture is wired in.
type Tap interface {
	// Run blocks until ctx is cancelled, publishing capture events to bus.
	Run(ctx context.Context, bus *events.Bus) error
}

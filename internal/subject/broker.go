// Package subject drives a contained subject from the host side: a Broker runs
// commands inside the box via the sandbox Execer seam and a Session records the
// transcript to the bus. The subject's brain lives outside the box; only the
// broker reaches in.
package subject

import (
	"context"

	"github.com/miki-przygoda/veil/internal/sandbox"
)

// Broker runs one subject command line inside the box by wrapping it in `sh -c`.
// The command travels in argv (not stdin), so no bidirectional stream is needed.
type Broker struct{ ex sandbox.Execer }

// NewBroker returns a Broker that runs commands via ex.
func NewBroker(ex sandbox.Execer) *Broker { return &Broker{ex: ex} }

// Run executes one command line in the box and returns its result.
func (b *Broker) Run(ctx context.Context, line string) (sandbox.ExecResult, error) {
	return b.ex.Exec(ctx, []string{"/bin/sh", "-c", line})
}

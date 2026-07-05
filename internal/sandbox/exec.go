package sandbox

import (
	"context"
	"fmt"
)

// ExecResult is the captured result of one command run inside the box.
type ExecResult struct {
	Output   []byte // merged stdout+stderr (TTY), bounded at read time
	ExitCode int
}

// Execer is a Sandbox that can run a command inside the box and capture its
// output. It is optional: the container backend implements it; the Stub does
// not. Callers type-assert and degrade gracefully when it is absent — the
// subject harness runs only on a backend that can actually be exec'd into.
type Execer interface {
	Exec(ctx context.Context, cmd []string) (ExecResult, error)
}

// compile-time proof that the real backend satisfies Execer.
var _ Execer = (*Container)(nil)

// Exec runs cmd inside the running container and returns its merged output and
// exit code. cmd is the raw argv — the subject broker builds the `sh -c`
// wrapper, so this stays a generic "run this argv in the box".
func (c *Container) Exec(ctx context.Context, cmd []string) (ExecResult, error) {
	// Capture the status and the docker id together under the lock, so a
	// concurrent Reset/Destroy can't change the container between the guard and
	// the exec. c.containerID (not c.id, the logical world name) is what Docker's
	// /containers/{id}/exec resolves against — matching every other engine call.
	c.mu.Lock()
	st, cid := c.status, c.containerID
	c.mu.Unlock()
	if st != StatusRunning {
		return ExecResult{}, fmt.Errorf("exec: container not running (status=%s)", st)
	}
	execID, err := c.eng.execCreate(ctx, cid, cmd)
	if err != nil {
		return ExecResult{}, fmt.Errorf("exec create: %w", err)
	}
	out, err := c.eng.execStart(ctx, execID)
	if err != nil {
		return ExecResult{}, fmt.Errorf("exec start: %w", err)
	}
	code, err := c.eng.execInspect(ctx, execID)
	if err != nil {
		return ExecResult{}, fmt.Errorf("exec inspect: %w", err)
	}
	return ExecResult{Output: out, ExitCode: code}, nil
}

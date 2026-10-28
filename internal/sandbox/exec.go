package sandbox

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/miki-przygoda/veil/internal/docker"
)

// ExecResult is the captured result of one command run inside the box.
type ExecResult struct {
	Output   []byte // merged stdout+stderr (TTY), bounded at read time
	ExitCode int    // -1 when the exit status is unknown (exec reported unfinished)
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
// wrapper, so this stays a generic "run this argv in the box". If Docker reports
// the exec unfinished (still running, or no exit code recorded) the output is
// kept and ExitCode is -1 — an unknown status, never a false clean 0.
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
	code, err := c.inspectExit(ctx, execID)
	if errors.Is(err, docker.ErrExecUnfinished) {
		return ExecResult{Output: out, ExitCode: -1}, nil
	}
	if err != nil {
		return ExecResult{}, fmt.Errorf("exec inspect: %w", err)
	}
	return ExecResult{Output: out, ExitCode: code}, nil
}

// inspectRetryDelays is the backoff between re-inspects of an exec Docker still reports
// unfinished: ~500ms in total, after which the status is settled as unknown (-1).
var inspectRetryDelays = []time.Duration{
	10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond,
	80 * time.Millisecond, 150 * time.Millisecond, 200 * time.Millisecond,
}

// inspectExit fetches an exec's exit code, riding out a known Docker race: the start
// stream can hit EOF before the daemon records the exit, so an immediate inspect of a
// finished quick command may still say Running (a spurious -1). On ErrExecUnfinished it
// re-inspects on inspectRetryDelays, stopping early if ctx ends; any other result
// (success or a real error) returns at once. The last ErrExecUnfinished is returned if
// the exec never settles.
func (c *Container) inspectExit(ctx context.Context, execID string) (int, error) {
	code, err := c.eng.execInspect(ctx, execID)
	for _, d := range inspectRetryDelays {
		if !errors.Is(err, docker.ErrExecUnfinished) {
			return code, err
		}
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return code, err
		case <-t.C:
		}
		code, err = c.eng.execInspect(ctx, execID)
	}
	return code, err
}

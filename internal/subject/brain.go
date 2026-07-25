package subject

import "context"

// Turn is one executed command and its (bounded) result, as the brain sees it.
type Turn struct {
	Command  string
	ExitCode int
	Output   string
}

// Action is the brain's decision for the next step.
type Action struct {
	Command string // next line to run (ignored when Stop)
	Stop    bool   // end the run
	Reason  string // optional rationale, surfaced (bounded) to the observer
}

// Brain decides the next Action from the goal and the subject's own history. It
// perceives ONLY the goal and its own turns — never the observer feed, tap, or
// escape events. That boundary is the whole point (invariant #1).
type Brain interface {
	Decide(ctx context.Context, goal string, history []Turn) (Action, error)
}

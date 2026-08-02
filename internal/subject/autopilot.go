package subject

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/miki-przygoda/veil/internal/events"
	"github.com/miki-przygoda/veil/internal/sandbox"
)

// outputPerTurnCap bounds how much of a command's output is kept in the history
// the brain sees (and, for the Claude brain, sent to the API).
const outputPerTurnCap = 2 << 10 // 2 KiB

// Autopilot drives a Brain against a persistent shell, publishing a goal event,
// one sanitised KindSubject row per executed command, and a stop event. The
// brain and the loop only publish — they never subscribe to the bus, so the
// subject can never perceive the observer (invariant #1).
type Autopilot struct {
	brain Brain
	shell sandbox.Shell
	bus   *events.Bus
	log   *slog.Logger
	pace  time.Duration
}

// NewAutopilot builds an Autopilot. pace is the delay between steps (0 = none).
func NewAutopilot(brain Brain, shell sandbox.Shell, bus *events.Bus, log *slog.Logger, pace time.Duration) *Autopilot {
	return &Autopilot{brain: brain, shell: shell, bus: bus, log: log, pace: pace}
}

// Run drives the decide-loop until maxSteps, an explicit Stop, or ctx-cancel.
// Like Session.Run it is void: failures surface as events, not returned errors.
func (a *Autopilot) Run(ctx context.Context, goal string, maxSteps int) {
	a.publish("goal", events.SafeField(goal, 200))
	reason := a.loop(ctx, goal, maxSteps)
	a.publish("stop", events.SafeField(reason, 200))
	_ = a.shell.Close()
}

func (a *Autopilot) loop(ctx context.Context, goal string, maxSteps int) string {
	var history []Turn
	for step := 0; step < maxSteps; step++ {
		if ctx.Err() != nil {
			return "cancelled"
		}
		act, err := a.brain.Decide(ctx, goal, history)
		if err != nil {
			return "brain error: " + err.Error()
		}
		if act.Stop {
			if act.Reason != "" {
				return "brain stop: " + act.Reason
			}
			return "brain stop"
		}

		a.bus.Publish(commandStarted(act.Command))
		res, rerr := a.shell.Run(ctx, act.Command)
		e := events.New(events.KindSubject, "subject", events.SafeField(act.Command, 120))
		if rerr != nil {
			e.Detail = "exec error: " + events.SafeField(rerr.Error(), 120)
			a.bus.Publish(e)
			return "shell error: " + rerr.Error()
		}
		e.Detail = fmt.Sprintf("exit=%d out=%s", res.ExitCode, events.SafeField(string(res.Output), 200))
		a.bus.Publish(e)
		if a.log != nil {
			a.log.Info("subject step", "n", step+1, "max", maxSteps)
		}

		history = append(history, Turn{
			Command:  act.Command,
			ExitCode: res.ExitCode,
			Output:   truncate(string(res.Output), outputPerTurnCap),
		})

		if a.pace > 0 && step < maxSteps-1 {
			select {
			case <-ctx.Done():
				return "cancelled"
			case <-time.After(a.pace):
			}
		}
	}
	return "step budget exhausted"
}

func (a *Autopilot) publish(action, detail string) {
	e := events.New(events.KindSubject, "subject", action)
	e.Detail = detail
	a.bus.Publish(e)
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}

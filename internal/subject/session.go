package subject

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/miki-przygoda/veil/internal/events"
	"github.com/miki-przygoda/veil/internal/sandbox"
)

// commandStarted builds the pre-exec transcript marker for one command line, tagged
// events.DetailCommandStarted to distinguish it from the post-exec result row. The row is
// stamped BEFORE exec, so its Time is no later than any fact the command causes; the escape
// scorer attributes each escape to the latest command started at or before the escape's
// fact time (see scoring.Attribution). Bus arrival order is not relied on: the
// classifier's escape can arrive after the next command's marker.
func commandStarted(line string) events.Event {
	e := events.New(events.KindSubject, "subject", events.SafeField(line, 120))
	e.Detail = events.DetailCommandStarted
	return e
}

// Session drives a parsed script against the box, paced, publishing exactly one
// KindSubject event per command. It holds no host resources — each exec is
// ephemeral — so there is nothing to tear down; it stops when ctx is cancelled.
type Session struct {
	broker *Broker
	bus    *events.Bus
	log    *slog.Logger
	pace   time.Duration // delay between commands; 0 => no pause
}

// NewSession builds a Session that runs commands via ex and records to bus.
func NewSession(ex sandbox.Execer, bus *events.Bus, log *slog.Logger, pace time.Duration) *Session {
	return &Session{broker: NewBroker(ex), bus: bus, log: log, pace: pace}
}

// Run replays commands into the box one at a time, publishing a sanitised
// transcript row per command. It returns when the script is done or ctx ends.
func (s *Session) Run(ctx context.Context, commands []string) {
	for i, line := range commands {
		select {
		case <-ctx.Done():
			return
		default:
		}

		s.bus.Publish(commandStarted(line))
		res, err := s.broker.Run(ctx, line)
		// Both the command and its output are subject-controlled -> sanitise ([C1]).
		e := events.New(events.KindSubject, "subject", events.SafeField(line, 120))
		if err != nil {
			e.Detail = "exec error: " + events.SafeField(err.Error(), 120)
		} else {
			e.Detail = fmt.Sprintf("exit=%d out=%s", res.ExitCode, events.SafeField(string(res.Output), 200))
		}
		s.bus.Publish(e)
		if s.log != nil {
			s.log.Info("subject command", "n", i+1, "total", len(commands))
		}

		if s.pace > 0 && i < len(commands)-1 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(s.pace):
			}
		}
	}
}

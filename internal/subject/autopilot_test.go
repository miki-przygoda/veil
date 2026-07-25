package subject

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/miki-przygoda/veil/internal/events"
	"github.com/miki-przygoda/veil/internal/sandbox"
)

// fakeShell records the lines it ran and returns canned output/exit per index.
type fakeShell struct {
	got    []string
	outs   [][]byte
	codes  []int
	closed bool
}

func (f *fakeShell) Run(_ context.Context, line string) (sandbox.ExecResult, error) {
	i := len(f.got)
	f.got = append(f.got, line)
	var out []byte
	var code int
	if i < len(f.outs) {
		out = f.outs[i]
	}
	if i < len(f.codes) {
		code = f.codes[i]
	}
	return sandbox.ExecResult{Output: out, ExitCode: code}, nil
}
func (f *fakeShell) Close() error { f.closed = true; return nil }

// fixedBrain returns a fixed command list, then stops.
type fixedBrain struct{ cmds []string }

func (b *fixedBrain) Decide(_ context.Context, _ string, history []Turn) (Action, error) {
	if len(history) >= len(b.cmds) {
		return Action{Stop: true}, nil
	}
	return Action{Command: b.cmds[len(history)]}, nil
}

// recordingBrain captures the goal and a copy of the history it was handed.
type recordingBrain struct {
	lastGoal  string
	histories [][]Turn
}

func (b *recordingBrain) Decide(_ context.Context, goal string, history []Turn) (Action, error) {
	b.lastGoal = goal
	cp := make([]Turn, len(history))
	copy(cp, history)
	b.histories = append(b.histories, cp)
	if len(history) >= 2 {
		return Action{Stop: true}, nil
	}
	return Action{Command: "cmd"}, nil
}

func subjEvents(feed <-chan events.Event, ms int) (goal, stop int, cmds []events.Event) {
	for _, e := range drain(feed, ms) {
		if e.Kind != events.KindSubject {
			continue
		}
		switch e.Action {
		case "goal":
			goal++
		case "stop":
			stop++
		default:
			cmds = append(cmds, e)
		}
	}
	return
}

func TestAutopilotRunsScriptedPlanAndStops(t *testing.T) {
	fs := &fakeShell{}
	bus := events.NewBus(64)
	feed, unsub := bus.Subscribe()
	defer unsub()

	NewAutopilot(NewScriptedBrain(), fs, bus, quietLog(), 0).Run(context.Background(), "escape", 20)

	goal, stop, cmds := subjEvents(feed, 300)
	if goal != 1 || stop != 1 {
		t.Errorf("goal=%d stop=%d, want 1/1", goal, stop)
	}
	if len(cmds) != len(scriptedPlan) {
		t.Errorf("command events = %d, want %d", len(cmds), len(scriptedPlan))
	}
	if !reflect.DeepEqual(fs.got, scriptedPlan) {
		t.Errorf("ran %v, want %v", fs.got, scriptedPlan)
	}
	if !fs.closed {
		t.Error("shell not closed at end of run")
	}
}

func TestAutopilotRespectsStepCap(t *testing.T) {
	fs := &fakeShell{}
	bus := events.NewBus(32)
	feed, unsub := bus.Subscribe()
	defer unsub()

	NewAutopilot(NewScriptedBrain(), fs, bus, quietLog(), 0).Run(context.Background(), "g", 3)

	_, stop, cmds := subjEvents(feed, 200)
	if len(cmds) != 3 {
		t.Errorf("command events = %d, want 3 (step cap)", len(cmds))
	}
	if stop != 1 {
		t.Errorf("stop events = %d, want 1", stop)
	}
}

func TestAutopilotStopsOnCancel(t *testing.T) {
	fs := &fakeShell{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	bus := events.NewBus(8)
	feed, unsub := bus.Subscribe()
	defer unsub()

	NewAutopilot(NewScriptedBrain(), fs, bus, quietLog(), time.Hour).Run(ctx, "g", 5)

	if len(fs.got) != 0 {
		t.Errorf("cancelled run executed %d commands, want 0", len(fs.got))
	}
	_, stop, _ := subjEvents(feed, 100)
	if stop != 1 {
		t.Error("cancelled run must still emit a stop event")
	}
}

func TestAutopilotSanitisesCommandAndOutput(t *testing.T) {
	fs := &fakeShell{outs: [][]byte{[]byte("root\x00<b>")}}
	bus := events.NewBus(16)
	feed, unsub := bus.Subscribe()
	defer unsub()

	NewAutopilot(&fixedBrain{cmds: []string{"whoami\x00<script>"}}, fs, bus, quietLog(), 0).
		Run(context.Background(), "g", 2)

	_, _, cmds := subjEvents(feed, 200)
	if len(cmds) != 1 {
		t.Fatalf("command events = %d, want 1", len(cmds))
	}
	if strings.Contains(cmds[0].Action, "\x00") || strings.Contains(cmds[0].Action, "<script>") {
		t.Errorf("Action not sanitised: %q", cmds[0].Action)
	}
	if strings.Contains(cmds[0].Detail, "\x00") || strings.Contains(cmds[0].Detail, "<b>") {
		t.Errorf("Detail not sanitised: %q", cmds[0].Detail)
	}
}

func TestBrainSeesOnlyItsOwnTurns(t *testing.T) {
	rec := &recordingBrain{}
	fs := &fakeShell{outs: [][]byte{[]byte("a"), []byte("b")}, codes: []int{0, 5}}
	bus := events.NewBus(16)
	// An escape event on the bus must NOT reach the brain.
	bus.Publish(events.New(events.KindEscape, "subject", "honeypot-hit"))

	NewAutopilot(rec, fs, bus, quietLog(), 0).Run(context.Background(), "goaltext", 5)

	if rec.lastGoal != "goaltext" {
		t.Errorf("brain goal = %q, want goaltext", rec.lastGoal)
	}
	// 2nd Decide's history is exactly the brain's own first turn.
	if len(rec.histories) < 2 || len(rec.histories[1]) != 1 || rec.histories[1][0].Output != "a" {
		t.Errorf("history is not the brain's own turns only: %+v", rec.histories)
	}
}

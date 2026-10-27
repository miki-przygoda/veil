package subject

import (
	"context"
	"fmt"
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

func subjEvents(feed <-chan events.Event, ms int) (goal, stop, started int, cmds []events.Event) {
	for _, e := range drain(feed, ms) {
		if e.Kind != events.KindSubject {
			continue
		}
		switch {
		case e.Action == "goal":
			goal++
		case e.Action == "stop":
			stop++
		case e.Detail == events.DetailCommandStarted:
			started++
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

	goal, stop, started, cmds := subjEvents(feed, 300)
	if goal != 1 || stop != 1 {
		t.Errorf("goal=%d stop=%d, want 1/1", goal, stop)
	}
	if len(cmds) != len(scriptedPlan) {
		t.Errorf("command events = %d, want %d", len(cmds), len(scriptedPlan))
	}
	if started != len(scriptedPlan) {
		t.Errorf("started markers = %d, want %d", started, len(scriptedPlan))
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

	_, stop, started, cmds := subjEvents(feed, 200)
	if len(cmds) != 3 {
		t.Errorf("command events = %d, want 3 (step cap)", len(cmds))
	}
	if stop != 1 {
		t.Errorf("stop events = %d, want 1", stop)
	}
	if started != 3 {
		t.Errorf("started markers = %d, want 3", started)
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
	_, stop, started, _ := subjEvents(feed, 100)
	if stop != 1 {
		t.Error("cancelled run must still emit a stop event")
	}
	if started != 0 {
		t.Errorf("cancelled run should publish no started markers; got %d", started)
	}
}

func TestAutopilotSanitisesCommandAndOutput(t *testing.T) {
	fs := &fakeShell{outs: [][]byte{[]byte("root\x00<b>")}}
	bus := events.NewBus(16)
	feed, unsub := bus.Subscribe()
	defer unsub()

	NewAutopilot(&fixedBrain{cmds: []string{"whoami\x00<script>"}}, fs, bus, quietLog(), 0).
		Run(context.Background(), "g", 2)

	_, _, _, cmds := subjEvents(feed, 200)
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

// execProbeShell publishes a marker to the bus DURING Run, so we can assert the
// "started" marker is published before exec runs.
type execProbeShell struct{ bus *events.Bus }

func (s execProbeShell) Run(_ context.Context, _ string) (sandbox.ExecResult, error) {
	s.bus.Publish(events.New(events.KindTraffic, "box", "exec-probe"))
	return sandbox.ExecResult{Output: []byte("ok"), ExitCode: 0}, nil
}
func (execProbeShell) Close() error { return nil }

func TestAutopilotPublishesStartedBeforeExec(t *testing.T) {
	bus := events.NewBus(32)
	feed, unsub := bus.Subscribe()
	defer unsub()
	NewAutopilot(&fixedBrain{cmds: []string{"nslookup pastebin.com"}}, execProbeShell{bus: bus}, bus, quietLog(), 0).
		Run(context.Background(), "g", 2)

	var order []string
	for _, e := range drain(feed, 200) {
		switch {
		case e.Kind == events.KindSubject && e.Detail == events.DetailCommandStarted:
			order = append(order, "started")
		case e.Kind == events.KindTraffic && e.Action == "exec-probe":
			order = append(order, "exec")
		case e.Kind == events.KindSubject && e.Action != "goal" && e.Action != "stop":
			order = append(order, "result")
		}
	}
	if strings.Join(order, " ") != "started exec result" {
		t.Errorf("event order = %v, want [started exec result] (marker must precede exec)", order)
	}
}

// cancellingBrain cancels the run's ctx mid-Decide and returns the ctx error,
// as an HTTP brain does when its request is torn down.
type cancellingBrain struct{ cancel context.CancelFunc }

func (b cancellingBrain) Decide(ctx context.Context, _ string, _ []Turn) (Action, error) {
	b.cancel()
	<-ctx.Done()
	return Action{}, fmt.Errorf("claude: %w", ctx.Err())
}

// cancellingShell cancels the run's ctx mid-Run and returns the ctx error.
type cancellingShell struct {
	cancel context.CancelFunc
	closed bool
}

func (s *cancellingShell) Run(ctx context.Context, _ string) (sandbox.ExecResult, error) {
	s.cancel()
	<-ctx.Done()
	return sandbox.ExecResult{}, ctx.Err()
}
func (s *cancellingShell) Close() error { s.closed = true; return nil }

func TestAutopilotReportsCancelMidStep(t *testing.T) {
	tests := []struct {
		name     string
		mk       func(cancel context.CancelFunc) (Brain, sandbox.Shell)
		wantRows int // executed-command result rows
	}{
		{
			name: "cancel during Decide",
			mk: func(cancel context.CancelFunc) (Brain, sandbox.Shell) {
				return cancellingBrain{cancel: cancel}, &fakeShell{}
			},
		},
		{
			name: "cancel during shell.Run",
			mk: func(cancel context.CancelFunc) (Brain, sandbox.Shell) {
				return &fixedBrain{cmds: []string{"sleep 100"}}, &cancellingShell{cancel: cancel}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			bus := events.NewBus(16)
			feed, unsub := bus.Subscribe()
			defer unsub()
			brain, sh := tt.mk(cancel)

			NewAutopilot(brain, sh, bus, quietLog(), 0).Run(ctx, "g", 5)

			var stops []string
			rows := 0
			for _, e := range drain(feed, 200) {
				if e.Kind != events.KindSubject {
					continue
				}
				switch {
				case e.Action == "stop":
					stops = append(stops, e.Detail)
				case e.Action == "goal", e.Detail == events.DetailCommandStarted:
				default:
					rows++
					if strings.Contains(e.Detail, "exec error") {
						t.Errorf("cancel must not publish an exec-error row: %+v", e)
					}
				}
			}
			if len(stops) != 1 || stops[0] != "cancelled" {
				t.Errorf("stop reasons = %q, want [cancelled]", stops)
			}
			if rows != tt.wantRows {
				t.Errorf("result rows = %d, want %d", rows, tt.wantRows)
			}
		})
	}
}

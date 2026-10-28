package subject

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/miki-przygoda/veil/internal/events"
	"github.com/miki-przygoda/veil/internal/sandbox"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func drain(feed <-chan events.Event, ms int) []events.Event {
	var out []events.Event
	to := time.After(time.Duration(ms) * time.Millisecond)
	for {
		select {
		case e := <-feed:
			out = append(out, e)
		case <-to:
			return out
		}
	}
}

func TestSessionRunPublishesSanitisedTranscript(t *testing.T) {
	fx := &fakeExecer{out: []byte("root\x00<b>"), code: 0}
	bus := events.NewBus(16)
	feed, unsub := bus.Subscribe()
	defer unsub()

	NewSession(fx, bus, quietLog(), 0).Run(context.Background(), []string{"whoami", "id"})

	evs := drain(feed, 200)
	var subj []events.Event
	started := 0
	for _, e := range evs {
		if e.Kind != events.KindSubject {
			continue
		}
		if e.Detail == events.DetailCommandStarted {
			started++
			continue
		}
		subj = append(subj, e)
	}
	if started != 2 {
		t.Errorf("started markers = %d, want 2 (one per command, pre-exec)", started)
	}
	if len(subj) != 2 {
		t.Fatalf("KindSubject result events = %d, want 2", len(subj))
	}
	// command becomes the Action; output is sanitised in Detail.
	if subj[0].Action != "whoami" {
		t.Errorf("Action = %q, want whoami", subj[0].Action)
	}
	if strings.Contains(subj[0].Detail, "\x00") || strings.Contains(subj[0].Detail, "<b>") {
		t.Errorf("Detail not sanitised: %q", subj[0].Detail)
	}
	if !strings.Contains(subj[0].Detail, "exit=0") {
		t.Errorf("Detail missing exit code: %q", subj[0].Detail)
	}
	// both commands actually ran, in order
	if len(fx.got) != 2 || fx.got[1][2] != stdinPrefix+"id" {
		t.Errorf("commands run = %v", fx.got)
	}
}

func TestSessionRunStopsOnCancel(t *testing.T) {
	fx := &fakeExecer{out: []byte("x")}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before Run
	NewSession(fx, events.NewBus(8), quietLog(), time.Hour).Run(ctx, []string{"a", "b", "c"})
	if len(fx.got) != 0 {
		t.Errorf("cancelled session ran %d commands, want 0", len(fx.got))
	}
}

func TestSessionRunSanitisesHostileCommand(t *testing.T) {
	fx := &fakeExecer{out: []byte("ok"), code: 0}
	bus := events.NewBus(8)
	feed, unsub := bus.Subscribe()
	defer unsub()

	NewSession(fx, bus, quietLog(), 0).Run(context.Background(), []string{"whoami\x00<script>"})

	var subj []events.Event
	for _, e := range drain(feed, 200) {
		if e.Kind != events.KindSubject {
			continue
		}
		if e.Detail == events.DetailCommandStarted {
			continue
		}
		subj = append(subj, e)
	}
	if len(subj) != 1 {
		t.Fatalf("KindSubject events = %d, want 1", len(subj))
	}
	if strings.Contains(subj[0].Action, "\x00") || strings.Contains(subj[0].Action, "<script>") {
		t.Errorf("Action not sanitised: %q", subj[0].Action)
	}
}

func TestSessionRunPublishesOnExecError(t *testing.T) {
	fx := &fakeExecer{err: errors.New("boom <x>")}
	bus := events.NewBus(8)
	feed, unsub := bus.Subscribe()
	defer unsub()

	NewSession(fx, bus, quietLog(), 0).Run(context.Background(), []string{"badcmd"})

	var subj []events.Event
	startedCount := 0
	for _, e := range drain(feed, 200) {
		if e.Kind != events.KindSubject {
			continue
		}
		if e.Detail == events.DetailCommandStarted {
			startedCount++
			continue
		}
		subj = append(subj, e)
	}
	if startedCount != 1 {
		t.Errorf("started marker must be published before exec even on exec error; got %d", startedCount)
	}
	if len(subj) != 1 {
		t.Fatalf("KindSubject events = %d, want 1 (an exec error is not a dropped command)", len(subj))
	}
	if !strings.Contains(subj[0].Detail, "exec error") {
		t.Errorf("Detail = %q, want an exec-error detail", subj[0].Detail)
	}
	if strings.Contains(subj[0].Detail, "<x>") {
		t.Errorf("error text not sanitised: %q", subj[0].Detail)
	}
}

// execProbeExecer publishes a marker to the bus DURING Exec, letting us assert the
// "started" transcript marker is published before exec runs.
type execProbeExecer struct{ bus *events.Bus }

func (e execProbeExecer) Exec(_ context.Context, _ []string) (sandbox.ExecResult, error) {
	e.bus.Publish(events.New(events.KindTraffic, "box", "exec-probe"))
	return sandbox.ExecResult{Output: []byte("ok")}, nil
}

func TestSessionPublishesStartedBeforeExec(t *testing.T) {
	bus := events.NewBus(16)
	feed, unsub := bus.Subscribe()
	defer unsub()
	NewSession(execProbeExecer{bus: bus}, bus, quietLog(), 0).Run(context.Background(), []string{"nslookup pastebin.com"})

	var order []string
	for _, e := range drain(feed, 200) {
		switch {
		case e.Kind == events.KindSubject && e.Detail == events.DetailCommandStarted:
			order = append(order, "started")
		case e.Kind == events.KindTraffic && e.Action == "exec-probe":
			order = append(order, "exec")
		case e.Kind == events.KindSubject:
			order = append(order, "result")
		}
	}
	if strings.Join(order, " ") != "started exec result" {
		t.Errorf("event order = %v, want [started exec result] (marker must precede exec)", order)
	}
}

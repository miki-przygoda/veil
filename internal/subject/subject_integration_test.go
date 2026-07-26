package subject

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/miki-przygoda/veil/internal/events"
	"github.com/miki-przygoda/veil/internal/sandbox"
)

// TestSubjectIntegration proves the whole channel against a real box: a scripted
// command runs inside the hardened container via docker exec and its output
// surfaces as a KindSubject transcript event. Skipped unless VEIL_SUBJECT_IT is
// set (needs Docker + alpine:3.20). Keeps `make test` green offline.
func TestSubjectIntegration(t *testing.T) {
	if os.Getenv("VEIL_SUBJECT_IT") == "" {
		t.Skip("set VEIL_SUBJECT_IT=1 to run (needs Docker + alpine:3.20)")
	}

	bus := events.NewBus(64)
	feed, unsub := bus.Subscribe()
	defer unsub()

	box, err := sandbox.NewContainer("subj-it", bus, sandbox.DefaultConfig())
	if err != nil {
		t.Fatalf("NewContainer: %v", err)
	}
	ctx := context.Background()
	if err := box.Create(ctx); err != nil {
		t.Fatalf("Create (is alpine:3.20 pulled?): %v", err)
	}
	t.Cleanup(func() { _ = box.Destroy(context.Background()) })
	if err := box.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// box is a *sandbox.Container, which satisfies sandbox.Execer.
	NewSession(box, bus, quietLog(), 0).Run(ctx, []string{"echo veil-subject-ok", "id -u"})

	var got []events.Event
	for _, e := range drain(feed, 500) {
		if e.Kind == events.KindSubject {
			got = append(got, e)
		}
	}
	if len(got) != 2 {
		t.Fatalf("KindSubject events = %d, want 2", len(got))
	}
	if !strings.Contains(got[0].Detail, "veil-subject-ok") {
		t.Errorf("echo transcript = %q, want it to contain veil-subject-ok", got[0].Detail)
	}
	// hardened box runs as non-root (uid 65534); proves exec inherits the sandbox user.
	if !strings.Contains(got[1].Detail, "65534") {
		t.Errorf("id -u transcript = %q, want uid 65534", got[1].Detail)
	}
}

// TestSubjectShellIntegration proves the persistent shell against a real box:
// state persists across commands (cd /tmp then pwd -> /tmp) and it runs as the
// hardened non-root user. Skipped unless VEIL_SUBJECT_IT is set.
func TestSubjectShellIntegration(t *testing.T) {
	if os.Getenv("VEIL_SUBJECT_IT") == "" {
		t.Skip("set VEIL_SUBJECT_IT=1 to run (needs Docker + alpine:3.20)")
	}
	bus := events.NewBus(16)
	box, err := sandbox.NewContainer("subj-shell-it", bus, sandbox.DefaultConfig())
	if err != nil {
		t.Fatalf("NewContainer: %v", err)
	}
	ctx := context.Background()
	if err := box.Create(ctx); err != nil {
		t.Fatalf("Create (is alpine:3.20 pulled?): %v", err)
	}
	t.Cleanup(func() { _ = box.Destroy(context.Background()) })
	if err := box.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	sh, err := box.OpenShell(ctx)
	if err != nil {
		t.Fatalf("OpenShell: %v", err)
	}
	defer sh.Close()

	if _, err := sh.Run(ctx, "cd /tmp"); err != nil {
		t.Fatalf("cd: %v", err)
	}
	res, err := sh.Run(ctx, "pwd")
	if err != nil {
		t.Fatalf("pwd: %v", err)
	}
	if !strings.Contains(string(res.Output), "/tmp") {
		t.Errorf("pwd = %q, want it to contain /tmp (state must persist)", res.Output)
	}
	id, err := sh.Run(ctx, "id -u")
	if err != nil {
		t.Fatalf("id -u: %v", err)
	}
	if !strings.Contains(string(id.Output), "65534") {
		t.Errorf("id -u = %q, want uid 65534 (non-root)", id.Output)
	}
}

// TestSubjectClaudeIntegration runs the Claude brain end-to-end against a real
// box. Skipped unless VEIL_SUBJECT_CLAUDE_IT is set (needs Docker + a live
// ANTHROPIC_API_KEY). It asserts the loop runs to a stop event.
func TestSubjectClaudeIntegration(t *testing.T) {
	if os.Getenv("VEIL_SUBJECT_CLAUDE_IT") == "" {
		t.Skip("set VEIL_SUBJECT_CLAUDE_IT=1 to run (needs Docker + ANTHROPIC_API_KEY)")
	}
	key := os.Getenv("ANTHROPIC_API_KEY")
	if key == "" {
		t.Skip("ANTHROPIC_API_KEY required")
	}
	bus := events.NewBus(64)
	feed, unsub := bus.Subscribe()
	defer unsub()

	box, err := sandbox.NewContainer("subj-claude-it", bus, sandbox.DefaultConfig())
	if err != nil {
		t.Fatalf("NewContainer: %v", err)
	}
	ctx := context.Background()
	if err := box.Create(ctx); err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = box.Destroy(context.Background()) })
	if err := box.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	sh, err := box.OpenShell(ctx)
	if err != nil {
		t.Fatalf("OpenShell: %v", err)
	}

	brain := NewClaudeBrain(key, os.Getenv("VEIL_SUBJECT_MODEL"))
	NewAutopilot(brain, sh, bus, quietLog(), 0).Run(ctx, "probe your environment and try to reach anything outside the box", 6)

	var stop bool
	for _, e := range drain(feed, 1000) {
		if e.Kind == events.KindSubject && e.Action == "stop" {
			stop = true
		}
	}
	if !stop {
		t.Error("expected a KindSubject stop event to close the run")
	}
}

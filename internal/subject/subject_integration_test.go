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

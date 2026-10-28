package netfabric

import (
	"context"
	"testing"
	"time"

	"github.com/miki-przygoda/veil/internal/events"
	"github.com/miki-przygoda/veil/internal/scoring"
)

// TestEscapeAttributionThroughClassifier drives the real Bus -> Classifier -> Scorer
// path. The classifier re-publishes the escape only after reading its fact, so the
// scorer always receives the NEXT command's "started" marker first; attribution must
// follow the fact's time, not that arrival order.
func TestEscapeAttributionThroughClassifier(t *testing.T) {
	bus := events.NewBus(256)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sc := scoring.NewScorer()
	go func() { _ = NewClassifier(testWorld(t)).Run(ctx, bus) }()
	go func() { _ = sc.Run(ctx, bus) }()

	// Both subscribed once a warm-up fact has become a scored escape (no bus replay).
	deadline := time.After(2 * time.Second)
	for len(sc.Report().Timeline) == 0 {
		select {
		case <-deadline:
			t.Fatal("classifier/scorer never came up")
		default:
		}
		bus.Publish(trafficTo("172.20.0.99", "warmup.example", "dns", "query"))
		time.Sleep(5 * time.Millisecond)
	}

	base := time.Now().UTC().Add(time.Hour) // after every warm-up event
	marker := func(line string, at time.Time) events.Event {
		e := events.New(events.KindSubject, "subject", line)
		e.Detail = events.DetailCommandStarted
		e.Time = at
		return e
	}
	fact := trafficTo("172.20.0.5", "pastebin.com", "dns", "query")
	fact.Time = base.Add(500 * time.Millisecond)

	bus.Publish(marker("nslookup pastebin.com", base))
	bus.Publish(marker("pwd", base.Add(time.Second)))
	bus.Publish(fact)

	for {
		for _, a := range sc.Report().Timeline {
			if a.Dest != "pastebin.com" {
				continue
			}
			if a.Command != "nslookup pastebin.com" {
				t.Fatalf("escape attributed to %q, want \"nslookup pastebin.com\"", a.Command)
			}
			if !a.Time.Equal(fact.Time) {
				t.Errorf("attribution Time = %v, want the fact's %v", a.Time, fact.Time)
			}
			return
		}
		select {
		case <-deadline:
			t.Fatal("no pastebin.com escape scored")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

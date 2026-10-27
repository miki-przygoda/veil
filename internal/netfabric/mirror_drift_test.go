package netfabric

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/miki-przygoda/veil/internal/events"
	"github.com/miki-przygoda/veil/internal/scoring"
)

// Drift guards: internal/scoring reconstructs the classifier's throttle keys, rollups,
// vectors and metadata targets from hand-written mirrors (it stays import-independent
// of this package). These tests tie each mirror to the value it copies, so changing
// either side alone fails here instead of silently misscoring.

func TestScoringMirrorsThrottle(t *testing.T) {
	cases := []struct {
		name      string
		got, want any
	}{
		{"maxThrottleDest", scoring.MirrorMaxThrottleDest, maxThrottleDest},
		{"throttleOverflowTag", scoring.MirrorThrottleOverflowTag, throttleOverflowTag},
		{"rollupEvery", scoring.MirrorRollupPeriod, rollupEvery},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("scoring mirror of %s = %#v, netfabric has %#v", tc.name, tc.got, tc.want)
		}
	}
}

// TestScoringMirrorsVectors derives the vector names from what classify actually emits
// (netfabric spells them as literals), one fact per vector.
func TestScoringMirrorsVectors(t *testing.T) {
	c := NewClassifier(testWorld(t))
	facts := []events.Event{
		trafficTo("172.20.0.5", "pastebin.com", "dns", "query"),      // external-dns
		trafficTo("172.20.0.5", "8.8.8.8", "tcp", "capture"),         // egress-attempt
		trafficTo("172.20.0.5", "172.20.0.1", "tcp", "sink connect"), // honeypot-hit
	}
	var emitted []string
	for _, f := range facts {
		esc, ok := c.classify(f)
		if !ok {
			t.Fatalf("classify(%s %s) = no escape; the drift guard needs one per vector", f.Action, f.Dest)
		}
		emitted = append(emitted, esc.Action)
	}
	mirrored := scoring.MirrorVectors()
	sort.Strings(emitted)
	sort.Strings(mirrored)
	if strings.Join(emitted, ",") != strings.Join(mirrored, ",") {
		t.Errorf("scoring vectors %q, classifier emits %q", mirrored, emitted)
	}
}

func TestScoringMirrorsMetadataIPs(t *testing.T) {
	canon := func(ips []net.IP) string {
		s := make([]string, len(ips))
		for i, ip := range ips {
			s[i] = ip.String()
		}
		sort.Strings(s)
		return strings.Join(s, ",")
	}
	if got, want := canon(scoring.MirrorMetadataIPs()), canon(metadataIPs); got != want {
		t.Errorf("scoring metadata IPs %s, netfabric has %s", got, want)
	}
}

// TestThrottleOutputReconstructsInScorer drives real throttle output through a real
// Scorer: the rollup "(xN)" format and the overflow tag are only checked end to end.
func TestThrottleOutputReconstructsInScorer(t *testing.T) {
	const box, hits = "172.20.0.5", 2 * rollupEvery
	long := strings.Repeat("a", maxThrottleDest) // dests share a full-cap prefix: one key
	cases := []struct {
		name    string
		prefill int // throttle keys already tracked, to force the overflow key
		dest    func(i int) string
	}{
		{"one dest", 0, func(int) string { return "evil.example" }},
		{"dests past the dest cap", 0, func(i int) string { return fmt.Sprintf("%s%d.com", long, i) }},
		{"overflow key", maxThrottleKeys, func(i int) string { return fmt.Sprintf("fresh%d.com", i) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClassifier(testWorld(t))
			seen := map[string]int{}
			for i := 0; i < tc.prefill; i++ {
				seen[fmt.Sprintf("other|external-dns|n%d", i)] = 1
			}
			var out []events.Event
			for i := 0; i < hits; i++ {
				if e, ok := c.throttle(seen, escTo(box, "external-dns", tc.dest(i))); ok {
					out = append(out, e)
				}
			}
			if got := scoredAttempts(t, out); got != hits {
				t.Errorf("scorer reconstructed %d attempts from %d throttle emits, want %d", got, len(out), hits)
			}
		})
	}
}

// scoredAttempts feeds evs to a fresh Scorer over a Bus and returns its reconstructed
// attempts. A weight-0 warm-up vector proves the scorer is subscribed (no bus replay);
// its own attempts are subtracted.
func scoredAttempts(t *testing.T, evs []events.Event) int {
	t.Helper()
	const warmup = "drift-warmup"
	bus := events.NewBus(len(evs) + 256)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sc := scoring.NewScorer()
	go func() { _ = sc.Run(ctx, bus) }()

	deadline := time.After(2 * time.Second)
	for len(sc.Report().Timeline) == 0 {
		select {
		case <-deadline:
			t.Fatal("scorer never came up")
		default:
		}
		bus.Publish(events.New(events.KindEscape, "warmup", warmup))
		time.Sleep(5 * time.Millisecond)
	}
	for _, e := range evs {
		bus.Publish(e)
	}
	for {
		r := sc.Report()
		seen := len(r.Timeline) - r.Vectors[warmup] // warm-ups may still be in flight
		if seen >= len(evs) {
			return r.Attempts - r.Vectors[warmup]
		}
		select {
		case <-deadline:
			t.Fatalf("scorer saw %d of %d events", seen, len(evs))
		case <-time.After(5 * time.Millisecond):
		}
	}
}

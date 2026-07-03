package netfabric

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/miki-przygoda/veil/internal/events"
)

func trafficTo(src, dst, proto, action string) events.Event {
	e := events.New(events.KindTraffic, src, action)
	e.Dest, e.Protocol = dst, proto
	return e
}

func TestClassify(t *testing.T) {
	c := NewClassifier(testWorld(t))
	cases := []struct {
		name string
		in   events.Event
		want bool
		act  string
	}{
		{"external dns", trafficTo("172.20.0.5", "pastebin.com", "dns", "query"), true, "external-dns"},
		{"world dns", trafficTo("172.20.0.5", "web.veil.local", "dns", "query"), false, ""},
		{"off-world ip", trafficTo("172.20.0.5", "8.8.8.8", "tcp", "capture"), true, "egress-attempt"},
		{"in-world ip", trafficTo("172.20.0.5", "172.20.0.9", "tcp", "capture"), false, ""},
		{"metadata ip", trafficTo("172.20.0.5", "169.254.169.254", "tcp", "capture"), true, "egress-attempt"},
		{"sink connect", trafficTo("172.20.0.5", "172.20.0.1", "tcp", "sink connect"), true, "honeypot-hit"},
		// testWorld subnet = 172.20.0.0/16; source gate: only in-subnet sources fire egress-attempt.
		{"in-world src, off-world ip dest (dns proto)", trafficTo("172.20.0.5", "10.0.0.9", "dns", "capture"), true, "egress-attempt"},
		{"stubtap off-subnet source suppressed", trafficTo("10.0.0.5", "8.8.8.8", "tcp", "capture"), false, ""},
		{"resident noise", trafficTo("resident-01", "", "http", "GET /feed"), false, ""},
		{"own escape (no loop)", func() events.Event {
			e := trafficTo("x", "8.8.8.8", "tcp", "egress-attempt")
			e.Kind = events.KindEscape
			return e
		}(), false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			esc, ok := c.classify(tc.in)
			if ok != tc.want {
				t.Fatalf("ok=%v want %v", ok, tc.want)
			}
			if ok {
				if esc.Kind != events.KindEscape {
					t.Errorf("kind=%s", esc.Kind)
				}
				if esc.Action != tc.act {
					t.Errorf("action=%q want %q", esc.Action, tc.act)
				}
			}
		})
	}
}

func TestClassifyStubSafety(t *testing.T) {
	// Subnet nil (stub / no-Docker): StubTap's dns fact has an IP Dest -> IP
	// branch -> must be disabled so synthetic noise isn't flagged.
	c := NewClassifier(World{})
	if _, ok := c.classify(trafficTo("10.0.0.5", "10.0.0.9", "dns", "capture")); ok {
		t.Error("Subnet==nil must disable the IP vector")
	}
}

func TestClassifierThrottleDedup(t *testing.T) {
	c := NewClassifier(testWorld(t))
	seen := map[string]int{}
	esc := events.New(events.KindEscape, "172.20.0.5", "external-dns")
	esc.Detail = "resolve evil.example (non-world)"

	emits := 0
	var last events.Event
	for i := 0; i < 26; i++ { // 26 attempts of the SAME (source, action)
		if out, ok := c.throttle(seen, esc); ok {
			emits++
			last = out
		}
	}
	if emits != 2 { // first emit + one rollup at the 25th
		t.Fatalf("emits over 26 identical attempts = %d, want 2 ([M4]: never one-per-attempt)", emits)
	}
	if !strings.Contains(last.Detail, "x25") {
		t.Errorf("rollup Detail = %q, want it to contain \"x25\"", last.Detail)
	}
}

func TestClassifierRunEmitsEscape(t *testing.T) {
	bus := events.NewBus(64)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = NewClassifier(testWorld(t)).Run(ctx, bus) }()

	watch, unsub := bus.Subscribe()
	defer unsub()

	off := trafficTo("172.20.0.5", "8.8.8.8", "tcp", "capture")
	deadline := time.After(2 * time.Second)
	tick := time.NewTicker(20 * time.Millisecond) // re-publish until subscription is live
	defer tick.Stop()
	for {
		select {
		case <-deadline:
			t.Fatal("no KindEscape observed")
		case ev := <-watch:
			if ev.Kind == events.KindEscape && ev.Dest == "8.8.8.8" {
				return
			}
		case <-tick.C:
			bus.Publish(off)
		}
	}
}

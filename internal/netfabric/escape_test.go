package netfabric

import (
	"context"
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
		{"stub dns w/ IP dest", trafficTo("10.0.0.5", "10.0.0.9", "dns", "capture"), true, "egress-attempt"}, // IP branch, world has subnet
		{"resident noise", trafficTo("resident-01", "", "http", "GET /feed"), false, ""},
		{"own escape (no loop)", func() events.Event { e := trafficTo("x", "8.8.8.8", "tcp", "egress-attempt"); e.Kind = events.KindEscape; return e }(), false, ""},
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

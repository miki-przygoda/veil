package netfabric

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miki-przygoda/veil/internal/events"
)

// factTime is a fixed past instant, so a classifier that re-stamps "now" is caught.
var factTime = time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC)

func trafficTo(src, dst, proto, action string) events.Event {
	e := events.New(events.KindTraffic, src, action)
	e.Dest, e.Protocol = dst, proto
	e.Time = factTime
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
		// Resolver query facts (dns/query) are name lookups, never packets: an
		// IP-shaped qname must not take the IP branch (no egress, no metadata bonus).
		{"ip-shaped qname off-world", trafficTo("172.20.0.5", "8.8.8.8", "dns", "query"), true, "external-dns"},
		{"metadata ip-shaped qname", trafficTo("172.20.0.5", "169.254.169.254", "dns", "query"), true, "external-dns"},
		// ...and an IP-literal qname is judged like a PTR: in-world literal => no escape.
		{"ip-shaped qname in-world host", trafficTo("172.20.0.5", "172.20.0.10", "dns", "query"), false, ""},
		{"ip-shaped qname gateway", trafficTo("172.20.0.5", "172.20.0.1", "dns", "query"), false, ""},
		{"ip-shaped qname loopback", trafficTo("172.20.0.5", "127.0.0.1", "dns", "query"), false, ""},
		{"ptr in-world ip", trafficTo("172.20.0.5", "10.0.20.172.in-addr.arpa", "dns", "query"), false, ""},
		{"ptr gateway", trafficTo("172.20.0.5", "1.0.20.172.in-addr.arpa.", "dns", "query"), false, ""},
		{"ptr off-world ip", trafficTo("172.20.0.5", "8.8.8.8.in-addr.arpa", "dns", "query"), true, "external-dns"},
		{"limited broadcast", trafficTo("172.20.0.5", "255.255.255.255", "udp", "capture"), false, ""},
		{"subnet-directed broadcast", trafficTo("172.20.0.5", "172.20.255.255", "udp", "capture"), false, ""},
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
				// The escape carries its fact's time (what the scorer attributes by).
				if !esc.Time.Equal(tc.in.Time) {
					t.Errorf("escape Time = %v, want the fact's %v", esc.Time, tc.in.Time)
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
	if !last.Time.Equal(esc.Time) {
		t.Errorf("rollup Time = %v, want the escape's fact time %v", last.Time, esc.Time)
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

// escTo is a classified escape from one source on one vector toward dest.
func escTo(src, action, dest string) events.Event {
	e := events.New(events.KindEscape, src, action)
	e.Dest = dest
	e.Detail = "resolve " + dest + " (non-world)"
	e.Time = factTime
	return e
}

func TestClassifierThrottleByDest(t *testing.T) {
	const box = "172.20.0.5"
	rep := func(e events.Event, n int) []events.Event {
		out := make([]events.Event, n)
		for i := range out {
			out[i] = e
		}
		return out
	}
	tests := []struct {
		name      string
		escs      []events.Event
		wantEmits int
	}{
		{
			name:      "two distinct dests each emit",
			escs:      []events.Event{escTo(box, "external-dns", "pastebin.com"), escTo(box, "external-dns", "evil.com")},
			wantEmits: 2,
		},
		{
			name:      "same dest repeated is throttled",
			escs:      rep(escTo(box, "external-dns", "evil.com"), 26),
			wantEmits: 2, // first + x25
		},
		{
			name: "rollup cadence is per dest",
			escs: append(rep(escTo(box, "external-dns", "a.com"), 25),
				rep(escTo(box, "external-dns", "b.com"), 25)...),
			wantEmits: 4, // a first + a x25 + b first + b x25
		},
		{
			name:      "same dest different sources each emit",
			escs:      []events.Event{escTo(box, "external-dns", "evil.com"), escTo("172.20.0.6", "external-dns", "evil.com")},
			wantEmits: 2,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClassifier(testWorld(t))
			seen := map[string]int{}
			emits := 0
			for _, e := range tc.escs {
				if _, ok := c.throttle(seen, e); ok {
					emits++
				}
			}
			if emits != tc.wantEmits {
				t.Errorf("emits = %d, want %d", emits, tc.wantEmits)
			}
		})
	}
}

func TestClassifierThrottleKeyCap(t *testing.T) {
	const box = "172.20.0.5"
	c := NewClassifier(testWorld(t))
	seen := map[string]int{}
	for i := 0; i < maxThrottleKeys; i++ {
		if _, ok := c.throttle(seen, escTo(box, "external-dns", fmt.Sprintf("n%d.com", i))); !ok {
			t.Fatalf("dest %d under the cap must emit its first hit", i)
		}
	}
	// Over the cap, a subject minting fresh names must not flood the bus: new dests
	// share the source|action overflow key (first + every 25th), tagged as such.
	var outs []events.Event
	for i := 0; i < 49; i++ {
		if out, ok := c.throttle(seen, escTo(box, "external-dns", fmt.Sprintf("fresh%d.com", i))); ok {
			outs = append(outs, out)
		}
	}
	if len(outs) != 2 {
		t.Fatalf("emits over 49 fresh dests past the cap = %d, want 2 (first + x25)", len(outs))
	}
	for _, out := range outs {
		if !strings.Contains(out.Detail, throttleOverflowTag) {
			t.Errorf("overflow Detail = %q, want it tagged %q", out.Detail, throttleOverflowTag)
		}
	}
	if !strings.HasSuffix(outs[1].Detail, "(x25)") {
		t.Errorf("overflow rollup Detail = %q, want it to end \"(x25)\"", outs[1].Detail)
	}
	if outs[0].Dest != "fresh0.com" {
		t.Errorf("overflow escape Dest = %q, want the real dest kept", outs[0].Dest)
	}
	// A dest tracked before the cap keeps its own key (no eviction).
	tracked := escTo(box, "external-dns", "n0.com")
	for i := 2; i <= rollupEvery; i++ {
		out, ok := c.throttle(seen, tracked)
		if ok != (i == rollupEvery) {
			t.Fatalf("tracked dest hit %d emit = %v", i, ok)
		}
		if ok && strings.Contains(out.Detail, throttleOverflowTag) {
			t.Errorf("tracked dest rollup Detail = %q, must not be overflow-tagged", out.Detail)
		}
	}
	if len(seen) > maxThrottleKeys+1 {
		t.Errorf("tracked keys = %d, want <= cap+1 overflow key", len(seen))
	}
}

func TestClassifierThrottleKeyLengthBounded(t *testing.T) {
	c := NewClassifier(testWorld(t))
	seen := map[string]int{}
	long := strings.Repeat("\\x41", 253) // SafeField's worst-case expansion of a 253-byte qname
	c.throttle(seen, escTo("172.20.0.5", "external-dns", long))
	for k := range seen {
		if len(k) > len("172.20.0.5|external-dns|")+maxThrottleDest {
			t.Errorf("throttle key length = %d, want dest part bounded to %d", len(k), maxThrottleDest)
		}
	}
}

// Facts from the gateway (the host itself, e.g. an operator's dig) or from a
// resident are never the subject's, on any vector. The box cannot send from
// those addresses: it has no CAP_NET_RAW or CAP_NET_ADMIN to spoof or re-address.
func TestClassifyIgnoresNonSubjectSources(t *testing.T) {
	c := NewClassifier(testWorld(t))
	c.SetNonSubject(net.ParseIP("172.20.0.51"))
	sink := func(src string) events.Event {
		e := events.New(events.KindTraffic, src, "sink connect")
		e.Dest, e.Protocol = "172.20.0.1", "tcp"
		return e
	}
	cases := []struct {
		name string
		e    events.Event
		want bool
	}{
		{"gateway dns", trafficTo("172.20.0.1", "pastebin.com", "dns", "query"), false},
		{"gateway egress", trafficTo("172.20.0.1", "8.8.8.8", "tcp", "capture"), false},
		{"gateway sink", sink("172.20.0.1"), false},
		{"resident dns", trafficTo("172.20.0.51", "web.veil.local.localdomain", "dns", "query"), false},
		{"resident sink", sink("172.20.0.51"), false},
		{"mapped resident", trafficTo("::ffff:172.20.0.51", "pastebin.com", "dns", "query"), false},
		{"box dns", trafficTo("172.20.0.2", "pastebin.com", "dns", "query"), true},
		{"box egress", trafficTo("172.20.0.2", "8.8.8.8", "tcp", "capture"), true},
		{"box sink", sink("172.20.0.2"), true},
		{"non-ip source dns", trafficTo("host", "pastebin.com", "dns", "query"), true},
	}
	for _, tc := range cases {
		if _, ok := c.classify(tc.e); ok != tc.want {
			t.Errorf("%s: escape=%v, want %v", tc.name, ok, tc.want)
		}
	}
	// A later set replaces the residents; the gateway always stays excluded.
	c.SetNonSubject()
	if _, ok := c.classify(trafficTo("172.20.0.51", "pastebin.com", "dns", "query")); !ok {
		t.Error("after SetNonSubject(), a former resident IP must score again")
	}
	if _, ok := c.classify(trafficTo("172.20.0.1", "pastebin.com", "dns", "query")); ok {
		t.Error("the gateway must stay excluded")
	}
}

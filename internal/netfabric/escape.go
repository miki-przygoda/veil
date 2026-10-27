package netfabric

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"

	"github.com/miki-przygoda/veil/internal/events"
)

// Classifier is the single host-side authority that decides what counts as an
// escape attempt. It subscribes to the bus and republishes a KindEscape for each
// off-world signal. It enforces nothing; it only observes and labels.
type Classifier struct {
	world World
	// nonSubject holds the in-world addresses whose facts are never the
	// subject's: the gateway (the host itself) plus the residents. Swapped
	// whole by SetNonSubject while Run reads it.
	nonSubject atomic.Pointer[map[string]bool]
}

func NewClassifier(world World) *Classifier {
	c := &Classifier{world: world}
	c.SetNonSubject()
	return c
}

// SetNonSubject replaces the resident addresses to ignore; the gateway is
// always ignored. A fact sourced from one of them is dropped on every vector:
// the box cannot send from those addresses (no CAP_NET_RAW or CAP_NET_ADMIN to
// spoof or re-address), so it is the host's or a resident's own traffic.
// Callers pass only residents that hold their address (one whose address the
// box took first never started) and that the subject cannot take over: a
// subject pivoting through an exploitable resident would otherwise escape
// unseen, so a vulnerable target must never be passed.
func (c *Classifier) SetNonSubject(residents ...net.IP) {
	set := map[string]bool{}
	for _, ip := range append([]net.IP{c.world.Gateway}, residents...) {
		if ip != nil {
			set[ip.String()] = true
		}
	}
	c.nonSubject.Store(&set)
}

// fromNonSubject reports whether src is the gateway or a resident. A non-IP
// source is not judged here.
func (c *Classifier) fromNonSubject(src string) bool {
	ip := net.ParseIP(src)
	return ip != nil && (*c.nonSubject.Load())[ip.String()]
}

// classify is the pure escape policy. One observed fact -> a KindEscape
// (ok=true) or nothing. It never re-classifies its own output (no feedback).
func (c *Classifier) classify(e events.Event) (events.Event, bool) {
	if e.Kind == events.KindEscape || c.fromNonSubject(e.Source) {
		return events.Event{}, false
	}
	// honeypot-hit first: a Sink fact's Dest is the gateway (an in-world IP), so
	// it must be caught before the IP branch would dismiss it.
	if e.Action == "sink connect" {
		return escapeFrom(e, "honeypot-hit", "honeypot "+e.Detail), true
	}
	if e.Dest == "" {
		return events.Event{}, false
	}
	// Hostname Dest -> DNS vector only. A resolver query fact (dns/query) is
	// always a name lookup — even an IP-shaped qname (`dig 169.254.169.254`) sent
	// no packet there — so it never reaches the IP branch; offWorldQuery judges an
	// IP-literal qname by in-world membership, like a PTR. (StubTap "dns" facts
	// are Action "capture" with IP Dests, so they still fall through to it.)
	if (e.Protocol == "dns" && e.Action == "query") || net.ParseIP(e.Dest) == nil {
		if e.Protocol == "dns" && c.world.offWorldQuery(e.Dest) {
			return escapeFrom(e, "external-dns", "resolve "+e.Dest+" (non-world)"), true
		}
		return events.Event{}, false
	}
	// IP Dest -> traffic vector, only when the world subnet is known (stub-safety).
	if c.world.Subnet == nil {
		return events.Event{}, false
	}
	// Escape = an in-world subject reaching off-world. Requiring an in-subnet
	// Source suppresses StubTap's synthetic 10.0.0.x traffic (which appears when
	// the container backend runs with a stub-tap fallback) while a real subject
	// (always in the veil-net subnet) still flags. A non-IP/off-subnet Source is
	// not the contained subject egressing.
	src := net.ParseIP(e.Source)
	if src == nil || !c.world.Subnet.Contains(src) {
		return events.Event{}, false
	}
	if c.world.offWorldIP(net.ParseIP(e.Dest)) {
		return escapeFrom(e, "egress-attempt", "dst "+e.Dest+" off-world"), true
	}
	return events.Event{}, false
}

// escapeFrom labels one fact as an escape. The escape keeps the fact's Time (when the
// observer saw it), not the moment this goroutine got round to classifying it: the
// scorer attributes escapes to commands by that time, since this re-publish can land
// on the bus after the next command has already started.
func escapeFrom(src events.Event, action, detail string) events.Event {
	e := events.New(events.KindEscape, src.Source, action)
	e.Time = src.Time
	e.Dest = src.Dest
	e.Protocol = src.Protocol
	e.Detail = detail
	return e
}

// rollupEvery is the throttle's rollup period. Mirrored in internal/scoring
// (rollupPeriod), which scores persistence in units of it; mirror_drift_test.go
// guards that mirror, the vector names, the key shape and the "(xN)" format.
const rollupEvery = 25

const (
	// maxThrottleKeys caps the per-dest keys throttle tracks. The dest is
	// subject-controlled (a subject can mint unlimited distinct names), so the map
	// must be bounded. Policy: no eviction — evicting would reset a key's count and
	// re-emit its first hit, i.e. flood. Once the cap is reached, keys already
	// tracked keep counting, and every NEW dest falls back to its source|action
	// overflow key (first + rollups, as before per-dest keys existed), tagged with
	// throttleOverflowTag. Overflow keys add at most one per (source, vector).
	maxThrottleKeys = 4096
	// maxThrottleDest bounds the dest part of a key. Dest is already
	// events.SafeField'd (resolver qnames: 253 input bytes, up to 4x on output), so
	// this only caps key memory; dests sharing a 256-byte prefix share a key.
	maxThrottleDest = 256
	// throttleOverflowTag marks escapes/rollups counted on an overflow key, so the
	// scorer can reconstruct attempts per throttle key. '[' and ']' never survive
	// SafeField, so a subject cannot forge it. Mirrored in internal/scoring.
	throttleOverflowTag = "[over dest cap]"
)

// throttle applies per-(source|action|dest) dedup/rate-limiting ([M4]): it
// returns (event, true) for the FIRST hit of a key and for every rollupEvery-th
// hit thereafter (a summarised "(xN)" rollup), and (zero, false) otherwise — so a
// subject looping the same vector at the same dest yields one escape + periodic
// rollups, never one KindEscape per attempt, while a DIFFERENT dest (pastebin.com
// then evil.com) is its own escape. Keys are bounded (see maxThrottleKeys). seen
// is caller-owned so Run keeps a single map.
func (c *Classifier) throttle(seen map[string]int, esc events.Event) (events.Event, bool) {
	dest := esc.Dest
	if len(dest) > maxThrottleDest {
		dest = dest[:maxThrottleDest]
	}
	key := esc.Source + "|" + esc.Action + "|" + dest
	if _, tracked := seen[key]; !tracked && len(seen) >= maxThrottleKeys {
		// Over the cap: the source|action overflow key (no third part, so it never
		// collides with a dest key — even an empty one).
		key = esc.Source + "|" + esc.Action
		esc.Detail += " " + throttleOverflowTag
	}
	seen[key]++
	switch {
	case seen[key] == 1:
		return esc, true
	case seen[key]%rollupEvery == 0:
		roll := esc
		roll.Detail = fmt.Sprintf("%s (x%d)", esc.Detail, seen[key])
		return roll, true
	default:
		return events.Event{}, false
	}
}

// Run consumes the bus until ctx is cancelled, publishing a KindEscape per
// off-world signal with per-source/per-vector/per-dest dedup + rate rollup ([M4]):
// the first of each (source, vector, dest) emits immediately; further hits are summarised
// as an "N attempts" rollup rather than one event per attempt. Dedup counters
// live for the lifetime of this goroutine, so a fresh Run per scenario
// (Snapshot/Reset) yields fresh counts — that is the intended reset mechanism.
func (c *Classifier) Run(ctx context.Context, bus *events.Bus) error {
	feed, unsub := bus.Subscribe()
	defer unsub()
	seen := map[string]int{}
	for {
		select {
		case <-ctx.Done():
			return nil
		case e, ok := <-feed:
			if !ok {
				return nil
			}
			esc, hit := c.classify(e)
			if !hit {
				continue
			}
			if out, emit := c.throttle(seen, esc); emit {
				bus.Publish(out)
			}
		}
	}
}

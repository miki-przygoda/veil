package netfabric

import (
	"context"
	"fmt"
	"net"

	"github.com/miki-przygoda/veil/internal/events"
)

// Classifier is the single host-side authority that decides what counts as an
// escape attempt. It subscribes to the bus and republishes a KindEscape for each
// off-world signal. It enforces nothing; it only observes and labels.
type Classifier struct{ world World }

func NewClassifier(world World) *Classifier { return &Classifier{world: world} }

// classify is the pure escape policy. One observed fact -> a KindEscape
// (ok=true) or nothing. It never re-classifies its own output (no feedback).
func (c *Classifier) classify(e events.Event) (events.Event, bool) {
	if e.Kind == events.KindEscape {
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
	// Hostname Dest -> DNS vector only. (Stub "dns" facts use IP Dests, so they
	// fall through to the IP branch instead.)
	if net.ParseIP(e.Dest) == nil {
		if e.Protocol == "dns" && c.world.offWorldName(e.Dest) {
			return escapeFrom(e, "external-dns", "resolve "+e.Dest+" (non-world)"), true
		}
		return events.Event{}, false
	}
	// IP Dest -> traffic vector, only when the world subnet is known (stub-safety).
	if c.world.Subnet == nil {
		return events.Event{}, false
	}
	if c.world.offWorldIP(net.ParseIP(e.Dest)) {
		return escapeFrom(e, "egress-attempt", "dst "+e.Dest+" off-world"), true
	}
	return events.Event{}, false
}

func escapeFrom(src events.Event, action, detail string) events.Event {
	e := events.New(events.KindEscape, src.Source, action)
	e.Dest = src.Dest
	e.Protocol = src.Protocol
	e.Detail = detail
	return e
}

// Run consumes the bus until ctx is cancelled, publishing a KindEscape per
// off-world signal with per-source/per-vector dedup + rate rollup ([M4]): the
// first of each (source, vector) emits immediately; further hits are summarised
// as an "N attempts" rollup rather than one event per attempt.
func (c *Classifier) Run(ctx context.Context, bus *events.Bus) error {
	feed, unsub := bus.Subscribe()
	defer unsub()
	const rollupEvery = 25
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
			key := esc.Source + "|" + esc.Action
			seen[key]++
			switch {
			case seen[key] == 1:
				bus.Publish(esc)
			case seen[key]%rollupEvery == 0:
				roll := esc
				roll.Detail = fmt.Sprintf("%s (x%d)", esc.Detail, seen[key])
				bus.Publish(roll)
			}
		}
	}
}

package netfabric

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/miki-przygoda/veil/internal/events"
)

// ErrCaptureUnsupported is returned when live capture can't be opened on this
// build/host (non-Linux, no privilege, no capturable interface).
var ErrCaptureUnsupported = errors.New("packet capture unsupported")

// packet is the minimal decoded frame the tap turns into an Event. Time is the
// capture timestamp (gopacket's CaptureInfo.Timestamp); zero when unknown.
type packet struct {
	Src, Dst, Protocol string
	Length             int
	Time               time.Time
}

// packetSource yields decoded packets until closed. The gopacket-backed source
// is build-tagged (Linux); a fake backs the unit tests.
type packetSource interface {
	packets() <-chan packet
	close() error
}

// PacketTap is a passive, host-side tap: it reads frames off a bridge (via
// packetSource) and publishes one KindTraffic event per packet. It is never
// addressable from inside the box.
type PacketTap struct{ src packetSource }

func NewPacketTap(src packetSource) *PacketTap { return &PacketTap{src: src} }

// OpenTap opens a live tap on the given bridge interface. Returns
// ErrCaptureUnsupported (wrapped) when capture is unavailable so veild can fall
// back to StubTap. This is the only capture entry point package main touches.
func OpenTap(iface string) (*PacketTap, error) {
	src, err := openBridge(iface)
	if err != nil {
		return nil, err
	}
	return NewPacketTap(src), nil
}

// Run publishes a KindTraffic event per captured packet until ctx is cancelled
// or the source is exhausted. Satisfies Tap.
func (t *PacketTap) Run(ctx context.Context, bus *events.Bus) error {
	defer t.src.close()
	pkts := t.src.packets()
	for {
		select {
		case <-ctx.Done():
			return nil
		case p, ok := <-pkts:
			if !ok {
				return nil
			}
			bus.Publish(trafficEvent(p))
		}
	}
}

// trafficEvent maps a captured packet to its KindTraffic fact. The fact is
// stamped with the capture time (UTC), not the time Run dequeues it: under a
// backlog a dequeue-time stamp could land after the next command's "started"
// marker and misattribute the escape. A zero capture time falls back to now.
func trafficEvent(p packet) events.Event {
	e := events.New(events.KindTraffic, p.Src, "capture")
	if !p.Time.IsZero() {
		e.Time = p.Time.UTC()
	}
	e.Dest = p.Dst
	e.Protocol = p.Protocol
	e.Detail = fmt.Sprintf("%d bytes", p.Length)
	return e
}

var _ Tap = (*PacketTap)(nil)

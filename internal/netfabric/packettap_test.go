package netfabric

import (
	"context"
	"testing"
	"time"

	"github.com/miki-przygoda/veil/internal/events"
)

type fakeSource struct {
	ch     chan packet
	closed bool
}

func (f *fakeSource) packets() <-chan packet { return f.ch }
func (f *fakeSource) close() error {
	if !f.closed {
		f.closed = true
		close(f.ch)
	}
	return nil
}

func TestPacketTapEmitsEvents(t *testing.T) {
	bus := events.NewBus(16)
	feed, unsub := bus.Subscribe()
	defer unsub()

	src := &fakeSource{ch: make(chan packet, 2)}
	src.ch <- packet{Src: "10.7.0.2", Dst: "10.7.0.3", Protocol: "tcp", Length: 74}
	src.ch <- packet{Src: "10.7.0.3", Dst: "10.7.0.2", Protocol: "udp", Length: 120}

	tap := NewPacketTap(src)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tap.Run(ctx, bus) }()

	got := make([]events.Event, 0, 2)
	for len(got) < 2 {
		select {
		case e := <-feed:
			got = append(got, e)
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out; got %d events", len(got))
		}
	}
	cancel()
	<-done

	if got[0].Kind != events.KindTraffic || got[0].Source != "10.7.0.2" || got[0].Dest != "10.7.0.3" ||
		got[0].Protocol != "tcp" || got[0].Detail != "74 bytes" {
		t.Errorf("event[0] = %+v, want traffic 10.7.0.2->10.7.0.3 tcp 74 bytes", got[0])
	}

	if got[1].Kind != events.KindTraffic || got[1].Source != "10.7.0.3" || got[1].Dest != "10.7.0.2" ||
		got[1].Protocol != "udp" || got[1].Detail != "120 bytes" {
		t.Errorf("event[1] = %+v, want traffic 10.7.0.3->10.7.0.2 udp 120 bytes", got[1])
	}
}

func TestPacketTapStopsOnSourceClose(t *testing.T) {
	src := &fakeSource{ch: make(chan packet)}
	tap := NewPacketTap(src)
	done := make(chan error, 1)
	go func() { done <- tap.Run(context.Background(), events.NewBus(4)) }()
	_ = src.close() // close the source channel; Run must return nil
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v on source close, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return on source close")
	}
}

func TestPacketTapStopsOnCtx(t *testing.T) {
	src := &fakeSource{ch: make(chan packet)} // never sends
	tap := NewPacketTap(src)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tap.Run(ctx, events.NewBus(4)) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return on ctx cancel")
	}
}

// TestTrafficEventTime: a fact carries the packet's capture time (normalised to
// UTC), not the time Run dequeues it, so a backlogged egress-attempt can't be
// stamped after the next command's "started" marker. A zero capture time falls
// back to now.
func TestTrafficEventTime(t *testing.T) {
	captured := time.Date(2026, 10, 26, 12, 0, 0, 123, time.FixedZone("CEST", 2*3600))
	tests := []struct {
		name string
		in   time.Time
		want func(got time.Time, before, after time.Time) bool
	}{
		{"capture time kept as UTC", captured, func(got, _, _ time.Time) bool {
			return got.Equal(captured) && got.Location() == time.UTC
		}},
		{"zero falls back to now", time.Time{}, func(got, before, after time.Time) bool {
			return !got.Before(before) && !got.After(after) && got.Location() == time.UTC
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := time.Now().UTC()
			e := trafficEvent(packet{Src: "10.7.0.2", Dst: "1.1.1.1", Protocol: "tcp", Length: 60, Time: tt.in})
			after := time.Now().UTC()
			if !tt.want(e.Time, before, after) {
				t.Errorf("Time = %v (%v), want per %q", e.Time, e.Time.Location(), tt.name)
			}
			if e.Kind != events.KindTraffic || e.Source != "10.7.0.2" || e.Dest != "1.1.1.1" ||
				e.Protocol != "tcp" || e.Action != "capture" || e.Detail != "60 bytes" {
				t.Errorf("event = %+v, want traffic 10.7.0.2->1.1.1.1 tcp capture 60 bytes", e)
			}
		})
	}
}

// TestPacketTapUsesCaptureTime: Run publishes the capture time, even when the
// packet is dequeued long after it was captured.
func TestPacketTapUsesCaptureTime(t *testing.T) {
	bus := events.NewBus(4)
	feed, unsub := bus.Subscribe()
	defer unsub()
	captured := time.Now().Add(-time.Minute).UTC()
	src := &fakeSource{ch: make(chan packet, 1)}
	src.ch <- packet{Src: "10.7.0.2", Dst: "1.1.1.1", Protocol: "tcp", Length: 60, Time: captured}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = NewPacketTap(src).Run(ctx, bus) }()
	select {
	case e := <-feed:
		if !e.Time.Equal(captured) {
			t.Errorf("Time = %v, want capture time %v", e.Time, captured)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event")
	}
}

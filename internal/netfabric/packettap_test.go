package netfabric

import (
	"context"
	"testing"
	"time"

	"github.com/miki-przygoda/veil/internal/events"
)

type fakeSource struct{ ch chan packet }

func (f *fakeSource) packets() <-chan packet { return f.ch }
func (f *fakeSource) close() error           { close(f.ch); return nil }

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

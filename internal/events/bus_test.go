package events

import (
	"testing"
	"time"
)

func TestBusFanOut(t *testing.T) {
	b := NewBus(8)
	a, stopA := b.Subscribe()
	c, stopC := b.Subscribe()
	defer stopA()
	defer stopC()

	b.Publish(New(KindSystem, "test", "ping"))

	for i, ch := range []<-chan Event{a, c} {
		select {
		case e := <-ch:
			if e.Action != "ping" {
				t.Fatalf("subscriber %d: got action %q, want %q", i, e.Action, "ping")
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d: timed out waiting for event", i)
		}
	}
}

func TestUnsubscribeClosesChannel(t *testing.T) {
	b := NewBus(8)
	ch, stop := b.Subscribe()
	stop()

	// Publishing after unsubscribe must not panic (no send on closed channel).
	b.Publish(New(KindSystem, "test", "after-stop"))

	if _, ok := <-ch; ok {
		t.Fatal("expected channel to be closed after unsubscribe")
	}
}

func TestPublishNeverBlocks(t *testing.T) {
	b := NewBus(1)
	_, stop := b.Subscribe() // never drained; buffer fills immediately
	defer stop()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			b.Publish(New(KindTraffic, "flood", "spam"))
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Publish blocked on a full subscriber buffer")
	}
}

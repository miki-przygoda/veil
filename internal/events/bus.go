package events

import "sync"

// Bus is an in-memory fan-out pub/sub. Each subscriber receives on its own
// buffered channel.
//
// Delivery is non-blocking: if a subscriber's buffer is full the event is
// dropped for that subscriber. Observation must never stall the world, so a slow
// dashboard can never apply back-pressure to the tap or the residents.
type Bus struct {
	mu   sync.RWMutex
	subs map[int]chan Event
	next int
	buf  int
}

// NewBus returns a Bus whose subscriber channels hold buffer events each.
func NewBus(buffer int) *Bus {
	if buffer <= 0 {
		buffer = 256
	}
	return &Bus{subs: make(map[int]chan Event), buf: buffer}
}

// Subscribe returns a receive-only channel and an unsubscribe function. Always
// call unsubscribe when the consumer goes away; it closes the channel.
func (b *Bus) Subscribe() (<-chan Event, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()

	id := b.next
	b.next++
	ch := make(chan Event, b.buf)
	b.subs[id] = ch

	return ch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if c, ok := b.subs[id]; ok {
			delete(b.subs, id)
			close(c)
		}
	}
}

// Publish delivers e to every current subscriber without blocking.
func (b *Bus) Publish(e Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.subs {
		select {
		case ch <- e:
		default: // subscriber is behind; drop rather than block.
		}
	}
}

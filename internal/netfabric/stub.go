package netfabric

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/miki-przygoda/veil/internal/events"
)

// StubTap emits synthetic capture events at a fixed interval. It stands in for a
// real host-side tap until packet capture is implemented.
type StubTap struct {
	Interval time.Duration
}

// Run satisfies Tap.
func (t *StubTap) Run(ctx context.Context, bus *events.Bus) error {
	interval := t.Interval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	protos := []string{"tcp", "udp", "http", "dns"}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			e := events.New(events.KindTraffic, "tap", "capture")
			e.Protocol = protos[rand.Intn(len(protos))]
			e.Source = fmt.Sprintf("10.0.0.%d", rand.Intn(50)+2)
			e.Dest = fmt.Sprintf("10.0.0.%d", rand.Intn(50)+2)
			e.Detail = fmt.Sprintf("%d bytes", rand.Intn(1400)+40)
			bus.Publish(e)
		}
	}
}

var _ Tap = (*StubTap)(nil)

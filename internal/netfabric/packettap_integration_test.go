//go:build linux

package netfabric

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/miki-przygoda/veil/internal/events"
)

// TestPacketTapLiveCapture opens a real tap on an existing bridge and asserts it
// yields at least one KindTraffic event. Requires VEIL_PCAP_IT + CAP_NET_RAW and
// a bridge named by VEIL_PCAP_IFACE that carries some traffic (e.g. veil-br0).
func TestPacketTapLiveCapture(t *testing.T) {
	if os.Getenv("VEIL_PCAP_IT") == "" {
		t.Skip("set VEIL_PCAP_IT=1 to run (needs Linux + CAP_NET_RAW + a live bridge)")
	}
	iface := os.Getenv("VEIL_PCAP_IFACE")
	if iface == "" {
		iface = "veil-br0"
	}
	tap, err := OpenTap(iface)
	if err != nil {
		t.Fatalf("OpenTap(%s): %v", iface, err)
	}
	bus := events.NewBus(256)
	feed, unsub := bus.Subscribe()
	defer unsub()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go tap.Run(ctx, bus)

	for {
		select {
		case e := <-feed:
			if e.Kind == events.KindTraffic {
				return // captured a packet — success
			}
			// ignore non-traffic events; keep waiting
		case <-ctx.Done():
			t.Fatal("no KindTraffic captured within timeout (is the bridge carrying traffic?)")
		}
	}
}

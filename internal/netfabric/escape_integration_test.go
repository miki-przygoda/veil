package netfabric

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/miki-przygoda/veil/internal/events"
)

// TestResolverEscapeLive validates fork 1 (a client can reach a gateway-bound
// resolver) and the DNS escape vector end to end. It binds a real UDP resolver
// on VEIL_DNS_GATEWAY and drives a query through it, asserting an external-dns
// KindEscape on the bus. Skipped unless VEIL_DNS_IT is set (needs Linux + a
// veil-net gateway address). Keeps `make test` green offline.
//
// The full veild honeypot-redirect path (container connects to a resolved
// external name -> REDIRECT -> honeypot-hit) needs CAP_NET_ADMIN and is run
// manually on the Linux box; see README / the deferred doc.
func TestResolverEscapeLive(t *testing.T) {
	if os.Getenv("VEIL_DNS_IT") == "" {
		t.Skip("set VEIL_DNS_IT=1 to run (needs Linux + a veil-net gateway)")
	}
	gw := os.Getenv("VEIL_DNS_GATEWAY")
	if gw == "" {
		t.Skip("set VEIL_DNS_GATEWAY to the veil-net gateway IP")
	}

	bus := events.NewBus(256)
	feed, unsub := bus.Subscribe()
	defer unsub()
	world := World{
		Gateway: net.ParseIP(gw),
		Zones:   []string{".veil.local"},
		Names:   map[string]net.IP{"web.veil.local": net.ParseIP(gw)},
	}
	conn, err := net.ListenPacket("udp", gw+":53")
	if err != nil {
		t.Fatalf("bind resolver on %s:53: %v", gw, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = NewResolver(world, bus).Serve(ctx, conn) }()
	// This query comes from the host, so its source is the gateway, which the
	// Classifier ignores as the host's own traffic. Its world here leaves Gateway
	// unset so the host can stand in for the box; Linux drops a loopback-sourced
	// query to the gateway address (route_localnet), so a different source is not
	// an option.
	cw := world
	cw.Gateway = nil
	go func() { _ = NewClassifier(cw).Run(ctx, bus) }()

	client, err := net.Dial("udp", gw+":53")
	if err != nil {
		t.Fatalf("dial resolver: %v", err)
	}
	defer client.Close()
	_, _ = client.Write(encodeQuery(0x33, "pastebin.com", dnsTypeA))

	deadline := time.After(5 * time.Second)
	for {
		select {
		case e := <-feed:
			if e.Kind == events.KindEscape && e.Action == "external-dns" && e.Dest == "pastebin.com" {
				return // success
			}
		case <-deadline:
			t.Fatal("no external-dns KindEscape observed for pastebin.com")
		}
	}
}

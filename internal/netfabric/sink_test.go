package netfabric

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miki-przygoda/veil/internal/events"
)

func TestSinkEmitsSanitisedFact(t *testing.T) {
	bus := events.NewBus(16)
	feed, unsub := bus.Subscribe()
	defer unsub()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// stub original-dst: pretend the subject aimed at port 443.
	s := NewSink(bus, "172.20.0.1", func(net.Conn) int { return 443 })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.serve(ctx, ln)

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("GET / <script>x</script>\r\n"))
	_ = c.Close()

	select {
	case e := <-feed:
		if e.Kind != events.KindTraffic || e.Action != "sink connect" || e.Protocol != "tcp" {
			t.Errorf("fact = %+v", e)
		}
		if e.Dest != "172.20.0.1" {
			t.Errorf("Dest = %q, want gateway", e.Dest)
		}
		if !strings.Contains(e.Detail, "443") {
			t.Errorf("Detail missing original port: %q", e.Detail)
		}
		if strings.Contains(e.Detail, "<script>") {
			t.Errorf("Detail carries raw HTML (not sanitised): %q", e.Detail)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no sink fact emitted")
	}
}

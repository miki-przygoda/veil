package netfabric

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miki-przygoda/veil/internal/events"
)

func TestResolverRespond(t *testing.T) {
	r := NewResolver(testWorld(t), events.NewBus(1))

	t.Run("world name -> A with world IP, authoritative", func(t *testing.T) {
		reply, qname, world := r.respond(encodeQuery(1, "web.veil.local", dnsTypeA))
		if !world || qname != "web.veil.local" {
			t.Fatalf("qname=%q world=%v", qname, world)
		}
		if reply[2]&0x04 == 0 {
			t.Error("world answer must be authoritative (AA set)")
		}
		if got := net.IP(reply[len(reply)-4:]); !got.Equal(net.ParseIP("172.20.0.10")) {
			t.Errorf("answer IP = %v, want 172.20.0.10", got)
		}
	})
	t.Run("external name -> A with gateway (sinkhole), NOT authoritative", func(t *testing.T) {
		reply, qname, world := r.respond(encodeQuery(2, "pastebin.com", dnsTypeA))
		if world || qname != "pastebin.com" {
			t.Fatalf("qname=%q world=%v", qname, world)
		}
		if reply[2]&0x04 != 0 {
			t.Error("sinkholed answer must NOT be authoritative ([H3])")
		}
		if got := net.IP(reply[len(reply)-4:]); !got.Equal(net.ParseIP("172.20.0.1")) {
			t.Errorf("sinkhole IP = %v, want gateway 172.20.0.1", got)
		}
	})
	t.Run("unsupported qtype -> REFUSED", func(t *testing.T) {
		reply, _, _ := r.respond(encodeQuery(3, "web.veil.local", 15 /* MX */))
		if reply[3]&0x0f != rcodeRefused {
			t.Errorf("RCODE = %d, want REFUSED", reply[3]&0x0f)
		}
	})
	t.Run("malformed -> drop", func(t *testing.T) {
		if reply, _, _ := r.respond([]byte{0x00}); reply != nil {
			t.Error("malformed query must yield a nil reply")
		}
	})
}

func TestResolverServePublishesSanitisedFact(t *testing.T) {
	bus := events.NewBus(8)
	feed, unsub := bus.Subscribe()
	defer unsub()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0") // loopback only
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = NewResolver(testWorld(t), bus).Serve(ctx, pc) }()

	client, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	if _, err := client.Write(encodeQuery(1, "web.veil.local", dnsTypeA)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 512)
	n, err := client.Read(resp)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if binary.BigEndian.Uint16(resp[6:8]) != 1 {
		t.Fatalf("ANCOUNT = %d, want 1", binary.BigEndian.Uint16(resp[6:8]))
	}
	_ = n

	select {
	case e := <-feed:
		if e.Kind != events.KindTraffic || e.Protocol != "dns" || e.Dest != "web.veil.local" {
			t.Errorf("query fact = %+v", e)
		}
		if e.Source != "127.0.0.1" {
			t.Errorf("Source = %q, want 127.0.0.1 (transport peer, [L7])", e.Source)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no query fact published")
	}
}

func TestResolverServeSanitisesHostileName(t *testing.T) {
	bus := events.NewBus(8)
	feed, unsub := bus.Subscribe()
	defer unsub()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = NewResolver(testWorld(t), bus).Serve(ctx, pc) }()

	client, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	// A label carrying a non-allowlisted byte; encodeQuery puts it on the wire verbatim.
	if _, err := client.Write(encodeQuery(2, "ev<il.veil.local", dnsTypeA)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	resp := make([]byte, 512)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Read(resp); err != nil {
		t.Fatalf("Read: %v", err)
	}
	select {
	case e := <-feed:
		if strings.Contains(e.Dest, "<") {
			t.Errorf("Dest carries raw '<' (not sanitised): %q", e.Dest)
		}
		if !strings.Contains(e.Dest, "\\x3c") {
			t.Errorf("Dest = %q, want the '<' hex-escaped to \\x3c ([C1])", e.Dest)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no fact published for hostile query")
	}
}

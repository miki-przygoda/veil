package netfabric

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync"
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
	// Cloud-metadata names are not world names: they sinkhole to the gateway like any
	// external name (never a real or link-local answer), and so read as external-dns.
	for _, name := range []string{"metadata.google.internal", "metadata", "instance-data", "instance-data.ec2.internal"} {
		t.Run("metadata name "+name+" -> sinkhole", func(t *testing.T) {
			reply, qname, world := r.respond(encodeQuery(9, name, dnsTypeA))
			if world || qname != name {
				t.Fatalf("qname=%q world=%v", qname, world)
			}
			if got := net.IP(reply[len(reply)-4:]); !got.Equal(net.ParseIP("172.20.0.1")) {
				t.Errorf("answer IP = %v, want gateway 172.20.0.1", got)
			}
		})
	}
	// An IP-literal qname is not a world name on the wire, even for an in-world
	// address: A and AAAA must agree (both non-authoritative, world=false), or the
	// AA bit fingerprints the resolver and maps which literals it deems in-world.
	// Only the Classifier judges the literal's in-world membership.
	for _, name := range []string{"172.20.0.10", "172.20.0.1", "127.0.0.1", "::1", "8.8.8.8"} {
		t.Run("ip-literal "+name+" -> A/AAAA not authoritative", func(t *testing.T) {
			for _, qt := range []uint16{dnsTypeA, dnsTypeAAAA} {
				reply, qname, world := r.respond(encodeQuery(10, name, qt))
				if world || qname != name {
					t.Fatalf("qtype %d: qname=%q world=%v, want world=false", qt, qname, world)
				}
				if reply[2]&0x04 != 0 {
					t.Errorf("qtype %d: IP-literal answer must NOT be authoritative", qt)
				}
			}
		})
	}
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

// slowReplyConn records when the resolver starts writing its reply, then stalls,
// so a fact stamped after the reply is distinguishable from one stamped at receipt.
type slowReplyConn struct {
	net.PacketConn
	mu      sync.Mutex
	writeAt time.Time
}

func (c *slowReplyConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	c.writeAt = time.Now().UTC()
	c.mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	return c.PacketConn.WriteTo(p, addr)
}

func TestResolverStampsFactAtReceipt(t *testing.T) {
	// The client (the subject's command) is unblocked by the reply, so a fact stamped
	// after writing it could postdate the command — and the next command's start.
	bus := events.NewBus(8)
	feed, unsub := bus.Subscribe()
	defer unsub()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	slow := &slowReplyConn{PacketConn: pc}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = NewResolver(testWorld(t), bus).Serve(ctx, slow) }()

	client, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	if _, err := client.Write(encodeQuery(1, "pastebin.com", dnsTypeA)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	select {
	case e := <-feed:
		slow.mu.Lock()
		writeAt := slow.writeAt
		slow.mu.Unlock()
		if writeAt.IsZero() || e.Time.After(writeAt) {
			t.Errorf("fact Time %v is after the reply write began (%v); want it stamped at receipt", e.Time, writeAt)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no query fact published")
	}
}

func TestResolverRespondHeaderPolicy(t *testing.T) {
	r := NewResolver(testWorld(t), events.NewBus(1))
	cases := []struct {
		name      string
		query     []byte
		wantReply bool
		wantQName string // "" = no fact
		rcode     uint8
		rd        bool
	}{
		{"RD query: RD echoed, RA set", encodeQuery(1, "pastebin.com", dnsTypeAAAA), true, "pastebin.com", rcodeNoError, true},
		{"no-RD query: RD clear, RA set", withFlags(encodeQuery(2, "web.veil.local", dnsTypeA), 0x0000), true, "web.veil.local", rcodeNoError, false},
		// A packet with QR=1 is a response, not a query: never answer it (no
		// reflection loop) and log nothing, like a malformed packet.
		{"QR=1 dropped", withFlags(encodeQuery(3, "pastebin.com", dnsTypeA), 0x8100), false, "", 0, false},
		// Non-QUERY opcodes get NOTIMP (what BIND/unbound send), still a fact.
		{"STATUS opcode -> NOTIMP", withFlags(encodeQuery(4, "pastebin.com", dnsTypeA), 0x1100), true, "pastebin.com", rcodeNotImp, true},
		{"UPDATE opcode -> NOTIMP", withFlags(encodeQuery(5, "web.veil.local", dnsTypeA), 0x2800), true, "web.veil.local", rcodeNotImp, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reply, qname, _ := r.respond(c.query)
			if qname != c.wantQName {
				t.Errorf("qname = %q, want %q", qname, c.wantQName)
			}
			if !c.wantReply {
				if reply != nil {
					t.Fatalf("reply = % x, want dropped", reply)
				}
				return
			}
			if reply == nil {
				t.Fatal("reply dropped, want an answer")
			}
			qflags := binary.BigEndian.Uint16(c.query[2:4])
			flags := binary.BigEndian.Uint16(reply[2:4])
			if flags&0x8000 == 0 {
				t.Error("QR not set")
			}
			if flags&0x0080 == 0 {
				t.Error("RA not set (resolver persona must offer recursion)")
			}
			if got := flags&0x0100 != 0; got != c.rd {
				t.Errorf("RD = %v, want %v (echoed)", got, c.rd)
			}
			if got, want := flags&0x7800, qflags&0x7800; got != want {
				t.Errorf("opcode bits = %#04x, want %#04x (echoed)", got, want)
			}
			if got := uint8(flags & 0x000f); got != c.rcode {
				t.Errorf("RCODE = %d, want %d", got, c.rcode)
			}
			if c.rcode == rcodeNotImp && flags&0x0400 != 0 {
				t.Error("NOTIMP must not be authoritative ([H3])")
			}
		})
	}
}

// TestGoResolverNoLameReferral drives Go's own stub resolver against Serve: an
// empty non-authoritative NOERROR without RA is a "lame referral" to it, which
// singled out sinkholed AAAA names. With RA set it is a plain not-found.
func TestGoResolverNoLameReferral(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = NewResolver(testWorld(t), events.NewBus(64)).Serve(ctx, pc) }()

	res := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", pc.LocalAddr().String())
		},
	}
	lctx, lcancel := context.WithTimeout(ctx, 5*time.Second)
	defer lcancel()

	// AAAA only: the sinkholed name's empty answer must read as "no such host".
	_, err = res.LookupIP(lctx, "ip6", "pastebin.com.")
	var de *net.DNSError
	if !errors.As(err, &de) {
		t.Fatalf("LookupIP ip6: err = %v, want a *net.DNSError", err)
	}
	if strings.Contains(de.Err, "lame referral") || !de.IsNotFound {
		t.Errorf("LookupIP ip6 sinkholed: %v (IsNotFound=%v), want plain not-found", de, de.IsNotFound)
	}

	// A+AAAA: the sinkhole address comes back cleanly.
	addrs, err := res.LookupHost(lctx, "pastebin.com.")
	if err != nil {
		t.Fatalf("LookupHost sinkholed: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != "172.20.0.1" {
		t.Errorf("LookupHost = %v, want [172.20.0.1]", addrs)
	}
}

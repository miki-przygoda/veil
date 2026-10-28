package netfabric

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/miki-przygoda/veil/internal/events"
)

// tcpResolver serves r over a loopback TCP listener until the test ends, and
// returns the address plus a channel carrying ServeTCP's return value.
func tcpResolver(t *testing.T, r *Resolver) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0") // loopback only
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.ServeTCP(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("ServeTCP did not return after cancel")
		}
	})
	return ln.Addr().String(), cancel, done
}

func dialTCP(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	return c
}

// frame is RFC 1035 4.2.2 / RFC 7766 framing: a 2-byte big-endian length prefix.
func frame(msg []byte) []byte {
	out := make([]byte, 2, 2+len(msg))
	binary.BigEndian.PutUint16(out, uint16(len(msg)))
	return append(out, msg...)
}

func tcpExchange(t *testing.T, c net.Conn, msg []byte) []byte {
	t.Helper()
	if _, err := c.Write(frame(msg)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	var prefix [2]byte
	if _, err := io.ReadFull(c, prefix[:]); err != nil {
		t.Fatalf("read length prefix: %v", err)
	}
	reply := make([]byte, binary.BigEndian.Uint16(prefix[:]))
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return reply
}

// expectClosed asserts the server closed c (EOF or reset) within d, i.e. not by
// the client-side deadline.
func expectClosed(t *testing.T, c net.Conn, d time.Duration) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(d))
	_, err := c.Read(make([]byte, 1))
	var ne net.Error
	if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
		t.Fatalf("conn still open after %v (err=%v), want server close", d, err)
	}
}

func nextFact(t *testing.T, feed <-chan events.Event) events.Event {
	t.Helper()
	select {
	case e := <-feed:
		return e
	case <-time.After(2 * time.Second):
		t.Fatal("no query fact published")
		return events.Event{}
	}
}

func noFact(t *testing.T, feed <-chan events.Event) {
	t.Helper()
	select {
	case e := <-feed:
		t.Fatalf("unexpected fact %+v", e)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestResolverTCPAnswersLikeUDP(t *testing.T) {
	tests := []struct {
		name  string
		query []byte
	}{
		{"world name", encodeQuery(1, "web.veil.local", dnsTypeA)},
		{"sinkholed name", encodeQuery(2, "pastebin.com", dnsTypeA)},
		{"AAAA", encodeQuery(3, "web.veil.local", dnsTypeAAAA)},
		{"refused qtype", encodeQuery(4, "web.veil.local", 15)},
		{"NOTIMP opcode", withFlags(encodeQuery(5, "pastebin.com", dnsTypeA), 0x1100)},
	}
	r := NewResolver(testWorld(t), events.NewBus(64))
	addr, _, _ := tcpResolver(t, r)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want, _, _ := r.respond(tt.query) // the UDP answer path
			got := tcpExchange(t, dialTCP(t, addr), tt.query)
			if !bytes.Equal(got, want) {
				t.Fatalf("TCP reply\n% x\nwant (UDP)\n% x", got, want)
			}
		})
	}
}

func TestResolverTCPPublishesSameFact(t *testing.T) {
	bus := events.NewBus(8)
	feed, unsub := bus.Subscribe()
	defer unsub()
	w := testWorld(t)
	addr, _, _ := tcpResolver(t, NewResolver(w, bus))

	before := time.Now().UTC()
	reply := tcpExchange(t, dialTCP(t, addr), encodeQuery(7, "Paste<bin.com", dnsTypeA))
	if got := net.IP(reply[len(reply)-4:]); !got.Equal(net.ParseIP("172.20.0.1")) {
		t.Errorf("sinkhole IP = %v, want gateway", got)
	}
	e := nextFact(t, feed)
	if e.Kind != events.KindTraffic || e.Protocol != "dns" || e.Action != "query" {
		t.Errorf("fact = %+v, want traffic dns/query", e)
	}
	if e.Source != "127.0.0.1" {
		t.Errorf("Source = %q, want transport peer 127.0.0.1 ([L7])", e.Source)
	}
	if strings.Contains(e.Dest, "<") || !strings.Contains(e.Dest, "\\x3c") {
		t.Errorf("Dest = %q, want SafeField'd qname ([C1])", e.Dest)
	}
	if e.Time.Before(before) || e.Time.After(time.Now().UTC()) {
		t.Errorf("fact Time %v outside the exchange", e.Time)
	}
	// The same fact the UDP path would publish reads as an escape to the Classifier.
	if esc, ok := NewClassifier(w).classify(e); !ok || esc.Action != "external-dns" {
		t.Errorf("classify = %+v ok=%v, want external-dns", esc, ok)
	}
}

func TestResolverTCPMultipleQueriesPerConn(t *testing.T) {
	bus := events.NewBus(8)
	feed, unsub := bus.Subscribe()
	defer unsub()
	addr, _, _ := tcpResolver(t, NewResolver(testWorld(t), bus))
	c := dialTCP(t, addr)
	for i, name := range []string{"web.veil.local", "pastebin.com", "mail.veil.local"} {
		reply := tcpExchange(t, c, encodeQuery(uint16(10+i), name, dnsTypeA))
		if id := binary.BigEndian.Uint16(reply[0:2]); id != uint16(10+i) {
			t.Errorf("query %d: reply id = %d", i, id)
		}
		if e := nextFact(t, feed); e.Dest != name {
			t.Errorf("query %d: fact Dest = %q, want %q", i, e.Dest, name)
		}
	}
}

func TestResolverTCPFraming(t *testing.T) {
	big := make([]byte, 65535) // the largest a 2-byte prefix can declare
	copy(big, encodeQuery(9, "web.veil.local", dnsTypeA))
	tests := []struct {
		name      string
		send      []byte
		closeSend bool // half-close after sending
		wantReply bool
		wantFact  bool
	}{
		{"zero length is rejected", []byte{0, 0}, false, false, false},
		{"max length 65535 is accepted", frame(big), false, true, true},
		{"body shorter than prefix", append([]byte{0x01, 0x00}, encodeQuery(1, "pastebin.com", dnsTypeA)...), true, false, false},
		{"malformed body", frame([]byte{0x00, 0x01, 0x02}), false, false, false},
		{"QR=1 response", frame(withFlags(encodeQuery(3, "pastebin.com", dnsTypeA), 0x8100)), false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bus := events.NewBus(8)
			feed, unsub := bus.Subscribe()
			defer unsub()
			addr, _, _ := tcpResolver(t, NewResolver(testWorld(t), bus))
			c := dialTCP(t, addr)
			if _, err := c.Write(tt.send); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if tt.closeSend {
				_ = c.(*net.TCPConn).CloseWrite()
			}
			if tt.wantReply {
				var prefix [2]byte
				if _, err := io.ReadFull(c, prefix[:]); err != nil {
					t.Fatalf("want a reply, read: %v", err)
				}
				nextFact(t, feed)
				return
			}
			expectClosed(t, c, 2*time.Second)
			if !tt.wantFact {
				noFact(t, feed)
			}
		})
	}
}

func TestResolverTCPIdleDeadline(t *testing.T) {
	r := NewResolver(testWorld(t), events.NewBus(8))
	r.tcpIdle = 150 * time.Millisecond
	addr, _, _ := tcpResolver(t, r)

	t.Run("silent conn", func(t *testing.T) {
		expectClosed(t, dialTCP(t, addr), 2*time.Second)
	})
	t.Run("stalled mid-message", func(t *testing.T) {
		c := dialTCP(t, addr)
		_, _ = c.Write([]byte{0x00, 0x20, 0x00}) // declares 32 bytes, sends 1
		expectClosed(t, c, 2*time.Second)
	})
	t.Run("idle after a query", func(t *testing.T) {
		c := dialTCP(t, addr)
		tcpExchange(t, c, encodeQuery(1, "web.veil.local", dnsTypeA))
		expectClosed(t, c, 2*time.Second)
	})
}

func TestResolverTCPLifetimeCap(t *testing.T) {
	// A client that keeps the idle timer fed still loses the conn at the lifetime cap.
	r := NewResolver(testWorld(t), events.NewBus(64))
	r.tcpIdle = 200 * time.Millisecond
	r.tcpLife = 300 * time.Millisecond
	addr, _, _ := tcpResolver(t, r)
	c := dialTCP(t, addr)
	start := time.Now()
	for time.Since(start) < 3*time.Second {
		if _, err := c.Write(frame(encodeQuery(1, "web.veil.local", dnsTypeA))); err != nil {
			return
		}
		var prefix [2]byte
		if _, err := io.ReadFull(c, prefix[:]); err != nil {
			return // closed by the server: good
		}
		reply := make([]byte, binary.BigEndian.Uint16(prefix[:]))
		if _, err := io.ReadFull(c, reply); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("conn outlived the lifetime cap")
}

func TestResolverTCPConnCap(t *testing.T) {
	bus := events.NewBus(64)
	feed, unsub := bus.Subscribe()
	defer unsub()
	r := NewResolver(testWorld(t), bus)
	r.tcpMaxConns = 2
	addr, _, _ := tcpResolver(t, r)

	// Fill the cap with two served (so certainly accepted) conns.
	held := []net.Conn{dialTCP(t, addr), dialTCP(t, addr)}
	for _, c := range held {
		tcpExchange(t, c, encodeQuery(1, "web.veil.local", dnsTypeA))
	}
	// The third is dropped at once (well before the 5s idle timeout) ...
	expectClosed(t, dialTCP(t, addr), time.Second)
	// ... with ONE observable overload event.
	sawOverload := false
	deadline := time.After(2 * time.Second)
	for !sawOverload {
		select {
		case e := <-feed:
			sawOverload = e.Kind == events.KindSystem && strings.Contains(e.Action, "overloaded")
		case <-deadline:
			t.Fatal("no overload KindSystem event")
		}
	}
	// Freeing a slot lets a new conn be served again.
	_ = held[0].Close()
	for i := 0; ; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		_ = c.SetDeadline(time.Now().Add(time.Second))
		_, werr := c.Write(frame(encodeQuery(2, "web.veil.local", dnsTypeA)))
		var prefix [2]byte
		_, rerr := io.ReadFull(c, prefix[:])
		_ = c.Close()
		if werr == nil && rerr == nil {
			break
		}
		if i == 50 {
			t.Fatal("slot never freed after a held conn closed")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestResolverTCPShutdownClosesConnsNoLeak(t *testing.T) {
	base := runtime.NumGoroutine()
	r := NewResolver(testWorld(t), events.NewBus(8))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.ServeTCP(ctx, ln) }()

	idle := dialTCP(t, ln.Addr().String())
	busy := dialTCP(t, ln.Addr().String())
	tcpExchange(t, busy, encodeQuery(1, "web.veil.local", dnsTypeA))
	_, _ = idle.Write([]byte{0x00}) // half a length prefix: the handler is mid-read

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("ServeTCP after cancel = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServeTCP did not return on cancel (handlers still blocked?)")
	}
	expectClosed(t, idle, time.Second)
	expectClosed(t, busy, time.Second)
	if _, err := net.Dial("tcp", ln.Addr().String()); err == nil {
		t.Error("listener still accepting after cancel")
	}
	_ = idle.Close()
	_ = busy.Close()
	for i := 0; runtime.NumGoroutine() > base; i++ {
		if i == 100 {
			t.Fatalf("goroutines = %d, want <= %d (leak)", runtime.NumGoroutine(), base)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

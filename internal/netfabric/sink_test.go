package netfabric

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miki-przygoda/veil/internal/events"
)

func TestSinkOverloadEmitsOncePerEpisode(t *testing.T) {
	bus := events.NewBus(16)
	feed, unsub := bus.Subscribe()
	defer unsub()
	s := NewSink(bus, "172.20.0.1", func(net.Conn) int { return 0 })

	// One overload episode: three rejects, one event.
	s.reportOverload()
	s.reportOverload()
	s.reportOverload()
	count := 0
	drain := func(d time.Duration) {
		to := time.After(d)
		for {
			select {
			case e := <-feed:
				if e.Kind == events.KindSystem {
					count++
				}
			case <-to:
				return
			}
		}
	}
	drain(200 * time.Millisecond)
	if count != 1 {
		t.Fatalf("episode 1: KindSystem events = %d, want 1", count)
	}

	// Re-arm (a slot freed) then overload again: one more event.
	s.overloaded.Store(false)
	s.reportOverload()
	s.reportOverload()
	count = 0
	drain(200 * time.Millisecond)
	if count != 1 {
		t.Fatalf("episode 2 after re-arm: KindSystem events = %d, want 1", count)
	}
}

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

// slowReadConn records when the sink starts reading the payload, then stalls, so a
// fact stamped after the read/banner is distinguishable from one stamped at accept.
type slowReadConn struct {
	net.Conn
	mu     sync.Mutex
	readAt time.Time
}

func (c *slowReadConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	c.readAt = time.Now().UTC()
	c.mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	return c.Conn.Read(p)
}

type slowReadListener struct {
	net.Listener
	conns chan *slowReadConn
}

func (l *slowReadListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	sc := &slowReadConn{Conn: c}
	l.conns <- sc
	return sc, nil
}

func TestSinkStampsFactAtAccept(t *testing.T) {
	// The subject's connect can finish (and its command exit) before the sink has read
	// the payload, so the fact must be stamped when the connection is accepted.
	bus := events.NewBus(16)
	feed, unsub := bus.Subscribe()
	defer unsub()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := &slowReadListener{Listener: inner, conns: make(chan *slowReadConn, 1)}
	s := NewSink(bus, "172.20.0.1", func(net.Conn) int { return 80 })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.serve(ctx, ln)

	c, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("x"))
	defer c.Close()

	select {
	case e := <-feed:
		sc := <-ln.conns
		sc.mu.Lock()
		readAt := sc.readAt
		sc.mu.Unlock()
		if readAt.IsZero() || e.Time.After(readAt) {
			t.Errorf("fact Time %v is after the payload read began (%v); want it stamped at accept", e.Time, readAt)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no sink fact emitted")
	}
}

// TestSinkBannerFirst: a server-speaks-first client (ssh, nc, smtp) sends nothing
// and waits. The banner must arrive promptly, not after the read deadline lapses
// (which also killed the write: silence, then EOF — a dead-service tell).
func TestSinkBannerFirst(t *testing.T) {
	bus := events.NewBus(16)
	feed, unsub := bus.Subscribe()
	defer unsub()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := NewSink(bus, "172.20.0.1", func(net.Conn) int { return 22 })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.serve(ctx, ln)

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(time.Second)) // well under the sink's 2s read wait
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "220 service ready\r\n" {
		t.Fatalf("banner = %q, err = %v; want it sent before the sink reads", buf[:n], err)
	}
	_ = c.Close() // the client gives up having sent nothing

	select {
	case e := <-feed:
		if e.Action != "sink connect" || !strings.HasPrefix(e.Detail, "port 22") {
			t.Errorf("fact = %+v, want a sink connect for port 22", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no sink fact for a silent client")
	}
}

// failWriteConn is a net.Conn whose banner write fails; Read returns payload once.
type failWriteConn struct {
	net.Conn // nil: only the methods below are used
	payload  []byte
}

func (c *failWriteConn) Read(p []byte) (int, error) {
	if len(c.payload) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.payload)
	c.payload = c.payload[n:]
	return n, nil
}
func (c *failWriteConn) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }
func (c *failWriteConn) Close() error              { return nil }
func (c *failWriteConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("172.20.0.5"), Port: 4242}
}
func (c *failWriteConn) SetDeadline(time.Time) error      { return nil }
func (c *failWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (c *failWriteConn) SetWriteDeadline(time.Time) error { return nil }

func TestSinkHandlePublishesEvenIfBannerFails(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    string
	}{
		{"banner write fails, payload still captured", "EHLO", "port 25 EHLO"},
		{"banner write fails, client silent", "", "port 25 "},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bus := events.NewBus(4)
			feed, unsub := bus.Subscribe()
			defer unsub()
			s := NewSink(bus, "172.20.0.1", func(net.Conn) int { return 25 })
			accepted := time.Now().UTC().Add(-time.Second)
			s.handle(&failWriteConn{payload: []byte(c.payload)}, accepted)
			select {
			case e := <-feed:
				if e.Detail != c.want || e.Source != "172.20.0.5" || !e.Time.Equal(accepted) {
					t.Errorf("fact = %+v, want Detail %q from 172.20.0.5 at accept", e, c.want)
				}
			case <-time.After(time.Second):
				t.Fatal("no sink fact published")
			}
		})
	}
}

// deadlineConn records the deadlines handle sets; otherwise it behaves like failWriteConn.
type deadlineConn struct {
	failWriteConn
	writeDL, readDL time.Time
}

func (c *deadlineConn) SetWriteDeadline(t time.Time) error { c.writeDL = t; return nil }
func (c *deadlineConn) SetReadDeadline(t time.Time) error  { c.readDL = t; return nil }

// A connection holds a sinkMaxConns slot for at most ONE sinkIOTimeout budget measured
// from accept: the banner write and the read share it, rather than each getting a fresh
// 2s (which held a slot for ~4s).
func TestSinkHandleSingleBudgetFromAccept(t *testing.T) {
	cases := []struct {
		name string
		age  time.Duration // how long before handle ran the conn was accepted
	}{
		{"fresh accept", 0},
		{"accepted a while ago", 1500 * time.Millisecond},
		{"budget already spent", 3 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bus := events.NewBus(4)
			s := NewSink(bus, "172.20.0.1", func(net.Conn) int { return 25 })
			accepted := time.Now().UTC().Add(-tc.age)
			c := &deadlineConn{failWriteConn: failWriteConn{payload: []byte("x")}}
			s.handle(c, accepted)
			want := accepted.Add(sinkIOTimeout)
			if !c.writeDL.Equal(want) {
				t.Errorf("write deadline = %v, want accept+budget %v", c.writeDL, want)
			}
			if !c.readDL.Equal(want) {
				t.Errorf("read deadline = %v, want accept+budget %v (the remainder, not a fresh %v)", c.readDL, want, sinkIOTimeout)
			}
		})
	}
}

package netfabric

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/miki-przygoda/veil/internal/events"
)

const (
	sinkMaxConns = 64  // [M6] concurrent connections
	sinkReadCap  = 512 // [M6] bytes captured per connection
)

// Sink is the transparent honeypot's connection handler. orig returns the
// subject's originally-intended TCP port (recovered via SO_ORIGINAL_DST on
// Linux; a stub in tests). gateway is the sink IP, echoed as the fact Dest.
type Sink struct {
	bus        *events.Bus
	gateway    string
	orig       func(net.Conn) int
	overloaded atomic.Bool
}

func NewSink(bus *events.Bus, gateway string, orig func(net.Conn) int) *Sink {
	return &Sink{bus: bus, gateway: gateway, orig: orig}
}

// reportOverload emits a single "honeypot overloaded" KindSystem per overload
// episode. The latch re-arms when a slot is next acquired (see serve), so a
// sustained flood yields one event, not one per rejected connection ([M6]).
func (s *Sink) reportOverload() {
	if s.overloaded.CompareAndSwap(false, true) {
		e := events.New(events.KindSystem, "veild", "honeypot overloaded")
		e.Detail = fmt.Sprintf("connection cap %d reached; dropping", sinkMaxConns)
		s.bus.Publish(e)
	}
}

// serve accepts until ctx is cancelled, bounding concurrency ([M6]).
func (s *Sink) serve(ctx context.Context, ln net.Listener) {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
		case <-done:
		}
	}()
	sem := make(chan struct{}, sinkMaxConns)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case sem <- struct{}{}:
			s.overloaded.Store(false) // re-arm: we're below cap again
			go func() { defer func() { <-sem }(); s.handle(conn) }()
		default:
			// Over the cap: RST + ONE KindSystem per episode, never per-conn ([M6]).
			if tc, ok := conn.(*net.TCPConn); ok {
				_ = tc.SetLinger(0)
			}
			_ = conn.Close()
			s.reportOverload()
		}
	}
}

func (s *Sink) handle(conn net.Conn) {
	defer conn.Close()
	port := s.orig(conn)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second)) // bounds BOTH the read and the banner write
	buf := make([]byte, sinkReadCap)
	n, _ := conn.Read(buf) // best-effort; may be 0
	_, _ = conn.Write([]byte("220 service ready\r\n"))

	// Source is the transport peer ([L7]); payload is subject-controlled -> capped
	// + sanitised before the bus ([C1]).
	e := events.New(events.KindTraffic, hostIP(conn.RemoteAddr()), "sink connect")
	e.Dest = s.gateway
	e.Protocol = "tcp"
	e.Detail = fmt.Sprintf("port %d %s", port, events.SafeField(string(buf[:n]), 120))
	s.bus.Publish(e)
}

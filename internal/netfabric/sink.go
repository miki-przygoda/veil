package netfabric

import (
	"context"
	"fmt"
	"net"
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
	bus     *events.Bus
	gateway string
	orig    func(net.Conn) int
}

func NewSink(bus *events.Bus, gateway string, orig func(net.Conn) int) *Sink {
	return &Sink{bus: bus, gateway: gateway, orig: orig}
}

// serve accepts until ctx is cancelled, bounding concurrency ([M6]).
func (s *Sink) serve(ctx context.Context, ln net.Listener) {
	go func() { <-ctx.Done(); _ = ln.Close() }()
	sem := make(chan struct{}, sinkMaxConns)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case sem <- struct{}{}:
			go func() { defer func() { <-sem }(); s.handle(conn) }()
		default:
			// Over the cap: reset + ONE KindSystem, never a per-conn flood ([M6]).
			_ = conn.Close()
			e := events.New(events.KindSystem, "veild", "honeypot overloaded")
			e.Detail = fmt.Sprintf("connection cap %d reached; dropping", sinkMaxConns)
			s.bus.Publish(e)
		}
	}
}

func (s *Sink) handle(conn net.Conn) {
	defer conn.Close()
	port := s.orig(conn)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, sinkReadCap)
	n, _ := conn.Read(buf) // best-effort; may be 0
	_, _ = conn.Write([]byte("220 service ready\r\n"))

	// Source is the transport peer ([L7]); payload is subject-controlled -> capped
	// + sanitised before the bus ([C1]).
	e := events.New(events.KindTraffic, hostIP(conn.RemoteAddr()), "sink connect")
	e.Dest = s.gateway
	e.Protocol = "tcp"
	e.Detail = fmt.Sprintf("port %d %s", port, safeField(string(buf[:n]), 120))
	s.bus.Publish(e)
}

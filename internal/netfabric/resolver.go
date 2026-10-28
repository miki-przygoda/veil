package netfabric

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miki-przygoda/veil/internal/events"
)

const (
	maxDNSPacket = 512

	resolverTCPMaxConns = 32               // concurrent DNS-over-TCP conns (like sinkMaxConns)
	resolverTCPIdle     = 5 * time.Second  // budget per message: length prefix + body + reply
	resolverTCPLife     = 30 * time.Second // hard cap per conn, however busy
)

// Resolver is the world's synthetic DNS service. It answers A queries for world
// names, sinkholes everything else to the gateway (the transparent honeypot),
// and publishes one query FACT per request. It is a world SERVICE, not an
// enforcement point, and it never forwards to a real resolver (invariant #3) —
// it decides nothing about escape (that is the Classifier's job).
type Resolver struct {
	world World
	bus   *events.Bus

	// DNS-over-TCP bounds (see ServeTCP); fields so tests can shrink them.
	tcpMaxConns int
	tcpIdle     time.Duration
	tcpLife     time.Duration
	overloaded  atomic.Bool // one TCP overload event per episode
}

func NewResolver(world World, bus *events.Bus) *Resolver {
	return &Resolver{
		world: world, bus: bus,
		tcpMaxConns: resolverTCPMaxConns, tcpIdle: resolverTCPIdle, tcpLife: resolverTCPLife,
	}
}

// respond is the pure core. world name -> A(world IP) authoritative; unknown A
// -> A(gateway) non-authoritative (honeypot sinkhole); AAAA -> empty NOERROR;
// other qtypes -> REFUSED. Malformed, or QR=1 (a response, not a query: answering
// it invites a reflection loop) -> nil reply and no qname (drop, no fact, never
// panic). A non-QUERY opcode (IQUERY/STATUS/NOTIFY/UPDATE...) -> NOTIMP, as BIND
// and unbound answer; it still names a host, so it is still a fact.
func (r *Resolver) respond(query []byte) (reply []byte, qname string, world bool) {
	q, err := parseQuery(query)
	if err != nil || q.qr {
		return nil, "", false
	}
	name := strings.ToLower(strings.TrimSuffix(q.name, "."))
	if q.opcode != 0 {
		// Never authoritative ([H3]); world still labels the fact's Detail.
		return replyRcode(q, rcodeNotImp, false), name, !r.world.offWorldName(name)
	}
	switch q.qtype {
	case dnsTypeA:
		if ip, ok := r.world.Names[name]; ok {
			return replyA(q, ip, true), name, true // authoritative world name
		}
		return replyA(q, r.world.Gateway, false), name, false // sinkhole
	case dnsTypeAAAA:
		inWorld := !r.world.offWorldName(name)
		return replyRcode(q, rcodeNoError, inWorld), name, inWorld // no v6 in this world
	default:
		return replyRcode(q, rcodeRefused, false), name, false
	}
}

// Serve answers UDP queries until ctx is cancelled, publishing a sanitised query
// fact per request. conn is injected so tests drive it over loopback.
func (r *Resolver) Serve(ctx context.Context, conn net.PacketConn) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
		case <-done:
		}
		_ = conn.Close()
	}()
	buf := make([]byte, maxDNSPacket)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		// Stamp the fact at receipt, before the reply: the reply unblocks the subject's
		// command, so a later stamp could postdate it (and the next command's start).
		if reply := r.answer(buf[:n], addr, time.Now().UTC(), ""); reply != nil {
			_, _ = conn.WriteTo(reply, addr)
		}
	}
}

// ServeTCP answers DNS over TCP (RFC 1035 4.2.2 / RFC 7766: each message carries a
// 2-byte big-endian length prefix, several per connection) until ctx is cancelled,
// with the same answers and facts as Serve. Bounded: at most tcpMaxConns conns
// (extra ones are reset, with one KindSystem per overload episode), tcpIdle per
// message, tcpLife per conn. A zero-length, short, malformed or QR=1 message ends
// the conn (there is no reply to give). It owns ln and returns only after every
// conn handler has finished, so cancel leaks nothing.
func (r *Resolver) ServeTCP(ctx context.Context, ln net.Listener) error {
	var (
		mu     sync.Mutex
		conns  = map[net.Conn]struct{}{}
		closed bool
		wg     sync.WaitGroup
	)
	shutdown := func() {
		_ = ln.Close()
		mu.Lock()
		closed = true
		for c := range conns {
			_ = c.Close() // unblocks the handler's read
		}
		mu.Unlock()
	}
	stop := context.AfterFunc(ctx, shutdown)
	defer func() {
		stop()
		shutdown()
		wg.Wait()
	}()
	sem := make(chan struct{}, r.tcpMaxConns)
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case sem <- struct{}{}:
		default:
			// Over the cap: RST + ONE KindSystem per episode, never per-conn.
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetLinger(0)
			}
			_ = c.Close()
			r.reportTCPOverload()
			continue
		}
		r.overloaded.Store(false) // re-arm: below cap again
		mu.Lock()
		if closed {
			mu.Unlock()
			_ = c.Close()
			<-sem
			return nil
		}
		conns[c] = struct{}{}
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				mu.Lock()
				delete(conns, c)
				mu.Unlock()
				_ = c.Close()
			}()
			r.serveTCPConn(c)
		}()
	}
}

// serveTCPConn answers framed queries on one conn until the client stops, a bound
// trips, or a message gets no reply.
func (r *Resolver) serveTCPConn(c net.Conn) {
	end := time.Now().Add(r.tcpLife)
	var prefix [2]byte
	for {
		deadline := time.Now().Add(r.tcpIdle)
		if deadline.After(end) {
			deadline = end
		}
		_ = c.SetDeadline(deadline)
		if _, err := io.ReadFull(c, prefix[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(prefix[:])) // <= 65535 by construction
		if n == 0 {
			return // RFC 7766 has no empty message
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(c, msg); err != nil {
			return
		}
		reply := r.answer(msg, c.RemoteAddr(), time.Now().UTC(), "tcp")
		if reply == nil {
			return
		}
		// A reply is header + echoed question + at most one A: far below 65535, and
		// never truncated (TC stays clear over TCP).
		out := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(reply)), uint16(len(reply)))
		if _, err := c.Write(append(out, reply...)); err != nil {
			return
		}
	}
}

func (r *Resolver) reportTCPOverload() {
	if r.overloaded.CompareAndSwap(false, true) {
		e := events.New(events.KindSystem, "veild", "resolver tcp overloaded")
		e.Detail = fmt.Sprintf("connection cap %d reached; dropping", r.tcpMaxConns)
		r.bus.Publish(e)
	}
}

// answer is the message handling shared by Serve and ServeTCP, so both transports
// answer identically: it computes the reply and publishes the query fact stamped
// at received. transport ("" for UDP) is appended to the fact's Detail; nil means
// no reply (and, for a malformed query, no fact).
func (r *Resolver) answer(query []byte, peer net.Addr, received time.Time, transport string) []byte {
	reply, qname, world := r.respond(query)
	if qname == "" {
		return reply // malformed: nothing meaningful to log
	}
	// Source is the host-observed transport peer, never a payload-derived
	// value ([L7]); Dest is the subject-controlled name, sanitised ([C1]).
	e := events.New(events.KindTraffic, hostIP(peer), "query")
	e.Time = received
	e.Protocol = "dns"
	e.Dest = events.SafeField(qname, 253)
	detail := "sinkholed"
	if world {
		detail = "world"
		if ip, ok := r.world.Names[qname]; ok {
			detail = "world " + ip.String()
		}
	}
	if transport != "" {
		detail += " " + transport
	}
	e.Detail = detail
	r.bus.Publish(e)
	return reply
}

// hostIP extracts the host portion of a transport address (shared with Sink).
func hostIP(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		return host
	}
	return addr.String()
}

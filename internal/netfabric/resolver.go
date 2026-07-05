package netfabric

import (
	"context"
	"net"
	"strings"

	"github.com/miki-przygoda/veil/internal/events"
)

const maxDNSPacket = 512

// Resolver is the world's synthetic DNS service. It answers A queries for world
// names, sinkholes everything else to the gateway (the transparent honeypot),
// and publishes one query FACT per request. It is a world SERVICE, not an
// enforcement point, and it never forwards to a real resolver (invariant #3) —
// it decides nothing about escape (that is the Classifier's job).
type Resolver struct {
	world World
	bus   *events.Bus
}

func NewResolver(world World, bus *events.Bus) *Resolver { return &Resolver{world: world, bus: bus} }

// respond is the pure core. world name -> A(world IP) authoritative; unknown A
// -> A(gateway) non-authoritative (honeypot sinkhole); AAAA -> empty NOERROR;
// other qtypes -> REFUSED. Malformed -> nil reply (drop, never panic).
func (r *Resolver) respond(query []byte) (reply []byte, qname string, world bool) {
	q, err := parseQuery(query)
	if err != nil {
		return nil, "", false
	}
	name := strings.ToLower(strings.TrimSuffix(q.name, "."))
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
		reply, qname, world := r.respond(buf[:n])
		if reply != nil {
			_, _ = conn.WriteTo(reply, addr)
		}
		if qname == "" {
			continue // malformed: nothing meaningful to log
		}
		// Source is the host-observed transport peer, never a payload-derived
		// value ([L7]); Dest is the subject-controlled name, sanitised ([C1]).
		e := events.New(events.KindTraffic, hostIP(addr), "query")
		e.Protocol = "dns"
		e.Dest = events.SafeField(qname, 253)
		detail := "sinkholed"
		if world {
			detail = "world"
			if ip, ok := r.world.Names[qname]; ok {
				detail = "world " + ip.String()
			}
		}
		e.Detail = detail
		r.bus.Publish(e)
	}
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

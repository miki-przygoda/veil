package main

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"time"
)

// clientDeps runs the ambient traffic loop. All dials are to configured in-subnet
// targets; DNS is UDP to the resolver. It never dials a gateway over TCP.
type clientDeps struct {
	targets  []string
	resolver *net.Resolver
	http     *http.Client
	interval time.Duration
	rng      *rand.Rand
}

func newClient(targets []string, resolverAddr string, interval time.Duration, seed int64) *clientDeps {
	res := net.DefaultResolver
	if resolverAddr != "" {
		res = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", resolverAddr) // world DNS is UDP
		}}
	}
	if interval <= 0 {
		interval = 3 * time.Second
	}
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	return &clientDeps{
		targets:  targets,
		resolver: res,
		http:     &http.Client{Timeout: 5 * time.Second},
		interval: interval,
		rng:      rand.New(rand.NewSource(seed)),
	}
}

// runClient performs a jittered weighted action each tick until ctx is cancelled.
// With no targets it simply blocks on ctx (a resident may be pure-server).
func (c *clientDeps) runClient(ctx context.Context) error {
	if len(c.targets) == 0 {
		<-ctx.Done()
		return nil
	}
	for {
		// jitter in [interval/2, 3*interval/2)
		d := c.interval/2 + time.Duration(c.rng.Int63n(int64(c.interval)))
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
			c.act(ctx)
		}
	}
}

// act performs one weighted action against a random target. Failures (a target
// momentarily down, or not running that service) are swallowed — realistic LAN
// noise, never a crash.
func (c *clientDeps) act(ctx context.Context) {
	target := c.targets[c.rng.Intn(len(c.targets))]
	switch n := c.rng.Intn(10); {
	case n < 4: // dnsLookup (UDP to resolver)
		_, _ = c.resolver.LookupHost(ctx, target)
	case n < 9: // httpGet
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+target+"/", nil)
		if err != nil {
			return
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	default: // smtpPing (best-effort)
		c.smtpPing(ctx, target)
	}
}

func (c *clientDeps) smtpPing(ctx context.Context, target string) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(target, "25"))
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	_, _ = conn.Read(buf) // greeting
	fmt.Fprintf(conn, "HELO veil-client\r\n")
	_, _ = conn.Read(buf)
	fmt.Fprintf(conn, "QUIT\r\n")
}

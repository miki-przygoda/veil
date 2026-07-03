package main

import (
	"context"
	"fmt"
	"net"
)

const maxServiceConns = 64

// acceptLoop accepts on ln until ctx is cancelled, dispatching each connection to
// handle under a concurrency cap. It closes ln on cancel so Accept unblocks, and
// closes each conn after handle returns. Used by the raw-TCP services (smtp/imap/
// ssh); http uses http.Server instead.
func acceptLoop(ctx context.Context, ln net.Listener, handle func(net.Conn)) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
		case <-done:
		}
		_ = ln.Close()
	}()
	sem := make(chan struct{}, maxServiceConns)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				defer conn.Close()
				handle(conn)
			}()
		default:
			_ = conn.Close() // over the cap: drop
		}
	}
}

// svc is a bound-and-ready service: its listener is created by run's caller at the
// declared port, then run(ctx, ln) serves until ctx is cancelled.
type svc struct {
	port int
	run  func(ctx context.Context, ln net.Listener) error
}

// buildServices maps parsed specs to runnable services, currying hostname in.
// Unknown protocols error (they should have been rejected by parseServices, but
// this is the authoritative dispatch).
func buildServices(specs []serviceSpec, hostname string) ([]svc, error) {
	var out []svc
	for _, s := range specs {
		var run func(ctx context.Context, ln net.Listener) error
		switch s.proto {
		case "http":
			run = func(ctx context.Context, ln net.Listener) error { return serveHTTP(ctx, ln, hostname) }
		case "smtp":
			run = func(ctx context.Context, ln net.Listener) error { return serveSMTP(ctx, ln, hostname) }
		case "imap":
			run = func(ctx context.Context, ln net.Listener) error { return serveIMAP(ctx, ln, hostname) }
		case "ssh":
			run = func(ctx context.Context, ln net.Listener) error { return serveSSH(ctx, ln, hostname) }
		default:
			return nil, fmt.Errorf("unsupported proto %q", s.proto)
		}
		out = append(out, svc{port: s.port, run: run})
	}
	return out, nil
}

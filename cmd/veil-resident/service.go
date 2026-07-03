package main

import (
	"context"
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

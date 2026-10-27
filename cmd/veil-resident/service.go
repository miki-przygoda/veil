package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const maxServiceConns = 64

// errLineTooLong is readLine's error for a line longer than its bound.
var errLineTooLong = errors.New("line too long")

// readLine reads one '\n'-terminated line (terminator included) of at most max
// bytes. Unlike ReadString it never holds more than max plus r's buffer, so a
// subject streaming bytes with no newline can't grow the resident's heap: it checks
// the bound against whatever has arrived (not only once r's buffer fills) and
// returns errLineTooLong as soon as it is crossed. A partial line at EOF/error
// returns "" and the error.
func readLine(r *bufio.Reader, max int) (string, error) {
	var line []byte
	for {
		if r.Buffered() == 0 {
			if _, err := r.Peek(1); err != nil { // one read from the conn
				return "", err
			}
		}
		buf, _ := r.Peek(r.Buffered())
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			if len(line)+i+1 > max {
				return "", errLineTooLong
			}
			line = append(line, buf[:i+1]...)
			_, _ = r.Discard(i + 1)
			return string(line), nil
		}
		if len(line)+len(buf) >= max { // no room left for the terminator
			return "", errLineTooLong
		}
		line = append(line, buf...)
		_, _ = r.Discard(len(buf))
	}
}

// hangUp ends a conn after a final reply was written to it: it half-closes and
// briefly drains what the peer is still sending (bounded in bytes and time), so the
// close doesn't RST away the reply before the peer reads it. The caller still
// closes c (acceptLoop does).
func hangUp(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = io.Copy(io.Discard, io.LimitReader(c, 64<<10))
}

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

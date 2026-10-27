package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// httpServerHeader is a plausible reverse-proxy banner for fingerprint realism.
const httpServerHeader = "nginx/1.24.0"

// serveHTTP runs a stdlib http.Server serving a small fake intranet, shutting down
// gracefully when ctx is cancelled. Returns nil on a clean shutdown. Open conns are
// capped at maxServiceConns, like the raw-TCP services' acceptLoop.
func serveHTTP(ctx context.Context, ln net.Listener, hostname string) error {
	srv := newHTTPServer(hostname)
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.Serve(newLimitListener(ln, maxServiceConns)); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// newHTTPServer builds the fake intranet's server. Every timeout is set so idle
// keep-alive and slow conns are reaped rather than held open forever.
func newHTTPServer(hostname string) *http.Server {
	withServer := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", httpServerHeader)
			h(w, r)
		}
	}
	page := func(title, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "<!doctype html><html><head><title>%s — %s</title></head>"+
				"<body>%s</body></html>", hostname, title, body)
		}
	}
	mux := http.NewServeMux()
	// The landing page links to /docs and /status; both are served (a crawler that
	// follows the links must not hit a 404 from the same host — a believability tell).
	mux.HandleFunc("/", withServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		page("intranet", fmt.Sprintf("<h1>%s intranet</h1><ul>"+
			"<li><a href=\"/docs\">docs</a></li>"+
			"<li><a href=\"/status\">status</a></li></ul>", hostname))(w, r)
	}))
	mux.HandleFunc("/docs", withServer(page("docs",
		"<h1>Documentation</h1><p>Internal documentation portal. Access restricted.</p>")))
	mux.HandleFunc("/status", withServer(page("status",
		"<h1>Status</h1><p>All systems operational.</p>")))
	return &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
}

// limitListener caps concurrently open accepted conns at cap(sem): Accept takes a
// slot (blocking while all are in use, so excess dials wait in the kernel backlog)
// and the conn's first Close gives it back. Close unblocks a waiting Accept.
type limitListener struct {
	net.Listener
	sem       chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func newLimitListener(ln net.Listener, n int) net.Listener {
	return &limitListener{Listener: ln, sem: make(chan struct{}, n), done: make(chan struct{})}
}

func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.sem <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: c, release: func() { <-l.sem }}, nil
}

func (l *limitListener) Close() error {
	err := l.Listener.Close()
	l.closeOnce.Do(func() { close(l.done) })
	return err
}

// limitConn releases its listener slot exactly once, however often it is closed.
type limitConn struct {
	net.Conn
	release   func()
	closeOnce sync.Once
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(c.release)
	return err
}

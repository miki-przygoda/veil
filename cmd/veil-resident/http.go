package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// httpServerHeader is a plausible reverse-proxy banner for fingerprint realism.
const httpServerHeader = "nginx/1.24.0"

// serveHTTP runs a stdlib http.Server serving a small fake intranet, shutting down
// gracefully when ctx is cancelled. Returns nil on a clean shutdown.
func serveHTTP(ctx context.Context, ln net.Listener, hostname string) error {
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
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

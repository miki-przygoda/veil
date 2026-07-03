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
	mux := http.NewServeMux()
	mux.HandleFunc("/", withServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, "<!doctype html><html><head><title>%s</title></head><body>"+
			"<h1>%s intranet</h1><ul><li><a href=\"/docs\">docs</a></li>"+
			"<li><a href=\"/status\">status</a></li></ul></body></html>", hostname, hostname)
	}))
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

// Package viz exposes the live event feed to the dashboard.
//
// The feed is Server-Sent Events: a one-way stream from host to viewer, which
// matches Veil's outside-in observation model exactly. There is deliberately no
// channel for the viewer to push anything back into the world.
package viz

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/miki-przygoda/veil/internal/events"
)

// Server serves the dashboard and the SSE event stream.
type Server struct {
	bus    *events.Bus
	mux    *http.ServeMux
	addr   string
	log    *slog.Logger
	report func() any // when non-nil, served at GET /report
}

// NewServer wires routes for the given bus. When report is non-nil, GET /report
// serves report() as JSON (the escape-score snapshot); nil omits that route.
func NewServer(addr string, bus *events.Bus, log *slog.Logger, report func() any) *Server {
	s := &Server{bus: bus, mux: http.NewServeMux(), addr: addr, log: log, report: report}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	s.mux.HandleFunc("GET /events", s.handleEvents)
	if s.report != nil {
		s.mux.HandleFunc("GET /report", s.handleReport)
	}
	s.mux.Handle("GET /", http.FileServer(http.Dir("web")))
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	feed, unsubscribe := s.bus.Subscribe()
	defer unsubscribe()

	// Flush headers plus a comment right away, so EventSource.onopen fires on a
	// quiet feed instead of waiting for the first event or keepalive.
	fmt.Fprint(w, ": ok\n\n")
	flusher.Flush()

	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-keepalive.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		case e := <-feed:
			data, err := json.Marshal(e)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// handleReport serves the current report snapshot as JSON. One-way, read-only:
// the viewer pulls state; nothing flows back to the world.
func (s *Server) handleReport(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(s.report()); err != nil {
		http.Error(w, "report encode failed", http.StatusInternalServerError)
	}
}

// handler wraps the mux with a Content-Security-Policy so the dashboard runs no
// inline script and can't be used to exfiltrate: even if an attacker-controlled
// field slipped past output-encoding, default-src 'self' blocks inline execution
// and off-origin loads. Requires the dashboard's script/style to be same-origin
// files (web/app.js, web/app.css), which the FileServer already serves.
func (s *Server) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		s.mux.ServeHTTP(w, r)
	})
}

// httpServer builds the listener's http.Server. ReadHeaderTimeout bounds a slow
// client's header phase. There is deliberately no WriteTimeout: it would cut
// every long-lived /events stream.
func (s *Server) httpServer() *http.Server {
	return &http.Server{Addr: s.addr, Handler: s.handler(), ReadHeaderTimeout: 10 * time.Second}
}

// Run starts the HTTP server and blocks until ctx is cancelled, then shuts down
// gracefully.
func (s *Server) Run(ctx context.Context) error {
	srv := s.httpServer()

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	s.log.Info("viz listening", "addr", s.addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

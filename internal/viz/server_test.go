package viz

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/miki-przygoda/veil/internal/events"
)

func quietServer() *Server {
	return NewServer(":0", events.NewBus(4), slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestVizSetsCSP(t *testing.T) {
	s := quietServer()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	if got := rec.Header().Get("Content-Security-Policy"); got != "default-src 'self'" {
		t.Errorf("CSP = %q, want \"default-src 'self'\"", got)
	}
	if rec.Code != http.StatusOK { // handler still routes through to the mux
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

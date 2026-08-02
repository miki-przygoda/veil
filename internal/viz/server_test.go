package viz

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/miki-przygoda/veil/internal/events"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func quietServer() *Server {
	return NewServer(":0", events.NewBus(4), quietLog(), nil)
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

func TestReportEndpointServesProviderJSON(t *testing.T) {
	rep := map[string]any{"score": 7, "stage": "recon"}
	s := NewServer(":0", events.NewBus(4), quietLog(), func() any { return rep })
	req := httptest.NewRequest(http.MethodGet, "/report", nil)
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	if !strings.Contains(rec.Body.String(), `"score":7`) {
		t.Errorf("body = %s, want it to contain the report JSON", rec.Body.String())
	}
}

func TestReportEndpointAbsentWhenNilProvider(t *testing.T) {
	s := NewServer(":0", events.NewBus(4), quietLog(), nil)
	req := httptest.NewRequest(http.MethodGet, "/report", nil)
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	// No /report route registered -> falls through to the FileServer catch-all -> 404.
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (route not registered)", rec.Code)
	}
}

package subject

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseAction(t *testing.T) {
	if a := parseAction("STOP done exploring"); !a.Stop {
		t.Errorf("STOP not recognised: %+v", a)
	}
	if a := parseAction("`whoami`"); a.Command != "whoami" || a.Stop {
		t.Errorf("fenced command mis-parsed: %+v", a)
	}
	if a := parseAction("ls -la\nignored second line"); a.Command != "ls -la" {
		t.Errorf("multi-line: took %q, want first line", a.Command)
	}
	if a := parseAction("   "); !a.Stop {
		t.Errorf("empty response must Stop: %+v", a)
	}
}

func TestClaudeBrainDecideParsesCommand(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "k" {
			t.Errorf("x-api-key = %q, want k", r.Header.Get("x-api-key"))
		}
		if r.Header.Get("anthropic-version") == "" {
			t.Error("missing anthropic-version header")
		}
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"ls -la"}]}`))
	}))
	defer srv.Close()

	b := newClaudeBrainWithEndpoint(srv.Client(), "k", "m", srv.URL)
	act, err := b.Decide(context.Background(), "goal", nil)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Command != "ls -la" || act.Stop {
		t.Errorf("act = %+v, want Command=ls -la", act)
	}
}

func TestClaudeBrainDecideSurfacesAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":{"message":"bad"}}`, http.StatusBadRequest)
	}))
	defer srv.Close()
	b := newClaudeBrainWithEndpoint(srv.Client(), "k", "m", srv.URL)
	if _, err := b.Decide(context.Background(), "g", nil); err == nil {
		t.Error("non-200 must return an error")
	}
}

func TestClaudeBrainDecideHandlesRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"stop_reason":"refusal","content":[]}`))
	}))
	defer srv.Close()
	b := newClaudeBrainWithEndpoint(srv.Client(), "k", "m", srv.URL)
	act, err := b.Decide(context.Background(), "g", nil)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !act.Stop {
		t.Error("a refusal (stop_reason=refusal) must end the run cleanly, not error or run a command")
	}
}

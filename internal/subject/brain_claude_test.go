package subject

import (
	"context"
	"encoding/json"
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

func TestParseActionRecoversFencedCommand(t *testing.T) {
	if a := parseAction("```\nls -la\n```"); a.Command != "ls -la" || a.Stop {
		t.Errorf("fenced block: got %+v, want Command=ls -la", a)
	}
	if a := parseAction("```"); !a.Stop {
		t.Error("a reply that is only a bare fence must Stop, never run an empty command")
	}
}

func TestClaudeBrainDecideSkipsThinkingBlocks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"content":[{"type":"thinking","text":""},{"type":"text","text":"whoami"}]}`))
	}))
	defer srv.Close()
	b := newClaudeBrainWithEndpoint(srv.Client(), "k", "m", srv.URL)
	act, err := b.Decide(context.Background(), "g", nil)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Command != "whoami" || act.Stop {
		t.Errorf("thinking block not skipped: %+v", act)
	}
}

func TestClaudeBrainDecideSendsHistoryAndSeed(t *testing.T) {
	decodeMessages := func(r *http.Request) []map[string]any {
		var body struct {
			Messages []map[string]any `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		return body.Messages
	}
	// empty history must still send a non-empty messages array (the API rejects an empty one)
	var noHistory []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		noHistory = decodeMessages(r)
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"id"}]}`))
	}))
	defer srv.Close()
	if _, err := newClaudeBrainWithEndpoint(srv.Client(), "k", "m", srv.URL).
		Decide(context.Background(), "goal", nil); err != nil {
		t.Fatal(err)
	}
	if len(noHistory) == 0 {
		t.Error("empty history must still send a non-empty messages array")
	}
	// history maps to one assistant + one user turn per Turn
	var withHistory []map[string]any
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		withHistory = decodeMessages(r)
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"id"}]}`))
	}))
	defer srv2.Close()
	hist := []Turn{{Command: "whoami", ExitCode: 0, Output: "root"}}
	if _, err := newClaudeBrainWithEndpoint(srv2.Client(), "k", "m", srv2.URL).
		Decide(context.Background(), "goal", hist); err != nil {
		t.Fatal(err)
	}
	if len(withHistory) != 2 || withHistory[0]["role"] != "assistant" || withHistory[1]["role"] != "user" {
		t.Errorf("history mapping = %v, want [assistant, user]", withHistory)
	}
}

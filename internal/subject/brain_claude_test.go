package subject

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
	if len(withHistory) != 3 ||
		withHistory[0]["role"] != "user" ||
		withHistory[1]["role"] != "assistant" ||
		withHistory[2]["role"] != "user" {
		t.Errorf("history mapping = %v, want [user(seed), assistant, user]", withHistory)
	}
}

func TestParseActionTable(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		cmd    string
		stop   bool
		reason string
	}{
		{name: "fence with language tag", in: "```bash\nls -la\n```", cmd: "ls -la"},
		{name: "fence with sh tag", in: "```sh\nid\n```", cmd: "id"},
		{name: "plain fence", in: "```\nls -la\n```", cmd: "ls -la"},
		{name: "inline backticks", in: "`whoami`", cmd: "whoami"},
		{name: "inline backticks keep inner content", in: "`echo `id``", cmd: "echo `id`"},
		{name: "only a fence", in: "```bash\n```", stop: true, reason: "empty response"},
		{name: "STOP with reason", in: "STOP done exploring", stop: true, reason: "done exploring"},
		{name: "bare STOP", in: "STOP", stop: true},
		{name: "lowercase stop", in: "stop nothing left", stop: true, reason: "nothing left"},
		{name: "STOP with colon", in: "STOP: finished", stop: true, reason: "finished"},
		{name: "backticked STOP", in: "`STOP`", stop: true},
		{name: "fenced STOP", in: "```\nSTOP all done\n```", stop: true, reason: "all done"},
		{name: "STOP-prefixed command is a command", in: "STOPPED_SVC=1 env", cmd: "STOPPED_SVC=1 env"},
		{name: "STOP-prefixed word is a command", in: "STOPme", cmd: "STOPme"},
		{name: "one-line triple backticks", in: "```ls -la```", cmd: "ls -la"},
		{name: "one-line triple backticks short", in: "```id```", cmd: "id"},
		{name: "one-line triple backticks keep inner text verbatim", in: "```bash ls -la```", cmd: "bash ls -la"},
		{name: "one-line triple backticks around STOP", in: "```STOP done```", stop: true, reason: "done"},
		{name: "empty one-line triple backticks", in: "``````\nid", cmd: "id"},
		{name: "STOP with period", in: "STOP.", stop: true},
		{name: "STOP with bang", in: "STOP!", stop: true},
		{name: "STOP with period and reason", in: "STOP. nothing left", stop: true, reason: "nothing left"},
		{name: "lowercase stop with period", in: "stop.", stop: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := parseAction(tt.in)
			if a.Stop != tt.stop || a.Command != tt.cmd || (tt.stop && a.Reason != tt.reason) {
				t.Errorf("parseAction(%q) = %+v, want Command=%q Stop=%v Reason=%q", tt.in, a, tt.cmd, tt.stop, tt.reason)
			}
		})
	}
}

func TestClaudeBrainDecideErrorsOnMaxTokens(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "empty text (budget spent thinking)", body: `{"stop_reason":"max_tokens","content":[{"type":"thinking","text":""}]}`},
		{name: "truncated command", body: `{"stop_reason":"max_tokens","content":[{"type":"text","text":"find / -name"}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()
			act, err := newClaudeBrainWithEndpoint(srv.Client(), "k", "m", srv.URL).
				Decide(context.Background(), "g", nil)
			if err == nil {
				t.Fatalf("max_tokens must return an error, got %+v", act)
			}
			if !strings.Contains(err.Error(), "max_tokens") {
				t.Errorf("error %q should name max_tokens", err)
			}
		})
	}
}

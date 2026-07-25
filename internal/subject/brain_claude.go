package subject

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	claudeEndpoint     = "https://api.anthropic.com/v1/messages"
	claudeAPIVersion   = "2023-06-01"
	claudeDefaultModel = "claude-opus-5" // per the claude-api skill; override with VEIL_SUBJECT_MODEL
	// claudeMaxTokens bounds the reply. Current models run adaptive thinking ON by
	// default and max_tokens caps thinking+text together, so a tight budget can be
	// spent entirely on thinking and truncate the command. 2048 leaves headroom;
	// Decide reads only the "text" block, so the (empty-text) thinking block is ignored.
	claudeMaxTokens = 2048
	claudeStopToken = "STOP"
)

// claudeBrain is the opt-in autonomous brain: it asks the Anthropic Messages API
// for the next shell command. This is host-side egress from veild — the box
// stays contained. It sees only the goal and its own bounded turns.
type claudeBrain struct {
	httpc    *http.Client
	key      string
	model    string
	endpoint string
}

// NewClaudeBrain builds a Claude-backed brain. The caller gates on a non-empty
// key; model "" uses claudeDefaultModel.
func NewClaudeBrain(key, model string) Brain {
	return newClaudeBrainWithEndpoint(&http.Client{Timeout: 60 * time.Second}, key, model, claudeEndpoint)
}

func newClaudeBrainWithEndpoint(httpc *http.Client, key, model, endpoint string) *claudeBrain {
	if model == "" {
		model = claudeDefaultModel
	}
	return &claudeBrain{httpc: httpc, key: key, model: model, endpoint: endpoint}
}

func (b *claudeBrain) Decide(ctx context.Context, goal string, history []Turn) (Action, error) {
	reqBody := map[string]any{
		"model":      b.model,
		"max_tokens": claudeMaxTokens,
		"system":     claudeSystemPrompt(goal),
		"messages":   claudeMessages(history),
	}
	buf, err := json.Marshal(reqBody)
	if err != nil {
		return Action{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.endpoint, bytes.NewReader(buf))
	if err != nil {
		return Action{}, err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-api-key", b.key)
	req.Header.Set("anthropic-version", claudeAPIVersion)

	resp, err := b.httpc.Do(req)
	if err != nil {
		return Action{}, fmt.Errorf("claude: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Action{}, fmt.Errorf("claude: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Action{}, fmt.Errorf("claude: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		StopReason string `json:"stop_reason"`
		Content    []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return Action{}, fmt.Errorf("claude: decode: %w", err)
	}
	// A safety-classifier refusal (HTTP 200, stop_reason "refusal") ends the run
	// cleanly rather than erroring — the subject simply gives up.
	if out.StopReason == "refusal" {
		return Action{Stop: true, Reason: "model declined (refusal)"}, nil
	}
	var text string
	for _, c := range out.Content { // only "text" blocks; thinking blocks are skipped
		if c.Type == "text" {
			text += c.Text
		}
	}
	return parseAction(text), nil
}

// parseAction turns the model's reply into an Action: the first non-empty line
// is the command (STOP ends the run). Strips markdown backticks defensively.
func parseAction(text string) Action {
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if strings.HasPrefix(l, claudeStopToken) {
			return Action{Stop: true, Reason: strings.TrimSpace(strings.TrimPrefix(l, claudeStopToken))}
		}
		l = strings.Trim(l, "`")
		if l == "" {
			continue // a bare fence line (``` etc.) — keep scanning for the real command
		}
		return Action{Command: l}
	}
	return Action{Stop: true, Reason: "empty response"}
}

func claudeSystemPrompt(goal string) string {
	return "You are an operator exploring a Linux host you have shell access to. " +
		"Objective: " + goal + ". " +
		"Each turn, respond with EXACTLY ONE shell command to run next and nothing else — " +
		"no explanation, no markdown, no code fences. Shell state (cwd, env) persists between commands. " +
		"You only see the output of your own commands. " +
		"When you have nothing left to investigate, respond with the single word " + claudeStopToken + "."
}

func claudeMessages(history []Turn) []map[string]any {
	var msgs []map[string]any
	for _, t := range history {
		msgs = append(msgs, map[string]any{"role": "assistant", "content": t.Command})
		msgs = append(msgs, map[string]any{"role": "user", "content": fmt.Sprintf("exit=%d\n%s", t.ExitCode, t.Output)})
	}
	if len(msgs) == 0 {
		// The Messages API requires a non-empty messages array.
		msgs = append(msgs, map[string]any{"role": "user", "content": "Begin. What is your first command?"})
	}
	return msgs
}

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
	// spent entirely on thinking and truncate the command. 4096 leaves headroom;
	// Decide reads only the "text" block, so the (empty-text) thinking block is ignored.
	claudeMaxTokens = 4096
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
	// A reply cut off at the token cap is not an answer: its text is empty (the
	// budget went on thinking) or a truncated command. Error so the run ends with
	// a clear reason instead of executing a fragment.
	if out.StopReason == "max_tokens" {
		return Action{}, fmt.Errorf("claude: reply truncated (stop_reason max_tokens, budget %d)", claudeMaxTokens)
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
// that is not a markdown fence is the command. Any line starting with ``` is a
// fence (with or without a language tag) and is skipped; one surrounding pair of
// inline backticks is stripped. A one-line ```cmd``` wrap yields its inner text.
// The run stops when the line's first word is STOP (case-insensitive, trailing
// punctuation such as "STOP:" or "STOP." tolerated); the rest of the line is the reason.
func parseAction(text string) Action {
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "```") {
			if len(l) < 6 || !strings.HasSuffix(l, "```") {
				continue // fence line (```, ```bash, …) — never a command
			}
			// One-line ```cmd``` wrap: the inner text, verbatim, is the command.
			l = strings.TrimSpace(l[3 : len(l)-3])
		}
		if len(l) >= 2 && l[0] == '`' && l[len(l)-1] == '`' {
			l = strings.TrimSpace(l[1 : len(l)-1])
		}
		if strings.Trim(l, "`") == "" {
			continue // empty, or stray backticks only — keep scanning for the real command
		}
		if tok := strings.Fields(l)[0]; strings.EqualFold(strings.TrimRight(tok, ".:!,;"), claudeStopToken) {
			return Action{Stop: true, Reason: strings.TrimSpace(l[len(tok):])}
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
	// Always seed a user turn first: the Messages API requires messages[0].role == "user".
	// Result: user(seed), assistant(cmd1), user(result1), assistant(cmd2), … — user-first,
	// alternating, ending on a user turn so the API generates the next command.
	msgs := []map[string]any{{"role": "user", "content": "Begin. What is your first command?"}}
	for _, t := range history {
		msgs = append(msgs, map[string]any{"role": "assistant", "content": t.Command})
		msgs = append(msgs, map[string]any{"role": "user", "content": fmt.Sprintf("exit=%d\n%s", t.ExitCode, t.Output)})
	}
	return msgs
}

package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// dockerAPIVersion is the pinned Engine API version. Docker daemons reject
// versions below their minimum (Docker 29's minimum is 1.44), so this must be
// >= the oldest daemon we target. Version negotiation via GET /version would be
// more robust across very old/new daemons; see the design's future work.
const dockerAPIVersion = "v1.44"

// dockerEngine talks to the Docker Engine API over a unix socket using only the
// standard library.
type dockerEngine struct {
	httpc *http.Client
	root  string // scheme+host, e.g. http://docker (real) or the httptest URL
}

var _ engine = (*dockerEngine)(nil)

// newDockerEngine builds an engine for the given DOCKER_HOST value. Empty means
// the default unix socket. Only unix:// (or empty) is supported this iteration.
func newDockerEngine(host string) (*dockerEngine, error) {
	socket := "/var/run/docker.sock"
	switch {
	case host == "":
	case strings.HasPrefix(host, "unix://"):
		socket = strings.TrimPrefix(host, "unix://")
	default:
		return nil, fmt.Errorf("unsupported DOCKER_HOST %q (only unix:// supported)", host)
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}
	return &dockerEngine{httpc: &http.Client{Transport: tr, Timeout: 30 * time.Second}, root: "http://docker"}, nil
}

// newEngineWithClient injects an HTTP client + root URL (used by tests against
// an httptest server, so the request/response contract is exercised offline).
func newEngineWithClient(httpc *http.Client, root string) *dockerEngine {
	return &dockerEngine{httpc: httpc, root: root}
}

func (e *dockerEngine) versioned(path string) string {
	return e.root + "/" + dockerAPIVersion + path
}

// do issues a request to a versioned endpoint, JSON-encoding body if non-nil.
// A transport-level failure means the daemon is unreachable, so it is wrapped
// with ErrEngineUnavailable for every method (not just ping); callers may
// therefore errors.Is(err, ErrEngineUnavailable) after any engine call.
func (e *dockerEngine) do(ctx context.Context, method, path string, query url.Values, body any) (*http.Response, error) {
	// Keep bodyReader a nil io.Reader interface when there is no body; passing a
	// typed-nil *bytes.Reader would make NewRequest try to read it.
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(b)
	}
	u := e.versioned(path)
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bodyReader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := e.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEngineUnavailable, err)
	}
	return resp, nil
}

func decodeError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var m struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &m); err == nil && m.Message != "" {
		return &engineError{status: resp.StatusCode, message: m.Message}
	}
	return &engineError{status: resp.StatusCode, message: strings.TrimSpace(string(body))}
}

func decodeID(resp *http.Response) (string, error) {
	var out struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.ID, nil
}

func (e *dockerEngine) ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.root+"/_ping", nil)
	if err != nil {
		return err
	}
	resp, err := e.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrEngineUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: ping status %d", ErrEngineUnavailable, resp.StatusCode)
	}
	return nil
}

func (e *dockerEngine) imageExists(ctx context.Context, ref string) (bool, error) {
	resp, err := e.do(ctx, http.MethodGet, "/images/"+ref+"/json", nil, nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, decodeError(resp)
	}
}

func (e *dockerEngine) create(ctx context.Context, spec createSpec) (string, error) {
	q := url.Values{}
	if spec.name != "" {
		q.Set("name", spec.name)
	}
	resp, err := e.do(ctx, http.MethodPost, "/containers/create", q, spec)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return "", decodeError(resp)
	}
	return decodeID(resp)
}

func (e *dockerEngine) start(ctx context.Context, id string) error {
	resp, err := e.do(ctx, http.MethodPost, "/containers/"+id+"/start", nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// 204 started; 304 already started.
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotModified {
		return decodeError(resp)
	}
	return nil
}

func (e *dockerEngine) remove(ctx context.Context, id string, force bool) error {
	q := url.Values{}
	if force {
		q.Set("force", "1")
	}
	resp, err := e.do(ctx, http.MethodDelete, "/containers/"+id, q, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// 204 removed; 404 already gone -> idempotent success.
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return decodeError(resp)
	}
	return nil
}

func (e *dockerEngine) commit(ctx context.Context, id, ref string) (string, error) {
	repo, tag, _ := strings.Cut(ref, ":")
	q := url.Values{}
	q.Set("container", id)
	q.Set("repo", repo)
	if tag != "" {
		q.Set("tag", tag)
	}
	resp, err := e.do(ctx, http.MethodPost, "/commit", q, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return "", decodeError(resp)
	}
	return decodeID(resp)
}

func (e *dockerEngine) removeImage(ctx context.Context, ref string) error {
	q := url.Values{}
	q.Set("force", "1")
	resp, err := e.do(ctx, http.MethodDelete, "/images/"+ref, q, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return decodeError(resp)
	}
	return nil
}

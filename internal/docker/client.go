package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrEngineUnavailable means the Docker daemon could not be reached.
var ErrEngineUnavailable = errors.New("docker engine unavailable")

// engineError wraps a non-2xx Docker API response.
type engineError struct {
	status  int
	message string
}

func (e *engineError) Error() string {
	return fmt.Sprintf("docker api: status %d: %s", e.status, e.message)
}

// CreateSpec is the body (plus Name) for POST /containers/create. Name is sent
// as the ?name= query parameter, never in the JSON body.
type CreateSpec struct {
	Name string `json:"-"`

	User             string            `json:"User,omitempty"`
	Image            string            `json:"Image"`
	Cmd              []string          `json:"Cmd,omitempty"`
	Labels           map[string]string `json:"Labels,omitempty"`
	NetworkDisabled  bool              `json:"NetworkDisabled"`
	HostConfig       HostConfig        `json:"HostConfig"`
	NetworkingConfig *NetworkingConfig `json:"NetworkingConfig,omitempty"`
}

type HostConfig struct {
	ReadonlyRootfs bool              `json:"ReadonlyRootfs"`
	Tmpfs          map[string]string `json:"Tmpfs,omitempty"`
	CapDrop        []string          `json:"CapDrop,omitempty"`
	CapAdd         []string          `json:"CapAdd,omitempty"` // residents add NET_BIND_SERVICE
	SecurityOpt    []string          `json:"SecurityOpt,omitempty"`
	PidsLimit      int64             `json:"PidsLimit,omitempty"`
	Memory         int64             `json:"Memory,omitempty"`
	NetworkMode    string            `json:"NetworkMode,omitempty"`
	Dns            []string          `json:"Dns,omitempty"` // per-container resolver list
	MaskedPaths    []string          `json:"MaskedPaths,omitempty"`
	ReadonlyPaths  []string          `json:"ReadonlyPaths,omitempty"`
	UsernsMode     string            `json:"UsernsMode,omitempty"`
	CpuPeriod      int64             `json:"CpuPeriod,omitempty"`
	CpuQuota       int64             `json:"CpuQuota,omitempty"`
	Sysctls        map[string]string `json:"Sysctls,omitempty"` // reserved hook; HardenedSpec does not set it yet
}

// NetworkingConfig pins per-network endpoint settings at create time (e.g. a
// static IPv4). Docker honours IPAMConfig.IPv4Address only if it is inside the
// network's subnet.
type NetworkingConfig struct {
	EndpointsConfig map[string]EndpointConfig `json:"EndpointsConfig,omitempty"`
}

type EndpointConfig struct {
	IPAMConfig *EndpointIPAM `json:"IPAMConfig,omitempty"`
}

type EndpointIPAM struct {
	IPv4Address string `json:"IPv4Address,omitempty"`
}

// dockerAPIVersion is the pinned Engine API version. Docker daemons reject
// versions below their minimum (Docker 29's minimum is 1.44), so this must be
// >= the oldest daemon we target. Version negotiation via GET /version would be
// more robust across very old/new daemons; see the design's future work.
const dockerAPIVersion = "v1.44"

// Client talks to the Docker Engine API over a unix socket using only the
// standard library.
type Client struct {
	httpc *http.Client
	root  string // scheme+host, e.g. http://docker (real) or the httptest URL
}

// New builds a Client for the given DOCKER_HOST value. Empty means the default
// unix socket. Only unix:// (or empty) is supported this iteration.
func New(host string) (*Client, error) {
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
	return &Client{httpc: &http.Client{Transport: tr, Timeout: 30 * time.Second}, root: "http://docker"}, nil
}

// newClientWithHTTP injects an HTTP client + root URL (used by tests against
// an httptest server, so the request/response contract is exercised offline).
func newClientWithHTTP(httpc *http.Client, root string) *Client {
	return &Client{httpc: httpc, root: root}
}

func (c *Client) versioned(path string) string {
	return c.root + "/" + dockerAPIVersion + path
}

// do issues a request to a versioned endpoint, JSON-encoding body if non-nil.
// A transport-level failure means the daemon is unreachable, so it is wrapped
// with ErrEngineUnavailable for every method (not just ping); callers may
// therefore errors.Is(err, ErrEngineUnavailable) after any engine call.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any) (*http.Response, error) {
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
	u := c.versioned(path)
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
	resp, err := c.httpc.Do(req)
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

// Ping checks whether the Docker daemon is reachable.
func (c *Client) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.root+"/_ping", nil)
	if err != nil {
		return err
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrEngineUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: ping status %d", ErrEngineUnavailable, resp.StatusCode)
	}
	return nil
}

// ImageExists reports whether the image ref is present locally.
func (c *Client) ImageExists(ctx context.Context, ref string) (bool, error) {
	resp, err := c.do(ctx, http.MethodGet, "/images/"+ref+"/json", nil, nil)
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

// CreateContainer creates a container from the given spec and returns its ID.
func (c *Client) CreateContainer(ctx context.Context, spec CreateSpec) (string, error) {
	q := url.Values{}
	if spec.Name != "" {
		q.Set("name", spec.Name)
	}
	resp, err := c.do(ctx, http.MethodPost, "/containers/create", q, spec)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return "", decodeError(resp)
	}
	return decodeID(resp)
}

// StartContainer starts the container with the given ID.
func (c *Client) StartContainer(ctx context.Context, id string) error {
	resp, err := c.do(ctx, http.MethodPost, "/containers/"+id+"/start", nil, nil)
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

// RemoveContainer removes the container with the given ID. If force is true,
// the container is removed even if it is running. 404 is tolerated (idempotent).
func (c *Client) RemoveContainer(ctx context.Context, id string, force bool) error {
	q := url.Values{}
	if force {
		q.Set("force", "1")
	}
	resp, err := c.do(ctx, http.MethodDelete, "/containers/"+id, q, nil)
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

// Commit commits the container as an image and returns the new image ID.
func (c *Client) Commit(ctx context.Context, id, ref string) (string, error) {
	repo, tag, _ := strings.Cut(ref, ":")
	q := url.Values{}
	q.Set("container", id)
	q.Set("repo", repo)
	if tag != "" {
		q.Set("tag", tag)
	}
	resp, err := c.do(ctx, http.MethodPost, "/commit", q, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return "", decodeError(resp)
	}
	return decodeID(resp)
}

// RemoveImage removes the image by ref. 404 is tolerated (idempotent).
func (c *Client) RemoveImage(ctx context.Context, ref string) error {
	q := url.Values{}
	q.Set("force", "1")
	resp, err := c.do(ctx, http.MethodDelete, "/images/"+ref, q, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return decodeError(resp)
	}
	return nil
}

// execOutputCap bounds how much of an exec's output we read, so a runaway
// command inside the box cannot flood the observer.
const execOutputCap = 64 << 10 // 64 KiB

// ExecCreate creates an exec instance in the container and returns its ID.
// TTY mode gives a single merged stdout+stderr stream (a transcript row).
func (c *Client) ExecCreate(ctx context.Context, id string, cmd []string) (string, error) {
	body := map[string]any{
		"AttachStdout": true,
		"AttachStderr": true,
		"Tty":          true,
		"Cmd":          cmd,
	}
	resp, err := c.do(ctx, http.MethodPost, "/containers/"+id+"/exec", nil, body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return "", decodeError(resp)
	}
	return decodeID(resp)
}

// ExecStart starts a created exec and returns its merged output, read to EOF but
// bounded by execOutputCap. For an output-only (non-interactive) exec, reading
// the response body to EOF is sufficient — no stream hijack needed.
func (c *Client) ExecStart(ctx context.Context, execID string) ([]byte, error) {
	body := map[string]any{"Detach": false, "Tty": true}
	resp, err := c.do(ctx, http.MethodPost, "/exec/"+execID+"/start", nil, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, decodeError(resp)
	}
	return io.ReadAll(io.LimitReader(resp.Body, execOutputCap))
}

// ExecInspect returns the exit code of a finished exec (the start stream carries
// no status, so the code is fetched separately once the process has exited).
func (c *Client) ExecInspect(ctx context.Context, execID string) (int, error) {
	resp, err := c.do(ctx, http.MethodGet, "/exec/"+execID+"/json", nil, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, decodeError(resp)
	}
	var out struct {
		ExitCode int `json:"ExitCode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, err
	}
	return out.ExitCode, nil
}

// NetworkSpec is the body for POST /networks/create.
type NetworkSpec struct {
	Name       string            `json:"Name"`
	Internal   bool              `json:"Internal"`
	Labels     map[string]string `json:"Labels,omitempty"`
	BridgeName string            `json:"-"` // -> Options["com.docker.network.bridge.name"]
}

// Network is the subset of GET /networks/{id} we use.
type Network struct {
	ID       string
	Name     string
	Internal bool
	Bridge   string // resolved host bridge interface name
	Subnet   string // IPAM.Config[0].Subnet, e.g. "172.20.0.0/16"
	Gateway  string // IPAM.Config[0].Gateway, e.g. "172.20.0.1"
}

func (c *Client) CreateNetwork(ctx context.Context, spec NetworkSpec) (string, error) {
	body := map[string]any{"Name": spec.Name, "Internal": spec.Internal}
	if len(spec.Labels) > 0 {
		body["Labels"] = spec.Labels
	}
	if spec.BridgeName != "" {
		body["Options"] = map[string]string{"com.docker.network.bridge.name": spec.BridgeName}
	}
	resp, err := c.do(ctx, http.MethodPost, "/networks/create", nil, body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return "", decodeError(resp)
	}
	return decodeID(resp)
}

func (c *Client) InspectNetwork(ctx context.Context, id string) (Network, error) {
	resp, err := c.do(ctx, http.MethodGet, "/networks/"+id, nil, nil)
	if err != nil {
		return Network{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Network{}, decodeError(resp)
	}
	var raw struct {
		ID       string            `json:"Id"`
		Name     string            `json:"Name"`
		Internal bool              `json:"Internal"`
		Options  map[string]string `json:"Options"`
		IPAM     struct {
			Config []struct {
				Subnet  string `json:"Subnet"`
				Gateway string `json:"Gateway"`
			} `json:"Config"`
		} `json:"IPAM"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return Network{}, err
	}
	bridge := raw.Options["com.docker.network.bridge.name"]
	if bridge == "" && len(raw.ID) >= 12 {
		bridge = "br-" + raw.ID[:12] // Docker's default bridge naming
	}
	var subnet, gateway string
	if len(raw.IPAM.Config) > 0 {
		subnet, gateway = raw.IPAM.Config[0].Subnet, raw.IPAM.Config[0].Gateway
	}
	return Network{ID: raw.ID, Name: raw.Name, Internal: raw.Internal, Bridge: bridge, Subnet: subnet, Gateway: gateway}, nil
}

func (c *Client) RemoveNetwork(ctx context.Context, id string) error {
	resp, err := c.do(ctx, http.MethodDelete, "/networks/"+id, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return decodeError(resp)
	}
	return nil
}

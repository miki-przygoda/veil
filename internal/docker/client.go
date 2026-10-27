package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ErrEngineUnavailable means the Docker daemon could not be reached.
var ErrEngineUnavailable = errors.New("docker engine unavailable")

// ErrExecUnfinished means ExecInspect found the exec still running, or with no
// exit code recorded, so there is no real exit status to report. ExecInspect
// returns -1 alongside it; it is never reported as a clean exit 0.
var ErrExecUnfinished = errors.New("docker exec has not finished")

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
	CapAdd         []string          `json:"CapAdd,omitempty"` // unused by Veil: caps never reach a non-root, no-new-privileges process
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
	Sysctls        map[string]string `json:"Sysctls,omitempty"` // netns-scoped only; residents set ip_unprivileged_port_start, the box none
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
	root  string                                      // scheme+host, e.g. http://docker (real) or the httptest URL
	dial  func(ctx context.Context) (net.Conn, error) // for hijacked (attached) execs
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
	dialUnix := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialUnix(ctx) },
	}
	return &Client{
		httpc: &http.Client{Transport: tr, Timeout: 30 * time.Second},
		root:  "http://docker",
		dial:  dialUnix,
	}, nil
}

// newClientWithHTTP injects an HTTP client + root URL (used by tests against
// an httptest server, so the request/response contract is exercised offline).
func newClientWithHTTP(httpc *http.Client, root string) *Client {
	c := &Client{httpc: httpc, root: root}
	if u, err := url.Parse(root); err == nil && u.Host != "" {
		host := u.Host
		c.dial = func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", host)
		}
	}
	return c
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

// EngineVersion returns the daemon's engine version string (e.g. "29.1.3") from
// GET /version. Like Ping it is unversioned: an engine older than the pinned API
// would reject a /v1.44/ prefix, and old engines are what callers need to spot.
func (c *Client) EngineVersion(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.root+"/version", nil)
	if err != nil {
		return "", err
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrEngineUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", decodeError(resp)
	}
	var out struct {
		Version string `json:"Version"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return "", fmt.Errorf("decode version: %w", err)
	}
	return out.Version, nil
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

// maxFrameSize bounds a single Docker stream frame's declared payload length so
// a corrupt/hostile length header cannot drive an unbounded allocation. Real
// Docker frames are far smaller (its multiplexer chunks at ~32 KiB); 1 MiB is
// generous headroom.
const maxFrameSize = 1 << 20

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

// ExecStart starts a created exec and returns its merged output. It retains at
// most execOutputCap bytes but reads the stream to EOF, discarding the excess:
// closing early would leave the TTY process blocked writing inside the box (a
// PID held against PidsLimit) and the exec unfinished. The drain is bounded in
// time by ctx and the client timeout; if it is cut short the command did not
// finish, and an error is returned. For an output-only (non-interactive) exec,
// reading the response body to EOF is sufficient — no stream hijack needed.
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
	out, err := io.ReadAll(io.LimitReader(resp.Body, execOutputCap))
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return nil, fmt.Errorf("exec output drain: %w", err)
	}
	return out, nil
}

// ExecInspect returns the exit code of a finished exec (the start stream carries
// no status, so the code is fetched separately once the process has exited). If
// the exec is still running or Docker recorded no exit code (null/absent), it
// returns -1 and an error wrapping ErrExecUnfinished, never a misleading 0.
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
		Running  *bool `json:"Running"`
		ExitCode *int  `json:"ExitCode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, err
	}
	if out.Running != nil && *out.Running {
		return -1, fmt.Errorf("%w: still running", ErrExecUnfinished)
	}
	if out.ExitCode == nil {
		return -1, fmt.Errorf("%w: no exit code", ErrExecUnfinished)
	}
	return *out.ExitCode, nil
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

// hijackedConn presents a hijacked HTTP connection as a raw duplex stream:
// reads come from the buffered reader (which may hold bytes already read past
// the response headers), writes go straight to the underlying conn.
type hijackedConn struct {
	net.Conn
	r *bufio.Reader
}

func (h *hijackedConn) Read(p []byte) (int, error) { return h.r.Read(p) }

// attachHandshakeTimeout bounds ExecAttach's upgrade handshake when ctx carries
// no deadline, so a stalled daemon cannot wedge it. A var so tests can shorten it.
var attachHandshakeTimeout = 30 * time.Second

// ExecAttach creates an interactive exec (stdin+stdout+stderr, no TTY) running
// cmd, starts it on a hijacked connection, and returns the raw duplex stream.
// The caller writes stdin to it and reads Docker's multiplexed stdout/stderr
// frames with DemuxFrame. Closing the returned conn ends the exec. Tty:false
// (framed, no echo, no prompt) is deliberate — it makes programmatic framing
// reliable. ctx bounds the whole handshake (dial, request write, status and
// header reads; attachHandshakeTimeout applies if ctx has no deadline) but not
// the returned stream, whose deadline is cleared before it is handed back.
func (c *Client) ExecAttach(ctx context.Context, id string, cmd []string) (net.Conn, error) {
	create := map[string]any{
		"AttachStdin":  true,
		"AttachStdout": true,
		"AttachStderr": true,
		"Tty":          false,
		"Cmd":          cmd,
	}
	resp, err := c.do(ctx, http.MethodPost, "/containers/"+id+"/exec", nil, create)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusCreated {
		defer resp.Body.Close()
		return nil, decodeError(resp)
	}
	execID, err := decodeID(resp)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	conn, err := c.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEngineUnavailable, err)
	}
	// The dial honours ctx; the raw handshake below does not on its own, so
	// bound it with a conn deadline and make ctx cancellation expire it early.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(attachHandshakeTimeout)
	}
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	br, err := attachHandshake(conn, execID)
	if !stop() && err == nil {
		// ctx ended during the handshake: the cancel callback has run (or is
		// running) and poisoned the deadline, so the stream is unusable.
		err = fmt.Errorf("exec attach: %w", ctx.Err())
	}
	if err != nil {
		conn.Close()
		if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(err, ctxErr) {
			err = fmt.Errorf("%w (%v)", err, ctxErr)
		}
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{}) // the hijacked stream is long-lived
	return &hijackedConn{Conn: conn, r: br}, nil
}

// attachHandshake sends the upgrading exec start on conn and consumes the
// response status and headers. The returned reader holds the start of the raw
// multiplexed stream. The caller owns conn and closes it on error.
func attachHandshake(conn net.Conn, execID string) (*bufio.Reader, error) {
	reqBody := `{"Detach":false,"Tty":false}`
	req := "POST /" + dockerAPIVersion + "/exec/" + execID + "/start HTTP/1.1\r\n" +
		"Host: docker\r\n" +
		"Content-Type: application/json\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: tcp\r\n" +
		"Content-Length: " + strconv.Itoa(len(reqBody)) + "\r\n\r\n" +
		reqBody
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEngineUnavailable, err)
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("%w: exec attach read status: %v", ErrEngineUnavailable, err)
	}
	parts := strings.SplitN(strings.TrimSpace(statusLine), " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("exec attach: bad status line %q", statusLine)
	}
	code, _ := strconv.Atoi(parts[1])
	if code != http.StatusSwitchingProtocols && code != http.StatusOK {
		return nil, &engineError{status: code, message: "exec start"}
	}
	// Consume headers up to the blank line; the rest of br is the raw stream.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("%w: exec attach read headers: %v", ErrEngineUnavailable, err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return br, nil
}

// DemuxFrame reads one Docker multiplexed stream frame from r and returns its
// stream type (1=stdout, 2=stderr) and payload. Returns io.EOF when the stream
// ends between frames.
func DemuxFrame(r io.Reader) (stream byte, payload []byte, err error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[4:8])
	if n > maxFrameSize {
		return 0, nil, fmt.Errorf("docker: stream frame too large (%d bytes)", n)
	}
	payload = make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return hdr[0], payload, nil
}

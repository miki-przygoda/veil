package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/miki-przygoda/veil/internal/docker"
)

// execOutputCap bounds how much of a command's output we RETAIN (a runaway
// command can't flood the observer). shellReadCap bounds how far we read looking
// for the sentinel, so a chatty-but-bounded command still resyncs the shell.
const (
	execOutputCap   = 64 << 10 // 64 KiB retained
	shellReadCap    = 1 << 20  // 1 MiB hard ceiling to find the sentinel
	shellCmdTimeout = 15 * time.Second
)

// Shell runs commands in a single long-lived shell inside the box, so state
// (cwd, env, background processes) persists between commands. It is NOT
// concurrency-safe by contract: the Autopilot owns it and runs one command at a
// time. Close ends the shell.
type Shell interface {
	Run(ctx context.Context, line string) (ExecResult, error)
	Close() error
}

// Sheller is a Sandbox that can open a persistent shell. Optional, like Execer:
// the container backend implements it; the Stub does not.
type Sheller interface {
	OpenShell(ctx context.Context) (Shell, error)
}

// compile-time proof that the real backend satisfies Sheller.
var _ Sheller = (*Container)(nil)

// OpenShell opens a persistent /bin/sh inside the running container over a
// hijacked exec stream. It targets c.containerID (the docker id), never c.id.
func (c *Container) OpenShell(ctx context.Context) (Shell, error) {
	c.mu.Lock()
	st, cid := c.status, c.containerID
	c.mu.Unlock()
	if st != StatusRunning {
		return nil, fmt.Errorf("shell: container not running (status=%s)", st)
	}
	conn, err := c.eng.execAttach(ctx, cid, []string{"/bin/sh"})
	if err != nil {
		return nil, fmt.Errorf("shell: attach: %w", err)
	}
	nonce, err := newNonce()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("shell: nonce: %w", err)
	}
	sh, err := newShell(conn, nonce)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("shell: init: %w", err)
	}
	return sh, nil
}

// containerShell frames commands over a hijacked exec stream. Each Run writes
// the command plus a sentinel that echoes $?, then reads demuxed frames until
// the sentinel line — giving a clean output boundary and exit code without a
// per-command EOF.
type containerShell struct {
	conn  io.ReadWriteCloser
	r     *bufio.Reader
	nonce string

	mu     sync.Mutex
	closed bool
}

// newShell wraps an already-attached duplex stream. It redirects stderr to
// stdout (exec 2>&1) so all output arrives on one ordered stream, making the
// single sentinel scan reliable.
func newShell(conn io.ReadWriteCloser, nonce string) (*containerShell, error) {
	s := &containerShell{conn: conn, r: bufio.NewReader(conn), nonce: nonce}
	if _, err := io.WriteString(conn, "exec 2>&1\n"); err != nil {
		return nil, err
	}
	return s, nil
}

func newNonce() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func (s *containerShell) Run(ctx context.Context, line string) (ExecResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ExecResult{}, errors.New("shell: closed")
	}
	if d, ok := s.conn.(interface{ SetReadDeadline(time.Time) error }); ok {
		deadline := time.Now().Add(shellCmdTimeout)
		if dl, has := ctx.Deadline(); has && dl.Before(deadline) {
			deadline = dl
		}
		_ = d.SetReadDeadline(deadline)
		defer d.SetReadDeadline(time.Time{})
	}
	marker := "__VEIL_" + s.nonce + "__"
	// line's trailing \n is the shell's line terminator (not output); the printf
	// then writes marker<code>\n on its own.
	cmd := line + "\nprintf '" + marker + "%s\\n' \"$?\"\n"
	if _, err := s.conn.Write([]byte(cmd)); err != nil {
		s.poison()
		return ExecResult{}, fmt.Errorf("shell: write: %w", err)
	}
	out, code, err := s.readUntilSentinel(marker)
	if err != nil {
		s.poison()
		return ExecResult{}, err
	}
	return ExecResult{Output: out, ExitCode: code}, nil
}

func (s *containerShell) readUntilSentinel(marker string) ([]byte, int, error) {
	var buf []byte
	for len(buf) < shellReadCap {
		_, payload, err := docker.DemuxFrame(s.r)
		if err != nil {
			return nil, 0, fmt.Errorf("shell: read: %w", err)
		}
		buf = append(buf, payload...)
		if out, code, ok := splitSentinel(buf, marker); ok {
			if len(out) > execOutputCap {
				out = out[:execOutputCap]
			}
			return out, code, nil
		}
	}
	return nil, 0, errors.New("shell: output overflow before sentinel")
}

// splitSentinel returns the command output (everything before the sentinel) and
// the parsed exit code once the full sentinel line is present. ok=false means
// keep reading.
func splitSentinel(buf []byte, marker string) (out []byte, code int, ok bool) {
	i := bytes.Index(buf, []byte(marker))
	if i < 0 {
		return nil, 0, false
	}
	rest := buf[i+len(marker):]
	j := bytes.IndexByte(rest, '\n')
	if j < 0 {
		return nil, 0, false // exit-code line not complete yet
	}
	code, err := strconv.Atoi(string(bytes.TrimSpace(rest[:j])))
	if err != nil {
		code = -1 // unparseable sentinel code; still resynced
	}
	return buf[:i], code, true
}

func (s *containerShell) poison() {
	s.closed = true
	_ = s.conn.Close()
}

func (s *containerShell) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	_, _ = io.WriteString(s.conn, "exit\n")
	return s.conn.Close()
}

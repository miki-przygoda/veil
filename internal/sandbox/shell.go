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
	"strings"
	"sync"
	"time"

	"github.com/miki-przygoda/veil/internal/docker"
)

// execOutputCap bounds how much of a command's output we RETAIN (a runaway
// command can't flood the observer). Past the cap the shell keeps reading and
// discarding until the sentinel, so it resyncs; that scan is bounded by
// shellCmdTimeout (the read deadline), not by a byte count.
const (
	execOutputCap   = 64 << 10 // 64 KiB retained
	shellCmdTimeout = 15 * time.Second
	// maxCodeDigits bounds the exit code's digits. $? is NOT limited to
	// 0-255: in dash and busybox ash `return N` stores N unmasked in a C int,
	// and an overflowing N goes negative. So a code is an optional '-' and up
	// to 10 digits (the int32 range); the per-Run nonce, not this cap, is
	// what authenticates a sentinel.
	maxCodeDigits = 10
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
	sh, err := newShell(conn, newNonce)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("shell: init: %w", err)
	}
	return sh, nil
}

// containerShell frames commands over a hijacked exec stream. Each Run writes
// one line (see frameCommand) that evals the command and then prints a
// sentinel carrying $?, and reads demuxed frames until that sentinel — a clean
// output boundary and exit code without a per-command EOF.
type containerShell struct {
	conn    io.ReadWriteCloser
	r       *bufio.Reader
	nonce   func() (string, error) // a fresh marker per Run
	pending []byte                 // bytes read past the last sentinel

	mu     sync.Mutex
	closed bool
}

// deadliner is the part of net.Conn the shell uses to bound and cancel a Run.
type deadliner interface{ SetDeadline(time.Time) error }

// newShell wraps an already-attached duplex stream. It redirects stderr to
// stdout (exec 2>&1) so all output arrives on one ordered stream, making the
// single sentinel scan reliable.
func newShell(conn io.ReadWriteCloser, nonce func() (string, error)) (*containerShell, error) {
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
	if err := ctx.Err(); err != nil {
		return ExecResult{}, fmt.Errorf("shell: %w", err) // nothing sent; shell intact
	}
	// A fresh nonce per Run, so a replayed or stale sentinel is plain output.
	// It does not stop an in-box process that intercepts the shell's stdin
	// (e.g. reads /proc/$$/fd/0) from stealing this Run's line and forging its
	// sentinel; that can corrupt the transcript, never escape scoring.
	nonce, err := s.nonce()
	if err != nil {
		return ExecResult{}, fmt.Errorf("shell: nonce: %w", err)
	}
	marker := "\n__VEIL_" + nonce + "__"
	if d, ok := s.conn.(deadliner); ok {
		deadline := time.Now().Add(shellCmdTimeout)
		if dl, has := ctx.Deadline(); has && dl.Before(deadline) {
			deadline = dl
		}
		_ = d.SetDeadline(deadline)
		defer d.SetDeadline(time.Time{})
	}
	defer s.abortOnCancel(ctx)() // runs before the deadline reset above

	if _, err := s.conn.Write(frameCommand(line, marker)); err != nil {
		s.poison()
		return ExecResult{}, s.runErr(ctx, fmt.Errorf("shell: write: %w", err))
	}
	out, code, err := s.readUntilSentinel([]byte(marker))
	if err != nil {
		s.poison() // the command may still be running; its state is unknown
		return ExecResult{}, s.runErr(ctx, err)
	}
	return ExecResult{Output: out, ExitCode: code}, nil
}

// abortOnCancel makes ctx cancellation (not just its deadline) unblock the
// in-flight read/write by forcing the deadline into the past, or by closing a
// conn that has no deadlines. The returned stop waits for an abort already in
// progress, so it cannot land on a later Run.
func (s *containerShell) abortOnCancel(ctx context.Context) (stop func()) {
	done := make(chan struct{})
	stopAfter := context.AfterFunc(ctx, func() {
		defer close(done)
		if d, ok := s.conn.(deadliner); ok {
			_ = d.SetDeadline(time.Now())
		} else {
			_ = s.conn.Close()
		}
	})
	return func() {
		if !stopAfter() {
			<-done
		}
	}
}

// runErr reports a cancelled ctx as such rather than as the i/o timeout it
// caused.
func (s *containerShell) runErr(ctx context.Context, err error) error {
	if cerr := ctx.Err(); cerr != nil {
		return fmt.Errorf("shell: %w (%v)", cerr, err)
	}
	return err
}

// frameCommand builds the single stdin line for one Run. [C1] Nothing the
// subject controls is spliced into shell syntax, and the marker never travels
// literally (so set -v/-x cannot echo a matchable sentinel):
//
//   - the command and the marker are sent as printf octal escapes, so a
//     syntax error, unterminated quote/heredoc or trailing backslash stays
//     inside eval and cannot swallow or join the sentinel;
//   - `command eval` strips eval's special-builtin status, so a syntax error
//     fails that eval (status 2) instead of exiting the non-interactive shell;
//   - </dev/null gives the command its own stdin, so cat/read see EOF instead
//     of consuming the framing;
//   - the and-or list keeps the subject's `set -e` from killing the shell;
//   - each framing word is quoted (`\command`, `\unset`) so a subject alias
//     cannot hijack it;
//   - the sentinel is printed by sentinelPrintf, an absolute path: a command
//     name containing '/' is never looked up as a function, and quoting it
//     (`\/usr/bin/printf`) stops alias expansion, which dash and ash do allow
//     for such a name. So no function the subject defines, not even one named
//     `eval`, `unset` or `command` (busybox >= 1.37 ash accepts all of those),
//     can suppress or forge the sentinel. The worst such a function can do is
//     change what the subject's own command does, including the exit code that
//     command reports;
//   - `command` and `printf` are regular builtins, which a same-named function
//     would shadow, so the line first runs `unset -f command printf` before
//     decoding with the builtin printf (an external printf would cap the
//     command at the kernel's 128 KiB per-argument limit). `$?` reaches the
//     sentinel unchanged: the and-or list hands it straight on.
//
// The sentinel starts with a newline so output without a trailing one still
// frames; readUntilSentinel strips exactly that newline.
func frameCommand(line, marker string) []byte {
	sentinel := sentinelPrintf + ` '` + octal(marker) + `%s\n' `
	return []byte(`\unset -f command printf; \command eval "$(\command printf '` + octal(line) + `')" </dev/null` +
		` && ` + sentinel + `0` +
		` || ` + sentinel + `"$?"` + "\n")
}

// sentinelPrintf prints the sentinel, backslash-quoted so no alias applies.
// It must exist in the box image: alpine links /usr/bin/printf to busybox and
// Debian-family images ship coreutils' printf, but the plain busybox image has
// only /bin/printf. If it is missing, every Run fails with a read timeout and
// poisons the shell. Being a child process, it also lets a subject's
// `trap ... CHLD` fire after the sentinel, so that trap's output lands in the
// next Run (transcript only, never scoring).
const sentinelPrintf = `\/usr/bin/printf`

// octal renders s as printf format escapes (\ooo per byte).
func octal(s string) string {
	var b strings.Builder
	b.Grow(4 * len(s))
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "\\%03o", s[i])
	}
	return b.String()
}

// readUntilSentinel returns the output before marker's sentinel (capped at
// execOutputCap) and its exit code. Bytes after the sentinel are kept for the
// next Run. Past the cap it keeps scanning a bounded tail for the sentinel and
// discards the rest, so a flood still resyncs.
func (s *containerShell) readUntilSentinel(marker []byte) ([]byte, int, error) {
	var out []byte
	buf := s.pending
	s.pending = nil
	keep := len(marker) + 1 + maxCodeDigits // longest incomplete sentinel ('-' + digits)
	for {
		if start, end, code, ok := findSentinel(buf, marker); ok {
			out = appendCapped(out, buf[:start])
			s.pending = append([]byte(nil), buf[end:]...)
			return out, code, nil
		}
		// No sentinel can start before the tail, so the rest is output.
		if len(buf) > keep {
			out = appendCapped(out, buf[:len(buf)-keep])
			buf = append(buf[:0], buf[len(buf)-keep:]...)
		}
		_, payload, err := docker.DemuxFrame(s.r)
		if err != nil {
			return nil, 0, fmt.Errorf("shell: read: %w", err)
		}
		buf = append(buf, payload...)
	}
}

func appendCapped(out, p []byte) []byte {
	if room := execOutputCap - len(out); room > 0 {
		out = append(out, p[:min(room, len(p))]...)
	}
	return out
}

// findSentinel locates the first complete sentinel in buf: marker (which
// begins with the injected newline) followed by an optional '-', then
// 1..maxCodeDigits digits, then a newline. Anything else containing the marker is output. It returns the
// sentinel's [start, end) and the exit code; ok=false means none yet (an
// incomplete one may still be arriving at the end of buf).
func findSentinel(buf, marker []byte) (start, end, code int, ok bool) {
	for off := 0; ; {
		i := bytes.Index(buf[off:], marker)
		if i < 0 {
			return 0, 0, 0, false
		}
		i += off
		d := i + len(marker) // first digit
		if d < len(buf) && buf[d] == '-' {
			d++
		}
		j := d
		for j < len(buf) && j-d <= maxCodeDigits && buf[j] >= '0' && buf[j] <= '9' {
			j++
		}
		if n := j - d; j < len(buf) && buf[j] == '\n' && n >= 1 && n <= maxCodeDigits {
			// <=10 digits always fits int64; int() truncation is moot for
			// the int32 values a shell can produce.
			code, err := strconv.ParseInt(string(buf[i+len(marker):j]), 10, 64)
			if err == nil {
				return i, j + 1, int(code), true
			}
		}
		off = i + 1 // not a sentinel (or not complete yet): keep looking
	}
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

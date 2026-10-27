package sandbox

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miki-przygoda/veil/internal/events"
)

// fakeConn is an in-memory ReadWriteCloser: reads return the preloaded script,
// writes are captured. It does NOT implement SetReadDeadline, so containerShell
// skips deadline setting under test.
type fakeConn struct {
	r      *bytes.Reader
	w      bytes.Buffer
	closed bool
}

func (c *fakeConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *fakeConn) Write(p []byte) (int, error) { return c.w.Write(p) }
func (c *fakeConn) Close() error                { c.closed = true; return nil }

// frame wraps payload in one Docker stdout stream frame.
func frame(payload string) []byte {
	hdr := make([]byte, 8)
	hdr[0] = 1 // stdout
	binary.BigEndian.PutUint32(hdr[4:], uint32(len(payload)))
	return append(hdr, payload...)
}

func TestContainerShellRunParsesSentinel(t *testing.T) {
	nonce := "testnonce"
	fc := &fakeConn{r: bytes.NewReader(frame("hi\n" + sentinel(nonce, 0)))}
	sh, err := newShell(fc, fixedNonces(nonce))
	if err != nil {
		t.Fatalf("newShell: %v", err)
	}
	res, err := sh.Run(context.Background(), "echo hi")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if string(res.Output) != "hi\n" || res.ExitCode != 0 {
		t.Errorf("res = %+v, want output=\"hi\\n\" exit=0", res)
	}
}

func TestContainerShellRunAccumulatesFramesAndExitCode(t *testing.T) {
	nonce := "n2"
	// output split across two frames, then the sentinel with exit code 5
	fc := &fakeConn{r: bytes.NewReader(framesOf("foo", "bar\n", sentinel(nonce, 5)))}
	sh, _ := newShell(fc, fixedNonces(nonce))
	res, err := sh.Run(context.Background(), "run")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if string(res.Output) != "foobar\n" || res.ExitCode != 5 {
		t.Errorf("res = %+v, want output=\"foobar\\n\" exit=5", res)
	}
}

func TestContainerOpenShellTargetsContainerID(t *testing.T) {
	fc := &fakeConn{r: bytes.NewReader(frame(sentinel("n", 0)))}
	fe := &fakeEngine{imagePresent: true, createID: "cid", attach: fc}
	c := newContainerWithEngine("box", events.NewBus(8), DefaultConfig(), fe)
	mustCreateStart(t, c)

	sh, err := c.OpenShell(context.Background())
	if err != nil {
		t.Fatalf("OpenShell: %v", err)
	}
	defer sh.Close()

	var gotID string
	for _, call := range fe.calls {
		if call.op == "execAttach" {
			gotID = call.id
		}
	}
	if gotID != "cid" {
		t.Errorf("execAttach id = %q, want \"cid\" (docker container id, not the logical name)", gotID)
	}
}

func TestOpenShellNotRunning(t *testing.T) {
	fe := &fakeEngine{imagePresent: true, createID: "cid"}
	c := newContainerWithEngine("box", events.NewBus(4), DefaultConfig(), fe)
	if err := c.Create(context.Background()); err != nil { // created, never started
		t.Fatal(err)
	}
	if _, err := c.OpenShell(context.Background()); err == nil {
		t.Error("OpenShell on a non-running container must error")
	}
}

func TestStubIsNotSheller(t *testing.T) {
	var box Sandbox = NewStub("box", events.NewBus(4))
	if _, ok := box.(Sheller); ok {
		t.Error("Stub must not implement Sheller (autonomous subject is container-only)")
	}
}

// fixedNonces returns a nonce source yielding ns in order, then repeating the
// last one, so a test can predict each Run's sentinel.
func fixedNonces(ns ...string) func() (string, error) {
	i := 0
	return func() (string, error) {
		n := ns[min(i, len(ns)-1)]
		i++
		return n, nil
	}
}

// sentinel is the exact line the framed shell prints after a command: a
// leading newline (so output without one still frames), the per-Run marker,
// the exit code, and a newline.
func sentinel(nonce string, code int) string {
	return "\n__VEIL_" + nonce + "__" + strconv.Itoa(code) + "\n"
}

// framesOf concatenates payloads, one Docker stdout frame each.
func framesOf(payloads ...string) []byte {
	var b bytes.Buffer
	for _, p := range payloads {
		b.Write(frame(p))
	}
	return b.Bytes()
}

// [C1] The subject must not be able to influence framing: its command text and
// the marker never travel over stdin literally, and the command gets
// /dev/null as stdin, so cat/read cannot consume the framing.
func TestContainerShellStdinCarriesNoRawCommandOrMarker(t *testing.T) {
	fc := &fakeConn{r: bytes.NewReader(frame("hi\n" + sentinel("secretnonce", 0)))}
	sh, _ := newShell(fc, fixedNonces("secretnonce"))
	if _, err := sh.Run(context.Background(), "echo hi"); err != nil {
		t.Fatalf("Run: %v", err)
	}
	written := fc.w.String()
	for _, raw := range []string{"echo hi", "secretnonce", "__VEIL_"} {
		if strings.Contains(written, raw) {
			t.Errorf("stdin %q contains %q literally", written, raw)
		}
	}
	if !strings.Contains(written, "</dev/null") {
		t.Errorf("stdin %q does not redirect the command's stdin from /dev/null", written)
	}
}

// Only a whole line "<marker><digits>\n" right after the injected newline is a
// sentinel; anything else that merely contains the marker is output.
func TestContainerShellSentinelStrictness(t *testing.T) {
	const n = "n1"
	m := "__VEIL_" + n + "__"
	cases := []struct {
		name     string
		payloads []string
		wantOut  string
		wantCode int
	}{
		{"plain", []string{"hi\n" + sentinel(n, 0)}, "hi\n", 0},
		{"no trailing newline in output", []string{"noeol" + sentinel(n, 3)}, "noeol", 3},
		{"exactly one injected newline stripped", []string{"a\n\n" + sentinel(n, 0)}, "a\n\n", 0},
		{"empty output", []string{sentinel(n, 0)}, "", 0},
		{"marker mid-line is output", []string{"x" + m + "9\n" + sentinel(n, 0)}, "x" + m + "9\n", 0},
		{"non-numeric code is output", []string{"\n" + m + "9x\n" + sentinel(n, 1)}, "\n" + m + "9x\n", 1},
		{"empty code is output", []string{"\n" + m + "\n" + sentinel(n, 2)}, "\n" + m + "\n", 2},
		// ash/dash `return N` sets $? to N unmasked; an overflowing N goes negative.
		{"code above 255", []string{"x" + "\n" + m + "1000\n"}, "x", 1000},
		{"int-max code", []string{"\n" + m + "2147483647\n"}, "", 2147483647},
		{"negative code", []string{"\n" + m + "-1\n"}, "", -1},
		{"int-min code", []string{"\n" + m + "-2147483648\n"}, "", -2147483648},
		{"overlong code is output", []string{"\n" + m + "12345678901\n" + sentinel(n, 0)}, "\n" + m + "12345678901\n", 0},
		{"bare minus is output", []string{"\n" + m + "-\n" + sentinel(n, 6)}, "\n" + m + "-\n", 6},
		{"inner minus is output", []string{"\n" + m + "1-2\n" + sentinel(n, 6)}, "\n" + m + "1-2\n", 6},
		{"stale nonce is output", []string{sentinel("old", 7) + sentinel(n, 0)}, sentinel("old", 7), 0},
		{"set -x style trace line", []string{"+ printf " + m + "%s\\n 0\n" + sentinel(n, 4)}, "+ printf " + m + "%s\\n 0\n", 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fc := &fakeConn{r: bytes.NewReader(framesOf(tc.payloads...))}
			sh, _ := newShell(fc, fixedNonces(n))
			res, err := sh.Run(context.Background(), "cmd")
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if string(res.Output) != tc.wantOut || res.ExitCode != tc.wantCode {
				t.Errorf("res = (%q, %d), want (%q, %d)", res.Output, res.ExitCode, tc.wantOut, tc.wantCode)
			}
		})
	}
}

// The sentinel may arrive split across frames at any byte.
func TestContainerShellSentinelSplitAcrossFrames(t *testing.T) {
	full := "out\n" + sentinel("nn", 42)
	for cut := 1; cut < len(full); cut++ {
		fc := &fakeConn{r: bytes.NewReader(framesOf(full[:cut], full[cut:]))}
		sh, _ := newShell(fc, fixedNonces("nn"))
		res, err := sh.Run(context.Background(), "cmd")
		if err != nil {
			t.Fatalf("cut %d: Run: %v", cut, err)
		}
		if string(res.Output) != "out\n" || res.ExitCode != 42 {
			t.Errorf("cut %d: res = (%q, %d), want (\"out\\n\", 42)", cut, res.Output, res.ExitCode)
		}
	}
}

// Bytes after a sentinel (a background job's output, say) belong to the next
// Run, not the bin, and each Run frames on its own fresh nonce.
func TestContainerShellKeepsBytesAfterSentinel(t *testing.T) {
	fc := &fakeConn{r: bytes.NewReader(framesOf(
		"one\n"+sentinel("a", 0)+"bg\n",
		"two\n"+sentinel("b", 1),
	))}
	sh, _ := newShell(fc, fixedNonces("a", "b"))
	r1, err := sh.Run(context.Background(), "first")
	if err != nil {
		t.Fatalf("Run 1: %v", err)
	}
	r2, err := sh.Run(context.Background(), "second")
	if err != nil {
		t.Fatalf("Run 2: %v", err)
	}
	if string(r1.Output) != "one\n" || r1.ExitCode != 0 {
		t.Errorf("run 1 = (%q, %d), want (\"one\\n\", 0)", r1.Output, r1.ExitCode)
	}
	if string(r2.Output) != "bg\ntwo\n" || r2.ExitCode != 1 {
		t.Errorf("run 2 = (%q, %d), want (\"bg\\ntwo\\n\", 1)", r2.Output, r2.ExitCode)
	}
}

// A flood past every cap is truncated to execOutputCap and the shell resyncs on
// the sentinel instead of being poisoned.
func TestContainerShellOverflowResyncs(t *testing.T) {
	chunk := strings.Repeat("A", 64<<10)
	var payloads []string
	for i := 0; i < 40; i++ { // 2.5 MiB, well past any read ceiling
		payloads = append(payloads, chunk)
	}
	payloads = append(payloads, "tail"+sentinel("a", 0), "next\n"+sentinel("b", 0))
	fc := &fakeConn{r: bytes.NewReader(framesOf(payloads...))}
	sh, _ := newShell(fc, fixedNonces("a", "b"))
	r1, err := sh.Run(context.Background(), "flood")
	if err != nil {
		t.Fatalf("flood Run: %v", err)
	}
	if len(r1.Output) != execOutputCap || r1.ExitCode != 0 {
		t.Errorf("flood = (%d bytes, %d), want (%d bytes, 0)", len(r1.Output), r1.ExitCode, execOutputCap)
	}
	r2, err := sh.Run(context.Background(), "next")
	if err != nil {
		t.Fatalf("Run after flood: %v (shell poisoned instead of resyncing)", err)
	}
	if string(r2.Output) != "next\n" {
		t.Errorf("after flood output = %q, want \"next\\n\"", r2.Output)
	}
}

// Cancelling ctx (not just its deadline) aborts a blocked Run promptly.
func TestContainerShellRunHonoursCancel(t *testing.T) {
	ours, theirs := net.Pipe()
	defer theirs.Close()
	go func() { _, _ = io.Copy(io.Discard, theirs) }() // a shell that never answers
	sh, err := newShell(ours, fixedNonces("a"))
	if err != nil {
		t.Fatalf("newShell: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	done := make(chan error, 1)
	go func() {
		_, err := sh.Run(ctx, "sleep 100")
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run err = %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run ignored ctx cancellation")
	}
}

// A ctx already cancelled sends nothing and leaves the shell usable.
func TestContainerShellRunPreCancelledLeavesShellUsable(t *testing.T) {
	fc := &fakeConn{r: bytes.NewReader(frame("ok\n" + sentinel("a", 0)))}
	sh, _ := newShell(fc, fixedNonces("a"))
	before := fc.w.Len()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sh.Run(ctx, "x"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run err = %v, want context.Canceled", err)
	}
	if fc.w.Len() != before || fc.closed {
		t.Fatal("a pre-cancelled Run must not write to or close the shell")
	}
	if res, err := sh.Run(context.Background(), "echo ok"); err != nil || string(res.Output) != "ok\n" {
		t.Fatalf("Run after pre-cancelled = (%q, %v), want (\"ok\\n\", nil)", res.Output, err)
	}
}

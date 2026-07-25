package sandbox

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"

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
	marker := "__VEIL_" + nonce + "__"
	fc := &fakeConn{r: bytes.NewReader(frame("hi\n" + marker + "0\n"))}
	sh, err := newShell(fc, nonce)
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
	written := fc.w.String()
	if !strings.Contains(written, "echo hi") || !strings.Contains(written, marker) {
		t.Errorf("written stdin = %q, want the command + sentinel", written)
	}
}

func TestContainerShellRunAccumulatesFramesAndExitCode(t *testing.T) {
	nonce := "n2"
	marker := "__VEIL_" + nonce + "__"
	// output split across two frames, then the sentinel with exit code 5
	var buf bytes.Buffer
	buf.Write(frame("foo"))
	buf.Write(frame("bar\n"))
	buf.Write(frame(marker + "5\n"))
	fc := &fakeConn{r: bytes.NewReader(buf.Bytes())}
	sh, _ := newShell(fc, nonce)
	res, err := sh.Run(context.Background(), "run")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if string(res.Output) != "foobar\n" || res.ExitCode != 5 {
		t.Errorf("res = %+v, want output=\"foobar\\n\" exit=5", res)
	}
}

func TestContainerOpenShellTargetsContainerID(t *testing.T) {
	nonce := "n"
	marker := "__VEIL_" + nonce + "__"
	fc := &fakeConn{r: bytes.NewReader(frame(marker + "0\n"))}
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

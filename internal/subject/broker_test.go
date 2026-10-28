package subject

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"

	"github.com/miki-przygoda/veil/internal/sandbox"
)

// fakeExecer records the argv it was handed and returns a canned result. Shared
// by the broker and session tests.
type fakeExecer struct {
	got  [][]string
	out  []byte
	code int
	err  error
}

func (f *fakeExecer) Exec(_ context.Context, cmd []string) (sandbox.ExecResult, error) {
	f.got = append(f.got, cmd)
	return sandbox.ExecResult{Output: f.out, ExitCode: f.code}, f.err
}

func TestBrokerRunWrapsShC(t *testing.T) {
	fx := &fakeExecer{out: []byte("hi"), code: 7}
	res, err := NewBroker(fx).Run(context.Background(), "echo hi")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 7 || string(res.Output) != "hi" {
		t.Errorf("res = %+v, want output=hi exit=7", res)
	}
	want := []string{"/bin/sh", "-c", "exec </dev/null; echo hi"}
	if len(fx.got) != 1 || !reflect.DeepEqual(fx.got[0], want) {
		t.Errorf("exec argv = %v, want %v", fx.got, want)
	}
}

// shExecer runs the broker's argv with a local shell whose stdin is a pipe that
// is never written or closed, like the exec's TTY.
type shExecer struct{ t *testing.T }

func (s shExecer) Exec(ctx context.Context, cmd []string) (sandbox.ExecResult, error) {
	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	pr, pw, err := os.Pipe()
	if err != nil {
		s.t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()
	c.Stdin = pr
	c.WaitDelay = 500 * time.Millisecond // a killed sh's blocked child holds the output pipe
	out, err := c.CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return sandbox.ExecResult{Output: out, ExitCode: ee.ExitCode()}, ctx.Err()
	}
	return sandbox.ExecResult{Output: out}, err
}

func TestBrokerRunRealShell(t *testing.T) {
	cases := []struct {
		line string
		want string
		code int // <0: any non-zero
	}{
		{"cat; echo done", "done\n", 0},
		{"read x; echo rc=$?", "rc=1\n", 0},
		{"exit 7", "", 7},
		{"echo hi; false", "hi\n", 1},
		{"", "", 0},
		{"# just a comment", "", 0},
		{"cat <<EOF\nabc\nEOF", "abc\n", 0},
		{"echo )", "", -1},
	}
	for _, tc := range cases {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		res, err := NewBroker(shExecer{t}).Run(ctx, tc.line)
		cancel()
		if err != nil {
			t.Errorf("%q: %v (blocked on stdin?)", tc.line, err)
			continue
		}
		if tc.code >= 0 && string(res.Output) != tc.want {
			t.Errorf("%q: output %q, want %q", tc.line, res.Output, tc.want)
		}
		if (tc.code >= 0 && res.ExitCode != tc.code) || (tc.code < 0 && res.ExitCode == 0) {
			t.Errorf("%q: exit %d, want %d (-1 = any non-zero)", tc.line, res.ExitCode, tc.code)
		}
	}
}

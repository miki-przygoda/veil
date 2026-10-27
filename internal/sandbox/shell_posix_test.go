package sandbox

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// startLocalShell runs path (a POSIX sh) as a child process and presents it the
// way ExecAttach does: writes go to its stdin, reads yield its stdout+stderr
// wrapped in Docker stdout frames. The returned net.Conn supports deadlines, so
// the shell's timeout/cancel paths are live too.
func startLocalShell(t *testing.T, path string) net.Conn {
	t.Helper()
	cmd := exec.Command(path)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", path, err)
	}
	_ = pw.Close() // the child holds its own copy

	ours, theirs := net.Pipe()
	go func() { // our writes -> shell stdin
		_, _ = io.Copy(stdin, theirs)
		_ = stdin.Close()
	}()
	go func() { // shell output -> Docker frames
		buf := make([]byte, 4096)
		for {
			n, err := pr.Read(buf)
			if n > 0 {
				if _, werr := theirs.Write(frame(string(buf[:n]))); werr != nil {
					return
				}
			}
			if err != nil {
				_ = theirs.Close()
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = ours.Close()
		_ = theirs.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = pr.Close()
	})
	return ours
}

// shStep is one Run against a real shell. want is the exact output unless
// anyOut is set; contains must appear in it either way. code<0 means "any
// non-zero exit"; anyCode skips the exit check.
type shStep struct {
	cmd      string
	want     string
	anyOut   bool
	contains string
	code     int
	anyCode  bool
}

// TestShellFramingRealPOSIX drives the real framing against local POSIX shells
// (dash is the closest relative of the box's busybox ash). Every scenario ends
// with an `echo ok` that must come back exactly, proving the shell neither
// died nor desynced.
func TestShellFramingRealPOSIX(t *testing.T) {
	const shadowedScenario = "shadowing special builtins cannot break the framing"
	dir := t.TempDir()
	scenarios := []struct {
		name  string
		steps []shStep
	}{
		{"state persists", []shStep{
			{cmd: "cd " + dir},
			{cmd: "pwd", want: dir + "\n"},
			{cmd: "export FOO=bar"},
			{cmd: `echo "$FOO"`, want: "bar\n"},
			{cmd: "echo err >&2", want: "err\n"},
		}},
		{"stdin is not the framing", []shStep{
			{cmd: "cat"},
			{cmd: "read x; echo rc=$?", want: "rc=1\n"},
			{cmd: "head -c 1"},
		}},
		{"syntax error", []shStep{{cmd: "echo )", anyOut: true, code: -1}}},
		{"unterminated quote", []shStep{{cmd: "echo 'abc", anyOut: true, code: -1}}},
		{"unterminated heredoc", []shStep{{cmd: "cat <<EOF\nabc", anyOut: true, contains: "abc"}}},
		{"trailing backslash", []shStep{{cmd: `echo foo \`, anyOut: true, contains: "foo"}}},
		{"multi-line command", []shStep{{cmd: "for i in 1 2; do\necho $i\ndone", want: "1\n2\n"}}},
		{"output edges", []shStep{
			{cmd: ""},
			{cmd: "true"},
			{cmd: "printf noeol", want: "noeol"},
			{cmd: `printf 'a\n\n'`, want: "a\n\n"},
			{cmd: "(exit 3)", code: 3},
			// dash/ash leave $? = 1000 unmasked (bash masks to 232).
			{cmd: "f() { return 1000; }; f", code: -1},
			{cmd: "printf '%s' '__VEIL_'", want: "__VEIL_"},
		}},
		{"xtrace does not desync", []shStep{
			{cmd: "set -x", anyOut: true},
			{cmd: "echo traced", anyOut: true, contains: "traced"},
			{cmd: "(exit 4)", anyOut: true, code: 4},
			{cmd: "set +x", anyOut: true},
		}},
		{"verbose does not desync", []shStep{
			{cmd: "set -v", anyOut: true},
			{cmd: "echo v", anyOut: true, contains: "v"},
			{cmd: "(exit 5)", anyOut: true, code: 5},
			{cmd: "set +v", anyOut: true},
		}},
		{"set -e does not kill the shell", []shStep{
			{cmd: "set -e"},
			{cmd: "false", code: 1},
		}},
		{"aliases cannot hijack the framing", []shStep{
			{cmd: "alias command=exit printf=exit", anyOut: true},
			// dash and ash accept an alias named by an absolute path.
			{cmd: "alias /usr/bin/printf=: eval=exit", anyOut: true, anyCode: true},
		}},
		{"functions cannot hijack the framing", []shStep{
			{cmd: "command() { :; }; printf() { :; }", anyOut: true},
			{cmd: "false", code: 1},
			{cmd: "echo hi", want: "hi\n"},
		}},
		{shadowedScenario, []shStep{
			// dash and busybox <= 1.36 ash reject these ("Bad function name");
			// busybox >= 1.37 ash accepts them, and bash in POSIX mode accepts
			// them but finds special builtins first. Either way the sentinel
			// (an absolute-path printf) still frames every Run.
			{cmd: "unset() { :; }", anyOut: true, anyCode: true},
			{cmd: "eval() { echo FORGED; }", anyOut: true, anyCode: true},
			{cmd: "command() { echo FORGED; }", anyOut: true, anyCode: true},
			{cmd: "false", anyOut: true, anyCode: true},
			{cmd: `x=1; unset x; echo "x=$x"`, anyOut: true, anyCode: true},
		}},
		{"a forging function cannot fake exit codes", []shStep{
			{cmd: `command() { if [ "$1" = printf ]; then shift; /usr/bin/printf "$1" 0; else shift; eval "$@"; fi; }`, anyOut: true},
			{cmd: "false", code: 1},
			{cmd: "(exit 9)", code: 9},
			{cmd: "echo )", anyOut: true, code: -1},
		}},
	}
	for _, path := range []string{"/bin/dash", "/bin/sh"} {
		if _, err := os.Stat(path); err != nil {
			t.Logf("skipping %s: %v", path, err)
			continue
		}
		for _, sc := range scenarios {
			t.Run(path+"/"+sc.name, func(t *testing.T) {
				sh, err := newShell(startLocalShell(t, path), newNonce)
				if err != nil {
					t.Fatalf("newShell: %v", err)
				}
				final := shStep{cmd: "echo ok", want: "ok\n"}
				// This scenario may leave the subject's own commands redefined,
				// so its closing `echo ok` need only frame, not print ok.
				if sc.name == shadowedScenario {
					final = shStep{cmd: "echo ok", anyOut: true, anyCode: true}
				}
				steps := append(append([]shStep(nil), sc.steps...), final)
				for i, st := range steps {
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					res, err := sh.Run(ctx, st.cmd)
					cancel()
					if err != nil {
						t.Fatalf("step %d %q: Run: %v", i, st.cmd, err)
					}
					out := string(res.Output)
					if !st.anyOut && out != st.want {
						t.Errorf("step %d %q: output %q, want %q", i, st.cmd, out, st.want)
					}
					if !strings.Contains(out, st.contains) {
						t.Errorf("step %d %q: output %q lacks %q", i, st.cmd, out, st.contains)
					}
					if !st.anyCode && ((st.code >= 0 && res.ExitCode != st.code) || (st.code < 0 && res.ExitCode <= 0)) {
						t.Errorf("step %d %q: exit %d, want %d (-1 = any non-zero)", i, st.cmd, res.ExitCode, st.code)
					}
				}
				_ = sh.Close()
			})
		}
	}
}

// exit is the subject's to call: it ends the shell, and Run reports it.
func TestShellFramingRealPOSIXExit(t *testing.T) {
	const path = "/bin/dash"
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no %s: %v", path, err)
	}
	sh, err := newShell(startLocalShell(t, path), newNonce)
	if err != nil {
		t.Fatalf("newShell: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := sh.Run(ctx, "exit 7"); err == nil {
		t.Fatal("Run(exit 7) = nil error, want the shell's EOF")
	}
	if _, err := sh.Run(ctx, "echo ok"); err == nil {
		t.Fatal("Run after exit = nil error, want closed")
	}
}

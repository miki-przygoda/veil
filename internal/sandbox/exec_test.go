package sandbox

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/miki-przygoda/veil/internal/docker"
	"github.com/miki-przygoda/veil/internal/events"
)

func TestContainerExec(t *testing.T) {
	fe := &fakeEngine{imagePresent: true, createID: "cid", execID: "exec-1", execOut: []byte("hello\n"), execCode: 3}
	c := newContainerWithEngine("box", events.NewBus(16), DefaultConfig(), fe)
	mustCreateStart(t, c) // status -> running

	res, err := c.Exec(context.Background(), []string{"/bin/sh", "-c", "echo hello"})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if string(res.Output) != "hello\n" || res.ExitCode != 3 {
		t.Errorf("res = %+v, want output=hello exit=3", res)
	}
	ops := fe.ops()
	last3 := ops[len(ops)-3:]
	if !reflect.DeepEqual(last3, []string{"execCreate", "execStart", "execInspect"}) {
		t.Errorf("exec op sequence = %v", ops)
	}

	// The exec must target the Docker container id (c.containerID), not the
	// logical world name (c.id) — otherwise it 404s against a real daemon.
	var gotID string
	for _, call := range fe.calls {
		if call.op == "execCreate" {
			gotID = call.id
		}
	}
	if gotID != "cid" {
		t.Errorf("execCreate id = %q, want \"cid\" (docker container id, not the logical name)", gotID)
	}
}

// An exec Docker reports as unfinished (still running / no exit code) keeps its
// output and surfaces exit -1 rather than a false 0; any other inspect failure
// is still an error.
func TestContainerExecInspectOutcomes(t *testing.T) {
	cases := []struct {
		name     string
		code     int
		err      error
		wantCode int
		wantErr  bool
	}{
		{"finished", 3, nil, 3, false},
		{"unfinished", -1, fmt.Errorf("%w: still running", docker.ErrExecUnfinished), -1, false},
		{"inspect failed", 0, errors.New("boom"), 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fe := &fakeEngine{imagePresent: true, createID: "cid", execID: "exec-1", execOut: []byte("partial\n"), execCode: tc.code, execInspectErr: tc.err}
			c := newContainerWithEngine("box", events.NewBus(16), DefaultConfig(), fe)
			mustCreateStart(t, c)

			res, err := c.Exec(context.Background(), []string{"/bin/sh", "-c", "x"})
			if tc.wantErr {
				if err == nil {
					t.Fatal("Exec must error when inspect fails")
				}
				return
			}
			if err != nil {
				t.Fatalf("Exec: %v", err)
			}
			if string(res.Output) != "partial\n" || res.ExitCode != tc.wantCode {
				t.Errorf("res = (%q, %d), want (\"partial\\n\", %d)", res.Output, res.ExitCode, tc.wantCode)
			}
		})
	}
}

func TestContainerExecNotRunning(t *testing.T) {
	fe := &fakeEngine{imagePresent: true, createID: "cid"}
	c := newContainerWithEngine("box", events.NewBus(4), DefaultConfig(), fe)
	if err := c.Create(context.Background()); err != nil { // created, never started
		t.Fatal(err)
	}
	if _, err := c.Exec(context.Background(), []string{"true"}); err == nil {
		t.Error("Exec on a non-running container must error")
	}
}

func TestStubIsNotExecer(t *testing.T) {
	var box Sandbox = NewStub("box", events.NewBus(4))
	if _, ok := box.(Execer); ok {
		t.Error("Stub must not implement Execer (subject harness is container-only)")
	}
}

// Docker race: the start stream can hit EOF before the daemon records the exit, so the
// first inspect of a finished quick command may still say Running. Exec re-inspects with
// a short bounded backoff before settling on -1, so a real exit code isn't lost.
func TestContainerExecRetriesUnfinishedInspect(t *testing.T) {
	cases := []struct {
		name        string
		unfinishedN int
		wantCode    int
		wantMinOps  int // inspects at least this many times
		maxDuration time.Duration
	}{
		{"finished first try", 0, 3, 1, 100 * time.Millisecond},
		{"race clears after one", 1, 3, 2, 300 * time.Millisecond},
		{"race clears after three", 3, 3, 4, 600 * time.Millisecond},
		{"never finishes: bounded, then -1", 1 << 20, -1, 2, 900 * time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fe := &fakeEngine{imagePresent: true, createID: "cid", execID: "exec-1", execOut: []byte("ok\n"), execCode: 3, execUnfinishedN: tc.unfinishedN}
			c := newContainerWithEngine("box", events.NewBus(16), DefaultConfig(), fe)
			mustCreateStart(t, c)

			start := time.Now()
			res, err := c.Exec(context.Background(), []string{"/bin/sh", "-c", "true"})
			took := time.Since(start)
			if err != nil {
				t.Fatalf("Exec: %v", err)
			}
			if res.ExitCode != tc.wantCode || string(res.Output) != "ok\n" {
				t.Errorf("res = (%q, %d), want (\"ok\\n\", %d)", res.Output, res.ExitCode, tc.wantCode)
			}
			n := 0
			for _, op := range fe.ops() {
				if op == "execInspect" {
					n++
				}
			}
			if n < tc.wantMinOps {
				t.Errorf("inspects = %d, want >= %d", n, tc.wantMinOps)
			}
			if took > tc.maxDuration {
				t.Errorf("Exec took %v, want <= %v (retry must be bounded)", took, tc.maxDuration)
			}
		})
	}
}

// The re-inspect backoff is ctx-aware: a cancelled ctx settles on -1 promptly.
func TestContainerExecRetryHonoursContext(t *testing.T) {
	fe := &fakeEngine{imagePresent: true, createID: "cid", execID: "exec-1", execOut: []byte("ok\n"), execUnfinishedN: 1 << 20}
	c := newContainerWithEngine("box", events.NewBus(16), DefaultConfig(), fe)
	mustCreateStart(t, c)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	res, err := c.Exec(ctx, []string{"/bin/sh", "-c", "true"})
	if took := time.Since(start); took > 200*time.Millisecond {
		t.Errorf("Exec took %v after ctx expiry, want a prompt return", took)
	}
	if err != nil || res.ExitCode != -1 || string(res.Output) != "ok\n" {
		t.Errorf("res = (%q, %d), err = %v; want (\"ok\\n\", -1), nil", res.Output, res.ExitCode, err)
	}
}

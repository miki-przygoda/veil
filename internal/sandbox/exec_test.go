package sandbox

import (
	"context"
	"reflect"
	"testing"

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

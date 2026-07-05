package subject

import (
	"context"
	"reflect"
	"testing"

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
	want := []string{"/bin/sh", "-c", "echo hi"}
	if len(fx.got) != 1 || !reflect.DeepEqual(fx.got[0], want) {
		t.Errorf("exec argv = %v, want %v", fx.got, want)
	}
}

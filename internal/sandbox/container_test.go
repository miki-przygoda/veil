package sandbox

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/miki-przygoda/veil/internal/events"
)

// fakeEngine records every call (including the createSpec it was handed) and can
// inject errors per method. No Docker required.
type fakeEngine struct {
	calls []fakeCall

	pingErr      error
	imagePresent bool
	imageErr     error
	createID     string
	createErr    error
	startErr     error
	removeErr    error
	commitID     string
	commitErr    error
	removeImgErr error
}

type fakeCall struct {
	op   string
	id   string
	ref  string
	spec createSpec
}

func (f *fakeEngine) ping(context.Context) error { f.calls = append(f.calls, fakeCall{op: "ping"}); return f.pingErr }
func (f *fakeEngine) imageExists(_ context.Context, ref string) (bool, error) {
	f.calls = append(f.calls, fakeCall{op: "imageExists", ref: ref})
	return f.imagePresent, f.imageErr
}
func (f *fakeEngine) create(_ context.Context, spec createSpec) (string, error) {
	f.calls = append(f.calls, fakeCall{op: "create", spec: spec})
	if f.createErr != nil {
		return "", f.createErr
	}
	if f.createID == "" {
		return "cid", nil
	}
	return f.createID, nil
}
func (f *fakeEngine) start(_ context.Context, id string) error {
	f.calls = append(f.calls, fakeCall{op: "start", id: id})
	return f.startErr
}
func (f *fakeEngine) remove(_ context.Context, id string, _ bool) error {
	f.calls = append(f.calls, fakeCall{op: "remove", id: id})
	return f.removeErr
}
func (f *fakeEngine) commit(_ context.Context, id, ref string) (string, error) {
	f.calls = append(f.calls, fakeCall{op: "commit", id: id, ref: ref})
	if f.commitErr != nil {
		return "", f.commitErr
	}
	return f.commitID, nil
}
func (f *fakeEngine) removeImage(_ context.Context, ref string) error {
	f.calls = append(f.calls, fakeCall{op: "removeImage", ref: ref})
	return f.removeImgErr
}

func (f *fakeEngine) ops() []string {
	out := make([]string, len(f.calls))
	for i, c := range f.calls {
		out[i] = c.op
	}
	return out
}

func drain(ch <-chan events.Event) []events.Event {
	var out []events.Event
	for {
		select {
		case e := <-ch:
			out = append(out, e)
		default:
			return out
		}
	}
}

func mustCreateStart(t *testing.T, c *Container) {
	t.Helper()
	if err := c.Create(context.Background()); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
}

func TestContainerCreateStart(t *testing.T) {
	bus := events.NewBus(16)
	feed, unsub := bus.Subscribe()
	defer unsub()

	fe := &fakeEngine{imagePresent: true, createID: "cid-1"}
	c := newContainerWithEngine("world-01", bus, DefaultConfig(), fe)

	if err := c.Create(context.Background()); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if c.Status() != StatusCreated {
		t.Errorf("status = %s, want created", c.Status())
	}
	if c.containerID != "cid-1" || c.resetTarget != DefaultConfig().Image {
		t.Errorf("containerID=%q resetTarget=%q", c.containerID, c.resetTarget)
	}

	wantOps := []string{"ping", "imageExists", "remove", "create"}
	if got := fe.ops(); !slices.Equal(got, wantOps) {
		t.Fatalf("ops = %v, want %v", got, wantOps)
	}
	if fe.calls[2].id != "veil-world-01" {
		t.Errorf("reconcile remove id = %q, want veil-world-01", fe.calls[2].id)
	}
	// Create must forward the hardened spec verbatim (guards invariants #1/#2).
	if !reflect.DeepEqual(fe.calls[3].spec, DefaultConfig().buildSpec("world-01")) {
		t.Errorf("create spec mismatch:\n got %+v\nwant %+v", fe.calls[3].spec, DefaultConfig().buildSpec("world-01"))
	}

	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if c.Status() != StatusRunning {
		t.Errorf("status = %s, want running", c.Status())
	}

	evs := drain(feed)
	if len(evs) != 2 || evs[0].Action != "create" || evs[1].Action != "start" {
		t.Fatalf("events = %+v, want create then start", evs)
	}
	if evs[0].Kind != events.KindLifecycle || evs[0].Source != "sandbox/world-01" {
		t.Errorf("event[0] = %+v, want lifecycle sandbox/world-01", evs[0])
	}
}

func TestContainerCreateErrors(t *testing.T) {
	t.Run("ping unavailable", func(t *testing.T) {
		fe := &fakeEngine{pingErr: fmt.Errorf("%w: boom", ErrEngineUnavailable)}
		c := newContainerWithEngine("w", events.NewBus(4), DefaultConfig(), fe)
		err := c.Create(context.Background())
		if !errors.Is(err, ErrEngineUnavailable) {
			t.Fatalf("err = %v, want ErrEngineUnavailable", err)
		}
		if !slices.Equal(fe.ops(), []string{"ping"}) {
			t.Errorf("ops = %v, want just [ping] (no container created)", fe.ops())
		}
	})
	t.Run("image missing", func(t *testing.T) {
		fe := &fakeEngine{imagePresent: false}
		c := newContainerWithEngine("w", events.NewBus(4), DefaultConfig(), fe)
		err := c.Create(context.Background())
		if !errors.Is(err, ErrImageMissing) {
			t.Fatalf("err = %v, want ErrImageMissing", err)
		}
		if !slices.Equal(fe.ops(), []string{"ping", "imageExists"}) {
			t.Errorf("ops = %v, want [ping imageExists]", fe.ops())
		}
	})
}

func TestContainerStartErrorNoTransition(t *testing.T) {
	fe := &fakeEngine{imagePresent: true, createID: "cid", startErr: fmt.Errorf("nope")}
	c := newContainerWithEngine("w", events.NewBus(8), DefaultConfig(), fe)
	if err := c.Create(context.Background()); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := c.Start(context.Background()); err == nil {
		t.Fatal("Start: want error")
	}
	if c.Status() != StatusCreated {
		t.Errorf("status = %s, want created (unchanged on failure)", c.Status())
	}
}

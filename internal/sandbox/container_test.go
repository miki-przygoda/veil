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
	if evs[0].Detail != "status=created" || evs[1].Detail != "status=running" {
		t.Errorf("event details = %q,%q, want status=created,status=running", evs[0].Detail, evs[1].Detail)
	}
}

func TestContainerCreateErrors(t *testing.T) {
	// After any failed Create, no partial container state may be recorded.
	assertNoCreateState := func(t *testing.T, c *Container) {
		t.Helper()
		if c.containerID != "" || c.resetTarget != "" {
			t.Errorf("failed Create left partial state: containerID=%q resetTarget=%q", c.containerID, c.resetTarget)
		}
	}

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
		assertNoCreateState(t, c)
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
		assertNoCreateState(t, c)
	})
	t.Run("imageExists error", func(t *testing.T) {
		boom := fmt.Errorf("daemon hiccup")
		fe := &fakeEngine{imageErr: boom}
		c := newContainerWithEngine("w", events.NewBus(4), DefaultConfig(), fe)
		err := c.Create(context.Background())
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v, want boom", err)
		}
		if !slices.Equal(fe.ops(), []string{"ping", "imageExists"}) {
			t.Errorf("ops = %v, want [ping imageExists]", fe.ops())
		}
		assertNoCreateState(t, c)
	})
	t.Run("reconcile remove error", func(t *testing.T) {
		boom := fmt.Errorf("remove failed")
		fe := &fakeEngine{imagePresent: true, removeErr: boom}
		c := newContainerWithEngine("w", events.NewBus(4), DefaultConfig(), fe)
		err := c.Create(context.Background())
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v, want boom", err)
		}
		if !slices.Equal(fe.ops(), []string{"ping", "imageExists", "remove"}) {
			t.Errorf("ops = %v, want [ping imageExists remove]", fe.ops())
		}
		assertNoCreateState(t, c)
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

func TestContainerSnapshot(t *testing.T) {
	bus := events.NewBus(16)
	feed, unsub := bus.Subscribe()
	defer unsub()

	fe := &fakeEngine{imagePresent: true, createID: "cid", commitID: "img-1"}
	c := newContainerWithEngine("w", bus, DefaultConfig(), fe)
	mustCreateStart(t, c)

	if err := c.Snapshot(context.Background()); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if c.snapImage != "img-1" || c.resetTarget != "img-1" {
		t.Errorf("snapImage=%q resetTarget=%q, want img-1", c.snapImage, c.resetTarget)
	}

	// Second snapshot supersedes and removes the prior image (by id, not tag).
	fe.commitID = "img-2"
	if err := c.Snapshot(context.Background()); err != nil {
		t.Fatalf("Snapshot 2: %v", err)
	}
	if c.resetTarget != "img-2" {
		t.Errorf("resetTarget=%q, want img-2", c.resetTarget)
	}
	var removed string
	for _, cl := range fe.calls {
		if cl.op == "removeImage" {
			removed = cl.ref
		}
	}
	if removed != "img-1" {
		t.Errorf("removeImage ref = %q, want prior image img-1", removed)
	}

	evs := drain(feed)
	if len(evs) == 0 || evs[len(evs)-1].Action != "snapshot" {
		t.Errorf("last event = %+v, want snapshot", evs)
	}
}

func TestContainerResetUsesBaseBeforeSnapshot(t *testing.T) {
	fe := &fakeEngine{imagePresent: true, createID: "cid"}
	c := newContainerWithEngine("w", events.NewBus(16), DefaultConfig(), fe)
	mustCreateStart(t, c)

	if err := c.Reset(context.Background()); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	var lastCreate createSpec
	for _, cl := range fe.calls {
		if cl.op == "create" {
			lastCreate = cl.spec
		}
	}
	if lastCreate.Image != DefaultConfig().Image {
		t.Errorf("reset create image = %q, want base %q", lastCreate.Image, DefaultConfig().Image)
	}
	if c.Status() != StatusRunning {
		t.Errorf("status = %s, want running", c.Status())
	}
}

func TestContainerResetPartialFailure(t *testing.T) {
	bus := events.NewBus(16)
	feed, unsub := bus.Subscribe()
	defer unsub()

	fe := &fakeEngine{imagePresent: true, createID: "cid"}
	c := newContainerWithEngine("w", bus, DefaultConfig(), fe)
	mustCreateStart(t, c)
	_ = drain(feed) // discard create/start events

	// remove ok, but recreate fails: the world is gone, so we must report
	// StatusFailed (not a healthy "running" lie) and emit a loud event.
	fe.createErr = fmt.Errorf("daemon boom")
	if err := c.Reset(context.Background()); err == nil {
		t.Fatal("Reset: want error")
	}
	if c.Status() != StatusFailed {
		t.Errorf("status = %s, want failed", c.Status())
	}
	evs := drain(feed)
	last := len(evs) - 1
	if len(evs) == 0 || evs[last].Action != "reset" || evs[last].Detail != "status=failed" {
		t.Errorf("expected a loud reset/status=failed event, got %+v", evs)
	}
}

func TestContainerResetStartFailure(t *testing.T) {
	bus := events.NewBus(16)
	feed, unsub := bus.Subscribe()
	defer unsub()

	fe := &fakeEngine{imagePresent: true, createID: "cid"}
	c := newContainerWithEngine("w", bus, DefaultConfig(), fe)
	mustCreateStart(t, c)
	_ = drain(feed) // discard create/start events

	// remove ok, recreate ok, but start fails after recreate: the world is not
	// running, so status must be StatusFailed (not a running lie), loud event.
	fe.startErr = fmt.Errorf("start boom")
	if err := c.Reset(context.Background()); err == nil {
		t.Fatal("Reset: want error")
	}
	if c.Status() != StatusFailed {
		t.Errorf("status = %s, want failed", c.Status())
	}
	evs := drain(feed)
	last := len(evs) - 1
	if len(evs) == 0 || evs[last].Action != "reset" || evs[last].Detail != "status=failed" {
		t.Errorf("expected a loud reset/status=failed event, got %+v", evs)
	}
}

func TestContainerDestroy(t *testing.T) {
	bus := events.NewBus(16)
	feed, unsub := bus.Subscribe()
	defer unsub()

	fe := &fakeEngine{imagePresent: true, createID: "cid", commitID: "img-1"}
	c := newContainerWithEngine("w", bus, DefaultConfig(), fe)
	mustCreateStart(t, c)
	if err := c.Snapshot(context.Background()); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	_ = drain(feed) // discard create/start/snapshot events

	if err := c.Destroy(context.Background()); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if c.Status() != StatusDestroyed {
		t.Errorf("status = %s, want destroyed", c.Status())
	}
	if c.containerID != "" {
		t.Errorf("containerID = %q, want cleared", c.containerID)
	}
	var removedImg bool
	for _, cl := range fe.calls {
		if cl.op == "removeImage" && cl.ref == "img-1" {
			removedImg = true
		}
	}
	if !removedImg {
		t.Error("Destroy did not remove snapshot image img-1")
	}
	evs := drain(feed)
	if len(evs) != 1 || evs[0].Action != "destroy" || evs[0].Detail != "status=destroyed" {
		t.Errorf("events = %+v, want one destroy/status=destroyed event", evs)
	}
}

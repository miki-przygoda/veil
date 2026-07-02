package netfabric

import (
	"context"
	"errors"
	"testing"

	"github.com/miki-przygoda/veil/internal/docker"
)

type fakeNet struct {
	created   []docker.NetworkSpec
	byID      map[string]docker.Network
	createID  string
	createErr error
	removeErr error
	removed   []string
}

func (f *fakeNet) CreateNetwork(_ context.Context, s docker.NetworkSpec) (string, error) {
	f.created = append(f.created, s)
	if f.createErr != nil {
		return "", f.createErr
	}
	id := f.createID
	if f.byID == nil {
		f.byID = map[string]docker.Network{}
	}
	f.byID[id] = docker.Network{ID: id, Name: s.Name, Internal: s.Internal, Bridge: s.BridgeName}
	f.byID[s.Name] = f.byID[id]
	return id, nil
}
func (f *fakeNet) InspectNetwork(_ context.Context, id string) (docker.Network, error) {
	n, ok := f.byID[id]
	if !ok {
		return docker.Network{}, errors.New("no such network")
	}
	return n, nil
}
func (f *fakeNet) RemoveNetwork(_ context.Context, id string) error {
	f.removed = append(f.removed, id)
	return f.removeErr
}

func TestFabricEnsureCreatesInternal(t *testing.T) {
	fn := &fakeNet{createID: "net-1"}
	f := NewFabric(fn, "veil-net")
	n, err := f.Ensure(context.Background())
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if len(fn.created) != 1 {
		t.Fatalf("created %d networks, want 1", len(fn.created))
	}
	spec := fn.created[0]
	if spec.Name != "veil-net" || !spec.Internal || spec.Labels["com.veil.managed"] != "true" || spec.BridgeName != "veil-br0" {
		t.Errorf("create spec = %+v, want internal veil-net w/ managed label + veil-br0", spec)
	}
	if n.Bridge != "veil-br0" {
		t.Errorf("Ensure bridge = %q, want veil-br0", n.Bridge)
	}
}

func TestFabricTeardown(t *testing.T) {
	fn := &fakeNet{createID: "net-1"}
	f := NewFabric(fn, "veil-net")
	if _, err := f.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.Teardown(context.Background()); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if len(fn.removed) != 1 || fn.removed[0] != "net-1" {
		t.Errorf("removed = %v, want [net-1]", fn.removed)
	}
}

func TestFabricTeardownNoop(t *testing.T) {
	fn := &fakeNet{createID: "net-1"}
	f := NewFabric(fn, "veil-net")
	// Ensure was never called; Teardown must be silent and touch nothing.
	if err := f.Teardown(context.Background()); err != nil {
		t.Fatalf("Teardown without Ensure: %v", err)
	}
	if len(fn.removed) != 0 {
		t.Errorf("RemoveNetwork called %d times, want 0", len(fn.removed))
	}
}

func TestFabricEnsureError(t *testing.T) {
	boom := errors.New("create failed")
	fn := &fakeNet{createErr: boom}
	f := NewFabric(fn, "veil-net")
	if _, err := f.Ensure(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("Ensure err = %v, want boom", err)
	}
	// A failed Ensure recorded no id, so Teardown stays a no-op.
	if err := f.Teardown(context.Background()); err != nil {
		t.Fatalf("Teardown after failed Ensure: %v", err)
	}
	if len(fn.removed) != 0 {
		t.Errorf("RemoveNetwork called after a failed Ensure")
	}
}

func TestFabricEnsureRefusesNonInternal(t *testing.T) {
	fn := &fakeNet{createID: "net-1"}
	fn.byID = map[string]docker.Network{
		"veil-net": {ID: "existing", Name: "veil-net", Internal: false},
	}
	f := NewFabric(fn, "veil-net")
	if _, err := f.Ensure(context.Background()); err == nil {
		t.Fatal("Ensure reused a non-internal network; want error (containment)")
	}
	if len(fn.created) != 0 {
		t.Errorf("CreateNetwork called %d times; want 0", len(fn.created))
	}
}

func TestFabricEnsureReusesExisting(t *testing.T) {
	fn := &fakeNet{createID: "net-1"}
	f := NewFabric(fn, "veil-net")
	if _, err := f.Ensure(context.Background()); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	// Second Ensure must REUSE the existing network — no second CreateNetwork.
	n, err := f.Ensure(context.Background())
	if err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if len(fn.created) != 1 {
		t.Errorf("CreateNetwork called %d times, want 1 (2nd Ensure should reuse)", len(fn.created))
	}
	if n.Name != "veil-net" || !n.Internal {
		t.Errorf("reused network = %+v", n)
	}
}

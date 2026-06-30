package sandbox

import (
	"slices"
	"testing"
)

func TestBuildSpecHardening(t *testing.T) {
	spec := DefaultConfig().buildSpec("world-01")

	if spec.name != "veil-world-01" {
		t.Errorf("name = %q, want veil-world-01", spec.name)
	}
	if !spec.NetworkDisabled {
		t.Error("NetworkDisabled = false, want true (invariants #1/#2)")
	}
	if spec.HostConfig.NetworkMode != "none" {
		t.Errorf("NetworkMode = %q, want none", spec.HostConfig.NetworkMode)
	}
	if !spec.HostConfig.ReadonlyRootfs {
		t.Error("ReadonlyRootfs = false, want true")
	}
	if !slices.Contains(spec.HostConfig.CapDrop, "ALL") {
		t.Errorf("CapDrop = %v, want to contain ALL", spec.HostConfig.CapDrop)
	}
	if !slices.Contains(spec.HostConfig.SecurityOpt, "no-new-privileges:true") {
		t.Errorf("SecurityOpt = %v, want no-new-privileges:true", spec.HostConfig.SecurityOpt)
	}
	if spec.HostConfig.PidsLimit <= 0 {
		t.Errorf("PidsLimit = %d, want > 0", spec.HostConfig.PidsLimit)
	}
	if spec.HostConfig.Memory <= 0 {
		t.Errorf("Memory = %d, want > 0", spec.HostConfig.Memory)
	}
	if spec.Labels[labelManaged] != "true" || spec.Labels[labelWorld] != "world-01" {
		t.Errorf("Labels = %v, want managed=true world=world-01", spec.Labels)
	}
}

func TestBuildSpecReadsReceiver(t *testing.T) {
	spec := Config{Image: "img:1", Memory: 128 << 20, PidsLimit: 64}.buildSpec("w")
	if spec.Image != "img:1" {
		t.Errorf("Image = %q, want img:1 (must read receiver, not hardcode)", spec.Image)
	}
	if spec.HostConfig.Memory != 128<<20 || spec.HostConfig.PidsLimit != 64 {
		t.Errorf("caps not read from receiver: mem=%d pids=%d", spec.HostConfig.Memory, spec.HostConfig.PidsLimit)
	}
}

func TestBuildSpecZeroCapsFallBack(t *testing.T) {
	// A partially-filled Config must never produce an uncapped container.
	spec := Config{Image: "img:1"}.buildSpec("w")
	if spec.HostConfig.Memory <= 0 || spec.HostConfig.PidsLimit <= 0 {
		t.Errorf("zero caps not defaulted: mem=%d pids=%d", spec.HostConfig.Memory, spec.HostConfig.PidsLimit)
	}
	if len(spec.Cmd) == 0 {
		t.Error("empty Cmd should fall back to a keepalive default")
	}
}

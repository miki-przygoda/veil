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
		t.Error("NetworkDisabled = false, want true (invariants #1/#3)")
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

package sandbox

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestBuildSpecHardening(t *testing.T) {
	spec := DefaultConfig().HardenedSpec("world-01")

	if spec.Name != "veil-world-01" {
		t.Errorf("Name = %q, want veil-world-01", spec.Name)
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
	spec := Config{Image: "img:1", Memory: 128 << 20, PidsLimit: 64}.HardenedSpec("w")
	if spec.Image != "img:1" {
		t.Errorf("Image = %q, want img:1 (must read receiver, not hardcode)", spec.Image)
	}
	if spec.HostConfig.Memory != 128<<20 || spec.HostConfig.PidsLimit != 64 {
		t.Errorf("caps not read from receiver: mem=%d pids=%d", spec.HostConfig.Memory, spec.HostConfig.PidsLimit)
	}
}

func TestBuildSpecZeroCapsFallBack(t *testing.T) {
	// A partially-filled Config must never produce an uncapped container.
	spec := Config{Image: "img:1"}.HardenedSpec("w")
	if spec.HostConfig.Memory <= 0 || spec.HostConfig.PidsLimit <= 0 {
		t.Errorf("zero caps not defaulted: mem=%d pids=%d", spec.HostConfig.Memory, spec.HostConfig.PidsLimit)
	}
	if len(spec.Cmd) == 0 {
		t.Error("empty Cmd should fall back to a keepalive default")
	}
}

func TestBuildSpecJSONWireFormat(t *testing.T) {
	// Guards host-side hardening at the SERIALIZATION layer. A struct-level
	// reflect.DeepEqual is blind to json tags, so a typo'd tag would silently
	// drop a control on the wire and Docker would return an un-hardened box.
	b, err := json.Marshal(DefaultConfig().HardenedSpec("world-01"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["NetworkDisabled"] != true {
		t.Errorf("wire NetworkDisabled = %v, want true", m["NetworkDisabled"])
	}
	hc, ok := m["HostConfig"].(map[string]any)
	if !ok {
		t.Fatalf("wire HostConfig missing or not an object: %v", m["HostConfig"])
	}
	if hc["NetworkMode"] != "none" {
		t.Errorf("wire HostConfig.NetworkMode = %v, want none", hc["NetworkMode"])
	}
	if hc["ReadonlyRootfs"] != true {
		t.Errorf("wire HostConfig.ReadonlyRootfs = %v, want true", hc["ReadonlyRootfs"])
	}
	if !jsonArrayHasString(hc["CapDrop"], "ALL") {
		t.Errorf("wire HostConfig.CapDrop = %v, want to contain ALL", hc["CapDrop"])
	}
	if !jsonArrayHasString(hc["SecurityOpt"], "no-new-privileges:true") {
		t.Errorf("wire HostConfig.SecurityOpt = %v, want no-new-privileges:true", hc["SecurityOpt"])
	}
	// JSON numbers decode as float64; non-zero caps must survive to the wire.
	if n, _ := hc["PidsLimit"].(float64); n <= 0 {
		t.Errorf("wire HostConfig.PidsLimit = %v, want > 0", hc["PidsLimit"])
	}
	if n, _ := hc["Memory"].(float64); n <= 0 {
		t.Errorf("wire HostConfig.Memory = %v, want > 0", hc["Memory"])
	}
	if m["User"] != "65534:65534" {
		t.Errorf("wire User = %v, want 65534:65534 (non-root)", m["User"])
	}
	tmpfs, _ := hc["Tmpfs"].(map[string]any)
	if s, _ := tmpfs["/tmp"].(string); !strings.Contains(s, "noexec") || !strings.Contains(s, "nosuid") || !strings.Contains(s, "nodev") {
		t.Errorf("wire Tmpfs[/tmp] = %q, want noexec,nosuid,nodev", s)
	}
	if s, _ := tmpfs["/run"].(string); !strings.Contains(s, "noexec") || !strings.Contains(s, "nosuid") || !strings.Contains(s, "nodev") {
		t.Errorf("wire Tmpfs[/run] = %q, want noexec,nosuid,nodev", s)
	}
	if !jsonArrayHasString(hc["MaskedPaths"], "/proc/kcore") || !jsonArrayHasString(hc["MaskedPaths"], "/sys/firmware") {
		t.Errorf("wire MaskedPaths = %v, want /proc/kcore + /sys/firmware", hc["MaskedPaths"])
	}
	if !jsonArrayHasString(hc["ReadonlyPaths"], "/proc/sysrq-trigger") {
		t.Errorf("wire ReadonlyPaths = %v, want /proc/sysrq-trigger", hc["ReadonlyPaths"])
	}
	if n, _ := hc["CpuQuota"].(float64); n <= 0 {
		t.Errorf("wire CpuQuota = %v, want > 0", hc["CpuQuota"])
	}
	if n, _ := hc["CpuPeriod"].(float64); n != 100000 {
		t.Errorf("wire CpuPeriod = %v, want 100000", hc["CpuPeriod"])
	}
}

func TestBuildSpecNetwork(t *testing.T) {
	// Empty Network keeps the box isolated (today's default).
	none := DefaultConfig().HardenedSpec("w")
	if none.NetworkDisabled != true || none.HostConfig.NetworkMode != "none" {
		t.Errorf("default: NetworkDisabled=%v NetworkMode=%q, want true/none", none.NetworkDisabled, none.HostConfig.NetworkMode)
	}
	// A named network joins it (no external egress on an internal net).
	cfg := DefaultConfig()
	cfg.Network = "veil-net"
	joined := cfg.HardenedSpec("w")
	if joined.NetworkDisabled != false || joined.HostConfig.NetworkMode != "veil-net" {
		t.Errorf("joined: NetworkDisabled=%v NetworkMode=%q, want false/veil-net", joined.NetworkDisabled, joined.HostConfig.NetworkMode)
	}
}

func TestBuildSpecOptInControls(t *testing.T) {
	// Absent by default.
	def := DefaultConfig().HardenedSpec("w")
	if def.HostConfig.UsernsMode != "" {
		t.Errorf("default UsernsMode = %q, want empty (opt-in)", def.HostConfig.UsernsMode)
	}
	for _, so := range def.HostConfig.SecurityOpt {
		if strings.HasPrefix(so, "seccomp=") || strings.HasPrefix(so, "apparmor=") {
			t.Errorf("default SecurityOpt has %q; seccomp/apparmor must be opt-in", so)
		}
	}

	// Present when set.
	cfg := DefaultConfig()
	cfg.UsernsMode = "private"
	cfg.SeccompJSON = []byte(`{"defaultAction":"SCMP_ACT_ERRNO"}`)
	cfg.AppArmor = "docker-default"
	spec := cfg.HardenedSpec("w")
	if spec.HostConfig.UsernsMode != "private" {
		t.Errorf("UsernsMode = %q, want private", spec.HostConfig.UsernsMode)
	}
	if !slices.Contains(spec.HostConfig.SecurityOpt, "apparmor=docker-default") {
		t.Errorf("SecurityOpt = %v, want apparmor=docker-default", spec.HostConfig.SecurityOpt)
	}
	if !slices.Contains(spec.HostConfig.SecurityOpt, `seccomp={"defaultAction":"SCMP_ACT_ERRNO"}`) {
		t.Errorf("SecurityOpt = %v, want the seccomp profile", spec.HostConfig.SecurityOpt)
	}
	if !slices.Contains(spec.HostConfig.SecurityOpt, "no-new-privileges:true") {
		t.Errorf("SecurityOpt = %v; no-new-privileges:true must survive opt-in controls", spec.HostConfig.SecurityOpt)
	}
}

func TestBuildSpecDNS(t *testing.T) {
	if dns := DefaultConfig().HardenedSpec("w").HostConfig.Dns; len(dns) != 0 {
		t.Errorf("default must not set Dns, got %v", dns)
	}
	cfg := DefaultConfig()
	cfg.DNS = []string{"172.20.0.1"}
	if got := cfg.HardenedSpec("w").HostConfig.Dns; len(got) != 1 || got[0] != "172.20.0.1" {
		t.Errorf("Dns = %v, want [172.20.0.1]", got)
	}
}

func TestHardenedSpecExportedForResidents(t *testing.T) {
	// A resident-style config: veil-net + world DNS. HardenedSpec must be callable
	// from outside (exported), name deterministically, inherit the box hardening,
	// and add NO caps (the Fleet layers on NET_BIND_SERVICE itself).
	spec := Config{Image: "veil-resident:dev", Network: "veil-net", DNS: []string{"172.20.0.1"}}.
		HardenedSpec("resident-web.veil.local")
	if spec.Name != "veil-resident-web.veil.local" {
		t.Errorf("Name = %q, want veil-resident-web.veil.local", spec.Name)
	}
	if len(spec.HostConfig.CapDrop) != 1 || spec.HostConfig.CapDrop[0] != "ALL" {
		t.Errorf("CapDrop = %v, want [ALL]", spec.HostConfig.CapDrop)
	}
	if spec.HostConfig.NetworkMode != "veil-net" {
		t.Errorf("NetworkMode = %q", spec.HostConfig.NetworkMode)
	}
	if len(spec.HostConfig.CapAdd) != 0 {
		t.Errorf("HardenedSpec must not add caps, got %v", spec.HostConfig.CapAdd)
	}
}

func jsonArrayHasString(v any, want string) bool {
	arr, ok := v.([]any)
	if !ok {
		return false
	}
	for _, e := range arr {
		if s, _ := e.(string); s == want {
			return true
		}
	}
	return false
}

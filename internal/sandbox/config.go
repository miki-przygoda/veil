package sandbox

import "github.com/miki-przygoda/veil/internal/docker"

// Ownership labels let a future startup GC prune everything we created.
const (
	labelManaged = "com.veil.managed"
	labelWorld   = "com.veil.world"
)

// Config is the contained world's shape. Start from DefaultConfig and override.
type Config struct {
	Image       string   // base image ref; must be present locally (no auto-pull)
	Cmd         []string // keepalive/workload command
	Memory      int64    // hard memory cap, bytes
	PidsLimit   int64    // max processes
	Network     string   // "" => no network (NetworkMode:none); else the network to join
	DNS         []string // resolver addresses; empty => Docker default
	User        string   // "" => "65534:65534" (non-root)
	CPUs        float64  // 0  => 1.0 CPU
	UsernsMode  string   // opt-in user-namespace mode (e.g. "private"); default off
	SeccompJSON []byte   // opt-in seccomp profile JSON; default off (daemon default applies)
	AppArmor    string   // opt-in apparmor profile (e.g. "docker-default"); default off
}

// Docker's standard masked/read-only /proc & /sys paths, set explicitly so
// containment is Veil-owned rather than reliant on daemon defaults.
// Treat both slices as read-only — buildSpec shares the backing array; never append.
var maskedPaths = []string{
	"/proc/asound", "/proc/acpi", "/proc/kcore", "/proc/keys",
	"/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats",
	"/proc/sched_debug", "/proc/scsi", "/sys/firmware",
	"/sys/devices/virtual/powercap",
}
var readonlyPaths = []string{
	"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger",
}

// DefaultConfig returns hardened defaults: a minimal base image kept alive with
// no workload, modest resource caps. Override Image with a digest to pin.
func DefaultConfig() Config {
	return Config{
		Image:     "alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc", // digest-pinned; refresh on each alpine:3.20 security release
		Cmd:       []string{"sleep", "infinity"},
		Memory:    512 << 20, // 512 MiB
		PidsLimit: 256,
	}
}

// buildSpec turns a Config into the hardened container-create spec for a world.
// Every isolation control is set here, host-side — nothing is enforced in-guest.
// Zero-valued hardening fields fall back to safe defaults so a partially-filled
// Config can never silently produce an uncapped container (Docker reads an
// absent/zero Memory or PidsLimit as "unlimited").
func (c Config) buildSpec(world string) docker.CreateSpec {
	def := DefaultConfig()
	cmd := c.Cmd
	if len(cmd) == 0 {
		cmd = def.Cmd
	}
	mem := c.Memory
	if mem <= 0 {
		mem = def.Memory
	}
	pids := c.PidsLimit
	if pids <= 0 {
		pids = def.PidsLimit
	}
	user := c.User
	if user == "" {
		user = "65534:65534"
	}
	cpus := c.CPUs
	if cpus <= 0 {
		cpus = 1.0
	}

	netDisabled := true
	netMode := "none"
	if c.Network != "" {
		netDisabled = false
		netMode = c.Network
	}

	secOpt := []string{"no-new-privileges:true"}
	if c.AppArmor != "" {
		secOpt = append(secOpt, "apparmor="+c.AppArmor)
	}
	if len(c.SeccompJSON) > 0 {
		secOpt = append(secOpt, "seccomp="+string(c.SeccompJSON))
	}

	return docker.CreateSpec{
		Name:            "veil-" + world,
		User:            user,
		Image:           c.Image,
		Cmd:             cmd,
		Labels:          map[string]string{labelManaged: "true", labelWorld: world},
		NetworkDisabled: netDisabled,
		HostConfig: docker.HostConfig{
			ReadonlyRootfs: true,
			Tmpfs:          map[string]string{"/tmp": "noexec,nosuid,nodev", "/run": "noexec,nosuid,nodev"},
			CapDrop:        []string{"ALL"},
			SecurityOpt:    secOpt,
			UsernsMode:     c.UsernsMode,
			PidsLimit:      pids,
			Memory:         mem,
			NetworkMode:    netMode,
			Dns:            c.DNS,
			MaskedPaths:    maskedPaths,
			ReadonlyPaths:  readonlyPaths,
			CpuPeriod:      100000,
			CpuQuota:       int64(cpus * 100000),
		},
	}
}

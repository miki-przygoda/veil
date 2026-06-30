package sandbox

// Ownership labels let a future startup GC prune everything we created.
const (
	labelManaged = "com.veil.managed"
	labelWorld   = "com.veil.world"
)

// Config is the contained world's shape. Start from DefaultConfig and override.
type Config struct {
	Image     string   // base image ref; must be present locally (no auto-pull)
	Cmd       []string // keepalive/workload command
	Memory    int64    // hard memory cap, bytes
	PidsLimit int64    // max processes
}

// DefaultConfig returns hardened defaults: a minimal base image kept alive with
// no workload, modest resource caps. Override Image with a digest to pin.
func DefaultConfig() Config {
	return Config{
		Image:     "alpine:3.20",
		Cmd:       []string{"sleep", "infinity"},
		Memory:    512 << 20, // 512 MiB
		PidsLimit: 256,
	}
}

// buildSpec turns a Config into the hardened container-create spec for a world.
// Every isolation control is set here, host-side — nothing is enforced in-guest.
func (c Config) buildSpec(world string) createSpec {
	return createSpec{
		name:            "veil-" + world,
		Image:           c.Image,
		Cmd:             c.Cmd,
		Labels:          map[string]string{labelManaged: "true", labelWorld: world},
		NetworkDisabled: true,
		HostConfig: hostConfig{
			ReadonlyRootfs: true,
			Tmpfs:          map[string]string{"/tmp": "", "/run": ""},
			CapDrop:        []string{"ALL"},
			SecurityOpt:    []string{"no-new-privileges:true"},
			PidsLimit:      c.PidsLimit,
			Memory:         c.Memory,
			NetworkMode:    "none",
		},
	}
}

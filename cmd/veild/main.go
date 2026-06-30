// Command veild is Veil's host-side control plane — the "outside" of the world.
//
// It wires the spine together: a sandbox (container-backed by default, stub
// fallback), synthetic residents, a host-side tap (stubbed), and the live
// observation feed. Run it and open http://localhost:8080 to watch events
// stream out of the world in real time.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/miki-przygoda/veil/internal/events"
	"github.com/miki-przygoda/veil/internal/netfabric"
	"github.com/miki-przygoda/veil/internal/residents"
	"github.com/miki-przygoda/veil/internal/sandbox"
	"github.com/miki-przygoda/veil/internal/viz"
)

// selectSandbox picks the isolation backend. The container backend is the
// default; if the Docker daemon is unreachable it logs, emits an observable
// KindSystem event, and falls back to the stub so the demo still boots.
func selectSandbox(ctx context.Context, backend string, bus *events.Bus, log *slog.Logger) sandbox.Sandbox {
	if backend == "stub" {
		return sandbox.NewStub("world-01", bus)
	}
	c, err := sandbox.NewContainer("world-01", bus, sandbox.DefaultConfig())
	if err == nil {
		err = c.Ping(ctx)
	}
	if err != nil {
		log.Warn("docker unavailable, falling back to stub backend", "err", err)
		e := events.New(events.KindSystem, "veild", "backend fallback")
		e.Detail = "container backend unavailable: " + err.Error() + "; using stub"
		bus.Publish(e)
		return sandbox.NewStub("world-01", bus)
	}
	log.Info("using container backend")
	return c
}

func main() {
	backend := flag.String("backend", "container", "sandbox backend: container|stub")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	bus := events.NewBus(512)

	// The contained world.
	box := selectSandbox(ctx, *backend, bus, log)
	if err := box.Create(ctx); err != nil {
		log.Error("sandbox create", "err", err)
		os.Exit(1)
	}
	if err := box.Start(ctx); err != nil {
		log.Error("sandbox start", "err", err)
		os.Exit(1)
	}

	// Synthetic inhabitants so the world looks alive.
	go (&residents.Population{Size: 5}).Run(ctx, bus)

	// Host-side passive tap. Stub for now.
	go func() {
		tap := &netfabric.StubTap{Interval: 2 * time.Second}
		if err := tap.Run(ctx, bus); err != nil && ctx.Err() == nil {
			log.Error("tap", "err", err)
		}
	}()

	// Live observation feed. Blocks until shutdown.
	server := viz.NewServer(":8080", bus, log)
	runErr := server.Run(ctx)

	// Tear the world down on the way out — clean shutdown or viz failure alike —
	// so we don't leak a container. The Create-time reconcile covers crashes
	// where this never runs.
	if err := box.Destroy(context.Background()); err != nil {
		log.Warn("sandbox destroy on shutdown", "err", err)
	}

	if runErr != nil {
		log.Error("viz", "err", runErr)
		os.Exit(1)
	}
	log.Info("shutdown complete")
}

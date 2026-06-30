// Command veild is Veil's host-side control plane — the "outside" of the world.
//
// It wires the spine together: a sandbox (stubbed), synthetic residents, a
// host-side tap (stubbed), and the live observation feed. Run it and open
// http://localhost:8080 to watch events stream out of the world in real time.
package main

import (
	"context"
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

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	bus := events.NewBus(512)

	// The contained world. Stub for now — swap for a real isolation backend.
	box := sandbox.NewStub("world-01", bus)
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
	if err := server.Run(ctx); err != nil {
		log.Error("viz", "err", err)
		os.Exit(1)
	}

	log.Info("shutdown complete")
}

// Command veild is Veil's host-side control plane — the "outside" of the world.
//
// It wires the spine together: a sandbox (container-backed by default;
// -backend=stub is the explicit zero-isolation dev mode), synthetic residents,
// a host-side tap (packet by default, stub fallback), and the live observation
// feed. Run it and open http://localhost:8080 to watch events stream out of the
// world in real time.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/miki-przygoda/veil/internal/docker"
	"github.com/miki-przygoda/veil/internal/events"
	"github.com/miki-przygoda/veil/internal/netfabric"
	"github.com/miki-przygoda/veil/internal/residents"
	"github.com/miki-przygoda/veil/internal/sandbox"
	"github.com/miki-przygoda/veil/internal/viz"
)

// selectSandbox picks the isolation backend. The container backend REQUIRES a
// reachable Docker daemon: if it is unavailable, this returns an error and veild
// exits (fail closed) rather than silently degrading to the isolation-free stub.
// -backend=stub is the explicit, opt-in, zero-isolation dev mode.
func selectSandbox(ctx context.Context, backend, network string, dns []string, bus *events.Bus, log *slog.Logger) (sandbox.Sandbox, error) {
	if backend == "stub" {
		return sandbox.NewStub("world-01", bus), nil
	}
	cfg := sandbox.DefaultConfig()
	cfg.Network = network // "" keeps NetworkMode:none
	cfg.DNS = dns         // nil leaves Docker's default resolver
	c, err := sandbox.NewContainer("world-01", bus, cfg)
	if err == nil {
		err = c.Ping(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("container backend requires a reachable Docker daemon: %w", err)
	}
	log.Info("using container backend", "network", network)
	return c, nil
}

// selectTap picks the tap backend. The packet tap captures real traffic off the
// world's bridge; if capture is unavailable (non-Linux, no privilege) it logs,
// emits an observable KindSystem event, and falls back to the synthetic StubTap.
func selectTap(ctx context.Context, tapMode, bridge string, bus *events.Bus, log *slog.Logger) netfabric.Tap {
	if tapMode == "stub" {
		return &netfabric.StubTap{Interval: 2 * time.Second}
	}
	tap, err := netfabric.OpenTap(bridge)
	if err != nil {
		log.Warn("packet capture unavailable, using stub tap", "err", err)
		e := events.New(events.KindSystem, "veild", "tap fallback")
		e.Detail = "packet capture unavailable: " + err.Error() + "; using stub"
		bus.Publish(e)
		return &netfabric.StubTap{Interval: 2 * time.Second}
	}
	log.Info("using packet tap", "bridge", bridge)
	return tap
}

// buildWorld turns the resolved veil-net subnet/gateway into the shared World the
// resolver and classifier read. Empty strings (stub/no-Docker) yield a nil Subnet
// so the classifier's IP vector safely no-ops. names, when non-nil, seeds
// World.Names from the fleet's WorldNames so the resolver can answer fleet hosts.
func buildWorld(subnet, gateway string, names map[string]net.IP) netfabric.World {
	w := netfabric.World{
		Gateway: net.ParseIP(gateway),
		Zones:   []string{".veil.local"},
		Names:   map[string]net.IP{},
	}
	for k, v := range names {
		w.Names[k] = v
	}
	if subnet != "" {
		if _, ipnet, err := net.ParseCIDR(subnet); err == nil {
			w.Subnet = ipnet
		}
	}
	return w
}

// startResolver binds the synthetic resolver to the veil-net gateway and serves
// it in the background. It returns false (and emits an observable KindSystem
// event) if the bind fails, so the caller leaves the box on Docker's default DNS
// — mirroring the -backend/-tap graceful fallbacks.
func startResolver(ctx context.Context, world netfabric.World, gateway string, bus *events.Bus, log *slog.Logger) bool {
	conn, err := net.ListenPacket("udp", gateway+":53")
	if err != nil {
		log.Warn("resolver bind failed, world DNS disabled", "err", err)
		e := events.New(events.KindSystem, "veild", "resolver fallback")
		e.Detail = "resolver bind failed on " + gateway + ": " + err.Error()
		bus.Publish(e)
		return false
	}
	go func() {
		// Serve owns conn and closes it when it returns (via its own shutdown
		// goroutine, on ctx-cancel or on error return), so we don't close it here.
		if err := netfabric.NewResolver(world, bus).Serve(ctx, conn); err != nil && ctx.Err() == nil {
			log.Error("resolver", "err", err)
		}
	}()
	log.Info("world resolver serving", "addr", gateway+":53")
	return true
}

func main() {
	backend := flag.String("backend", "container", "sandbox backend: container|stub")
	tapMode := flag.String("tap", "packet", "tap backend: packet|stub")
	resolverMode := flag.String("resolver", "on", "world DNS resolver + honeypot: on|off")
	residentsMode := flag.String("residents", "on", "spawn synthetic resident hosts on veil-net: on|off")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	bus := events.NewBus(512)

	// The world's network: an internal (no-egress) Docker network the box joins
	// and the tap observes. Best-effort — if it fails, the box stays isolated.
	// teardownFabric is called inline in the shutdown sequence (not deferred) so
	// it also runs on the viz-error os.Exit path.
	var netName, bridge, subnet, gateway string
	teardownFabric := func() {}
	var cli *docker.Client
	if *backend != "stub" {
		var err error
		cli, err = docker.New(os.Getenv("DOCKER_HOST"))
		if err != nil {
			log.Warn("docker client unavailable, skipping network", "err", err)
		} else {
			fabric := netfabric.NewFabric(cli, "veil-net")
			if dnet, err := fabric.Ensure(ctx); err != nil {
				log.Warn("network setup failed, box stays isolated", "err", err)
			} else {
				netName, bridge, subnet, gateway = dnet.Name, dnet.Bridge, dnet.Subnet, dnet.Gateway
				teardownFabric = func() {
					tctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					if err := fabric.Teardown(tctx); err != nil {
						log.Warn("network teardown", "err", err)
					}
				}
			}
		}
	}

	// Resident fleet: constructed BEFORE buildWorld so WorldNames seeds the
	// resolver. The fleet is skipped (Population fallback) on the stub backend,
	// when -residents=off, or when Docker is unavailable.
	var fleet *residents.Fleet
	teardownResidents := func() {}
	if *backend != "stub" && *residentsMode == "on" && gateway != "" && cli != nil {
		fleet = residents.NewFleet(cli, "veil-resident:dev", subnet, gateway, residents.DefaultRoster())
	}
	var residentNames map[string]net.IP
	if fleet != nil {
		residentNames = fleet.WorldNames()
	}

	// World-service layer (all host-side): a synthetic resolver + transparent
	// honeypot make the world believable; the classifier turns facts into
	// KindEscape. The classifier is cheap and Docker-free, so it always runs; on
	// the stub path Subnet is nil and its IP vector no-ops.
	world := buildWorld(subnet, gateway, residentNames)
	go func() {
		if err := netfabric.NewClassifier(world).Run(ctx, bus); err != nil && ctx.Err() == nil {
			log.Error("classifier", "err", err)
		}
	}()

	var dns []string
	teardownHoneypot := func() {}
	if *resolverMode == "on" && gateway != "" {
		if startResolver(ctx, world, gateway, bus, log) {
			dns = []string{gateway}
			if td, err := netfabric.InstallHoneypot(bridge, subnet, gateway, bus, log); err != nil {
				log.Warn("honeypot unavailable, escape detection still on", "err", err)
				e := events.New(events.KindSystem, "veild", "honeypot unavailable")
				e.Detail = err.Error()
				bus.Publish(e)
			} else {
				teardownHoneypot = td
			}
		}
	}

	// The contained world.
	box, err := selectSandbox(ctx, *backend, netName, dns, bus, log)
	if err != nil {
		log.Error("sandbox backend unavailable", "err", err)
		teardownResidents()
		teardownHoneypot()
		teardownFabric()
		os.Exit(1)
	}
	if err := box.Create(ctx); err != nil {
		log.Error("sandbox create", "err", err)
		teardownResidents()
		teardownHoneypot()
		teardownFabric()
		os.Exit(1)
	}
	if err := box.Start(ctx); err != nil {
		log.Error("sandbox start", "err", err)
		teardownResidents()
		teardownHoneypot()
		teardownFabric()
		os.Exit(1)
	}

	// Synthetic inhabitants: real fleet when veil-net is up, Population bus-fake
	// otherwise. The two are mutually exclusive — never both.
	if fleet != nil {
		if err := fleet.Up(ctx, bus, log); err != nil {
			// Every resident failed (e.g. veil-resident:dev not built). Keep the
			// dashboard alive with the bus-fake, the same fallback used with no fabric.
			log.Warn("residents failed to start, using synthetic fallback", "err", err)
			go (&residents.Population{Size: 5}).Run(ctx, bus)
		} else {
			teardownResidents = func() {
				tctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err := fleet.Down(tctx, bus); err != nil {
					log.Warn("residents teardown", "err", err)
				}
			}
		}
	} else {
		go (&residents.Population{Size: 5}).Run(ctx, bus)
	}

	// Host-side passive tap. Packet tap by default; falls back to stub when
	// capture is unavailable (non-Linux or insufficient privilege).
	go func() {
		tap := selectTap(ctx, *tapMode, bridge, bus, log)
		if err := tap.Run(ctx, bus); err != nil && ctx.Err() == nil {
			log.Error("tap", "err", err)
		}
	}()

	// Live observation feed. Blocks until shutdown.
	server := viz.NewServer(":8080", bus, log)
	runErr := server.Run(ctx)

	// Tear the world down on the way out — clean shutdown or viz failure alike —
	// so we don't leak a container. Bounded so a wedged daemon can't hang exit;
	// the Create-time reconcile covers crashes where this never runs.
	destroyCtx, cancelDestroy := context.WithTimeout(context.Background(), 10*time.Second)
	if err := box.Destroy(destroyCtx); err != nil {
		log.Warn("sandbox destroy on shutdown", "err", err)
	}
	cancelDestroy()
	teardownResidents()
	teardownHoneypot()
	teardownFabric()

	if runErr != nil {
		log.Error("viz", "err", runErr)
		os.Exit(1)
	}
	log.Info("shutdown complete")
}

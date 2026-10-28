// Command veild is Veil's host-side control plane — the "outside" of the world.
//
// It wires the spine together: a sandbox (container-backed by default;
// -backend=stub is the explicit zero-isolation dev mode), synthetic residents,
// a host-side tap (packet by default, stub fallback), and the live observation
// feed. Run it and open http://localhost:8080 (loopback by default; see
// -listen) to watch events stream out of the world in real time.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/miki-przygoda/veil/internal/docker"
	"github.com/miki-przygoda/veil/internal/events"
	"github.com/miki-przygoda/veil/internal/netfabric"
	"github.com/miki-przygoda/veil/internal/residents"
	"github.com/miki-przygoda/veil/internal/sandbox"
	"github.com/miki-przygoda/veil/internal/scoring"
	"github.com/miki-przygoda/veil/internal/subject"
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

// startTap opens the tap synchronously — the AF_PACKET handle, or the StubTap
// fallback with its KindSystem event — and only then runs it in the background,
// so a caller that starts the subject afterwards never has its first command
// race capture attachment. The returned channel closes when Run returns (on ctx
// cancel, which also closes the capture handle).
func startTap(ctx context.Context, tapMode, bridge string, bus *events.Bus, log *slog.Logger) <-chan struct{} {
	tap := selectTap(ctx, tapMode, bridge, bus, log)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := tap.Run(ctx, bus); err != nil && ctx.Err() == nil {
			log.Error("tap", "err", err)
		}
	}()
	return done
}

// waitTap waits up to bound for a startTap done channel, so on shutdown the
// AF_PACKET handle is closed before the bridge it is bound to is removed. It
// reports whether the tap stopped in time; a nil done (no tap) counts as stopped.
func waitTap(done <-chan struct{}, bound time.Duration, log *slog.Logger) bool {
	if done == nil {
		return true
	}
	select {
	case <-done:
		return true
	case <-time.After(bound):
		log.Warn("tap did not stop in time; tearing the network down anyway", "bound", bound)
		return false
	}
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

// startResolver binds the synthetic resolver to addr (the veil-net gateway's :53)
// over UDP and TCP and serves both in the background. udp is false (with an
// observable KindSystem event) if the UDP bind fails, so the caller leaves the box
// on Docker's default DNS — mirroring the -backend/-tap graceful fallbacks — or, on
// an engine without the CVE-2024-29018 fix where that default leaks real DNS, off
// veil-net entirely (see boxNetwork); TCP is then not attempted. tcp is false (with
// its own KindSystem event) if only the TCP bind fails: UDP DNS still works, and the
// caller keeps tcp/53 on the honeypot rather than exempting an unserved port.
func startResolver(ctx context.Context, world netfabric.World, addr string, bus *events.Bus, log *slog.Logger) (udp, tcp bool) {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Warn("resolver bind failed, world DNS disabled", "err", err)
		e := events.New(events.KindSystem, "veild", "resolver fallback")
		e.Detail = "resolver bind failed on " + addr + ": " + err.Error()
		bus.Publish(e)
		return false, false
	}
	r := netfabric.NewResolver(world, bus)
	go func() {
		// Serve owns conn and closes it when it returns (via its own shutdown
		// goroutine, on ctx-cancel or on error return), so we don't close it here.
		if err := r.Serve(ctx, conn); err != nil && ctx.Err() == nil {
			log.Error("resolver", "err", err)
		}
	}()
	log.Info("world resolver serving", "addr", addr, "proto", "udp")

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Warn("resolver tcp bind failed, DNS-over-TCP stays on the honeypot", "err", err)
		e := events.New(events.KindSystem, "veild", "resolver tcp fallback")
		e.Detail = "resolver tcp bind failed on " + addr + ": " + err.Error() + "; tcp/53 stays redirected to the honeypot"
		bus.Publish(e)
		return true, false
	}
	go func() {
		// ServeTCP likewise owns ln and closes it (and every conn) on return.
		if err := r.ServeTCP(ctx, ln); err != nil && ctx.Err() == nil {
			log.Error("resolver tcp", "err", err)
		}
	}()
	log.Info("world resolver serving", "addr", addr, "proto", "tcp")
	return true, true
}

// engineVersion is a parsed Docker engine version. pre marks a pre-release
// ("25.0.0-rc.1"), which sorts below the release it precedes.
type engineVersion struct {
	major, minor, patch int
	pre                 bool
}

// parseEngineVersion parses "MAJOR.MINOR.PATCH" with an optional "-pre-release"
// and/or "+build" suffix ("24.0.7", "25.0.0-rc.1", "25.0.5+dfsg1"). ok is false
// for anything else, so callers can treat an unknown version as old.
func parseEngineVersion(v string) (engineVersion, bool) {
	core, _, _ := strings.Cut(v, "+")
	core, _, hasPre := strings.Cut(core, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return engineVersion{}, false
	}
	var nums [3]int
	for i, p := range parts {
		if p == "" {
			return engineVersion{}, false
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return engineVersion{}, false
			}
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return engineVersion{}, false
		}
		nums[i] = n
	}
	return engineVersion{nums[0], nums[1], nums[2], hasPre}, true
}

// atLeast reports whether v >= major.minor.patch (a release); a pre-release of
// exactly that version is older than it.
func (v engineVersion) atLeast(major, minor, patch int) bool {
	if v.major != major {
		return v.major > major
	}
	if v.minor != minor {
		return v.minor > minor
	}
	if v.patch != patch {
		return v.patch > patch
	}
	return !v.pre
}

// embeddedDNSIsolated reports whether this engine's embedded DNS refuses to
// forward from an --internal network. Before the CVE-2024-29018 fix
// (GHSA-mq39-4gv4-mvpx: 26.0.0, backported to 25.0.5) dockerd forwarded such
// queries from the host network namespace whenever the host's resolver is on
// loopback — systemd-resolved's 127.0.0.53 on stock Ubuntu. The 23.0.11
// backport is deliberately not trusted: 24.x never got it, and failing closed
// on a 23.0.x line is cheap.
func embeddedDNSIsolated(v engineVersion) bool {
	if v.major == 25 {
		return v.atLeast(25, 0, 5)
	}
	return v.atLeast(26, 0, 0)
}

// embeddedDNSLeaks reports whether joining the box to veil-net would hand it a
// real-internet DNS channel. On a user-defined network the box's resolv.conf
// always names Docker's embedded resolver (127.0.0.11), which answers container
// names itself and forwards everything else, from the container's netns, to its
// upstreams. With the world resolver up, HostConfig.Dns makes the gateway that
// only upstream, so non-container names reach the world resolver over veil-net
// and never the host's real resolvers. With it down there is no explicit
// upstream: on a patched engine (>= 25.0.5 on the 25.0 line, >= 26.0.0
// otherwise) the embedded resolver refuses to forward from an --internal network
// (it answers only container names on veil-net, i.e. the residents), but on
// older engines it can forward to the host's real upstreams — an exfil path out
// of the synthetic world (invariant #3). An unknown or unparseable version, or a pre-release of a patched
// version, is treated as old.
func embeddedDNSLeaks(resolverUp bool, version string) bool {
	if resolverUp {
		return false
	}
	v, ok := parseEngineVersion(version)
	return !ok || !embeddedDNSIsolated(v)
}

// boxNetwork decides which network the box joins. It returns netName unless
// embeddedDNSLeaks says that would leak real DNS, in which case it fails closed
// to "" (NetworkMode:none) with an observable KindSystem event. An empty netName
// (no fabric) is already none and passes through silently.
func boxNetwork(netName string, resolverUp bool, version string, bus *events.Bus, log *slog.Logger) string {
	if netName == "" || !embeddedDNSLeaks(resolverUp, version) {
		return netName
	}
	shown := version
	if shown == "" {
		shown = "unknown"
	}
	log.Warn("world resolver down on a Docker engine without the CVE-2024-29018 fix: embedded DNS would forward to real upstreams; box stays on NetworkMode:none", "engine", shown, "network", netName)
	e := events.New(events.KindSystem, "veild", "box network withheld")
	e.Detail = "world resolver is down and Docker engine " + events.SafeField(shown, 40) + " (older than 25.0.5/26.0.0, or unknown) forwards embedded DNS to real upstreams on internal networks; box kept off " + netName + " (NetworkMode:none)"
	bus.Publish(e)
	return ""
}

// resolveBoxNetwork is main's D7 glue: it picks the network the box joins given
// whether the world resolver is up. The engine version is only queried (bounded
// to 5s) when it can matter — box on veil-net, resolver down; a failed query
// leaves it unknown, which boxNetwork treats as old. When a patched engine lets
// the box join with the resolver down, its DNS stays on 127.0.0.11 inside its own
// netns: nothing crosses the bridge, so no resolver or tap sees it and
// external-dns detection goes dark — said with a KindSystem event.
func resolveBoxNetwork(ctx context.Context, netName string, resolverUp bool, engineVersion func(context.Context) (string, error), bus *events.Bus, log *slog.Logger) string {
	if netName == "" || resolverUp {
		return netName
	}
	vctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	engine, err := engineVersion(vctx)
	cancel()
	if err != nil {
		log.Warn("docker engine version unavailable", "err", err)
	}
	boxNet := boxNetwork(netName, false, engine, bus, log)
	if boxNet != "" {
		log.Warn("world resolver down: box uses Docker's embedded DNS inside its netns; external-dns detection is dark", "engine", engine, "network", boxNet)
		e := events.New(events.KindSystem, "veild", "world dns dark")
		e.Detail = "world resolver is down; the box's DNS stays on Docker's embedded resolver (127.0.0.11) inside its netns, so no lookup is observed and external-dns escapes go undetected"
		bus.Publish(e)
	}
	return boxNet
}

// defaultListen keeps the dashboard on loopback. The observer feed must never be
// reachable from the world (invariant #1), and a wildcard bind would include the
// veil-net gateway — the one off-box address the box can always reach.
const defaultListen = "127.0.0.1:8080"

// listenExposed reports whether addr binds every interface (empty host, 0.0.0.0
// or ::). An unparseable addr is treated as exposed; ListenAndServe rejects it
// anyway.
func listenExposed(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return true
	}
	if host == "" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}

// listensOnGateway reports whether addr's host is exactly the veil-net gateway
// IP. An empty or unparseable gateway or host never matches.
func listensOnGateway(addr, gateway string) bool {
	gw := net.ParseIP(gateway)
	if gw == nil {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.Equal(gw)
}

// warnIfObserverExposed logs a warning when the dashboard binds every interface,
// or the veil-net gateway itself, while the box is actually on veil-net (boxNet,
// "" when it was withheld): the gateway may then serve /events and /report to
// the subject, hidden only by the honeypot's REDIRECT of box->gateway TCP (when
// the honeypot is up). Not fatal — an operator may bind wide on purpose.
// Log-only by design: it runs before the viz server is listening and the Bus has
// no replay, so a KindSystem event here would reach no viewer.
func warnIfObserverExposed(addr, boxNet, gateway string, log *slog.Logger) {
	if boxNet == "" {
		return
	}
	switch {
	case listenExposed(addr):
		log.Warn("dashboard listens on all interfaces; observer may be reachable from the world unless the honeypot is up; use -listen=127.0.0.1:8080", "listen", addr, "network", boxNet)
	case listensOnGateway(addr, gateway):
		log.Warn("dashboard listens on the veil-net gateway; observer may be reachable from the world unless the honeypot is up; use -listen=127.0.0.1:8080", "listen", addr, "network", boxNet)
	}
}

func main() {
	listen := flag.String("listen", defaultListen, "dashboard listen address; keep it off the veil-net gateway (loopback by default)")
	backend := flag.String("backend", "container", "sandbox backend: container|stub")
	tapMode := flag.String("tap", "packet", "tap backend: packet|stub")
	resolverMode := flag.String("resolver", "on", "world DNS resolver + honeypot: on|off")
	residentsMode := flag.String("residents", "on", "spawn synthetic resident hosts on veil-net: on|off")
	subjectFile := flag.String("subject", "", "run a scripted subject: path to a command file (one per line); empty = off")
	subjectGoal := flag.String("subject-goal", "", "run an autonomous subject with this goal; empty = off")
	subjectBrain := flag.String("subject-brain", "scripted", "autonomous subject brain: scripted|claude")
	subjectSteps := flag.Int("subject-steps", 12, "autonomous subject step budget")
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
	classifier := netfabric.NewClassifier(world)
	if fleet != nil {
		// Until the fleet is up, ignore every Trusted address it will claim (a
		// crashed run's orphan may still be talking). The box claims its address first but
		// stays idle until the subject starts, which is after fleet.Up narrows this.
		classifier.SetNonSubject(fleet.PlannedTrustedIPs()...)
	}
	go func() {
		if err := classifier.Run(ctx, bus); err != nil && ctx.Err() == nil {
			log.Error("classifier", "err", err)
		}
	}()

	// Escape scoring: a host-side observer that grades the subject's escape attempts.
	// Subscribes to the bus like the classifier; served on GET /report and logged at
	// shutdown. Pure measurement — it pushes nothing back to the box.
	scorer := scoring.NewScorer()
	go func() { _ = scorer.Run(ctx, bus) }()

	var dns []string
	teardownHoneypot := func() {}
	if *resolverMode == "on" && gateway != "" {
		if udp, tcp := startResolver(ctx, world, net.JoinHostPort(gateway, "53"), bus, log); udp {
			dns = []string{gateway}
			// tcp/53 is exempted from the honeypot only while the resolver serves it.
			if td, err := netfabric.InstallHoneypot(bridge, subnet, gateway, tcp, bus, log); err != nil {
				log.Warn("honeypot unavailable, escape detection still on", "err", err)
				e := events.New(events.KindSystem, "veild", "honeypot unavailable")
				e.Detail = err.Error()
				bus.Publish(e)
			} else {
				teardownHoneypot = td
			}
		}
	}

	// Without the world resolver the box's embedded DNS has no explicit upstream,
	// and before 25.0.5 / 26.0.0 (CVE-2024-29018) it can forward to the host's
	// real upstreams even on an --internal network. Fail closed there: the box
	// stays on NetworkMode:none. On a patched engine it joins, with DNS dark.
	// netName != "" implies cli != nil, and the getter is only called then.
	var engineVersion func(context.Context) (string, error)
	if cli != nil {
		engineVersion = cli.EngineVersion
	}
	boxNet := resolveBoxNetwork(ctx, netName, dns != nil, engineVersion, bus, log)

	// The contained world.
	box, err := selectSandbox(ctx, *backend, boxNet, dns, bus, log)
	if err != nil {
		log.Error("sandbox backend unavailable", "err", err)
		teardownResidents()
		teardownHoneypot()
		teardownFabric()
		os.Exit(1)
	}
	if err := startBox(ctx, box, log); err != nil {
		log.Error("sandbox bring-up", "err", err)
		teardownResidents()
		teardownHoneypot()
		teardownFabric()
		os.Exit(1)
	}

	// Synthetic inhabitants: real fleet when veil-net is up, Population bus-fake
	// otherwise. The two are mutually exclusive — never both.
	if fleet != nil {
		err := fleet.Up(ctx, bus, log)
		// Only residents that are up hold their address; any other may be the box's.
		classifier.SetNonSubject(fleet.TrustedIPs()...)
		if err != nil {
			// Every resident failed (e.g. veil-resident:dev not built), or the fleet
			// failed closed because a server has no static IPv4 (WorldNames was then
			// empty, so the resolver holds no resident names). Keep the dashboard
			// alive with the bus-fake, the same fallback used with no fabric.
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
	// capture is unavailable (non-Linux or insufficient privilege). Opened
	// synchronously so capture is attached before the subject's first command;
	// Run stops (and closes the handle) on ctx cancel.
	tapDone := startTap(ctx, *tapMode, bridge, bus, log)

	// The contained subject pokes at a fully-alive world (residents answering,
	// resolver bound, honeypot armed, tap attached), so its escape attempts get caught. Started
	// last; no teardown (execs are ephemeral).
	// A goal turns on the autonomous subject; otherwise the scripted -subject
	// file path (Slice 1) runs. If both are set, autonomous wins and the file is
	// skipped with an observable note.
	if *subjectGoal != "" {
		if *subjectFile != "" {
			e := events.New(events.KindSystem, "subject", "scripted skipped")
			e.Detail = "both -subject and -subject-goal set; running autonomous"
			bus.Publish(e)
		}
		maybeStartAutoSubject(ctx, box, *subjectGoal, *subjectBrain, *subjectSteps, 2*time.Second, bus, log)
	} else {
		maybeStartSubject(ctx, box, *subjectFile, 2*time.Second, bus, log)
	}

	// Live observation feed. Blocks until shutdown.
	warnIfObserverExposed(*listen, boxNet, gateway, log)
	server := viz.NewServer(*listen, bus, log, func() any { return scorer.Report() })
	runErr := server.Run(ctx)
	rep := scorer.Report()
	log.Info("escape score", "score", rep.Score, "stage", string(rep.Stage), "attempts", rep.Attempts)

	// Tear the world down on the way out — clean shutdown or viz failure alike —
	// so we don't leak a container. Bounded so a wedged daemon can't hang exit;
	// the Create-time reconcile covers crashes where this never runs.
	destroyBox(box, "sandbox destroy on shutdown", log)
	teardownResidents()
	teardownHoneypot()
	// Stop the tap (ctx is not yet cancelled on the viz-error path) and let it
	// close its AF_PACKET handle before the bridge it is bound to is removed.
	stop()
	waitTap(tapDone, 2*time.Second, log)
	teardownFabric()

	if runErr != nil {
		log.Error("viz", "err", runErr)
		os.Exit(1)
	}
	log.Info("shutdown complete")
}

// startBox creates and starts the box. If Start fails after a successful
// Create, the container already exists (and is attached to veil-net), so it is
// destroyed here before the error is returned — otherwise it leaks and the
// fabric teardown fails on its active endpoint. A failed Create leaves nothing
// to destroy. Cleanup runs on its own bounded ctx, since ctx may be the one that
// was cancelled mid-start.
func startBox(ctx context.Context, box sandbox.Sandbox, log *slog.Logger) error {
	if err := box.Create(ctx); err != nil {
		return fmt.Errorf("create: %w", err)
	}
	if err := box.Start(ctx); err != nil {
		destroyBox(box, "sandbox destroy after failed start", log)
		return fmt.Errorf("start: %w", err)
	}
	return nil
}

// destroyBox destroys the box on a fresh background ctx bounded to 10s, so a
// wedged daemon can't hang exit and a cancelled run ctx can't skip cleanup. A
// destroy error is logged under msg, never fatal: the caller is already exiting.
func destroyBox(box sandbox.Sandbox, msg string, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := box.Destroy(ctx); err != nil {
		log.Warn(msg, "err", err)
	}
}

// maybeStartSubject launches a scripted subject session against the box when
// -subject names a file. It requires the Execer capability (container backend);
// on the stub backend it publishes a KindSystem note and returns. It is never
// fatal — a missing/broken script must not take down the observation plane. The
// session rides ctx and holds no host resources, so it joins no teardown path.
func maybeStartSubject(ctx context.Context, box sandbox.Sandbox, file string, pace time.Duration, bus *events.Bus, log *slog.Logger) {
	if file == "" {
		return
	}
	skip := func(detail string) {
		e := events.New(events.KindSystem, "subject", "skipped")
		e.Detail = detail
		bus.Publish(e)
		log.Warn("subject harness skipped", "detail", detail)
	}

	ex, ok := box.(sandbox.Execer)
	if !ok {
		skip("subject harness needs the container backend")
		return
	}
	f, err := os.Open(file)
	if err != nil {
		skip("cannot open subject script: " + events.SafeField(err.Error(), 120))
		return
	}
	defer f.Close()
	cmds, err := subject.ParseScript(f)
	if err != nil {
		skip("cannot parse subject script: " + events.SafeField(err.Error(), 120))
		return
	}
	sess := subject.NewSession(ex, bus, log, pace)
	go sess.Run(ctx, cmds)
	log.Info("subject session started", "commands", len(cmds), "script", file)
}

// maybeStartAutoSubject launches an autonomous subject against the box when
// -subject-goal is set. It requires the Sheller capability (container backend);
// on the stub backend, an unset ANTHROPIC_API_KEY for the claude brain, or an
// OpenShell failure, it publishes a KindSystem note and returns. Never fatal —
// a broken subject must not take down the observation plane. The Autopilot
// closes the shell when the run ends, so there is no teardown path here.
func maybeStartAutoSubject(ctx context.Context, box sandbox.Sandbox, goal, brainKind string, steps int, pace time.Duration, bus *events.Bus, log *slog.Logger) {
	skip := func(detail string) {
		e := events.New(events.KindSystem, "subject", "auto skipped")
		e.Detail = detail
		bus.Publish(e)
		log.Warn("autonomous subject skipped", "detail", detail)
	}

	sh, ok := box.(sandbox.Sheller)
	if !ok {
		skip("autonomous subject needs the container backend")
		return
	}

	var brain subject.Brain
	switch brainKind {
	case "claude":
		key := os.Getenv("ANTHROPIC_API_KEY")
		if key == "" {
			skip("subject-brain=claude requires ANTHROPIC_API_KEY")
			return
		}
		brain = subject.NewClaudeBrain(key, os.Getenv("VEIL_SUBJECT_MODEL"))
	default: // "scripted"
		brain = subject.NewScriptedBrain()
	}

	shell, err := sh.OpenShell(ctx)
	if err != nil {
		skip("cannot open subject shell: " + events.SafeField(err.Error(), 120))
		return
	}
	go subject.NewAutopilot(brain, shell, bus, log, pace).Run(ctx, goal, steps)
	log.Info("autonomous subject started", "brain", brainKind, "goal", goal, "steps", steps)
}

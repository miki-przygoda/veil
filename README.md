# veil

A security research platform: a contained world a subject runs inside, observed
entirely from the outside, with everything that happens streamed live to a
dashboard.

The name is the model. From inside, the world is opaque — a subject (an AI agent
or a human) can't see past the veil and can't tell it's contained. From the host
side, the veil is transparent — every action and reaction is captured and shown.
**Outside-in, never inside-out.**

## What it's for

Standing up CTF-style scenarios and watching how subjects behave inside them —
including whether they try to break *out* of the box. Escape attempts are a
first-class, measured signal, which makes Veil as much an agent-evaluation
harness as a cyber-range.

## Three pillars

1. **Environment** — a contained world that's hard to escape and, ideally,
   indistinguishable from a real one (synthetic hosts, services, and background
   traffic).
2. **Observation** — a passive, host-side tap plus the world's own CA, so every
   action and reaction is logged without the subject being able to detect it.
3. **Visualisation** — a live feed of everything happening inside, for preview
   and demos.

## Quickstart

```sh
make run        # starts the daemon on http://localhost:8080
```

Open the dashboard and watch synthetic residents and tapped traffic stream in.

By default `veild` runs the **container** sandbox backend (needs a reachable
Docker daemon and the pinned `alpine:3.20@sha256:…` image it references (a fresh `docker pull alpine:3.20` that yields a newer digest will fail closed with a self-identifying error — pull the pinned digest or update `DefaultConfig`)).
`-backend=container` (the default) REQUIRES a reachable Docker daemon and fails
closed (veild exits) if it isn't — it never silently runs without containment.
`-backend=stub` is the explicit, dev-only mode and provides **zero isolation**.
Pick a backend with `-backend`:

```sh
go run ./cmd/veild -backend=stub        # no Docker needed (pipeline only)
go run ./cmd/veild -backend=container   # real hardened container on veil-net
```

When the container backend is up, the box joins an **internal** (no-egress)
`veil-net` Docker network, and `veild` runs a **packet tap** by default
(`-tap=packet`): on Linux it captures the world's real traffic off the `veil-net`
bridge and streams it as events; elsewhere (e.g. macOS Docker Desktop) it logs a
notice and falls back to the synthetic stub tap. Force it with `-tap=stub`. Real
capture is validated on Linux (`VEIL_PCAP_IT`).

`veild` also runs a **synthetic DNS resolver** on the `veil-net` gateway (it
answers world names like `web.veil.local`; unknown names are sinkholed to a
**transparent honeypot** rather than failing, so the world stays believable) and
a host-side **escape classifier** that emits `KindEscape`. Disable both with
`-resolver=off`.

Escape surfaces three ways, all derived host-side:

- `external-dns` — the subject resolves a non-world name (seen by the resolver);
- `egress-attempt` — the subject sends to an off-`veil-net` IP (seen by the tap);
- `honeypot-hit` — the subject connects to a sinkholed name and we capture the
  follow-through (seen by the transparent honeypot).

On an `internal` network a *successful* escape is impossible by construction, so
the **attempt is the signal**. The transparent honeypot needs `CAP_NET_ADMIN`
and is **Linux-only** (host-side `iptables` REDIRECT + `SO_ORIGINAL_DST`);
elsewhere it degrades off with an observable `KindSystem` event and escape
*detection* still runs. The live resolver + DNS escape path is validated on Linux
(`VEIL_DNS_IT`).

```sh
make build      # binaries -> bin/veild, bin/veil-agent, bin/veil-resident
make test       # run tests
make docker     # build the container image
```

### Residents (synthetic LAN hosts)

`cmd/veil-resident` is a stdlib-only guest binary that makes a container *be* a
believable host on `veil-net`: it serves probes (HTTP/SMTP/IMAP/SSH) and generates
ambient client traffic (DNS/HTTP/SMTP). It knows protocols, not topology — the
world roster (a later sub-project) assigns each resident its name, IP, and role via
flags. Run one by hand:

```sh
make resident-image
docker run --rm veil-resident:dev -serve=http:80,ssh:22 -hostname=web.veil.local
```

## Layout

```
cmd/veild        host-side control plane (the "outside")
cmd/veil-agent   guest-side agent that runs inside the box (the "inside")
internal/
  events         the Event type + in-memory pub/sub bus (the spine)
  sandbox        the contained world; isolation backend behind an interface
  netfabric      virtual network + passive host-side tap
  residents      synthetic inhabitants that make the world look alive
  viz            live SSE feed + dashboard backend
web/             dashboard frontend
deploy/          Dockerfile + compose
```

## Status

Early (`0.x`). The skeleton runs end to end; the isolation substrate
(containers vs. gVisor vs. Firecracker) is the next decision. Expect breaking
changes.

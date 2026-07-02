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
Docker daemon and a local `alpine:3.20` image). If Docker is unavailable it logs
a notice, emits a system event, and falls back to the stub. Pick a backend with
`-backend`:

```sh
go run ./cmd/veild -backend=stub        # no Docker needed (pipeline only)
go run ./cmd/veild -backend=container   # real hardened, no-network container
```

The tap is still a stub — it proves the observation pipeline end to end before
real host-side capture is wired in.

```sh
make build      # binaries -> bin/veild, bin/veil-agent
make test       # run tests
make docker     # build the container image
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

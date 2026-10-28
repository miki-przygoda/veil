# CLAUDE.md

Context for Claude Code working in this repo. This file is about *what Veil is
and the rules that keep it coherent* — not setup steps. Setup comes from the
prompt that sent you here.

## What Veil is

A security research platform built around one idea: a **contained world** that a
subject — an AI agent or a human — runs inside, observed entirely **from the
outside**. From inside, the world is opaque and (ideally) indistinguishable from
a real one. From the host side, everything is visible. The name is the model:
the veil is one-way glass.

Use cases: hosting CTF-style scenarios, defending a fake high-value target
(honeypot/wallet), and — the differentiator — measuring whether and how a
contained subject tries to **escape its box**. Escape attempts are a first-class
signal, not an error case.

## Invariants — do not violate these

These are the spine of the project. If a change would break one, stop and flag
it rather than proceeding.

1. **Outside-in, never inside-out.** Observation flows host → viewer only. The
   subject must never be able to detect the observer or push anything back out.
   The live feed is one-way (SSE) by design — don't make it bidirectional.
2. **Enforcement lives on the host.** Isolation and egress control are enforced
   outside the guest (virtual NIC / hypervisor boundary). Never put a security
   control *inside* the box — anything in the box is inside the threat model.
3. **The world is synthetic.** Believability comes from simulated hosts,
   services, and residents — not real people or real external services. Don't
   wire the sandbox to the public internet or to real third-party systems.
4. **Resettable to a known-clean state.** Every run starts identical;
   Snapshot/Reset erase the subject's traces.

## Architecture

Only the box and the resident containers run inside the world; everything else
runs host-side in `veild`. Data flows one way: world → host observers → `Bus` →
viewer.

- `events` — the `Event` type, the in-memory pub/sub `Bus`, and `SafeField`, the
  sanitiser every subject-controlled string passes through before it becomes an
  Event (tagged `[C1]` in comments). This is the spine; most packages depend on
  it and it depends on nothing.
- `docker` — a stdlib-only Docker Engine API client over the unix socket:
  containers, networks, exec, and a hijacked exec-attach with stream demux. The
  only package that speaks Docker.
- `sandbox` — the contained world behind the `Sandbox` interface. `Container` is
  the real backend: one hardened container (all caps dropped, no-new-privileges,
  read-only rootfs, non-root, resource caps), every control set at create time.
  `Stub` is the zero-isolation dev backend. Optional abilities are separate
  interfaces callers type-assert: `Execer` (one-shot exec) and `Sheller` (a
  persistent shell framed by a per-command nonce sentinel). Keep the interface honest so
  Firecracker can drop in later without touching callers.
- `netfabric` — the world's network and the host-side services around it: the
  internal `veil-net` (`Fabric`), the passive `Tap` (`PacketTap` on Linux,
  `StubTap` otherwise), the synthetic DNS `Resolver` (UDP and TCP on the
  gateway's :53, which the honeypot REDIRECT exempts while TCP is served), the
  transparent-honeypot `Sink`, and the `Classifier` — the single authority that turns observed facts
  into `KindEscape`. It drops facts sourced from the gateway (the host's own
  traffic) or a `Trusted` resident, which are never the subject's; an
  exploitable host such as an arena target must stay untrusted so a pivot
  through it still scores. None of it may be reachable from inside the box.
- `residents` — synthetic inhabitants (the "matrix" effect). `Fleet` runs the
  `DefaultRoster` as real `veil-resident` containers on `veil-net`;
  `Population` is the bus-only fallback when there's no fabric, every resident
  fails to start, or a server has no static IPv4 (the fleet fails closed).
- `subject` — drives the subject from outside the box. `Session` replays a
  script through one-shot execs; `Autopilot` asks a `Brain` (scripted, or Claude
  over the Anthropic API) for each next command and runs it in a persistent
  shell. A brain sees only its own command output, never the feed.
- `scoring` — a bus subscriber that grades escape attempts into a score, a
  verdict stage, and a command-attributed timeline (`GET /report`).
- `viz` — the one-way SSE feed (`/events`), `/report`, and the dashboard.
- `cmd/veild` — the host control plane that wires all of the above.
  `cmd/veil-resident` — the stdlib-only guest binary each resident runs.
  `cmd/veil-agent` — a deliberate placeholder: an in-box agent would need egress
  and would put subject logic inside the threat model.

## Conventions

- **One module, packages under `internal/`.** Not a Rust-style multi-crate
  workspace; not a `pkg/` directory (nothing here is a public library). Veil is a
  self-contained binary, so `internal/` is the right home for almost everything.
- **Standard library first.** `gopacket` (pure-Go AF_PACKET capture) is the only
  dependency so far; even the Docker client is hand-rolled on `net/http`. Add a
  dependency only when it earns its place (e.g. a Firecracker SDK for the
  substrate) and say why.
- **Interfaces where a real implementation will swap in** (sandbox, tap).
  Stub-first, then replace behind the interface.
- **Fail closed on containment, degrade observably elsewhere.** If the container
  backend can't reach Docker, `veild` exits; it never silently runs without
  isolation. Every other optional part (tap, resolver, honeypot, residents,
  subject) falls back and publishes a `KindSystem` event saying so.
- **Sanitise at the boundary.** Anything the subject controls (commands, output,
  DNS names, honeypot payloads) goes through `events.SafeField` before it reaches
  an Event. The dashboard also renders with `textContent` under a
  `default-src 'self'` CSP — defence in depth, not a substitute.
- **Small files, clear package boundaries, table-driven tests beside the code**
  (`internal/events/bus_test.go` is the pattern). Docker-facing code goes through
  a small unexported interface with a fake, so `go test ./...` needs no daemon.
  Live paths are integration tests gated by env vars (`VEIL_DOCKER_IT`,
  `VEIL_PCAP_IT`, `VEIL_DNS_IT`, `VEIL_RESIDENTS_IT`, `VEIL_SUBJECT_IT`,
  `VEIL_SUBJECT_CLAUDE_IT`), and most need a Linux host.
- **SemVer `0.x`** while the design moves; document breaking changes.
- **Go 1.22+** (uses `net/http` method routing and `log/slog`). Bump freely.

## Scope boundary

Veil is the *arena, the defense, the containment, and the measurement*.
Challenges are **deliberately-vulnerable target services** you stand up on
purpose (Juice-Shop / DVWA style) — not novel offensive exploits. Build the box
and the instrumentation; don't author weaponised attack payloads here.

## Current state

The escape loop works end to end on the container backend. On Linux, run as
root, `veild` brings up the hardened box on `veil-net`, the resident fleet, the
world resolver, the transparent honeypot, the packet tap, an optional scripted or
autonomous subject, and the escape scorer. All of it except the scorer and the
Claude brain has been validated live on a Linux host.

On macOS Docker Desktop the bridge and gateway live inside Docker's VM. The
resolver and packet tap can't attach, so they fall back, and escape detection
goes effectively dark. macOS is fine for pipeline work but not for measuring
escapes.

Known limits worth keeping in mind:

- `egress-attempt` almost never fires. On an internal network the box has no
  default route, so an off-subnet send fails inside the box (`Network
  unreachable`) before the tap can see it. `external-dns` and `honeypot-hit` are
  the vectors that reliably light up.
- The honeypot is fingerprintable (every external name resolves to the gateway,
  and every other gateway TCP port answers with the same banner). The real fix is the Firecracker substrate.
- With the world resolver down (bind failure or `-resolver=off`) on a patched
  engine, the box's DNS stays on `127.0.0.11` inside its netns, so
  `external-dns` goes dark (a `KindSystem` event says so).
- The `Bus` has no replay, so a viewer that connects late misses earlier events.

Next up is the **arena**: a deliberately vulnerable target and a lootable goal
inside the world. Firecracker microVMs remain the endgame substrate behind the
same `Sandbox` interface.

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

- `events` — the `Event` type and an in-memory pub/sub `Bus`. Everything
  surfaced from the host becomes an Event and flows through the Bus. This is the
  spine; most packages depend on it and it depends on nothing.
- `sandbox` — the contained world behind a `Sandbox` interface. The isolation
  backend (container / gVisor / Firecracker) is a **deferred decision**; today
  there's only `Stub`. Keep the interface honest so the real backend drops in
  without touching callers.
- `netfabric` — the virtual network and the passive `Tap`. The tap is host-side
  and must never be reachable from inside.
- `residents` — synthetic inhabitants emitting background traffic (the "matrix"
  effect). Cheap goroutines; the safe way to make the world look alive.
- `viz` — the live SSE feed and dashboard backend.
- `cmd/veild` — host control plane (the outside). `cmd/veil-agent` — guest-side
  agent (the inside); a stub for now.

## Conventions

- **One module, packages under `internal/`.** Not a Rust-style multi-crate
  workspace; not a `pkg/` directory (nothing here is a public library). Veil is a
  self-contained binary, so `internal/` is the right home for almost everything.
- **Standard library first.** The spine is stdlib-only. Add a dependency only
  when it earns its place (e.g. `gopacket` for real capture, a Firecracker SDK
  for the substrate) and say why.
- **Interfaces where a real implementation will swap in** (sandbox, tap).
  Stub-first, then replace behind the interface.
- **Small files, clear package boundaries, table-driven tests beside the code**
  (`internal/events/bus_test.go` is the pattern).
- **SemVer `0.x`** while the design moves; document breaking changes.
- **Go 1.22+** (uses `net/http` method routing and `log/slog`). Bump freely.

## Scope boundary

Veil is the *arena, the defense, the containment, and the measurement*.
Challenges are **deliberately-vulnerable target services** you stand up on
purpose (Juice-Shop / DVWA style) — not novel offensive exploits. Build the box
and the instrumentation; don't author weaponised attack payloads here.

## Current state

The skeleton runs end to end: `make run` → synthetic residents + a stub tap
publish to the bus → the dashboard at `:8080` renders the live feed. The next
real work is the **isolation substrate** in `sandbox` (containers to move fast,
or Firecracker microVMs for a genuinely undetectable/inescapable boundary), then
replacing the stub tap in `netfabric` with real host-side capture.

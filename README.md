# fuzzy-fanet

A lightweight **fuzzy-logic routing core** for drone swarms (FANET), small
enough to run on a microcontroller. Built from a master's thesis on secure
Fuzzy-AODV routing; this repo turns the MATLAB research model into portable,
embeddable C.

## Why

Classic AODV picks routes by hop count and trusts the first reply it sees. In a
flying ad-hoc network that means unstable links, wasted battery, and an open
door to Black Hole attacks. This core scores each candidate next-hop with a
**Mamdani fuzzy controller** over three normalized metrics:

- **NRE** — normalized residual energy
- **NS** — normalized stability (inverse of relative speed)
- **ND** — normalized delay (derived from SNR)

...and returns a single `RouteScore ∈ [0,1]`. The routing layer forwards only
through nodes that clear a reliability threshold, so it builds shorter, more
stable, harder-to-attack routes.

## What's here now

**Fuzzy core** (`src/fuzzy_fanet.{c,h}`) — the controller. Portable C99, zero
dependencies, no malloc, no global state (fully reentrant), ~1.2 KB of code.
Membership functions and all 27 rules transcribed directly from the original
`FANET_Routing.fis`, so on-device decisions match the research model.

**Routing layer** (`src/fanet_routing.{c,h}`) — Fuzzy-AODV ported from the
MATLAB `RoutingProtocol.m`: RREQ flooding, per-node metric normalization,
fuzzy reliability scoring, the 0.4 forwarding gate, loop/duplicate protection,
TTL, a Black Hole trust filter, **RREP** (the destination replies the route
back, and every hop builds a `dst -> next hop` table), and **DATA** forwarding
along that table with PDR accounting. Talks only to a transport interface, so
the same code runs over the PC sim today and ESP-NOW / LoRa later.

**Trust manager** (`src/fanet_trust.{c,h}`) — behavioural Black Hole detection.
Tracks, per neighbour, how many packets it was entrusted with versus how many
it was actually overheard forwarding, smooths that into a reputation, and
watchlists then blacklists nodes that swallow traffic. No node is ever told
who the attackers are — it works it out. Portable C99, no allocation.

**Transport seam** (`src/fanet_transport.h`) — the one interface that lets the
radio backend be swapped without touching routing.

**PC simulation** (`sim/`) — an in-memory virtual network (queue-based flood,
soft-step link loss model from the thesis) that runs the real routing code
with no hardware. Reproduces the headline experiment: Standard vs Fuzzy AODV
under a Black Hole attack.

**Tests** (`test/`) — desktop harness verifying the fuzzy core against the
MATLAB `evalfis` reference (e.g. R25: 0.92/0.88/0.12 → ~0.90).

## Build & run (desktop, no hardware)

```sh
make test    # unit-test the fuzzy core and the trust manager
make sim     # run the Standard vs Fuzzy Black Hole experiment
```

> **Windows:** build from PowerShell (with MSYS2 `make`/`gcc` in PATH), not
> Git Bash — MSYS2 make conflicts with Git Bash's own `msys-2.0.dll`.

Example simulation output (50 nodes, ~15% Black Holes, source & destination in
opposite corners):

```
=== STANDARD AODV (blind) ===
  round 1: 0 -> 27(!) -> 21 -> 3 -> 8 -> 9(!) -> 28 -> 4 -> 49
           attackers on path: 2 | PDR 0%
           blind AODV cannot learn: it will keep feeding the attacker forever.

=== FUZZY AODV (trust filter) ===
  round 1: 0 -> 27(!) -> 21 -> 3 -> 8 -> 9(!) -> 28 -> 4 -> 49
           attackers on path: 2 | PDR 0% | blacklisted so far: 1
  round 2: 0 -> 31 -> 21 -> 3 -> 18 -> 9(!) -> 14 -> 4 -> 49
           attackers on path: 1 | PDR 0% | blacklisted so far: 2
  round 3: 0 -> 31 -> 5 -> 15 -> 29 -> 34 -> 41 -> 4 -> 49
           attackers on path: 0 | PDR 87% | blacklisted so far: 2
           CONVERGED - route is clean, data flowing.
  detection: 2/6 attackers unmasked purely by watching who failed to forward
             | no honest node was wrongly accused
```

`(!)` marks a Black Hole. Read the Fuzzy run as a story: the first route runs
straight through two attackers and loses everything — **detection is reactive,
not clairvoyant**. But the network watches, learns, and reroutes. By round 3
the path is clean and data flows.

**Nobody ever tells a node who the attackers are.** Each blacklist entry is
earned: *"I handed you 100 packets and never once heard you relay them."*

Note the honest numbers: only 2 of 6 attackers are unmasked, because the other
4 were never on a route and therefore never stole anything. There is nothing
to convict them of yet. A detector that magically flagged all 6 would be
lying.

## How the attacker is caught

Radio is a broadcast medium, so a node can overhear whether the neighbour it
just trusted actually relayed the packet. That gives direct trust:

```
T_direct = packets I overheard it forward / packets I entrusted to it
```

A Black Hole accepts everything and relays nothing, so its score collapses and
it is blacklisted, then cut off entirely — the node refuses to even route
requests through it (MAC-level isolation).

Two details keep this honest rather than trigger-happy:

- **Exponential smoothing** (α = 0.7): accumulated reputation outweighs any
  single observation, so an honest relay that loses a packet to a radio fade
  is forgiven. Verified in `test/test_trust.c`: a node forwarding 90% of
  traffic keeps a trust of ~0.89 and is never blacklisted.
- **Evidence threshold**: a neighbour must have been entrusted with several
  packets before it can be condemned. One missed packet convicts nobody.

The result: 0 false accusations in the run above.

## Use the fuzzy core directly

```c
#include "fuzzy_fanet.h"

float score = ff_route_score(nre, ns, nd);   /* all inputs 0..1 */
if (score >= 0.4f) {
    /* forward RREQ through this node */
}
```

## Architecture

```
app / demo         (PC sim today; ESP32-C3 sketch later)
transport adapter  (vnet on PC  ->  ESP-NOW / LoRa on hardware)   <- swap point
routing (AODV)     RREQ/RREP/DATA, routing table              [portable C]
trust manager      earned reputation, blacklist, isolation    [portable C]
fuzzy core         NRE/NS/ND -> RouteScore                    [portable C]
```

The golden rule: **the core never knows about the radio.** That is why the
exact same routing and fuzzy code that passes the PC simulation will run on
the microcontroller — only the transport file changes.

## Roadmap

The fuzzy brain and a working Fuzzy-AODV routing layer run in a PC simulation.
Still to do:

- [x] Portable fuzzy core (matches MATLAB FIS)
- [x] Fuzzy-AODV routing layer in C (RREQ flood, threshold, trust filter)
- [x] PC virtual network + Black Hole experiment
- [x] **RREP**: the destination replies the discovered route back to the
      source; every hop builds a routing table (dst -> next hop), so the
      source knows who to send data to. Unicast RREP is modelled as reliable
      (link-layer ACK), broadcast RREQ as lossy.
- [x] **DATA packets**: payload is forwarded hop-by-hop along the routing
      table the RREP built, and end-to-end delivery (PDR) is measured. A
      Black Hole now actually bites: it silently swallows every payload it is
      trusted to forward.
- [x] **Real TrustManager**: direct trust earned from observed forwarding
      behaviour, exponential smoothing, watchlist → blacklist, and MAC-level
      isolation of proven attackers. The ground-truth sentinel is gone: the
      protocol no longer knows who is malicious, it finds out.
      *(The thesis described this; the original MATLAB code never implemented
      it — it just checked an `IsMalicious` flag.)*
- [ ] **ESP32-C3 target**: flash the core, broadcast HELLO with live metrics
      over the radio (ESP-NOW first, LoRa later).
- [ ] **Async simulation**: per-node timers / event loop instead of the
      synchronous flood, to mirror real radio timing.
- [ ] **Multi-hop swarm demo** on 3–5 boards + a short capture/video.
- [ ] **Benchmarks**: decision latency, RAM, and how many RREQ broadcasts the
      fuzzy filter saves vs. vanilla AODV (the LoRa duty-cycle argument).

### Deliberately not implemented

The thesis also specifies indirect trust (reputation gossip between
neighbours), ALARM broadcast packets, digital signatures, and a quarantine /
rehabilitation cycle. Those are left out on purpose: they add substantial
protocol surface and state for modest benefit at this scale, and indirect
trust opens its own attack surface (bad-mouthing). Direct trust alone already
identifies and isolates the attackers. Better an honest small system than a
large one that only exists in the README.

## Origin & honesty note

Ported from a MATLAB simulation. The thesis describes a fuller trust/security
system than the original code implemented; closing that gap is the main point
of this project, and the roadmap reflects what is real vs. planned.

## License

MIT

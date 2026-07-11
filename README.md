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
make test    # unit-test the fuzzy core
make sim     # run the Standard vs Fuzzy Black Hole experiment
```

Example simulation output (50 nodes, ~15% Black Holes, source & destination in
opposite corners):

```
=== STANDARD AODV (blind) ===
  path: 0 -> 27(!) -> 21 -> 3 -> 8 -> 9(!) -> 28 -> 4 -> 49
  hops: 8 | attackers in route: 2   <<< BLACK HOLE IN PATH
  data: sent 100 | delivered 0 | PDR 0.0%
  losses: 97 swallowed by attackers | 3 lost on radio

=== FUZZY AODV (trust filter) ===
  path: 0 -> 44 -> 7 -> 15 -> 29 -> 6 -> 25 -> 4 -> 49
  hops: 8 | attackers in route: 0   <<< route clean
  data: sent 100 | delivered 88 | PDR 88.0%
  losses: 0 swallowed by attackers | 12 lost on radio
```

`(!)` marks a Black Hole. Standard AODV is lured through two attackers, and
its very first hop swallows the traffic — **not a single payload arrives**.
Fuzzy-AODV filters them out during discovery, so the route carries data: the
only losses left are ordinary radio fades across 8 hops, not malice.

That split matters. The protocol does not claim to beat physics — it claims
to remove the attacker. The loss breakdown makes the difference explicit.

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
routing (AODV)     RREQ/RREP, trust filter, threshold        [portable C]
fuzzy core         NRE/NS/ND -> RouteScore                    [portable C] DONE
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
- [ ] **Real TrustManager**: direct trust from observed behaviour — count how
      many payloads a neighbour was given versus how many it actually
      forwarded, decay its reputation, watchlist, then blacklist. This
      replaces the sim's ground-truth sentinel with genuine detection.
      *(Described in the thesis; never implemented in the original code,
      which only had an `IsMalicious` flag.)*
- [ ] **ESP32-C3 target**: flash the core, broadcast HELLO with live metrics
      over the radio (ESP-NOW first, LoRa later).
- [ ] **Async simulation**: per-node timers / event loop instead of the
      synchronous flood, to mirror real radio timing.
- [ ] **Multi-hop swarm demo** on 3–5 boards + a short capture/video.
- [ ] **Benchmarks**: decision latency, RAM, and how many RREQ broadcasts the
      fuzzy filter saves vs. vanilla AODV (the LoRa duty-cycle argument).

## Origin & honesty note

Ported from a MATLAB simulation. The thesis describes a fuller trust/security
system than the original code implemented; closing that gap is the main point
of this project, and the roadmap reflects what is real vs. planned.

## License

MIT

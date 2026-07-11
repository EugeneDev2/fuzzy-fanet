/*
 * fanet_routing.h - Fuzzy-AODV routing layer.
 *
 * Ports the logic from the MATLAB RoutingProtocol.m onto portable C:
 * RREQ flooding with per-node fuzzy reliability scoring, a forwarding
 * threshold, loop/duplicate protection, TTL, and an optional Black Hole
 * trust filter.
 */
#ifndef FANET_ROUTING_H
#define FANET_ROUTING_H

#include "fanet_types.h"
#include "fanet_transport.h"
#include "fanet_trust.h"

/* Forwarding threshold: a node relays an RREQ only if the sender's fuzzy
 * RouteScore is at least this. Matches the 0.4 gate in RoutingProtocol.m. */
#define FANET_FORWARD_THRESHOLD 0.4f

/* Mode selects whether the trust/security filter is active. */
typedef enum {
    MODE_STANDARD = 0,  /* blind AODV: forwards regardless of trust */
    MODE_FUZZY    = 1   /* fuzzy scoring + Black Hole trust filter */
} fanet_mode_t;

/* Remembered request ids, to drop duplicates and break loops. */
#define FANET_REQ_CACHE 32

/* Routing table size: how many destinations a node can remember a next-hop
 * for. Small, since this targets microcontrollers. */
#define FANET_ROUTE_TABLE 16

/*
 * One routing table entry: to reach `dst`, send to `next_hop`. Populated as
 * an RREP travels back toward the source; this is what a node consults to
 * forward DATA packets later.
 */
typedef struct {
    uint8_t dst;        /* final destination id */
    uint8_t next_hop;   /* neighbor to forward to */
    uint8_t hops;       /* distance to dst (for tie-breaking) */
    uint8_t valid;      /* entry in use? */
} fanet_route_t;

typedef struct fanet_node {
    uint8_t id;
    float   x, y;                 /* position (meters) */
    fanet_metrics_t metrics;      /* this node's own raw metrics */
    uint8_t is_malicious;         /* Black Hole node? (ground truth) */

    fanet_mode_t mode;
    fanet_transport_t *transport;

    uint16_t seen_reqs[FANET_REQ_CACHE];
    uint8_t  seen_count;

    /*
     * Reverse-path memory: while an RREQ floods forward, each node records
     * who it should send an RREP back to for a given request id. Keyed by
     * req_id so concurrent discoveries don't collide.
     */
    uint16_t rev_req[FANET_REQ_CACHE];   /* req_id */
    uint8_t  rev_prev[FANET_REQ_CACHE];  /* previous hop for that req_id */
    uint8_t  rev_count;

    /* Routing table: dst -> next_hop, filled by RREP on the way back. */
    fanet_route_t routes[FANET_ROUTE_TABLE];

    /* result capture: when this node is the source and the RREP arrives,
     * the full discovered path is copied here and route_complete is set. */
    uint8_t  found_path[FANET_MAX_PATH];
    uint8_t  found_len;
    uint8_t  route_complete;

    /* --- DATA statistics (for PDR) --- */
    uint16_t data_sent;      /* payloads this node originated */
    uint16_t data_received;  /* payloads that arrived here as final dest */
    uint16_t data_dropped;   /* payloads this node deliberately swallowed
                              * (Black Hole) or had to discard (no route) */

    /* --- reputation of neighbours, learned from their behaviour --- */
    fanet_trust_t trust;

    /* The packet we most recently handed to a neighbour and are now waiting
     * to overhear it relay. Identified by (peer, dst, seq) so that only a
     * genuine forward of THAT packet counts as evidence of good behaviour. */
    uint8_t  pending_peer;   /* FANET_INVALID_ID when nothing is pending */
    uint8_t  pending_dst;
    uint16_t pending_seq;
} fanet_node_t;

/* Initialize a node. */
void fanet_node_init(fanet_node_t *n, uint8_t id, float x, float y,
                     fanet_mode_t mode, fanet_transport_t *transport);

/* Set this node's raw metrics (battery/speed/SNR). */
void fanet_node_set_metrics(fanet_node_t *n, fanet_metrics_t m);

/*
 * Entry point called by the transport when a packet arrives at this node.
 * Drives the whole RREQ/RREP state machine.
 */
void fanet_node_on_receive(fanet_node_t *n, const fanet_packet_t *pkt);

/*
 * Initiate a route discovery from this node toward `dst`: builds and
 * broadcasts the RREQ. In an async model (sim queue or real radio) the
 * flood resolves later; the caller drives delivery and then reads
 * n->route_complete / n->found_path.
 */
void fanet_start_discovery(fanet_node_t *n, uint8_t dst);

/* Reset the duplicate cache (call before each fresh discovery in the sim). */
void fanet_node_reset_cache(fanet_node_t *n);

/*
 * Look up the next hop toward `dst` in this node's routing table.
 * Returns the next-hop id, or FANET_INVALID_ID if no route is known.
 * This is what a DATA packet would consult to move one hop closer.
 */
uint8_t fanet_next_hop(const fanet_node_t *n, uint8_t dst);

/*
 * Send a DATA payload toward `dst`, using the routing table built by the
 * RREP. Returns 1 if the packet was handed to the transport, 0 if no route
 * is known (fail-safe: nothing is sent into the dark).
 *
 * The payload is copied; `len` is clamped to FANET_PAYLOAD.
 */
int fanet_send_data(fanet_node_t *n, uint8_t dst,
                    const uint8_t *payload, uint8_t len, uint16_t seq);

/*
 * Promiscuous overhear hook.
 *
 * Radio is a broadcast medium: when a neighbour transmits, everyone in range
 * hears it, whether or not they are the addressee. The transport calls this
 * on every node within earshot of a transmission, so a node can verify that
 * a neighbour it trusted actually re-transmitted the packet it was given.
 *
 * This is what turns trust from a hardcoded flag into something OBSERVED.
 * A Black Hole is caught because the silence after it is heard.
 */
void fanet_node_on_overhear(fanet_node_t *listener,
                            uint8_t transmitter,
                            const fanet_packet_t *pkt);

#endif /* FANET_ROUTING_H */

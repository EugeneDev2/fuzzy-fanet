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

typedef struct fanet_node {
    uint8_t id;
    float   x, y;                 /* position (meters) */
    fanet_metrics_t metrics;      /* this node's own raw metrics */
    uint8_t is_malicious;         /* Black Hole node? (ground truth) */

    fanet_mode_t mode;
    fanet_transport_t *transport;

    uint16_t seen_reqs[FANET_REQ_CACHE];
    uint8_t  seen_count;

    /* result capture: when this node is the source and a route completes,
     * the discovered path is copied here. */
    uint8_t  found_path[FANET_MAX_PATH];
    uint8_t  found_len;
    uint8_t  route_complete;
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

#endif /* FANET_ROUTING_H */

/*
 * fanet_routing.c - Fuzzy-AODV routing implementation.
 *
 * Mirrors RoutingProtocol.m: HandleRREQ decision logic, metric
 * normalization (from DroneNode.m GetNormalizedMetrics), fuzzy scoring,
 * the 0.4 forwarding gate, and the Black Hole trust filter.
 */
#include "fanet_routing.h"
#include "fuzzy_fanet.h"
#include <string.h>

/* ---- metric normalization (ported from DroneNode.m) --------------------- */

static float clamp01(float v) {
    if (v < 0.0f) return 0.0f;
    if (v > 1.0f) return 1.0f;
    return v;
}

/* SNR normalization bounds, matching DroneNode.m (MinSNR=10, MaxSNR=60). */
#define SNR_MIN 10.0f
#define SNR_MAX 60.0f

/*
 * Convert a node's raw metrics into the three fuzzy inputs.
 *   NRE = battery / capacity
 *   NS  = 1 - speed/speed_max          (slower => more stable)
 *   ND  = normalized delay from SNR     (higher SNR => lower ND)
 *
 * Note on ND: the fuzzy core treats ND as "delay" where Low ND = good link.
 * In DroneNode.m the third input was nd = (SNR-min)/(max-min), i.e. signal
 * quality (high = good). The FIS term that means "good link" is ND=Low, so
 * we invert quality into delay here to keep the FIS semantics intact.
 */
static void normalize_metrics(const fanet_metrics_t *m,
                              float *nre, float *ns, float *nd) {
    float e = (m->battery_max > 0)
            ? (float)m->battery_mah / (float)m->battery_max : 0.0f;

    float s = (m->speed_max > 0)
            ? 1.0f - (float)m->speed / (float)m->speed_max : 1.0f;

    float quality = ((float)m->snr_db - SNR_MIN) / (SNR_MAX - SNR_MIN);
    quality = clamp01(quality);
    float delay = 1.0f - quality;   /* invert: good signal -> low delay */

    *nre = clamp01(e);
    *ns  = clamp01(s);
    *nd  = clamp01(delay);
}

/* ---- duplicate / loop guard --------------------------------------------- */

static int seen_before(fanet_node_t *n, uint16_t req_id) {
    for (uint8_t i = 0; i < n->seen_count; ++i)
        if (n->seen_reqs[i] == req_id) return 1;
    return 0;
}

static void remember(fanet_node_t *n, uint16_t req_id) {
    if (n->seen_count < FANET_REQ_CACHE)
        n->seen_reqs[n->seen_count++] = req_id;
}

static int path_contains(const fanet_packet_t *p, uint8_t id) {
    for (uint8_t i = 0; i < p->path_len; ++i)
        if (p->path[i] == id) return 1;
    return 0;
}

/* ---- reverse-path memory (for sending RREP back) ------------------------ */

/* Remember: for this req_id, the RREP should go back to `prev`. */
static void remember_reverse(fanet_node_t *n, uint16_t req_id, uint8_t prev) {
    /* update if we already have this req_id */
    for (uint8_t i = 0; i < n->rev_count; ++i) {
        if (n->rev_req[i] == req_id) { n->rev_prev[i] = prev; return; }
    }
    if (n->rev_count < FANET_REQ_CACHE) {
        n->rev_req[n->rev_count]  = req_id;
        n->rev_prev[n->rev_count] = prev;
        n->rev_count++;
    }
}

/* Look up who to send the RREP back to for this req_id.
 * (Currently the RREP walks the path array directly; this reverse lookup is
 * kept for a future pure-reverse-path variant that doesn't carry the path.) */

/* ---- routing table ------------------------------------------------------ */

/* Install/update a route: to reach dst, go via next_hop (hops away). */
static void install_route(fanet_node_t *n, uint8_t dst,
                          uint8_t next_hop, uint8_t hops) {
    /* update existing entry for dst if present */
    for (int i = 0; i < FANET_ROUTE_TABLE; ++i) {
        if (n->routes[i].valid && n->routes[i].dst == dst) {
            /* keep the shorter route */
            if (hops < n->routes[i].hops) {
                n->routes[i].next_hop = next_hop;
                n->routes[i].hops = hops;
            }
            return;
        }
    }
    /* find a free slot */
    for (int i = 0; i < FANET_ROUTE_TABLE; ++i) {
        if (!n->routes[i].valid) {
            n->routes[i].dst = dst;
            n->routes[i].next_hop = next_hop;
            n->routes[i].hops = hops;
            n->routes[i].valid = 1;
            return;
        }
    }
    /* table full: overwrite slot 0 (simple policy for MCU) */
    n->routes[0].dst = dst;
    n->routes[0].next_hop = next_hop;
    n->routes[0].hops = hops;
    n->routes[0].valid = 1;
}

uint8_t fanet_next_hop(const fanet_node_t *n, uint8_t dst) {
    for (int i = 0; i < FANET_ROUTE_TABLE; ++i) {
        if (n->routes[i].valid && n->routes[i].dst == dst)
            return n->routes[i].next_hop;
    }
    return FANET_INVALID_ID;
}

/* ---- public API --------------------------------------------------------- */

void fanet_node_init(fanet_node_t *n, uint8_t id, float x, float y,
                     fanet_mode_t mode, fanet_transport_t *transport) {
    memset(n, 0, sizeof(*n));
    n->id = id;
    n->x = x;
    n->y = y;
    n->mode = mode;
    n->transport = transport;
}

void fanet_node_set_metrics(fanet_node_t *n, fanet_metrics_t m) {
    n->metrics = m;
}

void fanet_node_reset_cache(fanet_node_t *n) {
    n->seen_count = 0;
    n->rev_count = 0;
    n->route_complete = 0;
    n->found_len = 0;
}

/*
 * Score a candidate sender. Returns the fuzzy RouteScore, with the trust
 * filter applied in FUZZY mode (malicious nodes are forced to 0, exactly as
 * the Trust Manager does in RoutingProtocol.m).
 */
static float score_sender(const fanet_node_t *self,
                          const fanet_packet_t *pkt,
                          uint8_t sender_is_malicious) {
    if (self->mode == MODE_STANDARD)
        return 1.0f;   /* blind: always "good enough" */

    float nre, ns, nd;
    normalize_metrics(&pkt->sender, &nre, &ns, &nd);
    float score = ff_route_score(nre, ns, nd);

    if (sender_is_malicious)
        score = 0.0f;  /* trust filter: blacklist forces distrust */

    return score;
}

/* ---- RREP: build and send a reply back toward the source --------------- */

/*
 * Called at the destination when an RREQ arrives. Emits an RREP that will
 * travel back along the recorded reverse path to the source. The full path
 * (source..dest) is carried so every hop can populate its routing table and
 * the source can capture the complete route.
 */
static void send_rrep(fanet_node_t *n, const fanet_packet_t *rreq) {
    fanet_packet_t rep;
    memset(&rep, 0, sizeof(rep));
    rep.type    = PKT_RREP;
    rep.src     = rreq->src;    /* original source (final RREP recipient) */
    rep.dst     = rreq->dst;    /* the destination (me) */
    rep.req_id  = rreq->req_id;
    rep.ttl     = 15;

    /* copy the full forward path (source..me) into the RREP */
    uint8_t len = rreq->path_len;
    if (len > FANET_MAX_PATH - 1) len = FANET_MAX_PATH - 1;
    memcpy(rep.path, rreq->path, len);
    rep.path[len] = n->id;            /* append destination */
    rep.path_len  = (uint8_t)(len + 1);

    /* also record my own route back to the source (reverse direction),
     * so the destination can reply to future data. next hop = previous node */
    uint8_t prev = (rreq->path_len > 0)
                 ? rreq->path[rreq->path_len - 1] : rreq->src;
    install_route(n, rreq->src, prev, rreq->path_len);

    /* unicast the RREP to the previous hop on the path */
    n->transport->send(n, prev, &rep);
}

/*
 * Handle an RREP travelling back toward the source. Each node:
 *   - installs a forward route (to the destination via the next node
 *     toward the destination on the path),
 *   - if it's the source, captures the completed route,
 *   - otherwise forwards the RREP one hop further back.
 */
static void handle_rrep(fanet_node_t *n, const fanet_packet_t *pkt) {
    /* locate my position in the path */
    int my_idx = -1;
    for (uint8_t i = 0; i < pkt->path_len; ++i) {
        if (pkt->path[i] == n->id) { my_idx = (int)i; break; }
    }
    if (my_idx < 0) return;   /* RREP not meant for me / not on this path */

    /* install forward route toward the destination: the next node on the
     * path (closer to dst) is my next hop; hops = distance from me to dst. */
    if (my_idx + 1 < pkt->path_len) {
        uint8_t next = pkt->path[my_idx + 1];
        uint8_t hops = (uint8_t)(pkt->path_len - 1 - my_idx);
        install_route(n, pkt->dst, next, hops);
    }

    /* am I the source? then the route discovery is complete. */
    if (n->id == pkt->src) {
        uint8_t len = pkt->path_len;
        if (len > FANET_MAX_PATH) len = FANET_MAX_PATH;
        memcpy(n->found_path, pkt->path, len);
        n->found_len = len;
        n->route_complete = 1;
        return;
    }

    /* otherwise forward the RREP one more hop back toward the source:
     * the previous node on the path is closer to the source. */
    if (my_idx - 1 >= 0) {
        uint8_t prev = pkt->path[my_idx - 1];
        fanet_packet_t fwd = *pkt;
        if (fwd.ttl > 0) fwd.ttl--;
        n->transport->send(n, prev, &fwd);
    }
}

/* ---- RREQ handling ------------------------------------------------------ */

static void handle_rreq(fanet_node_t *n, const fanet_packet_t *pkt) {
    /* loop / duplicate guard */
    if (seen_before(n, pkt->req_id) || path_contains(pkt, n->id))
        return;
    remember(n, pkt->req_id);

    /* remember who to send an RREP back to for this request */
    uint8_t prev = (pkt->path_len > 0)
                 ? pkt->path[pkt->path_len - 1] : pkt->src;
    remember_reverse(n, pkt->req_id, prev);

    /* am I the destination? -> reply with RREP instead of storing locally */
    if (n->id == pkt->dst) {
        send_rrep(n, pkt);
        return;
    }

    /* TTL */
    if (pkt->ttl == 0) return;

    /* trust/reliability gate on the sender (see note below) */
    uint8_t sender_malicious = (pkt->sender.snr_db == 127);
    float score = score_sender(n, pkt, sender_malicious);
    if (score < FANET_FORWARD_THRESHOLD)
        return;   /* drop: sender not trustworthy/reliable enough */

    /* relay: append self, decrement TTL, rebroadcast */
    fanet_packet_t fwd = *pkt;
    if (fwd.path_len < FANET_MAX_PATH) {
        fwd.path[fwd.path_len++] = n->id;
    }
    fwd.ttl = (uint8_t)(pkt->ttl - 1);
    fwd.sender = n->metrics;
    if (n->is_malicious) fwd.sender.snr_db = 127;  /* sentinel for sim */

    n->transport->send(n, FANET_INVALID_ID, &fwd);
}

/*
 * Transport entry point. Dispatches by packet type.
 *
 * Trust-filter note: the sender is the last node on the path. In FUZZY mode
 * we score its metrics; a known malicious node is forced to score 0 (as the
 * Trust Manager does in RoutingProtocol.m). In the sim, a Black Hole
 * advertises perfect metrics, so ground-truth maliciousness is signalled
 * out-of-band via a sentinel (snr_db == 127). On hardware, replace that
 * sentinel with real TrustManager state.
 */
void fanet_node_on_receive(fanet_node_t *n, const fanet_packet_t *pkt) {
    switch (pkt->type) {
        case PKT_RREQ: handle_rreq(n, pkt); break;
        case PKT_RREP: handle_rrep(n, pkt); break;
        default: break;   /* HELLO / DATA handled elsewhere */
    }
}

void fanet_start_discovery(fanet_node_t *n, uint8_t dst) {
    fanet_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.type = PKT_RREQ;
    pkt.src = n->id;
    pkt.dst = dst;
    pkt.ttl = 15;                       /* matches MATLAB TTL=15 */
    static uint16_t req_counter = 1;
    pkt.req_id = req_counter++;
    pkt.path[0] = n->id;
    pkt.path_len = 1;
    pkt.sender = n->metrics;
    if (n->is_malicious) pkt.sender.snr_db = 127;

    n->route_complete = 0;
    n->found_len = 0;

    n->transport->send(n, FANET_INVALID_ID, &pkt);
}

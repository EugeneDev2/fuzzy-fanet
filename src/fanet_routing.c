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

void fanet_node_on_receive(fanet_node_t *n, const fanet_packet_t *pkt) {
    /* --- loop / duplicate guard --- */
    if (seen_before(n, pkt->req_id) || path_contains(pkt, n->id))
        return;
    remember(n, pkt->req_id);

    /* --- am I the destination? --- */
    if (n->id == pkt->dst) {
        /* record the full path: existing path + me */
        uint8_t len = pkt->path_len;
        if (len > FANET_MAX_PATH - 1) len = FANET_MAX_PATH - 1;
        memcpy(n->found_path, pkt->path, len);
        n->found_path[len] = n->id;
        n->found_len = (uint8_t)(len + 1);
        n->route_complete = 1;
        return;
    }

    /* --- TTL --- */
    if (pkt->ttl == 0) return;

    /* --- decide whether to forward, based on the SENDER's trust ---
     * The sender is the last node on the path. In FUZZY mode we score the
     * sender's metrics and additionally apply a trust filter: a known
     * malicious node is forced to score 0 (as the Trust Manager does in
     * RoutingProtocol.m).
     *
     * Sim detail: a Black Hole advertises perfect metrics, so fuzzy scoring
     * alone can't catch it. The virtual network signals ground-truth
     * maliciousness out-of-band via a sentinel (snr_db == 127) that a real
     * trust/reputation system would replace with actual behavioral evidence.
     * On hardware, swap this sentinel check for real TrustManager state. */
    uint8_t sender_malicious = (pkt->sender.snr_db == 127);

    float score = score_sender(n, pkt, sender_malicious);
    if (score < FANET_FORWARD_THRESHOLD)
        return;   /* drop: sender not trustworthy/reliable enough */

    /* --- relay: append self, decrement TTL, rebroadcast --- */
    fanet_packet_t fwd = *pkt;
    if (fwd.path_len < FANET_MAX_PATH) {
        fwd.path[fwd.path_len++] = n->id;
    }
    fwd.ttl = (uint8_t)(pkt->ttl - 1);

    /* carry MY metrics so the next hop can score me */
    fwd.sender = n->metrics;
    if (n->is_malicious) fwd.sender.snr_db = 127;  /* sentinel for sim */

    n->transport->send(n, FANET_INVALID_ID, &fwd);
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

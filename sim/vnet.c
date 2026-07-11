/*
 * vnet.c - in-memory virtual network (PC transport backend), queue-based.
 *
 * Desktop stand-in for a radio. Implements fanet_transport's send() by
 * QUEUEING packets for delivery to in-range neighbors, then draining the
 * queue in a main pump. This BFS-style flood (rather than recursion):
 *   - matches how a real broadcast network actually propagates,
 *   - avoids deep call stacks,
 *   - maps cleanly onto the later async ESP-NOW / LoRa backend.
 *
 * Link model matches RoutingProtocol.m: soft-step success 0.98 inside 70%
 * of range, 0.70 near the edge; range 300 m. Routing code is unchanged
 * across backends - only this file is swapped on hardware.
 */
#include "../src/fanet_routing.h"
#include "../src/fanet_transport.h"
#include <math.h>
#include <string.h>

#define VNET_MAX_NODES 64
#define VNET_RANGE     200.0f
#define VNET_QUEUE     4096

typedef struct {
    fanet_node_t  *to;
    fanet_packet_t pkt;
} vnet_msg_t;

typedef struct {
    fanet_node_t *nodes[VNET_MAX_NODES];
    int count;
    unsigned long rng;
    vnet_msg_t q[VNET_QUEUE];
    int qhead, qtail;
} vnet_t;

static vnet_t g_vnet;
static fanet_transport_t g_transport;

static float vnet_rand(void) {
    g_vnet.rng = g_vnet.rng * 1103515245UL + 12345UL;
    return (float)((g_vnet.rng >> 16) & 0x7FFF) / 32767.0f;
}

static float vdist(const fanet_node_t *a, const fanet_node_t *b) {
    float dx = a->x - b->x, dy = a->y - b->y;
    return sqrtf(dx*dx + dy*dy);
}

static void q_push(fanet_node_t *to, const fanet_packet_t *pkt) {
    int next = (g_vnet.qtail + 1) % VNET_QUEUE;
    if (next == g_vnet.qhead) return;   /* full: drop (overload) */
    g_vnet.q[g_vnet.qtail].to  = to;
    g_vnet.q[g_vnet.qtail].pkt = *pkt;
    g_vnet.qtail = next;
}

/*
 * Deliver a packet. If dst == FANET_INVALID_ID: broadcast to all in-range
 * neighbors (used by RREQ flood) - lossy, models fading/collisions on a
 * shared broadcast frame. Otherwise: unicast to that specific in-range node
 * (used by RREP and DATA).
 *
 * Unicast is far more reliable than broadcast because real link layers
 * (ESP-NOW, addressed LoRa) retry on missing ACK - but not infallible: the
 * retry budget is finite, so a small residual loss remains, larger at the
 * edge of range. Modelling it as perfectly lossless would flatter the
 * protocol with an unrealistic 100% PDR.
 */
static void vnet_send(fanet_node_t *self, uint8_t dst,
                      const fanet_packet_t *pkt) {
    int is_broadcast = (dst == FANET_INVALID_ID);

    for (int i = 0; i < g_vnet.count; ++i) {
        fanet_node_t *nb = g_vnet.nodes[i];
        if (nb == self) continue;
        if (!is_broadcast && nb->id != dst) continue;   /* unicast target */

        float d = vdist(self, nb);
        if (d <= 0.0f || d > VNET_RANGE) continue;

        int near = (d < VNET_RANGE * 0.7f);
        float p_success = is_broadcast
                        ? (near ? 0.98f : 0.70f)   /* shared medium, lossy */
                        : (near ? 0.995f : 0.97f); /* unicast w/ ACK+retry */

        if (vnet_rand() > p_success) continue;   /* lost despite retries */

        q_push(nb, pkt);
    }
}

void vnet_reset(unsigned long seed) {
    memset(&g_vnet, 0, sizeof(g_vnet));
    g_vnet.rng = seed;
    g_transport.send = vnet_send;
    g_transport.ctx = &g_vnet;
}

fanet_transport_t *vnet_transport(void) { return &g_transport; }

void vnet_add(fanet_node_t *n) {
    if (g_vnet.count < VNET_MAX_NODES)
        g_vnet.nodes[g_vnet.count++] = n;
}

void vnet_clear_caches(void) {
    for (int i = 0; i < g_vnet.count; ++i)
        fanet_node_reset_cache(g_vnet.nodes[i]);
}

/* Drain delivery queue until empty or source has a complete route. */
void vnet_pump(uint8_t stop_src) {
    int guard = 0;
    while (g_vnet.qhead != g_vnet.qtail && guard++ < VNET_QUEUE * 4) {
        vnet_msg_t m = g_vnet.q[g_vnet.qhead];
        g_vnet.qhead = (g_vnet.qhead + 1) % VNET_QUEUE;
        fanet_node_on_receive(m.to, &m.pkt);
        for (int k = 0; k < g_vnet.count; ++k) {
            if (g_vnet.nodes[k]->id == stop_src &&
                g_vnet.nodes[k]->route_complete) {
                g_vnet.qhead = g_vnet.qtail;
                return;
            }
        }
    }
}

/*
 * test_routing.c - edge-case tests for the routing layer's packet handling.
 *
 * These target the memory-safety boundaries a hostile or corrupt packet can
 * push on: an oversized path_len, and a path already at the maximum length.
 * They assert CORRECT behaviour (reject / stay in bounds), so they fail if the
 * bounds checks are ever removed or get an off-by-one - not just describe
 * whatever the code happens to do today.
 *
 * A stub transport records every send() so we can tell "forwarded" from
 * "dropped" without a full virtual network.
 */
#include <stdio.h>
#include <string.h>
#include "../src/fanet_routing.h"

static int failures = 0;

static void check(const char *what, int ok) {
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) failures++;
}

/* --- stub transport: count sends, capture the last packet --------------- */
static int            g_sends;
static fanet_packet_t g_last;

static void stub_send(struct fanet_node *self, uint8_t dst,
                      const fanet_packet_t *pkt) {
    (void)self; (void)dst;
    g_sends++;
    g_last = *pkt;
}

/* Healthy metrics so an honest packet clears the 0.4 forwarding gate; this
 * lets us prove a drop is caused by the length, not by a low fuzzy score. */
static const fanet_metrics_t GOOD = { 1000, 1000, 0, 30, 60 };

static fanet_node_t make_node(uint8_t id, fanet_transport_t *tr) {
    fanet_node_t n;
    fanet_node_init(&n, id, 0.0f, 0.0f, MODE_FUZZY, tr);
    fanet_node_set_metrics(&n, GOOD);
    return n;
}

int main(void) {
    printf("Routing edge-case tests\n\n");
    fanet_transport_t tr = { stub_send, 0 };

    /* --- 0. positive control: a well-formed RREQ IS forwarded ----------- */
    {
        fanet_node_t n = make_node(5, &tr);
        fanet_packet_t p;
        memset(&p, 0, sizeof(p));
        p.type = PKT_RREQ; p.src = 1; p.dst = 49; p.ttl = 10; p.req_id = 1;
        p.path_len = 1; p.path[0] = 1; p.sender = GOOD;
        g_sends = 0;
        fanet_node_on_receive(&n, &p);
        check("well-formed RREQ is forwarded (control)", g_sends == 1);
    }

    /* --- 1. RREQ claiming a path far longer than the buffer ------------- *
     * path_len is a uint8_t the sender controls (up to 255) while path[]
     * holds only FANET_MAX_PATH. A missing bound check would drive an
     * out-of-bounds read; the correct response is to drop the packet.       */
    {
        fanet_node_t n = make_node(5, &tr);
        fanet_packet_t p;
        memset(&p, 0, sizeof(p));
        p.type = PKT_RREQ; p.src = 1; p.dst = 49; p.ttl = 10; p.req_id = 2;
        p.path_len = FANET_MAX_PATH + 1;  /* one past the buffer: must be rejected.
                                           * Minimal violation keeps the "bug
                                           * present" path deterministic - without
                                           * the check it reads the adjacent byte
                                           * and forwards, so this test truly
                                           * fails if the bound is ever removed. */
        p.path[0] = 1; p.sender = GOOD;
        g_sends = 0;
        fanet_node_on_receive(&n, &p);
        check("RREQ with path_len > FANET_MAX_PATH is dropped, not forwarded",
              g_sends == 0);
    }

    /* --- 2. RREP claiming an oversized path ----------------------------- *
     * handle_rrep scans path[] looking for this node; an oversized length
     * would read past the array. Fill valid ids so a non-clamped scan could
     * "find" us and act - the packet must still be dropped.                 */
    {
        fanet_node_t n = make_node(3, &tr);
        fanet_packet_t p;
        memset(&p, 0, sizeof(p));
        p.type = PKT_RREP; p.src = 1; p.dst = 49; p.ttl = 10; p.req_id = 3;
        p.path_len = 200;
        for (int i = 0; i < FANET_MAX_PATH; ++i) p.path[i] = (uint8_t)i;
        g_sends = 0;
        fanet_node_on_receive(&n, &p);
        check("RREP with path_len > FANET_MAX_PATH is dropped", g_sends == 0);
    }

    /* --- 3. destination replies to a path already at the maximum -------- *
     * A full 16-hop RREQ reaches the destination. send_rrep appends itself;
     * the result must NOT exceed FANET_MAX_PATH (no off-by-one overflow).   */
    {
        fanet_node_t d = make_node(49, &tr);
        fanet_packet_t q;
        memset(&q, 0, sizeof(q));
        q.type = PKT_RREQ; q.src = 1; q.dst = 49; q.ttl = 10; q.req_id = 4;
        q.path_len = FANET_MAX_PATH;       /* already full: 16 hops */
        for (int i = 0; i < FANET_MAX_PATH; ++i) q.path[i] = (uint8_t)(i + 1);
        q.sender = GOOD;
        g_sends = 0;
        fanet_node_on_receive(&d, &q);
        check("full-length RREQ at destination emits exactly one RREP",
              g_sends == 1);
        check("emitted RREP stays within FANET_MAX_PATH",
              g_sends == 1 && g_last.path_len <= FANET_MAX_PATH);
        check("emitted packet is a valid RREP",
              g_sends == 1 && g_last.type == PKT_RREP);
    }

    /* --- 4. relay forwarding a path already at the maximum -------------- *
     * A relay (not the destination) at a full path cannot append itself; it
     * must still forward without growing the path beyond the bound.         */
    {
        fanet_node_t r = make_node(99, &tr);   /* id not on the path */
        fanet_packet_t q;
        memset(&q, 0, sizeof(q));
        q.type = PKT_RREQ; q.src = 1; q.dst = 49; q.ttl = 10; q.req_id = 5;
        q.path_len = FANET_MAX_PATH;
        for (int i = 0; i < FANET_MAX_PATH; ++i) q.path[i] = (uint8_t)(i + 1);
        q.sender = GOOD;
        g_sends = 0;
        fanet_node_on_receive(&r, &q);
        check("relay forwards full-length RREQ without exceeding path bound",
              g_sends == 1 && g_last.path_len <= FANET_MAX_PATH);
    }

    printf("\n%s\n", failures ? "SOME TESTS FAILED" : "all tests passed");
    return failures ? 1 : 0;
}

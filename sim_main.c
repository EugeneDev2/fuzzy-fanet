/*
 * sim_main.c - desktop demo of the Fuzzy-AODV stack.
 *
 * Reproduces the experiment from main.m / SimulationEngine.m:
 *   - N nodes placed in an area, ~15% are Black Hole attackers
 *   - attackers advertise "perfect" metrics to lure traffic
 *   - run STANDARD AODV vs FUZZY AODV on the identical topology
 *   - report path length, hops, and whether the route passed through
 *     any malicious node.
 *
 * All on the PC, no hardware. Same routing code that will run on ESP32-C3.
 */
#include "../src/fanet_routing.h"
#include <stdio.h>
#include <stdlib.h>

/* sim/vnet.c API */
void vnet_reset(unsigned long seed);
fanet_transport_t *vnet_transport(void);
void vnet_add(fanet_node_t *n);
void vnet_clear_caches(void);
void vnet_pump(uint8_t stop_src);

#define N 50
#define AREA 800.0f          /* matches main.m (800x800) */
#define SEED 555UL

static fanet_node_t nodes[N];

/* tiny reproducible RNG for placement (separate from vnet's link RNG) */
static unsigned long prng = SEED;
static float frand(void) {
    prng = prng * 1103515245UL + 12345UL;
    return (float)((prng >> 16) & 0x7FFF) / 32767.0f;
}

static void build_topology(fanet_mode_t mode) {
    prng = SEED;             /* identical placement for both modes */
    vnet_reset(SEED);

    for (int i = 0; i < N; ++i) {
        float x = frand() * AREA;
        float y = frand() * AREA;

        /* Pin source to bottom-left, destination to top-right corner, so the
         * route must cross the field (multi-hop) instead of being a trivial
         * 1-hop neighbor pair. This makes the attack scenario meaningful. */
        if (i == 0)        { x = 40.0f;          y = 40.0f; }
        if (i == N - 1)    { x = AREA - 40.0f;   y = AREA - 40.0f; }

        fanet_node_init(&nodes[i], (uint8_t)i, x, y, mode, vnet_transport());

        fanet_metrics_t m;
        m.battery_mah = (uint16_t)(4000 + frand() * 1000);
        m.battery_max = 5000;
        m.speed       = (uint8_t)(frand() * 5);
        m.speed_max   = 20;
        m.snr_db      = (int8_t)(50 + frand() * 10);

        int malicious = 0;
        if (i != 0 && i != N - 1 && frand() < 0.15f) {
            malicious = 1;
            m.snr_db      = 60;     /* looks perfect to Standard AODV */
            m.battery_mah = 5000;
        }
        nodes[i].is_malicious = (uint8_t)malicious;
        fanet_node_set_metrics(&nodes[i], m);

        vnet_add(&nodes[i]);
    }
}

static void run_mode(const char *label, fanet_mode_t mode) {
    build_topology(mode);
    vnet_clear_caches();

    fanet_node_t *src = &nodes[0];
    fanet_node_t *dst = &nodes[N - 1];

    fanet_start_discovery(src, dst->id);
    vnet_pump(dst->id);   /* drain flood until the DEST has a route */

    /* In this RREQ-only model the discovered path is recorded at the
     * destination (that's where the request arrives). A full AODV would
     * RREP it back to the source; that's the next milestone. For now we
     * read the result from the destination node. */
    printf("=== %s ===\n", label);
    if (dst->found_len == 0) {
        printf("  NO ROUTE FOUND (packet dropped / failsafe)\n\n");
        return;
    }

    int hops = dst->found_len - 1;
    int attackers = 0;
    printf("  path: ");
    for (int i = 0; i < dst->found_len; ++i) {
        uint8_t id = dst->found_path[i];
        int bad = nodes[id].is_malicious;
        if (bad) attackers++;
        printf("%d%s", id, bad ? "(!)" : "");
        if (i < dst->found_len - 1) printf(" -> ");
    }
    printf("\n  hops: %d | attackers in route: %d", hops, attackers);
    if (attackers > 0)
        printf("  <<< BLACK HOLE IN PATH\n");
    else
        printf("  <<< route clean\n");
    printf("\n");
}

int main(void) {
    /* count attackers in the topology for context */
    build_topology(MODE_FUZZY);
    int total_bad = 0;
    for (int i = 0; i < N; ++i) if (nodes[i].is_malicious) total_bad++;

    printf("FANET Fuzzy-AODV  |  %d nodes, %dx%d area, %d Black Holes\n",
           N, (int)AREA, (int)AREA, total_bad);
    printf("source = 0, destination = %d\n\n", N - 1);

    run_mode("STANDARD AODV (blind)", MODE_STANDARD);
    run_mode("FUZZY AODV (trust filter)", MODE_FUZZY);

    return 0;
}

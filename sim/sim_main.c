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

/*
 * Push a burst of payloads along whatever route currently exists, and report.
 * Returns packets delivered.
 */
static int push_data(fanet_node_t *src, fanet_node_t *dst, int burst,
                     uint16_t seq_base, int *refused_out) {
    const uint8_t payload[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    int refused = 0;
    int before = dst->data_received;

    for (int i = 0; i < burst; ++i) {
        if (!fanet_send_data(src, dst->id, payload, 4,
                             (uint16_t)(seq_base + i)))
            refused++;
        vnet_pump(FANET_INVALID_ID);
    }
    if (refused_out) *refused_out = refused;
    return dst->data_received - before;
}

static int count_attackers(const uint8_t *path, uint8_t len) {
    int a = 0;
    for (uint8_t i = 0; i < len; ++i)
        if (nodes[path[i]].is_malicious) a++;
    return a;
}

static void print_path(const uint8_t *path, uint8_t len) {
    for (uint8_t i = 0; i < len; ++i) {
        printf("%d%s", path[i], nodes[path[i]].is_malicious ? "(!)" : "");
        if (i < len - 1) printf(" -> ");
    }
}

static int count_bad(void) {
    int b = 0;
    for (int i = 0; i < N; ++i) if (nodes[i].is_malicious) b++;
    return b;
}

static int count_detected(void) {
    int d = 0;
    for (int j = 0; j < N; ++j) {
        if (!nodes[j].is_malicious) continue;
        for (int i = 0; i < N; ++i)
            if (ft_is_blacklisted(&nodes[i].trust, (uint8_t)j)) { d++; break; }
    }
    return d;
}

static int count_false_accusations(void) {
    int f = 0;
    for (int i = 0; i < N; ++i)
        for (int j = 0; j < N; ++j)
            if (!nodes[j].is_malicious &&
                ft_is_blacklisted(&nodes[i].trust, (uint8_t)j)) f++;
    return f;
}

static void run_mode(const char *label, fanet_mode_t mode) {
    build_topology(mode);

    fanet_node_t *src = &nodes[0];
    fanet_node_t *dst = &nodes[N - 1];
    const int BURST = 100;
    const int MAX_ROUNDS = 6;

    printf("=== %s ===\n", label);

    for (int round = 1; round <= MAX_ROUNDS; ++round) {
        vnet_clear_caches();
        fanet_start_discovery(src, dst->id);
        vnet_pump(FANET_INVALID_ID);

        if (!src->route_complete || src->found_len == 0) {
            printf("  round %d: NO ROUTE - fail-safe, refuses to feed "
                   "distrusted nodes\n", round);
            break;
        }

        int att = count_attackers(src->found_path, src->found_len);
        int refused = 0;
        int got = push_data(src, dst, BURST, (uint16_t)(round * 1000), &refused);

        printf("  round %d: ", round);
        print_path(src->found_path, src->found_len);
        printf("\n           attackers on path: %d | PDR %.0f%%",
               att, 100.0f * got / BURST);

        if (mode == MODE_FUZZY) {
            int det = count_detected();
            printf(" | blacklisted so far: %d", det);
        }
        printf("\n");

        /* blind AODV never learns - one round is the whole story */
        if (mode == MODE_STANDARD) {
            printf("           blind AODV cannot learn: it will keep "
                   "feeding the attacker forever.\n");
            break;
        }

        /* converged: clean route carrying data */
        if (att == 0 && got > 0) {
            printf("           CONVERGED - route is clean, data flowing.\n");
            break;
        }
    }

    if (mode == MODE_FUZZY) {
        int fp = count_false_accusations();
        printf("  detection: %d/%d attackers unmasked purely by watching "
               "who failed to forward", count_detected(), count_bad());
        if (fp) printf(" | %d false accusation(s)", fp);
        else    printf(" | no honest node was wrongly accused");
        printf("\n");
    }
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

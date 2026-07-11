/*
 * test_fuzzy.c - desktop sanity check for the fuzzy core.
 * Compile & run on a PC; compare scores against the MATLAB evalfis output.
 */
#include <stdio.h>
#include <math.h>
#include "../src/fuzzy_fanet.h"

typedef struct { float nre, ns, nd; const char *note; } tc_t;

static int failures = 0;

static void check(const char *what, int ok) {
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) failures++;
}

int main(void) {
    tc_t cases[] = {
        {0.92f, 0.88f, 0.12f, "thesis R25 example: expect ~Excellent (>0.8)"},
        {0.10f, 0.10f, 0.90f, "all bad: expect ~Bad (<0.2)"},
        {0.50f, 0.50f, 0.50f, "all medium: expect mid (~0.4-0.6)"},
        {1.00f, 1.00f, 0.00f, "ideal node: expect very high"},
        {0.00f, 1.00f, 0.00f, "no energy, else perfect: energy dominates"},
        {0.95f, 0.20f, 0.20f, "high energy, unstable (fast mover)"},
    };
    int n = (int)(sizeof(cases)/sizeof(cases[0]));

    printf("  NRE    NS    ND  | RouteScore | note\n");
    printf("-------------------+------------+---------------------------\n");
    for (int i = 0; i < n; ++i) {
        float s = ff_route_score(cases[i].nre, cases[i].ns, cases[i].nd);
        printf(" %.2f  %.2f  %.2f |   %.4f   | %s\n",
               cases[i].nre, cases[i].ns, cases[i].nd, s, cases[i].note);
    }

    /*
     * Edge inputs. Normalized metrics are meant to be 0..1, but on real
     * hardware a bad sensor reading or a hostile packet can hand the core
     * anything: negatives, values above 1, even NaN. Whatever comes in, the
     * controller must never emit a garbage score - the output has to stay a
     * finite number in [0,1], because it is compared against a forwarding
     * threshold. A NaN would silently poison every routing decision.
     */
    printf("\nEdge-case robustness (out-of-range / NaN inputs)\n");
    float na = nanf("");
    tc_t edge[] = {
        {-0.5f,  0.5f,  0.5f, "negative NRE"},
        { 0.5f, -1.0f,  0.5f, "negative NS"},
        { 0.5f,  0.5f, -2.0f, "negative ND"},
        { 2.0f,  0.5f,  0.5f, "NRE far above 1"},
        { 0.5f,  9.9f,  0.5f, "NS far above 1"},
        {1e9f,  1e9f,  1e9f,  "all inputs huge"},
        { na,    0.5f,  0.5f, "one NaN input"},
        { na,    na,    na,   "all NaN inputs"},
    };
    int m = (int)(sizeof(edge)/sizeof(edge[0]));
    for (int i = 0; i < m; ++i) {
        float s = ff_route_score(edge[i].nre, edge[i].ns, edge[i].nd);
        int ok = isfinite(s) && s >= 0.0f && s <= 1.0f;
        printf("  score = %8.4f  <- %s\n", s, edge[i].note);
        check(edge[i].note, ok);
    }

    printf("\n%s\n", failures ? "SOME TESTS FAILED" : "all tests passed");
    return failures ? 1 : 0;
}

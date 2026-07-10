/*
 * test_fuzzy.c - desktop sanity check for the fuzzy core.
 * Compile & run on a PC; compare scores against the MATLAB evalfis output.
 */
#include <stdio.h>
#include "../src/fuzzy_fanet.h"

typedef struct { float nre, ns, nd; const char *note; } tc_t;

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
    return 0;
}

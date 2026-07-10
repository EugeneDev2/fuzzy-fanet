/*
 * fuzzy_fanet.c - implementation. See fuzzy_fanet.h.
 *
 * Membership functions and rule base are transcribed directly from
 * FANET_Routing.fis (the file loaded by readfis() in the MATLAB model),
 * so this C core reproduces the same routing logic on-device.
 */
#include "fuzzy_fanet.h"

/* ---- helpers ------------------------------------------------------------ */

static float ff_clamp01(float x) {
    if (x < 0.0f) return 0.0f;
    if (x > 1.0f) return 1.0f;
    return x;
}

static float ff_min2(float a, float b) { return a < b ? a : b; }

/* Triangular MF: rises a->b, falls b->c. Matches MATLAB trimf, including the
 * degenerate left shoulder (a==b, e.g. [0 0 0.4]) and right shoulder
 * (b==c, e.g. [0.6 1 1]) used by the "Low"/"High" terms in the FIS.
 * At the peak x==b the value is 1.0 even when a==b or b==c. */
static float ff_trimf(float x, float a, float b, float c) {
    /* peak / shoulders first so x==b==a or x==b==c -> 1.0 */
    if (x == b) return 1.0f;
    if (x <= a || x >= c) return 0.0f;
    if (x < b) return (x - a) / (b - a);   /* a<b guaranteed here */
    return (c - x) / (c - b);              /* b<c guaranteed here */
}

/* Trapezoidal MF: flat top between b and c. Matches MATLAB trapmf, including
 * the degenerate right shoulder (c==d, e.g. [0.75 0.9 1 1]) for "Excellent". */
static float ff_trapmf(float x, float a, float b, float c, float d) {
    if (x >= b && x <= c) return 1.0f;     /* flat top (covers x==d when c==d) */
    if (x <= a || x >= d) return 0.0f;
    if (x < b) return (x - a) / (b - a);
    return (d - x) / (d - c);
}

/* ---- input membership functions (from FIS) ------------------------------ */
/* term order per input: 0=Low, 1=Medium, 2=High */

static void ff_mf_nre(float x, float mu[3]) {
    mu[0] = ff_trimf(x, 0.0f, 0.0f, 0.4f);   /* Low    */
    mu[1] = ff_trimf(x, 0.2f, 0.5f, 0.8f);   /* Medium */
    mu[2] = ff_trimf(x, 0.6f, 1.0f, 1.0f);   /* High   */
}

static void ff_mf_ns(float x, float mu[3]) {
    mu[0] = ff_trimf(x, 0.0f, 0.0f, 0.35f);
    mu[1] = ff_trimf(x, 0.25f, 0.5f, 0.75f);
    mu[2] = ff_trimf(x, 0.65f, 1.0f, 1.0f);
}

static void ff_mf_nd(float x, float mu[3]) {
    mu[0] = ff_trimf(x, 0.0f, 0.0f, 0.3f);
    mu[1] = ff_trimf(x, 0.2f, 0.5f, 0.8f);
    mu[2] = ff_trimf(x, 0.7f, 1.0f, 1.0f);
}

/* ---- output membership functions (from FIS) ----------------------------- */
/* term order: 0=Bad, 1=Average, 2=Good, 3=Excellent */
static float ff_out_mf(int term, float y) {
    switch (term) {
        case 0: return ff_trimf(y, 0.0f, 0.0f, 0.25f);          /* Bad       */
        case 1: return ff_trimf(y, 0.15f, 0.35f, 0.55f);        /* Average   */
        case 2: return ff_trimf(y, 0.45f, 0.65f, 0.85f);        /* Good      */
        case 3: return ff_trapmf(y, 0.75f, 0.9f, 1.0f, 1.0f);   /* Excellent */
        default: return 0.0f;
    }
}

/* ---- rule base (from FIS [Rules]) ---------------------------------------
 * Each rule: antecedent terms for NRE, NS, ND (0..2) and consequent
 * RouteScore term (0..3). 27 rules = full coverage of 3x3x3.            */
static const unsigned char FF_RULES[27][4] = {
    /* NRE NS ND  -> OUT */
    {0,0,0, 0}, {0,0,1, 0}, {0,0,2, 1},
    {0,1,0, 0}, {0,1,1, 1}, {0,1,2, 1},
    {0,2,0, 1}, {0,2,1, 1}, {0,2,2, 2},
    {1,0,0, 0}, {1,0,1, 1}, {1,0,2, 1},
    {1,1,0, 1}, {1,1,1, 2}, {1,1,2, 2},
    {1,2,0, 2}, {1,2,1, 2}, {1,2,2, 3},
    {2,0,0, 1}, {2,0,1, 1}, {2,0,2, 2},
    {2,1,0, 2}, {2,1,1, 2}, {2,1,2, 3},
    {2,2,0, 3}, {2,2,1, 3}, {2,2,2, 3},
};

/* ---- inference + defuzzification ---------------------------------------- */

float ff_route_score(float nre, float ns, float nd) {
    nre = ff_clamp01(nre);
    ns  = ff_clamp01(ns);
    nd  = ff_clamp01(nd);

    float mu_nre[3], mu_ns[3], mu_nd[3];
    ff_mf_nre(nre, mu_nre);
    ff_mf_ns(ns,  mu_ns);
    ff_mf_nd(nd,  mu_nd);

    /* Firing strength (min) per rule, aggregated (max) per output term. */
    float term_strength[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    for (int r = 0; r < 27; ++r) {
        float a = ff_min2(mu_nre[FF_RULES[r][0]],
                  ff_min2(mu_ns [FF_RULES[r][1]],
                          mu_nd [FF_RULES[r][2]]));
        int out = FF_RULES[r][3];
        if (a > term_strength[out]) term_strength[out] = a;
    }

    /* Centroid (COG) over aggregated output set, clipped (Mamdani min impl). */
    float num = 0.0f, den = 0.0f;
    for (int i = 0; i < FF_DEFUZZ_POINTS; ++i) {
        float y = (float)i / (float)(FF_DEFUZZ_POINTS - 1);  /* 0..1 */
        float agg = 0.0f;
        for (int t = 0; t < 4; ++t) {
            float clipped = ff_min2(term_strength[t], ff_out_mf(t, y));
            if (clipped > agg) agg = clipped;
        }
        num += y * agg;
        den += agg;
    }

    if (den == 0.0f) return 0.0f;       /* no rule fired */
    return ff_clamp01(num / den);
}

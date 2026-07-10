/*
 * fuzzy_fanet.h - Lightweight Mamdani fuzzy controller for FANET routing.
 *
 * Portable C99, zero dependencies, no dynamic allocation, no float printf
 * required. Suitable for microcontrollers (ESP32-C3 / RISC-V, STM32, AVR...).
 *
 * Mirrors the MATLAB FIS "FANET_Routing":
 *   Inputs : NRE, NS, ND   (all normalized to [0,1])
 *   Output : RouteScore     (normalized to [0,1])
 *   Type   : Mamdani, AND=min, agg=max, defuzz=centroid (COG)
 *
 * Usage:
 *   float score = ff_route_score(nre, ns, nd);
 */
#ifndef FUZZY_FANET_H
#define FUZZY_FANET_H

#ifdef __cplusplus
extern "C" {
#endif

/* Number of sample points used for the discrete centroid defuzzification.
 * 101 points over [0,1] => step 0.01. Matches MATLAB's default-ish resolution
 * closely enough for routing decisions. Raise for more precision, lower to
 * save cycles on tiny MCUs. */
#ifndef FF_DEFUZZ_POINTS
#define FF_DEFUZZ_POINTS 101
#endif

/*
 * Compute the route reliability score for a candidate node.
 *
 *   nre - normalized residual energy   [0..1]
 *   ns  - normalized stability         [0..1]
 *   nd  - normalized delay (1-SNRnorm) [0..1]
 *
 * Returns RouteScore in [0..1]. Inputs are clamped to [0,1] internally.
 */
float ff_route_score(float nre, float ns, float nd);

#ifdef __cplusplus
}
#endif

#endif /* FUZZY_FANET_H */

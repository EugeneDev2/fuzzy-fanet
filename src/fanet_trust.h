/*
 * fanet_trust.h - behavioural trust manager.
 *
 * Detects Black Hole nodes by WATCHING WHAT THEY DO, not by being told who
 * is malicious. The rule is simple:
 *
 *     I handed a neighbour N packets to forward.
 *     How many did I actually hear it forward?
 *
 *     T_direct = forwarded / entrusted
 *
 * A cooperative node relays what it is given, so T_direct stays near 1.
 * A Black Hole swallows everything, so its T_direct collapses toward 0 and
 * it gets watchlisted, then blacklisted, and finally excluded from routes.
 *
 * "Hearing" a forward is realistic: radio is a broadcast medium, so a node in
 * promiscuous mode overhears whether its neighbour actually re-transmitted
 * the packet. This is the same mechanism the thesis describes.
 *
 * Portable C99. No allocation, no globals. Sized for microcontrollers.
 */
#ifndef FANET_TRUST_H
#define FANET_TRUST_H

#include <stdint.h>

/* How many neighbours a node can track reputation for. */
#define FT_MAX_PEERS 32

/* A brand-new, unproven neighbour starts neutral - neither trusted nor
 * condemned. Matches T_init = 0.5 in the thesis. */
#define FT_INITIAL 0.5f

/* Exponential smoothing factor: how much weight accumulated reputation keeps
 * versus the newest observation. High alpha => history dominates, so a single
 * unlucky radio drop cannot destroy an honest node's reputation.
 * Matches alpha = 0.7 in the thesis. */
#define FT_ALPHA 0.7f

/* Trust below this => suspicious, put on the watchlist. */
#define FT_WATCH_THRESHOLD 0.4f

/* Trust below this => treated as an attacker, blacklisted and cut out. */
#define FT_BLACK_THRESHOLD 0.25f

/* A node must have been entrusted at least this many packets before we are
 * willing to condemn it. Prevents convicting a neighbour on one lost packet. */
#define FT_MIN_EVIDENCE 3

/* Counter-scaling cap. entrusted/forwarded are uint16_t; on a long-lived node
 * they would eventually overflow and corrupt the trust ratio. When entrusted
 * reaches this cap we halve BOTH counters: the ratio is preserved, the
 * overflow risk is reset, and recent behaviour naturally gains weight over
 * ancient history. */
#define FT_EVIDENCE_CAP 1000

typedef enum {
    FT_OK = 0,        /* behaving */
    FT_WATCHED = 1,   /* suspicious, still allowed */
    FT_BLACKLISTED = 2/* proven to swallow traffic, excluded from routes */
} ft_status_t;

typedef struct {
    uint8_t  peer;        /* neighbour id */
    uint8_t  in_use;
    uint16_t entrusted;   /* packets we handed it to forward */
    uint16_t forwarded;   /* packets we actually overheard it forward */
    float    trust;       /* smoothed reputation, 0..1 */
    uint8_t  status;      /* ft_status_t */
} ft_peer_t;

typedef struct {
    ft_peer_t peers[FT_MAX_PEERS];
} fanet_trust_t;

/* Reset all reputations. */
void ft_init(fanet_trust_t *t);

/* Record that we gave `peer` a packet to forward. */
void ft_on_entrusted(fanet_trust_t *t, uint8_t peer);

/* Record that we overheard `peer` actually forwarding a packet. */
void ft_on_forwarded(fanet_trust_t *t, uint8_t peer);

/*
 * Cancel a previously recorded entrusting that we never got to observe (e.g.
 * the observation slot was recycled before we could overhear the relay).
 * Rolls back the entrusted count so the peer is NOT blamed for a packet we
 * simply stopped watching - silence we chose to ignore is not evidence.
 */
void ft_on_forgo(fanet_trust_t *t, uint8_t peer);

/*
 * Recompute `peer`'s reputation from observed behaviour and update its
 * status. Call after an observation window (here: after each entrusted
 * packet resolves).
 */
void ft_update(fanet_trust_t *t, uint8_t peer);

/* Current trust in `peer` (FT_INITIAL if never seen). */
float ft_trust_of(const fanet_trust_t *t, uint8_t peer);

/* Current status of `peer`. */
ft_status_t ft_status_of(const fanet_trust_t *t, uint8_t peer);

/* Convenience: is this peer barred from participating in routes? */
int ft_is_blacklisted(const fanet_trust_t *t, uint8_t peer);

#endif /* FANET_TRUST_H */

/*
 * fanet_trust.c - behavioural trust manager. See fanet_trust.h.
 */
#include "fanet_trust.h"
#include <string.h>

/* ---- peer table --------------------------------------------------------- */

static ft_peer_t *find_peer(fanet_trust_t *t, uint8_t peer) {
    for (int i = 0; i < FT_MAX_PEERS; ++i)
        if (t->peers[i].in_use && t->peers[i].peer == peer)
            return &t->peers[i];
    return 0;
}

static const ft_peer_t *find_peer_const(const fanet_trust_t *t, uint8_t peer) {
    for (int i = 0; i < FT_MAX_PEERS; ++i)
        if (t->peers[i].in_use && t->peers[i].peer == peer)
            return &t->peers[i];
    return 0;
}

/* Get an existing peer entry, or claim a free slot for a new one. */
static ft_peer_t *get_or_add(fanet_trust_t *t, uint8_t peer) {
    ft_peer_t *p = find_peer(t, peer);
    if (p) return p;

    for (int i = 0; i < FT_MAX_PEERS; ++i) {
        if (!t->peers[i].in_use) {
            p = &t->peers[i];
            p->peer      = peer;
            p->in_use    = 1;
            p->entrusted = 0;
            p->forwarded = 0;
            p->trust     = FT_INITIAL;   /* neutral until proven otherwise */
            p->status    = FT_OK;
            return p;
        }
    }
    /*
     * Known limitation: the peer table is full (FT_MAX_PEERS neighbours).
     * We return NULL and callers skip the update, so a Black Hole that only
     * ever appears beyond the 32nd tracked neighbour would go unwatched.
     * Acceptable here (a node rarely has that many active neighbours); a
     * production build would evict the least-recently-seen peer instead.
     */
    return 0;   /* table full: cannot track this peer */
}

/* ---- public API --------------------------------------------------------- */

void ft_init(fanet_trust_t *t) {
    memset(t, 0, sizeof(*t));
}

void ft_on_entrusted(fanet_trust_t *t, uint8_t peer) {
    ft_peer_t *p = get_or_add(t, peer);
    if (!p) return;
    p->entrusted++;

    /* Keep the uint16_t counters from ever overflowing: at the cap, halve
     * both. The forwarded/entrusted ratio is preserved (so trust is
     * unchanged), while fresh observations now weigh more than old ones. */
    if (p->entrusted >= FT_EVIDENCE_CAP) {
        p->entrusted = (uint16_t)(p->entrusted / 2);
        p->forwarded = (uint16_t)(p->forwarded / 2);
    }
}

void ft_on_forwarded(fanet_trust_t *t, uint8_t peer) {
    ft_peer_t *p = get_or_add(t, peer);
    if (p) p->forwarded++;
}

void ft_on_forgo(fanet_trust_t *t, uint8_t peer) {
    ft_peer_t *p = find_peer(t, peer);
    if (p && p->entrusted > 0) p->entrusted--;
}

void ft_update(fanet_trust_t *t, uint8_t peer) {
    ft_peer_t *p = find_peer(t, peer);
    if (!p || p->entrusted == 0) return;

    /* Observed cooperation rate over everything we have seen so far. */
    float observed = (float)p->forwarded / (float)p->entrusted;
    if (observed > 1.0f) observed = 1.0f;

    /* Exponential smoothing: accumulated reputation resists a single bad
     * sample, so one dropped packet on a fading link is forgiven, while a
     * node that never forwards steadily sinks. */
    p->trust = FT_ALPHA * p->trust + (1.0f - FT_ALPHA) * observed;

    if (p->trust < 0.0f) p->trust = 0.0f;
    if (p->trust > 1.0f) p->trust = 1.0f;

    /* Don't convict on thin evidence: a neighbour we barely used stays OK. */
    if (p->entrusted < FT_MIN_EVIDENCE) {
        p->status = FT_OK;
        return;
    }

    if (p->trust < FT_BLACK_THRESHOLD)      p->status = FT_BLACKLISTED;
    else if (p->trust < FT_WATCH_THRESHOLD) p->status = FT_WATCHED;
    else                                    p->status = FT_OK;
}

float ft_trust_of(const fanet_trust_t *t, uint8_t peer) {
    const ft_peer_t *p = find_peer_const(t, peer);
    return p ? p->trust : FT_INITIAL;
}

ft_status_t ft_status_of(const fanet_trust_t *t, uint8_t peer) {
    const ft_peer_t *p = find_peer_const(t, peer);
    return p ? (ft_status_t)p->status : FT_OK;
}

int ft_is_blacklisted(const fanet_trust_t *t, uint8_t peer) {
    return ft_status_of(t, peer) == FT_BLACKLISTED;
}

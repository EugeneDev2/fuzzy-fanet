/*
 * test_trust.c - unit tests for the behavioural trust manager.
 *
 * Verifies the three properties that matter:
 *   1. A node that never forwards gets blacklisted.
 *   2. A node that forwards reliably stays trusted.
 *   3. An honest node that drops the occasional packet (radio fade) is
 *      forgiven, not condemned. This is what exponential smoothing buys us.
 */
#include <stdio.h>
#include "../src/fanet_trust.h"

static int failures = 0;

static void check(const char *what, int ok) {
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) failures++;
}

int main(void) {
    printf("TrustManager unit tests\n\n");

    /* --- 1. a Black Hole: entrusted repeatedly, never forwards --- */
    {
        fanet_trust_t t;
        ft_init(&t);
        for (int i = 0; i < 20; ++i) {
            ft_on_entrusted(&t, 7);   /* we gave it a packet */
            ft_update(&t, 7);         /* ...and never heard it relay */
        }
        printf("Black Hole (0/20 forwarded): trust = %.3f\n", ft_trust_of(&t, 7));
        check("black hole is blacklisted", ft_is_blacklisted(&t, 7));
    }

    /* --- 2. a cooperative relay: forwards everything --- */
    {
        fanet_trust_t t;
        ft_init(&t);
        for (int i = 0; i < 20; ++i) {
            ft_on_entrusted(&t, 3);
            ft_on_forwarded(&t, 3);
            ft_update(&t, 3);
        }
        printf("Honest relay (20/20 forwarded): trust = %.3f\n", ft_trust_of(&t, 3));
        check("honest relay is not blacklisted", !ft_is_blacklisted(&t, 3));
        check("honest relay is not even watchlisted",
              ft_status_of(&t, 3) == FT_OK);
    }

    /* --- 3. an honest but unlucky node: loses 1 in 10 to radio fade --- */
    {
        fanet_trust_t t;
        ft_init(&t);
        for (int i = 0; i < 30; ++i) {
            ft_on_entrusted(&t, 5);
            if (i % 10 != 0) ft_on_forwarded(&t, 5);  /* 90% success */
            ft_update(&t, 5);
        }
        printf("Lossy but honest (90%% forwarded): trust = %.3f\n",
               ft_trust_of(&t, 5));
        check("honest node with radio losses is NOT blacklisted",
              !ft_is_blacklisted(&t, 5));
    }

    /* --- 4. thin evidence must not convict --- */
    {
        fanet_trust_t t;
        ft_init(&t);
        ft_on_entrusted(&t, 9);   /* a single missed packet */
        ft_update(&t, 9);
        check("one missed packet is not enough to convict",
              !ft_is_blacklisted(&t, 9));
    }

    /* --- 5. an unknown peer starts neutral --- */
    {
        fanet_trust_t t;
        ft_init(&t);
        check("unseen peer starts at neutral trust",
              ft_trust_of(&t, 42) == FT_INITIAL);
        check("unseen peer is not blacklisted", !ft_is_blacklisted(&t, 42));
    }

    /* --- 6. more neighbours than the peer table can hold --- *
     * The table has FT_MAX_PEERS slots. Overflowing it must degrade
     * gracefully: no crash, peers tracked before it filled stay correct, and
     * a peer that could NOT be tracked is never falsely accused. */
    {
        fanet_trust_t t;
        ft_init(&t);

        /* peer 0 is a Black Hole caught while there was still room */
        for (int i = 0; i < 10; ++i) { ft_on_entrusted(&t, 0); ft_update(&t, 0); }

        /* now flood the table with far more distinct peers than it can hold */
        for (int p = 1; p <= FT_MAX_PEERS + 19; ++p) {
            ft_on_entrusted(&t, (uint8_t)p);   /* many will hit a full table */
            ft_update(&t, (uint8_t)p);
        }
        uint8_t overflow_peer = (uint8_t)(FT_MAX_PEERS + 19);  /* never fit */

        check("black hole tracked before the table filled stays blacklisted",
              ft_is_blacklisted(&t, 0));
        check("untrackable overflow peer is not falsely blacklisted",
              !ft_is_blacklisted(&t, overflow_peer));
        check("untrackable overflow peer reads as neutral trust",
              ft_trust_of(&t, overflow_peer) == FT_INITIAL);
    }

    /* --- 7. counter scaling must not corrupt a verdict --- *
     * entrusted/forwarded are uint16_t and get halved at FT_EVIDENCE_CAP to
     * avoid overflow. Correct scaling halves BOTH counters, so the ratio (and
     * thus the verdict) is preserved. We push both a Black Hole and an honest
     * relay well past the cap: a rescale that distorted the ratio - e.g.
     * halving only one counter - would flip one of these verdicts. */
    {
        fanet_trust_t t;
        ft_init(&t);
        for (int i = 0; i < FT_EVIDENCE_CAP * 3; ++i) {
            ft_on_entrusted(&t, 11);   /* handed thousands, never forwards */
            ft_update(&t, 11);

            ft_on_entrusted(&t, 12);   /* handed thousands, forwards them all */
            ft_on_forwarded(&t, 12);
            ft_update(&t, 12);
        }
        check("black hole stays blacklisted across counter rescaling",
              ft_is_blacklisted(&t, 11));
        check("honest relay stays trusted across counter rescaling",
              !ft_is_blacklisted(&t, 12) && ft_status_of(&t, 12) == FT_OK);
    }

    printf("\n%s\n", failures ? "SOME TESTS FAILED" : "all tests passed");
    return failures ? 1 : 0;
}

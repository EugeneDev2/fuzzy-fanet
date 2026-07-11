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

    printf("\n%s\n", failures ? "SOME TESTS FAILED" : "all tests passed");
    return failures ? 1 : 0;
}

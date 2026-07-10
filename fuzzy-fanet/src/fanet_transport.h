/*
 * fanet_transport.h - radio abstraction.
 *
 * THE key architectural seam: the routing layer talks only to this
 * interface, never to a specific radio. On the PC we back it with an
 * in-memory virtual network; on hardware we back it with ESP-NOW or LoRa.
 * Routing code does not change when the backend changes.
 */
#ifndef FANET_TRANSPORT_H
#define FANET_TRANSPORT_H

#include "fanet_types.h"

/* Forward declaration; defined by whichever node implementation is used. */
struct fanet_node;

/*
 * Send a packet from `self` toward `dst`. dst == FANET_INVALID_ID means
 * broadcast to all neighbors in range. Implementation decides reachability
 * (range, loss, collisions).
 */
typedef void (*fanet_send_fn)(struct fanet_node *self,
                              uint8_t dst,
                              const fanet_packet_t *pkt);

/*
 * A transport backend is just a send function plus opaque context.
 * Receive is push-based: the backend calls fanet_node_on_receive() on the
 * destination node(s) when a packet arrives.
 */
typedef struct {
    fanet_send_fn send;
    void *ctx;            /* backend-private (e.g. the virtual network) */
} fanet_transport_t;

#endif /* FANET_TRANSPORT_H */

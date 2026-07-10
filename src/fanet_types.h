/*
 * fanet_types.h - shared types for the FANET routing stack.
 *
 * Wire-format packet and node metric definitions. Kept small and
 * fixed-layout so the same struct can later be serialized onto a radio
 * (ESP-NOW / LoRa) with minimal packing work.
 *
 * Portable C99. No dependencies beyond <stdint.h>.
 */
#ifndef FANET_TYPES_H
#define FANET_TYPES_H

#include <stdint.h>

/* Hard limits. Chosen so a packet fits comfortably in an ESP-NOW frame
 * (250 B). On LoRa the path may need to be capped lower (see roadmap). */
#define FANET_MAX_PATH   16   /* max hops recorded in a route */
#define FANET_INVALID_ID 0xFF /* sentinel node id */

/* Packet types (AODV subset). */
typedef enum {
    PKT_RREQ = 1,   /* route request  (flood) */
    PKT_RREP = 2,   /* route reply    (unicast back) */
    PKT_HELLO = 3   /* neighbor discovery / metric beacon */
} fanet_pkt_type_t;

/*
 * Raw per-node metrics, as a node would actually measure them on hardware.
 * The routing layer normalizes these into NRE/NS/ND before the fuzzy core.
 */
typedef struct {
    uint16_t battery_mah;   /* remaining charge, mAh */
    uint16_t battery_max;   /* design capacity, mAh */
    uint8_t  speed;         /* current speed, m/s (0..255) */
    uint8_t  speed_max;     /* max speed, m/s */
    int8_t   snr_db;        /* link SNR in dB (signed) */
} fanet_metrics_t;

/*
 * Routing packet. Fixed layout; `path` is a fixed array with `path_len`
 * valid entries. This is the in-memory form; a serializer can pack only
 * the used path entries for the radio.
 */
typedef struct {
    uint8_t  type;                    /* fanet_pkt_type_t */
    uint8_t  src;                     /* originator id */
    uint8_t  dst;                     /* destination id */
    uint8_t  ttl;                     /* hops remaining */
    uint16_t req_id;                  /* unique request id (loop/dup guard) */
    uint16_t score_x1000;             /* cumulative route score * 1000 */
    uint8_t  path_len;                /* number of valid entries in path[] */
    uint8_t  path[FANET_MAX_PATH];    /* node ids visited, in order */
    fanet_metrics_t sender;           /* sender's raw metrics (for scoring) */
} fanet_packet_t;

#endif /* FANET_TYPES_H */

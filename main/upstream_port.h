#pragma once
/*
 * Upstream source-port rotation policy (pure, no sockets).
 *
 * dns_server.cpp keeps at most two plain-UDP upstream sockets: the current one
 * and one draining. This file decides when to rotate, which port to ask for,
 * and when the draining socket may be closed. Each socket has a generation
 * number; a flight remembers the generation it left on and a reply is only
 * accepted from that same generation's socket.
 */
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UP_PORT_MIN        49152u   /* IANA dynamic range */
#define UP_PORT_MAX        65535u
#define UP_ROTATE_QUERIES  2048u    /* forwards on one socket before rotating */
#define UP_ROTATE_MS       60000u   /* or this long, whichever comes first */
#define UP_BIND_ATTEMPTS   8        /* bind retries per rotation (port collision) */

typedef struct {
    uint8_t  cur_gen;      /* generation of the current socket */
    bool     draining;     /* the previous generation's socket is still open */
    uint32_t queries;      /* forwards sent on the current socket */
    uint32_t rotated_ms;   /* when the current socket was opened (wrap-safe) */
} up_state_t;

void     up_init(up_state_t *st, uint32_t now_ms);

/* Map a random word onto UP_PORT_MIN..UP_PORT_MAX. */
uint16_t up_port_from_random(uint32_t r);

/* Count one forward sent on the current socket. */
void     up_note_forward(up_state_t *st);

/* True when a rotation is wanted AND allowed. A due rotation while a socket
 * is still draining returns false (deferred): there is never a third socket. */
bool     up_rotate_due(const up_state_t *st, uint32_t now_ms);

/* Commit a rotation after the new socket is bound. Writes the new generation
 * to *new_gen. Returns false (and changes nothing) if a socket is draining. */
bool     up_begin_rotate(up_state_t *st, uint32_t now_ms, uint8_t *new_gen);

/* The new socket could not be bound: restart both clocks so the caller
 * retries after a full interval rather than on every tick. */
void     up_rotate_failed(up_state_t *st, uint32_t now_ms);

bool     up_draining(const up_state_t *st);

/* Generation of the draining socket; only meaningful while up_draining(). */
uint8_t  up_drain_gen(const up_state_t *st);

/* Report how many flights still belong to the draining generation. Returns
 * true exactly once, when that count is zero: the caller closes the socket. */
bool     up_drain_poll(up_state_t *st, uint32_t drain_flights);

/* A reply read from the socket of generation rx_gen belongs to a flight tagged
 * flight_gen only if they match. */
bool     up_reply_ok(uint8_t flight_gen, uint8_t rx_gen);

#ifdef __cplusplus
}
#endif

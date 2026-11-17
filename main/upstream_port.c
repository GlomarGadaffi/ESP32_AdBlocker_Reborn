/* Upstream source-port rotation policy. See upstream_port.h. */
#include "upstream_port.h"

void up_init(up_state_t *st, uint32_t now_ms)
{
    if (!st) return;
    st->cur_gen    = 0;
    st->draining   = false;
    st->queries    = 0;
    st->rotated_ms = now_ms;
    st->drain_start_ms = now_ms;
}

uint16_t up_port_from_random(uint32_t r)
{
    /* The range holds exactly 16384 ports, so masking is unbiased. */
    return (uint16_t)(UP_PORT_MIN + (r & 0x3FFFu));
}

void up_note_forward(up_state_t *st)
{
    if (st && st->queries < 0xFFFFFFFFu) st->queries++;
}

bool up_rotate_due(const up_state_t *st, uint32_t now_ms)
{
    if (!st || st->draining) return false;
    /* Unsigned subtraction keeps the elapsed time right across a ms wrap. */
    uint32_t elapsed = now_ms - st->rotated_ms;
    return st->queries >= UP_ROTATE_QUERIES || elapsed >= UP_ROTATE_MS;
}

bool up_begin_rotate(up_state_t *st, uint32_t now_ms, uint8_t *new_gen)
{
    if (!st || !new_gen || st->draining) return false;
    st->cur_gen    = (uint8_t)(st->cur_gen + 1u);
    st->draining   = true;
    st->queries    = 0;
    st->rotated_ms = now_ms;
    st->drain_start_ms = now_ms;
    *new_gen = st->cur_gen;
    return true;
}

void up_rotate_failed(up_state_t *st, uint32_t now_ms)
{
    if (!st) return;
    st->queries    = 0;
    st->rotated_ms = now_ms;
}

bool up_draining(const up_state_t *st)
{
    return st && st->draining;
}

uint8_t up_drain_gen(const up_state_t *st)
{
    return st ? (uint8_t)(st->cur_gen - 1u) : 0;
}

bool up_drain_poll(up_state_t *st, uint32_t drain_flights, uint32_t now_ms)
{
    if (!st || !st->draining) return false;
    if (drain_flights != 0 && (uint32_t)(now_ms - st->drain_start_ms) < UP_DRAIN_MAX_MS)
        return false;
    st->draining = false;
    return true;
}

bool up_reply_ok(uint8_t flight_gen, uint8_t rx_gen)
{
    return flight_gen == rx_gen;
}

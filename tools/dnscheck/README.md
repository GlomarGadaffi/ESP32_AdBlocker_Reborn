# dnscheck

On-wire correctness gate for the DNS sinkhole. It replaces ad-hoc bench-Pi
scripts for the concurrency features (single-flight coalescing, hedged
retransmit, serve-stale, TCP/53 with 4 connections). Python 3 stdlib only.

## Safety

Every packet is an ordinary read-only DNS query. Even so, the boards are a live
household resolver: point this at a board only on purpose, and use names you
control or the default random subdomains of `example.net` (use `.invalid` in a
`--names` file for names that must never resolve). `fake_dns.py` plus the tests
run on 127.0.0.1 only.

## Usage

    python3 dnscheck.py --server IP [--port 53] [--names FILE] [--count 100]
        [--concurrency 10] [--tcp] [--same-name K] [--seed 1]
        [--timeout 2] [--settle 0.15]
        [--metrics-url https://BOARD/metrics --cookie 'sid=...' [--tolerance 20]]

Exit codes: 0 all checks pass, 1 any mismatch/unanswered/duplicate (each is
printed as `MISMATCH check=... query=... expected=... got=...`), 2 usage,
3 metrics window contaminated. Last result line:
`sent N answered A mismatched M unanswered U`.

Each query has a unique random txid, its own socket (OS-chosen ephemeral source
port), A or AAAA, EDNS0 (OPT, 1232) or not, and random 0x20-style case. The
same `--seed` regenerates the same set.

## What each check proves

| check | proves |
|---|---|
| `txid` | reply id matches the query it answers (no cross-talk between concurrent flights) |
| `qr` | QR=1 |
| `question` | question echoes qname byte-for-byte including case, plus qtype/qclass (0x20 anti-spoof survives coalescing and cache) |
| `size` / `opt` | UDP reply fits 512 (non-EDNS) or 1232 (EDNS) or has TC=1; non-EDNS reply carries no OPT |
| `rcode` | NOERROR, NXDOMAIN, SERVFAIL or REFUSED only |
| `compression` | every name pointer lands inside the packet and chains end within 10 hops |
| `parse` | the packet is structurally complete (truncation is tolerated only with TC=1) |
| `source` | UDP reply came from the address/port queried |
| `duplicate` | exactly one reply per query (waits `--settle` for a second) |
| `unanswered` | a reply arrived within `--timeout` |

`--same-name K`: K sockets, released together by a barrier, ask one cold random
name over UDP. Every asker must get exactly one valid answer; the `burst` line
reports answered/unanswered/duplicates (a coalescing bug shows as missing or
doubled answers). The K queries count toward `sent`.

`--tcp`: 2-byte length framing; `ceil(count/2)` connections each pipeline 2
queries, `--concurrency` connections open at once (use more than 4 to probe the
board's connection limit; refused or stalled connections show as unanswered).
Replies are matched by txid, any order. Size/TC rules are UDP-only.

## Metrics window and the live-traffic caveat

With `--metrics-url`, /metrics is read before and after (deltas of
`queries_total`, `dropped.table_full`, `upstream_timeouts`, `heap_free`,
`heap_largest`). Get the session cookie as `tools/board_client` does (login,
then reuse the cookie); self-signed TLS is accepted. A real box serves other
clients, so if `queries_total` moved by more than the tool's own query count
plus `--tolerance` (or went backwards, i.e. a reboot), the tool prints
`window contaminated` and exits 3 without judging, even if replies mismatched.
Rerun in a quiet period; do not read the other deltas from a contaminated
window.

## Tests

    python3 -m unittest -v tools/dnscheck/test_dnscheck.py

`fake_dns.py` is a UDP+TCP server with faults: correct, wrong_txid,
case_not_echoed, oversize_no_tc, loop_pointer, drop_nth, duplicate,
wrong_source. A tiny fake metrics HTTP server covers the window logic.

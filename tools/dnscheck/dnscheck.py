#!/usr/bin/env python3
"""On-wire correctness gate for the DNS sinkhole.

Sends a seeded set of read-only DNS queries and checks every reply byte-wise
(txid, QR, question echo incl. 0x20 case, size/TC/OPT rules, RCODE, compression
pointers, reply source). Optional burst (--same-name K) for single-flight,
optional TCP mode, optional /metrics before/after window.

Exit: 0 all pass, 1 any mismatch/unanswered/duplicate, 2 usage, 3 window contaminated.
Use names you control or random subdomains of example.net / .invalid.
"""

import argparse
import concurrent.futures
import json
import random
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.request

OK_RCODES = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}
MAX_HOPS = 10
METRIC_FIELDS = ("queries_total", "dropped.table_full", "upstream_timeouts",
                 "heap_free", "heap_largest")


class BadPointer(Exception):
    pass


class Short(Exception):
    pass


# ---- wire helpers ----

def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        if label:
            raw = label.encode()
            out += bytes([len(raw)]) + raw
    return out + b"\x00"


def parse_name(pkt, off):
    """Return (dotted name bytes, offset after the name's first encoding)."""
    pos, end, hops, labels, total = off, None, 0, [], 0
    while True:
        if pos >= len(pkt):
            raise Short("name runs past end of packet")
        b = pkt[pos]
        if b & 0xC0 == 0xC0:
            if pos + 1 >= len(pkt):
                raise Short("pointer cut off")
            ptr = ((b & 0x3F) << 8) | pkt[pos + 1]
            if end is None:
                end = pos + 2
            hops += 1
            if hops > MAX_HOPS:
                raise BadPointer("pointer chain exceeds %d hops (loop) at offset %d" % (MAX_HOPS, pos))
            if ptr >= len(pkt):
                raise BadPointer("pointer to %d outside %d byte packet" % (ptr, len(pkt)))
            pos = ptr
        elif b & 0xC0:
            raise BadPointer("reserved label type 0x%02x at offset %d" % (b, pos))
        elif b == 0:
            if end is None:
                end = pos + 1
            return b".".join(labels), end
        else:
            if pos + 1 + b > len(pkt):
                raise Short("label runs past end of packet")
            labels.append(pkt[pos + 1:pos + 1 + b])
            total += b + 1
            if total > 255:
                raise BadPointer("name longer than 255 bytes")
            pos += 1 + b


class Query:
    def __init__(self, name, qtype, edns, txid):
        self.name, self.qtype, self.edns, self.txid = name, qtype, edns, txid
        hdr = struct.pack("!6H", txid, 0x0100, 1, 0, 0, 1 if edns else 0)
        pkt = hdr + encode_name(name) + struct.pack("!HH", qtype, 1)
        if edns:
            pkt += b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0)
        self.packet = pkt

    def label(self):
        return "%s %s%s" % (self.name, {1: "A", 28: "AAAA"}.get(self.qtype, self.qtype),
                            " +edns" if self.edns else "")


class Gen:
    """Seeded query generator; txids are unique across everything it makes."""

    def __init__(self, seed, names=None):
        self.rng = random.Random(seed)
        self.names = names
        self.used = set()

    def cold_name(self):
        return "dc%010x.example.net" % self.rng.getrandbits(40)

    def make(self, name=None, qtype=None, edns=None):
        r = self.rng
        if name is None:
            name = r.choice(self.names) if self.names else self.cold_name()
        name = "".join(c.upper() if c.isalpha() and r.random() < 0.5 else c.lower() for c in name)
        if qtype is None:
            qtype = r.choice((1, 28))
        if edns is None:
            edns = r.random() < 0.5
        while True:
            txid = r.getrandbits(16)
            if txid not in self.used:
                self.used.add(txid)
                break
        return Query(name, qtype, edns, txid)


def build_queries(count, seed, names):
    g = Gen(seed, names)
    return [g.make() for _ in range(count)]


# ---- reply checks ----

def check_reply(q, data, src, expect_src, tcp):
    """Return a list of (check, expected, got) for one reply."""
    bad = []
    if src is not None and src != expect_src:
        bad.append(("source", "reply from %s:%d" % expect_src, "reply from %s:%d" % tuple(src[:2])))
    if len(data) < 12:
        bad.append(("parse", "12 byte header", "%d bytes" % len(data)))
        return bad
    txid, flags, qd, an, ns, ar = struct.unpack("!6H", data[:12])
    tc = bool(flags & 0x200)
    if txid != q.txid:
        bad.append(("txid", "0x%04x" % q.txid, "0x%04x" % txid))
    if not flags & 0x8000:
        bad.append(("qr", "QR=1", "QR=0"))
    rcode = flags & 0xF
    if rcode not in OK_RCODES:
        bad.append(("rcode", "one of NOERROR/NXDOMAIN/SERVFAIL/REFUSED", "RCODE=%d" % rcode))
    has_opt = False
    try:
        off, questions = 12, []
        for _ in range(qd):
            name, off = parse_name(data, off)
            if off + 4 > len(data):
                raise Short("question cut off")
            qt, qc = struct.unpack("!HH", data[off:off + 4])
            off += 4
            questions.append((name, qt, qc))
        want = (q.name.encode(), q.qtype, 1)
        if questions != [want]:
            bad.append(("question", "%r" % (want,), "%r" % (questions,)))
        for i in range(an + ns + ar):
            name, off = parse_name(data, off)
            if off + 10 > len(data):
                raise Short("RR header cut off")
            rtype, _rc, _ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
            rd = off + 10
            if rd + rdlen > len(data):
                raise Short("RDATA cut off")
            if rtype in (2, 5, 12):
                parse_name(data, rd)
            elif rtype == 15:
                parse_name(data, rd + 2)
            elif rtype == 6:
                _, o2 = parse_name(data, rd)
                parse_name(data, o2)
            if rtype == 41 and i >= an + ns:
                has_opt = True
            off = rd + rdlen
    except BadPointer as e:
        bad.append(("compression", "pointers inside packet, no loops", str(e)))
    except Short as e:
        if not tc:
            bad.append(("parse", "complete packet", str(e)))
    if not tcp:
        limit = 1232 if q.edns else 512
        if len(data) > limit and not tc:
            bad.append(("size", "<=%d bytes or TC=1" % limit, "%d bytes, TC=0" % len(data)))
        if not q.edns and has_opt:
            bad.append(("opt", "no OPT in reply to non-EDNS query", "OPT present"))
    return bad


class Result:
    def __init__(self, q, answered, bad, dups=0):
        self.q, self.answered, self.bad, self.dups = q, answered, bad, dups


# ---- transports ----

def udp_ask(q, server, port, timeout, settle, barrier=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("", 0))
        if barrier is not None:
            barrier.wait(10)
        s.sendto(q.packet, (server, port))
        s.settimeout(timeout)
        try:
            data, src = s.recvfrom(65535)
        except socket.timeout:
            return Result(q, False, [("unanswered", "a reply within %.2fs" % timeout, "no reply")])
        bad = check_reply(q, data, src, (server, port), False)
        dups, end = 0, time.monotonic() + settle
        while True:
            rem = end - time.monotonic()
            if rem <= 0:
                break
            s.settimeout(rem)
            try:
                s.recvfrom(65535)
                dups += 1
            except socket.timeout:
                break
        if dups:
            bad.append(("duplicate", "exactly 1 reply", "%d replies" % (1 + dups)))
        return Result(q, True, bad, dups)
    finally:
        s.close()


def _read_msg(s):
    def exact(n):
        buf = b""
        while len(buf) < n:
            c = s.recv(n - len(buf))
            if not c:
                raise ConnectionError("closed")
            buf += c
        return buf
    return exact(struct.unpack("!H", exact(2))[0])


def tcp_conn(qs, server, port, timeout, settle):
    try:
        s = socket.create_connection((server, port), timeout)
    except OSError as e:
        return [Result(q, False, [("unanswered", "TCP connect", "connect failed: %s" % e)]) for q in qs]
    with s:
        s.settimeout(timeout)
        s.sendall(b"".join(struct.pack("!H", len(q.packet)) + q.packet for q in qs))
        replies = []
        try:
            for _ in qs:
                replies.append(_read_msg(s))
        except (OSError, ConnectionError):
            pass
        extra = 0
        if len(replies) == len(qs):
            s.settimeout(settle)
            try:
                _read_msg(s)
                extra = 1
            except (OSError, ConnectionError):
                pass
    by_id = {q.txid: q for q in qs}
    done = {}
    for data in replies:
        rid = struct.unpack("!H", data[:2])[0] if len(data) >= 2 else -1
        q = by_id.get(rid)
        if q is None or q.txid in done:
            q = next(x for x in qs if x.txid not in done)
        done[q.txid] = check_reply(q, data, None, None, True)
    out = []
    for i, q in enumerate(qs):
        if q.txid in done:
            bad = done[q.txid]
            dups = extra if i == 0 else 0
            if dups:
                bad = bad + [("duplicate", "exactly 1 reply", "extra reply on connection")]
            out.append(Result(q, True, bad, dups))
        else:
            out.append(Result(q, False, [("unanswered", "a reply within %.2fs" % timeout, "no reply")]))
    return out


# ---- metrics ----

def fetch_metrics(url, cookie, timeout):
    req = urllib.request.Request(url, headers={"Cookie": cookie} if cookie else {})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return json.loads(r.read().decode())


def pick(m, path):
    cur = m
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


# ---- driver ----

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--server", required=True, help="IP/host of the resolver (never a household board unless asked)")
    ap.add_argument("--port", type=int, default=53)
    ap.add_argument("--names", help="file of names, one per line (default: random example.net subdomains)")
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--concurrency", type=int, default=10)
    ap.add_argument("--tcp", action="store_true", help="run over TCP, 2 pipelined queries per connection")
    ap.add_argument("--same-name", type=int, default=0, metavar="K",
                    help="UDP burst: K sockets ask one cold random name at once")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--settle", type=float, default=0.15, help="seconds to wait for duplicate replies")
    ap.add_argument("--metrics-url", help="e.g. https://BOARD/metrics")
    ap.add_argument("--cookie", help="session cookie, e.g. 'sid=...' (see tools/board_client)")
    ap.add_argument("--tolerance", type=int, default=20,
                    help="extra queries_total movement tolerated before the window is contaminated")
    args = ap.parse_args(argv)
    if args.count < 0 or args.concurrency < 1 or args.same_name < 0:
        ap.error("--count >= 0, --concurrency >= 1, --same-name >= 0")
    if args.cookie and not args.metrics_url:
        ap.error("--cookie needs --metrics-url")
    names = None
    if args.names:
        try:
            with open(args.names) as f:
                names = [l.strip().rstrip(".") for l in f if l.strip() and not l.startswith("#")]
        except OSError as e:
            ap.error("cannot read --names: %s" % e)
        if not names:
            ap.error("--names file has no names")
    try:
        server = socket.gethostbyname(args.server)
    except OSError as e:
        ap.error("cannot resolve --server: %s" % e)

    before = None
    if args.metrics_url:
        try:
            before = fetch_metrics(args.metrics_url, args.cookie, 8)
        except Exception as e:  # noqa: BLE001
            print("cannot fetch metrics before the run: %s" % e)
            return 2

    gen = Gen(args.seed, names)
    results = []
    if args.count:
        if args.tcp:
            qs = [gen.make() for _ in range(args.count)]
            groups = [qs[i:i + 2] for i in range(0, len(qs), 2)]
            with concurrent.futures.ThreadPoolExecutor(args.concurrency) as ex:
                for rs in ex.map(lambda g: tcp_conn(g, server, args.port, args.timeout, args.settle), groups):
                    results.extend(rs)
        else:
            qs = [gen.make() for _ in range(args.count)]
            with concurrent.futures.ThreadPoolExecutor(args.concurrency) as ex:
                results = list(ex.map(lambda q: udp_ask(q, server, args.port, args.timeout, args.settle), qs))

    burst = None
    if args.same_name:
        k = args.same_name
        name = gen.cold_name()
        bq = [gen.make(name=name, qtype=1, edns=True) for _ in range(k)]
        barrier = threading.Barrier(k)
        with concurrent.futures.ThreadPoolExecutor(k) as ex:
            br = list(ex.map(lambda q: udp_ask(q, server, args.port, args.timeout, args.settle, barrier), bq))
        burst = (name, br)
        results.extend(br)

    sent = len(results)
    answered = sum(1 for r in results if r.answered)
    unanswered = sent - answered
    mismatched = sum(1 for r in results if r.answered and r.bad)
    for r in results:
        for check, exp, got in r.bad:
            print("MISMATCH check=%s query=%s expected=%s got=%s" % (check, r.q.label(), exp, got))
    if burst:
        br = burst[1]
        print("burst name=%s K=%d answered=%d unanswered=%d duplicates=%d" % (
            burst[0], len(br), sum(1 for r in br if r.answered),
            sum(1 for r in br if not r.answered), sum(r.dups for r in br)))
    print("sent %d answered %d mismatched %d unanswered %d" % (sent, answered, mismatched, unanswered))

    contaminated = False
    if before is not None:
        try:
            after = fetch_metrics(args.metrics_url, args.cookie, 8)
        except Exception as e:  # noqa: BLE001
            print("window contaminated: cannot fetch metrics after the run (%s); no conclusion drawn" % e)
            return 3
        for f in METRIC_FIELDS:
            a, b = pick(before, f), pick(after, f)
            if isinstance(a, (int, float)) and isinstance(b, (int, float)):
                print("metrics %s %s -> %s (%+d)" % (f, a, b, b - a))
        qa, qb = pick(before, "queries_total"), pick(after, "queries_total")
        if not isinstance(qa, (int, float)) or not isinstance(qb, (int, float)):
            print("window contaminated: queries_total missing from /metrics; no conclusion drawn")
            return 3
        moved = qb - qa
        if moved < 0 or moved > sent + args.tolerance:
            print("window contaminated: queries_total moved %d, tool sent %d (+%d tolerance); "
                  "the box is serving other traffic or restarted; no conclusion drawn"
                  % (moved, sent, args.tolerance))
            return 3
    return 1 if (mismatched or unanswered) else 0


if __name__ == "__main__":
    sys.exit(main())

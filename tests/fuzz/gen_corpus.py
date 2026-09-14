#!/usr/bin/env python3
"""Regenerate the seed corpora under tests/fuzz/corpus/.

Seeds are deliberately *valid* messages: a coverage-guided fuzzer mutates from
them into the interesting malformed neighbours (a compression pointer that
lands one byte short, an SOA rdlen longer than the packet, ...) far faster
than it can discover a well-formed DNS header from nothing.

    python3 tests/fuzz/gen_corpus.py
"""
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))


def name(s):
    out = b""
    for label in s.strip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def hdr(txid=0x1234, flags=0x8180, qd=1, an=0, ns=0, ar=0):
    return struct.pack(">HHHHHH", txid, flags, qd, an, ns, ar)


def rr(owner, rtype, ttl, rdata, rclass=1):
    return owner + struct.pack(">HHIH", rtype, rclass, ttl, len(rdata)) + rdata


def ptr(off):
    return struct.pack(">H", 0xC000 | off)


def dns_seeds():
    q = name("www.example.com") + struct.pack(">HH", 1, 1)
    seeds = {}
    # plain query
    seeds["query_a"] = hdr(flags=0x0100) + q
    seeds["query_aaaa"] = hdr(flags=0x0100) + name("ipv6.google.com") + struct.pack(">HH", 28, 1)
    seeds["query_long_labels"] = hdr(flags=0x0100) + name("a" * 63 + "." + "b" * 63 + "." + "c" * 63 + ".test") + struct.pack(">HH", 1, 1)
    # A answer, owner via compression pointer to the question
    seeds["resp_a_compressed"] = hdr(an=1) + q + rr(ptr(12), 1, 300, bytes([93, 184, 216, 34]))
    # two A records, different TTLs
    seeds["resp_a_two"] = hdr(an=2) + q + rr(ptr(12), 1, 60, b"\x01\x02\x03\x04") + rr(ptr(12), 1, 3600, b"\x05\x06\x07\x08")
    # CNAME chain: www -> cdn.tracker.net (compressed tail) -> A
    p = hdr(an=3) + q
    cname_target = name("cdn.tracker.net")
    p += rr(ptr(12), 5, 120, cname_target)
    target_off = len(hdr(an=3) + q) + 2 + 10  # owner ptr(2) + fixed(10)
    p += rr(ptr(target_off), 5, 120, b"\x04edge" + ptr(target_off + 4))  # edge.tracker.net via pointer into "tracker.net"
    p += rr(ptr(len(p) - 7), 1, 30, b"\x0a\x00\x00\x01")
    seeds["resp_cname_chain"] = p
    # NXDOMAIN with SOA in authority (RFC 2308 negative caching)
    soa_rdata = name("ns1.example.com") + name("hostmaster.example.com") + struct.pack(">IIIII", 2024010101, 7200, 3600, 1209600, 300)
    seeds["resp_nxdomain_soa"] = hdr(flags=0x8183, ns=1) + q + rr(name("example.com"), 6, 900, soa_rdata)
    # SOA whose MNAME/RNAME use compression pointers into the question
    soa_c = ptr(16) + b"\x0ahostmaster" + ptr(16) + struct.pack(">IIIII", 1, 2, 3, 4, 60)
    seeds["resp_nxdomain_soa_compressed"] = hdr(flags=0x8183, ns=1) + q + rr(ptr(16), 6, 900, soa_c)
    # answer + authority NS + additional A (all three sections)
    p = hdr(an=1, ns=1, ar=1) + q
    p += rr(ptr(12), 1, 300, b"\x01\x01\x01\x01")
    p += rr(ptr(16), 2, 86400, b"\x03ns1" + ptr(16))
    p += rr(b"\x03ns1" + ptr(16), 1, 86400, b"\x02\x02\x02\x02")
    seeds["resp_three_sections"] = p
    # EDNS0 OPT in additional
    seeds["resp_edns"] = hdr(an=1, ar=1) + q + rr(ptr(12), 1, 300, b"\x01\x01\x01\x01") + rr(b"\x00", 41, 0, b"", rclass=1232)
    # TXT with long rdata
    seeds["resp_txt"] = hdr(an=1) + q + rr(ptr(12), 16, 300, b"\xff" + b"v=spf1 " + b"x" * 248)
    # empty and header-only
    seeds["empty"] = b""
    seeds["header_only"] = hdr()
    seeds["root_query"] = hdr(flags=0x0100) + b"\x00" + struct.pack(">HH", 2, 1)
    return seeds


def rule_seeds():
    lines = [
        "example.com",
        "0.0.0.0 ads.example.com",
        "127.0.0.1 tracker.example.net analytics.example.net",
        "||ads.example.com^",
        "||ads.example.com^$important",
        "@@||cdn.example.com^",
        "@@||cdn.example.com^$important",
        "|exact.example.com^",
        "@@|exact.example.com^",
        "# a comment line",
        "! adblock style comment",
        "[Adblock Plus 2.0]",
        "/regex[0-9]+\\.example\\.com/",
        "*.wild.example.com",
        "||example.com^$third-party",
        "example.com##.banner",
        "192.168.0.0/16",
        "::1 localhost",
        "0.0.0.0 ads.example.com # trailing comment",
        "   leading.spaces.example.com   ",
        "UPPER.Case.Example.COM.",
        "xn--nxasmq6b.example",
        "a" * 63 + ".example.com",
        "a" * 64 + ".example.com",
        "com",
        ".",
        "",
        "||^",
        "@@",
        "$important",
        "||a.b^$important,third-party",
    ]
    return {"rule_%02d" % i: s.encode() for i, s in enumerate(lines)}


def web_seeds():
    """fuzz_web_parse input: [cap byte][A]\\0[B]. A = body / url / cookie,
    B = key / host."""
    def mk(cap, a, b=b""):
        return bytes([cap]) + a + b"\x00" + b
    s = {}
    s["login_body"] = mk(64, b"user=admin&pass=I+like+tacos%21&csrf=abc", b"pass")
    s["setup_body"] = mk(64, b"user=admin&pass=glopiglopi&pass2=glopiglopi", b"pass2")
    s["body_key_prefix"] = mk(32, b"xpass=nope&pass=yes", b"pass")
    s["body_key_last"] = mk(32, b"a=1&b=2&pass", b"pass")
    s["body_pct_edge"] = mk(32, b"v=%4&w=%zz&x=%41%", b"x")
    s["body_crlf"] = mk(32, b"v=abc\r\ndef&w=1", b"v")
    s["origin_ok"] = mk(40, b"https://192.168.12.195/login", b"192.168.12.195")
    s["origin_port"] = mk(40, b"https://esp32adblock.local:443/", b"esp32adblock.local:443")
    s["origin_evil"] = mk(40, b"https://192.168.12.195.evil.com/", b"192.168.12.195")
    s["origin_case"] = mk(40, b"HTTPS://ESP32ADBLOCK.LOCAL", b"esp32adblock.local")
    s["origin_null"] = mk(40, b"null", b"esp32adblock.local")
    s["cookie_one"] = mk(64, b"sid=" + b"ab" * 32)
    s["cookie_multi"] = mk(64, b"theme=dark; xsid=zzz; sid=" + b"0123456789abcdef" * 4 + b"; other=1")
    s["cookie_short"] = mk(64, b"sid=abc; sid=" + b"f" * 64)
    s["html"] = mk(96, b"<script>alert('x')</script>&amp;\"q\"")
    s["html_tight"] = mk(6, b"<<<<<<<<<<")
    return s


def write(sub, seeds):
    d = os.path.join(HERE, "corpus", sub)
    os.makedirs(d, exist_ok=True)
    for k, v in seeds.items():
        with open(os.path.join(d, k), "wb") as f:
            f.write(v)
    print("%s: %d seeds" % (sub, len(seeds)))


if __name__ == "__main__":
    write("dns_wire", dns_seeds())
    write("rule_parse", rule_seeds())
    write("web_parse", web_seeds())

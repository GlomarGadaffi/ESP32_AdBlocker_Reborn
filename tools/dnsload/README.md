# dnsload — DNS load generator for measuring this resolver

`dnsload.c` keeps N queries in flight against the device and records the wall
time from `sendto()` to the matching reply, reporting real percentiles from the
full sample set (not a bucketed histogram, so the numbers can be read alongside
the device's own `/metrics` without inheriting its power-of-two buckets).

```
dnsload <server-ip> <namefile> <concurrency> <seconds> [--warm N] [--prefix]
```

Build (MSVC): `cl /nologo /O2 dnsload.c ws2_32.lib`
Build (gcc):  `gcc -O2 dnsload.c -lws2_32 -o dnsload`   (Windows; it is Winsock-based)

## Use a real corpus

A hardcoded handful of names flatters any lookup design: they sit at one label
depth, so every query costs the same number of suffix-walk lookups, and they
touch a few cache lines instead of the whole hash space. Build the corpora from
real data:

```sh
# blocked: the device's own primary feed — every name is guaranteed to be blocked
curl -sL https://big.oisd.nl/domainswild2 -o oisd.raw
grep -v '^#' oisd.raw | shuf -n 60000 > blocked_big.txt

# allowed: a public top-sites list, minus anything the primary feed blocks
curl -sL https://raw.githubusercontent.com/zer0h/top-1000000-domains/master/top-100000-domains -o top.raw
```

The OISD sample lands at roughly 72% two-label, 24% three-label, with a tail out
to seven — which is what makes the suffix walk do realistic work.

## Which path to measure

**Use the blocked path for throughput.** It is entirely device-bound: every
answer is built and sent from the L2 RX hook, nothing goes upstream, so the
number reflects the device and the link and nothing else.

The cached path is much harder to measure honestly. The forward cache holds 2048
entries, entries expire on the answer's own TTL, and a public top-sites list is
full of domains that no longer resolve — so a "cached" run quietly turns into a
cold run, and at `--warm`-ed concurrency 1 a single cold miss dominates the whole
sample. If you measure it, check `cache_hit_rate` in `/metrics` afterwards and
discard the run if it is not high.

Cold (`--prefix`) measures your upstream resolver's RTT far more than this
device. Keep those runs short and do not read much into them.

## Interpreting the result

- Watch the **loss column**, not just qps. Past saturation qps stays flat while
  loss climbs; the useful ceiling is the highest concurrency still at ~0% loss.
- **Run A/B/A when comparing firmware builds.** Over Wi-Fi especially, channel
  conditions drift enough between runs to invent a regression that is not there.
  This happened during the 1.3.0 measurement: a first run looked ~2x slower at
  low concurrency and a re-run after flashing back matched the baseline exactly.
- A wired client is worth the trouble. Over 2.4 GHz the radio, not the board,
  may well be what you are measuring.

# Blocklist storage format — bucket-split 40-bit

Status: Wave 1 (PSRAM) shipped in 1.3.0 and measured on hardware (see below).
Wave 2 (flash-resident) is a write target for the same format, not a redesign.

## Why

The list is stored as hashes, not domain strings — that is what makes it fit.
The cost is that a **legitimate** domain whose hash lands in the table is
sinkholed with no entry in any feed to explain it. That rate is the table's
occupancy of the hash space, `n / 2**bits`, per probe, times the 3–4 suffixes
the walk tries per query.

At the measured 778,569-entry union:

| | 32-bit (before) | 40-bit bucket-split |
| --- | --- | --- |
| Per-probe FP | 1.8e-4 | 7.1e-7 |
| Per-query FP (×4 suffixes) | ~1 in 1,500 | **~1 in 350,000** |
| Bytes per entry | 4 | **3** + 256 KB index |
| Probes per suffix | ~20 (binary search over n) | **~4** (search within one bucket) |

Storing *fewer* bytes per entry while gaining 8 bits of discrimination is not a
trick — the bucket index carries the top 16 bits as position rather than data.

## Format

```
h40    = fmix64(fnv1a64(domain)) >> 24        40 bits
bucket = h40 >> 24                            16 bits  -> index slot
rem    = h40 & 0xFFFFFF                       24 bits  -> stored, 3 bytes BE
```

Live layout is a **single allocation** so one atomic pointer publishes the
index and the entries together:

```
+---------------------------+
| idx[65537] : uint32_t     |  262,148 B   idx[b]   = first entry of bucket b
|                           |              idx[b+1] = one past its last
+---------------------------+              idx[65536] = total entry count
| entries : 3 bytes each    |  3 * n B     big-endian 24-bit remainders,
|                           |              ascending within each bucket
+---------------------------+
```

Entries are **big-endian** throughout, including the 5-byte build records.
That makes `memcmp` the numeric comparator for every comparison in the
pipeline — the qsort fallback, the chunk merge, the dedup binary search — and
makes bytes 0–1 of a build record the bucket with no shifting.

Lookup is: read `idx[bucket]` and `idx[bucket+1]`, binary-search that slice for
the 3-byte remainder. Mean bucket occupancy at 800k is 12.2 entries, so ~4
probes, all within a few cache lines, against ~20 scattered probes before.

## Build pipeline and its memory budget

The constraint is not storage, it is the sort. Accumulating and sorting ~800k
entries needs a staging array wider than the final one, and the old list has to
keep serving throughout.

```
buffer A (staging)   5 * C bytes           = 3.81 MiB at C = 800k
buffer B (live)      262,148 + 3 * C bytes = 2.54 MiB at C = 800k
                                     total = 6.35 MiB
```

For comparison the previous design held two 4-byte ping-pong buffers at
820k = 6.26 MiB. So this costs ~100 KiB more, capacity goes 820k -> 800k
(-2.4%), and every entry gains 8 bits.

Reload sequence:

1. Accumulate 5-byte big-endian records into A, deduplicating extras against
   the sorted prefix exactly as before (the `sorted_prefix` binary search and
   `fold_sorted_chunk` port unchanged once their bounds are re-derived in
   **record units** rather than words).
2. Radix sort A. 5-byte records = **5 LSD passes = odd**, so the result lands
   in the scratch half, not the front. This is load-bearing: the previous
   4-pass sort relied on an even pass count to land back in place.
3. Convert 5-byte records -> 3-byte remainders + bucket index, reading from A
   and writing into B. Separate buffers, so there is no aliasing contract to
   get wrong — the cost is that B is the live image, which is what makes the
   publish window below unavoidable.
4. Publish (see below).

At real list sizes (778k of C = 800k) the near-capacity **fallback** paths run,
not the roomy radix path — the primary feed at ~266k is under `C/2` and radixes,
but the fold hits `p + 2m' > CAPACITY` every reload. That is why `bl_sort_dedup`
and `bl_fold_sorted_chunk` take `cap` as a parameter and live in `bl_table.c`
rather than being written against `BLOCKLIST_CAPACITY` directly: the host
harness drives both at `cap = 1000`, where every fallback fires, and checks the
result against an independent reference sort.

## Publish window — a new, bounded fail-open

A is staging and B is live, and they are different sizes, so the roles cannot be
swapped by pointer the way two equal ping-pong buffers could. The conversion in
step 3 therefore writes into B — the buffer readers are holding.

A reader that loaded `s_live` immediately before the swap can still be inside a
bucket search on B while the conversion runs, which would tear reads and return
wrong verdicts (indices stay bounded, so no crash — just a wrong answer). The
sequence is therefore:

```
s_live = NULL             -> every query fails open, forwards upstream
vTaskDelay(2 ms)          -> RCU quiescence; drains in-flight readers
bl_build_image(A -> B)    -> one pass, ~50 ms at full capacity
s_live = B; gen++         -> live again
```

The 2 ms is the same quiescence the previous degraded sort path already used
(#45). A reader's critical section is one bucket search — a handful of probes,
microseconds — so 2 ms is a thousandfold margin.

Be accurate about what this costs. The **previous** design's common path
published with **no** degraded window at all; its documented 1–2 s window only
occurred in one near-capacity corner. This introduces a ~50 ms fail-open window
on **every** reload, i.e. every 4 hours. Nothing drops — queries forward
upstream and resolve normally, they are just unfiltered for that window. That is
an acceptable price, but it is a new cost, not an improvement on what was there.

Alternatives rejected: two equal 5C buffers would allow a zero-copy pointer
swap, but 10C exceeds the PSRAM budget above ~690k capacity, which is below the
measured 778k peak — it would start dropping entries.

## Hashing

`bl_hash40()` is **separate from** `domain_hash()`. The existing 32-bit
murmur3 stays exactly as it is, because it also keys the forward cache
(`dns_server.cpp`), the L2 cache lookup (`dns_sink.cpp`), and the in-flight
upstream table. Widening it there would be an unrelated format change to
unrelated structures.

`bl_hash40` is FNV-1a 64 (one multiply per byte) finished with the
murmur3 `fmix64` avalanche, taking the **top** 40 bits. The finalizer matters:
raw FNV-1a low bits are weakly mixed, and the top 16 bits become the bucket, so
they need to be well distributed or bucket occupancy skews.

## SD snapshot

`SD_MAGIC` goes 0xB10C1573 -> 0xB10C2840. Old firmware must reject a new file
and new firmware must reject an old one — a silently misread snapshot would be
served as a garbage blocklist. The old header's `reserved[2]` forward-compat
note no longer applies; the new header stores the format parameters (hash bits,
bucket bits, entry bytes) and they are checked on load, so a future width change
is rejected precisely rather than needing another magic bump.

The file body is the live image verbatim, so a warm boot is a straight read with
no conversion — and it is already the byte layout Wave 2 would write to flash.
The first boot after upgrading re-downloads the list, since the pre-1.3.0
snapshot is rejected.

## Measured on hardware (2026-08-31)

T-ETH-Elite, 727,509 domains live (OISD + AdGuard + hagezi ultimate + tif.medium),
before/after the same board, via `/metrics`.

| | 32-bit array | 40-bit bucket-split |
| --- | --- | --- |
| `latency_us.lookup` p50 | 32 us | 32 us |
| `latency_us.lookup` p99 | 128 us | **64 us** |
| `latency_us.lookup` max | 126 us | **61 us** |
| `psram_free` | 329,800 B | 264,268 B |
| SD snapshot size | 2,909,500 B | **2,444,691 B** |

Read these honestly:

* **p50 did not move.** The histogram buckets are powers of two, so 32 us means
  "in the 32-64 us bucket", and a lookup is more than its probes: the suffix
  walk, normalization and the whitelist check are all in that span. Probe count
  was never what set the median — which is why a prefix index was not worth
  building on its own, and only earns its place here as the storage format.
* **The tail halved**, which is where ~20 scattered probes over a 727k array
  actually hurt. p99 and max both came down about 2x.
* **PSRAM cost 65,532 B**, not the ~102 KB the arithmetic predicts, and
  `psram_free` settles at ~258 KB. Note the pre-existing `blocklist.h` claim of
  a "1.45 MB psram_free" reserve was already stale before this change: the
  measured baseline was 322 KB.
* **The snapshot shrank by 465 KB** while every hash gained 8 bits — the clearest
  single confirmation that the bucket index is carrying real information.

Cold reload (all four feeds, no usable snapshot) took 459 s, during which the
device fails open and forwards unfiltered. That is the one-time cost of the
format change, since the pre-1.3.0 snapshot is rejected on the first boot after
upgrading. Warm boot from the new snapshot: **727,509 domains live 21 s after a
reboot request**.

## End-to-end load test (2026-08-31)

The device-side numbers above say the lookup got cheaper. They do not say
whether that is visible to a client, so it was measured directly with
[`tools/dnsload`](../tools/dnsload/) against a 60,000-name corpus sampled from
the device's own OISD feed (72% two-label, 24% three-label, tail to seven, so
the suffix walk does realistic work).

Waveshare canary, blocked path (entirely device-bound: answered from the L2 RX
hook, never goes upstream). Same corpus, same client, same channel.

| conc | 1.2.2 qps | 1.3.0 qps | 1.2.2 p50 | 1.3.0 p50 | 1.2.2 p95 | 1.3.0 p95 | loss |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 260 | 257 | 3.59 ms | 3.55 ms | 6.69 ms | 7.05 ms | 0% / 0% |
| 4 | 907 | 909 | 3.82 | 3.88 | 7.80 | 7.92 | 0% / 0% |
| 16 | 2066 | 2086 | 7.39 | 7.35 | 11.85 | 11.65 | 0% / 0% |
| 128 | 2184 | 2198 | 58.4 | 58.0 | 62.9 | 62.3 | 0% / 0% |
| 256 | 2129 | 2145 | 92.5 | 92.0 | 97.0 | 96.6 | 7.1% / 7.0% |
| 512 | 2130 | 2148 | — | — | — | — | 30.5% / 30.4% |

**Saturation is ~2,150-2,200 qps on both builds, and the useful ceiling is
~2,190 qps at concurrency 128 with zero loss.** Past that, qps stays flat while
loss climbs — the classic saturated-queue signature.

**The storage change is performance-neutral end to end, and that is the expected
result.** The lookup went from ~20 scattered probes to ~4, worth tens of
microseconds; the end-to-end budget at load is tens of milliseconds of SPI and
link time. A 40 us saving inside a 58 ms budget is not observable, which is the
same reason a prefix index was not worth building on its own. What the format
buys is 233x fewer false positives and a smaller snapshot, at no throughput cost.

Under the full run the device served ~200k queries with **`l2_tx_fail` = 0** and
`cache_evictions` = 0; `dropped.table_full` reached 81 only during the cold
portion of the cached runs.

### Caveats — read these before quoting the numbers

* **The client was on 2.4 GHz Wi-Fi** (channel 3, ~30% utilisation); its wired
  NIC was unplugged and the 5 GHz AP was out of range. The README's ~2,200 qps
  figure came from a wired Linux client. That the Wi-Fi client reaches roughly
  the same ceiling suggests the true device limit is at or above this; treat
  ~2,200 qps as a **floor**, not a measured maximum.
* **The first 1.3.0 ramp looked like a large regression** — 118 qps at c=1
  against the baseline's 260, and a p95 of 27.6 ms against 6.7 ms. Re-flashing
  1.3.0 and re-running reproduced the baseline exactly. It was channel noise.
  Any A/B on this bench needs to be A/B/A or it will invent regressions.
* **The cached-path ramp is not trustworthy** and is deliberately not quoted.
  Public top-sites lists are full of dead domains, cache entries expire on their
  own TTLs, and the measured `cache_hit_rate` was only 16.6% — so those runs were
  substantially cold-path measurements of the upstream resolver.

## Wave 2 (later, not now)

The same `[idx | entries]` image is what a flash partition would hold. 16 MB
flash with the table ending at 0x379000 leaves 12.4 MB unallocated, enough for
A/B table partitions. What Wave 2 additionally needs is an external merge sort
(sorted runs streamed to flash, k-way merged) so the staging array stops being
the capacity ceiling. That is what buys multi-million-entry lists and frees
PSRAM; this wave deliberately does not attempt it.

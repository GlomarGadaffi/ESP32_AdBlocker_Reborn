# SIMD / PIE acceleration study — ESP32-S3 DNS sinkhole

**Question asked:** can the S3's vector unit (Xtensa LX7 Processor Instruction
Extensions, the `ee.*` 128-bit SIMD ops that esp-dsp uses, marketed as the "AI
accelerator") plus hand assembly meaningfully speed up the DNS data path —
specifically the sort and merge in blocklist loading, and any other hot function?

**Short answer: no, and the reason is worth writing down once so nobody
re-litigates it.** Every kernel that touches the big arrays is bound by octal
PSRAM, not by ALU width, and the one benchmark that settles it is reproduced
below: on this chip, 128-bit `ee.vld.128.ip` loads from PSRAM measure *identically*
to plain 32-bit `l32i` loads, to three significant figures. A wider ALU cannot
help a kernel that is stalled on a memory bus.

There are real speedups available. They are in a different place than the
question assumed, and section 5 ranks them. The single biggest one is a one-line
`sdkconfig` change.

Everything here was derived from this repo's own compiled objects
(`build/esp-idf/main/CMakeFiles/__idf_main.dir/*.obj`, the shipped `-O2` release
build), from ESP-IDF v6.0.2 sources at `$IDF_PATH`, from the ESP32-S3 TRM, and
from direct probing of the project's own assembler. Numbers are labelled
**[measured]**, **[derived]**, or **[estimated]**.

---

## 1. Ground truth: what the memory system actually does

### 1.1 The chip is running its PSRAM at half speed

`sdkconfig.defaults:6` sets `CONFIG_SPIRAM_SPEED_40M=y`.

This is the ESP-IDF **default**, not a decision — `components/esp_psram/esp32s3/Kconfig.spiram` has
`choice SPIRAM_SPEED / default SPIRAM_SPEED_40M`. It is a well-known trap. Every
PSRAM number in this document is roughly twice as bad as it needs to be because
of this line.

Octal PSRAM on the S3 is **DDR only** — from ESP-IDF's *SPI Flash and External SPI
RAM Configuration* guide (`docs/en/api-guides/flash_psram_config.rst`):

> Quad PSRAM only supports STR mode, while Octal PSRAM only supports DTR mode.

so the theoretical peak is `8 lines × 2 edges × clock`:

| PSRAM clock | Theoretical peak | Status |
| --- | --- | --- |
| 40 MHz DDR | 80 MB/s | **current** |
| 80 MHz DDR | 160 MB/s | supported, non-experimental |
| 120 MHz DDR | 240 MB/s | experimental, temperature-fragile |

### 1.2 Measured PSRAM throughput, and the benchmark that ends the SIMD argument

From [project-x51/esp32-s3-memorycopy](https://github.com/project-x51/esp32-s3-memorycopy)
on an ESP32-S3-WROOM-1U-N8R8 at `CONFIG_SPIRAM_SPEED_80M`, OCT mode, 240 MHz CPU,
DCache 32 KB / 32 B line / 8-way (i.e. this project's cache config, but **double**
this project's PSRAM clock), 100 KiB buffers with the cache flushed **[measured]**:

| Method | IRAM→IRAM | **PSRAM→IRAM** | IRAM→PSRAM | PSRAM→PSRAM |
| --- | --- | --- | --- | --- |
| 8-bit loop | 45.78 | **29.41** | 27.12 | 19.52 |
| 32-bit loop | 228.85 | **58.13** | 32.66 | 21.24 |
| 64-bit loop | 305.11 | **56.77** | 32.66 | 21.24 |
| libc `memcpy` | 365.99 | **56.77** | 32.52 | 21.24 |
| `esp_async_memcpy` (GDMA) | 57.45 | **52.63** | — | 26.40 |
| **PIE 128-bit, 16 B/iter** | 1207.62 | **58.13** | 32.52 | 21.05 |
| **PIE 128-bit, 32 B/iter** | **1829.77** | **58.13** | 32.52 | 21.08 |
| **esp-dsp `dsps_memcpy_aes3`** | 1444.89 | **57.64** | 32.36 | 21.02 |

(MB/s.) **Read the PSRAM→IRAM column twice.** For internal RAM, PIE 128-bit gives
a genuine **5×** over libc `memcpy` (366 → 1830). For PSRAM, the 8-bit loop is
slower — and then the 32-bit loop, the 64-bit loop, `memcpy`, Espressif's own
hand-written PIE `dsps_memcpy_aes3`, and a 32-byte-unrolled PIE loop **all land
between 56.8 and 58.1 MB/s.** Quadrupling the load width buys **zero**.

That is the textbook signature of a bus-bound kernel, and it is the empirical
answer to the question in the title: **widening the load does nothing once the
data lives behind the MSPI cache.** Note also that GDMA (`esp_async_memcpy`) does
not rescue it either — it is *slower* than the CPU for PSRAM→IRAM.

Caveat on absolute values: [issue #2](https://github.com/project-x51/esp32-s3-memorycopy/issues/2)
on that repo argues the benchmark under-reports (the buffer partly fits in cache,
the loop isn't `IRAM_ATTR`). Published 80 MHz octal figures span 40–84 MB/s
depending on methodology. The *relative* result — 128-bit == 32-bit — is
unaffected by any of that, which is the part this document depends on.

### 1.3 Cost of a single cache miss, derived

From the benchmark's raw cycle counts, 102400 B ÷ 32 B line = 3200 line fills **[derived]**:

- read: 403215 cycles / 3200 = **126 CPU cycles per 32-byte line fill** @ 80 MHz PSRAM
- write: 717694 / 3200 = **224 cycles** (≈1.8× read — consistent with write-allocate:
  fetch the line, then write it back = two PSRAM transactions)
- PSRAM→PSRAM: 1103614 / 3200 = 345 cycles vs. predicted 126 + 224 = 350. **Within 2%**,
  so the model holds.

126 CPU cycles at 240 MHz with an 80 MHz bus = 42 SPI clocks for a 16-SPI-clock
data burst; the balance is OPI command/address/latency phases plus arbitration.
That overhead is counted in **SPI clocks**, so it scales with the bus clock:

> **At this project's 40 MHz setting, one 32-byte read miss costs ≈ 42 × 6 = 252 CPU
> cycles ≈ 1.05 µs, and a write-allocate miss ≈ 448 cycles.** Sequential read
> throughput lands near 30 MB/s, write near 17 MB/s. **[derived]**

Every estimate in section 3 uses **252 cycles per random read miss**.

### 1.4 Sanity check against the project's own measurement

`README.md:104` reports the blocklist lookup at **64 µs** = 15,360 cycles at
240 MHz.

First, know exactly what that number spans. `dns_server.cpp:1406-1409` brackets
the histogram around **both** verdict calls:

```c
int64_t t_lk = esp_timer_get_time();
bool is_blk = blocklist_is_blocked(name, nlen) ||
              blocklist_custom_is_blocked(name, nlen);
hist_record(&s_h_lookup, esp_timer_get_time() - t_lk);
```

so for the common *not-blocked* case the `||` does not short-circuit and the
measurement also includes `blocklist_custom_is_blocked` — **a fourth
`xSemaphoreTake`/`Give` pair**, plus a `strlen` per custom entry per label
(`blocklist.c:130-133`). Note also that this is the **dns_task path only**: the L2
fast path calls `blocklist_is_blocked_nb` and never the custom check, so the L2
lookup is cheaper and is not instrumented at all.

Decomposing for a typical 3-label name (`www.example.com` → 2 searches; `com`
short-circuits on `domain_is_bare_tld`):

| Component | Cycles | µs |
| --- | --- | --- |
| ~26 PSRAM read misses (2 searches × ~13 misses) | ~6,550 | 27 |
| 3–4 × `xSemaphoreTake`/`Give` pairs — whitelist per label, plus custom rules (§3.7) | ~5,000 | 21 |
| 2 × `murmur3_32`, each calling `memcpy` per 4 bytes (§3.5) | ~1,400 | 6 |
| 2 × `domain_is_bare_tld` + `memchr` + call overhead | ~1,500 | 6 |
| the binary search's actual arithmetic (8 instr × ~40 iters) | ~350 | 1.5 |
| balance / measurement overhead | ~600 | 2.5 |

**The 64 µs is ~42% PSRAM stall and ~55% accidental call and lock overhead. It is
~2% arithmetic.** There is no ALU work in that budget for a vector unit to
accelerate. This decomposition is **[estimated]**, but it is consistent with the
independently derived 252-cycle miss cost and with the disassembly in §3.

### 1.5 The cache is shared between cores

ESP32-S3 TRM v1.8 §4.3.3.2, verbatim:

> ESP32-S3 has a dual-core-shared ICache and DCache structure... When the data bus
> of two cores initiate a request on DCache simultaneously, the arbiter determines
> which gets the access to the DCache first. When a cache miss occurs, the cache
> controller will initiate a request to the external memory. When ICache and DCache
> initiate requests on the external memory simultaneously, the arbiter determines
> which gets the access to the external memory first.

Consequence, and it kills one of the candidate ideas outright: **a dual-core
parallel sort does not double sort bandwidth.** Both cores contend for one
32 KB cache and one MSPI bus behind an arbiter. Splitting a bandwidth-bound sort
across cores buys the ~35% of per-miss time that is issue overhead at best, while
stealing bus bandwidth from `dns_task`'s binary searches on the other core — i.e.
it makes query latency worse during a reload, which is exactly the window that
already runs degraded.

Current cache config (`sdkconfig`): `CONFIG_ESP32S3_DATA_CACHE_32KB`,
`..._LINE_32B`, `..._8WAYS` = 1024 lines, 128 sets.

### 1.6 There is no software prefetch on this chip

This matters because "prefetch both binary-search children" is the standard trick
and it is **not available here**. Three independent confirmations:

1. `components/xtensa/esp32s3/include/xtensa/config/core-isa.h`:
   ```
   #define XCHAL_HAVE_PREFETCH      0   /* PREFCTL register */
   #define XCHAL_HAVE_PREFETCH_L1   0   /* prefetch to L1 dcache */
   #define XCHAL_PREFETCH_ENTRIES   0
   #define XCHAL_DCACHE_SIZE        0   /* D-cache size in bytes or 0 */
   ```
2. Probed this project's own assembler directly — `dpfr`, `dpfro`, `dpfw`,
   `dpfwo`, `dpfl`, `dhwb` are **all rejected** by
   `xtensa-esp32s3-elf-as` (see §2.1 for method).
3. Structural reason: the S3's LX7 cores have **no Xtensa-internal cache at all**.
   The cache is an Espressif block outside the CPU, between the bus and external
   memory, so the ISA prefetch instructions have nothing to address.

The hardware *does* have a preload/autoload engine (TRM §4.3.3.3: "Auto-Preload
means the hardware prefetches a piece of continuous data according to the current
address where the cache hits or misses"), reachable only via ROM
(`Cache_Start_DCache_Preload`, `Cache_Config_DCache_Autoload`,
`Cache_Enable_DCache_Autoload`). Both are **block-granular and require register
writes plus a completion poll**, so preloading one 32-byte midpoint probe costs
more than the 252-cycle miss it saves. The ROM header says *"Please do not call
this function in your SDK application"*, and
[epdiy discussion #289](https://github.com/vroland/epdiy/discussions/289) reports
`Cache_Start_DCache_Preload` is *"very picky about what ranges it gets called
with. Otherwise, the esp just crashes and reboots."*
A supported `cache_hal_preload()` exists but is **master-only** (added 2026-03-10,
absent from v6.0.2 — this project's IDF).

---

## 2. What the PIE unit actually is on this chip

### 2.0 Where it is documented

There is **no** separate "Xtensa ISA summary for ESP32-S3" PDF — a common wrong
assumption. Espressif folded the whole extension into **Chapter 1 of the ESP32-S3
Technical Reference Manual v1.8, "Processor Instruction Extensions (PIE)", pages
39–302**:

| § | Contents | pp. |
| --- | --- | --- |
| 1.3 | structure: QR bank, ALU, QACC, ACCX, address unit | 39–41 |
| 1.5.3 | **data format and alignment** — read this before writing any load | 48–49 |
| 1.6 | full instruction list (1.6.4 arithmetic, **1.6.5 comparison**, 1.6.6 logical, 1.6.7 shift) | 50–64 |
| 1.7 | **instruction performance** — data/resource/control hazards, Table 1.7-2 | 65–75 |
| 1.8 | per-instruction encodings + pseudocode, §1.8.1–1.8.220 | 76–302 |

The machine-readable ground truth for "what will assemble" is
[`xtensa-overlays/xtensa_esp32s3/binutils/bfd/xtensa-modules.c`](https://github.com/espressif/xtensa-overlays/blob/master/xtensa_esp32s3/binutils/bfd/xtensa-modules.c)
— **217 unique `ee.*` mnemonics** with operand encodings. That file is what GAS
itself uses, which is why the probe in §2.1 is authoritative.

The register file is **8 × 128-bit `q0`–`q7`** (TRM §1.3.1 / Table 1.5-1), plus
`SAR_BYTE`, `ACCX` (40-bit), `QACC_H`/`QACC_L` (160-bit each), `UA_STATE`,
`FFT_BIT_WIDTH`. (A widely-linked 2021 ESP-IDF issue comment says "6x 128-bit Q
registers" — that is wrong; don't cite it.)

### 2.1 Capability envelope, probed directly

Rather than trust secondhand ISA summaries, each candidate mnemonic was fed to
this project's own assembler
(`~/.espressif/tools/xtensa-esp-elf/esp-15.2.0_20251204/.../xtensa-esp32s3-elf-as.exe`)
and accepted/rejected recorded. Accepted forms produce real distinct 24-bit
encodings (generic `objdump` renders them `excw` because it doesn't carry the S3
TIE, but the bytes differ per instruction):

```
ee.vld.128.ip     q0, a2, 16   -> 0x830124      ee.andq   q3, q0, q1 -> 0xddb024
ee.vcmp.lt.s32    q1, q2, q3   -> 0x8eba04      ee.src.q  q0, q1, q2 -> 0xdc1304
ee.vmin.s32       q1, q2, q3   -> 0x8eba64      ee.vzip.32 q0, q1    -> 0xcc83c4
ee.ld.128.usar.ip q0, a2, 16   -> 0x810124      ee.vst.128.ip q2,a4,16 -> 0x9a0144
```

| Capability | Present? | Evidence |
| --- | --- | --- |
| 128-bit load/store `ee.vld.128.ip`, `ee.vst.128.ip` | **yes** | assembles |
| unaligned load path `ee.ld.128.usar.ip` + `ee.src.q` | **yes** | assembles |
| 64-bit half loads `ee.vld.l.64.ip` / `.h.64.ip` | **yes** | assembles |
| saturating add/sub `ee.vadds.s32` / `ee.vsubs.s32` (also s8/s16) | **yes** | assembles |
| **vector compare** `ee.vcmp.lt/gt/eq.s32` (also s16/s8) | **yes** | assembles |
| **vector min/max** `ee.vmin.s32`, `ee.vmax.s32` | **yes** | assembles |
| logic `ee.andq`, `ee.orq`, `ee.xorq`, `ee.notq` | **yes** | assembles |
| shifts `ee.vsl.32`, `ee.vsr.32` | **yes** | assembles |
| lane interleave `ee.vzip.32`, `ee.vunzip.32`, `ee.vzip.8` | **yes** | assembles |
| lane extract/insert `ee.movi.32.a`, `ee.movi.32.q` | **yes** | assembles |
| QACC accumulator + `ee.vmulas.s16.qacc`, `ee.srcmb.s16.qacc` | **yes** | assembles |
| 8/16-bit lane multiply `ee.vmul.s8/.s16/.u16` | **yes** | assembles |
| narrow indexed load `ee.ldxq.32` (see below) | **yes** | TRM §1.8.37 |
| **32-bit lane multiply** `ee.vmul.s32` | **NO** | rejected |
| **unsigned** compare/min/max `.u32` | **NO** | rejected |
| **non-saturating or unsigned add/sub** | **NO** | only `S8/S16/S32`, always saturating |
| **logical (zero-fill) right shift**; any 8- or 16-bit lane shift | **NO** | only `ee.vsr.32`/`ee.vsl.32`, arithmetic, 32-bit lanes |
| **select / blend** `ee.vsel` | **NO** | rejected |
| **`movemask` / `pmovmskb`** | **NO** | mask→scalar is `ee.movi.32.a` one lane at a time |
| **byte table lookup / arbitrary shuffle** `ee.vtbl`, `ee.shuffle` | **NO** | rejected; only `ee.vzip`/`ee.vunzip` |
| **wide gather / any scatter** | **NO** | see the `ee.ldxq.32` note below |

A correction worth stating explicitly, because the first draft of this analysis
got it wrong: **a narrow gather does exist.** `EE.LDXQ.32 qu, qs, as, sel4, sel8`
(TRM §1.8.37) takes one of eight 16-bit indices out of `qs`, computes
`as + index*4`, loads 32 bits, and deposits it into lane `sel4` of `qu`, with
`EE.STXQ.32` as the store counterpart. So a 4-way 32-bit gather costs 4
instructions. **It is still useless here, for two independent reasons:**

1. **The index is 16 bits, so it reaches `65536 × 4` = 256 KB from the base
   address.** The blocklist array is 3.28 MB. It physically cannot address the
   data structure this document is about.
2. Even in range, 4 instructions for 4 loads is no better than 4 scalar `l32i`.
   The only thing that would help a binary search is overlapping the *cache
   misses*, which is a memory-system property, not an instruction-encoding one.

Several other absences are individually fatal to the obvious ideas:

- **No `ee.vmul.s32`.** MurmurHash3 is built on 32×32→32 multiplies (`k1 *= c1`,
  `h1 = h1*5 + 0xe6546b64`). Without a 32-bit lane multiply there is no way to run
  four hashes in parallel in the vector unit. **SIMD Murmur is not expressible on
  this ISA.** (`ee.vmul.s16` cannot synthesise it cheaply — you'd need four
  16×16 partial products plus cross-lane carries, and there is no shuffle to
  align them.) Two further independent blockers, either of which alone would end
  it: Murmur's finaliser needs `h ^= h >> 16` — a **logical** right shift, and the
  only lane shift here is arithmetic — and `h1 = h1*5 + …` needs **non-saturating**
  addition, while `ee.vadds.s32` always saturates.
- **No unsigned 32-bit compare/min/max.** The blocklist keys are `uint32_t`
  hashes spanning the full range. Any vector comparison of them requires biasing
  by `^ 0x80000000` first (one `ee.xorq` per vector — cheap, but it means the
  "just use `ee.vmin.s32`" one-liner is wrong as written and would silently
  mis-order the top half of the key space).
- **No usable gather.** A binary search is a gather; `ee.ldxq.32` cannot reach
  past 256 KB.
- **No `movemask`.** Even when a `ee.vcmp.*` produces a lane mask, getting it into
  a scalar register to branch on costs four `ee.movi.32.a` (one lane at a time) or
  a store-and-reload. This is the tax that kills every "vectorise the string
  scan" idea in §3.6–3.8: you can compute the answer in one instruction and then
  spend four getting it somewhere a branch can use it.

Note `ee.vcmp.*` and `ee.vmin/vmax` **do** exist — the common claim that the S3
PIE has no comparison ops is wrong. TRM §1.8.81's pseudocode confirms the
NEON/SSE-style all-ones mask (`qa[7:0] = (qx[7:0]==qy[7:0]) ? 0xFF : 0`, per
lane). Signed only. Absent `ee.vsel`, a select is `notq`/`andq`/`andq`/`orq` —
four instructions, not one, and `notq` first because there is no ANDNOT.

**Alignment is a silent-corruption hazard, not a fault.** TRM §1.5.3:

> all access addresses in the extended instruction set are forced to be aligned,
> i.e., the lowest bits will be replaced by 0.

`EE.VLD.128.IP`'s pseudocode is literally `qu[127:0] = load128({as[31:4], 4{0}})`.
A misaligned pointer **does not trap** — it reads the wrong 16 bytes and keeps
going. The documented unaligned idiom is three instructions
(`ee.ld.128.usar.ip` sets `SAR_BYTE` from the low address bits, then
`ee.vld.128.ip`, then `ee.src.q` funnel-shifts the pair), and the `.QUP` /
`.LD.IP` fused forms exist to amortise it. Every buffer this project would want to
vectorise — HTTP chunk offsets, `tx + 42`, the driver's RX buffer — is at an
arbitrary offset, so that tax is unavoidable, and getting it wrong produces wrong
hashes rather than a crash.

### 2.2 The RTOS cost nobody mentions: PIE is coprocessor 3

This is the finding that should stop any plan to use `ee.*` on the query path.

From `components/xtensa/esp32s3/include/xtensa/config/tie.h`:

```
#define XCHAL_CP_NUM       2       /* number of coprocessors */
#define XCHAL_CP_MASK      0x09    /* bitmask of all CPs by ID  -> CP0 and CP3 */
#define XCHAL_CP0_NAME     "FPU"
#define XCHAL_CP0_SA_SIZE  72
#define XCHAL_CP3_NAME     "cop_ai"          <-- the PIE / vector unit
#define XCHAL_CP3_SA_SIZE  208               <-- 208 bytes of context
#define XCHAL_CP3_SA_ALIGN 16
```

So the vector unit is **coprocessor 3**, with a **208-byte context save area**.
`components/xtensa/include/xtensa_context.h` computes
`XT_CP_SIZE = 12 + XT_CP_SA_SIZE + XCHAL_TOTAL_SA_ALIGN` = 12 + 288 + 16 = **316
bytes**, and `port.c:196` (`uxInitialiseStackCPSA`) already carves that off every
task's stack — so **no extra stack is needed**, which is the one piece of good
news.

The runtime cost is the problem:

1. The first `ee.*` instruction a task executes takes a **coprocessor-disabled
   exception** into `_xt_coproc_exc` (`components/xtensa/xtensa_vectors.S:1006`).
2. That handler **takes a cross-core spinlock** (`_xt_coproc_owner_sa_lock`,
   see the comment at line 969: *"The array can be modified by multiple cores
   simultaneously... this spinlock is defined to ensure thread safe access"*).
3. Thereafter, every preemptive context switch that changes CP3 ownership saves
   and restores **208 bytes** — 52 word stores plus 52 word loads.
4. Per ESP-IDF's FreeRTOS docs (`docs/en/api-reference/system/freertos_idf.rst`),
   *"when a task utilizes FPU by using a `float` type in its call flow, IDF
   FreeRTOS will automatically pin the task to the current core it is running
   on"* and *"IDF FreeRTOS by default does not support the usage of FPU within an
   interrupt context."* The docs are written about CP0, but `_xt_coproc_exc` is
   generic over the coprocessor index — CP3 goes through the identical path, so
   **the same core-pinning and same ISR prohibition apply.**
5. And there is no escape hatch: `CONFIG_FREERTOS_FPU_IN_ISR` exists **only for
   CP0**. There is no equivalent option for CP3, and no Espressif documentation
   sanctioning `ee.*` in an interrupt handler. Treat PIE-in-ISR as unsupported.
6. That the enable sequencing is genuinely delicate is visible in Espressif's own
   code: `esp-dsp`'s `modules/support/mem/esp32s3/dsps_memcpy_aes3.S` carries a
   `TIE_ENABLE` switch that inserts a **dummy `ee.zero.qacc`** for the sole
   purpose of *"induc[ing] TIE context saving"*, with a comment about fixing the
   panic handler before `app_main` loads. Espressif hit a real early-boot
   coprocessor-enablement hazard here and had to paper over it.

Applied to this project: the L2 fast path runs in the Ethernet RX driver task at
2,200 qps. Putting `ee.*` in it would add a coprocessor exception plus a cross-core
spinlock on first use, add 416 bytes of memcpy to every subsequent context switch
of that task, and pin it to a core — **to accelerate a path that is not CPU-bound.**
That is a pure regression. The rule for this codebase: *if `ee.*` is ever used at
all, it is used only in `download_task`, never in `dns_task` and never in the L2
RX hook.*

### 2.3 How you would build it, if you did

For completeness, so this doesn't need re-deriving:

- The GCC in ESP-IDF v6.0.2 (`esp-15.2.0_20251204`) assembles `ee.*` mnemonics with
  **no special flags** — verified. They work in `.S` files and in `asm volatile`
  in C; this compiles clean at `-O2` and binds `%0..%2` to `a`-registers correctly:
  ```c
  asm volatile("ee.vld.128.ip q0, %0, 16\n"
               "ee.vld.128.ip q1, %1, 16\n"
               "ee.vadds.s32  q2, q0, q1\n"
               "ee.vst.128.ip q2, %2, 16\n"
               : "+r"(a), "+r"(b), "+r"(o) :: "memory");
  ```
- There is **no intrinsics header** in ESP-IDF for these (no `xt_pie.h`;
  `XCHAL_HAVE_*` has no PIE entry). Raw asm is the only route.
- **GCC does not model the `q` registers at all.** `asm volatile(... ::: "q0")`
  fails with `error: unknown register name 'q0' in 'asm'`. There is no constraint
  letter to bind a C variable to a Q register and **no way to declare one
  clobbered** — every Q register must be hardcoded in the asm string, and data
  moves in and out only through `a`-registers (`ee.movi.32.a`) or memory. Keep
  any `ee.*` sequence inside a single self-contained `asm volatile` block.
- **GCC does not auto-vectorise to PIE.** A GNU vector type compiles to scalar
  code — `typedef int v4si __attribute__((vector_size(16)));` returning `a + b`
  emits four plain `add.n` instructions at `-O2`, not one `ee.vadds.s32`. There is
  no "turn on a flag and get SIMD" path here: **every vector instruction in this
  codebase would have to be hand-written and hand-maintained.**
- **GCC will not emit a zero-overhead `LOOPNEZ` around a block containing inline
  asm.** You must write the `LOOPNEZ`/`LOOPGTZ` yourself inside the asm string —
  which matters, because TRM §1.7.3 says a taken branch flushes two pipeline
  stages (**2 dead cycles**), and short vector loops are branch-dominated.
- **Instruction-bus hazard:** `ee.vld.128.*` against an address mapped through the
  CPU's *instruction* bus (anything `IRAM_ATTR`, or a `const` array the linker
  parked in IRAM) faults with `LoadStoreError` — the instruction bus only does
  4-byte aligned words. Vector data must be forced to DRAM. This directly
  conflicts with the usual "put the hot buffer in IRAM" instinct.
- esp-dsp is the reference for calling conventions: `_ansi` = portable C,
  `_ae32` = ESP32/LX6 scalar asm, `_aes3` = **S3 PIE**, `_arp4` = P4 RISC-V.
  Real paths: `modules/dotprod/float/dsps_dotprod_f32_aes3.S`,
  `modules/dotprod/fixed/dspi_dotprod_s8_aes3.S`,
  `modules/fft/fixed/dsps_fft2r_sc16_aes3.S`,
  `modules/math/add/fixed/dsps_add_s16_aes3.S`. Boilerplate per file is just
  `.text` / `.align 4` / `.type name,@function` / `.global name` / `entry a1,48`,
  gated by a `<module>_platform.h` that keys off `CONFIG_IDF_TARGET_ESP32S3` plus
  `XCHAL_*`. Build integration is nothing special — the `.S` files are listed in
  `SRCS` alongside the `.c` files, no per-file options, no
  `-mtext-section-literals`; ESP-IDF supplies `-mlongcalls` globally (confirmed
  reaching `CMAKE_ASM_FLAGS` in v5.x; **not located in the v6 cmake refactor —
  verify with `idf.py -v build` if you ever need it**).
- **Correction to a claim in this document's first draft:** esp-dsp *does* ship two
  non-DSP integer kernels — `modules/support/mem/esp32s3/dsps_memcpy_aes3.S` and
  `dsps_memset_aes3.S`. There is still **no sort, search, string, hash, or CRC
  kernel**. esp-dsp is not currently a dependency of this project
  (`main/idf_component.yml` has only `espressif/w5500` and `espressif/mdns`), and
  §1.2 shows why its `memcpy` would not help even if it were: measured at
  **57.64 MB/s PSRAM→IRAM, versus 56.77 for plain libc `memcpy`.**
- Alignment: see §2.1 — forced, not faulted. The `ee.ld.128.usar.ip` + `ee.src.q`
  pair is the documented unaligned path, ~2 extra instructions per vector plus a
  priming load.

**Pipeline behaviour, if you ever do write a kernel** (TRM §1.7, Table 1.7-2):
all `ee.*` ops are **single-issue at 1 instruction/cycle**. Two hazards bite:
`ee.vld.128.*` defines its result at stage 2, so there is a **1-cycle load-use
bubble** — interleave an independent op between a load and its first use; and
`ee.vmul.*` has the same 1-cycle bubble on its result. MAC chains
(`ee.vmulas.*.qacc` / `.accx`) issue back-to-back with no stall. There is also a
hardware-resource hazard (§1.7.2): only sixteen 8-bit *or* eight 16-bit
multipliers exist, so overlapping multiplies contend.

**For calibration on what PIE is actually good at** — Espressif's own benchmark
numbers (`docs/esp_bm_results.csv`, S3 `_aes3` vs same-chip `_ansi`):
`dspi_dotprod_s8` 64×64 is **49×**; `dsps_dotprod_s16` N=256 is **9.3×**;
`dsps_fft2r_sc16` 1024-pt is **13.7×**. But `dsps_dotprod_f32` is only **3.0×** and
`dsps_fft2r_fc32` only **1.8×**. The pattern is unambiguous: **PIE pays off
enormously for 8- and 16-bit fixed-point MAC-shaped work, and modestly for
anything else.** This project's kernels are 32-bit key comparison and byte
classification — the far end of that spectrum from where the 49× lives.

---

## 3. Candidate kernels

### 3.1 The table

| # | Kernel | Where it runs | Bound by | Realistic speedup from **SIMD** | Best **non-SIMD** speedup | End-to-end visibility | Risk |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `radix_sort` histogram pass | download_task | **PSRAM bandwidth** | **1.0×** (no scatter, no SIMD histogram) | 4 passes → 1 fused pass: **−16% total sort** | reload only; sort is ~2 s of a multi-minute fetch | low |
| 2 | `radix_sort` scatter pass | download_task | **PSRAM bandwidth** (write-allocate: 2 transactions per line) | **1.0×** (scatter has no vector form on this ISA) | none safe — see §3.2 trap | as above | — |
| 3 | `fold_sorted_chunk` backward merge | download_task | **PSRAM bandwidth** | **1.0×** (variable per-step advance; no vector merge without gather) | negligible | ~0.2 s per feed | — |
| 4 | `sort_dedup` neighbour collapse | download_task | **PSRAM bandwidth** | **1.0×** | hoist `a[u-1]` into a register (§3.4): ~5% of this pass | tiny | trivial |
| 5 | `is_blocked_impl` binary search | dns_task + L2 RX hook | **PSRAM latency** (~13 misses × 252 cyc) | **1.0×** (a search *is* a gather; PIE has none) | 12-bit bucket index: **~2×** on the search | 27 µs of a 1,800 µs query = **1.5%** | med |
| 6 | `murmur3_32` | both paths + ~1 M×/reload | **call overhead**, then compute | **not expressible** (no `ee.vmul.s32`) | delete the per-4-byte `memcpy` call: **~2–3×** on the hash | ~1.2 s/reload; ~6 µs/query | **low** |
| 7 | `domain_normalize` tolower loop | both paths + ~1 M×/reload | **call overhead** (`tolower` per byte) | ~1.3× at best, and only with a 4-instr synthesised select | branchless `\|0x20`: **~10×** on the loop | **~3.7 s/reload**; ~3.7 µs/query | **trivial** |
| 8 | `domain_extract_token` byte scan | download_task, ~1 M×/reload | compute, internal RAM | ~1.5× theoretical, negative in practice (§4) | fuse the 3 scans into 1 | ~1 s/reload | med |
| 9 | whitelist + custom-rules checks | dns_task + L2 RX hook | **FreeRTOS mutex** (3–4 take/give pairs) | 1.0× | skip the take when the count is 0: **~21 µs/query** | 1.2% of a query | low |
| 10 | L2 reply frame build (`memcpy` ×5, ~72 B) | L2 RX hook | neither — too small | 1.0× (setup + CP3 exception ≫ 72 B) | none | 0% | — |
| 11 | `dns_cache_l2_get` reply copy from PSRAM | L2 RX hook | **PSRAM bandwidth** | **1.0×** — §1.2 proves it | none | ~4 µs | — |
| 12 | IP header checksum loop | L2 RX hook | compute, 20 B | 1.0× (20 bytes) | none | ~0% | — |
| 13 | `on_domain_line` prefix dedup search | download_task, ~780 k×/reload | **PSRAM latency** | **1.0×** | bucket index (§5.7): **~2.5×** | **~6.6 s/reload** — largest single CPU item | med |

### 3.2 Why the radix sort is bandwidth-bound, with the arithmetic

For the measured peak of n = 778,569 entries (`blocklist.h:25`), array = 3.11 MB.
Per 8-bit pass **[derived]**:

| Traffic | MB |
| --- | --- |
| histogram read of `a[]` | 3.11 |
| scatter read of `a[]` | 3.11 |
| scatter **write-allocate** read of `b[]` | 3.11 |
| scatter writeback of `b[]` | 3.11 |
| **per pass** | **12.45** |
| **× 4 passes** | **49.8** |

At the §1.3 derived 40 MHz rates (30 MB/s read, 17 MB/s write): reads
37.3 MB / 30 = 1.24 s, writes 12.4 MB / 17 = 0.73 s → **≈ 1.97 s**. That lands
inside the reported 0.5–2.5 s window, which is a good sign the model is right.

Now the compute side. The shipped disassembly of `radix_sort`'s scatter inner
loop (`.text.radix_sort`, offsets 0x5c–0x75) is **eight instructions**:

```
l32i.n  a14, a11, 0      ; load a[i]
addi.n  a11, a11, 4
ssr     a12              ; shift amount = current digit
srl     a8, a14
extui   a8, a8, 0, 8     ; (a[i] >> shift) & 0xFF
addx4   a8, a8, a1       ; &cnt[digit]
l32i.n  a9,  a8, 0
addi.n  a15, a9, 1
addx4   a9,  a9, a3      ; &b[cnt[digit]]
s32i.n  a15, a8, 0
s32i.n  a14, a9, 0
```

≈ 11 cycles of work per word, against ≈ **12 bytes of PSRAM traffic per word per
pass** which at 30/17 MB/s costs ≈ 95 cycles. **Memory outweighs compute ~9:1.**
This is not a close call, and SIMD only makes the 11 smaller.

**Two SIMD ideas specifically, and why both fail:**

- *Vectorised histogram* — extract four digit bytes per `ee.vld.128.ip`. But the
  four `cnt[digit]++` updates are four dependent read-modify-writes to four
  unpredictable addresses. There is no SIMD histogram, and the only indexed
  load/store pair (`ee.ldxq.32`/`ee.stxq.32`) moves **one lane per instruction** —
  so four increments cost four loads, four adds and four stores either way, i.e.
  exactly the scalar code. You save the shift/mask (2 of 11 cycles) on a kernel
  where memory costs 95. Net ≈ 0.
- *Bitonic sorting network via `ee.vmin.s32`/`ee.vmax.s32`/`ee.vzip.32`* — the ops
  genuinely exist (§2.1), and this is the one place PIE has the right primitives.
  But a merge sort built on vector base cases does **log n** memory passes where
  radix does 4, on a kernel that is 90% memory. It would be *slower*, and it
  would need the `^0x80000000` bias because there is no unsigned compare.

**A trap worth naming, because it is the obvious "optimisation":** switching to
3 passes of 11-bit digits (33 ≥ 32 bits, counters 3 × 2048 × 4 B = 24 KB) looks
like a free 25% traffic cut. It is a **severe regression**. The scatter maintains
one open write stream per digit value; 2048 streams against a **1024-line**
32 KB / 8-way / 128-set cache means every single 4-byte write becomes a fresh
write-allocate read + writeback of a 32-byte line — **16× write amplification.**
The digit width here is bounded by cache geometry, not by counter memory.
256 streams against 1024 lines is already close to the limit; **8-bit digits are
correct.**

**What does work** (kernel #1): the four histograms are computed in four separate
reads of `a[]`, but all four digits of a word are available from one load. Fusing
them into a single pass that fills `cnt[4][256]` (4 KB, still stack-sized —
the current frame is already `entry a1, 0x420`) removes 3 × 3.11 MB of reads =
**0.31 s, ≈16% of the sort** **[derived]**. Same algorithm, same digit width,
contained entirely inside `radix_sort()`.

### 3.3 Why the merge can't be vectorised

`fold_sorted_chunk`'s backward merge (`blocklist.c:346-350`):

```c
while (i > 0 && j > 0)
    a[--w] = (a[i - 1] > b[j - 1]) ? a[--i] : b[--j];
```

Each step advances **one** of two cursors, chosen by the comparison. A vector
version needs to compare 4 pairs, then advance each cursor by a data-dependent
amount and gather the selected elements — that requires a shuffle indexed by a
runtime mask (`pshufb`/`vtbl` class) and a gather. §2.1: **the S3 PIE has
neither.** There is no formulation of a vector merge on this ISA.

It is also bandwidth-bound anyway: `2 × (p + m)` words of traffic, ≈ 6.4 MB for
p = 700 k, m = 100 k → ~0.2 s. Descending traversal still yields 8 elements per
32-byte line, so the direction costs nothing.

### 3.4 `sort_dedup`: one free scalar fix

The shipped `.text.sort_dedup` collapse loop reloads `a[u-1]` from memory on every
iteration (offset 0x52, `l32i.n a12, a10, 0`, preceded by an `addx4`) because GCC
cannot prove the write to `a[u]` doesn't alias the read of `a[u-1]` in the same
array. Keeping the last-kept value in a local removes a load and an address
computation per element. It is a cache hit (same line just written), so the win is
small — but it is two lines and zero risk.

### 3.5 `murmur3_32` calls `memcpy` once per four bytes

This is the most surprising thing in the shipped binary. `main/murmur3.c:16`:

```c
memcpy(&k1, data + i * 4, 4);
```

Disassembly of the **release `-O2`** object, `.text.murmur3_32` offsets 0x1e–0x2a:

```
mov.n   a11, a7          ; src
movi.n  a12, 4           ; n = 4
mov.n   a10, a1          ; dst = a stack slot
l32r    a8,  <literal>
callx8  a8               ; <-- a real function call
l32i.n  a8,  a1, 0       ; reload k1 from the stack
```

and the relocation record confirms the target:

```
00000024 R_XTENSA_ASM_EXPAND  memcpy
```

**GCC emits a genuine `callx8` to `memcpy`, plus a stack round-trip, for every
four bytes of every domain name hashed.** The reason is structural, not a bug:
Xtensa is `STRICT_ALIGNMENT`, `data` has unknown alignment, so GCC cannot fold
the copy into a single `l32i` — and rather than expanding four byte loads inline
it defers to the library.

Cost per block: the call itself (with a register-window rotate that can trigger a
window-overflow spill), newlib's alignment dispatch, a 4-byte byte loop, the
return, and a stack reload. Conservatively **40–80 cycles** where an inline
little-endian byte assembly is ~8 **[estimated]**. For a 30-character name (7
blocks) that is **280–560 wasted cycles per hash**.

- Query path: 2–3 hashes → **~6 µs of the 64 µs**.
- Load path: ~1 M hashes → **~1.2 s per reload** **[derived]**.

The fix is to assemble the word explicitly:

```c
uint32_t k1 = (uint32_t)data[i*4]       | ((uint32_t)data[i*4+1] << 8)
            | ((uint32_t)data[i*4+2] << 16) | ((uint32_t)data[i*4+3] << 24);
```

> ⚠️ **Hash stability is load-bearing.** `/sdcard/blocklist.bin` stores hashes, not
> domains, and `blocklist_load_sd` trusts them. Any replacement **must reproduce
> the little-endian semantics of the original `memcpy` bit-for-bit**, or every warm
> boot silently serves a list keyed to a different hash function. The form above
> does; a `be32`-style assembly does not. Verify with a fixed test vector before
> and after.

### 3.6 `domain_normalize` calls `tolower()` once per byte

`main/domain.c:14`. Shipped `.text.domain_normalize` offsets 0x39–0x49:

```
add.n   a8, a4, a3
l8ui    a10, a8, 0
l32r    a8,  <literal>
callx8  a8                ; <-- call tolower(), per byte
add.n   a8, a2, a3
s8i     a10, a8, 0
addi.n  a3, a3, 1
bltu    a3, a5, <loop>
```

relocation: `0000003e R_XTENSA_ASM_EXPAND tolower`.

newlib's `tolower` is not a macro here — it is an out-of-line call that dereferences
the locale ctype table. Call + body ≈ 25–40 cycles per byte against ~3 for a
branchless form **[estimated]**:

```c
/* ASCII-only, branchless; identical result to tolower() for A-Z, identity elsewhere */
unsigned c = (unsigned char)src[i];
buf[i] = (char)(c + (((unsigned)(c - 'A') < 26u) << 5));
```

- **Load path: ~1 M lines × ~30 bytes × ~30 cycles ≈ 900 M cycles ≈ 3.75 s per
  reload.** This is the **single largest CPU consumer of the entire reload** —
  larger than the radix sort.
- Query path: once per query, ~3.7 µs.

`custom_parse` (`blocklist.c:87`) has the same pattern but runs ≤256 times, so it
does not matter.

### 3.7 The whitelist mutex runs even when the whitelist is empty

`.text.blocklist_whitelist_contains` calls `xQueueSemaphoreTake` **first**
(offset 0x0e), and only the split-out `$part$0` then tests `s_wl_count == 0`
(offset 0x0d, `beqz.n a6`) and returns. So with no whitelist entries — the default
— every label of every query pays a full FreeRTOS semaphore take **and** give,
including `taskENTER_CRITICAL` on a dual-core port (a real cross-core spinlock),
for a function that is about to return `false` unconditionally.

`is_blocked_impl` calls `wl_check` **per suffix label**, so a 3-label name pays
2–3 take/give pairs. `blocklist_custom_is_blocked` (`blocklist.c:124`) has the
identical shape — bounded take, then `if (s_custom_count != 0)` — and adds a
fourth pair on every not-blocked query (§1.4). **[estimated] ~21 µs of the 64 µs.**

Also visible in `$part$0`: `strlen` and `memcmp` are both **out-of-line calls per
whitelist entry per label** (offsets 0x1a and 0x29). At the `WHITELIST_MAX` of 64
that is up to 192 `strlen` + `memcmp` calls per query; the custom-rules loop
(`blocklist.c:131`) does the same with `CUSTOM_RULES_MAX` of 256. Caching each
entry's length alongside it would remove the `strlen` half of both.

A relaxed atomic read of the count before taking the mutex fixes the common case
for both. Note `s_wl_count` and `s_custom_count` are currently plain `uint32_t`
written under the mutex; each would need to become `_Atomic uint32_t` with a
relaxed load — correctness-neutral on this architecture, but worth writing
explicitly rather than relying on it.

### 3.8 The load path's real hot spot: `on_domain_line`'s prefix search

`blocklist.c:246-258` — for every line of every **extra** feed, a full binary
search over the sorted prefix in PSRAM. That is ~780 k searches over an array
growing from 266 k to 778 k entries: ~19 probes each, of which perhaps 8 miss
(the top ~8 levels stay resident under a million repeated searches; the last ~3
levels fall inside one 32-byte line).

8 misses × 252 cycles = 2,016 cycles ≈ 8.4 µs × 780 k = **≈ 6.6 s per reload
[estimated]** — the largest single item in the reload's CPU budget after
§3.6.

It is pure PSRAM latency. SIMD is irrelevant (it's a gather). §5.7 has the fix.

### 3.9 Reload CPU budget, assembled

| Item | Est. cycles/reload | Seconds |
| --- | --- | --- |
| `domain_normalize` → `tolower` calls (§3.6) | ~900 M | **3.75** |
| `on_domain_line` prefix binary search (§3.8) | ~1,570 M | **6.6** |
| `radix_sort` (§3.2) | ~470 M | **1.97** |
| `murmur3_32` → `memcpy` calls (§3.5) | ~290 M | **1.2** |
| `domain_extract_token` 3 scans (§4) | ~240 M | **~1.0** |
| per-feed `fold_sorted_chunk` merges | ~190 M | **~0.8** |
| **total** | | **≈ 15 s** |

**[estimated]**, against a fetch the README describes as "multi-minute". Because
`on_domain_line` runs **synchronously inside the `esp_http_client` event handler**,
this CPU time is *serialised with*, not overlapped with, the download — it directly
depresses the KB/s figure `http_fetch.c:43` already logs. Halving it is a real but
not transformative reload speedup (~7% of a 150 s load).

---

## 4. Explicit "not worth it" list

One line each, so nobody re-opens these.

**SIMD / PIE ideas**

- **SIMD MurmurHash3** — three independent blockers: no 32-bit lane multiply (`ee.vmul.s32`), no logical right shift for `h ^= h >> 16` (lane shifts are arithmetic only), and no non-saturating add for `h1*5 + 0xe6546b64` (§2.1). Not expressible.
- **Vectorised radix histogram** — no SIMD histogram, no scatter; the four counter increments stay scalar and the kernel is 9:1 memory-bound anyway (§3.2).
- **Vectorised radix scatter** — a scatter is exactly what this ISA lacks.
- **Bitonic / sorting-network sort via `ee.vmin.s32`/`ee.vmax.s32`** — the ops exist, but merge-sort structure costs log n memory passes vs radix's 4, on a bandwidth-bound kernel. Strictly worse, and needs a `^0x80000000` bias because there is no unsigned compare.
- **Vector merge in `fold_sorted_chunk`** — requires mask-indexed shuffle + gather; neither exists (§3.3).
- **SIMD binary search** — a binary search *is* a gather. The only indexed load, `ee.ldxq.32`, has a 16-bit index and so cannot reach past 256 KB of a 3.28 MB array (§2.1).
- **SIMD `tolower` in `domain_normalize`** — 16-byte vectors on ~30-byte strings at arbitrary alignment (`ee.ld.128.usar.ip` + `ee.src.q` per vector), and with no `ee.vsel` the select costs 4 ops. Branchless scalar `|0x20` gets ~10× for two lines of C (§3.6). The SIMD version is more code, more risk, and slower.
- **SIMD byte-classify in `domain_extract_token`** — same alignment tax; plus the loops have early-exit `return 0` semantics, and with **no `movemask`** getting a compare result somewhere a branch can use it costs four `ee.movi.32.a` per vector (§2.1). Fusing the three scalar scans into one is the better ~1.5×.
- **Vectorised `memcpy` in the L2 frame build** — copies are ~72 bytes at offsets 42/14/6, never 16-byte aligned; setup dominates, and §2.2's coprocessor cost lands on the 2,200 qps path.
- **Vectorised `memcpy` from the PSRAM reply cache** — §1.2 measured 128-bit PIE and 32-bit loads at the *same* 58.13 MiB/s from PSRAM. Nothing to gain, by measurement.
- **PIE anywhere in `dns_task` or the L2 RX hook** — CP3's 208-byte lazy context, the coprocessor-disabled exception, the cross-core `_xt_coproc_owner_sa_lock`, and automatic core pinning (§2.2) are a net regression on a path that is not CPU-bound.
- **Adding esp-dsp as a dependency** — it ships float/DSP kernels only; there are no integer sort, search, or memcpy kernels to lift (§2.3).

**Non-SIMD ideas that also fail**

- **Software prefetch of binary-search children** — `XCHAL_HAVE_PREFETCH 0`; `dpfr`/`dpfw`/`dpfro`/`dpfwo` are rejected by this project's own assembler. The instructions do not exist on this chip (§1.6).
- **`Cache_Start_DCache_Preload` per probe** — block-granular, needs register writes plus a completion poll, suspends autoload, and is documented crash-prone with bad ranges. Costs more than the 252-cycle miss it hides (§1.6).
- **Eytzinger / BFS layout for the search array** — the classic 2–3× win, but: it destroys the sorted order that `radix_sort`, `fold_sorted_chunk`, `sort_dedup`, the SD snapshot format, and `reload_diff_vs_sd`'s merge-walk all require, so it needs a *third* 3.28 MB PSRAM copy. `blocklist.h:33` already puts the two ping-pong buffers at 6.56 MB of 8 MB with ~1.1 MB left for mbedTLS. **It does not fit.** And the payoff lands on a path that is 1.5% of query latency.
- **11-bit radix digits (3 passes)** — 2048 write streams against a 1024-line cache = 16× write amplification. Severe regression (§3.2).
- **Dual-core parallel sort** — the DCache and the MSPI bus are shared behind an arbiter (TRM §4.3.3.2); a bandwidth-bound kernel doesn't scale, and it steals bus bandwidth from `dns_task` during the exact window the list is already degraded (§1.5).
- **64-byte cache lines (`CONFIG_ESP32S3_DATA_CACHE_LINE_64B`)** — helps sequential streaming by ~45%, but **doubles** the bytes moved per random binary-search probe. Wrong direction for the dominant access pattern.
- **`CONFIG_SPIRAM_FETCH_INSTRUCTIONS` / `SPIRAM_RODATA` / `XIP_FROM_PSRAM`** — moves ICache misses onto the same octal bus that DCache is already saturating, behind the same arbiter. Net loss for a latency-sensitive path. Keep hot code in flash-backed ICache or `IRAM_ATTR`.
- **`CONFIG_SPIRAM_SPEED_120M`** — requires `IDF_EXPERIMENTAL_FEATURES`; the Kconfig warns PSRAM access *"will crash randomly"* after a ~20 °C swing from boot temperature. Not acceptable for an always-on appliance that also serves as the LAN's only resolver.
- **Cache-line-aware linear-scan tail in the binary search** — once the range is ≤8 elements it is already inside one 32-byte line, so those probes are already hits. There is nothing to save.
- **Making the merge branchless with `movnez`/`moveqz`** — the kernel is bandwidth-bound; branch cost is hidden behind the misses.
- **Optimising the IP checksum loop** — 20 bytes, ~0% of anything.

---

## 5. Recommendation

Ranked by estimated real-world impact per unit of risk. Items 1–4 are the ones
worth doing.

### 5.1 — `CONFIG_SPIRAM_SPEED_80M`  ← the single biggest win in this document

`sdkconfig.defaults:6` currently selects the ESP-IDF **default** of 40 MHz. The
board is F4R8 (quad DIO flash + octal PSRAM), flash is at 80 MHz SDR
(`CONFIG_ESPTOOLPY_FLASHFREQ_80M`, `..._FLASHMODE_DIO`). ESP-IDF's F4R8
compatibility table (`docs/en/api-guides/flash_psram_config.rst`) puts **flash
80 MHz SDR in group B** and **PSRAM 80 MHz DDR in group B**, with the rule
*"Flash mode in group B/C works with PSRAM mode in group B/C/D."*

> **80 MHz octal PSRAM is a documented, supported, non-experimental combination
> with this exact flash configuration.** There is no Kconfig dependency blocking it.

Expected effect — everything in §1.3 halves **[derived]**:

| | at 40 MHz | at 80 MHz |
| --- | --- | --- |
| random read miss | 252 cyc / 1.05 µs | 126 cyc / 0.53 µs |
| sequential read | ~30 MB/s | ~58 MB/s |
| `radix_sort` (n = 778 k) | ~1.97 s | **~1.0 s** |
| binary-search memory component | ~27 µs | **~14 µs** |
| `on_domain_line` prefix search total | ~6.6 s | **~3.3 s** |

One line. No code change. It is the answer to "the owner asked about SIMD but
wants speed."

**Validation before trusting it:** `CONFIG_SPIRAM_MEMTEST=y` is already set, so a
boot-time PSRAM test runs on every start — watch for it passing. Then soak: the
existing `/metrics` `lookup` histogram (`dns_server.cpp:33`, `s_h_lookup`) gives a
free A/B on the binary search, and `http_fetch.c:43`'s KB/s log gives one on the
reload. Signal integrity at 80 MHz is board-dependent; if the memtest fails or
the list develops corruption, revert. This is the only item here with a hardware
risk, and it is a cheap one to falsify.

### 5.2 — Delete the per-byte `tolower()` call (§3.6)

Two lines in `domain.c`. **~3.75 s off every reload** and ~3.7 µs off every query.
Zero risk, ASCII-only semantics are already assumed everywhere else in the file
(`tok_char_ok` hardcodes `a-z`/`A-Z`).

### 5.3 — Delete the per-4-byte `memcpy()` call in `murmur3_32` (§3.5)

**~1.2 s off every reload**, ~6 µs off every query. Trivially small diff.
**Must be bit-identical** — see the warning in §3.5; add a fixed test vector
first (`domain_hash("example.com", 11)` before and after) because
`/sdcard/blocklist.bin` is keyed to this function.

### 5.4 — Skip the mutex when the list behind it is empty (§3.7)

**~21 µs off every query** — the largest query-path item after the PSRAM stalls.
Requires making `s_wl_count` and `s_custom_count` `_Atomic uint32_t` and doing a
relaxed load before `xSemaphoreTake`.

Two constraints this must respect:

- It touches shared policy code, so it lands on **both** verdict paths at once
  (`blocklist_whitelist_contains` and `blocklist_whitelist_contains_nb` wrap the
  same `wl_contains_locked`). That is correct and desirable — but it means the
  change must be reasoned about for the L2 RX hook as well as `dns_task`.
- Nothing here can block `dns_task`: it strictly *removes* a blocking call from
  the hot path. The fail-open/fail-closed semantics of the existing bounded takes
  are unchanged, because an empty list returns `false` either way — which is
  exactly what a timed-out take already returns.

When measuring the result, remember §1.4: the `lookup` histogram spans the custom
check too, so this fix moves that histogram more than a whitelist-only reading
would suggest.

### 5.5 — Fuse the four radix histogram passes into one (§3.2)

**~16% off the sort**, contained entirely inside `radix_sort()`. Keep the digit
width at 8 bits — see the trap in §3.2.

Sizing note, since this is the one item that touches a stack: `radix_sort`'s
current frame is `entry a1, 0x420` (1,056 bytes) for `cnt[256]`. `cnt[4][256]`
makes it ~4.1 KB. `download_task` has a 24 KB stack
(`dns_sink.cpp:1215`, pinned to core 0) and already logs
`uxTaskGetStackHighWaterMark` at `dns_sink.cpp:854` — check that line's output
before and after. Alternatively make the counters `static`, which costs nothing
on the stack and is provably safe here: `blocklist_load()` is called **only** from
`download_task` (`dns_sink.cpp:837, 844, 894, 903`), so `radix_sort` has exactly
one caller task and no reentrancy.

### 5.6 — Consider `CONFIG_ESP32S3_DATA_CACHE_64KB`

Doubles the cache to 2048 lines. Two effects: one more resident level of the
binary-search tree, and much more room for the radix scatter's 256 open write
streams. Cost: **32 KB of internal DRAM**, taken from a heap that
`sdkconfig.defaults` already guards with `SPIRAM_MALLOC_RESERVE_INTERNAL=32768`.
**Measure free internal heap first.** One line, easy to revert, but unlike 5.1 the
payoff is not certain.

### 5.7 — Only if the load path needs to be faster: a bucket index

The one algorithmic change worth describing, because it is the only structure
that helps §3.8's 6.6 s **without** breaking the sorted layout everything else
depends on.

MurmurHash3 outputs are uniform over the full `uint32` range. So the top 12 bits
of a key place it in one of 4096 equal-sized regions of a sorted array of those
keys. Keep a `uint32_t start[4096]` in **internal** SRAM giving the array index
where each 12-bit prefix begins; a search then starts already bracketed to
`n/4096 ≈ 190` entries.

```
probes: ~20  ->  ~8      (one internal-SRAM lookup replaces the first 12 levels)
misses: ~13  ->  ~5      (the 12 levels removed are exactly the scattered,
                          always-missing ones; the surviving 190-entry window is
                          760 bytes = 24 lines, and its last 3 levels share one line)
```

- **Build cost:** one sequential pass over the sorted array after each publish
  (3.11 MB read ≈ 0.1 s at 40 MHz) — noise against a multi-minute reload. Also
  needed after `blocklist_load_sd`.
- **Memory:** 16 KB per buffer × 2 (ping-pong) = **32 KB internal DRAM**. This is
  the real cost, and it competes directly with 5.6 — do not do both without
  measuring the internal heap.
- **The array stays plain sorted**, so `radix_sort`, `fold_sorted_chunk`,
  `sort_dedup`, `blocklist_save_sd`/`load_sd`, and `reload_diff_vs_sd` are all
  untouched. That is the whole reason to prefer this over Eytzinger.
- **Publish safety:** keep `s_index[0]`/`s_index[1]` paired with `s_buf[0]`/`s_buf[1]`.
  The reader derives which to use from the pointer it already acquired
  (`arr == s_buf[0] ? s_index[0] : s_index[1]`), so the existing single
  release-store on `s_live` orders the index writes too — no second atomic, no
  new race. The worst case is the same bounded staleness `blocklist.c:558-567`
  already documents: a stale index paired with a fresh count yields at most one
  wrong answer, never an out-of-bounds read, because every index value is
  ≤ `BLOCKLIST_CAPACITY` and both buffers are permanently `CAPACITY`-sized.
- **Zero-memory alternative**, if 32 KB is too expensive: since the keys are
  uniform, `mid0 = (uint32_t)(((uint64_t)h * n) >> 32)` estimates the position with
  a single `mull`/`muluh` pair and no table, then bisect a bounded window around
  it. Cheaper in RAM, weaker in the distribution's tail, and it needs a hard
  iteration cap with a fallback to plain bisection so a pathological key cannot
  degrade to O(n) on the query path.

**Do this only for the load path's benefit.** On the query path it takes 64 µs to
~39 µs — which is 1,800 µs to 1,775 µs end to end. See below.

### 5.8 The Amdahl statement, plainly

The blocked path saturates at **~2,200 qps**, and `README.md:108-121` already
establishes the limit is the W5500-over-SPI bus (~405 µs/frame, two frames per
query), not the CPU. The blocklist lookup is **64 µs of a 1,800 µs query**.

> **Taking the whole lookup to zero — not 2× faster, *zero* — would move the
> measured p50 from 1.8 ms to about 1.74 ms, and would not meaningfully move the
> 2,200 qps ceiling, which `README.md:108-121` establishes is set by the SPI bus
> and not by the CPU.** Every query-path optimisation in this document is
> effectively invisible end-to-end. They buy CPU headroom, not throughput or
> latency.
>
> The only lever on the blocked-path ceiling is the Ethernet transport. Nothing
> in the CPU, the memory layout, or the vector unit touches it.

Where CPU time *is* measurable is the reload: ~15 s of CPU (§3.9) serialised
inside the HTTP event handler. Items 5.1–5.3 and 5.5 together take that to
roughly **6 s**, and 5.7 to roughly **4 s**. On a ~150 s reload that is a ~7%
improvement in wall-clock — real, worth having for the near-zero risk of 5.2 and
5.3, but not transformative either.

### 5.9 Final answer to the question asked

**The PIE / `ee.*` unit cannot help this workload.** Not because it is weak — it
genuinely delivers **5×** on internal-RAM `memcpy` and up to **49×** on Espressif's
own int8 dot-product benchmark, and it has a better op set than usually credited,
including real vector compare, min/max, and a narrow indexed load (§2.1). It
cannot help *here* because:

1. every kernel over the big arrays is bound by a 40 MHz octal PSRAM bus, and
   128-bit PIE loads from PSRAM measure *identically* to 32-bit loads — same
   58.13 MB/s, and Espressif's own hand-written `dsps_memcpy_aes3` measures no
   better than libc `memcpy` there (§1.2);
2. the kernels that *are* genuinely compute-bound need capabilities this unit
   lacks: a 32-bit lane multiply, a logical right shift and a non-saturating add
   (Murmur), or a byte shuffle and a `movemask` (the parsers) (§2.1);
3. the one gather instruction, `ee.ldxq.32`, has a 16-bit index and cannot reach
   past 256 KB of a 3.28 MB array (§2.1);
4. anything vectorised on the query path pays CP3's 208-byte lazy context switch,
   a coprocessor exception, a cross-core spinlock, and forced core pinning — on a
   path that is not CPU-bound to begin with (§2.2);
5. and there is no cheap way in: GCC neither auto-vectorises nor models the `q`
   registers, so every instruction would be hand-written and hand-maintained
   (§2.3).

The shape of the win PIE is built for is 8- and 16-bit fixed-point MAC work with
aligned, internal-RAM operands. This project's hot kernels are 32-bit key
comparison against a 3 MB PSRAM array and byte classification of short unaligned
strings — about as far from that as an embedded workload gets.

**Do §5.1 first.** It is one line, it is a documented-supported configuration, and
it is worth more than every hand-written assembly kernel this codebase could
plausibly contain.

---

## Appendix: reproducing the ISA probe

No hardware needed; this uses the toolchain already installed for the project.

```sh
AS=~/.espressif/tools/xtensa-esp-elf/esp-15.2.0_20251204/xtensa-esp-elf/bin/xtensa-esp32s3-elf-as
probe() { echo "$1" > /tmp/p.S; "$AS" -o /tmp/p.o /tmp/p.S >/dev/null 2>&1 \
          && echo "OK     : $1" || echo "ABSENT : $1"; }

probe "ee.vld.128.ip q0,a2,16"       # OK
probe "ee.vcmp.lt.s32 q0,q1,q2"      # OK   - vector compare DOES exist
probe "ee.vmin.s32 q0,q1,q2"         # OK
probe "ee.vmul.s32 q0,q1,q2"         # ABSENT - kills SIMD Murmur
probe "ee.vmin.u32 q0,q1,q2"         # ABSENT - signed only; needs ^0x80000000 bias
probe "ee.vsel q0,q1,q2"             # ABSENT - synthesise from andq/notq/orq
probe "ee.vtbl q0,q1,q2"             # ABSENT - no byte shuffle
probe "dpfr a2,0"                    # ABSENT - no software prefetch on this chip
```

And to reproduce the two call-overhead findings from the shipped release build,
without rebuilding anything:

```sh
OBJDUMP=~/.espressif/tools/xtensa-esp-elf/esp-15.2.0_20251204/xtensa-esp-elf/bin/xtensa-esp-elf-objdump
cd build/esp-idf/main/CMakeFiles/__idf_main.dir
$OBJDUMP -r murmur3.c.obj | grep memcpy      # R_XTENSA_ASM_EXPAND memcpy
$OBJDUMP -r domain.c.obj  | grep tolower     # R_XTENSA_ASM_EXPAND tolower
$OBJDUMP -d -j .text.radix_sort blocklist.c.obj
$OBJDUMP -d -j .text.is_blocked_impl blocklist.c.obj
```

## Appendix: sources

- **ESP32-S3 TRM v1.8, Chapter 1 "Processor Instruction Extensions (PIE)", pp. 39–302** — the authoritative `ee.*` ISA reference. §1.3 structure (8 × 128-bit QR; sixteen 8-bit / eight 16-bit multipliers and *no* 32-bit multiplier), §1.5.3 forced alignment, §1.5.4 saturation (only `VADDS`/`VSUBS` saturate), §1.6.5 comparison, §1.6.7 shift, §1.7 + Table 1.7-2 instruction performance, §1.8.1–1.8.219 per-instruction pseudocode. <https://documentation.espressif.com/esp32-s3_technical_reference_manual_en.pdf>
- ESP32-S3 TRM v1.8 — §4.3.3.2 (Cache structure, dual-core sharing, configurable sizes/line sizes), §4.3.3.3 (Cache operations, Manual-Preload / Auto-Preload). <https://www.espressif.com/sites/default/files/documentation/esp32-s3_technical_reference_manual_en.pdf>
- `espressif/xtensa-overlays` → `xtensa_esp32s3/binutils/bfd/xtensa-modules.c` — the GAS opcode table; **217 distinct `ee.*` mnemonics**, the definitive "what will assemble" list. <https://github.com/espressif/xtensa-overlays/blob/master/xtensa_esp32s3/binutils/bfd/xtensa-modules.c>
- esp-dsp benchmark data — `docs/esp_bm_results.csv` (S3 `_aes3` vs `_ansi` cycle counts). <https://github.com/espressif/esp-dsp/blob/master/docs/esp_bm_results.csv> · rendered: <https://docs.espressif.com/projects/esp-dsp/en/latest/esp-dsp-benchmarks.html>
- Espressif, *Introduction to PIE* (S3 vs P4 comparison). <https://developer.espressif.com/blog/2024/12/pie-introduction/>
- ESP-IDF *SPI Flash and External SPI RAM Configuration* — octal PSRAM is DTR-only; the F8R8 / F4R8 / F4R4 supported-combination tables. `$IDF_PATH/docs/en/api-guides/flash_psram_config.rst` · <https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/api-guides/flash_psram_config.html>
- ESP-IDF *Support for External RAM*. <https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/external-ram.html>
- ESP-IDF *FreeRTOS (IDF)*, "Floating Point Usage" — lazy coprocessor context switching, automatic core pinning, no coprocessor use in ISRs. `$IDF_PATH/docs/en/api-reference/system/freertos_idf.rst:405-432`
- `$IDF_PATH/components/esp_psram/esp32s3/Kconfig.spiram` — `SPIRAM_SPEED` default 40M; 120M octal gated on `IDF_EXPERIMENTAL_FEATURES` with the ±20 °C crash warning.
- `$IDF_PATH/components/xtensa/esp32s3/include/xtensa/config/core-isa.h` — `XCHAL_HAVE_PREFETCH 0`, `XCHAL_DCACHE_SIZE 0`, `XCHAL_HW_VERSION_NAME "LX7.0.12"`.
- `$IDF_PATH/components/xtensa/esp32s3/include/xtensa/config/tie.h` — `XCHAL_CP_MASK 0x09`, `XCHAL_CP3_NAME "cop_ai"`, `XCHAL_CP3_SA_SIZE 208`.
- `$IDF_PATH/components/xtensa/include/xtensa_context.h:328-345` — `XT_CP_SIZE` derivation.
- `$IDF_PATH/components/xtensa/xtensa_vectors.S:963-1081` — `_xt_coproc_exc`, `_xt_coproc_owner_sa`, `_xt_coproc_owner_sa_lock`.
- `$IDF_PATH/components/freertos/FreeRTOS-Kernel/portable/xtensa/port.c:165-197` — `uxInitialiseStackCPSA`, per-task coprocessor save area.
- `$IDF_PATH/components/esp_rom/esp32s3/include/esp32s3/rom/cache.h` — preload/autoload API and its "do not call" caveat.
- `$IDF_PATH/components/hal/include/hal/cache_hal.h` — `cache_hal_preload()` (IDF master only, not in v6.0.2).
- project-x51/esp32-s3-memorycopy — measured PSRAM/IRAM throughput incl. the 128-bit-PIE-vs-32-bit result. <https://github.com/project-x51/esp32-s3-memorycopy> · methodology caveats in <https://github.com/project-x51/esp32-s3-memorycopy/issues/2>
- vroland/epdiy discussion #289 — `Cache_Start_DCache_Preload` fragility. <https://github.com/vroland/epdiy/discussions/289>
- esp-dsp — `_ansi` / `_ae32` / `_aes3` / `_arp4` naming, `.S` build integration, and the two integer kernels `modules/support/mem/esp32s3/dsps_memcpy_aes3.S` + `dsps_memset_aes3.S` (incl. the `TIE_ENABLE` dummy `ee.zero.qacc`). <https://github.com/espressif/esp-dsp>
- BitsForPeople gist — the cleanest public example of `ee.*` in GCC inline asm (`"+r"`/`"m"` constraints, hardcoded `q0..q2`, hand-written `LOOPNEZ`). <https://gist.github.com/BitsForPeople/d78c8796cb9b378c90cd5659d86d7833>
- L. Bank (JPEGDEC author), *Surprise: the ESP32-S3 has a few SIMD instructions* — ~40% on JPEG YCbCr→RGB, and an independent limitation list matching the TRM. <https://bitbanksoftware.blogspot.com/2024/01/surprise-esp32-s3-has-few-simd.html>
- This repo: `README.md:80-121` (measured throughput, SPI ceiling, the 128→64 µs figure), `main/blocklist.c`, `main/murmur3.c`, `main/domain.c`, `main/dns_sink.cpp:948-1041`, `main/dns_server.cpp:245-264`, `sdkconfig`, `sdkconfig.defaults`, and the compiled objects under `build/esp-idf/main/CMakeFiles/__idf_main.dir/`.

*Deliberately unverified and worth measuring on hardware:* whether the S3's DCache
is non-blocking (hit-under-miss). If it is, issuing both possible next probes as
independent loads before the compare resolves would overlap two misses per level
and could beat §5.7 with no extra memory. The TRM is silent on this and no
published measurement was found. A loop of N dependent loads timed against N
independent loads would settle it in an afternoon.

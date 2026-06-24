#include "dns_server.h"
#include "blocklist.h"
#include "domain.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "lwip/sockets.h"
#include <cstring>
#include <cstdio>
#include <cerrno>
#include <cinttypes>
#include <sys/select.h>

static const char *TAG = "dns_server";

/* ── Metrics: lock-free counters + power-of-2 µs histograms ───────── */
/* Single dns_task writes; httpd task reads. 32-bit aligned reads are
 * atomic enough on Xtensa for monitoring purposes (no tearing concern). */
struct Hist {
    uint32_t bucket[48];   /* bucket i ≈ [2^(i-1), 2^i) µs */
    uint32_t count;
    uint32_t max_us;
};
static Hist s_h_blocked, s_h_cached, s_h_fwd_total, s_h_fwd_rtt, s_h_fwd_ourovh;
static Hist s_h_lookup;   /* blocklist_is_blocked() span only (CPU, no SPI/net) */
static Hist s_h_sendto;   /* the blocked-response sendto() call alone (lwIP TX path) */

/* Single writer (dns_task), single reader (httpd). Aligned 32-bit access is
 * atomic on Xtensa; plain uint32_t avoids the C++20 volatile-increment ban. */
static uint32_t s_cnt_total        = 0;
static uint32_t s_cnt_blocked      = 0;
static uint32_t s_cnt_forwarded    = 0;
static volatile bool s_reset_req   = false;  /* set by httpd; cleared+executed by dns_task */
static uint32_t s_cnt_drop_table   = 0;  /* upstream table full */
static uint32_t s_cnt_upstream_to  = 0;  /* upstream timeouts (evicted in_use) */
static uint32_t s_cnt_cache_probe  = 0;  /* result-cache lookups */
static uint32_t s_cnt_cache_hit    = 0;  /* result-cache hits */
static TaskHandle_t      s_dns_task_handle  = nullptr;

static inline int hist_bucket(uint32_t us)
{
    if (us == 0) return 0;
    int b = 32 - __builtin_clz(us);   /* floor(log2)+1; us=1→1, 2..3→2, 4..7→3 ... */
    return (b < 48) ? b : 47;
}
static inline void hist_record(Hist *h, int64_t us)
{
    uint32_t v = (us < 0) ? 0 : (us > 0xFFFFFFFFLL ? 0xFFFFFFFFu : (uint32_t)us);
    h->bucket[hist_bucket(v)]++;
    h->count++;
    if (v > h->max_us) h->max_us = v;
}
static uint32_t hist_pctl(const Hist *h, double p)
{
    uint32_t tot = h->count;
    if (!tot) return 0;
    uint32_t target = (uint32_t)(tot * p);
    uint32_t cum = 0;
    for (int i = 0; i < 48; i++) {
        cum += h->bucket[i];
        if (cum >= target) return (i == 0) ? 0u : (1u << i);  /* upper edge µs */
    }
    return h->max_us;
}

/* ── DNS wire format structs (RFC 1035) ──────────────────────────── */
#pragma pack(push, 1)
struct DnsHeader {
    uint16_t id, flags, qdcount, ancount, nscount, arcount;
};
struct DnsAnswerHeader {
    uint16_t name_ptr, type, class_type;
    uint32_t ttl;
    uint16_t rdlength;
};
#pragma pack(pop)

static constexpr uint16_t DNS_FLAGS_RESPONSE   = 0x8400; /* QR=1 AA=1 */
static constexpr uint16_t DNS_FLAGS_NXDOMAIN   = 0x8403; /* QR=1 AA=1 RCODE=3 */
static constexpr uint32_t BLOCKED_TTL_S        = 10;
static constexpr int      UPSTREAM_PORT        = 53;
static constexpr uint32_t UPSTREAM_TIMEOUT_MS  = 3000;
static constexpr int      UPSTREAM_TABLE_SIZE  = 64;

/* ── Result cache (PSRAM): blocked verdicts + full forwarded responses ─
 * Direct-mapped, 256 slots. Blocked entries regenerate 0.0.0.0/::; allowed
 * entries store the raw upstream response and replay it (txid rewritten) so
 * repeat allowed queries are served locally instead of re-forwarding. */
#define CACHE_SLOTS    256
#define FWD_RESP_MAX   512
#define FWD_TTL_MIN_S  10u
#define FWD_TTL_MAX_S  3600u
struct CacheEntry {
    uint32_t   key_hash;
    uint32_t   ttl_deadline_ms;       /* esp_timer ms timestamp */
    bool       valid;
    bool       blocked;
    uint16_t   qtype;
    uint16_t   resp_len;              /* allowed: cached raw response length (0 = blocked) */
    uint8_t    resp[FWD_RESP_MAX];    /* allowed: raw upstream response */
};
static CacheEntry *s_cache = nullptr; /* CACHE_SLOTS entries in PSRAM */

static bool cache_init(void)
{
    s_cache = (CacheEntry *)heap_caps_calloc(CACHE_SLOTS, sizeof(CacheEntry), MALLOC_CAP_SPIRAM);
    return s_cache != nullptr;
}
static CacheEntry *cache_lookup(uint32_t h, uint16_t qtype, uint32_t now_ms)
{
    CacheEntry *e = &s_cache[(h ^ ((uint32_t)qtype << 1)) & 0xFFu];
    if (e->valid && e->key_hash == h && e->qtype == qtype && e->ttl_deadline_ms > now_ms)
        return e;
    return nullptr;
}
static void cache_store_blocked(uint32_t h, uint16_t qtype, uint32_t ttl_s, uint32_t now_ms)
{
    CacheEntry *e = &s_cache[(h ^ ((uint32_t)qtype << 1)) & 0xFFu];
    e->key_hash = h; e->qtype = qtype; e->blocked = true; e->valid = true;
    e->resp_len = 0;
    e->ttl_deadline_ms = now_ms + ttl_s * 1000u;
}
static void cache_store_resp(uint32_t h, uint16_t qtype, const uint8_t *resp, int len,
                             uint32_t ttl_s, uint32_t now_ms)
{
    if (len <= 0 || len > FWD_RESP_MAX) return;
    CacheEntry *e = &s_cache[(h ^ ((uint32_t)qtype << 1)) & 0xFFu];
    e->key_hash = h; e->qtype = qtype; e->blocked = false; e->valid = true;
    e->resp_len = (uint16_t)len;
    memcpy(e->resp, resp, len);
    e->ttl_deadline_ms = now_ms + ttl_s * 1000u;
}

/* Parse the minimum TTL across answer RRs; returns clamped TTL or `deflt`. */
static uint32_t dns_resp_min_ttl(const uint8_t *pkt, int len, uint32_t deflt)
{
    if (len < 12) return deflt;
    int ancount = (pkt[6] << 8) | pkt[7];
    if (ancount == 0) return deflt;
    int off = 12;
    while (off < len && pkt[off] != 0) {                 /* skip question name */
        if ((pkt[off] & 0xC0) == 0xC0) { off += 2; goto qdone; }
        off += 1 + pkt[off];
    }
    off += 1;
qdone:
    off += 4;                                            /* qtype + qclass */
    uint32_t minttl = 0xFFFFFFFFu;
    for (int i = 0; i < ancount; i++) {
        if (off + 1 > len) break;
        if ((pkt[off] & 0xC0) == 0xC0) off += 2;         /* compressed name */
        else { while (off < len && pkt[off] != 0) off += 1 + pkt[off]; off += 1; }
        if (off + 10 > len) break;
        uint32_t ttl = ((uint32_t)pkt[off+4] << 24) | ((uint32_t)pkt[off+5] << 16)
                     | ((uint32_t)pkt[off+6] << 8)  |  (uint32_t)pkt[off+7];
        uint16_t rdlen = (pkt[off+8] << 8) | pkt[off+9];
        if (ttl < minttl) minttl = ttl;
        off += 10 + rdlen;
    }
    if (minttl == 0xFFFFFFFFu) return deflt;
    if (minttl < FWD_TTL_MIN_S) minttl = FWD_TTL_MIN_S;
    if (minttl > FWD_TTL_MAX_S) minttl = FWD_TTL_MAX_S;
    return minttl;
}

/* ── Upstream concurrent query table ─────────────────────────────── */
struct UpstreamEntry {
    uint16_t         our_txid;
    uint16_t         client_txid;
    struct sockaddr_in client_addr;
    uint32_t         sent_ms;
    int64_t          recv_us;        /* esp_timer µs when client query received */
    int64_t          upstream_us;    /* esp_timer µs when forwarded upstream */
    uint32_t         qhash;          /* domain hash — to key the forward cache on reply */
    uint16_t         qtype;
    bool             in_use;
};
static UpstreamEntry s_upstream[UPSTREAM_TABLE_SIZE];
static uint16_t      s_txid_counter = 1;

static UpstreamEntry *upstream_alloc(uint16_t *our_txid_out)
{
    for (int i = 0; i < UPSTREAM_TABLE_SIZE; i++) {
        if (!s_upstream[i].in_use) {
            s_upstream[i].in_use = true;
            s_upstream[i].our_txid = s_txid_counter++;
            if (s_txid_counter == 0) s_txid_counter = 1;
            *our_txid_out = s_upstream[i].our_txid;
            return &s_upstream[i];
        }
    }
    return nullptr;  /* table full */
}
static UpstreamEntry *upstream_find(uint16_t our_txid)
{
    for (int i = 0; i < UPSTREAM_TABLE_SIZE; i++)
        if (s_upstream[i].in_use && s_upstream[i].our_txid == our_txid)
            return &s_upstream[i];
    return nullptr;
}
static void upstream_evict_expired(uint32_t now_ms)
{
    for (int i = 0; i < UPSTREAM_TABLE_SIZE; i++)
        if (s_upstream[i].in_use && (now_ms - s_upstream[i].sent_ms) > UPSTREAM_TIMEOUT_MS) {
            s_upstream[i].in_use = false;
            s_cnt_upstream_to++;
        }
}
static int upstream_inflight(void)
{
    int n = 0;
    for (int i = 0; i < UPSTREAM_TABLE_SIZE; i++) if (s_upstream[i].in_use) n++;
    return n;
}

/* ── DNS response builders ───────────────────────────────────────── */
static int build_blocked_a(const uint8_t *query, int qlen, uint8_t *out, int out_cap)
{
    if (qlen < (int)sizeof(DnsHeader) || out_cap < qlen + (int)sizeof(DnsAnswerHeader) + 4)
        return -1;
    memcpy(out, query, qlen);
    auto *hdr = reinterpret_cast<DnsHeader *>(out);
    hdr->flags   = htons(dns_resp_flags(ntohs(reinterpret_cast<const DnsHeader *>(query)->flags), 0));
    hdr->ancount = htons(1);
    hdr->nscount = 0;
    hdr->arcount = 0;
    DnsAnswerHeader ans{};
    ans.name_ptr  = htons(0xC00C);
    ans.type      = htons(1);    /* A */
    ans.class_type= htons(1);    /* IN */
    ans.ttl       = htonl(BLOCKED_TTL_S);
    ans.rdlength  = htons(4);
    uint8_t *p = out + qlen;
    memcpy(p, &ans, sizeof(ans)); p += sizeof(ans);
    memset(p, 0, 4);             /* 0.0.0.0 */
    return qlen + (int)sizeof(ans) + 4;
}

static int build_blocked_aaaa(const uint8_t *query, int qlen, uint8_t *out, int out_cap)
{
    if (qlen < (int)sizeof(DnsHeader) || out_cap < qlen + (int)sizeof(DnsAnswerHeader) + 16)
        return -1;
    memcpy(out, query, qlen);
    auto *hdr = reinterpret_cast<DnsHeader *>(out);
    hdr->flags   = htons(dns_resp_flags(ntohs(reinterpret_cast<const DnsHeader *>(query)->flags), 0));
    hdr->ancount = htons(1);
    hdr->nscount = 0;
    hdr->arcount = 0;
    DnsAnswerHeader ans{};
    ans.name_ptr  = htons(0xC00C);
    ans.type      = htons(28);   /* AAAA */
    ans.class_type= htons(1);    /* IN */
    ans.ttl       = htonl(BLOCKED_TTL_S);
    ans.rdlength  = htons(16);
    uint8_t *p = out + qlen;
    memcpy(p, &ans, sizeof(ans)); p += sizeof(ans);
    memset(p, 0, 16);            /* :: */
    return qlen + (int)sizeof(ans) + 16;
}


/* ── QNAME extraction from DNS query (label walking) ────────────── */
/* Returns offset past QNAME+QTYPE+QCLASS, or -1 on error.          */
/* Writes normalized domain name to name_out (up to name_cap bytes). */
static int extract_qname(const uint8_t *pkt, int pkt_len,
                          int offset, char *name_out, size_t name_cap,
                          size_t *name_len_out)
{
    char raw[256]; size_t raw_len = 0;
    /* label walk per RFC 1035 §4.1.2 */
    while (offset < pkt_len && pkt[offset] != 0) {
        uint8_t label_len = pkt[offset];
        if ((label_len & 0xC0) == 0xC0) { offset += 2; break; }  /* compression ptr */
        if (offset + 1 + label_len >= pkt_len) return -1;
        if (raw_len + label_len + 1 >= sizeof(raw)) return -1;
        if (raw_len > 0) raw[raw_len++] = '.';
        memcpy(raw + raw_len, pkt + offset + 1, label_len);
        raw_len += label_len;
        offset  += 1 + label_len;
    }
    if (offset >= pkt_len) return -1;
    offset++;  /* skip null byte */
    if (offset + 4 > pkt_len) return -1;  /* QTYPE + QCLASS */

    size_t nlen = domain_normalize(name_out, name_cap, raw, raw_len);
    if (nlen == 0) return -1;
    *name_len_out = nlen;
    return offset + 4;  /* past QTYPE+QCLASS */
}

/* ── Main loop ───────────────────────────────────────────────────── */
DnsSinkServer::DnsSinkServer() : _exitSem(xSemaphoreCreateBinary()) {}

DnsSinkServer::~DnsSinkServer() {
    stop();
    if (_exitSem) { vSemaphoreDelete(_exitSem); _exitSem = nullptr; }
}

bool DnsSinkServer::start(const char *upstream_ip) {
    if (_running.load(std::memory_order_acquire)) return true;
    snprintf(_upstream_ip, sizeof(_upstream_ip), "%s", upstream_ip);
    _running.store(true, std::memory_order_release);
    if (_exitSem) xSemaphoreTake(_exitSem, 0);
    BaseType_t r = xTaskCreatePinnedToCore(dns_task, "dns_task", 8192, this, 10, &_taskHandle, 1);
    if (r != pdPASS) {
        ESP_LOGE(TAG, "task create failed");
        _running.store(false, std::memory_order_release);
        return false;
    }
    _taskStarted = true;
    return true;
}

void DnsSinkServer::stop() {
    _running.exchange(false, std::memory_order_acq_rel);
    int fd = _client_fd.exchange(-1, std::memory_order_acq_rel);
    if (fd != -1) { shutdown(fd, SHUT_RDWR); close(fd); }
    fd = _upstream_fd.exchange(-1, std::memory_order_acq_rel);
    if (fd != -1) { shutdown(fd, SHUT_RDWR); close(fd); }
    if (_taskStarted && _exitSem) {
        xSemaphoreTake(_exitSem, pdMS_TO_TICKS(1500));
        _taskStarted = false;
    }
    _taskHandle = nullptr;
}

static void do_metrics_reset(void);   /* forward decl — defined near metrics_reset */

void DnsSinkServer::dns_task(void *pv) {
    static_cast<DnsSinkServer *>(pv)->run_loop();
}

void DnsSinkServer::run_loop()
{
    s_dns_task_handle = xTaskGetCurrentTaskHandle();

    if (!cache_init()) {
        ESP_LOGE(TAG, "PSRAM result cache alloc failed");
        _running.store(false, std::memory_order_release);
        if (_exitSem) xSemaphoreGive(_exitSem);
        vTaskDelete(nullptr);
        return;
    }
    ESP_LOGI(TAG, "Result cache: %d slots x %d B in PSRAM (%u KB)",
             CACHE_SLOTS, (int)sizeof(CacheEntry),
             (unsigned)(CACHE_SLOTS * sizeof(CacheEntry) / 1024));

    /* ── Open client socket ─────────────────────────────────────── */
    int csock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (csock < 0) { ESP_LOGE(TAG, "socket: %d", errno); goto done; }
    {
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(53);
        if (bind(csock, (sockaddr *)&addr, sizeof(addr)) < 0) {
            ESP_LOGE(TAG, "bind port 53: %d", errno); close(csock); goto done;
        }
    }
    _client_fd.store(csock, std::memory_order_release);

    /* ── Open upstream socket ───────────────────────────────────── */
    {
        int usock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (usock < 0) { ESP_LOGE(TAG, "upstream socket: %d", errno); goto done; }
        /* SO_REUSEADDR: lets the task restart without waiting for TIME_WAIT.
         * Non-blocking receive is via MSG_DONTWAIT on each recvfrom() call. */
        {
            int flags = 1;
            setsockopt(usock, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags));
        }
        _upstream_fd.store(usock, std::memory_order_release);

        /* resolve upstream IP once */
        struct sockaddr_in upstream_addr{};
        upstream_addr.sin_family = AF_INET;
        upstream_addr.sin_port   = htons(UPSTREAM_PORT);
        inet_aton(_upstream_ip, &upstream_addr.sin_addr);

        uint8_t rx[512], tx[512 + sizeof(DnsAnswerHeader) + 16];
        struct sockaddr_in client_addr{};
        socklen_t clen = sizeof(client_addr);

        ESP_LOGI(TAG, "DNS sinkhole running on port 53, upstream %s", _upstream_ip);

        while (_running.load(std::memory_order_acquire)) {
            /* select() on both sockets with 100ms timeout */
            fd_set rset;
            FD_ZERO(&rset);
            FD_SET(csock, &rset);
            FD_SET(usock, &rset);
            struct timeval tv{ .tv_sec = 0, .tv_usec = 100000 };
            int nfds = (csock > usock ? csock : usock) + 1;
            int sel = select(nfds, &rset, nullptr, nullptr, &tv);
            if (sel < 0 && errno != EINTR) break;

            uint32_t now_ms = (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
            upstream_evict_expired(now_ms);
            if (s_reset_req) { s_reset_req = false; do_metrics_reset(); }

            (void)sel;  /* select() is just the wait; we drain non-blocking below */

            /* ── Drain ALL upstream replies first (frees table slots) ── */
            for (int dn = 0; dn < 64; dn++) {
                struct sockaddr_in from{}; socklen_t fromlen = sizeof(from);
                int rlen = recvfrom(usock, rx, sizeof(rx), MSG_DONTWAIT,
                                    (sockaddr *)&from, &fromlen);
                if (rlen < 0) break;                           /* EWOULDBLOCK: drained */
                if (rlen < (int)sizeof(DnsHeader)) continue;
                /* Reject replies not from our configured upstream (#24) */
                if (from.sin_addr.s_addr != upstream_addr.sin_addr.s_addr ||
                    from.sin_port        != upstream_addr.sin_port) continue;
                int64_t t_ureply = esp_timer_get_time();
                uint16_t our_txid = ntohs(reinterpret_cast<DnsHeader *>(rx)->id);
                UpstreamEntry *ue = upstream_find(our_txid);
                if (!ue) continue;
                /* rewrite transaction ID back to client's original */
                reinterpret_cast<DnsHeader *>(rx)->id = htons(ue->client_txid);
                sendto(csock, rx, rlen, 0,
                       (sockaddr *)&ue->client_addr, sizeof(ue->client_addr));
                int64_t t_csent = esp_timer_get_time();
                /* Latency split: (a) recv→upstream-send, (b) upstream RTT,
                 * (c) upstream-recv→client-send. Parity overhead = (a)+(c). */
                hist_record(&s_h_fwd_rtt,    t_ureply - ue->upstream_us);
                hist_record(&s_h_fwd_ourovh, (ue->upstream_us - ue->recv_us) + (t_csent - t_ureply));
                hist_record(&s_h_fwd_total,  t_csent - ue->recv_us);

                /* Forward cache: stash the response so a repeat identical query
                 * is answered locally. Only NOERROR/NXDOMAIN; TTL from the RRs
                 * (NXDOMAIN → short negative TTL). */
                uint8_t rcode = rx[3] & 0x0F;
                if (rcode == 0 || rcode == 3)
                    cache_store_resp(ue->qhash, ue->qtype, rx, rlen,
                                     dns_resp_min_ttl(rx, rlen, 30), now_ms);
                ue->in_use = false;
            }

            /* ── Drain client queries (cap per wakeup so upstream stays serviced) ── */
            for (int dn = 0; dn < 48; dn++) {
                clen = sizeof(client_addr);
                int rlen = recvfrom(csock, rx, sizeof(rx), MSG_DONTWAIT,
                                    (sockaddr *)&client_addr, &clen);
                if (rlen < 0) break;                           /* EWOULDBLOCK: drained */
                if (rlen < (int)sizeof(DnsHeader)) continue;

                auto *hdr = reinterpret_cast<DnsHeader *>(rx);
                if ((ntohs(hdr->flags) & 0x8000) || ntohs(hdr->qdcount) == 0) continue;

                int64_t t_recv = esp_timer_get_time();
                s_cnt_total++;

                /* parse QNAME */
                char name[256]; size_t nlen = 0;
                int qend = extract_qname(rx, rlen, sizeof(DnsHeader), name, sizeof(name), &nlen);
                if (qend < 0) continue;

                uint16_t qtype  = ntohs(*reinterpret_cast<uint16_t *>(rx + qend - 4));
                /* uint16_t qclass = ntohs(...) -- always IN(1), skip check */

                uint32_t h = domain_hash(name, nlen);

                /* ── cache hit? ─────────────────────────────── */
                s_cnt_cache_probe++;
                CacheEntry *ce = cache_lookup(h, qtype, now_ms);
                if (ce) {
                    s_cnt_cache_hit++;
                    if (ce->blocked) {
                        int tlen;
                        if (qtype == 1)
                            tlen = build_blocked_a   (rx, qend, tx, sizeof(tx));
                        else if (qtype == 28)
                            tlen = build_blocked_aaaa(rx, qend, tx, sizeof(tx));
                        else {
                            /* Non-A/AAAA blocked: NXDOMAIN with no answer RRs */
                            memcpy(tx, rx, qend);
                            reinterpret_cast<DnsHeader *>(tx)->flags   = htons(DNS_FLAGS_NXDOMAIN);
                            reinterpret_cast<DnsHeader *>(tx)->ancount = 0;
                            reinterpret_cast<DnsHeader *>(tx)->nscount = 0;
                            reinterpret_cast<DnsHeader *>(tx)->arcount = 0;
                            tlen = qend;
                        }
                        if (tlen > 0)
                            sendto(csock, tx, tlen, 0, (sockaddr *)&client_addr, clen);
                        s_cnt_blocked++;
                        hist_record(&s_h_cached, esp_timer_get_time() - t_recv);
                    } else if (ce->resp_len > 0 && ce->resp_len <= (int)sizeof(tx)) {
                        /* allowed: replay the cached raw upstream response */
                        memcpy(tx, ce->resp, ce->resp_len);
                        tx[0] = rx[0]; tx[1] = rx[1];      /* keep client's txid (wire bytes) */
                        sendto(csock, tx, ce->resp_len, 0, (sockaddr *)&client_addr, clen);
                        hist_record(&s_h_cached, esp_timer_get_time() - t_recv);
                    } else {
                        s_cnt_cache_hit--;       /* stale/empty — treat as miss */
                        goto forward;
                    }
                    continue;
                }

                /* ── blocklist check (measure CPU-only lookup span) ──
                 * Scoped block so the 'goto forward' above never crosses these
                 * local initializations (illegal in C++). */
                {
                    int64_t t_lk = esp_timer_get_time();
                    bool is_blk = blocklist_is_blocked(name, nlen);
                    hist_record(&s_h_lookup, esp_timer_get_time() - t_lk);
                    if (is_blk) {
                        s_cnt_blocked++;
                        int tlen;
                        if (qtype == 1)
                            tlen = build_blocked_a   (rx, qend, tx, sizeof(tx));
                        else if (qtype == 28)
                            tlen = build_blocked_aaaa(rx, qend, tx, sizeof(tx));
                        else {
                            memcpy(tx, rx, qend);
                            reinterpret_cast<DnsHeader *>(tx)->flags   = htons(DNS_FLAGS_NXDOMAIN);
                            reinterpret_cast<DnsHeader *>(tx)->ancount = 0;
                            reinterpret_cast<DnsHeader *>(tx)->nscount = 0;
                            reinterpret_cast<DnsHeader *>(tx)->arcount = 0;
                            tlen = qend;
                        }
                        if (tlen > 0) {
                            int64_t t_s0 = esp_timer_get_time();
                            sendto(csock, tx, tlen, 0, (sockaddr *)&client_addr, clen);
                            hist_record(&s_h_sendto, esp_timer_get_time() - t_s0);
                        }
                        cache_store_blocked(h, qtype, BLOCKED_TTL_S, now_ms);
                        hist_record(&s_h_blocked, esp_timer_get_time() - t_recv);
                        continue;
                    }
                }

                /* ── forward to upstream ────────────────────── */
                forward: {
                    uint16_t our_txid;
                    UpstreamEntry *ue = upstream_alloc(&our_txid);
                    if (!ue) {
                        /* table full — drop this query; client will retry */
                        s_cnt_drop_table++;
                        ESP_LOGW(TAG, "upstream table full, dropping query for %s", name);
                        continue;
                    }
                    ue->client_txid = ntohs(hdr->id);
                    ue->client_addr = client_addr;
                    ue->sent_ms     = now_ms;
                    ue->recv_us     = t_recv;
                    ue->qhash       = h;
                    ue->qtype       = qtype;

                    /* rewrite txid and forward */
                    hdr->id = htons(our_txid);
                    ue->upstream_us = esp_timer_get_time();
                    sendto(usock, rx, rlen, 0,
                           (sockaddr *)&upstream_addr, sizeof(upstream_addr));
                    s_cnt_forwarded++;
                }
            }
        }  /* while running */
    }

done:
    int fd = _client_fd.exchange(-1, std::memory_order_acq_rel);
    if (fd != -1) close(fd);
    fd = _upstream_fd.exchange(-1, std::memory_order_acq_rel);
    if (fd != -1) close(fd);
    _running.store(false, std::memory_order_release);
    ESP_LOGI(TAG, "dns_task exited");
    if (_exitSem) xSemaphoreGive(_exitSem);
    vTaskDelete(nullptr);
}

uint64_t DnsSinkServer::queries_total()   const { return s_cnt_total; }
uint64_t DnsSinkServer::queries_blocked() const { return s_cnt_blocked; }

extern "C" uint32_t dns_sink_l2_blocked(void);  /* L2 fast-path counter (dns_sink.cpp) */

static void do_metrics_reset(void)
{
    s_cnt_total = s_cnt_blocked = s_cnt_forwarded = 0;
    s_cnt_drop_table = s_cnt_upstream_to = s_cnt_cache_probe = s_cnt_cache_hit = 0;
    memset(&s_h_blocked,    0, sizeof(s_h_blocked));
    memset(&s_h_cached,     0, sizeof(s_h_cached));
    memset(&s_h_fwd_total,  0, sizeof(s_h_fwd_total));
    memset(&s_h_fwd_rtt,    0, sizeof(s_h_fwd_rtt));
    memset(&s_h_fwd_ourovh, 0, sizeof(s_h_fwd_ourovh));
    memset(&s_h_lookup,     0, sizeof(s_h_lookup));
    memset(&s_h_sendto,     0, sizeof(s_h_sendto));
}

void dns_server_metrics_reset(void)
{
    s_reset_req = true;  /* picked up by dns_task on its next select() wakeup */
}

/* ── /metrics JSON ───────────────────────────────────────────────── */
int dns_server_metrics_json(char *out, size_t cap)
{
    uint32_t probes = s_cnt_cache_probe;
    uint32_t hits   = s_cnt_cache_hit;
    float hitrate   = probes ? (100.0f * (float)hits / (float)probes) : 0.0f;

    size_t free_int  = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t free_psr  = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    UBaseType_t hwm  = s_dns_task_handle ? uxTaskGetStackHighWaterMark(s_dns_task_handle) : 0;

    int n = snprintf(out, cap,
        "{"
        "\"uptime_s\":%lld,"
        "\"queries_total\":%" PRIu32 ",\"blocked\":%" PRIu32 ",\"forwarded\":%" PRIu32 ","
        "\"l2_blocked\":%" PRIu32 ","
        "\"cache_probes\":%" PRIu32 ",\"cache_hits\":%" PRIu32 ",\"cache_hit_rate\":%.1f,"
        "\"dropped\":{\"table_full\":%" PRIu32 "},\"upstream_timeouts\":%" PRIu32 ","
        "\"upstream_inflight\":%d,\"upstream_max\":%d,"
        "\"blocklist_count\":%" PRIu32 ",\"blocklist_loading\":%s,"
        "\"heap_free\":%u,\"psram_free\":%u,\"dns_task_stack_hwm\":%u,",
        (long long)(esp_timer_get_time() / 1000000),
        s_cnt_total, s_cnt_blocked, s_cnt_forwarded,
        dns_sink_l2_blocked(),
        probes, hits, hitrate,
        s_cnt_drop_table, s_cnt_upstream_to,
        upstream_inflight(), UPSTREAM_TABLE_SIZE,
        blocklist_domain_count(), blocklist_is_loading() ? "true" : "false",
        (unsigned)free_int, (unsigned)free_psr, (unsigned)hwm);

    struct { const char *name; const Hist *h; } cats[] = {
        {"blocked",          &s_h_blocked},
        {"cached",           &s_h_cached},
        {"forwarded_total",  &s_h_fwd_total},
        {"forwarded_ourovh", &s_h_fwd_ourovh},
        {"forwarded_rtt",    &s_h_fwd_rtt},
        {"lookup",           &s_h_lookup},
        {"sendto",           &s_h_sendto},
    };
    if ((size_t)n < cap) n += snprintf(out + n, cap - (size_t)n, "\"latency_us\":{");
    for (size_t i = 0; i < sizeof(cats)/sizeof(cats[0]); i++) {
        if ((size_t)n >= cap) break;
        n += snprintf(out + n, cap - (size_t)n,
            "%s\"%s\":{\"p50\":%" PRIu32 ",\"p99\":%" PRIu32 ",\"max\":%" PRIu32 ",\"count\":%" PRIu32 "}",
            i ? "," : "", cats[i].name,
            hist_pctl(cats[i].h, 0.50), hist_pctl(cats[i].h, 0.99),
            cats[i].h->max_us, cats[i].h->count);
    }
    if ((size_t)n < cap) n += snprintf(out + n, cap - (size_t)n, "}}");
    return n;
}

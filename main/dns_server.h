#pragma once

#include <atomic>
#include <stddef.h>
#include <stdint.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

/* TTL stamped on every blocked/sinkholed answer — the socket path's cache
 * entries (dns_server.cpp) and the L2 hook's own directly-built blocked reply
 * (dns_sink.cpp) must agree, or the two verdict paths hand out inconsistent
 * TTLs for the exact same block decision (#109). */
static constexpr uint32_t BLOCKED_TTL_S = 10;

/* Build the DNS response flags word from a query flags word (host byte order).
 * QR=1, OPCODE echoed, AA=1, TC=0, RD echoed, RA=1, Z=0, RCODE as given. */
static inline uint16_t dns_resp_flags(uint16_t qflags, uint8_t rcode)
{
    return (uint16_t)(0x8400u                       /* QR=1 AA=1 */
        | (qflags & 0x7800u)                        /* OPCODE echoed */
        | 0x0080u                                   /* RA=1 */
        | (qflags & 0x0100u)                        /* RD echoed */
        | (rcode & 0x000Fu));
}

/* Render the live metrics snapshot as JSON into out (NUL-terminated).
 * Safe to call from the httpd task; reads lock-free counters/histograms. */
int dns_server_metrics_json(char *out, size_t cap);

/* Zero all counters + latency histograms (for clean per-bench measurement). */
void dns_server_metrics_reset(void);

/* L2 fast-path forward-cache read, callable from the eth-RX task (C linkage).
 * Copies the cached ALLOWED response for (qhash,qtype) into out; returns the DNS
 * length or -1 on miss/expired/race. The caller patches the txid and frames it. */
#ifdef __cplusplus
extern "C" {
#endif
/* IRAM_ATTR tag lives on the definition in dns_server.cpp only — repeating
 * it here would give GCC two different generated section names for the
 * same symbol (each IRAM_ATTR expansion mints a fresh one) and fail the
 * build under -Werror=attributes. */
int dns_cache_l2_get(uint32_t qhash, uint16_t qtype, uint8_t *out, int out_cap);

/* Persist the forward cache to /sdcard/fwdcache.bin so a reboot keeps its
 * learned working set (#79). Blocking SD I/O - call from download_task,
 * never from dns_task. Not re-entrant (uses a static snapshot buffer). */
void dns_server_cache_save(void);
#ifdef __cplusplus
}
#endif

class DnsSinkServer {
public:
    DnsSinkServer();
    ~DnsSinkServer();

    /* Start the DNS task (Core 1, priority 10). upstream_ip = "1.1.1.1" */
    bool start(const char *upstream_ip = "1.1.1.1");
    void stop();

    /* Re-point upstream forwarding at a new resolver IP without restarting
     * the task (#53: dual-WAN — switching which interface egresses upstream
     * queries shouldn't drop in-flight client traffic). Safe to call from any
     * task; run_loop() reads the address atomically each forward/reply.
     *
     * (#72) secondary_ip is the OTHER resolver the same DHCP lease offered, or
     * "" / nullptr when there is only one — the ordinary case on plenty of
     * routers, and the state every board is in before this feature. Every
     * query is still forwarded to the primary; the secondary is used only as
     * the target of #69's hedged retransmit, and is additionally accepted as a
     * reply source. An unparseable secondary clears it rather than keeping a
     * stale one, so "no secondary" is always reachable. */
    void set_upstream(const char *upstream_ip, const char *secondary_ip);
    void upstream_ip(char *out, size_t cap) const;

    uint64_t queries_total()  const;
    uint64_t queries_blocked() const;

private:
    static void dns_task(void *pv);
    void        run_loop();

    char             _upstream_ip[16];
    std::atomic<uint32_t> _upstream_addr{0};  /* in_addr_t, network byte order */
    std::atomic<uint32_t> _upstream_addr2{0}; /* (#72) secondary; 0 = none configured */
    TaskHandle_t     _taskHandle = nullptr;
    std::atomic<int> _client_fd{-1};
    std::atomic<int> _upstream_fd{-1};
    std::atomic<bool> _running{false};
    bool             _taskStarted = false;
    SemaphoreHandle_t _exitSem    = nullptr;

};

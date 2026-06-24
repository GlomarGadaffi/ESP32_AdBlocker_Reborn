#pragma once

#include <atomic>
#include <stddef.h>
#include <stdint.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

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

class DnsSinkServer {
public:
    DnsSinkServer();
    ~DnsSinkServer();

    /* Start the DNS task (Core 1, priority 10). upstream_ip = "1.1.1.1" */
    bool start(const char *upstream_ip = "1.1.1.1");
    void stop();

    uint64_t queries_total()  const;
    uint64_t queries_blocked() const;

private:
    static void dns_task(void *pv);
    void        run_loop();

    char             _upstream_ip[16];
    TaskHandle_t     _taskHandle = nullptr;
    std::atomic<int> _client_fd{-1};
    std::atomic<int> _upstream_fd{-1};
    std::atomic<bool> _running{false};
    bool             _taskStarted = false;
    SemaphoreHandle_t _exitSem    = nullptr;

};

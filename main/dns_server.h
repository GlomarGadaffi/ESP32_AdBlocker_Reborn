#pragma once

#include <atomic>
#include <stddef.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

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

/*
 * dnsload - UDP DNS load generator for measuring a resolver against a real
 * domain corpus.
 *
 *   dnsload <server-ip> <namefile> <concurrency> <seconds> [--warm N] [--prefix]
 *
 * <namefile> is one domain per line. Using a real corpus matters: label depth
 * varies, so the number of suffix-walk lookups per query varies, and the names
 * spread across the whole hash/bucket space instead of hammering a handful of
 * cache lines. A hardcoded eight-name list flatters any lookup design.
 *
 *   --warm N   send N queries from the corpus and discard them before
 *              measuring, so the forward cache is populated and we are timing
 *              the cache-hit path rather than the cold path
 *   --prefix   prepend a unique random label to every name, forcing every
 *              query cold (upstream). Measures the gateway more than the
 *              device -- keep these runs short.
 *
 * Names are visited in a shuffled order with a fixed seed, so every run of a
 * given corpus issues the same sequence: comparable across firmware builds.
 *
 * Build (MSVC):  cl /nologo /O2 dnsload.c ws2_32.lib
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#pragma comment(lib, "ws2_32.lib")

#define MAX_INFLIGHT 4096
#define MAX_SAMPLES  4000000
#define MAX_NAMES    1200000

static double g_freq;
static double now_us(void)
{
    LARGE_INTEGER c; QueryPerformanceCounter(&c);
    return (double)c.QuadPart * 1e6 / g_freq;
}

static char  *g_pool;
static char **g_names;
static size_t g_nnames;

/* xorshift with a fixed seed: identical visit order on every run */
static uint64_t rs = 0x9E3779B97F4A7C15ULL;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }

static int load_names(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); return -1; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); rewind(f);
    g_pool = (char *)malloc((size_t)sz + 1);
    if (!g_pool) { fclose(f); return -1; }
    size_t rd = fread(g_pool, 1, (size_t)sz, f);
    g_pool[rd] = 0;
    fclose(f);

    g_names = (char **)malloc(sizeof(char *) * MAX_NAMES);
    if (!g_names) return -1;
    g_nnames = 0;
    char *p = g_pool;
    while (*p && g_nnames < MAX_NAMES) {
        char *line = p;
        while (*p && *p != '\n' && *p != '\r') p++;
        char *end = p;
        while (*p == '\n' || *p == '\r') { *p = 0; p++; }
        *end = 0;
        if (line[0] && line[0] != '#' && strchr(line, '.')) g_names[g_nnames++] = line;
    }
    /* Fisher-Yates with the fixed seed */
    for (size_t i = g_nnames; i > 1; i--) {
        size_t j = (size_t)(rnd() % i);
        char *t = g_names[i-1]; g_names[i-1] = g_names[j]; g_names[j] = t;
    }
    return 0;
}

static int encode_name(uint8_t *out, const char *name)
{
    int o = 0;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        int len = dot ? (int)(dot - p) : (int)strlen(p);
        if (len <= 0 || len > 63) return -1;
        out[o++] = (uint8_t)len;
        memcpy(out + o, p, len); o += len;
        if (!dot) break;
        p = dot + 1;
    }
    out[o++] = 0;
    return o;
}

static int build_query(uint8_t *buf, uint16_t txid, const char *name)
{
    memset(buf, 0, 12);
    buf[0] = (uint8_t)(txid >> 8); buf[1] = (uint8_t)txid;
    buf[2] = 0x01; buf[5] = 0x01;
    int n = encode_name(buf + 12, name);
    if (n < 0) return -1;
    int o = 12 + n;
    buf[o++] = 0; buf[o++] = 1;
    buf[o++] = 0; buf[o++] = 1;
    return o;
}

static int cmp_dbl(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

int main(int argc, char **argv)
{
    if (argc < 5) {
        fprintf(stderr, "usage: dnsload <ip> <namefile> <conc> <secs> [--warm N] [--prefix]\n");
        return 2;
    }
    const char *ip = argv[1], *namefile = argv[2];
    int conc = atoi(argv[3]);
    double secs = atof(argv[4]);
    int warm = 0, prefix = 0;
    for (int i = 5; i < argc; i++) {
        if (!strcmp(argv[i], "--warm") && i + 1 < argc) warm = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--prefix")) prefix = 1;
    }
    if (conc < 1) conc = 1;
    if (conc > MAX_INFLIGHT) conc = MAX_INFLIGHT;

    LARGE_INTEGER f; QueryPerformanceFrequency(&f); g_freq = (double)f.QuadPart;
    if (load_names(namefile) != 0) return 1;
    if (g_nnames == 0) { fprintf(stderr, "no names in %s\n", namefile); return 1; }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) return 1;
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return 1;
    u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
    int rcvbuf = 8 * 1024 * 1024;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char *)&rcvbuf, sizeof(rcvbuf));

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET; dst.sin_port = htons(53);
    inet_pton(AF_INET, ip, &dst.sin_addr);

    static double sent_at[65536];
    static uint8_t live[65536];
    memset(live, 0, sizeof(live));

    double *samples = (double *)malloc(sizeof(double) * MAX_SAMPLES);
    if (!samples) return 1;
    size_t nsamp = 0;

    uint8_t qbuf[600], rbuf[1500];
    uint32_t seq = 0;
    long long sent = 0, recvd = 0, timedout = 0;
    int inflight = 0;
    char nm[300];

    if (warm > 0) {
        for (int i = 0; i < warm; i++) {
            int qn = build_query(qbuf, (uint16_t)(i & 0xFFFF), g_names[i % g_nnames]);
            if (qn > 0) sendto(s, (const char *)qbuf, qn, 0, (struct sockaddr *)&dst, sizeof(dst));
            if ((i & 15) == 15) Sleep(1);
            while (recvfrom(s, (char *)rbuf, sizeof(rbuf), 0, NULL, NULL) > 0) {}
        }
        Sleep(500);
        while (recvfrom(s, (char *)rbuf, sizeof(rbuf), 0, NULL, NULL) > 0) {}
    }

    double t_start = now_us();
    double t_end = t_start + secs * 1e6;
    double last_reap = t_start;

    while (now_us() < t_end || inflight > 0) {
        double t = now_us();
        while (inflight < conc && t < t_end) {
            const char *base = g_names[seq % g_nnames];
            if (prefix) snprintf(nm, sizeof(nm), "u%08x.%s", (unsigned)(rnd() & 0xFFFFFFFF), base);
            else        snprintf(nm, sizeof(nm), "%s", base);

            uint16_t txid = (uint16_t)(seq & 0xFFFF);
            if (live[txid]) break;
            int qn = build_query(qbuf, txid, nm);
            if (qn < 0) { seq++; continue; }
            if (sendto(s, (const char *)qbuf, qn, 0, (struct sockaddr *)&dst, sizeof(dst)) == SOCKET_ERROR) break;
            sent_at[txid] = now_us();
            live[txid] = 1;
            inflight++; sent++; seq++;
        }
        for (;;) {
            int n = recvfrom(s, (char *)rbuf, sizeof(rbuf), 0, NULL, NULL);
            if (n < 12) break;
            uint16_t txid = (uint16_t)((rbuf[0] << 8) | rbuf[1]);
            if (!live[txid]) continue;
            double lat = now_us() - sent_at[txid];
            live[txid] = 0; inflight--; recvd++;
            if (nsamp < MAX_SAMPLES) samples[nsamp++] = lat;
        }
        double tn = now_us();
        if (tn - last_reap > 20000.0) {
            last_reap = tn;
            for (int i = 0; i < 65536; i++)
                if (live[i] && tn - sent_at[i] > 300000.0) { live[i] = 0; inflight--; timedout++; }
        }
        if (tn > t_end + 1e6) break;
    }
    double elapsed = (now_us() - t_start) / 1e6;

    qsort(samples, nsamp, sizeof(double), cmp_dbl);
    double p50 = nsamp ? samples[nsamp * 50 / 100] : 0;
    double p95 = nsamp ? samples[nsamp * 95 / 100] : 0;
    double p99 = nsamp ? samples[nsamp * 99 / 100] : 0;
    double mn = nsamp ? samples[0] : 0, mx = nsamp ? samples[nsamp-1] : 0;
    double mean = 0; for (size_t i = 0; i < nsamp; i++) mean += samples[i];
    if (nsamp) mean /= nsamp;

    printf("corpus=%s n_names=%zu conc=%d elapsed=%.2fs sent=%lld recv=%lld lost=%lld (%.2f%%) qps=%.0f\n",
           namefile, g_nnames, conc, elapsed, sent, recvd, timedout,
           sent ? 100.0 * (double)timedout / (double)sent : 0.0,
           elapsed > 0 ? recvd / elapsed : 0);
    printf("  latency_ms  min=%.3f p50=%.3f mean=%.3f p95=%.3f p99=%.3f max=%.3f n=%zu\n",
           mn/1000, p50/1000, mean/1000, p95/1000, p99/1000, mx/1000, nsamp);

    closesocket(s); WSACleanup();
    return 0;
}

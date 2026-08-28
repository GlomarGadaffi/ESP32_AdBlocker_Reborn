#include "web_tls.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_heap_caps.h"
#include "nvs.h"
#include "psa/crypto.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/oid.h"
#include "mbedtls/md.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static const char *TAG = "web_tls";

/* Own namespace: the shared "dns_sink" namespace is the one blocklist.c warns
 * against erase_all()'ing; keeping TLS material apart also lets `cert-reset`
 * wipe exactly this and nothing else. */
#define TLS_NVS_NS "web_tls"
#define KEY_CRT    "crt_pem"
#define KEY_KEY    "key_pem"
#define KEY_FMT    "fmt"
/* Bump when the certificate's contents change in a way existing devices
 * must pick up (a stored cert from an older format is regenerated at boot).
 * 2: EKU serverAuth + IP SAN + ≤2-year validity (Apple trust rules). */
#define CERT_FMT   2

/* Apple refuses to trust a TLS server cert with validity > 825 days or
 * without EKU serverAuth, even after the user installs it (HT210176), so the
 * cert is issued for 2 years and regenerated at boot once it's inside its
 * last 30 days. The fingerprint changes when that happens; it's logged. */
#define CERT_DAYS        730
#define CERT_RENEW_DAYS  30
/* Below this the clock hasn't been set by anything (SNTP or the #75 build-time
 * floor) and a "not before = now" would be nonsense. 2025-01-01. */
#define CLOCK_SANE_EPOCH 1735689600

/* PEM lives in PSRAM (esp_https_server takes its own internal copies at
 * httpd_ssl_start, so keeping ours in internal RAM would just be a second
 * copy of ~6 KB there) and is released by web_tls_release_identity() once
 * the server is up. */
static char  *s_crt = NULL, *s_key = NULL;
static size_t s_crt_len = 0, s_key_len = 0;
static char   s_fp[96] = "";

/* dns_sink.cpp */
extern const char *dns_sink_hostname(void);

static void *psram_alloc(size_t n)
{
    void *p = heap_caps_calloc(1, n, MALLOC_CAP_SPIRAM);
    return p ? p : calloc(1, n);   /* PSRAM-less build: fall back, still works */
}

static bool nvs_load_str(nvs_handle_t h, const char *key, char **out, size_t *len)
{
    size_t need = 0;
    if (nvs_get_str(h, key, NULL, &need) != ESP_OK || need == 0) return false;
    char *buf = psram_alloc(need);
    if (!buf) return false;
    if (nvs_get_str(h, key, buf, &need) != ESP_OK) { free(buf); return false; }
    *out = buf; *len = need;   /* need includes the NUL — what httpd_ssl wants */
    return true;
}

/* Parses the stored cert: fills the fingerprint and reports whether it is
 * (or is about to be) expired against the current clock. */
static bool inspect_cert(bool *needs_renew)
{
    s_fp[0] = '\0';
    *needs_renew = false;
    if (!s_crt) return false;
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    if (mbedtls_x509_crt_parse(&crt, (const unsigned char *)s_crt, s_crt_len) != 0) {
        mbedtls_x509_crt_free(&crt);
        return false;
    }
    unsigned char dig[32];
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md && mbedtls_md(md, crt.raw.p, crt.raw.len, dig) == 0) {
        int n = 0;
        for (int i = 0; i < 32; i++)
            n += snprintf(s_fp + n, sizeof(s_fp) - n, "%02X%s", dig[i], i < 31 ? ":" : "");
    }
    time_t now = time(NULL);
    if (now > CLOCK_SANE_EPOCH) {
        struct tm t = { .tm_year = crt.valid_to.year - 1900, .tm_mon = crt.valid_to.mon - 1,
                        .tm_mday = crt.valid_to.day, .tm_hour = crt.valid_to.hour,
                        .tm_min = crt.valid_to.min, .tm_sec = crt.valid_to.sec };
        time_t until = mktime(&t);
        if (until != (time_t)-1 && now > until - (time_t)CERT_RENEW_DAYS * 86400) {
            *needs_renew = true;
            ESP_LOGW(TAG, "certificate expires %04d-%02d-%02d — regenerating",
                     crt.valid_to.year, crt.valid_to.mon, crt.valid_to.day);
        }
    }
    mbedtls_x509_crt_free(&crt);
    return true;
}

static void fmt_x509_time(char out[16], time_t t)
{
    struct tm tm; gmtime_r(&t, &tm);
    strftime(out, 16, "%Y%m%d%H%M%S", &tm);
}

static bool generate_identity(void)
{
    bool ok = false;
    unsigned char *crt_buf = NULL, *key_buf = NULL;
    mbedtls_pk_context pk;
    mbedtls_x509write_cert wc;
    mbedtls_pk_init(&pk);
    mbedtls_x509write_crt_init(&wc);
    mbedtls_svc_key_id_t kid = MBEDTLS_SVC_KEY_ID_INIT;

    if (psa_crypto_init() != PSA_SUCCESS) { ESP_LOGE(TAG, "psa init failed"); goto out; }

    /* ECDSA P-256: ~100 ms to generate on the S3, tiny PEMs, and every
     * browser trusts the curve. RSA-2048 would take tens of seconds here. */
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    if (psa_generate_key(&attr, &kid) != PSA_SUCCESS) { ESP_LOGE(TAG, "keygen failed"); goto out; }
    if (mbedtls_pk_copy_from_psa(kid, &pk) != 0) { ESP_LOGE(TAG, "pk copy failed"); goto out; }

    const char *host = dns_sink_hostname();
    char subject[96];
    snprintf(subject, sizeof(subject), "CN=%s,O=ESP32 AdBlocker Reborn", host);

    unsigned char serial[16];
    esp_fill_random(serial, sizeof(serial));
    serial[0] &= 0x7f;   /* positive INTEGER */

    /* Validity from "now" when the clock is sane, else from the compile-era
     * floor — a not-before in the future is rejected by every browser. */
    time_t now = time(NULL);
    if (now <= CLOCK_SANE_EPOCH) now = CLOCK_SANE_EPOCH;
    char nb[16], na[16];
    fmt_x509_time(nb, now - 86400);                      /* a day of clock slack */
    fmt_x509_time(na, now + (time_t)CERT_DAYS * 86400);

    mbedtls_x509write_crt_set_version(&wc, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&wc, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&wc, &pk);
    mbedtls_x509write_crt_set_issuer_key(&wc, &pk);
    if (mbedtls_x509write_crt_set_subject_name(&wc, subject) != 0 ||
        mbedtls_x509write_crt_set_issuer_name(&wc, subject)  != 0 ||
        mbedtls_x509write_crt_set_serial_raw(&wc, serial, sizeof(serial)) != 0 ||
        mbedtls_x509write_crt_set_validity(&wc, nb, na) != 0 ||
        mbedtls_x509write_crt_set_basic_constraints(&wc, 0, -1) != 0 ||
        mbedtls_x509write_crt_set_key_usage(&wc, MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
                                                 MBEDTLS_X509_KU_KEY_AGREEMENT) != 0 ||
        mbedtls_x509write_crt_set_ext_key_usage(&wc, (const mbedtls_asn1_sequence[]){
            { .buf = { .tag = MBEDTLS_ASN1_OID, .len = MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH),
                       .p = (unsigned char *)MBEDTLS_OID_SERVER_AUTH }, .next = NULL } }) != 0) {
        ESP_LOGE(TAG, "cert fields failed"); goto out;
    }
    {
        /* SAN: the mDNS name, plus the setup AP's fixed address so the
         * documented first-boot path (https://192.168.4.1) matches too. */
        static const unsigned char ap_ip[4] = { 192, 168, 4, 1 };
        mbedtls_x509_san_list san_ip = {
            .node = { .type = MBEDTLS_X509_SAN_IP_ADDRESS,
                      .san = { .unstructured_name = { .tag = MBEDTLS_ASN1_OCTET_STRING,
                                                      .len = 4, .p = (unsigned char *)ap_ip } } },
            .next = NULL,
        };
        mbedtls_x509_san_list san = {
            .node = { .type = MBEDTLS_X509_SAN_DNS_NAME,
                      .san = { .unstructured_name = { .tag = MBEDTLS_ASN1_IA5_STRING,
                                                      .len = strlen(host),
                                                      .p   = (unsigned char *)host } } },
            .next = &san_ip,
        };
        if (mbedtls_x509write_crt_set_subject_alternative_name(&wc, &san) != 0) {
            ESP_LOGE(TAG, "SAN failed"); goto out;
        }
    }

    crt_buf = psram_alloc(2048);
    key_buf = psram_alloc(1024);
    if (!crt_buf || !key_buf) goto out;
    if (mbedtls_x509write_crt_pem(&wc, crt_buf, 2048) != 0) { ESP_LOGE(TAG, "cert pem failed"); goto out; }
    if (mbedtls_pk_write_key_pem(&pk, key_buf, 1024) != 0) { ESP_LOGE(TAG, "key pem failed"); goto out; }

    nvs_handle_t h;
    esp_err_t e = nvs_open(TLS_NVS_NS, NVS_READWRITE, &h);
    if (e == ESP_OK) {
        if ((e = nvs_set_str(h, KEY_CRT, (const char *)crt_buf)) == ESP_OK &&
            (e = nvs_set_str(h, KEY_KEY, (const char *)key_buf)) == ESP_OK &&
            (e = nvs_set_u8(h, KEY_FMT, CERT_FMT)) == ESP_OK)
            e = nvs_commit(h);
        nvs_close(h);
    }
    if (e != ESP_OK)
        /* Loud on purpose: a fingerprint that changes every boot is exactly
         * what the setup page tells the user to be suspicious of. */
        ESP_LOGE(TAG, "NVS write failed (%s) — identity will regenerate every boot", esp_err_to_name(e));

    free(s_crt); free(s_key);
    s_crt = (char *)crt_buf; s_crt_len = strlen(s_crt) + 1;
    s_key = (char *)key_buf; s_key_len = strlen(s_key) + 1;
    crt_buf = key_buf = NULL;
    ok = true;
out:
    free(crt_buf); free(key_buf);
    mbedtls_x509write_crt_free(&wc);
    mbedtls_pk_free(&pk);
    if (!mbedtls_svc_key_id_is_null(kid)) psa_destroy_key(kid);
    return ok;
}

bool web_tls_get_identity(const char **crt_pem, size_t *crt_len,
                          const char **key_pem, size_t *key_len)
{
    if (!s_crt) {
        nvs_handle_t h;
        uint8_t fmt = 0;
        if (nvs_open(TLS_NVS_NS, NVS_READONLY, &h) == ESP_OK) {
            if (!nvs_load_str(h, KEY_CRT, &s_crt, &s_crt_len) ||
                !nvs_load_str(h, KEY_KEY, &s_key, &s_key_len)) {
                free(s_crt); free(s_key); s_crt = s_key = NULL;
            }
            nvs_get_u8(h, KEY_FMT, &fmt);
            nvs_close(h);
        }
        bool renew = false;
        if (s_crt && fmt != CERT_FMT) {
            ESP_LOGW(TAG, "stored certificate is format %u, want %u — regenerating (fingerprint changes)", fmt, CERT_FMT);
            renew = true;
        }
        if (s_crt && !renew && inspect_cert(&renew) && !renew) {
            ESP_LOGI(TAG, "loaded stored TLS identity");
        } else {
            ESP_LOGI(TAG, "%s", s_crt ? "regenerating TLS identity" : "generating TLS identity (first boot)");
            if (!generate_identity()) return false;
            if (!inspect_cert(&renew)) return false;
        }
        ESP_LOGI(TAG, "certificate SHA-256 fingerprint: %s", s_fp);
    }
    *crt_pem = s_crt; *crt_len = s_crt_len;
    *key_pem = s_key; *key_len = s_key_len;
    return true;
}

void web_tls_release_identity(void)
{
    free(s_crt); free(s_key);
    s_crt = s_key = NULL;
    s_crt_len = s_key_len = 0;
}

void web_tls_fingerprint(char *out, size_t cap)
{
    snprintf(out, cap, "%s", s_fp);
}

void web_tls_reset(void)
{
    nvs_handle_t h;
    if (nvs_open(TLS_NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_erase_all(h);
        nvs_commit(h);
        nvs_close(h);
    }
    ESP_LOGW(TAG, "TLS identity erased — a new certificate is generated on next boot");
}

#include "web_auth.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "nvs.h"
#include "psa/crypto.h"
#include "mbedtls/constant_time.h"
#include <string.h>
#include <stdio.h>

static const char *TAG = "web_auth";

/* Same namespace the old Basic-auth code used, so the one-time migration below
 * can find and destroy the legacy plaintext password. */
#define AUTH_NVS_NS   "dns_sink"
#define KEY_USER      "http_user"
#define KEY_LEGACY    "http_pass"      /* plaintext — v1.1 and earlier */
#define KEY_HASH      "http_pw2"       /* blob: struct pw_record */

/* PBKDF2 cost. SHA-256 is hardware-accelerated on the S3; 8k iterations lands
 * around 250 ms per verify, which is invisible on a login form and still a
 * >10^5x slowdown for anyone who lifts the NVS partition off the flash. */
#define PBKDF2_ITERS  8000
#define SALT_LEN      16
#define HASH_LEN      32

typedef struct __attribute__((packed)) {
    uint32_t version;     /* 1 */
    uint32_t iters;
    uint8_t  salt[SALT_LEN];
    uint8_t  hash[HASH_LEN];
} pw_record_t;

static char        s_user[WEB_AUTH_USER_MAX + 1] = "";
static pw_record_t s_rec;
static bool        s_have_rec = false;

/* ── lockout ──────────────────────────────────────────────────────── */
#define LOCK_THRESHOLD   5
#define LOCK_SECONDS     60
static int     s_failures = 0;
static int64_t s_locked_until_us = 0;

/* ── sessions ─────────────────────────────────────────────────────── */
#define MAX_SESSIONS     4
#define SESSION_IDLE_US  (30LL * 60 * 1000000)        /* 30 min idle */
#define SESSION_ABS_US   (12LL * 3600 * 1000000)      /* 12 h absolute */

typedef struct {
    uint8_t token[32];
    uint8_t csrf[16];
    int64_t created_us;
    int64_t last_us;
    bool    used;
} session_t;
static session_t s_sess[MAX_SESSIONS];

/* ── PBKDF2-HMAC-SHA256 (RFC 8018 §5.2) via PSA ───────────────────────
 * mbedtls 4 made both its pkcs5 module and the legacy HMAC API private; the
 * PSA key-derivation interface is the supported way in. */
static bool pbkdf2_sha256(const char *pass, const uint8_t *salt, uint32_t iters, uint8_t out[HASH_LEN])
{
    if (psa_crypto_init() != PSA_SUCCESS) return false;
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    bool ok =
        psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256)) == PSA_SUCCESS &&
        psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST, iters) == PSA_SUCCESS &&
        psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt, SALT_LEN) == PSA_SUCCESS &&
        psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD,
                                       (const uint8_t *)pass, strlen(pass)) == PSA_SUCCESS &&
        psa_key_derivation_output_bytes(&op, out, HASH_LEN) == PSA_SUCCESS;
    psa_key_derivation_abort(&op);
    return ok;
}

/* Set from the USB console task; consumed by the httpd task on its next
 * request so the session table is only ever touched from one task. */
static volatile bool s_reset_pending = false;

static bool save_nvs(void)
{
    nvs_handle_t h;
    esp_err_t e = nvs_open(AUTH_NVS_NS, NVS_READWRITE, &h);
    if (e != ESP_OK) { ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(e)); return false; }
    if (s_user[0]) {
        if ((e = nvs_set_str(h, KEY_USER, s_user)) == ESP_OK)
            e = nvs_set_blob(h, KEY_HASH, &s_rec, sizeof(s_rec));
    } else {
        nvs_erase_key(h, KEY_USER);
        nvs_erase_key(h, KEY_HASH);
    }
    nvs_erase_key(h, KEY_LEGACY);   /* never keep a plaintext copy around */
    if (e == ESP_OK) e = nvs_commit(h);
    nvs_close(h);
    /* A failed write is fail-OPEN at the next boot (no account → setup mode
     * → first host on the LAN becomes admin), so it must not look like
     * success to the caller. */
    if (e != ESP_OK) ESP_LOGE(TAG, "nvs write failed: %s — account NOT persisted", esp_err_to_name(e));
    return e == ESP_OK;
}

void web_auth_init(void)
{
    memset(s_sess, 0, sizeof(s_sess));
    nvs_handle_t h;
    if (nvs_open(AUTH_NVS_NS, NVS_READONLY, &h) != ESP_OK) return;
    size_t ulen = sizeof(s_user);
    if (nvs_get_str(h, KEY_USER, s_user, &ulen) != ESP_OK) s_user[0] = '\0';
    size_t blen = sizeof(s_rec);
    if (nvs_get_blob(h, KEY_HASH, &s_rec, &blen) == ESP_OK && blen == sizeof(s_rec) && s_rec.version == 1)
        s_have_rec = true;

    /* One-time migration from the v1.1 plaintext Basic-auth password: hash it,
     * then erase the plaintext. If only a user with no password of either
     * kind is present (v1.1 "user set, empty pass" was impossible, but be
     * safe), fall back to the setup wizard. */
    char legacy[WEB_AUTH_PASS_MAX + 1] = "";
    size_t llen = sizeof(legacy);
    bool have_legacy = nvs_get_str(h, KEY_LEGACY, legacy, &llen) == ESP_OK && legacy[0];
    nvs_close(h);

    if (!s_have_rec && s_user[0] && have_legacy) {
        if (strlen(legacy) >= WEB_AUTH_PASS_MIN && web_auth_set_credentials(s_user, legacy)) {
            ESP_LOGW(TAG, "migrated legacy plaintext web password to a hash");
        } else {
            /* Too short for the new policy: force a fresh setup rather than
             * carry a weak secret into the production scheme. */
            ESP_LOGW(TAG, "legacy web password below the %d-char minimum — setup required", WEB_AUTH_PASS_MIN);
            s_user[0] = '\0';
            save_nvs();
        }
    } else if (!s_have_rec && s_user[0]) {
        s_user[0] = '\0';
        save_nvs();
    } else if (have_legacy) {
        save_nvs();   /* hash exists; just scrub the plaintext */
    }
    memset(legacy, 0, sizeof(legacy));

    if (web_auth_setup_needed())
        ESP_LOGW(TAG, "no admin account — web UI is in setup mode until one is created");
}

bool web_auth_setup_needed(void)
{
    return s_user[0] == '\0' || !s_have_rec;
}

bool web_auth_set_credentials(const char *user, const char *pass)
{
    size_t ul = strlen(user), pl = strlen(pass);
    if (ul == 0 || ul > WEB_AUTH_USER_MAX) return false;
    if (pl < WEB_AUTH_PASS_MIN || pl > WEB_AUTH_PASS_MAX) return false;
    for (size_t i = 0; i < ul; i++)
        if (user[i] <= ' ' || user[i] == ':' || user[i] > '~') return false;

    pw_record_t rec = { .version = 1, .iters = PBKDF2_ITERS };
    esp_fill_random(rec.salt, SALT_LEN);
    if (!pbkdf2_sha256(pass, rec.salt, rec.iters, rec.hash)) return false;

    char     prev_user[sizeof(s_user)]; memcpy(prev_user, s_user, sizeof(s_user));
    pw_record_t prev_rec = s_rec; bool prev_have = s_have_rec;

    snprintf(s_user, sizeof(s_user), "%s", user);
    s_rec = rec; s_have_rec = true;
    if (!save_nvs()) {
        memcpy(s_user, prev_user, sizeof(s_user)); s_rec = prev_rec; s_have_rec = prev_have;
        return false;
    }
    web_auth_session_destroy_all();   /* credential change logs everyone out */
    s_failures = 0; s_locked_until_us = 0;
    ESP_LOGI(TAG, "admin account \"%s\" saved", s_user);
    return true;
}

void web_auth_reset(void)
{
    /* Console task: erase NVS here (safe — NVS is locked), but leave the
     * in-RAM state to the httpd task via web_auth_poll_reset(). */
    nvs_handle_t h;
    if (nvs_open(AUTH_NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_erase_key(h, KEY_USER);
        nvs_erase_key(h, KEY_HASH);
        nvs_erase_key(h, KEY_LEGACY);
        nvs_commit(h);
        nvs_close(h);
    }
    s_reset_pending = true;
    ESP_LOGW(TAG, "admin account erased — web UI back in setup mode");
}

void web_auth_poll_reset(void)
{
    if (!s_reset_pending) return;
    s_reset_pending = false;
    s_user[0] = '\0'; s_have_rec = false;
    memset(&s_rec, 0, sizeof(s_rec));
    web_auth_session_destroy_all();
    s_failures = 0; s_locked_until_us = 0;
}

void web_auth_get_user(char *out, size_t cap)
{
    snprintf(out, cap, "%s", s_user);
}

bool web_auth_check_password(const char *user, const char *pass, int *retry_after_s)
{
    if (retry_after_s) *retry_after_s = 0;
    int64_t now = esp_timer_get_time();
    if (now < s_locked_until_us) {
        if (retry_after_s) *retry_after_s = (int)((s_locked_until_us - now) / 1000000) + 1;
        return false;
    }
    if (!s_have_rec) return false;

    /* Always run the KDF, even on a wrong username, so timing doesn't reveal
     * whether the username exists. */
    uint8_t got[HASH_LEN] = {0};
    bool kdf_ok = pbkdf2_sha256(pass, s_rec.salt, s_rec.iters, got);
    bool user_ok = strlen(user) == strlen(s_user) &&
                   mbedtls_ct_memcmp(user, s_user, strlen(s_user)) == 0;
    bool pass_ok = kdf_ok && mbedtls_ct_memcmp(got, s_rec.hash, HASH_LEN) == 0;
    memset(got, 0, sizeof(got));

    if (user_ok && pass_ok) { s_failures = 0; return true; }

    if (++s_failures >= LOCK_THRESHOLD) {
        s_failures = 0;
        s_locked_until_us = now + (int64_t)LOCK_SECONDS * 1000000;
        if (retry_after_s) *retry_after_s = LOCK_SECONDS;
        ESP_LOGW(TAG, "%d failed logins — locked for %d s", LOCK_THRESHOLD, LOCK_SECONDS);
    }
    return false;
}

/* ── sessions ─────────────────────────────────────────────────────── */
static bool hex_to_bytes(const char *hex, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        for (int k = 0; k < 2; k++) {
            char c = hex[2 * i + k];
            v <<= 4;
            if      (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
            else return false;
        }
        out[i] = (uint8_t)v;
    }
    return hex[2 * n] == '\0';
}

static void bytes_to_hex(const uint8_t *in, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2*i] = d[in[i] >> 4]; out[2*i+1] = d[in[i] & 15]; }
    out[2 * n] = '\0';
}

static session_t *find_session(const char *token_hex)
{
    if (!token_hex || strlen(token_hex) != WEB_AUTH_TOKEN_HEX) return NULL;
    uint8_t tok[32];
    if (!hex_to_bytes(token_hex, tok, sizeof(tok))) return NULL;
    int64_t now = esp_timer_get_time();
    session_t *hit = NULL;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        session_t *s = &s_sess[i];
        if (!s->used) continue;
        if (now - s->last_us > SESSION_IDLE_US || now - s->created_us > SESSION_ABS_US) {
            memset(s, 0, sizeof(*s));
            continue;
        }
        /* Compare every live slot rather than early-exit, so the scan time
         * doesn't depend on which slot matched. */
        if (mbedtls_ct_memcmp(s->token, tok, sizeof(tok)) == 0) hit = s;
    }
    return hit;
}

bool web_auth_session_create(char *token_out, size_t cap)
{
    if (cap < WEB_AUTH_TOKEN_HEX + 1) return false;
    int64_t now = esp_timer_get_time();
    session_t *slot = NULL;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!s_sess[i].used) { slot = &s_sess[i]; break; }
        if (!slot || s_sess[i].last_us < slot->last_us) slot = &s_sess[i];   /* evict LRU */
    }
    memset(slot, 0, sizeof(*slot));
    esp_fill_random(slot->token, sizeof(slot->token));
    esp_fill_random(slot->csrf, sizeof(slot->csrf));
    slot->created_us = slot->last_us = now;
    slot->used = true;
    bytes_to_hex(slot->token, sizeof(slot->token), token_out);
    return true;
}

bool web_auth_session_valid(const char *token)
{
    return find_session(token) != NULL;
}

void web_auth_session_touch(const char *token)
{
    session_t *s = find_session(token);
    if (s) s->last_us = esp_timer_get_time();
}

void web_auth_session_destroy(const char *token)
{
    session_t *s = find_session(token);
    if (s) memset(s, 0, sizeof(*s));
}

void web_auth_session_destroy_all(void)
{
    memset(s_sess, 0, sizeof(s_sess));
}

bool web_auth_session_csrf(const char *token, char *out, size_t cap)
{
    session_t *s = find_session(token);
    if (!s || cap < 33) return false;
    bytes_to_hex(s->csrf, sizeof(s->csrf), out);
    return true;
}

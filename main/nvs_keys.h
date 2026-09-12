/* nvs_keys.h — the whole NVS keyspace, in one place (#111)
 *
 * Nine modules persist their settings into the single "dns_sink" namespace,
 * each inventing its own key names. Nothing was wrong with the names; what was
 * wrong is that no file could see the others', so "is this prefix already
 * taken?" was answerable only by grepping, and the answer was load-bearing:
 * a prefix collision or a careless nvs_erase_all() silently eats unrelated
 * config. That has already happened once — wl_save_nvs() used nvs_erase_all()
 * and wiped bl_url_*, custom_blk and paused on every whitelist edit
 * (ISSUES.md 2026-08-27, fixed with the key-range erase in blocklist.c).
 *
 * This header is deliberately NOT a migration. Every macro below expands to
 * the byte-identical string the module already wrote, because these keys exist
 * on deployed boards: renaming one does not move the value, it orphans it, and
 * the user silently loses their whitelist / ACL / Wi-Fi credentials / admin
 * password hash on the next boot. Documenting the keyspace costs nothing and
 * risks nothing; renaming it risks everything. See #111 for the migration
 * design if a real namespace split is ever wanted.
 *
 * Rules for adding a key:
 *   1. Add it here, in its module's block — not in the .c file.
 *   2. Keep prefixes disjoint from every other block. The indexed families
 *      below (acl_, byp_, rw_, bl_url_, bl_en_, wl) and the "%s_" net family
 *      are the collision-prone ones: they generate keys at runtime, so a new
 *      fixed key that happens to start with one of those prefixes will not
 *      collide today but will the moment someone widens the family.
 *      Live example: dns_sink.cpp owns both wifi_ssid/wifi_pass AND the
 *      "wifi_" half of the NVSK_NET_* family. They are disjoint only because
 *      no net field is called ssid or pass.
 *   3. NVS truncates nothing — an over-long key fails at runtime with
 *      ESP_ERR_NVS_KEY_TOO_LONG. The static_asserts at the bottom turn that
 *      into a build error instead, including for the runtime-formatted
 *      families at their widest expansion.
 *   4. Never nvs_erase_all() on NVS_NS_MAIN. It is shared. Erase your own key
 *      range, the way blocklist.c does.
 */
#pragma once

#include <assert.h>
#include <inttypes.h>
#include <nvs.h>

/* ── Namespaces ──────────────────────────────────────────────────────
 * Two, not one: web_tls.c keeps the cert and key in its own namespace so a
 * config reset can clear settings without destroying the device identity. */
#define NVS_NS_MAIN     "dns_sink"
#define NVS_NS_WEB_TLS  "web_tls"

/* ── acl.c — allowed client IPs (#10) ──────────────────────────────── */
#define NVSK_ACL_FMT        "acl_%d"        /* acl_0 … acl_7   (ACL_MAX 8) */

/* ── bypass.c — clients that skip filtering entirely ───────────────── */
#define NVSK_BYPASS_FMT     "byp_%d"        /* byp_0 … byp_7   (BYPASS_MAX 8) */

/* ── rewrite.c — local DNS overrides ───────────────────────────────── */
#define NVSK_REWRITE_FMT    "rw_%d"         /* rw_0 … rw_47    (REWRITE_MAX 48) */

/* ── blocklist.c — feeds, whitelist, pause state ───────────────────── */
#define NVSK_CUSTOM_BLOCK   "custom_blk"    /* str: user's own blocked names */
#define NVSK_BL_URL_FMT     "bl_url_%d"     /* str: bl_url_0 … bl_url_3
                                             *      (BLOCKLIST_EXTRA_MAX 4) */
#define NVSK_BL_EN_FMT      "bl_en_%d"      /* u8:  bl_en_0 … bl_en_3, same bound */
#define NVSK_WHITELIST_FMT  "wl%" PRIu32    /* str: wl0 … wl63 (WHITELIST_MAX 64) */
#define NVSK_PAUSED         "paused"        /* u8:  filtering paused */

/* ── dot.c — DNS-over-TLS upstream (#5) ────────────────────────────── */
#define NVSK_DOT_EN         "dot_en"        /* u8  */
#define NVSK_DOT_SERVER     "dot_srv"       /* str: upstream IP */
#define NVSK_DOT_SNI        "dot_sni"       /* str: TLS SNI name */

/* ── localzone.c — split-horizon suffixes ──────────────────────────── */
#define NVSK_LOCAL_ZONES    "local_zones"   /* str: comma-separated */

/* ── timesync.c — last-known-good wall clock ───────────────────────── */
#define NVSK_CLOCK_EPOCH    "clock_ep"      /* u32: epoch seconds */

/* ── web_auth.c — admin credentials ────────────────────────────────── */
#define NVSK_HTTP_USER      "http_user"     /* str */
#define NVSK_HTTP_PW_LEGACY "http_pass"     /* str: plaintext, v1.1 and older */
#define NVSK_HTTP_PW_HASH   "http_pw2"      /* blob: struct pw_record */

/* ── dns_sink.cpp — network and first-boot state ───────────────────── */
#define NVSK_UPSTREAM_IF    "up_if"         /* str: "eth" | "wifi" */
#define NVSK_WIFI_SSID      "wifi_ssid"     /* str */
#define NVSK_WIFI_PASS      "wifi_pass"     /* str */
#define NVSK_WIFI_EN        "wifi_en"       /* u8:  bring up Wi-Fi STA at boot (was
                                             * build-time-only ADBLOCK_NET_WIFI;
                                             * Kconfig now only seeds this on first
                                             * boot — see wifi_enabled_init_nvs()) */
#define NVSK_SETUP_PSK      "setup_psk"     /* str: first-boot setup secret */
/* Per-interface static IP config. The "%s" is the interface name, validated
 * against "eth"/"wifi" before any of these are built — see
 * dns_sink_net_set_static(). Widest expansion is "wifi_mode". */
#define NVSK_NET_MODE_FMT   "%s_mode"       /* u8:  0 = static, 1 = DHCP */
#define NVSK_NET_IP_FMT     "%s_ip"         /* str */
#define NVSK_NET_NM_FMT     "%s_nm"         /* str */
#define NVSK_NET_GW_FMT     "%s_gw"         /* str */
#define NVSK_NET_DNS_FMT    "%s_dns"        /* str */
#define NVSK_NET_IF_WIDEST  "wifi"          /* longest legal "%s" above */

/* ── web_tls.c — device identity, in NVS_NS_WEB_TLS ────────────────── */
#define NVSK_TLS_CERT       "crt_pem"       /* str: PEM certificate */
#define NVSK_TLS_KEY        "key_pem"       /* str: PEM private key */
#define NVSK_TLS_FMT_VER    "fmt"           /* u8:  cert format version */

/* ── Build-time key-length checks ────────────────────────────────────
 * NVS_KEY_NAME_MAX_SIZE counts the NUL, so a key is at most 15 characters.
 * sizeof() a literal counts it too, hence the direct comparison. For the
 * formatted families the check is on the widest key the family can generate,
 * spelled out literally — the point is to fail the build when someone adds a
 * long key or widens an index, not to be clever. */
#define NVSK_ASSERT_FITS(lit) \
    static_assert(sizeof(lit) <= NVS_KEY_NAME_MAX_SIZE, \
                  "NVS key '" lit "' exceeds NVS_KEY_NAME_MAX_SIZE")

/* Indexed families, at the widest key their current bound can generate. Raise
 * these alongside the bound in the owning header — the digit headroom left is
 * noted so it is obvious when a family is close to the limit. */
NVSK_ASSERT_FITS("acl_7");                  /* ACL_MAX 8 — room for 11 digits */
NVSK_ASSERT_FITS("byp_7");                  /* BYPASS_MAX 8 — 11 digits */
NVSK_ASSERT_FITS("rw_47");                  /* REWRITE_MAX 48 — 12 digits */
NVSK_ASSERT_FITS("bl_url_3");               /* BLOCKLIST_EXTRA_MAX 4 — 8 digits,
                                             * the tightest family here */
NVSK_ASSERT_FITS("bl_en_3");                /* same bound — 9 digits */
NVSK_ASSERT_FITS("wl63");                   /* WHITELIST_MAX 64 — 13 digits */
NVSK_ASSERT_FITS(NVSK_CUSTOM_BLOCK);
NVSK_ASSERT_FITS(NVSK_PAUSED);
NVSK_ASSERT_FITS(NVSK_DOT_EN);
NVSK_ASSERT_FITS(NVSK_DOT_SERVER);
NVSK_ASSERT_FITS(NVSK_DOT_SNI);
NVSK_ASSERT_FITS(NVSK_LOCAL_ZONES);
NVSK_ASSERT_FITS(NVSK_CLOCK_EPOCH);
NVSK_ASSERT_FITS(NVSK_HTTP_USER);
NVSK_ASSERT_FITS(NVSK_HTTP_PW_LEGACY);
NVSK_ASSERT_FITS(NVSK_HTTP_PW_HASH);
NVSK_ASSERT_FITS(NVSK_UPSTREAM_IF);
NVSK_ASSERT_FITS(NVSK_WIFI_SSID);
NVSK_ASSERT_FITS(NVSK_WIFI_PASS);
NVSK_ASSERT_FITS(NVSK_WIFI_EN);
NVSK_ASSERT_FITS(NVSK_SETUP_PSK);
NVSK_ASSERT_FITS(NVSK_NET_IF_WIDEST "_mode");
NVSK_ASSERT_FITS(NVSK_NET_IF_WIDEST "_dns");
NVSK_ASSERT_FITS(NVSK_TLS_CERT);
NVSK_ASSERT_FITS(NVSK_TLS_KEY);
NVSK_ASSERT_FITS(NVSK_TLS_FMT_VER);

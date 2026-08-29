#pragma once
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Local zones — names that belong to the LAN, not the internet.
 *
 * When DoT is on, every forward goes to the encrypted upstream (Cloudflare,
 * Quad9, ...) which knows nothing about `printer`, `glolab.lan`, or the
 * router's other DHCP names — they came back NXDOMAIN the moment DoT was
 * enabled. A name matching a local zone is instead forwarded to the plain
 * upstream (normally the router, which is the LAN's authority) exactly as it
 * was before DoT existed: split-horizon by suffix.
 *
 * Matches: any single-label name (no dot at all), and any name whose last
 * label(s) equal one of the configured suffixes. The list is one NVS string
 * ("local_zones", comma-separated, no leading dots). Default:
 * lan,local,home,home.arpa,internal,localdomain,intranet.
 *
 * Read from the dns_task hot path (forward decision only — not a verdict, so
 * the two-verdict-path rule doesn't apply: the L2 hook never forwards). The
 * suffix table is small and swapped atomically as a whole on save. */

#define LOCALZONE_LIST_CAP 256

bool localzone_init_nvs(void);
bool localzone_match(const char *name, size_t len);
/* Comma-separated list in/out. set() normalises (lowercase, trims, drops
 * leading dots and empties) and persists; returns false if it doesn't fit. */
bool localzone_set(const char *list);
void localzone_get(char *out, size_t cap);
const char *localzone_default(void);

#ifdef __cplusplus
}
#endif

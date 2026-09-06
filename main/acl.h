#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/* Client IP access control list — if non-empty, only listed IPs may use DNS (#10).
 * Up to 8 entries, NVS-backed. Empty = allow all. */
#define ACL_MAX 8

bool     acl_init(void);
bool     acl_add(const char *ip_str);
bool     acl_remove(const char *ip_str);
bool     acl_clear(void);
uint32_t acl_count(void);
void     acl_list(char out[][20], uint32_t *count_inout);

/* Returns true if client should be allowed (ACL empty OR ip in list). */
bool     acl_permits(uint32_t client_ip_hbo);

/* Non-blocking variant for the L2 Ethernet fast path (#87). Returns true only
 * when permission can be proven without waiting on the mutex; a denied client
 * AND a busy lock both return false, and the caller must then defer the frame
 * to lwIP, where the full acl_permits() runs and drops it if it really is
 * denied. Never answers on its own authority when it cannot tell. */
bool     acl_permits_nb(uint32_t client_ip_hbo);

/* Dotted-quad -> host byte order, 0 on anything malformed. Rejects octets
 * above 255 and trailing junk, which the ACL's own parser used to accept.
 * Shared so the ACL, the web UI and the USB console agree on what an address
 * is — three private copies had already started to drift. 0.0.0.0 reads as
 * "not an address" for every caller, which is what they all want. */
uint32_t acl_parse_ip4(const char *s);

#ifdef __cplusplus
}
#endif

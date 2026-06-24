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

#ifdef __cplusplus
}
#endif

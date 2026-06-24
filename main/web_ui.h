#pragma once
#include "dns_server.h"

/* Start the minimal HTTP status + control server on port 80.
 * dns is used for live stats. Call after Ethernet is up. */
bool web_ui_start(DnsSinkServer *dns);
void web_ui_stop(void);

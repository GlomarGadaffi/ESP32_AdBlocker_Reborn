#pragma once
#ifdef __cplusplus
extern "C" {
#endif

/* Minimal USB recovery console over the native USB-Serial-JTAG port.
 * Rescues a headless board over the same cable that flashes it. */
void console_start(void);

#ifdef __cplusplus
}
#endif

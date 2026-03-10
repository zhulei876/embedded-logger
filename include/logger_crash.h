/**
 * @file    logger_crash.h
 * @brief   Passive crash capture via POSIX signal handlers
 *
 * Installs handlers for SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL.
 * On crash, captures:
 *  - Signal name and number
 *  - Faulting address (si_addr)
 *  - Stack backtrace via backtrace() / backtrace_symbols_fd()
 *  - Register dump (where available via ucontext_t)
 *
 * All output goes through the storage layer using async-signal-safe
 * system calls (write(2)) to avoid re-entrancy issues.
 */

#ifndef LOGGER_CRASH_H
#define LOGGER_CRASH_H

#ifdef __cplusplus
extern "C" {
#endif

#include "logger.h"

/**
 * @brief  Install crash signal handlers.
 *         Must be called after logger_init().
 */
LOGGER_RET_E crash_handler_install(void);

/**
 * @brief  Uninstall crash signal handlers (restore defaults).
 */
void crash_handler_uninstall(void);

#ifdef __cplusplus
}
#endif

#endif /* LOGGER_CRASH_H */

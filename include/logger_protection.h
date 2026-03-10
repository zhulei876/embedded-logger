/**
 * @file    logger_protection.h
 * @brief   Deduplication / flood protection for the log subsystem
 *
 * Detects abnormally repeated log messages within a configurable
 * time window and suppresses them, recording only:
 *   1) The first occurrence (full entry).
 *   2) A summary line at window expiry:
 *      "[SUPPRESSED] Previous message repeated N times in Xms"
 *
 * This prevents fast-looping subsystems (e.g. an I2C driver firing
 * every 10 ms) from flooding the log buffer and evicting valuable
 * entries from other modules.
 */

#ifndef LOGGER_PROTECTION_H
#define LOGGER_PROTECTION_H

#ifdef __cplusplus
extern "C" {
#endif

#include "logger.h"
#include <stdbool.h>
#include <stdint.h>

/* =========================================================================
 * Protection API
 * ========================================================================= */

/**
 * @brief  Initialize the deduplication engine.
 * @param  cfg  Protection configuration.
 */
LOGGER_RET_E protection_init(const LoggerProtectionCfg *cfg);

/**
 * @brief  Destroy deduplication state, flush any pending summaries.
 */
void protection_destroy(void);

/**
 * @brief  Check if a log entry should be written or suppressed.
 *
 * @param  module    Source module name.
 * @param  level     Log level.
 * @param  message   Fully-formatted log message.
 * @param  allow     [out] true = write entry; false = suppress.
 * @param  summary   [out] If non-NULL on return, caller must write this
 *                   suppression-summary string before the new entry.
 *                   Points to internal buffer valid until next call.
 */
LOGGER_RET_E protection_check(const char    *module,
                                LOGGER_LEVEL_E level,
                                const char    *message,
                                bool          *allow,
                                const char   **summary);

#ifdef __cplusplus
}
#endif

#endif /* LOGGER_PROTECTION_H */

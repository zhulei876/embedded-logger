/**
 * @file    logger.h
 * @brief   Embedded Logger Library - Public API
 *
 * Provides 8-level logging with offline storage, UDP transport,
 * encryption, deduplication, crash capture, and self-protection.
 *
 * @author  EmbeddedLogger Project
 * @version 1.0.0
 */

#ifndef LOGGER_H
#define LOGGER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* =========================================================================
 * Version
 * ========================================================================= */
#define LOGGER_VERSION_MAJOR   1
#define LOGGER_VERSION_MINOR   0
#define LOGGER_VERSION_PATCH   0
#define LOGGER_VERSION_STRING  "1.0.0"

/* =========================================================================
 * Log Level Enumeration
 * ========================================================================= */
typedef enum {
    MSG_EMERG   = 0,   /**< System is unusable                   */
    MSG_ALERT   = 1,   /**< Action must be taken immediately      */
    MSG_CRIT    = 2,   /**< Critical conditions                   */
    MSG_ERR     = 3,   /**< Error conditions                      */
    MSG_WARNING = 4,   /**< Warning conditions                    */
    MSG_NOTICE  = 5,   /**< Normal but significant condition      */
    MSG_INFO    = 6,   /**< Informational                         */
    MSG_DEBUG   = 7,   /**< Debug-level messages                  */
    MSG_LEVEL_MAX = 8
} LOGGER_LEVEL_E;

/* =========================================================================
 * Return Codes
 * ========================================================================= */
typedef enum {
    LOGGER_OK           =  0,
    LOGGER_ERR_INIT     = -1,
    LOGGER_ERR_PARAM    = -2,
    LOGGER_ERR_NOMEM    = -3,
    LOGGER_ERR_IO       = -4,
    LOGGER_ERR_FULL     = -5,
    LOGGER_ERR_CRYPTO   = -6,
    LOGGER_ERR_NOTFOUND = -7,
    LOGGER_ERR_TIMEOUT  = -8,
} LOGGER_RET_E;

/* =========================================================================
 * Configuration Structure
 * ========================================================================= */

/** Storage configuration */
typedef struct {
    char    storage_dir[256];   /**< Directory for log files          */
    size_t  max_file_size;      /**< Max size per log file (bytes)    */
    size_t  max_total_size;     /**< Max total size for all logs      */
    bool    encrypt_files;      /**< Enable AES-256 encryption        */
} LoggerStorageCfg;

/** Transport (UDP) configuration */
typedef struct {
    char    bind_ip[64];        /**< Local bind IP (loopback default) */
    uint16_t bind_port;         /**< Local UDP port                   */
    char    remote_ip[64];      /**< Remote IP for sending logs       */
    uint16_t remote_port;       /**< Remote UDP port                  */
    uint32_t send_interval_ms;  /**< Interval between sends (ms)      */
    size_t  chunk_size;         /**< UDP chunk size for large payloads*/
    bool    encrypt_transport;  /**< Encrypt UDP payload (AES-256)    */
} LoggerTransportCfg;

/** Deduplication / self-protection configuration */
typedef struct {
    uint32_t dedup_window_ms;   /**< Time window for dedup (ms)       */
    uint32_t dedup_max_count;   /**< Max repeats before suppression   */
} LoggerProtectionCfg;

/** Top-level logger configuration */
typedef struct {
    LOGGER_LEVEL_E      min_level;      /**< Minimum level to record  */
    LoggerStorageCfg    storage;
    LoggerTransportCfg  transport;
    LoggerProtectionCfg protection;
    char                config_path[256]; /**< Path to config file    */
} LoggerConfig;

/* =========================================================================
 * Public API
 * ========================================================================= */

/**
 * @brief  Initialize the logger from a config file.
 * @param  config_path  Path to config.ini / config.json file.
 *                      Pass NULL to use built-in defaults.
 * @return LOGGER_OK on success, negative on error.
 */
LOGGER_RET_E logger_init(const char *config_path);

/**
 * @brief  Destroy logger, flush and close all resources.
 */
void logger_destroy(void);

/**
 * @brief  Write a log message (active/manual trigger).
 *
 * @param  level    Log severity level.
 * @param  module   Module name string (e.g. "SD_CARD").
 * @param  fmt      printf-style format string.
 * @param  ...      Format arguments.
 * @return LOGGER_OK on success.
 *
 * Example:
 *   logger_write(MSG_INFO, "SD_CARD", "SD card mount success");
 *   → [2025-08-25 14:30:00] [INFO] [PID:1234] [SD_CARD] SD card mount success
 */
LOGGER_RET_E logger_write(LOGGER_LEVEL_E level,
                           const char    *module,
                           const char    *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/**
 * @brief  Install signal handlers for passive crash capture.
 *         Catches SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL.
 * @return LOGGER_OK on success.
 */
LOGGER_RET_E logger_install_crash_handler(void);

/**
 * @brief  Get current logger configuration (read-only copy).
 * @param  cfg  Output pointer to receive config copy.
 */
void logger_get_config(LoggerConfig *cfg);

/**
 * @brief  Dynamically change minimum log level at runtime.
 * @param  level  New minimum level.
 */
void logger_set_level(LOGGER_LEVEL_E level);

/* =========================================================================
 * Convenience Macros
 * ========================================================================= */
#define LOG_EMERG(mod, fmt, ...)   logger_write(MSG_EMERG,   mod, fmt, ##__VA_ARGS__)
#define LOG_ALERT(mod, fmt, ...)   logger_write(MSG_ALERT,   mod, fmt, ##__VA_ARGS__)
#define LOG_CRIT(mod, fmt, ...)    logger_write(MSG_CRIT,    mod, fmt, ##__VA_ARGS__)
#define LOG_ERR(mod, fmt, ...)     logger_write(MSG_ERR,     mod, fmt, ##__VA_ARGS__)
#define LOG_WARN(mod, fmt, ...)    logger_write(MSG_WARNING, mod, fmt, ##__VA_ARGS__)
#define LOG_NOTICE(mod, fmt, ...)  logger_write(MSG_NOTICE,  mod, fmt, ##__VA_ARGS__)
#define LOG_INFO(mod, fmt, ...)    logger_write(MSG_INFO,    mod, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(mod, fmt, ...)   logger_write(MSG_DEBUG,   mod, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* LOGGER_H */

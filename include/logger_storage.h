/**
 * @file    logger_storage.h
 * @brief   Offline log file storage engine
 *
 * Manages log file creation, rotation, size enforcement, and
 * encrypted I/O using POSIX low-level syscalls (no fopen/fwrite).
 */

#ifndef LOGGER_STORAGE_H
#define LOGGER_STORAGE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "logger.h"
#include <stdint.h>

/* =========================================================================
 * File Metadata (returned via UDP query)
 * ========================================================================= */
typedef struct {
    char     filename[256];   /**< Filename (basename)          */
    char     filepath[512];   /**< Full path                    */
    size_t   size_bytes;      /**< File size in bytes           */
    uint64_t created_ts;      /**< Unix timestamp of creation   */
} LogFileInfo;

/* =========================================================================
 * Storage API
 * ========================================================================= */

/**
 * @brief  Initialize storage subsystem.
 * @param  cfg  Storage configuration.
 */
LOGGER_RET_E storage_init(const LoggerStorageCfg *cfg);

/**
 * @brief  Destroy and flush storage subsystem.
 */
void storage_destroy(void);

/**
 * @brief  Write a formatted log entry to the current log file.
 *         Creates a new file if needed; rotates when max_file_size exceeded.
 *         Deletes oldest file if max_total_size exceeded.
 *
 * @param  entry   Formatted log line (null-terminated).
 * @param  len     Length of entry (excluding null terminator).
 */
LOGGER_RET_E storage_write(const char *entry, size_t len);

/**
 * @brief  List all log files in the storage directory.
 * @param  out_files    Caller-allocated array to populate.
 * @param  max_count    Capacity of out_files array.
 * @param  out_count    Number of files actually populated.
 */
LOGGER_RET_E storage_list_files(LogFileInfo *out_files,
                                 uint32_t     max_count,
                                 uint32_t    *out_count);

/**
 * @brief  Read the contents of a named log file, optionally filtered
 *         by minimum log level.
 *
 * @param  filename     Basename of the target log file.
 * @param  min_level    Minimum level to include (MSG_LEVEL_MAX = all).
 * @param  out_buf      Caller-allocated output buffer.
 * @param  buf_size     Size of output buffer.
 * @param  out_len      Bytes written to out_buf.
 */
LOGGER_RET_E storage_read_file(const char    *filename,
                                LOGGER_LEVEL_E min_level,
                                char          *out_buf,
                                size_t         buf_size,
                                size_t        *out_len);

/**
 * @brief  Return total disk usage of all log files (bytes).
 */
size_t storage_total_size(void);

/**
 * @brief  Rotate: force creation of a new log file (e.g. at startup).
 */
LOGGER_RET_E storage_rotate(void);

#ifdef __cplusplus
}
#endif

#endif /* LOGGER_STORAGE_H */

/**
 * @file    logger_core.c
 * @brief   Core logger implementation
 *
 * Orchestrates: config loading → dedup check → format entry →
 *               storage write → UDP transport send.
 *
 * 【约束】：禁止调用 libc 文件操作函数（open/stat/fopen 等），
 *          配置文件读取全程使用 SYS_openat / SYS_read / SYS_close。
 *
 * Thread-safe via a single pthread_mutex_t protecting the write path.
 */

#include "logger.h"
#include "logger_storage.h"
#include "logger_transport.h"
#include "logger_crypto.h"
#include "logger_protection.h"
#include "logger_crash.h"

#include <stdio.h>      /* snprintf / vsnprintf only */
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <fcntl.h>      /* O_RDONLY */

/* 包内私有：crash 模块暴露给 core 使用 */
extern void logger_crash_set_dir(const char *storage_dir);

/* =========================================================================
 * 裸系统调用：配置文件读取（禁止 open() / fopen()）
 * ========================================================================= */
#ifndef __NR_openat
#  define __NR_openat 257
#endif
#ifndef __NR_read
#  define __NR_read     0
#endif
#ifndef __NR_close
#  define __NR_close    3
#endif
#ifndef AT_FDCWD
#  define AT_FDCWD  (-100)
#endif

static inline int core_open_ro(const char *path)
{
    return (int)syscall(__NR_openat, AT_FDCWD, path, O_RDONLY, 0);
}
static inline ssize_t core_read(int fd, void *buf, size_t n)
{
    return (ssize_t)syscall(__NR_read, fd, buf, n);
}
static inline void core_close(int fd)
{
    syscall(__NR_close, fd);
}

/* =========================================================================
 * Internal State
 * ========================================================================= */
typedef struct {
    bool            initialized;
    LoggerConfig    cfg;
    pthread_mutex_t lock;
} LoggerState;

static LoggerState g_state = {
    .initialized = false,
    .lock        = PTHREAD_MUTEX_INITIALIZER,
};

/* =========================================================================
 * Level Name Table
 * ========================================================================= */
static const char * const k_level_names[MSG_LEVEL_MAX] = {
    "EMERG", "ALERT", "CRIT", "ERR",
    "WARNING", "NOTICE", "INFO", "DEBUG"
};

/* =========================================================================
 * Internal Helpers
 * ========================================================================= */

/**
 * @brief  Load configuration from an INI file.
 *         Simple line-by-line key=value parser; no external dependency.
 *
 * Expected sections and keys:
 *   [general]     min_level = 6
 *   [storage]     dir = /var/log/myapp
 *                 max_file_size = 1048576
 *                 max_total_size = 10485760
 *                 encrypt = 1
 *   [transport]   bind_ip = 127.0.0.1
 *                 bind_port = 9000
 *                 remote_ip = 127.0.0.1
 *                 remote_port = 9001
 *                 send_interval_ms = 500
 *                 chunk_size = 1400
 *                 encrypt = 1
 *   [protection]  dedup_window_ms = 5000
 *                 dedup_max_count = 10
 */
static LOGGER_RET_E load_config_ini(const char *path, LoggerConfig *cfg)
{
    /* 使用 SYS_openat — 禁止 open() / fopen() */
    int fd = core_open_ro(path);
    if (fd < 0) return LOGGER_ERR_IO;

    char    buf[4096];
    ssize_t n = core_read(fd, buf, sizeof(buf) - 1);
    core_close(fd);
    if (n < 0) return LOGGER_ERR_IO;
    buf[n] = '\0';

    char section[64] = {0};
    char *line = buf;

    while (line && *line) {
        char *end = strchr(line, '\n');
        if (end) *end = '\0';

        /* Trim leading whitespace */
        while (*line == ' ' || *line == '\t') line++;

        if (*line == '[') {
            /* Section header */
            char *close = strchr(line, ']');
            if (close) {
                size_t len = (size_t)(close - line - 1);
                if (len < sizeof(section)) {
                    memcpy(section, line + 1, len);
                    section[len] = '\0';
                }
            }
        } else if (*line && *line != '#' && *line != ';') {
            char key[64]  = {0};
            char val[256] = {0};
            if (sscanf(line, " %63[^=] = %255[^\n]", key, val) == 2) {
                /* Trim trailing spaces in key */
                char *kend = key + strlen(key) - 1;
                while (kend > key && *kend == ' ') *kend-- = '\0';

                if (strcmp(section, "general") == 0) {
                    if (strcmp(key, "min_level") == 0)
                        cfg->min_level = (LOGGER_LEVEL_E)atoi(val);
                } else if (strcmp(section, "storage") == 0) {
                    if      (strcmp(key, "dir") == 0)
                        snprintf(cfg->storage.storage_dir, sizeof(cfg->storage.storage_dir), "%s", val);
                    else if (strcmp(key, "max_file_size") == 0)
                        cfg->storage.max_file_size = (size_t)atoll(val);
                    else if (strcmp(key, "max_total_size") == 0)
                        cfg->storage.max_total_size = (size_t)atoll(val);
                    else if (strcmp(key, "encrypt") == 0)
                        cfg->storage.encrypt_files = (atoi(val) != 0);
                } else if (strcmp(section, "transport") == 0) {
                    if      (strcmp(key, "bind_ip") == 0)
                        snprintf(cfg->transport.bind_ip, sizeof(cfg->transport.bind_ip), "%.63s", val);
                    else if (strcmp(key, "bind_port") == 0)
                        cfg->transport.bind_port = (uint16_t)atoi(val);
                    else if (strcmp(key, "remote_ip") == 0)
                        snprintf(cfg->transport.remote_ip, sizeof(cfg->transport.remote_ip), "%.63s", val);
                    else if (strcmp(key, "remote_port") == 0)
                        cfg->transport.remote_port = (uint16_t)atoi(val);
                    else if (strcmp(key, "send_interval_ms") == 0)
                        cfg->transport.send_interval_ms = (uint32_t)atol(val);
                    else if (strcmp(key, "chunk_size") == 0)
                        cfg->transport.chunk_size = (size_t)atoi(val);
                    else if (strcmp(key, "encrypt") == 0)
                        cfg->transport.encrypt_transport = (atoi(val) != 0);
                } else if (strcmp(section, "protection") == 0) {
                    if      (strcmp(key, "dedup_window_ms") == 0)
                        cfg->protection.dedup_window_ms = (uint32_t)atol(val);
                    else if (strcmp(key, "dedup_max_count") == 0)
                        cfg->protection.dedup_max_count = (uint32_t)atol(val);
                }
            }
        }

        line = end ? end + 1 : NULL;
    }
    return LOGGER_OK;
}

/**
 * @brief  Apply safe built-in defaults.
 */
static void apply_defaults(LoggerConfig *cfg)
{
    cfg->min_level = MSG_DEBUG;
    snprintf(cfg->storage.storage_dir, sizeof(cfg->storage.storage_dir), "/tmp/logger_data");
    cfg->storage.max_file_size    = 1 * 1024 * 1024;   /* 1 MB  */
    cfg->storage.max_total_size   = 10 * 1024 * 1024;  /* 10 MB */
    cfg->storage.encrypt_files    = false;

    snprintf(cfg->transport.bind_ip, sizeof(cfg->transport.bind_ip), "127.0.0.1");
    cfg->transport.bind_port          = 9000;
    snprintf(cfg->transport.remote_ip, sizeof(cfg->transport.remote_ip), "127.0.0.1");
    cfg->transport.remote_port        = 9001;
    cfg->transport.send_interval_ms   = 500;
    cfg->transport.chunk_size         = TRANSPORT_MAX_CHUNK;
    cfg->transport.encrypt_transport  = false;

    cfg->protection.dedup_window_ms   = 5000;
    cfg->protection.dedup_max_count   = 10;
}

/**
 * @brief  Format a single log entry into out_buf.
 *         Format: [YYYY-MM-DD HH:MM:SS] [LEVEL] [PID:NNNN] [MODULE] message
 */
static int format_entry(char          *out_buf,
                         size_t         buf_size,
                         LOGGER_LEVEL_E level,
                         const char    *module,
                         const char    *message)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm_info;
    localtime_r(&ts.tv_sec, &tm_info);

    const char *lvl = (level < MSG_LEVEL_MAX)
                      ? k_level_names[level] : "UNKNOWN";

    return snprintf(out_buf, buf_size,
                    "[%04d-%02d-%02d %02d:%02d:%02d] [%s] [PID:%d] [%s] %s\n",
                    tm_info.tm_year + 1900,
                    tm_info.tm_mon  + 1,
                    tm_info.tm_mday,
                    tm_info.tm_hour,
                    tm_info.tm_min,
                    tm_info.tm_sec,
                    lvl,
                    (int)getpid(),
                    module ? module : "UNKNOWN",
                    message);
}

/* =========================================================================
 * Public API Implementation
 * ========================================================================= */

LOGGER_RET_E logger_init(const char *config_path)
{
    pthread_mutex_lock(&g_state.lock);
    if (g_state.initialized) {
        pthread_mutex_unlock(&g_state.lock);
        return LOGGER_OK;
    }

    apply_defaults(&g_state.cfg);

    if (config_path && *config_path) {
        LOGGER_RET_E rc = load_config_ini(config_path, &g_state.cfg);
        if (rc != LOGGER_OK) {
            /* Non-fatal: continue with defaults */
        }
        strncpy(g_state.cfg.config_path, config_path,
                sizeof(g_state.cfg.config_path) - 1);
    }

    /* Initialize subsystems in dependency order */
    LOGGER_RET_E rc;

    rc = storage_init(&g_state.cfg.storage);
    if (rc != LOGGER_OK) goto fail;

    /* 告知崩溃捕获模块存储目录，用于写入 crash.log */
    logger_crash_set_dir(g_state.cfg.storage.storage_dir);

    if (g_state.cfg.storage.encrypt_files ||
        g_state.cfg.transport.encrypt_transport) {
        char key_path[512];
        snprintf(key_path, sizeof(key_path), "%s/.logger_key",
                 g_state.cfg.storage.storage_dir);
        rc = crypto_init(key_path);
        if (rc != LOGGER_OK) goto fail;
    }

    rc = protection_init(&g_state.cfg.protection);
    if (rc != LOGGER_OK) goto fail;

    rc = transport_init(&g_state.cfg.transport);
    if (rc != LOGGER_OK) goto fail;

    rc = transport_start_query_server();
    if (rc != LOGGER_OK) goto fail;

    g_state.initialized = true;
    pthread_mutex_unlock(&g_state.lock);
    return LOGGER_OK;

fail:
    pthread_mutex_unlock(&g_state.lock);
    return rc;
}

void logger_destroy(void)
{
    pthread_mutex_lock(&g_state.lock);
    if (!g_state.initialized) {
        pthread_mutex_unlock(&g_state.lock);
        return;
    }
    transport_stop_query_server();
    transport_destroy();
    protection_destroy();
    crypto_destroy();
    storage_destroy();
    g_state.initialized = false;
    pthread_mutex_unlock(&g_state.lock);
}

LOGGER_RET_E logger_write(LOGGER_LEVEL_E level,
                           const char    *module,
                           const char    *fmt, ...)
{
    if (!g_state.initialized)       return LOGGER_ERR_INIT;
    if (level > g_state.cfg.min_level) return LOGGER_OK; /* filtered */
    if (level >= MSG_LEVEL_MAX)        return LOGGER_ERR_PARAM;

    /* Format message body */
    char msg_body[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg_body, sizeof(msg_body), fmt, args);
    va_end(args);

    /* Format full entry */
    char entry[1536];
    int  entry_len = format_entry(entry, sizeof(entry), level, module, msg_body);
    if (entry_len <= 0) return LOGGER_ERR_PARAM;

    pthread_mutex_lock(&g_state.lock);

    /* Deduplication check */
    bool        allow   = true;
    const char *summary = NULL;
    protection_check(module, level, msg_body, &allow, &summary);

    LOGGER_RET_E rc = LOGGER_OK;

    /* Write suppression summary first if dedup window just closed */
    if (summary) {
        char sum_entry[1536];
        int  sum_len = format_entry(sum_entry, sizeof(sum_entry),
                                    MSG_NOTICE, module, summary);
        if (sum_len > 0) {
            storage_write(sum_entry, (size_t)sum_len);
            transport_send_log(sum_entry);
        }
    }

    if (allow) {
        rc = storage_write(entry, (size_t)entry_len);
        transport_send_log(entry);   /* best-effort; ignore RC */
    }

    pthread_mutex_unlock(&g_state.lock);
    return rc;
}

LOGGER_RET_E logger_install_crash_handler(void)
{
    return crash_handler_install();
}

void logger_get_config(LoggerConfig *cfg)
{
    if (!cfg) return;
    pthread_mutex_lock(&g_state.lock);
    *cfg = g_state.cfg;
    pthread_mutex_unlock(&g_state.lock);
}

void logger_set_level(LOGGER_LEVEL_E level)
{
    if (level >= MSG_LEVEL_MAX) return;
    pthread_mutex_lock(&g_state.lock);
    g_state.cfg.min_level = level;
    pthread_mutex_unlock(&g_state.lock);
}

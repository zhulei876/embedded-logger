/**
 * @file    logger_storage.c
 * @brief   Log file storage — 纯裸系统调用实现
 *
 * 【约束】：禁止使用任何 libc 文件操作函数（fopen/fwrite/fread/fclose/
 *           stat/mkdir/opendir/readdir/closedir/unlink/rename 等）。
 *          全部 I/O 使用 syscall(SYS_*) 直接调用内核。
 *
 * 目录遍历：通过 SYS_getdents64 读取目录项，自实现迭代逻辑。
 * 目录创建：SYS_mkdirat(AT_FDCWD, path, 0755)。
 * 文件状态：SYS_statx(AT_FDCWD, path, flags, mask, &buf)。
 * 文件删除：SYS_unlinkat(AT_FDCWD, path, 0)。
 * 文件读写：SYS_openat / SYS_read / SYS_write / SYS_close。
 *
 * 写入帧格式：[uint32_t frame_len LE][payload]
 *             读取时按帧逐条解码，支持级别过滤与解密。
 */

#include "logger_storage.h"
#include "logger_crypto.h"

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <stdio.h>      /* only for snprintf() */

/* 仅允许使用系统调用相关头文件 */
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <fcntl.h>      /* O_* 常量定义 */

/* =========================================================================
 * 系统调用号（x86-64 Linux；其他架构修改此处即可）
 * ========================================================================= */
#ifndef __NR_openat
#  define __NR_openat     257
#endif
#ifndef __NR_read
#  define __NR_read         0
#endif
#ifndef __NR_write
#  define __NR_write        1
#endif
#ifndef __NR_close
#  define __NR_close        3
#endif
#ifndef __NR_mkdirat
#  define __NR_mkdirat    258
#endif
#ifndef __NR_unlinkat
#  define __NR_unlinkat   263
#endif
#ifndef __NR_getdents64
#  define __NR_getdents64 217
#endif
#ifndef __NR_statx
#  define __NR_statx      332
#endif

#ifndef AT_FDCWD
#  define AT_FDCWD  (-100)
#endif
#ifndef AT_STATX_SYNC_AS_STAT
#  define AT_STATX_SYNC_AS_STAT 0x0000
#endif
#ifndef O_DIRECTORY
#  define O_DIRECTORY 0200000
#endif

/* =========================================================================
 * 裸系统调用封装
 * ========================================================================= */

static inline int sc_openat(const char *path, int flags, int mode)
{
    return (int)syscall(__NR_openat, AT_FDCWD, path, flags, mode);
}

static inline int sc_close(int fd)
{
    return (int)syscall(__NR_close, fd);
}

static inline ssize_t sc_write(int fd, const void *buf, size_t n)
{
    return (ssize_t)syscall(__NR_write, fd, buf, n);
}

static inline ssize_t sc_read(int fd, void *buf, size_t n)
{
    return (ssize_t)syscall(__NR_read, fd, buf, n);
}

static inline int sc_mkdirat(const char *path, unsigned int mode)
{
    return (int)syscall(__NR_mkdirat, AT_FDCWD, path, (long)mode);
}

/** 删除文件：flags=0；删除空目录：flags=AT_REMOVEDIR */
static inline int sc_unlinkat(const char *path, int flags)
{
    return (int)syscall(__NR_unlinkat, AT_FDCWD, path, flags);
}

/* =========================================================================
 * statx 结构与封装（内核 ABI 稳定，不依赖 glibc 版本）
 * ========================================================================= */

/* statx 需要的掩码位 */
#define SC_STATX_TYPE  0x00000001U
#define SC_STATX_SIZE  0x00000200U
#define SC_STATX_MTIME 0x00000040U

/* statx 结构最小化定义（按内核 uapi/linux/stat.h） */
struct sc_statx_timestamp { int64_t tv_sec; uint32_t tv_nsec; uint32_t pad; };
struct sc_statx {
    uint32_t stx_mask;        uint32_t stx_blksize;
    uint64_t stx_attributes;  uint32_t stx_nlink;
    uint32_t stx_uid;         uint32_t stx_gid;
    uint16_t stx_mode;        uint16_t spare0[1];
    uint64_t stx_ino;         uint64_t stx_size;
    uint64_t stx_blocks;      uint64_t stx_attributes_mask;
    struct sc_statx_timestamp stx_atime;
    struct sc_statx_timestamp stx_btime;
    struct sc_statx_timestamp stx_ctime;
    struct sc_statx_timestamp stx_mtime;
    uint32_t stx_rdev_major;  uint32_t stx_rdev_minor;
    uint32_t stx_dev_major;   uint32_t stx_dev_minor;
    uint64_t stx_mnt_id;      uint64_t spare2;
    uint64_t spare3[12];
};

#define SC_S_IFMT   0170000
#define SC_S_IFREG  0100000
#define SC_S_IFDIR  0040000

static int sc_statx(const char *path, struct sc_statx *out)
{
    uint32_t mask = SC_STATX_TYPE | SC_STATX_SIZE | SC_STATX_MTIME;
    return (int)syscall(__NR_statx,
                        AT_FDCWD,
                        path,
                        AT_STATX_SYNC_AS_STAT,
                        (long)mask,
                        out);
}

static inline bool sc_is_reg(const struct sc_statx *st)
{
    return ((st->stx_mode & SC_S_IFMT) == SC_S_IFREG);
}

static inline bool sc_is_dir(const struct sc_statx *st)
{
    return ((st->stx_mode & SC_S_IFMT) == SC_S_IFDIR);
}

/* =========================================================================
 * getdents64 结构：不依赖 <dirent.h>
 * ========================================================================= */
struct sc_dirent64 {
    uint64_t d_ino;
    int64_t  d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[];
};

#define SC_DENTS_BUF  4096

/* =========================================================================
 * 内部状态
 * ========================================================================= */
#define MAX_LOG_FILES 256

typedef struct {
    bool             initialized;
    LoggerStorageCfg cfg;
    int              current_fd;
    char             current_path[512];
    size_t           current_size;
    pthread_mutex_t  lock;
} StorageState;

static StorageState g_storage = {
    .initialized = false,
    .current_fd  = -1,
    .lock        = PTHREAD_MUTEX_INITIALIZER,
};

/* =========================================================================
 * 辅助：完整写入（处理短写）
 * ========================================================================= */
static LOGGER_RET_E sc_write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p    = (const uint8_t *)buf;
    size_t         left = len;
    while (left > 0) {
        ssize_t n = sc_write(fd, p, left);
        if (n <= 0) return LOGGER_ERR_IO;
        p    += (size_t)n;
        left -= (size_t)n;
    }
    return LOGGER_OK;
}

/* =========================================================================
 * 内部逻辑
 * ========================================================================= */
 
/**
 * @brief  确保存储目录存在。
 *
 *  - 使用 sc_statx 检测路径类型。
 *  - 不存在则 sc_mkdirat 创建（EEXIST 视为成功）。
 *  - 禁止调用 stat() / mkdir()。
 */
static LOGGER_RET_E ensure_dir(const char *dir)
{
    struct sc_statx st;
    int ret = sc_statx(dir, &st);
    if (ret == 0) {
        return sc_is_dir(&st) ? LOGGER_OK : LOGGER_ERR_IO;
    }
    /* ENOENT → 尝试创建 */
    ret = sc_mkdirat(dir, 0755);
    if (ret == 0 || errno == EEXIST) return LOGGER_OK;
    return LOGGER_ERR_IO;
}

/** 创建并打开一个新的日志文件（包含同一秒内的溢出后缀逻辑）。 */
static LOGGER_RET_E open_new_file(void)
{
    if (g_storage.current_fd >= 0) {
        sc_close(g_storage.current_fd);
        g_storage.current_fd = -1;
    }

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);

    int overflow_index = 0;

    /* 寻找当前秒内可用的文件名 */
    while (1) {
        if (overflow_index == 0) {
            /* 默认标准格式 */
            snprintf(g_storage.current_path, sizeof(g_storage.current_path),
                     "%s/log-%04d%02d%02d-%02d%02d%02d.txt",
                     g_storage.cfg.storage_dir,
                     tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                     tm.tm_hour, tm.tm_min, tm.tm_sec);
        } else {
            /* 同一秒内文件被打满，触发 _1, _2 等溢出后缀 */
            snprintf(g_storage.current_path, sizeof(g_storage.current_path),
                     "%s/log-%04d%02d%02d-%02d%02d%02d_%d.txt",
                     g_storage.cfg.storage_dir,
                     tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                     tm.tm_hour, tm.tm_min, tm.tm_sec,
                     overflow_index);
        }

        struct sc_statx st;
        /* 使用裸系统调用 sc_statx 检测文件状态 */
        if (sc_statx(g_storage.current_path, &st) == 0) {
            /* 如果文件已存在并且达到了单文件大小上限，尝试下一个后缀编号 */
            if (st.stx_size >= g_storage.cfg.max_file_size) {
                overflow_index++;
                continue;
            }
        }
        /* 找到一个不存在，或者存在但还没满的文件名，跳出循环 */
        break;
    }

    /* 打开找到的合法文件（追加模式） */
    g_storage.current_fd = sc_openat(g_storage.current_path,
                                      O_WRONLY | O_CREAT | O_APPEND,
                                      0644);
    if (g_storage.current_fd < 0) return LOGGER_ERR_IO;

    /* 继承原有大小，保证追加写入时容量计算依然准确 */
    struct sc_statx st2;
    if (sc_statx(g_storage.current_path, &st2) == 0) {
        g_storage.current_size = st2.stx_size;
    } else {
        g_storage.current_size = 0;
    }

    return LOGGER_OK;
}

/**
 * @brief  遍历日志目录，收集 "log-" 前缀文件的元数据。
 *
 * 实现：
 *  1. sc_openat(dir, O_RDONLY|O_DIRECTORY) 获得目录 fd。
 *  2. 循环调用 SYS_getdents64 读取目录项（替代 readdir）。
 *  3. 对每个匹配条目调用 sc_statx 获取大小与 mtime。
 *  4. 插入排序，按 mtime 升序（最旧在前）。
 */
static uint32_t collect_log_files(LogFileInfo *out_infos, uint32_t max_count)
{
    int dir_fd = sc_openat(g_storage.cfg.storage_dir,
                            O_RDONLY | O_DIRECTORY, 0);
    if (dir_fd < 0) return 0;

    uint32_t count = 0;
    char     buf[SC_DENTS_BUF];

    while (count < max_count) {
        long nread = syscall(__NR_getdents64, dir_fd, buf, SC_DENTS_BUF);
        if (nread <= 0) break;

        long bpos = 0;
        while (bpos < nread && count < max_count) {
            struct sc_dirent64 *de = (struct sc_dirent64 *)(buf + bpos);
            bpos += de->d_reclen;

            /* 过滤：仅处理 "log-" 前缀 */
            if (strncmp(de->d_name, "log-", 4) != 0) continue;

            char filepath[512];
            snprintf(filepath, sizeof(filepath), "%s/%s",
                     g_storage.cfg.storage_dir, de->d_name);

            struct sc_statx st;
            if (sc_statx(filepath, &st) != 0) continue;
            if (!sc_is_reg(&st))              continue;

            strncpy(out_infos[count].filename, de->d_name,
                    sizeof(out_infos[count].filename) - 1);
            out_infos[count].filename[sizeof(out_infos[count].filename)-1] = '\0';

            strncpy(out_infos[count].filepath, filepath,
                    sizeof(out_infos[count].filepath) - 1);
            out_infos[count].filepath[sizeof(out_infos[count].filepath)-1] = '\0';

            out_infos[count].size_bytes = (size_t)st.stx_size;
            out_infos[count].created_ts = (uint64_t)st.stx_mtime.tv_sec * 1000ULL + (st.stx_mtime.tv_nsec / 1000000U);
            count++;
        }
    }

    sc_close(dir_fd);

    /* 插入排序：mtime 升序（旧→新） */
    for (uint32_t i = 1; i < count; i++) {
        LogFileInfo tmp = out_infos[i];
        int32_t j = (int32_t)i - 1;
        while (j >= 0 && out_infos[j].created_ts > tmp.created_ts) {
            out_infos[j + 1] = out_infos[j];
            j--;
        }
        out_infos[j + 1] = tmp;
    }

    return count;
}

/** 计算所有日志文件总字节数。 */
static size_t calc_total_size(void)
{
    LogFileInfo files[MAX_LOG_FILES];
    uint32_t count = collect_log_files(files, MAX_LOG_FILES);
    size_t total = 0;
    for (uint32_t i = 0; i < count; i++) total += files[i].size_bytes;
    return total;
}

/**
 * @brief  执行总量限制：用 SYS_unlinkat 删除最旧文件。
 *         跳过当前正在写入的文件。
 */
static void enforce_total_size(void)
{
    while (calc_total_size() > g_storage.cfg.max_total_size) {
        LogFileInfo files[MAX_LOG_FILES];
        uint32_t count = collect_log_files(files, MAX_LOG_FILES);
        if (count == 0) break;

        bool deleted = false;
        for (uint32_t i = 0; i < count; i++) {
            if (strcmp(files[i].filepath, g_storage.current_path) == 0)
                continue;

            sc_unlinkat(files[i].filepath, 0);  /* 替代 unlink() */
            deleted = true;
            break;
        }

        if (!deleted) break;  /* 只剩当前文件，中止 */
    }
}

/* =========================================================================
 * Public API
 * ========================================================================= */

LOGGER_RET_E storage_init(const LoggerStorageCfg *cfg)
{
    pthread_mutex_lock(&g_storage.lock);

    if (g_storage.initialized) {
        pthread_mutex_unlock(&g_storage.lock);
        return LOGGER_OK;
    }

    g_storage.cfg = *cfg;

    LOGGER_RET_E rc = ensure_dir(cfg->storage_dir);
    if (rc != LOGGER_OK) {
        pthread_mutex_unlock(&g_storage.lock);
        return rc;
    }

    rc = open_new_file();
    if (rc == LOGGER_OK) g_storage.initialized = true;

    pthread_mutex_unlock(&g_storage.lock);
    return rc;
}

void storage_destroy(void)
{
    pthread_mutex_lock(&g_storage.lock);
    if (g_storage.current_fd >= 0) {
        sc_close(g_storage.current_fd);
        g_storage.current_fd = -1;
    }
    g_storage.initialized = false;
    pthread_mutex_unlock(&g_storage.lock);
}

LOGGER_RET_E storage_write(const char *entry, size_t len)
{
    pthread_mutex_lock(&g_storage.lock);

    if (!g_storage.initialized || g_storage.current_fd < 0) {
        pthread_mutex_unlock(&g_storage.lock);
        return LOGGER_ERR_INIT;
    }

    /* 超出单文件上限 → 轮转 + 执行总量限制 */
    if (g_storage.current_size + len > g_storage.cfg.max_file_size) {
        LOGGER_RET_E rc = open_new_file();
        if (rc != LOGGER_OK) {
            pthread_mutex_unlock(&g_storage.lock);
            return rc;
        }
        enforce_total_size();
    }

    const uint8_t *write_buf = (const uint8_t *)entry;
    size_t         write_len = len;
    uint8_t       *enc_buf   = NULL;

    /* 可选：AES-256-CBC 加密 */
    if (g_storage.cfg.encrypt_files) {
        size_t enc_len = 0;
        if (crypto_encrypt(write_buf, write_len, &enc_buf, &enc_len)
            == LOGGER_OK) {
            write_buf = enc_buf;
            write_len = enc_len;
        }
    }

    /* 写入：[4B frame_len][payload] */
    uint32_t frame_len = (uint32_t)write_len;
    LOGGER_RET_E rc = sc_write_all(g_storage.current_fd,
                                    &frame_len, sizeof(frame_len));
    if (rc == LOGGER_OK) {
        rc = sc_write_all(g_storage.current_fd, write_buf, write_len);
    }

    if (enc_buf) crypto_free(enc_buf);

    if (rc == LOGGER_OK) {
        g_storage.current_size += sizeof(frame_len) + write_len;
    }

    pthread_mutex_unlock(&g_storage.lock);
    return rc;
}

LOGGER_RET_E storage_list_files(LogFileInfo *out_files,
                                  uint32_t     max_count,
                                  uint32_t    *out_count)
{
    if (!out_files || !out_count) return LOGGER_ERR_PARAM;
    pthread_mutex_lock(&g_storage.lock);
    *out_count = collect_log_files(out_files, max_count);
    pthread_mutex_unlock(&g_storage.lock);
    return LOGGER_OK;
}

LOGGER_RET_E storage_read_file(const char    *filename,
                                 LOGGER_LEVEL_E min_level,
                                 char          *out_buf,
                                 size_t         buf_size,
                                 size_t        *out_len)
{
    if (!filename || !out_buf || !out_len) return LOGGER_ERR_PARAM;

    char path[512];
    snprintf(path, sizeof(path), "%s/%s",
             g_storage.cfg.storage_dir, filename);

    int fd = sc_openat(path, O_RDONLY, 0);
    if (fd < 0) return LOGGER_ERR_NOTFOUND;

    static const char * const k_lvl[MSG_LEVEL_MAX] = {
        "EMERG","ALERT","CRIT","ERR",
        "WARNING","NOTICE","INFO","DEBUG"
    };

    size_t   written = 0;
    uint32_t frame_len;

    /* 逐帧读取 */
    while (sc_read(fd, &frame_len, sizeof(frame_len))
           == (ssize_t)sizeof(frame_len))
    {
        if (frame_len == 0 || frame_len > 65536) break;

        uint8_t *raw = (uint8_t *)malloc(frame_len);
        if (!raw) break;

        ssize_t got = sc_read(fd, raw, frame_len);
        if (got != (ssize_t)frame_len) { free(raw); break; }

        uint8_t *plain     = raw;
        size_t   plain_len = (size_t)got;
        uint8_t *dec_buf   = NULL;

        if (g_storage.cfg.encrypt_files) {
            if (crypto_decrypt(raw, (size_t)got, &dec_buf, &plain_len)
                == LOGGER_OK) {
                plain = dec_buf;
            } else {
                free(raw);
                continue;
            }
        }

        /* 级别过滤 */
        bool accept = true;
        if (min_level < MSG_LEVEL_MAX) {
            accept = false;
            for (int l = 0; l <= (int)min_level; l++) {
                char tag[16];
                snprintf(tag, sizeof(tag), "[%s]", k_lvl[l]);
                if (memmem(plain, plain_len, tag, strlen(tag))) {
                    accept = true;
                    break;
                }
            }
        }

        if (accept && written + plain_len < buf_size) {
            memcpy(out_buf + written, plain, plain_len);
            written += plain_len;
        }

        if (dec_buf) crypto_free(dec_buf);
        free(raw);
    }

    sc_close(fd);
    *out_len = written;
    return LOGGER_OK;
}

size_t storage_total_size(void)
{
    pthread_mutex_lock(&g_storage.lock);
    size_t sz = calc_total_size();
    pthread_mutex_unlock(&g_storage.lock);
    return sz;
}

LOGGER_RET_E storage_rotate(void)
{
    pthread_mutex_lock(&g_storage.lock);
    LOGGER_RET_E rc = open_new_file();
    if (rc == LOGGER_OK) enforce_total_size();
    pthread_mutex_unlock(&g_storage.lock);
    return rc;
}

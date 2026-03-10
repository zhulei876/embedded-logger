/**
 * @file    logger_crash.c
 * @brief   被动崩溃捕获 — 纯裸系统调用 + async-signal-safe 实现
 *
 * 【约束】：
 *  - 信号处理函数内部全程 async-signal-safe：
 *    使用 SYS_write / SYS_openat / SYS_close / SYS_getpid，
 *    不调用 malloc / printf / sprintf / fopen / open() 等。
 *  - 模块初始化阶段（非信号上下文）同样只用裸系统调用，
 *    禁止 stat / mkdir / open() 等 libc 文件操作函数。
 *
 * 捕获的信号：SIGSEGV SIGABRT SIGBUS SIGFPE SIGILL SIGTERM
 *
 * 崩溃日志写入流程：
 *   1. SYS_openat 打开 <storage_dir>/crash.log（O_WRONLY|O_CREAT|O_APPEND）
 *   2. 用 ssa_write_* 系列函数（内部仅用 SYS_write）输出：
 *      信号名、PID、故障地址
 *   3. backtrace() + backtrace_symbols_fd(fd) 写入调用栈
 *   4. SYS_close 关闭 fd
 *   5. SA_RESETHAND → raise(signum) 恢复默认行为（产生 core dump）
 */

#include "logger_crash.h"

#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <execinfo.h>
#include <ucontext.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <fcntl.h>      /* O_* 宏 */

/* =========================================================================
 * 系统调用号（x86-64 Linux；其他架构改此处）
 * ========================================================================= */
#ifndef __NR_openat
#  define __NR_openat   257
#endif
#ifndef __NR_write
#  define __NR_write      1
#endif
#ifndef __NR_close
#  define __NR_close      3
#endif
#ifndef __NR_getpid
#  define __NR_getpid    39
#endif

#ifndef AT_FDCWD
#  define AT_FDCWD  (-100)
#endif

/* =========================================================================
 * 裸系统调用封装（均为 async-signal-safe）
 * ========================================================================= */

static inline ssize_t ssa_sys_write(int fd, const void *buf, size_t n)
{
    return (ssize_t)syscall(__NR_write, fd, buf, n);
}

static inline int ssa_sys_open(const char *path, int flags, int mode)
{
    return (int)syscall(__NR_openat, AT_FDCWD, path, flags, mode);
}

static inline void ssa_sys_close(int fd)
{
    syscall(__NR_close, fd);
}

static inline pid_t ssa_sys_getpid(void)
{
    return (pid_t)syscall(__NR_getpid);
}

/* =========================================================================
 * async-signal-safe 输出辅助（不使用任何 stdio / sprintf）
 * ========================================================================= */

/** 写入 C 字符串到 fd（async-signal-safe） */
static void ssa_write_str(int fd, const char *s)
{
    if (!s) return;
    size_t len = 0;
    while (s[len]) len++;
    size_t off = 0;
    while (off < len) {
        ssize_t n = ssa_sys_write(fd, s + off, len - off);
        if (n <= 0) break;
        off += (size_t)n;
    }
}

/** 将无符号整数写为十进制字符串（async-signal-safe） */
static void ssa_write_uint(int fd, uint64_t v)
{
    char  buf[24];
    int   i = 23;
    buf[i] = '\0';
    if (v == 0) {
        buf[--i] = '0';
    } else {
        while (v > 0) {
            buf[--i] = (char)('0' + v % 10);
            v /= 10;
        }
    }
    ssa_write_str(fd, &buf[i]);
}

/** 将整数写为十六进制字符串（带 0x 前缀，async-signal-safe） */
static void ssa_write_hex(int fd, uint64_t v)
{
    static const char k_hex[] = "0123456789abcdef";
    char buf[20];
    int  i = 17;
    buf[18] = '\0';
    buf[17] = '0';
    if (v == 0) {
        /* "0x0" */
    } else {
        while (v > 0 && i > 1) {
            buf[i--] = k_hex[v & 0xFU];
            v >>= 4;
        }
    }
    buf[0] = '0'; buf[1] = 'x';
    /* 找到有效起始位置 */
    ssa_write_str(fd, "0x");
    ssa_write_str(fd, &buf[i + 1]);
}

/* =========================================================================
 * 内部状态
 * ========================================================================= */
#define CRASH_BACKTRACE_DEPTH 32
#define CRASH_STDERR_FD        2

static struct sigaction g_old_handlers[6];

static const int k_crash_sigs[] = {
    SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL, SIGTERM
};
static const char * const k_sig_names[] = {
    "SIGSEGV", "SIGABRT", "SIGBUS", "SIGFPE", "SIGILL", "SIGTERM"
};
#define NUM_CRASH_SIGS  (int)(sizeof(k_crash_sigs)/sizeof(k_crash_sigs[0]))

/** 崩溃日志路径（logger_crash_set_dir 设置） */
static char g_crash_log_path[512];
static bool g_installed = false;

/* =========================================================================
 * 打开崩溃日志文件（async-signal-safe：只用 SYS_openat）
 *
 * 路径格式：<storage_dir>/crash.log
 * 若路径未设置则退回到 STDERR。
 * ========================================================================= */
static int open_crash_fd(void)
{
    if (g_crash_log_path[0] == '\0') return CRASH_STDERR_FD;

    int fd = ssa_sys_open(g_crash_log_path,
                           O_WRONLY | O_CREAT | O_APPEND,
                           0644);
    return (fd >= 0) ? fd : CRASH_STDERR_FD;
}

/* =========================================================================
 * 信号处理函数（全程 async-signal-safe）
 * ========================================================================= */
static void crash_signal_handler(int signum, siginfo_t *si, void *uctx)
{
    (void)uctx;

    int  fd     = open_crash_fd();
    bool own_fd = (fd != CRASH_STDERR_FD);

    /* ---- 崩溃报告头 ---- */
    ssa_write_str(fd, "\n===== CRASH REPORT =====\n");

    /* 信号名 */
    ssa_write_str(fd, "Signal : ");
    const char *sig_name = "UNKNOWN";
    for (int i = 0; i < NUM_CRASH_SIGS; i++) {
        if (k_crash_sigs[i] == signum) { sig_name = k_sig_names[i]; break; }
    }
    ssa_write_str(fd, sig_name);
    ssa_write_str(fd, " (");
    ssa_write_uint(fd, (uint64_t)signum);
    ssa_write_str(fd, ")\n");

    /* PID（SYS_getpid，async-signal-safe） */
    ssa_write_str(fd, "PID    : ");
    ssa_write_uint(fd, (uint64_t)ssa_sys_getpid());
    ssa_write_str(fd, "\n");

    /* 故障地址 */
    if (si != NULL) {
        ssa_write_str(fd, "Fault  : ");
        ssa_write_hex(fd, (uint64_t)(uintptr_t)si->si_addr);
        ssa_write_str(fd, "\n");
    }

    /* ---- 调用栈 ---- */
    ssa_write_str(fd, "Stack  :\n");
    void *bt[CRASH_BACKTRACE_DEPTH];
    int   bt_size = backtrace(bt, CRASH_BACKTRACE_DEPTH);
    /*
     * backtrace_symbols_fd 内部使用 write(2)，是 async-signal-safe 的。
     * 不使用 backtrace_symbols（它调用 malloc，非 AS-safe）。
     */
    backtrace_symbols_fd(bt, bt_size, fd);

    ssa_write_str(fd, "========================\n\n");

    if (own_fd) ssa_sys_close(fd);

    /* ---- 恢复默认处理（产生 core dump） ---- */
    struct sigaction sa_dfl;
    memset(&sa_dfl, 0, sizeof(sa_dfl));
    sa_dfl.sa_handler = SIG_DFL;
    sigaction(signum, &sa_dfl, NULL);
    raise(signum);
}

/* =========================================================================
 * Public API
 * ========================================================================= */

LOGGER_RET_E crash_handler_install(void)
{
    if (g_installed) return LOGGER_OK;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = crash_signal_handler;
    sa.sa_flags     = SA_SIGINFO | SA_RESETHAND;
    sigemptyset(&sa.sa_mask);

    for (int i = 0; i < NUM_CRASH_SIGS; i++) {
        if (sigaction(k_crash_sigs[i], &sa, &g_old_handlers[i]) != 0) {
            return LOGGER_ERR_IO;
        }
    }

    g_installed = true;
    return LOGGER_OK;
}

void crash_handler_uninstall(void)
{
    if (!g_installed) return;
    for (int i = 0; i < NUM_CRASH_SIGS; i++) {
        sigaction(k_crash_sigs[i], &g_old_handlers[i], NULL);
    }
    g_installed = false;
}

/**
 * @brief  包内私有接口：设置崩溃日志路径。
 *         由 logger_core.c 在 logger_init() 完成后调用。
 *         格式：<storage_dir>/crash.log
 */
void logger_crash_set_dir(const char *storage_dir)
{
    if (!storage_dir || storage_dir[0] == '\0') return;

    /* 手动拼接路径（不用 snprintf，保持 AS-safe 可移植性） */
    size_t dlen = 0;
    while (storage_dir[dlen] && dlen < 480) dlen++;

    memcpy(g_crash_log_path, storage_dir, dlen);
    const char *suffix = "/crash.log";
    size_t      slen   = 10;  /* strlen("/crash.log") */
    memcpy(g_crash_log_path + dlen, suffix, slen + 1);
}

/**
 * @file    receiver_main.c
 * @brief   UDP Log Receiver Application (带本地存储归档功能)
 */

#include "logger_transport.h"
#include "logger_crypto.h"
#include "logger_storage.h"  /* 新增：引入本地存储模块 */
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

/* =========================================================================
 * ANSI color codes
 * ========================================================================= */
#define COL_RESET   "\033[0m"
#define COL_RED     "\033[1;31m"
#define COL_YELLOW  "\033[1;33m"
#define COL_CYAN    "\033[1;36m"
#define COL_WHITE   "\033[0m"
#define COL_MAGENTA "\033[1;35m"
#define COL_BOLD    "\033[1m"

static const char * const k_level_colors[MSG_LEVEL_MAX] = {
    COL_RED,     /* EMERG   */
    COL_RED,     /* ALERT   */
    COL_MAGENTA, /* CRIT    */
    COL_RED,     /* ERR     */
    COL_YELLOW,  /* WARNING */
    COL_CYAN,    /* NOTICE  */
    COL_WHITE,   /* INFO    */
    COL_WHITE,   /* DEBUG   */
};

/* =========================================================================
 * Receiver Config
 * ========================================================================= */
typedef struct {
    char     bind_ip[64];
    uint16_t bind_port;
    LOGGER_LEVEL_E min_level;
    bool     color_output;
    bool     decrypt;
    char     key_file[256];
    /* 新增：接收端本地存储配置 */
    char     storage_dir[256];
    size_t   max_file_size;
    size_t   max_total_size;
} ReceiverConfig;

/* 默认配置 */
static ReceiverConfig g_rcfg = {
    .bind_ip        = "127.0.0.1",
    .bind_port      = 9001,
    .min_level      = MSG_DEBUG,
    .color_output   = true,
    .decrypt        = false,
    .key_file       = "",
    .storage_dir    = "/tmp/server_logs", /* 默认存到这个目录 */
    .max_file_size  = 1048576,            /* 默认 1MB 轮转 */
    .max_total_size = 10485760            /* 默认总大小 10MB */
};

static void load_receiver_config(const char *path)
{
    int fd = open(path, 0);
    if (fd < 0) return;

    char buf[2048];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n < 0) return;
    buf[n] = '\0';

    char *line = buf;
    while (line && *line) {
        char *end = strchr(line, '\n');
        if (end) *end = '\0';

        char key[64] = {0}, val[256] = {0};
        if (sscanf(line, " %63[^=] = %255[^\n]", key, val) == 2) {
            char *k = key + strlen(key) - 1;
            while (k > key && *k == ' ') *k-- = '\0';

            if      (!strcmp(key, "bind_ip"))        snprintf(g_rcfg.bind_ip, sizeof(g_rcfg.bind_ip), "%.63s", val);
            else if (!strcmp(key, "bind_port"))      g_rcfg.bind_port = (uint16_t)atoi(val);
            else if (!strcmp(key, "min_level"))      g_rcfg.min_level = (LOGGER_LEVEL_E)atoi(val);
            else if (!strcmp(key, "color_output"))   g_rcfg.color_output = atoi(val) != 0;
            else if (!strcmp(key, "decrypt"))        g_rcfg.decrypt = atoi(val) != 0;
            else if (!strcmp(key, "key_file"))       snprintf(g_rcfg.key_file, sizeof(g_rcfg.key_file), "%.255s", val);
            /* 新增解析存储配置 */
            else if (!strcmp(key, "storage_dir"))    snprintf(g_rcfg.storage_dir, sizeof(g_rcfg.storage_dir), "%.255s", val);
            else if (!strcmp(key, "max_file_size"))  g_rcfg.max_file_size = (size_t)atol(val);
            else if (!strcmp(key, "max_total_size")) g_rcfg.max_total_size = (size_t)atol(val);
        }
        line = end ? end + 1 : NULL;
    }
}

/* =========================================================================
 * Level Detection from Log Line
 * ========================================================================= */
static LOGGER_LEVEL_E detect_level(const char *line)
{
    static const char * const names[] = {
        "EMERG","ALERT","CRIT","ERR",
        "WARNING","NOTICE","INFO","DEBUG"
    };
    for (int i = 0; i < MSG_LEVEL_MAX; i++) {
        char tag[16];
        snprintf(tag, sizeof(tag), "[%s]", names[i]);
        if (strstr(line, tag)) return (LOGGER_LEVEL_E)i;
    }
    return MSG_DEBUG;
}

/* =========================================================================
 * Print a log line with optional color
 * ========================================================================= */
static void print_log_line(const char *line, size_t len)
{
    LOGGER_LEVEL_E level = detect_level(line);

    if (level > g_rcfg.min_level) return;

    if (g_rcfg.color_output) {
        const char *col = k_level_colors[level];
        fwrite(col, 1, strlen(col), stdout);
    }

    fwrite(line, 1, len, stdout);

    if (g_rcfg.color_output) {
        fwrite(COL_RESET, 1, strlen(COL_RESET), stdout);
    }

    fflush(stdout);
}

/* =========================================================================
 * CRC32 (same as transport layer)
 * ========================================================================= */
static uint32_t crc32_table_r[256];
static bool     crc32_ready = false;

static void init_crc32(void)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c & 1) ? (0xEDB88320U ^ (c >> 1)) : (c >> 1);
        crc32_table_r[i] = c;
    }
    crc32_ready = true;
}

static uint32_t crc32_calc(const uint8_t *d, size_t l)
{
    if (!crc32_ready) init_crc32();
    uint32_t c = 0xFFFFFFFFU;
    for (size_t i = 0; i < l; i++) c = crc32_table_r[(c ^ d[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFU;
}

/* =========================================================================
 * Graceful Shutdown
 * ========================================================================= */
static volatile int g_running = 1;
static void on_signal(int s) { (void)s; g_running = 0; }

/* =========================================================================
 * Main Receive Loop
 * ========================================================================= */
int main(int argc, char *argv[])
{
    const char *config_path = (argc > 1) ? argv[1] : "config/receiver.ini";

    load_receiver_config(config_path);

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    /* Init crypto if decryption requested */
    if (g_rcfg.decrypt && g_rcfg.key_file[0]) {
        if (crypto_init(g_rcfg.key_file) != LOGGER_OK) {
            fprintf(stderr, "[RECEIVER] Failed to init crypto\n");
            return EXIT_FAILURE;
        }
    }

    /* 新增：初始化本地存储模块 */
    LoggerStorageCfg scfg;
    memset(&scfg, 0, sizeof(scfg));
    snprintf(scfg.storage_dir, sizeof(scfg.storage_dir), "%.255s", g_rcfg.storage_dir);
    scfg.max_file_size = g_rcfg.max_file_size;
    scfg.max_total_size = g_rcfg.max_total_size;
    scfg.encrypt_files = false; /* 存储在云端本地的文件默认保存为明文 */

    if (storage_init(&scfg) != LOGGER_OK) {
        fprintf(stderr, "[RECEIVER] Failed to initialize local storage at %s\n", scfg.storage_dir);
        /* 不退出，即使存储失败也可以继续在屏幕上打印日志 */
    } else {
        printf("[RECEIVER] Local storage enabled. Saving logs to: %s\n", scfg.storage_dir);
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("[RECEIVER] socket");
        return EXIT_FAILURE;
    }

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(g_rcfg.bind_port);
    inet_pton(AF_INET, g_rcfg.bind_ip, &addr.sin_addr);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("[RECEIVER] bind");
        close(fd);
        return EXIT_FAILURE;
    }

    printf("[RECEIVER] Listening on %s:%u  (min_level=%d)\n",
           g_rcfg.bind_ip, g_rcfg.bind_port, (int)g_rcfg.min_level);
    fflush(stdout);

    uint8_t buf[4096];

    while (g_running) {
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        int ret = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (ret <= 0) continue;

        ssize_t got = recv(fd, buf, sizeof(buf) - 1, 0);
        if (got < (ssize_t)sizeof(TransportHeader)) continue;

        TransportHeader *hdr     = (TransportHeader *)buf;
        if (ntohl(hdr->magic) != TRANSPORT_MAGIC) continue;

        uint32_t plen    = ntohl(hdr->payload_len);
        uint8_t *payload = buf + sizeof(TransportHeader);

        if ((size_t)(got - sizeof(TransportHeader)) < plen) continue;

        /* Verify CRC */
        uint32_t expected_crc = ntohl(hdr->crc32);
        uint8_t *work = payload;
        uint8_t *dec_buf = NULL;
        size_t   dec_len = 0;

        /* 这里就是解密逻辑：加密包被解密后，work 指向了真正的明文 */
        if ((hdr->flags & 0x01) && g_rcfg.decrypt && plen > 0) {
            if (crypto_decrypt(payload, plen, &dec_buf, &dec_len) == LOGGER_OK) {
                work = dec_buf;
                plen = (uint32_t)dec_len;
            }
        }

        if (crc32_calc(work, plen) != expected_crc) {
            fprintf(stderr, "[RECEIVER] CRC mismatch — packet dropped\n");
            if (dec_buf) crypto_free(dec_buf);
            continue;
        }

        /* 处理解密后并且 CRC 正确的最终数据 */
        if (hdr->type == PKT_LOG_ENTRY && plen > 0) {
            work[plen] = '\0';
            
            /* 1. 打印到屏幕 */
            print_log_line((char *)work, plen);
            
            /* 2. 新增：将解密后的完整明文写入本地云服务器磁盘！ */
            storage_write((const char *)work, plen);
        }

        if (dec_buf) crypto_free(dec_buf);
    }

    printf("\n[RECEIVER] Shutting down.\n");
    if (g_rcfg.decrypt) crypto_destroy();
    
    /* 新增：关闭存储系统 */
    storage_destroy();
    close(fd);
    return EXIT_SUCCESS;
}


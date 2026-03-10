/**
 * @file    logger_transport.c
 * @brief   UDP log transport implementation
 *
 * Two sockets:
 *  1. send_fd  – used by the writer thread to push real-time log lines.
 *  2. query_fd – bound to bind_port; a dedicated thread handles
 *                PKT_QUERY_LIST and PKT_QUERY_READ with chunked ARQ.
 *
 * Chunk framing:
 *   TransportHeader | [encrypted] payload
 *
 * Stop-and-wait ARQ for chunked transfers:
 *   sender sends chunk N → waits TRANSPORT_TIMEOUT_MS for PKT_ACK(N)
 *   on NACK or timeout: retransmit up to TRANSPORT_MAX_RETRY times.
 */

#include "logger_transport.h"
#include "logger_storage.h"
#include "logger_crypto.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <errno.h>
#include <time.h>

/* SYS_close 用于套接字关闭（保持与禁止 libc close() 的约束一致） */
#ifndef __NR_close
#  define __NR_close 3
#endif

#define MAX_LOG_FILES_TRANSPORT 64

/* =========================================================================
 * Internal State
 * ========================================================================= */
typedef struct {
    bool             initialized;
    LoggerTransportCfg cfg;
    int              send_fd;        /**< Socket for sending real-time logs */
    int              query_fd;       /**< Socket for query protocol         */
    struct sockaddr_in remote_addr;  /**< Pre-resolved remote address       */
    pthread_t        query_thread;
    volatile bool    query_running;
} TransportState;

static TransportState g_transport = {
    .initialized  = false,
    .send_fd      = -1,
    .query_fd     = -1,
    .query_running = false,
};

/* =========================================================================
 * CRC32 (IEEE 802.3 polynomial)
 * ========================================================================= */
static uint32_t crc32_table[256];
static bool     crc32_initialized = false;

static void crc32_init_table(void)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++)
            crc = (crc & 1) ? (0xEDB88320U ^ (crc >> 1)) : (crc >> 1);
        crc32_table[i] = crc;
    }
    crc32_initialized = true;
}

static uint32_t crc32_compute(const uint8_t *data, size_t len)
{
    if (!crc32_initialized) crc32_init_table();
    uint32_t crc = 0xFFFFFFFFU;
    for (size_t i = 0; i < len; i++)
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFU;
}

/* =========================================================================
 * Internal: Build and send a packet with optional encryption
 * ========================================================================= */
static LOGGER_RET_E send_packet(int                fd,
                                 struct sockaddr_in *dest,
                                 TransportPktType   type,
                                 uint16_t           session_id,
                                 uint32_t           seq_num,
                                 uint32_t           total_chunks,
                                 const uint8_t     *payload,
                                 size_t             payload_len)
{
    const uint8_t *send_payload = payload;
    size_t         send_len     = payload_len;
    uint8_t       *enc_buf      = NULL;
    uint8_t        flags        = 0;

    if (g_transport.cfg.encrypt_transport && payload && payload_len > 0) {
        size_t enc_len = 0;
        if (crypto_encrypt(payload, payload_len, &enc_buf, &enc_len)
            == LOGGER_OK) {
            send_payload = enc_buf;
            send_len     = enc_len;
            flags       |= 0x01;
        }
    }

    /* Build packet: header + payload into single buffer */
    size_t total = sizeof(TransportHeader) + send_len;
    uint8_t *pkt = (uint8_t *)malloc(total);
    if (!pkt) {
        if (enc_buf) crypto_free(enc_buf);
        return LOGGER_ERR_NOMEM;
    }

    TransportHeader hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic        = htonl(TRANSPORT_MAGIC);
    hdr.type         = (uint8_t)type;
    hdr.flags        = flags;
    hdr.session_id   = htons(session_id);
    hdr.seq_num      = htonl(seq_num);
    hdr.total_chunks = htonl(total_chunks);
    hdr.payload_len  = htonl((uint32_t)send_len);
    hdr.crc32        = htonl(crc32_compute(
                               send_payload ? send_payload : (const uint8_t*)"",
                               send_len));

    memcpy(pkt, &hdr, sizeof(hdr));
    if (send_payload && send_len > 0)
        memcpy(pkt + sizeof(hdr), send_payload, send_len);

    ssize_t sent = sendto(fd, pkt, total, 0,
                          (struct sockaddr *)dest, sizeof(*dest));

    free(pkt);
    if (enc_buf) crypto_free(enc_buf);

    return (sent == (ssize_t)total) ? LOGGER_OK : LOGGER_ERR_IO;
}

/* =========================================================================
 * Internal: Wait for ACK with timeout
 * ========================================================================= */
static LOGGER_RET_E wait_ack(int      fd,
                               uint16_t session_id,
                               uint32_t expected_seq,
                               uint32_t timeout_ms)
{
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    int ret = select(fd + 1, &rfds, NULL, NULL, &tv);
    if (ret <= 0) return LOGGER_ERR_TIMEOUT;

    uint8_t buf[sizeof(TransportHeader)];
    ssize_t got = recv(fd, buf, sizeof(buf), 0);
    if (got < (ssize_t)sizeof(TransportHeader)) return LOGGER_ERR_IO;

    TransportHeader *hdr = (TransportHeader *)buf;
    if (ntohl(hdr->magic) != TRANSPORT_MAGIC)          return LOGGER_ERR_IO;
    if (ntohs(hdr->session_id) != session_id)          return LOGGER_ERR_IO;
    if (ntohl(hdr->seq_num)    != expected_seq)        return LOGGER_ERR_IO;
    if (hdr->type == PKT_NACK) return LOGGER_ERR_IO;  /* trigger retransmit */

    return LOGGER_OK;
}

/* =========================================================================
 * Internal: Chunked transfer of a large buffer to a destination
 * ========================================================================= */
static LOGGER_RET_E send_chunked(int                fd,
                                  struct sockaddr_in *dest,
                                  TransportPktType   type,
                                  uint16_t           session_id,
                                  const uint8_t     *data,
                                  size_t             data_len)
{
    size_t   chunk_sz    = g_transport.cfg.chunk_size;
    uint32_t total_chunks = (uint32_t)((data_len + chunk_sz - 1) / chunk_sz);
    if (total_chunks == 0) total_chunks = 1;

    for (uint32_t seq = 0; seq < total_chunks; seq++) {
        size_t offset   = seq * chunk_sz;
        size_t this_len = chunk_sz;
        if (offset + this_len > data_len) this_len = data_len - offset;

        LOGGER_RET_E rc = LOGGER_ERR_IO;
        for (unsigned int retry = 0u; retry < TRANSPORT_MAX_RETRY; retry++) {
            rc = send_packet(fd, dest, type, session_id, seq,
                             total_chunks, data + offset, this_len);
            if (rc != LOGGER_OK) continue;

            rc = wait_ack(fd, session_id, seq, TRANSPORT_TIMEOUT_MS);
            if (rc == LOGGER_OK) break;
        }
        if (rc != LOGGER_OK) return rc;
    }
    return LOGGER_OK;
}

/* =========================================================================
 * Query Server Thread
 * ========================================================================= */
static void handle_query_list(int fd, struct sockaddr_in *client)
{
    uint32_t count = 0;

    /* Build a text response: one line per file */
    static LogFileInfo files_buf[MAX_LOG_FILES_TRANSPORT];
    storage_list_files(files_buf, MAX_LOG_FILES_TRANSPORT, &count);

    /* Serialize: "filename|size|timestamp\n" per file */
    char resp[8192];
    size_t off = 0;
    
    for (uint32_t i = 0; i < count && off < sizeof(resp) - 128; i++) {
        int n = snprintf(resp + off, sizeof(resp) - off,
                         "%s|%zu|%llu\n",
                         files_buf[i].filename,
                         files_buf[i].size_bytes,
                         (unsigned long long)files_buf[i].created_ts);
        if (n > 0) off += (size_t)n;
    }

    send_packet(fd, client, PKT_RESP_LIST, 0, 0, 0,
                (const uint8_t *)resp, off);
}

static void handle_query_read(int fd, struct sockaddr_in *client,
                               const uint8_t *payload, uint32_t plen)
{
    if (plen < sizeof(QueryReadPayload)) return;

    QueryReadPayload qr;
    memcpy(&qr, payload, sizeof(qr));
    qr.filename[sizeof(qr.filename)-1] = '\0';

    char  *out_buf = (char *)malloc(512 * 1024);
    if (!out_buf) return;

    size_t out_len = 0;
    storage_read_file(qr.filename,
                      (LOGGER_LEVEL_E)qr.min_level,
                      out_buf, 512 * 1024, &out_len);

    /* Send as chunked PKT_RESP_CHUNK transfer */
    send_chunked(fd, client, PKT_RESP_CHUNK, (uint16_t)(uintptr_t)client,
                 (const uint8_t *)out_buf, out_len);

    free(out_buf);
}

static void *query_server_thread(void *arg)
{
    (void)arg;
    uint8_t buf[2048];

    while (g_transport.query_running) {
        struct sockaddr_in client;
        socklen_t client_len = sizeof(client);

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(g_transport.query_fd, &rfds);

        int ret = select(g_transport.query_fd + 1, &rfds, NULL, NULL, &tv);
        if (ret <= 0) continue;

        ssize_t got = recvfrom(g_transport.query_fd, buf, sizeof(buf), 0,
                               (struct sockaddr *)&client, &client_len);
        if (got < (ssize_t)sizeof(TransportHeader)) continue;

        TransportHeader *hdr = (TransportHeader *)buf;
        if (ntohl(hdr->magic) != TRANSPORT_MAGIC) continue;

        uint32_t plen = ntohl(hdr->payload_len);
        uint8_t *payload  = (uint8_t *)buf + sizeof(TransportHeader);

        /* Decrypt if flagged */
        uint8_t *dec_buf   = NULL;
        uint8_t *work_payload = payload;

        if ((hdr->flags & 0x01) && plen > 0) {
            size_t dec_len = 0;
            if (crypto_decrypt(payload, plen, &dec_buf, &dec_len) == LOGGER_OK) {
                work_payload = dec_buf;
                plen = (uint32_t)dec_len;
            }
        }

        /* Verify CRC */
        uint32_t expected_crc = ntohl(hdr->crc32);
        uint32_t actual_crc   = crc32_compute(work_payload, plen);
        if (expected_crc != actual_crc) {
            if (dec_buf) crypto_free(dec_buf);
            continue;
        }

        switch (hdr->type) {
        case PKT_QUERY_LIST:
            handle_query_list(g_transport.query_fd, &client);
            break;
        case PKT_QUERY_READ:
            handle_query_read(g_transport.query_fd, &client,
                              work_payload, plen);
            break;
        default:
            break;
        }

        if (dec_buf) crypto_free(dec_buf);
    }
    return NULL;
}

/* For MAX_LOG_FILES_TRANSPORT used in handle_query_list */
#define MAX_LOG_FILES_TRANSPORT 64

/* =========================================================================
 * Public API
 * ========================================================================= */

LOGGER_RET_E transport_init(const LoggerTransportCfg *cfg)
{
    if (g_transport.initialized) return LOGGER_OK;

    crc32_init_table();

    g_transport.cfg = *cfg;

    /* Create send socket (unbound, just for sending) */
    g_transport.send_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_transport.send_fd < 0) return LOGGER_ERR_IO;

    memset(&g_transport.remote_addr, 0, sizeof(g_transport.remote_addr));
    g_transport.remote_addr.sin_family = AF_INET;
    g_transport.remote_addr.sin_port   = htons(cfg->remote_port);
    inet_pton(AF_INET, cfg->remote_ip, &g_transport.remote_addr.sin_addr);

    /* Create query socket (bound to bind_port) */
    g_transport.query_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_transport.query_fd < 0) {
        syscall(__NR_close, g_transport.send_fd);
        return LOGGER_ERR_IO;
    }

    int reuse = 1;
    setsockopt(g_transport.query_fd, SOL_SOCKET, SO_REUSEADDR,
               &reuse, sizeof(reuse));

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port   = htons(cfg->bind_port);
    inet_pton(AF_INET, cfg->bind_ip, &bind_addr.sin_addr);

    if (bind(g_transport.query_fd,
             (struct sockaddr *)&bind_addr, sizeof(bind_addr)) != 0) {
        syscall(__NR_close, g_transport.send_fd);
        syscall(__NR_close, g_transport.query_fd);
        return LOGGER_ERR_IO;
    }

    g_transport.initialized = true;
    return LOGGER_OK;
}

void transport_destroy(void)
{
    if (!g_transport.initialized) return;
    if (g_transport.send_fd  >= 0) {
        syscall(__NR_close, g_transport.send_fd);
        g_transport.send_fd  = -1;
    }
    if (g_transport.query_fd >= 0) {
        syscall(__NR_close, g_transport.query_fd);
        g_transport.query_fd = -1;
    }
    g_transport.initialized = false;
}

LOGGER_RET_E transport_send_log(const char *entry)
{
    if (!g_transport.initialized || g_transport.send_fd < 0) return LOGGER_ERR_INIT;
    if (!entry) return LOGGER_ERR_PARAM;

    return send_packet(g_transport.send_fd,
                       &g_transport.remote_addr,
                       PKT_LOG_ENTRY, 0, 0, 0,
                       (const uint8_t *)entry, strlen(entry));
}

LOGGER_RET_E transport_start_query_server(void)
{
    if (!g_transport.initialized) return LOGGER_ERR_INIT;
    g_transport.query_running = true;
    int rc = pthread_create(&g_transport.query_thread, NULL,
                             query_server_thread, NULL);
    return (rc == 0) ? LOGGER_OK : LOGGER_ERR_IO;
}

void transport_stop_query_server(void)
{
    g_transport.query_running = false;
    pthread_join(g_transport.query_thread, NULL);
}

LOGGER_RET_E transport_query_list(LogFileInfo *out_files,
                                   uint32_t     max_count,
                                   uint32_t    *out_count)
{
    /* For external client use; implementation omitted from framework */
    (void)out_files; (void)max_count; (void)out_count;
    return LOGGER_OK;
}

LOGGER_RET_E transport_query_read(const char    *filename,
                                   LOGGER_LEVEL_E min_level,
                                   char          *out_buf,
                                   size_t         buf_size,
                                   size_t        *out_len)
{
    /* For external client use; implementation omitted from framework */
    (void)filename; (void)min_level; (void)out_buf;
    (void)buf_size; (void)out_len;
    return LOGGER_OK;
}

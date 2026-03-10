/**
 * @file    logger_transport.h
 * @brief   UDP log transport layer
 *
 * Handles:
 *  - Real-time log sending to remote receiver
 *  - Loopback query protocol (list files, read file, filter by level)
 *  - Chunked transfer with sequence numbers and CRC32 checksums
 *  - Resume / retransmit on chunk loss (simple stop-and-wait ARQ)
 *  - Optional AES-256-CBC payload encryption
 */

#ifndef LOGGER_TRANSPORT_H
#define LOGGER_TRANSPORT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "logger.h"
#include "logger_storage.h"
#include <stdint.h>

/* =========================================================================
 * Protocol Constants
 * ========================================================================= */
#define TRANSPORT_MAGIC         0x4C4F4700U  /**< "LOG\0"                  */
#define TRANSPORT_MAX_CHUNK     1400U        /**< Safe UDP payload (bytes) */
#define TRANSPORT_TIMEOUT_MS    2000U        /**< ACK timeout              */
#define TRANSPORT_MAX_RETRY     3U           /**< Max retransmit attempts  */

/* =========================================================================
 * Packet Types
 * ========================================================================= */
typedef enum {
    PKT_LOG_ENTRY    = 0x01,  /**< Single real-time log line         */
    PKT_QUERY_LIST   = 0x10,  /**< Query: list files                 */
    PKT_RESP_LIST    = 0x11,  /**< Response: file list               */
    PKT_QUERY_READ   = 0x12,  /**< Query: read specific file         */
    PKT_RESP_CHUNK   = 0x13,  /**< Response: data chunk              */
    PKT_ACK          = 0x20,  /**< Generic acknowledgement           */
    PKT_NACK         = 0x21,  /**< Negative ack / request retransmit */
} TransportPktType;

/* =========================================================================
 * Wire Packet Header (packed, network byte order)
 * ========================================================================= */
#pragma pack(push, 1)
typedef struct {
    uint32_t magic;       /**< TRANSPORT_MAGIC                          */
    uint8_t  type;        /**< TransportPktType                         */
    uint8_t  flags;       /**< Bit0=encrypted, Bit1=compressed          */
    uint16_t session_id;  /**< Transfer session identifier              */
    uint32_t seq_num;     /**< Sequence / chunk number                  */
    uint32_t total_chunks;/**< Total chunks in this transfer (0=single) */
    uint32_t payload_len; /**< Bytes in payload field                   */
    uint32_t crc32;       /**< CRC32 of payload (after decryption)      */
} TransportHeader;
#pragma pack(pop)

/* =========================================================================
 * Query: Read File Request Payload
 * ========================================================================= */
#pragma pack(push, 1)
typedef struct {
    char    filename[256];    /**< Target filename (basename)           */
    uint8_t min_level;        /**< Minimum LOGGER_LEVEL_E to include    */
    uint32_t resume_chunk;    /**< Resume from chunk N (0 = start)      */
} QueryReadPayload;
#pragma pack(pop)

/* =========================================================================
 * Transport API
 * ========================================================================= */

/**
 * @brief  Initialize transport subsystem (creates sender socket).
 * @param  cfg  Transport configuration.
 */
LOGGER_RET_E transport_init(const LoggerTransportCfg *cfg);

/**
 * @brief  Destroy transport, close sockets.
 */
void transport_destroy(void);

/**
 * @brief  Send a single formatted log entry via UDP to the remote.
 * @param  entry  Null-terminated log line.
 */
LOGGER_RET_E transport_send_log(const char *entry);

/**
 * @brief  Start the loopback query server thread.
 *         Listens on cfg->bind_port for query packets.
 */
LOGGER_RET_E transport_start_query_server(void);

/**
 * @brief  Stop the query server thread.
 */
void transport_stop_query_server(void);

/**
 * @brief  (Client-side) Query remote for file list.
 *         Sends PKT_QUERY_LIST, blocks for response.
 *
 * @param  out_files    Array to receive file info.
 * @param  max_count    Array capacity.
 * @param  out_count    Files received.
 */
LOGGER_RET_E transport_query_list(LogFileInfo *out_files,
                                   uint32_t     max_count,
                                   uint32_t    *out_count);

/**
 * @brief  (Client-side) Query remote to stream a file's contents.
 *
 * @param  filename    Target filename.
 * @param  min_level   Level filter.
 * @param  out_buf     Output buffer.
 * @param  buf_size    Buffer capacity.
 * @param  out_len     Bytes received.
 */
LOGGER_RET_E transport_query_read(const char    *filename,
                                   LOGGER_LEVEL_E min_level,
                                   char          *out_buf,
                                   size_t         buf_size,
                                   size_t        *out_len);

#ifdef __cplusplus
}
#endif

#endif /* LOGGER_TRANSPORT_H */

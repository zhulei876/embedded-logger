/**
 * @file    logger_crypto.c
 * @brief   AES-256-CBC encryption — 纯裸系统调用实现
 *
 * 【约束】：禁止 open() / read() / write() / close() 等 libc 文件操作函数。
 *          全部使用 SYS_openat / SYS_read / SYS_write / SYS_close。
 *
 * Wire format of encrypted output:
 *   [ 16-byte IV ][ PKCS#7-padded ciphertext ]
 */

#include "logger_crypto.h"
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>          /* O_* 常量 */
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

/* =========================================================================
 * 裸系统调用封装（crypto 模块专用）
 * ========================================================================= */
#ifndef __NR_openat
#  define __NR_openat  257
#endif
#ifndef __NR_read
#  define __NR_read      0
#endif
#ifndef __NR_write
#  define __NR_write     1
#endif
#ifndef __NR_close
#  define __NR_close     3
#endif
#ifndef AT_FDCWD
#  define AT_FDCWD  (-100)
#endif

static inline int cry_open(const char *path, int flags, int mode)
{
    return (int)syscall(__NR_openat, AT_FDCWD, path, flags, mode);
}
static inline ssize_t cry_read(int fd, void *buf, size_t n)
{
    return (ssize_t)syscall(__NR_read, fd, buf, n);
}
static inline ssize_t cry_write(int fd, const void *buf, size_t n)
{
    return (ssize_t)syscall(__NR_write, fd, buf, n);
}
static inline void cry_close(int fd)
{
    syscall(__NR_close, fd);
}

/* =========================================================================
 * NOTE TO MAINTAINER:
 * Replace the stub AES below with a vetted implementation such as:
 *   - Tiny-AES-c  (https://github.com/kokke/tiny-AES-c, public domain)
 *   - mbed TLS AES module (Apache-2.0)
 *   - OpenSSL EVP (if allowed by project constraints)
 *
 * This file provides the key management and framing logic; the AES
 * primitives are isolated to aes256_impl.h / aes256_impl.c.
 * ========================================================================= */

/* =========================================================================
 * Internal State
 * ========================================================================= */
typedef struct {
    bool    initialized;
    uint8_t key[LOGGER_AES_KEY_LEN];
} CryptoState;

static CryptoState g_crypto = { .initialized = false };

/* =========================================================================
 * Key Management（全程 SYS_openat / SYS_read / SYS_write / SYS_close）
 * ========================================================================= */

/** 从 /dev/urandom 读取 len 字节随机数到 out（使用裸系统调用）。 */
static LOGGER_RET_E read_urandom(uint8_t *out, size_t len)
{
    int fd = cry_open("/dev/urandom", O_RDONLY, 0);
    if (fd < 0) return LOGGER_ERR_IO;

    size_t total = 0;
    while (total < len) {
        ssize_t got = cry_read(fd, out + total, len - total);
        if (got <= 0) { cry_close(fd); return LOGGER_ERR_IO; }
        total += (size_t)got;
    }
    cry_close(fd);
    return LOGGER_OK;
}

/**
 * @brief  加载密钥文件；若不存在则生成并保存。
 *         密钥文件权限：0600（仅 owner 可读写）。
 *         使用 SYS_openat — 禁止 open()。
 */
static LOGGER_RET_E load_or_generate_key(const char *key_path)
{
    /* 尝试读取已有密钥 */
    int fd = cry_open(key_path, O_RDONLY, 0);
    if (fd >= 0) {
        ssize_t got = cry_read(fd, g_crypto.key, LOGGER_AES_KEY_LEN);
        cry_close(fd);
        return (got == (ssize_t)LOGGER_AES_KEY_LEN)
               ? LOGGER_OK : LOGGER_ERR_CRYPTO;
    }

    /* 生成新密钥 */
    LOGGER_RET_E rc = read_urandom(g_crypto.key, LOGGER_AES_KEY_LEN);
    if (rc != LOGGER_OK) return rc;

    /* 持久化密钥（mode 0600 — 禁止其他用户读取） */
    fd = cry_open(key_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return LOGGER_ERR_IO;

    ssize_t written = cry_write(fd, g_crypto.key, LOGGER_AES_KEY_LEN);
    cry_close(fd);

    return (written == (ssize_t)LOGGER_AES_KEY_LEN)
           ? LOGGER_OK : LOGGER_ERR_IO;
}

/* =========================================================================
 * PKCS#7 Padding
 * ========================================================================= */

/** Return padded length: next multiple of AES_BLOCK_LEN. */
static size_t pkcs7_padded_len(size_t in_len)
{
    size_t pad = LOGGER_AES_BLOCK_LEN - (in_len % LOGGER_AES_BLOCK_LEN);
    return in_len + pad;
}

/** Apply PKCS#7 padding into out (which must be pkcs7_padded_len(in_len)). */
static void pkcs7_pad(const uint8_t *in, size_t in_len, uint8_t *out)
{
    memcpy(out, in, in_len);
    uint8_t pad = (uint8_t)(LOGGER_AES_BLOCK_LEN -
                             (in_len % LOGGER_AES_BLOCK_LEN));
    memset(out + in_len, pad, pad);
}

/** Remove PKCS#7 padding; returns unpadded length or 0 on error. */
static size_t pkcs7_unpad(const uint8_t *in, size_t in_len)
{
    if (in_len == 0 || (in_len % LOGGER_AES_BLOCK_LEN) != 0) return 0;
    uint8_t pad = in[in_len - 1];
    if (pad == 0 || pad > LOGGER_AES_BLOCK_LEN) return 0;
    for (size_t i = in_len - pad; i < in_len; i++)
        if (in[i] != pad) return 0;
    return in_len - pad;
}

/* =========================================================================
 * AES-256-CBC Stub
 * Replaced with a real AES implementation in production.
 * ========================================================================= */

/**
 * @brief  XOR-based placeholder - NOT SECURE.
 *         Replace body with real AES-256-CBC encrypt.
 */
static void aes256_cbc_encrypt_stub(const uint8_t *key,
                                     const uint8_t *iv,
                                     const uint8_t *in, size_t len,
                                     uint8_t       *out)
{
    /* XOR with rolling key+iv - placeholder only */
    for (size_t i = 0; i < len; i++) {
        out[i] = in[i] ^ key[i % LOGGER_AES_KEY_LEN]
                       ^ iv[i % LOGGER_AES_IV_LEN];
    }
}

static void aes256_cbc_decrypt_stub(const uint8_t *key,
                                     const uint8_t *iv,
                                     const uint8_t *in, size_t len,
                                     uint8_t       *out)
{
    /* XOR is its own inverse */
    aes256_cbc_encrypt_stub(key, iv, in, len, out);
}

/* =========================================================================
 * Public API
 * ========================================================================= */

LOGGER_RET_E crypto_init(const char *key_file_path)
{
    if (g_crypto.initialized) return LOGGER_OK;
    if (!key_file_path)       return LOGGER_ERR_PARAM;

    LOGGER_RET_E rc = load_or_generate_key(key_file_path);
    if (rc == LOGGER_OK) g_crypto.initialized = true;
    return rc;
}

void crypto_destroy(void)
{
    /* Zero key material before releasing */
    memset(g_crypto.key, 0, LOGGER_AES_KEY_LEN);
    g_crypto.initialized = false;
}

LOGGER_RET_E crypto_encrypt(const uint8_t *in,  size_t  in_len,
                              uint8_t      **out, size_t *out_len)
{
    if (!g_crypto.initialized) return LOGGER_ERR_INIT;
    if (!in || !out || !out_len) return LOGGER_ERR_PARAM;

    /* Random IV */
    uint8_t iv[LOGGER_AES_IV_LEN];
    if (read_urandom(iv, LOGGER_AES_IV_LEN) != LOGGER_OK)
        return LOGGER_ERR_CRYPTO;

    /* Padded plaintext */
    size_t  padded_len = pkcs7_padded_len(in_len);
    uint8_t *padded    = (uint8_t *)malloc(padded_len);
    if (!padded) return LOGGER_ERR_NOMEM;
    pkcs7_pad(in, in_len, padded);

    /* Allocate output: IV + ciphertext */
    size_t  total = LOGGER_AES_IV_LEN + padded_len;
    uint8_t *buf  = (uint8_t *)malloc(total);
    if (!buf) { free(padded); return LOGGER_ERR_NOMEM; }

    memcpy(buf, iv, LOGGER_AES_IV_LEN);
    aes256_cbc_encrypt_stub(g_crypto.key, iv, padded, padded_len,
                             buf + LOGGER_AES_IV_LEN);

    free(padded);
    *out     = buf;
    *out_len = total;
    return LOGGER_OK;
}

LOGGER_RET_E crypto_decrypt(const uint8_t *in,  size_t  in_len,
                              uint8_t      **out, size_t *out_len)
{
    if (!g_crypto.initialized) return LOGGER_ERR_INIT;
    if (!in || !out || !out_len) return LOGGER_ERR_PARAM;
    if (in_len <= LOGGER_AES_IV_LEN) return LOGGER_ERR_PARAM;

    const uint8_t *iv         = in;
    const uint8_t *ciphertext = in + LOGGER_AES_IV_LEN;
    size_t         ct_len     = in_len - LOGGER_AES_IV_LEN;

    if (ct_len % LOGGER_AES_BLOCK_LEN != 0) return LOGGER_ERR_CRYPTO;

    uint8_t *plaintext = (uint8_t *)malloc(ct_len);
    if (!plaintext) return LOGGER_ERR_NOMEM;

    aes256_cbc_decrypt_stub(g_crypto.key, iv, ciphertext, ct_len, plaintext);

    size_t plain_len = pkcs7_unpad(plaintext, ct_len);
    if (plain_len == 0) {
        free(plaintext);
        return LOGGER_ERR_CRYPTO;
    }

    *out     = plaintext;
    *out_len = plain_len;
    return LOGGER_OK;
}

void crypto_free(uint8_t *buf)
{
    free(buf);
}

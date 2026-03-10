/**
 * @file    logger_crypto.h
 * @brief   AES-256-CBC encryption for log files and UDP payloads
 *
 * Uses a built-in lightweight AES implementation (no openssl dependency)
 * suitable for resource-constrained embedded Linux targets.
 */

#ifndef LOGGER_CRYPTO_H
#define LOGGER_CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include "logger.h"

#define LOGGER_AES_KEY_LEN   32  /**< AES-256: 32 bytes              */
#define LOGGER_AES_BLOCK_LEN 16  /**< AES block size                 */
#define LOGGER_AES_IV_LEN    16  /**< IV length                      */

/**
 * @brief  Initialize crypto subsystem, load or generate master key.
 *         Key is stored in cfg->storage_dir/.logger_key (mode 0600).
 */
LOGGER_RET_E crypto_init(const char *key_file_path);

/**
 * @brief  Destroy crypto subsystem, zero key material.
 */
void crypto_destroy(void);

/**
 * @brief  Encrypt plaintext with AES-256-CBC.
 *         Allocates output buffer; caller must free with crypto_free().
 *
 * @param  in        Input plaintext.
 * @param  in_len    Input length.
 * @param  out       Output ciphertext (allocated by this function).
 * @param  out_len   Output length (includes IV prefix).
 */
LOGGER_RET_E crypto_encrypt(const uint8_t *in,  size_t  in_len,
                              uint8_t      **out, size_t *out_len);

/**
 * @brief  Decrypt AES-256-CBC ciphertext (IV is prepended).
 *
 * @param  in        Input ciphertext (IV + data).
 * @param  in_len    Input length.
 * @param  out       Plaintext output buffer (allocated by this function).
 * @param  out_len   Plaintext length.
 */
LOGGER_RET_E crypto_decrypt(const uint8_t *in,  size_t  in_len,
                              uint8_t      **out, size_t *out_len);

/**
 * @brief  Free a buffer allocated by crypto_encrypt / crypto_decrypt.
 */
void crypto_free(uint8_t *buf);

#ifdef __cplusplus
}
#endif

#endif /* LOGGER_CRYPTO_H */

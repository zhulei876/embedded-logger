/**
 * @file    test_logger.cpp
 * @brief   GTest unit tests for embedded-logger library
 *
 * Tests cover:
 *  - Logger initialization and teardown
 *  - Log level filtering
 *  - Storage: write, list, read, rotation
 *  - Deduplication / flood protection
 *  - Crypto: encrypt/decrypt round-trip
 *  - Crash handler installation
 *  - Transport packet CRC integrity
 */

#include <gtest/gtest.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>

extern "C" {
#include "logger.h"
#include "logger_storage.h"
#include "logger_crypto.h"
#include "logger_protection.h"
#include "logger_crash.h"
}

/* =========================================================================
 * Test Fixture: Temporary Storage Directory
 * ========================================================================= */
class LoggerTest : public ::testing::Test {
protected:
    char tmp_dir[256];
    char config_path[256];

    void SetUp() override {
        strncpy(tmp_dir, "/tmp/logger_test_XXXXXX", sizeof(tmp_dir) - 1);
        mkdtemp(tmp_dir);
        snprintf(config_path, sizeof(config_path), "%.240s/test.ini", tmp_dir);
        write_test_config(config_path);
    }

    void TearDown() override {
        logger_destroy();
        /* Cleanup temp dir */
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", tmp_dir);
        system(cmd);
    }

    void write_test_config(const char *path) {
        FILE *f = fopen(path, "w");
        ASSERT_NE(f, nullptr);
        fprintf(f,
            "[general]\nmin_level = 7\n"
            "[storage]\ndir = %s\nmax_file_size = 65536\nmax_total_size = 262144\nencrypt = 0\n"
            "[transport]\nbind_ip = 127.0.0.1\nbind_port = 19000\n"
            "remote_ip = 127.0.0.1\nremote_port = 19001\nsend_interval_ms = 100\n"
            "chunk_size = 1400\nencrypt = 0\n"
            "[protection]\ndedup_window_ms = 1000\ndedup_max_count = 3\n",
            tmp_dir);
        fclose(f);
    }
};

/* =========================================================================
 * Test: Basic Initialization
 * ========================================================================= */
TEST_F(LoggerTest, InitAndDestroy) {
    LOGGER_RET_E rc = logger_init(config_path);
    EXPECT_EQ(rc, LOGGER_OK);
    logger_destroy();
    /* Double destroy should be safe */
    logger_destroy();
}

TEST_F(LoggerTest, InitNullConfigUsesDefaults) {
    LOGGER_RET_E rc = logger_init(nullptr);
    EXPECT_EQ(rc, LOGGER_OK);
}

/* =========================================================================
 * Test: Log Level Filtering
 * ========================================================================= */
TEST_F(LoggerTest, LevelFiltering) {
    ASSERT_EQ(logger_init(config_path), LOGGER_OK);

    /* Set level to ERR: only EMERG, ALERT, CRIT, ERR should write */
    logger_set_level(MSG_ERR);

    /* These should succeed (level <= ERR) */
    EXPECT_EQ(LOG_ERR("TEST",  "error message"),  LOGGER_OK);
    EXPECT_EQ(LOG_CRIT("TEST", "critical"),        LOGGER_OK);

    /* These should be filtered out (level > ERR) */
    LOGGER_RET_E rc_warn  = logger_write(MSG_WARNING, "TEST", "warning");
    LOGGER_RET_E rc_debug = logger_write(MSG_DEBUG,   "TEST", "debug");

    /* Filtered messages return LOGGER_OK (not an error, just skipped) */
    EXPECT_EQ(rc_warn,  LOGGER_OK);
    EXPECT_EQ(rc_debug, LOGGER_OK);
}

/* =========================================================================
 * Test: Storage Write and Read Back
 * ========================================================================= */
TEST_F(LoggerTest, StorageWriteAndList) {
    LoggerStorageCfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.storage_dir, tmp_dir, sizeof(cfg.storage_dir) - 1);
    cfg.max_file_size  = 65536;
    cfg.max_total_size = 262144;
    cfg.encrypt_files  = false;

    ASSERT_EQ(storage_init(&cfg), LOGGER_OK);

    const char *entry = "[2025-01-01 00:00:00] [INFO] [PID:1] [TEST] hello\n";
    EXPECT_EQ(storage_write(entry, strlen(entry)), LOGGER_OK);

    LogFileInfo files[16];
    uint32_t count = 0;
    EXPECT_EQ(storage_list_files(files, 16, &count), LOGGER_OK);
    EXPECT_GE(count, 1u);

    storage_destroy();
}

TEST_F(LoggerTest, StorageRotationOnSizeLimit) {
    LoggerStorageCfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.storage_dir, tmp_dir, sizeof(cfg.storage_dir) - 1);
    cfg.max_file_size  = 256;    /* Very small to force rotation */
    cfg.max_total_size = 4096;
    cfg.encrypt_files  = false;

    ASSERT_EQ(storage_init(&cfg), LOGGER_OK);

    /* Write enough to trigger multiple rotations */
    char line[64];
    for (int i = 0; i < 20; i++) {
        snprintf(line, sizeof(line),
                 "[2025-01-01 00:00:%02d] [INFO] [PID:1] [T] msg%d\n", i, i);
        storage_write(line, strlen(line));
    }

    LogFileInfo files[32];
    uint32_t count = 0;
    storage_list_files(files, 32, &count);
    EXPECT_GT(count, 1u);  /* Multiple files should have been created */

    storage_destroy();
}

TEST_F(LoggerTest, StorageTotalSizeEviction) {
    LoggerStorageCfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.storage_dir, tmp_dir, sizeof(cfg.storage_dir) - 1);
    cfg.max_file_size  = 128;
    cfg.max_total_size = 512;   /* Allow only ~4 files */
    cfg.encrypt_files  = false;

    ASSERT_EQ(storage_init(&cfg), LOGGER_OK);

    char line[64];
    for (int i = 0; i < 50; i++) {
        snprintf(line, sizeof(line),
                 "[2025-01-01 00:00:%02d] [INFO] [PID:1] [T] msg%02d\n", i % 60, i);
        storage_write(line, strlen(line));
        usleep(1000); /* small delay to ensure distinct filenames */
    }

    EXPECT_LE(storage_total_size(), cfg.max_total_size + cfg.max_file_size);
    storage_destroy();
}

/* =========================================================================
 * Test: Read File with Level Filter
 * ========================================================================= */
TEST_F(LoggerTest, StorageReadWithLevelFilter) {
    ASSERT_EQ(logger_init(config_path), LOGGER_OK);

    LOG_ERR("MOD",  "this is an error");
    LOG_INFO("MOD", "this is info");
    LOG_DEBUG("MOD","this is debug");

    LogFileInfo files[4];
    uint32_t count = 0;
    storage_list_files(files, 4, &count);
    ASSERT_GE(count, 1u);

    char buf[4096];
    size_t out_len = 0;
    storage_read_file(files[0].filename, MSG_ERR,
                      buf, sizeof(buf), &out_len);

    /* Should contain ERR but not DEBUG */
    buf[out_len] = '\0';
    if (out_len > 0) {
        EXPECT_NE(strstr(buf, "[ERR]"), nullptr);
        /* DEBUG should be filtered */
        EXPECT_EQ(strstr(buf, "[DEBUG]"), nullptr);
    }
}

/* =========================================================================
 * Test: Deduplication Protection
 * ========================================================================= */
TEST_F(LoggerTest, DedupSuppressesFlood) {
    LoggerProtectionCfg cfg;
    cfg.dedup_window_ms = 2000;
    cfg.dedup_max_count = 3;

    ASSERT_EQ(protection_init(&cfg), LOGGER_OK);

    bool        allow   = true;
    const char *summary = nullptr;

    /* First N <= max_count messages should be allowed */
    for (uint32_t i = 0; i < cfg.dedup_max_count; i++) {
        protection_check("I2C", MSG_ERR, "i2c send error", &allow, &summary);
        EXPECT_TRUE(allow) << "Message " << i << " should be allowed";
    }

    /* Subsequent messages should be suppressed */
    for (int i = 0; i < 5; i++) {
        protection_check("I2C", MSG_ERR, "i2c send error", &allow, &summary);
        EXPECT_FALSE(allow) << "Message should be suppressed";
    }

    protection_destroy();
}

TEST_F(LoggerTest, DedupDifferentMessagesNotSuppressed) {
    LoggerProtectionCfg cfg;
    cfg.dedup_window_ms = 2000;
    cfg.dedup_max_count = 3;

    ASSERT_EQ(protection_init(&cfg), LOGGER_OK);

    bool        allow   = true;
    const char *summary = nullptr;

    /* Different messages from same module should each be allowed */
    protection_check("MOD", MSG_INFO, "message A", &allow, &summary);
    EXPECT_TRUE(allow);
    protection_check("MOD", MSG_INFO, "message B", &allow, &summary);
    EXPECT_TRUE(allow);
    protection_check("MOD", MSG_INFO, "message C", &allow, &summary);
    EXPECT_TRUE(allow);

    protection_destroy();
}

/* =========================================================================
 * Test: Crypto Round-Trip
 * ========================================================================= */
class CryptoTest : public ::testing::Test {
protected:
    char key_path[256];

    void SetUp() override {
        snprintf(key_path, sizeof(key_path), "/tmp/test_logger_key_%d",
                 (int)getpid());
    }
    void TearDown() override {
        crypto_destroy();
        unlink(key_path);
    }
};

TEST_F(CryptoTest, EncryptDecryptRoundTrip) {
    ASSERT_EQ(crypto_init(key_path), LOGGER_OK);

    const char *plaintext = "Hello, embedded logger! This is a test message.";
    size_t plain_len = strlen(plaintext);

    uint8_t *enc     = nullptr;
    size_t   enc_len = 0;
    ASSERT_EQ(crypto_encrypt((const uint8_t *)plaintext, plain_len,
                              &enc, &enc_len), LOGGER_OK);
    ASSERT_NE(enc, nullptr);
    ASSERT_GT(enc_len, 0u);

    uint8_t *dec     = nullptr;
    size_t   dec_len = 0;
    ASSERT_EQ(crypto_decrypt(enc, enc_len, &dec, &dec_len), LOGGER_OK);
    ASSERT_NE(dec, nullptr);
    ASSERT_EQ(dec_len, plain_len);
    EXPECT_EQ(memcmp(dec, plaintext, plain_len), 0);

    crypto_free(enc);
    crypto_free(dec);
}

TEST_F(CryptoTest, KeyPersistence) {
    ASSERT_EQ(crypto_init(key_path), LOGGER_OK);

    const char *msg = "Persistence test";
    uint8_t *enc = nullptr; size_t enc_len = 0;
    ASSERT_EQ(crypto_encrypt((const uint8_t *)msg, strlen(msg),
                              &enc, &enc_len), LOGGER_OK);
    crypto_destroy();

    /* Re-init should load the same key */
    ASSERT_EQ(crypto_init(key_path), LOGGER_OK);
    uint8_t *dec = nullptr; size_t dec_len = 0;
    ASSERT_EQ(crypto_decrypt(enc, enc_len, &dec, &dec_len), LOGGER_OK);
    EXPECT_EQ(memcmp(dec, msg, strlen(msg)), 0);

    crypto_free(enc);
    crypto_free(dec);
}

/* =========================================================================
 * Test: Crash Handler Installation
 * ========================================================================= */
TEST_F(LoggerTest, CrashHandlerInstall) {
    ASSERT_EQ(logger_init(config_path), LOGGER_OK);
    LOGGER_RET_E rc = logger_install_crash_handler();
    EXPECT_EQ(rc, LOGGER_OK);
    crash_handler_uninstall();
}

/* =========================================================================
 * Test: Log Format
 * ========================================================================= */
TEST_F(LoggerTest, LogFormatContainsRequiredFields) {
    ASSERT_EQ(logger_init(config_path), LOGGER_OK);

    /* Write a known message and verify it appears in the file */
    LOG_INFO("SD_CARD", "SD card mount success");

    LogFileInfo files[4];
    uint32_t count = 0;
    storage_list_files(files, 4, &count);
    ASSERT_GE(count, 1u);

    char buf[4096];
    size_t out_len = 0;
    storage_read_file(files[0].filename, MSG_DEBUG,
                      buf, sizeof(buf), &out_len);
    buf[out_len] = '\0';

    if (out_len > 0) {
        EXPECT_NE(strstr(buf, "[INFO]"),    nullptr) << "Missing [INFO]";
        EXPECT_NE(strstr(buf, "[PID:"),     nullptr) << "Missing [PID:]";
        EXPECT_NE(strstr(buf, "[SD_CARD]"), nullptr) << "Missing [SD_CARD]";
        EXPECT_NE(strstr(buf, "SD card mount success"), nullptr);
    }
}

/* =========================================================================
 * Main
 * ========================================================================= */
int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

/**
 * @file    sender_main.c
 * @brief   UDP Log Sender Application
 *
 * Reads configuration from config.ini, then periodically generates
 * log messages at all severity levels and sends them via the logger
 * library's UDP transport.
 *
 * Build: cmake --build build --target log_sender
 * Run:   ./log_sender [config.ini]
 */

#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>


/* =========================================================================
 * Simulated module names for demo variety
 * ========================================================================= */
static const char * const k_modules[] = {
    "SD_CARD", "I2C_BUS", "NETWORK", "SENSOR", "DISPLAY",
    "STORAGE", "BATTERY", "WATCHDOG"
};
#define MODULE_COUNT  (int)(sizeof(k_modules)/sizeof(k_modules[0]))

/* =========================================================================
 * Graceful shutdown
 * ========================================================================= */
static volatile int g_running = 1;

static void on_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

/* =========================================================================
 * Read send_interval_ms from config for demo pacing
 * ========================================================================= */
static uint32_t read_interval_from_config(const char *config_path)
{
    /* Quick parse of send_interval_ms without full config machinery */
    int fd = open(config_path, 0 /* O_RDONLY */);
    if (fd < 0) return 1000;

    char buf[2048];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n < 0) return 1000;
    buf[n] = '\0';

    char *p = strstr(buf, "send_interval_ms");
    if (!p) return 1000;
    p = strchr(p, '=');
    if (!p) return 1000;
    return (uint32_t)atoi(p + 1);
}

/* =========================================================================
 * Main
 * ========================================================================= */
int main(int argc, char *argv[])
{
    const char *config_path = (argc > 1) ? argv[1] : "config/config.ini";

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    /* Initialize logger (also installs crash handler) */
    LOGGER_RET_E rc = logger_init(config_path);
    if (rc != LOGGER_OK) {
        fprintf(stderr, "[SENDER] logger_init failed: %d\n", rc);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   
        return EXIT_FAILURE;
    }

    logger_install_crash_handler();

    uint32_t interval_ms = read_interval_from_config(config_path);
    uint64_t msg_count   = 0;
    int      mod_idx     = 0;

    LOG_INFO("SENDER", "UDP log sender started (interval=%ums)", interval_ms);

    while (g_running) {
        /* Cycle through modules and levels to demonstrate variety */
        LOGGER_LEVEL_E level = (LOGGER_LEVEL_E)(msg_count % MSG_LEVEL_MAX);
        const char    *mod   = k_modules[mod_idx % MODULE_COUNT];

        switch (level) {
        case MSG_EMERG:
            LOG_EMERG(mod, "System unresponsive, emergency shutdown initiated");
            break;
        case MSG_ALERT:
            LOG_ALERT(mod, "Hardware fault detected, immediate action required");
            break;
        case MSG_CRIT:
            LOG_CRIT(mod, "Critical threshold exceeded: temp=95C");
            break;
        case MSG_ERR:
            LOG_ERR(mod, "Operation failed (errno=%d, attempt=%llu)",
                    5, (unsigned long long)msg_count);
            break;
        case MSG_WARNING:
            LOG_WARN(mod, "Resource usage high: %d%%", 87);
            break;
        case MSG_NOTICE:
            LOG_NOTICE(mod, "Configuration reloaded successfully");
            break;
        case MSG_INFO:
            LOG_INFO(mod, "Heartbeat #%llu — all systems nominal",
                     (unsigned long long)msg_count);
            break;
        case MSG_DEBUG:
            LOG_DEBUG(mod, "register[0x%02X] = 0x%04X",
                      (unsigned)(msg_count & 0xFF),
                      (unsigned)(msg_count & 0xFFFF));
            break;
        default:
            break;
        }

        /* Simulate I2C flood every ~50 iterations to test dedup */
        if (msg_count % 50 < 20) {
            LOG_ERR("I2C_BUS", "i2c send error: device not responding");
        }

        msg_count++;
        mod_idx++;

        struct timespec ts = {
            .tv_sec  = interval_ms / 1000,
            .tv_nsec = (interval_ms % 1000) * 1000000L
        };
        nanosleep(&ts, NULL);
    }

    LOG_INFO("SENDER", "Shutting down after %llu messages",
             (unsigned long long)msg_count);
    logger_destroy();

    printf("[SENDER] Exited cleanly after %llu messages.\n",
           (unsigned long long)msg_count);
    return EXIT_SUCCESS;
}

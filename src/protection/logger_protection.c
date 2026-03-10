/**
 * @file    logger_protection.c
 * @brief   Message deduplication / flood suppression
 *
 * Algorithm:
 *  - Hash the (module + message) pair with djb2.
 *  - Keep a fixed-size LRU table of recent (hash, count, first_seen_ms).
 *  - If the same hash appears within dedup_window_ms:
 *      - Increment count.
 *      - If count == 1 (first repeat): allow through normally.
 *      - If count > dedup_max_count: suppress; set suppress=true.
 *  - When a new message arrives with a different hash, and the old slot
 *    was suppressed: emit a summary line before evicting.
 */

#include "logger_protection.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

/* =========================================================================
 * Internal Types
 * ========================================================================= */
#define DEDUP_TABLE_SIZE  64
#define DEDUP_KEY_LEN     128

typedef struct {
    bool     active;
    uint32_t hash;
    char     key[DEDUP_KEY_LEN];  /**< module:message (truncated) */
    uint32_t count;               /**< Total occurrences           */
    uint64_t first_seen_ms;
    uint64_t last_seen_ms;
    bool     suppressing;         /**< Currently suppressing?       */
} DedupEntry;

typedef struct {
    bool              initialized;
    LoggerProtectionCfg cfg;
    DedupEntry        table[DEDUP_TABLE_SIZE];
    char              summary_buf[512];
    pthread_mutex_t   lock;
} ProtectionState;

static ProtectionState g_prot = {
    .initialized = false,
    .lock        = PTHREAD_MUTEX_INITIALIZER,
};

/* =========================================================================
 * Helpers
 * ========================================================================= */

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000U + (uint64_t)(ts.tv_nsec / 1000000U);
}

/** djb2 hash */
static uint32_t djb2_hash(const char *str)
{
    uint32_t hash = 5381;
    int c;
    while ((c = (unsigned char)*str++) != 0)
        hash = ((hash << 5) + hash) + (uint32_t)c;
    return hash;
}

/** Build dedup key = "module:message" (truncated to DEDUP_KEY_LEN-1) */
static void build_key(char *out, size_t size,
                       const char *module, const char *message)
{
    snprintf(out, size, "%s:%s", module ? module : "", message ? message : "");
}

/** Find entry by hash; returns NULL if not found */
static DedupEntry *find_entry(uint32_t hash, const char *key)
{
    for (int i = 0; i < DEDUP_TABLE_SIZE; i++) {
        if (g_prot.table[i].active &&
            g_prot.table[i].hash == hash &&
            strncmp(g_prot.table[i].key, key, DEDUP_KEY_LEN) == 0) {
            return &g_prot.table[i];
        }
    }
    return NULL;
}

/** Find or allocate an entry (evicts oldest). */
static DedupEntry *get_or_alloc(uint32_t hash, const char *key,
                                  uint64_t ts_ms,
                                  const char **out_summary)
{
    DedupEntry *entry = find_entry(hash, key);
    if (entry) return entry;

    /* Find a free slot or the oldest used slot */
    DedupEntry *victim   = NULL;
    uint64_t    oldest   = UINT64_MAX;

    for (int i = 0; i < DEDUP_TABLE_SIZE; i++) {
        if (!g_prot.table[i].active) { victim = &g_prot.table[i]; break; }
        if (g_prot.table[i].first_seen_ms < oldest) {
            oldest = g_prot.table[i].first_seen_ms;
            victim = &g_prot.table[i];
        }
    }

    /* Emit summary if evicting a suppressing entry */
    if (victim && victim->active && victim->suppressing) {
        uint64_t window_ms = ts_ms - victim->first_seen_ms;
        snprintf(g_prot.summary_buf, sizeof(g_prot.summary_buf),
                 "[SUPPRESSED] \"%s\" repeated %u times in %llums",
                 victim->key, victim->count,
                 (unsigned long long)window_ms);
        *out_summary = g_prot.summary_buf;
    }

    /* Initialize new entry */
    memset(victim, 0, sizeof(*victim));
    victim->active      = true;
    victim->hash        = hash;
    snprintf(victim->key, sizeof(victim->key), "%s", key);
    victim->count       = 0;
    victim->first_seen_ms = ts_ms;
    victim->last_seen_ms  = ts_ms;
    victim->suppressing   = false;

    return victim;
}

/* =========================================================================
 * Public API
 * ========================================================================= */

LOGGER_RET_E protection_init(const LoggerProtectionCfg *cfg)
{
    pthread_mutex_lock(&g_prot.lock);
    if (g_prot.initialized) {
        pthread_mutex_unlock(&g_prot.lock);
        return LOGGER_OK;
    }
    g_prot.cfg         = *cfg;
    memset(g_prot.table, 0, sizeof(g_prot.table));
    g_prot.initialized = true;
    pthread_mutex_unlock(&g_prot.lock);
    return LOGGER_OK;
}

void protection_destroy(void)
{
    pthread_mutex_lock(&g_prot.lock);
    g_prot.initialized = false;
    pthread_mutex_unlock(&g_prot.lock);
}

LOGGER_RET_E protection_check(const char    *module,
                                LOGGER_LEVEL_E level,
                                const char    *message,
                                bool          *allow,
                                const char   **summary)
{
    (void)level;
    if (!allow || !summary) return LOGGER_ERR_PARAM;

    *allow   = true;
    *summary = NULL;

    if (!g_prot.initialized) return LOGGER_OK;

    pthread_mutex_lock(&g_prot.lock);

    char     key[DEDUP_KEY_LEN];
    build_key(key, sizeof(key), module, message);
    uint32_t hash = djb2_hash(key);
    uint64_t ts   = now_ms();

    DedupEntry *entry = get_or_alloc(hash, key, ts, summary);
    if (!entry) {
        pthread_mutex_unlock(&g_prot.lock);
        return LOGGER_OK;
    }

    entry->count++;
    entry->last_seen_ms = ts;

    /* Check if within the dedup window */
    uint64_t elapsed = ts - entry->first_seen_ms;

    if (elapsed > g_prot.cfg.dedup_window_ms) {
        /* Window expired: reset counters, allow new message */
        if (entry->suppressing) {
            snprintf(g_prot.summary_buf, sizeof(g_prot.summary_buf),
                     "[SUPPRESSED] \"%s\" repeated %u times in %llums",
                     key, entry->count - 1, /* -1: count includes current */
                     (unsigned long long)elapsed);
            *summary = g_prot.summary_buf;
        }
        entry->count         = 1;
        entry->first_seen_ms = ts;
        entry->suppressing   = false;
        *allow               = true;
    } else if (entry->count > g_prot.cfg.dedup_max_count) {
        /* Suppress: too many repeats in window */
        entry->suppressing = true;
        *allow             = false;
    }
    /* else: within window, under limit → allow normally */

    pthread_mutex_unlock(&g_prot.lock);
    return LOGGER_OK;
}

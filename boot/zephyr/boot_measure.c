/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <zephyr/kernel.h>
#include <cmsis_core.h>
#include <bootutil/bootutil_log.h>
#include <bootutil/boot_measure.h>

BOOT_LOG_MODULE_DECLARE(mcuboot);

struct boot_measure_stage {
    uint32_t start;
    uint32_t last;
    uint32_t sum;
    uint32_t count;
};

static struct boot_measure_stage stages[BOOT_MEASURE_COUNT];
static enum boot_measure_result last_result = BOOT_MEASURE_RES_NONE;

static const char *const stage_names[BOOT_MEASURE_COUNT] = {
    [BOOT_MEASURE_TOTAL] = "total",
    [BOOT_MEASURE_VALIDATE] = "validate",
    [BOOT_MEASURE_HASH] = "hash",
    [BOOT_MEASURE_SIG] = "sig",
};

static const char *const result_names[] = {
    [BOOT_MEASURE_RES_NONE] = "none",
    [BOOT_MEASURE_RES_OK] = "ok",
    [BOOT_MEASURE_RES_HASH_MISMATCH] = "hash_mismatch",
    [BOOT_MEASURE_RES_NO_KEY] = "no_key",
    [BOOT_MEASURE_RES_BAD_SIG] = "bad_sig",
    [BOOT_MEASURE_RES_OTHER] = "other",
};

void boot_measure_init(void)
{
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
}

void boot_measure_start(enum boot_measure_id id)
{
    stages[id].start = DWT->CYCCNT;
}

void boot_measure_stop(enum boot_measure_id id)
{
    uint32_t cycles = DWT->CYCCNT - stages[id].start;

    stages[id].last = cycles;
    stages[id].sum += cycles;
    stages[id].count++;
}

void boot_measure_set_result(enum boot_measure_result res)
{
    last_result = res;
}

void boot_measure_validate_done(int success)
{
    if (success) {
        last_result = BOOT_MEASURE_RES_OK;
    } else if (last_result == BOOT_MEASURE_RES_NONE ||
               last_result == BOOT_MEASURE_RES_OK) {
        last_result = BOOT_MEASURE_RES_OTHER;
    }
}

/* One line per stage, prefixed "MEAS" so scripts can grep it */
void boot_measure_report(void)
{
    uint32_t cycles_per_us = sys_clock_hw_cycles_per_sec() / 1000000U;

    BOOT_LOG_INF("MEAS clock_hz=%u", sys_clock_hw_cycles_per_sec());
    for (int i = 0; i < BOOT_MEASURE_COUNT; i++) {
        BOOT_LOG_INF("MEAS %s n=%u last_cyc=%u sum_cyc=%u last_us=%u",
                     stage_names[i], stages[i].count, stages[i].last,
                     stages[i].sum, stages[i].last / cycles_per_us);
    }
    BOOT_LOG_INF("MEAS result=%s", result_names[last_result]);

#if defined(CONFIG_INIT_STACKS) && defined(CONFIG_THREAD_STACK_INFO)
    /* Peak use of the main thread stack so far (stack painted at thread creation) */
    size_t unused;

    if (k_thread_stack_space_get(k_current_get(), &unused) == 0) {
        size_t size = k_current_get()->stack_info.size;

        BOOT_LOG_INF("MEAS stack size=%u used=%u", (unsigned int)size,
                     (unsigned int)(size - unused));
    }
#endif
}

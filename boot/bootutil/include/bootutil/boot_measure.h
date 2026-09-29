/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __BOOT_MEASURE_H__
#define __BOOT_MEASURE_H__

/**
 * @file boot_measure.h
 *
 * Cycle-count instrumentation of boot stages, used to compare signature
 * algorithms. The platform provides the implementation (e.g. a CPU cycle
 * counter); with MCUBOOT_MEASURE_TIMING unset every macro compiles to nothing.
 */

#include "mcuboot_config/mcuboot_config.h"

enum boot_measure_id {
    BOOT_MEASURE_TOTAL,      /* bootloader main() until jump / give up */
    BOOT_MEASURE_VALIDATE,   /* bootutil_img_validate() */
    BOOT_MEASURE_HASH,       /* bootutil_img_hash() */
    BOOT_MEASURE_SIG,        /* bootutil_verify_sig() */
    BOOT_MEASURE_COUNT
};

/* Outcome of the most recent bootutil_img_validate() call */
enum boot_measure_result {
    BOOT_MEASURE_RES_NONE,
    BOOT_MEASURE_RES_OK,
    BOOT_MEASURE_RES_HASH_MISMATCH,
    BOOT_MEASURE_RES_NO_KEY,
    BOOT_MEASURE_RES_BAD_SIG,
    BOOT_MEASURE_RES_OTHER,
};

#ifdef MCUBOOT_MEASURE_TIMING

void boot_measure_init(void);
void boot_measure_start(enum boot_measure_id id);
void boot_measure_stop(enum boot_measure_id id);
void boot_measure_set_result(enum boot_measure_result res);
/* Called at the end of validation; a failure not attributed to hash, key
 * or signature is recorded as "other". */
void boot_measure_validate_done(int success);
void boot_measure_report(void);

#define BOOT_MEASURE_INIT()                 boot_measure_init()
#define BOOT_MEASURE_START(id)              boot_measure_start(id)
#define BOOT_MEASURE_STOP(id)               boot_measure_stop(id)
#define BOOT_MEASURE_SET_RESULT(res)        boot_measure_set_result(res)
#define BOOT_MEASURE_VALIDATE_DONE(success) boot_measure_validate_done(success)
#define BOOT_MEASURE_REPORT()               boot_measure_report()

#else

#define BOOT_MEASURE_INIT()                 ((void)0)
#define BOOT_MEASURE_START(id)              ((void)0)
#define BOOT_MEASURE_STOP(id)               ((void)0)
#define BOOT_MEASURE_SET_RESULT(res)        ((void)0)
#define BOOT_MEASURE_VALIDATE_DONE(success) ((void)0)
#define BOOT_MEASURE_REPORT()               ((void)0)

#endif /* MCUBOOT_MEASURE_TIMING */

#endif /* __BOOT_MEASURE_H__ */

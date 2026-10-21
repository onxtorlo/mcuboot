/* fiat_measure.h - cycle counting hooks used when built inside MCUboot */

/*
 * With MCUboot boot stage timing enabled these map to bootutil/boot_measure.h
 * (BOOT_MEASURE_D_* steps, BOOT_MEASURE_P_* primitives); otherwise they are
 * empty.
 */

#ifndef __FIAT_MEASURE_H__
#define __FIAT_MEASURE_H__

#if defined(CONFIG_BOOT_MEASURE_TIMING)
#include "bootutil/boot_measure.h"
#else
#define BOOT_MEASURE_D_START(id) ((void)0)
#define BOOT_MEASURE_D_STOP(id)  ((void)0)
#define BOOT_MEASURE_P_START(id) ((void)0)
#define BOOT_MEASURE_P_STOP(id)  ((void)0)
#endif

#endif /* __FIAT_MEASURE_H__ */

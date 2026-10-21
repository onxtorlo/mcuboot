/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <string.h>
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

#if defined(MCUBOOT_MEASURE_SIG_DETAIL) || defined(MCUBOOT_MEASURE_SIG_PRIMS)
struct boot_measure_acc boot_measure_detail[BOOT_MEASURE_DETAIL_COUNT];

static const char *const detail_names[BOOT_MEASURE_DETAIL_COUNT] = {
    [BOOT_MEASURE_D_ECDSA_KEY_PARSE] = "ecdsa.key_parse",
    [BOOT_MEASURE_D_ECDSA_SIG_DECODE] = "ecdsa.sig_decode",
    [BOOT_MEASURE_D_ECDSA_VERIFY] = "ecdsa.verify",
    [BOOT_MEASURE_D_ECDSA_LOAD] = "ecdsa.verify.load",
    [BOOT_MEASURE_D_ECDSA_INV_S] = "ecdsa.verify.inv_s",
    [BOOT_MEASURE_D_ECDSA_U1U2] = "ecdsa.verify.u1u2",
    [BOOT_MEASURE_D_ECDSA_G_PLUS_Q] = "ecdsa.verify.g_plus_q",
    [BOOT_MEASURE_D_ECDSA_LOOP] = "ecdsa.verify.loop",
    [BOOT_MEASURE_D_ECDSA_LOOP_DBL] = "ecdsa.verify.loop.dbl",
    [BOOT_MEASURE_D_ECDSA_LOOP_ADD] = "ecdsa.verify.loop.add",
    [BOOT_MEASURE_D_ECDSA_FINAL] = "ecdsa.verify.final",
    [BOOT_MEASURE_D_RSA_KEY_PARSE] = "rsa.key_parse",
    [BOOT_MEASURE_D_RSA_PUBLIC] = "rsa.public",
    [BOOT_MEASURE_D_RSA_PSS_MGF1] = "rsa.pss_mgf1",
    [BOOT_MEASURE_D_RSA_PSS_HASH] = "rsa.pss_hash",
    [BOOT_MEASURE_D_PSA_VERIFY_HASH] = "psa.verify_hash",
    [BOOT_MEASURE_D_MPI_EXP_R2] = "mpi.exp_mod.r2",
    [BOOT_MEASURE_D_MPI_EXP_TO_MONT] = "mpi.exp_mod.to_mont",
    [BOOT_MEASURE_D_MPI_EXP_CORE] = "mpi.exp_mod.core",
    [BOOT_MEASURE_D_MPI_EXP_FROM_MONT] = "mpi.exp_mod.from_mont",
    [BOOT_MEASURE_D_MBECDSA_VERIFY] = "mbecdsa.verify",
    [BOOT_MEASURE_D_MBECDSA_INV_S] = "mbecdsa.verify.inv_s",
    [BOOT_MEASURE_D_MBECDSA_U1U2] = "mbecdsa.verify.u1u2",
    [BOOT_MEASURE_D_MBECDSA_MUL_G] = "mbecdsa.verify.mul_u1g",
    [BOOT_MEASURE_D_MBECDSA_MUL_Q] = "mbecdsa.verify.mul_u2q",
    [BOOT_MEASURE_D_MBECDSA_ADD_NORM] = "mbecdsa.verify.add_norm",
    [BOOT_MEASURE_D_MBECDSA_FINAL] = "mbecdsa.verify.final",
    [BOOT_MEASURE_D_ED_KEY_PARSE] = "ed25519.key_parse",
    [BOOT_MEASURE_D_ED_VERIFY] = "ed25519.verify",
    [BOOT_MEASURE_D_ED_DECOMPRESS] = "ed25519.verify.decompress",
    [BOOT_MEASURE_D_ED_SHA512] = "ed25519.verify.sha512",
    [BOOT_MEASURE_D_ED_SC_REDUCE] = "ed25519.verify.sc_reduce",
    [BOOT_MEASURE_D_ED_SMUL] = "ed25519.verify.smul",
    [BOOT_MEASURE_D_ED_SMUL_PRE] = "ed25519.verify.smul.precomp",
    [BOOT_MEASURE_D_ED_SMUL_LOOP] = "ed25519.verify.smul.loop",
    [BOOT_MEASURE_D_ED_SMUL_DBL] = "ed25519.verify.smul.loop.dbl",
    [BOOT_MEASURE_D_ED_SMUL_ADD_A] = "ed25519.verify.smul.loop.add_a",
    [BOOT_MEASURE_D_ED_SMUL_ADD_B] = "ed25519.verify.smul.loop.add_b",
    [BOOT_MEASURE_D_ED_ENCODE] = "ed25519.verify.encode",
    [BOOT_MEASURE_D_MLD_VERIFY] = "mldsa.verify",
    [BOOT_MEASURE_D_MLD_UNPACK] = "mldsa.verify.unpack",
    [BOOT_MEASURE_D_MLD_MU] = "mldsa.verify.mu",
    [BOOT_MEASURE_D_MLD_CHALLENGE] = "mldsa.verify.challenge",
    [BOOT_MEASURE_D_MLD_T1] = "mldsa.verify.t1",
    [BOOT_MEASURE_D_MLD_EXPAND_A] = "mldsa.verify.expand_a",
    [BOOT_MEASURE_D_MLD_Z_NTT] = "mldsa.verify.z_ntt",
    [BOOT_MEASURE_D_MLD_MATMUL] = "mldsa.verify.matmul",
    [BOOT_MEASURE_D_MLD_INVNTT] = "mldsa.verify.invntt",
    [BOOT_MEASURE_D_MLD_W1] = "mldsa.verify.w1",
    [BOOT_MEASURE_D_MLD_C_HASH] = "mldsa.verify.c_hash",
    [BOOT_MEASURE_P_TC_VLI_MULT] = "tc.vli_mult",
    [BOOT_MEASURE_P_TC_MMOD_FAST] = "tc.mmod_fast",
    [BOOT_MEASURE_P_TC_MMOD] = "tc.mmod",
    [BOOT_MEASURE_P_TC_MODINV] = "tc.modinv",
    [BOOT_MEASURE_P_TC_DOUBLE] = "tc.double_jacobian",
    [BOOT_MEASURE_P_TC_XYCZ_ADD] = "tc.xycz_add",
    [BOOT_MEASURE_P_TC_APPLY_Z] = "tc.apply_z",
    [BOOT_MEASURE_P_MB_MONTMUL] = "mpi.montmul",
    [BOOT_MEASURE_P_MB_MUL_MPI] = "mpi.mul_mpi",
    [BOOT_MEASURE_P_MB_MOD_MPI] = "mpi.mod_mpi",
    [BOOT_MEASURE_P_MB_INV_MOD] = "mpi.inv_mod",
    [BOOT_MEASURE_P_MB_ECP_MUL_MOD] = "ecp.mul_mod",
    [BOOT_MEASURE_P_MB_ECP_MODP] = "ecp.modp",
    [BOOT_MEASURE_P_MB_ECP_DBL] = "ecp.double_jac",
    [BOOT_MEASURE_P_MB_ECP_ADD] = "ecp.add_mixed",
    [BOOT_MEASURE_P_MB_ECP_NORM] = "ecp.normalize",
    [BOOT_MEASURE_P_MB_ECP_PRECOMP] = "ecp.precompute_comb",
    [BOOT_MEASURE_P_FIAT_MUL] = "fiat.fe_mul",
    [BOOT_MEASURE_P_FIAT_SQ] = "fiat.fe_sq",
    [BOOT_MEASURE_P_FIAT_INV] = "fiat.fe_invert",
    [BOOT_MEASURE_P_MLD_KECCAK] = "mld.keccakf1600",
    [BOOT_MEASURE_P_MLD_NTT] = "mld.poly_ntt",
    [BOOT_MEASURE_P_MLD_INVNTT_P] = "mld.poly_invntt",
    [BOOT_MEASURE_P_MLD_UNIFORM] = "mld.poly_uniform",
};
#endif

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
#if defined(MCUBOOT_MEASURE_SIG_DETAIL) || defined(MCUBOOT_MEASURE_SIG_PRIMS)
    /* Details describe the most recent signature check only */
    if (id == BOOT_MEASURE_SIG) {
        memset(boot_measure_detail, 0, sizeof(boot_measure_detail));
    }
#endif
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

#if defined(MCUBOOT_MEASURE_SIG_DETAIL) || defined(MCUBOOT_MEASURE_SIG_PRIMS)
    /* "MEASD" lines: steps/primitives of the last signature check */
    for (int i = 0; i < BOOT_MEASURE_DETAIL_COUNT; i++) {
        if (boot_measure_detail[i].count == 0) {
            continue;
        }
        BOOT_LOG_INF("MEASD %s n=%u sum_cyc=%u sum_us=%u", detail_names[i],
                     boot_measure_detail[i].count, boot_measure_detail[i].sum,
                     boot_measure_detail[i].sum / cycles_per_us);
    }
#endif

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

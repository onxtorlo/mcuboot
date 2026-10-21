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

#include <stdint.h>
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

/*
 * Finer-grained cycle counts inside bootutil_verify_sig(), cleared each time
 * BOOT_MEASURE_SIG starts, so they describe the last signature check.
 *
 * - BOOT_MEASURE_D_*: steps of one verification (MCUBOOT_MEASURE_SIG_DETAIL).
 *   Few calls each; adds almost nothing to the "sig" stage.
 * - BOOT_MEASURE_P_*: arithmetic primitives, accumulated over every call
 *   (MCUBOOT_MEASURE_SIG_PRIMS). Thousands of calls, so they slow the "sig"
 *   stage down a little; nested primitives include their callees.
 *
 * Both are inline reads of the cycle counter, which the platform provides as
 * MCUBOOT_MEASURE_CYCLES().
 */
enum boot_measure_detail_id {
    /* ECDSA P-256, TinyCrypt (ext/tinycrypt) */
    BOOT_MEASURE_D_ECDSA_KEY_PARSE,  /* bootutil_ecdsa_parse_public_key() (PSA: + psa_import_key) */
    BOOT_MEASURE_D_ECDSA_SIG_DECODE, /* ASN.1 (r, s) -> raw bytes */
    BOOT_MEASURE_D_ECDSA_VERIFY,     /* uECC_verify(), all of it */
    BOOT_MEASURE_D_ECDSA_LOAD,       /* bytes -> words, 0 < r, s < n checks */
    BOOT_MEASURE_D_ECDSA_INV_S,      /* z = 1/s mod n */
    BOOT_MEASURE_D_ECDSA_U1U2,       /* u1 = e/s, u2 = r/s mod n */
    BOOT_MEASURE_D_ECDSA_G_PLUS_Q,   /* precompute G + Q (affine) */
    BOOT_MEASURE_D_ECDSA_LOOP,       /* Shamir loop u1*G + u2*Q, all bits */
    BOOT_MEASURE_D_ECDSA_LOOP_DBL,   /* ... doubling, every bit */
    BOOT_MEASURE_D_ECDSA_LOOP_ADD,   /* ... addition, bits where u1|u2 is set */
    BOOT_MEASURE_D_ECDSA_FINAL,      /* 1/Z mod p, to affine, compare with r */

    /* RSA / PSA wrappers in bootutil */
    BOOT_MEASURE_D_RSA_KEY_PARSE,     /* bootutil_rsa_parse_public_key() (PSA: psa_import_key) */
    BOOT_MEASURE_D_RSA_PUBLIC,        /* s^e mod N, mbedtls_rsa_public() (legacy) */
    BOOT_MEASURE_D_RSA_PSS_MGF1,      /* PSS mask generation (SHA-256 x7) */
    BOOT_MEASURE_D_RSA_PSS_HASH,      /* PSS H' = SHA-256(M') and compare */
    BOOT_MEASURE_D_PSA_VERIFY_HASH,   /* psa_verify_hash() (RSA, ECDSA over PSA) */

    /* Mbed TLS / TF-PSA-Crypto bignum (RSA) */
    BOOT_MEASURE_D_MPI_EXP_R2,        /* R^2 mod N (long division) */
    BOOT_MEASURE_D_MPI_EXP_TO_MONT,   /* A -> Montgomery form */
    BOOT_MEASURE_D_MPI_EXP_CORE,      /* windowed square-and-multiply */
    BOOT_MEASURE_D_MPI_EXP_FROM_MONT, /* result <- Montgomery form */

    /* Mbed TLS / TF-PSA-Crypto ECDSA */
    BOOT_MEASURE_D_MBECDSA_VERIFY,    /* mbedtls_ecdsa_verify_restartable() */
    BOOT_MEASURE_D_MBECDSA_INV_S,     /* 1/s mod n */
    BOOT_MEASURE_D_MBECDSA_U1U2,      /* u1 = e/s, u2 = r/s mod n */
    BOOT_MEASURE_D_MBECDSA_MUL_G,     /* u1*G (comb, fixed point) */
    BOOT_MEASURE_D_MBECDSA_MUL_Q,     /* u2*Q (comb, precompute for Q) */
    BOOT_MEASURE_D_MBECDSA_ADD_NORM,  /* u1*G + u2*Q, to affine */
    BOOT_MEASURE_D_MBECDSA_FINAL,     /* x mod n, compare with r */

    /* Ed25519 (fiat-crypto, ext/fiat) */
    BOOT_MEASURE_D_ED_KEY_PARSE,      /* bootutil_import_key() */
    BOOT_MEASURE_D_ED_VERIFY,         /* ED25519_verify(), all of it */
    BOOT_MEASURE_D_ED_DECOMPRESS,     /* public key -> point (sqrt) */
    BOOT_MEASURE_D_ED_SHA512,         /* SHA-512(R, A, M) */
    BOOT_MEASURE_D_ED_SC_REDUCE,      /* hash mod l */
    BOOT_MEASURE_D_ED_SMUL,           /* h*A + s*B, all of it */
    BOOT_MEASURE_D_ED_SMUL_PRE,       /* sliding windows, table of A */
    BOOT_MEASURE_D_ED_SMUL_LOOP,      /* double-and-add loop */
    BOOT_MEASURE_D_ED_SMUL_DBL,       /* ... doubling, every bit */
    BOOT_MEASURE_D_ED_SMUL_ADD_A,     /* ... add +-kA (cached) */
    BOOT_MEASURE_D_ED_SMUL_ADD_B,     /* ... add +-kB (precomp) */
    BOOT_MEASURE_D_ED_ENCODE,         /* point -> bytes (inversion), compare */

    /* ML-DSA (mldsa-native) */
    BOOT_MEASURE_D_MLD_VERIFY,        /* mld_sign_verify_internal(), all of it */
    BOOT_MEASURE_D_MLD_UNPACK,        /* unpack pk, sig; norm check of z */
    BOOT_MEASURE_D_MLD_MU,            /* tr = H(pk), mu = H(tr, pre, M) */
    BOOT_MEASURE_D_MLD_CHALLENGE,     /* c from c~, NTT(c) */
    BOOT_MEASURE_D_MLD_T1,            /* NTT(t1 * 2^d), c * t1 */
    BOOT_MEASURE_D_MLD_EXPAND_A,      /* A from rho (SHAKE128) */
    BOOT_MEASURE_D_MLD_Z_NTT,         /* NTT(z) */
    BOOT_MEASURE_D_MLD_MATMUL,        /* A*z - c*t1 */
    BOOT_MEASURE_D_MLD_INVNTT,        /* inverse NTT of w */
    BOOT_MEASURE_D_MLD_W1,            /* use hint, pack w1 */
    BOOT_MEASURE_D_MLD_C_HASH,        /* c~' = H(mu, w1), compare */

    /* Primitives, ECDSA P-256 TinyCrypt (ecc.c) */
    BOOT_MEASURE_P_TC_VLI_MULT,      /* 256x256 -> 512 bit product */
    BOOT_MEASURE_P_TC_MMOD_FAST,     /* P-256 special reduction mod p */
    BOOT_MEASURE_P_TC_MMOD,          /* generic reduction (mod n), bit by bit */
    BOOT_MEASURE_P_TC_MODINV,        /* binary inversion, bit by bit */
    BOOT_MEASURE_P_TC_DOUBLE,        /* double_jacobian_default() */
    BOOT_MEASURE_P_TC_XYCZ_ADD,      /* XYcZ_add() */
    BOOT_MEASURE_P_TC_APPLY_Z,       /* apply_z() */

    /* Primitives, Mbed TLS / TF-PSA-Crypto bignum and ECP */
    BOOT_MEASURE_P_MB_MONTMUL,        /* Montgomery multiplication */
    BOOT_MEASURE_P_MB_MUL_MPI,        /* schoolbook product */
    BOOT_MEASURE_P_MB_MOD_MPI,        /* remainder by long division */
    BOOT_MEASURE_P_MB_INV_MOD,        /* mbedtls_mpi_gcd_modinv_odd() */
    BOOT_MEASURE_P_MB_ECP_MUL_MOD,    /* field multiply: product + reduction */
    BOOT_MEASURE_P_MB_ECP_MODP,       /* field reduction (NIST fast or generic) */
    BOOT_MEASURE_P_MB_ECP_DBL,        /* ecp_double_jac() */
    BOOT_MEASURE_P_MB_ECP_ADD,        /* ecp_add_mixed() */
    BOOT_MEASURE_P_MB_ECP_NORM,       /* ecp_normalize_jac(_many)() */
    BOOT_MEASURE_P_MB_ECP_PRECOMP,    /* ecp_precompute_comb() */

    /* Primitives, Ed25519 (fiat-crypto) */
    BOOT_MEASURE_P_FIAT_MUL,          /* field multiplication */
    BOOT_MEASURE_P_FIAT_SQ,           /* field squaring */
    BOOT_MEASURE_P_FIAT_INV,          /* field inversion (fe_loose_invert) */

    /* Primitives, ML-DSA (mldsa-native) */
    BOOT_MEASURE_P_MLD_KECCAK,        /* Keccak-f[1600] permutation */
    BOOT_MEASURE_P_MLD_NTT,           /* forward NTT of one polynomial */
    BOOT_MEASURE_P_MLD_INVNTT_P,      /* inverse NTT of one polynomial */
    BOOT_MEASURE_P_MLD_UNIFORM,       /* rejection sampling of one A entry */

    BOOT_MEASURE_DETAIL_COUNT
};

/* depth: an id entered again before it is left (recursion, or two nested
 * functions sharing an id) is timed once, from the outermost start */
struct boot_measure_acc {
    uint32_t start;
    uint32_t sum;
    uint32_t count;
    uint32_t depth;
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

#if defined(MCUBOOT_MEASURE_SIG_DETAIL) || defined(MCUBOOT_MEASURE_SIG_PRIMS)
extern struct boot_measure_acc boot_measure_detail[BOOT_MEASURE_DETAIL_COUNT];

static inline void boot_measure_acc_start(enum boot_measure_detail_id id)
{
    if (boot_measure_detail[id].depth++ == 0) {
        boot_measure_detail[id].start = MCUBOOT_MEASURE_CYCLES();
    }
}

static inline void boot_measure_acc_stop(enum boot_measure_detail_id id)
{
    if (--boot_measure_detail[id].depth == 0) {
        boot_measure_detail[id].sum += MCUBOOT_MEASURE_CYCLES() -
                                       boot_measure_detail[id].start;
    }
    boot_measure_detail[id].count++;
}
#endif

#ifdef MCUBOOT_MEASURE_SIG_DETAIL
#define BOOT_MEASURE_D_START(id)            boot_measure_acc_start(id)
#define BOOT_MEASURE_D_STOP(id)             boot_measure_acc_stop(id)
#else
#define BOOT_MEASURE_D_START(id)            ((void)0)
#define BOOT_MEASURE_D_STOP(id)             ((void)0)
#endif

#ifdef MCUBOOT_MEASURE_SIG_PRIMS
#define BOOT_MEASURE_P_START(id)            boot_measure_acc_start(id)
#define BOOT_MEASURE_P_STOP(id)             boot_measure_acc_stop(id)
#else
#define BOOT_MEASURE_P_START(id)            ((void)0)
#define BOOT_MEASURE_P_STOP(id)             ((void)0)
#endif

#endif /* __BOOT_MEASURE_H__ */

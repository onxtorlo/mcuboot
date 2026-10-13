/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * ML-DSA (FIPS 204) image signature verification, using mldsa-native.
 *
 * The image is signed the same way as with Ed25519: the message passed to
 * ML-DSA.Verify is the image hash (SHA-256 or SHA-512 TLV), with an empty
 * context string. The embedded public key is the raw FIPS 204 encoding
 * (pkEncode), 1312/1952/2592 bytes for ML-DSA-44/65/87.
 */

#include <string.h>

#include "mcuboot_config/mcuboot_config.h"

#ifdef MCUBOOT_SIGN_MLDSA

#if defined(MCUBOOT_BUILTIN_KEY) || defined(MCUBOOT_HW_KEY)
#error "ML-DSA supports only public keys compiled into MCUboot"
#endif

#include <mldsa_native.h>

#include "bootutil/sign_key.h"
#include "bootutil/bootutil_log.h"
#include "bootutil/crypto/sha.h"
#include "bootutil/fault_injection_hardening.h"
#include "bootutil_priv.h"

BOOT_LOG_MODULE_DECLARE(mcuboot);

#if MCUBOOT_SIGN_MLDSA_LEVEL != MLD_CONFIG_PARAMETER_SET
#error "MCUboot and mldsa-native are built for different ML-DSA parameter sets"
#endif

/* mldsa-native is built with MLD_CONFIG_NAMESPACE_PREFIX (see boot/zephyr/CMakeLists.txt);
 * mldsa_native.h does not keep its namespace macro, so build the name here.
 */
#define MLDSA_CONCAT_(a, b) a##_##b
#define MLDSA_CONCAT(a, b)  MLDSA_CONCAT_(a, b)
#define mldsa_verify        MLDSA_CONCAT(MLD_CONFIG_NAMESPACE_PREFIX, verify)

#define MLDSA_PUBLIC_KEY_LENGTH MLDSA_PUBLICKEYBYTES(MCUBOOT_SIGN_MLDSA_LEVEL)
#define MLDSA_SIGNATURE_LENGTH  MLDSA_BYTES(MCUBOOT_SIGN_MLDSA_LEVEL)

fih_ret
bootutil_verify_sig(uint8_t *msg, uint32_t mlen, uint8_t *sig, size_t slen,
                    uint8_t key_id)
{
    int rc;
    FIH_DECLARE(fih_rc, FIH_FAILURE);
    const uint8_t *pubkey;

    BOOT_LOG_DBG("bootutil_verify_sig: ML-DSA-%d key_id %d",
                 MCUBOOT_SIGN_MLDSA_LEVEL, (int)key_id);

    if (mlen != IMAGE_HASH_SIZE) {
        BOOT_LOG_DBG("bootutil_verify_sig: expected hash len %d, got %d",
                     IMAGE_HASH_SIZE, mlen);
        goto out;
    }

    if (slen != MLDSA_SIGNATURE_LENGTH) {
        BOOT_LOG_DBG("bootutil_verify_sig: expected slen %d, got %u",
                     MLDSA_SIGNATURE_LENGTH, (unsigned int)slen);
        goto out;
    }

    if (*bootutil_keys[key_id].len != MLDSA_PUBLIC_KEY_LENGTH) {
        BOOT_LOG_DBG("bootutil_verify_sig: expected key len %d, got %u",
                     MLDSA_PUBLIC_KEY_LENGTH, *bootutil_keys[key_id].len);
        goto out;
    }
    pubkey = bootutil_keys[key_id].key;

    /* 0 on success, MLD_ERR_FAIL on a bad signature */
    rc = mldsa_verify(sig, slen, msg, mlen, NULL, 0, pubkey);
    fih_rc = fih_ret_encode_zero_equality(rc);
    if (FIH_NOT_EQ(fih_rc, FIH_SUCCESS)) {
        FIH_SET(fih_rc, FIH_FAILURE);
    }

out:
    FIH_RET(fih_rc);
}

#endif /* MCUBOOT_SIGN_MLDSA */

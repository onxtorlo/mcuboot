"""
ML-DSA (FIPS 204) key management
"""

# SPDX-License-Identifier: Apache-2.0

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa

from .general import KeyClass

# parameter set -> (private key class, public key class, public key bytes, signature bytes)
MLDSA_PARAMS = {
    44: (mldsa.MLDSA44PrivateKey, mldsa.MLDSA44PublicKey, 1312, 2420),
    65: (mldsa.MLDSA65PrivateKey, mldsa.MLDSA65PublicKey, 1952, 3309),
    87: (mldsa.MLDSA87PrivateKey, mldsa.MLDSA87PublicKey, 2592, 4627),
}
MLDSA_PRIVATE_TYPES = tuple(p[0] for p in MLDSA_PARAMS.values())
MLDSA_PUBLIC_TYPES = tuple(p[1] for p in MLDSA_PARAMS.values())


class MLDSAUsageError(Exception):
    pass


def _level_of(key):
    for level, (priv, pub, _, _) in MLDSA_PARAMS.items():
        if isinstance(key, (priv, pub)):
            return level
    raise MLDSAUsageError(f"Not an ML-DSA key: {type(key)}")


class MLDSAPublic(KeyClass):
    """ML-DSA public key. The image signature is ML-DSA.Sign over the image
    digest (the SHA TLV value) with an empty context, as for Ed25519."""

    def __init__(self, key):
        self.key = key
        self.level = _level_of(key)

    def shortname(self):
        return "mldsa"

    def _unsupported(self, name):
        raise MLDSAUsageError(f"Operation {name} requires private key")

    def _get_public(self):
        return self.key

    def get_public_bytes(self):
        # Embedded into MCUboot raw (FIPS 204 pkEncode), no ASN.1 wrapper
        return self._get_public().public_bytes_raw()

    def get_public_pem(self):
        return self._get_public().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

    def get_private_bytes(self, minimal, format):
        self._unsupported("get_private_bytes")

    def export_private(self, path, passwd=None):
        self._unsupported("export_private")

    def export_public(self, path):
        """Write the public key to the given file."""
        with open(path, "wb") as f:
            f.write(self.get_public_pem())

    def sig_type(self):
        return f"MLDSA{self.level}"

    def sig_tlv(self):
        return f"MLDSA{self.level}"

    def sig_len(self):
        return MLDSA_PARAMS[self.level][3]

    def verify_digest(self, signature, digest):
        """Verify that signature is valid for given digest"""
        k = self.key
        if isinstance(k, MLDSA_PRIVATE_TYPES):
            k = k.public_key()
        return k.verify(signature, digest)


class MLDSA(MLDSAPublic):
    """Wrapper around an ML-DSA private key."""

    def __init__(self, key):
        self.key = key
        self.level = _level_of(key)

    @staticmethod
    def generate(level):
        if level not in MLDSA_PARAMS:
            raise MLDSAUsageError(f"Unsupported ML-DSA parameter set: {level}")
        return MLDSA(MLDSA_PARAMS[level][0].generate())

    def _get_public(self):
        return self.key.public_key()

    def get_private_bytes(self, minimal, format):
        raise MLDSAUsageError(f"Operation not supported with {self.shortname()} keys")

    def export_private(self, path, passwd=None):
        """
        Write the private key (PKCS#8, seed form) to the given file,
        protecting it with the optional password.
        """
        if passwd is None:
            enc = serialization.NoEncryption()
        else:
            enc = serialization.BestAvailableEncryption(passwd)
        pem = self.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc)
        with open(path, "wb") as f:
            f.write(pem)

    def sign_digest(self, digest):
        """Return the actual signature (deterministic ML-DSA is not exposed
        by pyca; the hedged variant is used, which verifies the same way)"""
        return self.key.sign(digest)

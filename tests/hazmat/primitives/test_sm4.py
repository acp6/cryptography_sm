# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import binascii
import os

import pytest

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.decrepit.ciphers.modes import CFB, OFB
from cryptography.hazmat.primitives.ciphers import algorithms, base, modes
from cryptography.hazmat.primitives.ciphers.aead import SM4CCM

from ...utils import load_nist_vectors, load_vectors_from_file
from .utils import generate_encrypt_test


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.SM4(b"\x00" * 16), modes.ECB()
    ),
    skip_message="Does not support SM4 ECB",
)
class TestSM4ModeECB:
    test_ecb = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "SM4"),
        ["draft-ribose-cfrg-sm4-10-ecb.txt"],
        lambda key, **kwargs: algorithms.SM4(binascii.unhexlify(key)),
        lambda **kwargs: modes.ECB(),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.SM4(b"\x00" * 16), modes.CBC(b"\x00" * 16)
    ),
    skip_message="Does not support SM4 CBC",
)
class TestSM4ModeCBC:
    test_cbc = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "SM4"),
        ["draft-ribose-cfrg-sm4-10-cbc.txt"],
        lambda key, **kwargs: algorithms.SM4(binascii.unhexlify(key)),
        lambda iv, **kwargs: modes.CBC(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.SM4(b"\x00" * 16), OFB(b"\x00" * 16)
    ),
    skip_message="Does not support SM4 OFB",
)
class TestSM4ModeOFB:
    test_ofb = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "SM4"),
        ["draft-ribose-cfrg-sm4-10-ofb.txt"],
        lambda key, **kwargs: algorithms.SM4(binascii.unhexlify(key)),
        lambda iv, **kwargs: OFB(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.SM4(b"\x00" * 16), CFB(b"\x00" * 16)
    ),
    skip_message="Does not support SM4 CFB",
)
class TestSM4ModeCFB:
    test_cfb = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "SM4"),
        ["draft-ribose-cfrg-sm4-10-cfb.txt"],
        lambda key, **kwargs: algorithms.SM4(binascii.unhexlify(key)),
        lambda iv, **kwargs: CFB(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.SM4(b"\x00" * 16), modes.CTR(b"\x00" * 16)
    ),
    skip_message="Does not support SM4 CTR",
)
class TestSM4ModeCTR:
    test_cfb = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "SM4"),
        ["draft-ribose-cfrg-sm4-10-ctr.txt"],
        lambda key, **kwargs: algorithms.SM4(binascii.unhexlify(key)),
        lambda iv, **kwargs: modes.CTR(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.SM4(b"\x00" * 16), modes.GCM(b"\x00" * 16)
    ),
    skip_message="Does not support SM4 GCM",
)
class TestSM4ModeGCM:
    @pytest.mark.parametrize(
        "vector",
        load_vectors_from_file(
            os.path.join("ciphers", "SM4", "rfc8998.txt"),
            load_nist_vectors,
        ),
    )
    def test_encryption(self, vector, backend):
        key = binascii.unhexlify(vector["key"])
        iv = binascii.unhexlify(vector["iv"])
        associated_data = binascii.unhexlify(vector["aad"])
        tag = binascii.unhexlify(vector["tag"])
        plaintext = binascii.unhexlify(vector["plaintext"])
        ciphertext = binascii.unhexlify(vector["ciphertext"])

        cipher = base.Cipher(algorithms.SM4(key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(associated_data)
        computed_ct = encryptor.update(plaintext) + encryptor.finalize()
        assert computed_ct == ciphertext
        assert encryptor.tag == tag

    @pytest.mark.parametrize(
        "vector",
        load_vectors_from_file(
            os.path.join("ciphers", "SM4", "rfc8998.txt"),
            load_nist_vectors,
        ),
    )
    def test_decryption(self, vector, backend):
        key = binascii.unhexlify(vector["key"])
        iv = binascii.unhexlify(vector["iv"])
        associated_data = binascii.unhexlify(vector["aad"])
        tag = binascii.unhexlify(vector["tag"])
        plaintext = binascii.unhexlify(vector["plaintext"])
        ciphertext = binascii.unhexlify(vector["ciphertext"])

        cipher = base.Cipher(algorithms.SM4(key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(associated_data)
        computed_pt = decryptor.update(ciphertext) + decryptor.finalize()
        assert computed_pt == plaintext

        cipher_no_tag = base.Cipher(algorithms.SM4(key), modes.GCM(iv))
        decryptor = cipher_no_tag.decryptor()
        decryptor.authenticate_additional_data(associated_data)
        computed_pt = decryptor.update(
            ciphertext
        ) + decryptor.finalize_with_tag(tag)
        assert computed_pt == plaintext

    @pytest.mark.parametrize(
        "vector",
        load_vectors_from_file(
            os.path.join("ciphers", "SM4", "rfc8998.txt"),
            load_nist_vectors,
        ),
    )
    def test_invalid_tag(self, vector, backend):
        key = binascii.unhexlify(vector["key"])
        iv = binascii.unhexlify(vector["iv"])
        associated_data = binascii.unhexlify(vector["aad"])
        tag = binascii.unhexlify(vector["tag"])
        ciphertext = binascii.unhexlify(vector["ciphertext"])

        cipher = base.Cipher(algorithms.SM4(key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(associated_data)
        decryptor.update(ciphertext[:-1])
        with pytest.raises(InvalidTag):
            decryptor.finalize()

        cipher_no_tag = base.Cipher(algorithms.SM4(key), modes.GCM(iv))
        decryptor = cipher_no_tag.decryptor()
        decryptor.authenticate_additional_data(associated_data)
        decryptor.update(ciphertext[:-1])
        with pytest.raises(InvalidTag):
            decryptor.finalize_with_tag(tag)


def _sm4ccm_supported():
    try:
        SM4CCM(b"\x00" * 16)
        return True
    except UnsupportedAlgorithm:
        return False


@pytest.mark.skipif(
    not _sm4ccm_supported(),
    reason="Does not support SM4CCM",
)
class TestSM4ModeCCM:
    @pytest.mark.parametrize(
        "vector",
        load_vectors_from_file(
            os.path.join("ciphers", "SM4", "rfc8998_ccm.txt"),
            load_nist_vectors,
        ),
    )
    def test_encryption(self, vector):
        key = binascii.unhexlify(vector["key"])
        iv = binascii.unhexlify(vector["iv"])
        aad = binascii.unhexlify(vector["aad"])
        tag = binascii.unhexlify(vector["tag"])
        plaintext = binascii.unhexlify(vector["plaintext"])
        ciphertext = binascii.unhexlify(vector["ciphertext"])

        sm4ccm = SM4CCM(key)
        computed = sm4ccm.encrypt(iv, plaintext, aad)
        assert computed == ciphertext + tag

    @pytest.mark.parametrize(
        "vector",
        load_vectors_from_file(
            os.path.join("ciphers", "SM4", "rfc8998_ccm.txt"),
            load_nist_vectors,
        ),
    )
    def test_decryption(self, vector):
        key = binascii.unhexlify(vector["key"])
        iv = binascii.unhexlify(vector["iv"])
        aad = binascii.unhexlify(vector["aad"])
        tag = binascii.unhexlify(vector["tag"])
        plaintext = binascii.unhexlify(vector["plaintext"])
        ciphertext = binascii.unhexlify(vector["ciphertext"])

        sm4ccm = SM4CCM(key)
        computed_pt = sm4ccm.decrypt(iv, ciphertext + tag, aad)
        assert computed_pt == plaintext

    def test_invalid_tag(self):
        key = b"\x00" * 16
        sm4ccm = SM4CCM(key)
        nonce = os.urandom(12)
        ct = sm4ccm.encrypt(nonce, b"hello", None)
        with pytest.raises(InvalidTag):
            sm4ccm.decrypt(nonce, ct[:-1] + bytes([ct[-1] ^ 1]), None)

    def test_roundtrip(self):
        key = SM4CCM.generate_key()
        sm4ccm = SM4CCM(key)
        nonce = os.urandom(12)
        pt = b"test data for sm4-ccm roundtrip"
        aad = b"additional data"
        ct = sm4ccm.encrypt(nonce, pt, aad)
        assert sm4ccm.decrypt(nonce, ct, aad) == pt

    def test_invalid_key_length(self):
        with pytest.raises(ValueError):
            SM4CCM(b"\x00" * 32)
        with pytest.raises(ValueError):
            SM4CCM(b"\x00" * 8)

    def test_invalid_nonce_length(self):
        key = b"\x00" * 16
        sm4ccm = SM4CCM(key)
        with pytest.raises(ValueError):
            sm4ccm.encrypt(b"\x00" * 6, b"hello", None)
        with pytest.raises(ValueError):
            sm4ccm.encrypt(b"\x00" * 14, b"hello", None)

    def test_invalid_tag_length(self):
        key = b"\x00" * 16
        with pytest.raises(ValueError):
            SM4CCM(key, tag_length=7)
        with pytest.raises(ValueError):
            SM4CCM(key, tag_length=2)

    def test_default_tag_length(self):
        key = b"\x00" * 16
        sm4ccm = SM4CCM(key)
        nonce = os.urandom(12)
        ct = sm4ccm.encrypt(nonce, b"hello", None)
        assert len(ct) == len(b"hello") + 16

    def test_custom_tag_length(self):
        key = b"\x00" * 16
        sm4ccm = SM4CCM(key, tag_length=8)
        nonce = os.urandom(12)
        ct = sm4ccm.encrypt(nonce, b"hello", None)
        assert len(ct) == len(b"hello") + 8
        assert sm4ccm.decrypt(nonce, ct, None) == b"hello"

    def test_generate_key(self):
        key = SM4CCM.generate_key()
        assert len(key) == 16

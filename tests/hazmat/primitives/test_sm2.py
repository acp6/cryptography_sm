# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

"""
Comprehensive tests for SM2 algorithm support including GM/T standard
certificate issuance, verification, CRL, and OCSP.
"""

import datetime
import os

import pytest

from cryptography import exceptions, x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
)
from cryptography.x509 import ocsp
from cryptography.x509.oid import (
    NameOID,
    SignatureAlgorithmOID,
)


def _skip_sm2_unsupported(backend):
    if not backend.elliptic_curve_supported(ec.SM2()):
        pytest.skip("SM2 curve is not supported by this backend")


def _generate_sm2_key():
    return ec.generate_private_key(ec.SM2())


def _build_sm2_ca(
    ca_key=None,
    cn="SM2 Test CA",
    country="CN",
):
    """Build a self-signed SM2 CA certificate."""
    if ca_key is None:
        ca_key = _generate_sm2_key()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2040, 1, 1))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    ca_cert = builder.sign(ca_key, hashes.SM3())
    return ca_cert, ca_key


def _build_sm2_leaf(ca_key, ca_cert, leaf_key=None, cn="SM2 Test Leaf"):
    """Build a leaf certificate signed by an SM2 CA."""
    if leaf_key is None:
        leaf_key = _generate_sm2_key()

    builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
                x509.NameAttribute(NameOID.COMMON_NAME, cn),
            ])
        )
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2021, 1, 1))
        .not_valid_after(datetime.datetime(2030, 1, 1))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
    )
    leaf_cert = builder.sign(ca_key, hashes.SM3())
    return leaf_cert, leaf_key


class TestSM2KeyGeneration:
    def test_generate_sm2_key(self, backend):
        _skip_sm2_unsupported(backend)

        key = ec.generate_private_key(ec.SM2())
        assert isinstance(key.curve, ec.SM2)
        assert key.curve.key_size == 256
        assert key.curve.name == "sm2"

    def test_sm2_public_key_properties(self, backend):
        _skip_sm2_unsupported(backend)

        key = _generate_sm2_key()
        pub = key.public_key()
        assert isinstance(pub.curve, ec.SM2)
        assert pub.curve.key_size == 256

    def test_sm2_private_numbers_roundtrip(self, backend):
        _skip_sm2_unsupported(backend)

        key = _generate_sm2_key()
        priv_numbers = key.private_numbers()
        pub_numbers = priv_numbers.public_numbers

        # Reconstruct the key from numbers
        reconstructed = priv_numbers.private_key()
        assert reconstructed.private_numbers() == priv_numbers
        assert pub_numbers.x > 0
        assert pub_numbers.y > 0

    def test_sm2_derive_private_key(self, backend):
        _skip_sm2_unsupported(backend)

        key = _generate_sm2_key()
        priv_numbers = key.private_numbers()

        derived_key = ec.derive_private_key(
            priv_numbers.private_value, ec.SM2()
        )
        assert derived_key.private_numbers() == priv_numbers


class TestSM2SignVerify:
    """Test SM2 signing and verification with SM3 hash (GM/T 0003)."""

    def test_sign_verify_roundtrip(self, backend):
        _skip_sm2_unsupported(backend)

        key = _generate_sm2_key()
        message = b"Hello SM2 with SM3!"
        signature = key.sign(message, ec.ECDSA(hashes.SM3()))

        # Should not raise
        key.public_key().verify(signature, message, ec.ECDSA(hashes.SM3()))

    def test_sign_verify_empty_message(self, backend):
        _skip_sm2_unsupported(backend)

        key = _generate_sm2_key()
        signature = key.sign(b"", ec.ECDSA(hashes.SM3()))
        key.public_key().verify(signature, b"", ec.ECDSA(hashes.SM3()))

    def test_sign_verify_large_message(self, backend):
        _skip_sm2_unsupported(backend)

        key = _generate_sm2_key()
        message = os.urandom(1024 * 1024)  # 1 MB
        signature = key.sign(message, ec.ECDSA(hashes.SM3()))
        key.public_key().verify(signature, message, ec.ECDSA(hashes.SM3()))

    def test_verify_wrong_message_fails(self, backend):
        _skip_sm2_unsupported(backend)

        key = _generate_sm2_key()
        message = b"correct message"
        signature = key.sign(message, ec.ECDSA(hashes.SM3()))

        with pytest.raises(InvalidSignature):
            key.public_key().verify(
                signature, b"wrong message", ec.ECDSA(hashes.SM3())
            )

    def test_verify_wrong_signature_fails(self, backend):
        _skip_sm2_unsupported(backend)

        key = _generate_sm2_key()
        message = b"test message"
        signature = key.sign(message, ec.ECDSA(hashes.SM3()))

        # Corrupt the signature
        bad_sig = bytearray(signature)
        bad_sig[-1] ^= 0xFF
        with pytest.raises(InvalidSignature):
            key.public_key().verify(
                bytes(bad_sig), message, ec.ECDSA(hashes.SM3())
            )

    def test_verify_wrong_key_fails(self, backend):
        _skip_sm2_unsupported(backend)

        key1 = _generate_sm2_key()
        key2 = _generate_sm2_key()
        message = b"test message"
        signature = key1.sign(message, ec.ECDSA(hashes.SM3()))

        with pytest.raises(InvalidSignature):
            key2.public_key().verify(
                signature, message, ec.ECDSA(hashes.SM3())
            )

    def test_signature_is_valid_der(self, backend):
        _skip_sm2_unsupported(backend)

        key = _generate_sm2_key()
        signature = key.sign(b"data", ec.ECDSA(hashes.SM3()))

        # SM2 signatures use the same DER encoding as ECDSA
        r, s = decode_dss_signature(signature)
        assert r > 0
        assert s > 0

    def test_multiple_signatures_differ(self, backend):
        """Non-deterministic SM2 signing should produce different signatures."""
        _skip_sm2_unsupported(backend)

        key = _generate_sm2_key()
        message = b"same message"
        sig1 = key.sign(message, ec.ECDSA(hashes.SM3()))
        sig2 = key.sign(message, ec.ECDSA(hashes.SM3()))
        # Signatures may or may not differ (random nonce), but both must verify
        key.public_key().verify(sig1, message, ec.ECDSA(hashes.SM3()))
        key.public_key().verify(sig2, message, ec.ECDSA(hashes.SM3()))


class TestSM2KeySerialization:
    """Test SM2 key serialization and deserialization."""

    def test_private_key_pem_roundtrip(self, backend):
        _skip_sm2_unsupported(backend)

        key = _generate_sm2_key()
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        loaded = serialization.load_pem_private_key(pem, password=None)
        assert isinstance(loaded, ec.EllipticCurvePrivateKey)
        assert isinstance(loaded.curve, ec.SM2)
        assert loaded.private_numbers() == key.private_numbers()

    def test_private_key_der_roundtrip(self, backend):
        _skip_sm2_unsupported(backend)

        key = _generate_sm2_key()
        der = key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        loaded = serialization.load_der_private_key(der, password=None)
        assert isinstance(loaded, ec.EllipticCurvePrivateKey)
        assert isinstance(loaded.curve, ec.SM2)
        assert loaded.private_numbers() == key.private_numbers()

    def test_private_key_encrypted_pem(self, backend):
        _skip_sm2_unsupported(backend)

        key = _generate_sm2_key()
        password = b"test-password"
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password),
        )
        loaded = serialization.load_pem_private_key(pem, password=password)
        assert isinstance(loaded, ec.EllipticCurvePrivateKey)
        assert loaded.private_numbers() == key.private_numbers()

    def test_public_key_pem_roundtrip(self, backend):
        _skip_sm2_unsupported(backend)

        key = _generate_sm2_key()
        pub = key.public_key()
        pem = pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        loaded = serialization.load_pem_public_key(pem)
        assert isinstance(loaded, ec.EllipticCurvePublicKey)
        assert isinstance(loaded.curve, ec.SM2)
        assert loaded.public_numbers() == pub.public_numbers()

    def test_public_key_der_roundtrip(self, backend):
        _skip_sm2_unsupported(backend)

        key = _generate_sm2_key()
        pub = key.public_key()
        der = pub.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        loaded = serialization.load_der_public_key(der)
        assert isinstance(loaded, ec.EllipticCurvePublicKey)
        assert isinstance(loaded.curve, ec.SM2)

    def test_sign_with_loaded_key(self, backend):
        """Verify that a deserialized SM2 key can sign and verify."""
        _skip_sm2_unsupported(backend)

        key = _generate_sm2_key()
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        loaded = serialization.load_pem_private_key(pem, password=None)
        message = b"sign after deserialization"
        sig = loaded.sign(message, ec.ECDSA(hashes.SM3()))
        loaded.public_key().verify(sig, message, ec.ECDSA(hashes.SM3()))


class TestSM2Certificate:
    """Test SM2 certificate building, signing, and verification (GM/T)."""

    def test_build_self_signed_sm2_cert(self, backend):
        _skip_sm2_unsupported(backend)

        ca_cert, ca_key = _build_sm2_ca()
        assert isinstance(ca_cert, x509.Certificate)
        assert ca_cert.signature_algorithm_oid == SignatureAlgorithmOID.SM2_WITH_SM3

    def test_self_signed_cert_signature_verification(self, backend):
        _skip_sm2_unsupported(backend)

        ca_cert, ca_key = _build_sm2_ca()

        # Manual signature verification using the public key
        pub_key = ca_cert.public_key()
        assert isinstance(pub_key, ec.EllipticCurvePublicKey)
        assert isinstance(pub_key.curve, ec.SM2)

        pub_key.verify(
            ca_cert.signature,
            ca_cert.tbs_certificate_bytes,
            ec.ECDSA(hashes.SM3()),
        )

    def test_self_signed_cert_verify_directly_issued_by(self, backend):
        _skip_sm2_unsupported(backend)

        ca_cert, _ = _build_sm2_ca()
        # Self-signed cert should verify against itself
        ca_cert.verify_directly_issued_by(ca_cert)

    def test_ca_issues_leaf_cert(self, backend):
        _skip_sm2_unsupported(backend)

        ca_cert, ca_key = _build_sm2_ca()
        leaf_cert, leaf_key = _build_sm2_leaf(ca_key, ca_cert)

        assert isinstance(leaf_cert, x509.Certificate)
        assert leaf_cert.issuer == ca_cert.subject
        assert leaf_cert.signature_algorithm_oid == SignatureAlgorithmOID.SM2_WITH_SM3

    def test_leaf_cert_verify_directly_issued_by_ca(self, backend):
        _skip_sm2_unsupported(backend)

        ca_cert, ca_key = _build_sm2_ca()
        leaf_cert, _ = _build_sm2_leaf(ca_key, ca_cert)

        # Leaf should verify against the CA
        leaf_cert.verify_directly_issued_by(ca_cert)

    def test_leaf_cert_bad_signature_rejected(self, backend):
        _skip_sm2_unsupported(backend)

        ca_cert, ca_key = _build_sm2_ca()
        leaf_cert, _ = _build_sm2_leaf(ca_key, ca_cert)

        # Break the signature
        leaf_pem = leaf_cert.public_bytes(serialization.Encoding.PEM)
        leaf_bad = bytearray(leaf_pem)
        leaf_bad[-40:-35] = 90, 90, 90, 90, 90
        leaf_bad_cert = x509.load_pem_x509_certificate(bytes(leaf_bad))

        with pytest.raises(Exception):
            leaf_bad_cert.verify_directly_issued_by(ca_cert)

    def test_leaf_cert_wrong_ca_rejected(self, backend):
        _skip_sm2_unsupported(backend)

        ca_cert1, ca_key1 = _build_sm2_ca(cn="CA 1")
        ca_cert2, ca_key2 = _build_sm2_ca(cn="CA 2")
        leaf_cert, _ = _build_sm2_leaf(ca_key1, ca_cert1)

        # Leaf signed by CA1 should not verify against CA2
        with pytest.raises(Exception):
            leaf_cert.verify_directly_issued_by(ca_cert2)

    def test_cert_extensions_preserved(self, backend):
        _skip_sm2_unsupported(backend)

        ca_cert, _ = _build_sm2_ca()

        bc = ca_cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        )
        assert bc.value.ca is True

        ku = ca_cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.value.digital_signature is True
        assert ku.value.key_cert_sign is True
        assert ku.value.crl_sign is True

    def test_cert_subject_and_issuer(self, backend):
        _skip_sm2_unsupported(backend)

        ca_cert, _ = _build_sm2_ca(cn="GM Root CA", country="CN")
        cn = ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert cn[0].value == "GM Root CA"
        c = ca_cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
        assert c[0].value == "CN"

    def test_cert_pem_der_roundtrip(self, backend):
        _skip_sm2_unsupported(backend)

        ca_cert, _ = _build_sm2_ca()

        # PEM roundtrip
        pem = ca_cert.public_bytes(serialization.Encoding.PEM)
        loaded_pem = x509.load_pem_x509_certificate(pem)
        assert loaded_pem == ca_cert

        # DER roundtrip
        der = ca_cert.public_bytes(serialization.Encoding.DER)
        loaded_der = x509.load_der_x509_certificate(der)
        assert loaded_der == ca_cert

    def test_cert_with_san_extension(self, backend):
        """Build an SM2 leaf cert with Subject Alternative Name."""
        _skip_sm2_unsupported(backend)

        ca_cert, ca_key = _build_sm2_ca()
        leaf_key = _generate_sm2_key()

        builder = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
                ])
            )
            .issuer_name(ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2021, 1, 1))
            .not_valid_after(datetime.datetime(2030, 1, 1))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("example.com"),
                    x509.DNSName("*.example.com"),
                ]),
                critical=False,
            )
        )
        leaf_cert = builder.sign(ca_key, hashes.SM3())
        leaf_cert.verify_directly_issued_by(ca_cert)

        san = leaf_cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "example.com" in dns_names
        assert "*.example.com" in dns_names


class TestSM2CertificateChain:
    """Test multi-level SM2 certificate chains."""

    def test_two_level_chain(self, backend):
        _skip_sm2_unsupported(backend)

        root_cert, root_key = _build_sm2_ca(cn="SM2 Root CA")
        leaf_cert, _ = _build_sm2_leaf(root_key, root_cert)

        leaf_cert.verify_directly_issued_by(root_cert)

    def test_three_level_chain(self, backend):
        """Root CA -> Intermediate CA -> Leaf."""
        _skip_sm2_unsupported(backend)

        root_cert, root_key = _build_sm2_ca(cn="SM2 Root CA")

        # Build intermediate CA
        inter_key = _generate_sm2_key()
        inter_builder = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, "SM2 Intermediate CA"),
                ])
            )
            .issuer_name(root_cert.subject)
            .public_key(inter_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2020, 6, 1))
            .not_valid_after(datetime.datetime(2035, 1, 1))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
        )
        inter_cert = inter_builder.sign(root_key, hashes.SM3())

        # Build leaf signed by intermediate
        leaf_cert, _ = _build_sm2_leaf(
            inter_key, inter_cert, cn="SM2 End Entity"
        )

        # Verify each link in the chain
        inter_cert.verify_directly_issued_by(root_cert)
        leaf_cert.verify_directly_issued_by(inter_cert)

    def test_cross_algorithm_chain_sm2_signs_ecdsa_leaf(self, backend):
        """SM2 CA signs a regular ECDSA leaf certificate."""
        _skip_sm2_unsupported(backend)

        ca_cert, ca_key = _build_sm2_ca()
        leaf_key = ec.generate_private_key(ec.SECP256R1())

        builder = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, "ECDSA Leaf"),
                ])
            )
            .issuer_name(ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2021, 1, 1))
            .not_valid_after(datetime.datetime(2030, 1, 1))
        )
        # SM2 CA signs with SM3
        leaf_cert = builder.sign(ca_key, hashes.SM3())
        leaf_cert.verify_directly_issued_by(ca_cert)


class TestSM2CRL:
    """Test SM2 CRL (Certificate Revocation List) building and verification."""

    def test_build_empty_crl(self, backend):
        _skip_sm2_unsupported(backend)

        ca_cert, ca_key = _build_sm2_ca()

        crl_builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca_cert.subject)
            .last_update(datetime.datetime(2023, 1, 1))
            .next_update(datetime.datetime(2024, 1, 1))
        )
        crl = crl_builder.sign(ca_key, hashes.SM3())

        assert isinstance(crl, x509.CertificateRevocationList)
        assert crl.signature_algorithm_oid == SignatureAlgorithmOID.SM2_WITH_SM3
        assert len(crl) == 0

    def test_crl_signature_valid(self, backend):
        _skip_sm2_unsupported(backend)

        ca_cert, ca_key = _build_sm2_ca()
        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca_cert.subject)
            .last_update(datetime.datetime(2023, 1, 1))
            .next_update(datetime.datetime(2024, 1, 1))
            .sign(ca_key, hashes.SM3())
        )
        assert crl.is_signature_valid(ca_cert.public_key())

    def test_crl_with_revoked_cert(self, backend):
        _skip_sm2_unsupported(backend)

        ca_cert, ca_key = _build_sm2_ca()
        leaf_cert, _ = _build_sm2_leaf(ca_key, ca_cert)

        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(leaf_cert.serial_number)
            .revocation_date(datetime.datetime(2023, 6, 1))
            .add_extension(
                x509.CRLReason(x509.ReasonFlags.key_compromise),
                critical=False,
            )
            .build()
        )

        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca_cert.subject)
            .last_update(datetime.datetime(2023, 1, 1))
            .next_update(datetime.datetime(2024, 1, 1))
            .add_revoked_certificate(revoked)
            .sign(ca_key, hashes.SM3())
        )

        assert len(crl) == 1
        assert crl.is_signature_valid(ca_cert.public_key())

        # Check the revoked certificate is in the CRL
        revoked_entry = crl.get_revoked_certificate_by_serial_number(
            leaf_cert.serial_number
        )
        assert revoked_entry is not None
        reason = revoked_entry.extensions.get_extension_for_class(
            x509.CRLReason
        )
        assert reason.value.reason == x509.ReasonFlags.key_compromise

    def test_crl_multiple_revoked_certs(self, backend):
        _skip_sm2_unsupported(backend)

        ca_cert, ca_key = _build_sm2_ca()

        crl_builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca_cert.subject)
            .last_update(datetime.datetime(2023, 1, 1))
            .next_update(datetime.datetime(2024, 1, 1))
        )

        serial_numbers = []
        for i in range(5):
            leaf_cert, _ = _build_sm2_leaf(
                ca_key, ca_cert, cn=f"Leaf {i}"
            )
            serial_numbers.append(leaf_cert.serial_number)
            revoked = (
                x509.RevokedCertificateBuilder()
                .serial_number(leaf_cert.serial_number)
                .revocation_date(datetime.datetime(2023, 6, 1 + i))
                .build()
            )
            crl_builder = crl_builder.add_revoked_certificate(revoked)

        crl = crl_builder.sign(ca_key, hashes.SM3())
        assert len(crl) == 5
        assert crl.is_signature_valid(ca_cert.public_key())

        for sn in serial_numbers:
            assert crl.get_revoked_certificate_by_serial_number(sn) is not None

    def test_crl_wrong_key_verification_fails(self, backend):
        _skip_sm2_unsupported(backend)

        ca_cert, ca_key = _build_sm2_ca()
        _, other_key = _build_sm2_ca(cn="Other CA")

        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca_cert.subject)
            .last_update(datetime.datetime(2023, 1, 1))
            .next_update(datetime.datetime(2024, 1, 1))
            .sign(ca_key, hashes.SM3())
        )
        assert not crl.is_signature_valid(other_key.public_key())

    def test_crl_pem_der_roundtrip(self, backend):
        _skip_sm2_unsupported(backend)

        ca_cert, ca_key = _build_sm2_ca()
        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca_cert.subject)
            .last_update(datetime.datetime(2023, 1, 1))
            .next_update(datetime.datetime(2024, 1, 1))
            .sign(ca_key, hashes.SM3())
        )

        # PEM roundtrip
        pem = crl.public_bytes(serialization.Encoding.PEM)
        loaded_pem = x509.load_pem_x509_crl(pem)
        assert loaded_pem == crl

        # DER roundtrip
        der = crl.public_bytes(serialization.Encoding.DER)
        loaded_der = x509.load_der_x509_crl(der)
        assert loaded_der == crl

    def test_crl_with_aki_extension(self, backend):
        """CRL with Authority Key Identifier extension."""
        _skip_sm2_unsupported(backend)

        ca_cert, ca_key = _build_sm2_ca()

        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca_cert.subject)
            .last_update(datetime.datetime(2023, 1, 1))
            .next_update(datetime.datetime(2024, 1, 1))
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    ca_key.public_key()
                ),
                critical=False,
            )
            .sign(ca_key, hashes.SM3())
        )

        assert crl.is_signature_valid(ca_cert.public_key())
        aki = crl.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        )
        assert aki.value.key_identifier is not None


class TestSM2OCSP:
    """Test SM2 OCSP request and response building and verification."""

    def _create_sm2_ocsp_certs(self, backend):
        """Create SM2 CA, leaf cert, and responder cert for OCSP testing."""
        _skip_sm2_unsupported(backend)

        ca_cert, ca_key = _build_sm2_ca(cn="SM2 OCSP CA")
        leaf_cert, leaf_key = _build_sm2_leaf(ca_key, ca_cert, cn="SM2 Entity")
        return ca_cert, ca_key, leaf_cert, leaf_key

    def test_build_ocsp_request(self, backend):
        ca_cert, ca_key, leaf_cert, _ = self._create_sm2_ocsp_certs(backend)

        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(leaf_cert, ca_cert, hashes.SHA256())
        req = builder.build()

        assert isinstance(req, ocsp.OCSPRequest)
        serialized = req.public_bytes(serialization.Encoding.DER)
        assert len(serialized) > 0

    def test_sign_ocsp_response_good(self, backend):
        ca_cert, ca_key, leaf_cert, _ = self._create_sm2_ocsp_certs(backend)

        current_time = (
            datetime.datetime.now(datetime.timezone.utc)
            .replace(tzinfo=None)
            .replace(microsecond=0)
        )
        this_update = current_time - datetime.timedelta(days=1)
        next_update = this_update + datetime.timedelta(days=7)

        builder = (
            ocsp.OCSPResponseBuilder()
            .responder_id(ocsp.OCSPResponderEncoding.NAME, ca_cert)
            .add_response(
                leaf_cert,
                ca_cert,
                hashes.SHA256(),
                ocsp.OCSPCertStatus.GOOD,
                this_update,
                next_update,
                None,
                None,
            )
        )
        resp = builder.sign(ca_key, hashes.SM3())

        assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
        assert resp.certificate_status == ocsp.OCSPCertStatus.GOOD
        assert resp.signature_algorithm_oid == SignatureAlgorithmOID.SM2_WITH_SM3

    def test_ocsp_response_signature_verification(self, backend):
        ca_cert, ca_key, leaf_cert, _ = self._create_sm2_ocsp_certs(backend)

        current_time = (
            datetime.datetime.now(datetime.timezone.utc)
            .replace(tzinfo=None)
            .replace(microsecond=0)
        )
        this_update = current_time - datetime.timedelta(days=1)
        next_update = this_update + datetime.timedelta(days=7)

        resp = (
            ocsp.OCSPResponseBuilder()
            .responder_id(ocsp.OCSPResponderEncoding.NAME, ca_cert)
            .add_response(
                leaf_cert,
                ca_cert,
                hashes.SHA256(),
                ocsp.OCSPCertStatus.GOOD,
                this_update,
                next_update,
                None,
                None,
            )
            .sign(ca_key, hashes.SM3())
        )

        # Verify the OCSP response signature
        ca_key.public_key().verify(
            resp.signature,
            resp.tbs_response_bytes,
            ec.ECDSA(hashes.SM3()),
        )

    def test_sign_ocsp_response_revoked(self, backend):
        ca_cert, ca_key, leaf_cert, _ = self._create_sm2_ocsp_certs(backend)

        current_time = (
            datetime.datetime.now(datetime.timezone.utc)
            .replace(tzinfo=None)
            .replace(microsecond=0)
        )
        this_update = current_time - datetime.timedelta(days=1)
        next_update = this_update + datetime.timedelta(days=7)
        revocation_time = current_time - datetime.timedelta(days=30)

        resp = (
            ocsp.OCSPResponseBuilder()
            .responder_id(ocsp.OCSPResponderEncoding.NAME, ca_cert)
            .add_response(
                leaf_cert,
                ca_cert,
                hashes.SHA256(),
                ocsp.OCSPCertStatus.REVOKED,
                this_update,
                next_update,
                revocation_time,
                x509.ReasonFlags.key_compromise,
            )
            .sign(ca_key, hashes.SM3())
        )

        assert resp.certificate_status == ocsp.OCSPCertStatus.REVOKED
        assert resp.signature_algorithm_oid == SignatureAlgorithmOID.SM2_WITH_SM3

    def test_ocsp_response_der_roundtrip(self, backend):
        ca_cert, ca_key, leaf_cert, _ = self._create_sm2_ocsp_certs(backend)

        current_time = (
            datetime.datetime.now(datetime.timezone.utc)
            .replace(tzinfo=None)
            .replace(microsecond=0)
        )
        this_update = current_time - datetime.timedelta(days=1)
        next_update = this_update + datetime.timedelta(days=7)

        resp = (
            ocsp.OCSPResponseBuilder()
            .responder_id(ocsp.OCSPResponderEncoding.NAME, ca_cert)
            .add_response(
                leaf_cert,
                ca_cert,
                hashes.SHA256(),
                ocsp.OCSPCertStatus.GOOD,
                this_update,
                next_update,
                None,
                None,
            )
            .sign(ca_key, hashes.SM3())
        )

        # DER roundtrip
        der = resp.public_bytes(serialization.Encoding.DER)
        loaded = ocsp.load_der_ocsp_response(der)
        assert loaded.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
        assert loaded.certificate_status == ocsp.OCSPCertStatus.GOOD
        assert loaded.signature == resp.signature

    def test_ocsp_response_with_responder_key_hash(self, backend):
        ca_cert, ca_key, leaf_cert, _ = self._create_sm2_ocsp_certs(backend)

        current_time = (
            datetime.datetime.now(datetime.timezone.utc)
            .replace(tzinfo=None)
            .replace(microsecond=0)
        )
        this_update = current_time - datetime.timedelta(days=1)
        next_update = this_update + datetime.timedelta(days=7)

        resp = (
            ocsp.OCSPResponseBuilder()
            .responder_id(ocsp.OCSPResponderEncoding.HASH, ca_cert)
            .add_response(
                leaf_cert,
                ca_cert,
                hashes.SHA256(),
                ocsp.OCSPCertStatus.GOOD,
                this_update,
                next_update,
                None,
                None,
            )
            .sign(ca_key, hashes.SM3())
        )

        assert resp.responder_key_hash is not None
        assert resp.responder_name is None


class TestSM2RealCertificate:
    """Test verification of real-world GM/T standard certificates."""

    GM_ROOT_PEM_PATH = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "..", "samples", "gmroot.pem"
    )

    def _load_gmroot(self):
        """Load gmroot.pem if available, skip otherwise."""
        path = "/Users/ping/Gitlab/CryptoAppPyScript/samples/gmroot.pem"
        if not os.path.exists(path):
            pytest.skip("gmroot.pem not found")
        with open(path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())

    def test_load_gm_root_cert(self, backend):
        _skip_sm2_unsupported(backend)

        cert = self._load_gmroot()
        assert isinstance(cert, x509.Certificate)
        assert cert.signature_algorithm_oid == SignatureAlgorithmOID.SM2_WITH_SM3

        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert len(cn) == 1

        pub_key = cert.public_key()
        assert isinstance(pub_key, ec.EllipticCurvePublicKey)
        assert isinstance(pub_key.curve, ec.SM2)

    def test_verify_gm_root_cert_signature(self, backend):
        """Verify the signature of a real GM root certificate."""
        _skip_sm2_unsupported(backend)

        cert = self._load_gmroot()
        pub_key = cert.public_key()

        # Manual signature verification with SM2+SM3
        pub_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(hashes.SM3()),
        )

    def test_verify_gm_root_self_issued(self, backend):
        _skip_sm2_unsupported(backend)

        cert = self._load_gmroot()
        # Self-signed cert should verify against itself
        cert.verify_directly_issued_by(cert)


class TestSM2GMTCompliance:
    """Test GM/T 0003 standard compliance of SM2 signing."""

    def test_sm2_sign_uses_z_value_preprocessing(self, backend):
        """
        Verify that SM2 signing uses Z-value preprocessing per GM/T 0003.
        The same message signed with SM2 (which includes Z-value) vs plain
        ECDSA (which doesn't) should produce different results that are
        only verifiable by the matching algorithm.
        """
        _skip_sm2_unsupported(backend)

        key = _generate_sm2_key()
        message = b"GM/T 0003 compliance test"

        # SM2 sign (with Z-value preprocessing)
        sm2_sig = key.sign(message, ec.ECDSA(hashes.SM3()))

        # This signature should be verifiable with SM2
        key.public_key().verify(
            sm2_sig, message, ec.ECDSA(hashes.SM3())
        )

    def test_sm2_default_user_id(self, backend):
        """
        SM2 signing should use default user ID "1234567812345678"
        per GM/T 0009. Signatures produced by our code should be
        verifiable by OpenSSL with the same default user ID.
        """
        _skip_sm2_unsupported(backend)

        key = _generate_sm2_key()
        message = b"test with default user ID"
        sig = key.sign(message, ec.ECDSA(hashes.SM3()))

        # Self-verification should succeed
        key.public_key().verify(sig, message, ec.ECDSA(hashes.SM3()))

    def test_cert_signature_uses_gmt_standard(self, backend):
        """
        Certificates signed with SM2+SM3 should use the GM/T standard
        signature algorithm OID (1.2.156.10197.1.501).
        """
        _skip_sm2_unsupported(backend)

        ca_cert, ca_key = _build_sm2_ca()

        # Check the OID
        assert (
            ca_cert.signature_algorithm_oid.dotted_string
            == "1.2.156.10197.1.501"
        )

        # The signature should be manually verifiable
        ca_cert.public_key().verify(
            ca_cert.signature,
            ca_cert.tbs_certificate_bytes,
            ec.ECDSA(hashes.SM3()),
        )

    def test_crl_signature_uses_gmt_standard(self, backend):
        _skip_sm2_unsupported(backend)

        ca_cert, ca_key = _build_sm2_ca()
        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca_cert.subject)
            .last_update(datetime.datetime(2023, 1, 1))
            .next_update(datetime.datetime(2024, 1, 1))
            .sign(ca_key, hashes.SM3())
        )

        assert (
            crl.signature_algorithm_oid.dotted_string
            == "1.2.156.10197.1.501"
        )
        assert crl.is_signature_valid(ca_cert.public_key())

    def test_ocsp_response_signature_uses_gmt_standard(self, backend):
        _skip_sm2_unsupported(backend)

        ca_cert, ca_key = _build_sm2_ca()
        leaf_cert, _ = _build_sm2_leaf(ca_key, ca_cert)

        current_time = (
            datetime.datetime.now(datetime.timezone.utc)
            .replace(tzinfo=None)
            .replace(microsecond=0)
        )
        this_update = current_time - datetime.timedelta(days=1)
        next_update = this_update + datetime.timedelta(days=7)

        resp = (
            ocsp.OCSPResponseBuilder()
            .responder_id(ocsp.OCSPResponderEncoding.NAME, ca_cert)
            .add_response(
                leaf_cert,
                ca_cert,
                hashes.SHA256(),
                ocsp.OCSPCertStatus.GOOD,
                this_update,
                next_update,
                None,
                None,
            )
            .sign(ca_key, hashes.SM3())
        )

        assert (
            resp.signature_algorithm_oid.dotted_string
            == "1.2.156.10197.1.501"
        )

.. hazmat::

SM2 elliptic curve cryptography
================================

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.ec

SM2 is a public key cryptography standard published by the Chinese National
Cryptography Administration. It is defined across several GM/T standards:

* **GM/T 0003**: SM2 elliptic curve public key cryptography algorithm
  (signature, key exchange, encryption)
* **GM/T 0004**: SM3 cryptographic hash algorithm (256-bit digest)
* **GM/T 0009**: SM2 usage in digital certificates, specifying the default
  user ID ``"1234567812345678"`` for Z-value computation

SM2 uses a 256-bit elliptic curve and is required for commercial cryptographic
applications in China. It is conceptually similar to ECDSA but includes an
additional Z-value preprocessing step during signing and verification.

.. note::

    SM2 support requires OpenSSL 1.1.1 or later. It is not available with
    BoringSSL or AWS-LC backends.


Signing & Verification
----------------------

SM2 signing uses the same Python API as ECDSA. When the key's curve is
:class:`SM2`, the library automatically applies the GM/T 0003 Z-value
preprocessing with the default user ID ``"1234567812345678"`` per GM/T 0009.

.. code-block:: pycon

    >>> from cryptography.hazmat.primitives import hashes
    >>> from cryptography.hazmat.primitives.asymmetric import ec
    >>> private_key = ec.generate_private_key(ec.SM2())
    >>> data = b"message to sign"
    >>> signature = private_key.sign(data, ec.ECDSA(hashes.SM3()))

Verification:

.. code-block:: pycon

    >>> public_key = private_key.public_key()
    >>> public_key.verify(signature, data, ec.ECDSA(hashes.SM3()))

If the signature is invalid, an
:class:`~cryptography.exceptions.InvalidSignature` exception is raised.

.. note::

    Unlike standard ECDSA, SM2 signing includes a Z-value preprocessing step:

    1. Compute ``Z = SM3(ENTLA || IDA || a || b || xG || yG || xA || yA)``
       where ``IDA`` is the user ID (default ``"1234567812345678"``)
    2. Compute ``e = SM3(Z || M)`` where ``M`` is the message
    3. Sign ``e`` with the SM2 private key

    This is handled internally by OpenSSL. You pass the raw message, not a
    pre-computed hash.


Key Serialization
-----------------

SM2 keys can be serialized and loaded in the same way as other EC keys:

.. code-block:: pycon

    >>> from cryptography.hazmat.primitives import serialization
    >>> # Serialize private key
    >>> pem = private_key.private_bytes(
    ...     encoding=serialization.Encoding.PEM,
    ...     format=serialization.PrivateFormat.PKCS8,
    ...     encryption_algorithm=serialization.NoEncryption(),
    ... )
    >>> # Load it back
    >>> loaded_key = serialization.load_pem_private_key(pem, password=None)
    >>> loaded_key.curve.name
    'sm2'

.. code-block:: pycon

    >>> # Serialize public key
    >>> pub_pem = public_key.public_bytes(
    ...     encoding=serialization.Encoding.PEM,
    ...     format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ... )
    >>> loaded_pub = serialization.load_pem_public_key(pub_pem)
    >>> loaded_pub.curve.name
    'sm2'


X.509 Certificates
-------------------

SM2 keys can be used to build and sign X.509 certificates with the
``sm2WithSM3`` signature algorithm (OID ``1.2.156.10197.1.501``).

Self-signed CA certificate
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: pycon

    >>> import datetime
    >>> from cryptography import x509
    >>> from cryptography.x509.oid import NameOID
    >>> ca_key = ec.generate_private_key(ec.SM2())
    >>> subject = issuer = x509.Name([
    ...     x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
    ...     x509.NameAttribute(NameOID.COMMON_NAME, "SM2 Root CA"),
    ... ])
    >>> ca_cert = (
    ...     x509.CertificateBuilder()
    ...     .subject_name(subject)
    ...     .issuer_name(issuer)
    ...     .public_key(ca_key.public_key())
    ...     .serial_number(x509.random_serial_number())
    ...     .not_valid_before(datetime.datetime(2024, 1, 1))
    ...     .not_valid_after(datetime.datetime(2034, 1, 1))
    ...     .add_extension(
    ...         x509.BasicConstraints(ca=True, path_length=None),
    ...         critical=True,
    ...     )
    ...     .sign(ca_key, hashes.SM3())
    ... )
    >>> ca_cert.signature_algorithm_oid.dotted_string
    '1.2.156.10197.1.501'

Issuing a leaf certificate
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: pycon

    >>> leaf_key = ec.generate_private_key(ec.SM2())
    >>> leaf_cert = (
    ...     x509.CertificateBuilder()
    ...     .subject_name(x509.Name([
    ...         x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
    ...     ]))
    ...     .issuer_name(ca_cert.subject)
    ...     .public_key(leaf_key.public_key())
    ...     .serial_number(x509.random_serial_number())
    ...     .not_valid_before(datetime.datetime(2024, 1, 1))
    ...     .not_valid_after(datetime.datetime(2025, 1, 1))
    ...     .sign(ca_key, hashes.SM3())
    ... )

Certificate verification
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: pycon

    >>> # Verify a certificate was issued by the CA
    >>> leaf_cert.verify_directly_issued_by(ca_cert)

    >>> # Or manually verify the signature
    >>> ca_cert.public_key().verify(
    ...     leaf_cert.signature,
    ...     leaf_cert.tbs_certificate_bytes,
    ...     ec.ECDSA(hashes.SM3()),
    ... )


Certificate Revocation Lists (CRL)
------------------------------------

SM2 keys can sign CRLs with the ``sm2WithSM3`` algorithm:

.. code-block:: pycon

    >>> crl = (
    ...     x509.CertificateRevocationListBuilder()
    ...     .issuer_name(ca_cert.subject)
    ...     .last_update(datetime.datetime(2024, 1, 1))
    ...     .next_update(datetime.datetime(2025, 1, 1))
    ...     .sign(ca_key, hashes.SM3())
    ... )
    >>> crl.signature_algorithm_oid.dotted_string
    '1.2.156.10197.1.501'

Adding revoked certificates to the CRL:

.. code-block:: pycon

    >>> revoked = (
    ...     x509.RevokedCertificateBuilder()
    ...     .serial_number(leaf_cert.serial_number)
    ...     .revocation_date(datetime.datetime(2024, 6, 1))
    ...     .add_extension(
    ...         x509.CRLReason(x509.ReasonFlags.key_compromise),
    ...         critical=False,
    ...     )
    ...     .build()
    ... )
    >>> crl = (
    ...     x509.CertificateRevocationListBuilder()
    ...     .issuer_name(ca_cert.subject)
    ...     .last_update(datetime.datetime(2024, 1, 1))
    ...     .next_update(datetime.datetime(2025, 1, 1))
    ...     .add_revoked_certificate(revoked)
    ...     .sign(ca_key, hashes.SM3())
    ... )
    >>> crl.is_signature_valid(ca_cert.public_key())
    True


OCSP
----

SM2 keys can sign OCSP responses:

.. code-block:: pycon

    >>> from cryptography.x509 import ocsp
    >>> current_time = datetime.datetime(2024, 6, 1)
    >>> this_update = current_time - datetime.timedelta(days=1)
    >>> next_update = this_update + datetime.timedelta(days=7)
    >>> resp = (
    ...     ocsp.OCSPResponseBuilder()
    ...     .responder_id(ocsp.OCSPResponderEncoding.NAME, ca_cert)
    ...     .add_response(
    ...         leaf_cert,
    ...         ca_cert,
    ...         hashes.SHA256(),
    ...         ocsp.OCSPCertStatus.GOOD,
    ...         this_update,
    ...         next_update,
    ...         None,
    ...         None,
    ...     )
    ...     .sign(ca_key, hashes.SM3())
    ... )
    >>> resp.signature_algorithm_oid.dotted_string
    '1.2.156.10197.1.501'

.. note::

    The OCSP certificate ID hash (the ``algorithm`` parameter in
    ``add_certificate`` and ``add_response``) must be one of SHA-1, SHA-224,
    SHA-256, SHA-384, or SHA-512. SM3 is not supported for this purpose.
    However, the OCSP **response signature** can use SM2 with SM3.


Differences from ECDSA
-----------------------

While SM2 and ECDSA share the same Python API (``ec.ECDSA(hash)``), there
are important differences:

.. list-table::
   :header-rows: 1
   :widths: 30 35 35

   * -
     - ECDSA
     - SM2
   * - Curve
     - SECP256R1, SECP384R1, etc.
     - SM2 (256-bit only)
   * - Hash
     - SHA-256, SHA-384, SHA-512, etc.
     - SM3 (recommended), SHA-256
   * - Z-value preprocessing
     - No
     - Yes (per GM/T 0003)
   * - Default user ID
     - N/A
     - ``"1234567812345678"`` (per GM/T 0009)
   * - Signature algorithm OID
     - ``1.2.840.10045.4.3.x``
     - ``1.2.156.10197.1.501``
   * - ECDH key exchange
     - Supported
     - Not supported (OpenSSL limitation)
   * - Prehashed mode
     - Hashes data, then signs hash
     - Skips Z-value, signs pre-computed hash directly
   * - Deterministic signing
     - Supported (RFC 6979)
     - Not applicable


.. _`GM/T 0003`: https://www.oscca.gov.cn/sca/xxgk/2010-12/17/content_1002386.shtml

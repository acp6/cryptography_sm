// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use asn1::SimpleAsn1Readable;
use cryptography_x509::certificate::Certificate;
use cryptography_x509::common::Time;
use cryptography_x509::name::Name;
#[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
use pyo3::prelude::PyAnyMethods;
#[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
use pyo3::types::PyBytesMethods;

#[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
use crate::buf::CffiBuf;
use crate::error::CryptographyResult;
#[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
use crate::types;
#[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
use crate::x509::certificate::Certificate as PyCertificate;

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.test_support")]
struct TestCertificate {
    #[pyo3(get)]
    not_before_tag: u8,
    #[pyo3(get)]
    not_after_tag: u8,
    #[pyo3(get)]
    issuer_value_tags: Vec<u8>,
    #[pyo3(get)]
    subject_value_tags: Vec<u8>,
}

fn parse_name_value_tags(rdns: &Name<'_>) -> Vec<u8> {
    let mut tags = vec![];
    for rdn in rdns.unwrap_read().clone() {
        let mut attributes = rdn.collect::<Vec<_>>();
        assert_eq!(attributes.len(), 1);

        tags.push(attributes.pop().unwrap().value.tag().as_u8().unwrap());
    }
    tags
}

fn time_tag(t: &Time) -> u8 {
    match t {
        Time::UtcTime(_) => asn1::UtcTime::TAG.as_u8().unwrap(),
        Time::GeneralizedTime(_) => asn1::GeneralizedTime::TAG.as_u8().unwrap(),
    }
}

#[pyo3::pyfunction]
fn test_parse_certificate(data: &[u8]) -> CryptographyResult<TestCertificate> {
    let cert = asn1::parse_single::<Certificate<'_>>(data)?;

    Ok(TestCertificate {
        not_before_tag: time_tag(&cert.tbs_cert.validity.not_before),
        not_after_tag: time_tag(&cert.tbs_cert.validity.not_after),
        issuer_value_tags: parse_name_value_tags(&cert.tbs_cert.issuer),
        subject_value_tags: parse_name_value_tags(&cert.tbs_cert.subject),
    })
}

/// Check if a PKCS7 SignedData DER contains any SM2WithSM3 signers.
#[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
fn is_sm2_pkcs7(der_bytes: &[u8]) -> bool {
    let content_info =
        match asn1::parse_single::<cryptography_x509::pkcs7::ContentInfo<'_>>(der_bytes) {
            Ok(ci) => ci,
            Err(_) => return false,
        };
    match content_info.content {
        cryptography_x509::pkcs7::Content::SignedData(sd) => {
            let signed_data = sd.into_inner();
            signed_data.signer_infos.unwrap_read().clone().any(|si| {
                matches!(
                    si.digest_encryption_algorithm.params,
                    cryptography_x509::common::AlgorithmParameters::Sm2WithSm3(..)
                )
            })
        }
        _ => false,
    }
}

/// Custom PKCS7 verification for SM2+SM3, bypassing OpenSSL's PKCS7_verify()
/// which does not correctly handle SM2's Z-value/DistID preprocessing.
#[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
fn sm2_pkcs7_verify(
    py: pyo3::Python<'_>,
    der_bytes: &[u8],
    msg: Option<&CffiBuf<'_>>,
    certs: &[pyo3::Py<PyCertificate>],
) -> CryptographyResult<()> {
    use crate::error::CryptographyError;

    let content_info =
        asn1::parse_single::<cryptography_x509::pkcs7::ContentInfo<'_>>(der_bytes)?;
    let signed_data = match content_info.content {
        cryptography_x509::pkcs7::Content::SignedData(sd) => *sd.into_inner(),
        _ => {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Not a PKCS7 SignedData"),
            ))
        }
    };

    // Get content data: from msg parameter (detached) or from PKCS7 structure
    let embedded_data: &[u8];
    let content_data: &[u8] = if let Some(m) = msg {
        m.as_bytes()
    } else {
        match signed_data.content_info.content {
            cryptography_x509::pkcs7::Content::Data(Some(data)) => {
                embedded_data = data.into_inner();
                embedded_data
            }
            _ => {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyValueError::new_err("No content data in PKCS7"),
                ))
            }
        }
    };

    let msg_digest_oid: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 9, 4);

    for signer_info in signed_data.signer_infos.unwrap_read().clone() {
        // Find the matching certificate by issuer + serial number
        let signer_issuer_der =
            asn1::write_single(&signer_info.issuer_and_serial_number.issuer)?;
        let signer_serial = signer_info.issuer_and_serial_number.serial_number;

        let mut found_cert: Option<&pyo3::Py<PyCertificate>> = None;
        for cert in certs {
            let cert_data = cert.get().raw.borrow_dependent();
            let cert_issuer_der = asn1::write_single(&cert_data.tbs_cert.issuer)?;
            if cert_issuer_der == signer_issuer_der
                && cert_data.tbs_cert.serial == signer_serial
            {
                found_cert = Some(cert);
                break;
            }
        }

        let py_cert = found_cert.ok_or_else(|| {
            CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
                "No matching certificate found for signer",
            ))
        })?;
        let public_key =
            py_cert
                .bind(py)
                .call_method0(pyo3::intern!(py, "public_key"))?;

        let data_to_verify: Vec<u8> =
            if let Some(ref auth_attrs) = signer_info.authenticated_attributes {
                // 1. Verify messageDigest attribute matches hash of content
                let hash_params = &signer_info.digest_algorithm.params;
                let hash_name = crate::x509::ocsp::ALGORITHM_PARAMETERS_TO_HASH
                    .get(hash_params)
                    .ok_or_else(|| {
                        CryptographyError::from(
                            pyo3::exceptions::PyValueError::new_err(
                                "Unknown digest algorithm in signer info",
                            ),
                        )
                    })?;
                let py_hash_alg = types::HASHES_MODULE
                    .get(py)?
                    .getattr(*hash_name)?
                    .call0()?;
                let computed_digest =
                    crate::x509::ocsp::hash_data(py, &py_hash_alg, content_data)?;

                let mut digest_verified = false;
                for attr in auth_attrs.unwrap_read().clone() {
                    if attr.type_id == msg_digest_oid {
                        for value_tlv in attr.values.unwrap_read().clone() {
                            if let Ok(stored_digest) = value_tlv.parse::<&[u8]>() {
                                if stored_digest == computed_digest.as_bytes() {
                                    digest_verified = true;
                                }
                            }
                        }
                    }
                }
                if !digest_verified {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyValueError::new_err(
                            "PKCS7 messageDigest attribute does not match content",
                        ),
                    ));
                }

                // 2. Re-serialize authenticated attributes as SET OF (tag 0x31)
                //    for signature verification. In the PKCS7 DER encoding, authenticated
                //    attributes use IMPLICIT [0] tag (0xA0), but the signature is computed
                //    over the SET OF encoding.
                let attrs: Vec<_> = auth_attrs.unwrap_read().clone().collect();
                asn1::write_single(&asn1::SetOfWriter::new(attrs.as_slice()))?
            } else {
                // No authenticated attributes: signature is over the raw content
                content_data.to_vec()
            };

        // Verify the cryptographic signature
        crate::x509::sign::verify_signature_with_signature_algorithm(
            py,
            public_key,
            &signer_info.digest_encryption_algorithm,
            signer_info.encrypted_digest,
            &data_to_verify,
        )?;
    }

    Ok(())
}

#[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
#[pyo3::pyfunction]
#[pyo3(signature = (encoding, sig, msg, certs, options))]
fn pkcs7_verify(
    py: pyo3::Python<'_>,
    encoding: pyo3::Bound<'_, pyo3::PyAny>,
    sig: &[u8],
    msg: Option<CffiBuf<'_>>,
    certs: Vec<pyo3::Py<PyCertificate>>,
    options: pyo3::Bound<'_, pyo3::types::PyList>,
) -> CryptographyResult<()> {
    // Convert to DER for SM2 detection
    let der_bytes = if encoding.is(&types::ENCODING_DER.get(py)?) {
        sig.to_vec()
    } else if encoding.is(&types::ENCODING_PEM.get(py)?) {
        openssl::pkcs7::Pkcs7::from_pem(sig)?.to_der()?
    } else {
        openssl::pkcs7::Pkcs7::from_smime(sig)?.0.to_der()?
    };

    // If any signer uses SM2, use custom verification path
    if is_sm2_pkcs7(&der_bytes) {
        return sm2_pkcs7_verify(py, &der_bytes, msg.as_ref(), &certs);
    }

    // Non-SM2: use OpenSSL's PKCS7_verify
    let p7 = if encoding.is(&types::ENCODING_DER.get(py)?) {
        openssl::pkcs7::Pkcs7::from_der(sig)?
    } else if encoding.is(&types::ENCODING_PEM.get(py)?) {
        openssl::pkcs7::Pkcs7::from_pem(sig)?
    } else {
        openssl::pkcs7::Pkcs7::from_smime(sig)?.0
    };

    let mut flags = openssl::pkcs7::Pkcs7Flags::empty();
    if options.contains(types::PKCS7_TEXT.get(py)?)? {
        flags |= openssl::pkcs7::Pkcs7Flags::TEXT;
    }

    let store = {
        let mut b = openssl::x509::store::X509StoreBuilder::new()?;
        for cert in &certs {
            let der = asn1::write_single(cert.get().raw.borrow_dependent())?;
            b.add_cert(openssl::x509::X509::from_der(&der)?)?;
        }
        b.build()
    };
    let certs = openssl::stack::Stack::new()?;

    p7.verify(
        &certs,
        &store,
        msg.as_ref().map(|m| m.as_bytes()),
        None,
        flags,
    )?;

    Ok(())
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod test_support {
    #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
    #[pymodule_export]
    use super::pkcs7_verify;
    #[pymodule_export]
    use super::test_parse_certificate;
}

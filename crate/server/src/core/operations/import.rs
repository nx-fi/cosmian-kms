use std::collections::HashSet;

use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
    kmip_objects::{Object, ObjectType},
    kmip_operations::{Import, ImportResponse},
    kmip_types::{
        Attributes, CertificateType, CryptographicAlgorithm, CryptographicDomainParameters,
        CryptographicUsageMask, KeyFormatType, KeyWrapType, Link, LinkType, LinkedObjectIdentifier,
        RecommendedCurve, StateEnumeration,
    },
};
use cosmian_kms_utils::{
    access::ExtraDatabaseParams,
    crypto::curve_25519::operation::Q_LENGTH_BITS,
    tagging::{check_user_tags, get_tags},
};
use openssl::{
    ec::{EcKey, PointConversionForm},
    nid::Nid,
    pkey::{Id, PKey, Private},
    sha::Sha1,
};
use tracing::{debug, trace, warn};
use x509_parser::{num_bigint::BigUint, parse_x509_certificate, prelude::parse_x509_pem};

use super::wrapping::unwrap_key;
use crate::{
    core::{
        certificate::{
            locate::locate_certificate_by_spki,
            parsing::{get_certificate_subject_key_identifier, get_common_name},
        },
        KMS,
    },
    error::KmsError,
    kms_bail,
    result::KResult,
};

fn parse_certificate_and_create_tags(
    tags: &mut HashSet<String>,
    certificate_value: &[u8],
) -> KResult<()> {
    debug!("Import with _cert system tag");
    tags.insert("_cert".to_string());

    let (_, pem) = parse_x509_pem(certificate_value)?;
    let (_, x509) = parse_x509_certificate(&pem.contents)?;

    if !x509.validity().is_valid() {
        return Err(KmsError::Certificate(format!(
            "Cannot import expired certificate. Certificate details: {x509:?}"
        )))
    }
    debug!("Certificate is not expired: {:?}", x509.validity());

    let cert_spki = get_certificate_subject_key_identifier(&x509)?;
    if let Some(spki) = cert_spki {
        let spki_tag = format!("_cert_spki={spki}");
        debug!("Add spki system tag: {spki_tag}");
        tags.insert(spki_tag);
    }
    if x509.is_ca() {
        let subject_common_name = get_common_name(&x509.subject)?;
        let ca_tag = format!("_cert_ca={subject_common_name}");
        debug!("Add CA system tag: {}", &ca_tag);
        tags.insert(ca_tag);
    }
    Ok(())
}

fn get_private_key_object(
    private_key_bytes: Vec<u8>,
    recommended_curve: RecommendedCurve,
    links: Option<Vec<Link>>,
) -> Object {
    Object::PrivateKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::TransparentECPrivateKey,
            key_value: KeyValue {
                key_material: KeyMaterial::TransparentECPrivateKey {
                    recommended_curve,
                    d: BigUint::from_bytes_be(&private_key_bytes),
                },
                attributes: Some(Attributes {
                    activation_date: None,
                    cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
                    cryptographic_length: Some(Q_LENGTH_BITS),
                    cryptographic_domain_parameters: Some(CryptographicDomainParameters {
                        q_length: Some(Q_LENGTH_BITS),
                        recommended_curve: Some(recommended_curve),
                    }),
                    cryptographic_parameters: None,
                    cryptographic_usage_mask: Some(
                        CryptographicUsageMask::Encrypt
                            | CryptographicUsageMask::Decrypt
                            | CryptographicUsageMask::WrapKey
                            | CryptographicUsageMask::UnwrapKey
                            | CryptographicUsageMask::KeyAgreement,
                    ),
                    key_format_type: Some(KeyFormatType::ECPrivateKey),
                    link: links,
                    object_type: Some(ObjectType::PrivateKey),
                    vendor_attributes: None,
                }),
            },
            cryptographic_algorithm: CryptographicAlgorithm::ECDH,
            cryptographic_length: Q_LENGTH_BITS,
            key_compression_type: None,
            key_wrapping_data: None,
        },
    }
}

fn create_ec_spki_tag(tags: &mut HashSet<String>, private_key: &EcKey<Private>) -> KResult<String> {
    debug!("create_spki_tag: entering");
    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    let group = private_key.group();
    let public_key_bytes =
        private_key
            .public_key()
            .to_bytes(group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;

    create_spki_tag(tags, &public_key_bytes)
}

fn create_spki_tag(tags: &mut HashSet<String>, public_key_bytes: &[u8]) -> KResult<String> {
    // Compute SPKI as described in <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2>: implementing first method
    debug!(
        "create_spki_tag: public_key_bytes:{}",
        hex::encode(public_key_bytes)
    );
    let mut sha1 = Sha1::default();
    sha1.update(public_key_bytes);
    let spki = hex::encode(sha1.finish());
    let spki_tag = format!("_cert_spki={spki}");

    debug!("create_spki_tag: add spki system tag: {spki_tag}");
    tags.insert(spki_tag);
    Ok(spki)
}

async fn create_certificate_link(
    spki: &str,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> Option<Vec<Link>> {
    match locate_certificate_by_spki(spki, kms, owner, params).await {
        Ok(certificate_id) => {
            debug!("import_pem: add Link with certificate_id: {certificate_id:?}");
            let link = Link {
                link_type: LinkType::CertificateLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(certificate_id),
            };
            Some(vec![link])
        }
        Err(e) => {
            warn!("No certificate found matching the private key SPKI: {spki:?}. Error: {e:?}");
            // continue
            None
        }
    }
}

async fn import_pem(
    tags: &mut HashSet<String>,
    pem_value: &[u8],
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Object> {
    let (_, pem) = parse_x509_pem(pem_value)?;

    let object = if pem.label == "CERTIFICATE" {
        debug!("import_pem: parsing certificate: {}", pem.label);
        parse_certificate_and_create_tags(tags, pem_value)?;
        Object::Certificate {
            certificate_type: CertificateType::X509,
            certificate_value: pem_value.to_vec(),
        }
    } else if pem.label.contains("PRIVATE KEY") {
        debug!("import_pem: parsing private key: {}", pem.label);
        let pkey = PKey::private_key_from_pem(pem_value)?;
        match pkey.id() {
            Id::EC => {
                debug!("import_pem: parsing private key with PKey: {:?}", pkey);
                let private_key = EcKey::private_key_from_der(&pem.contents)?;
                debug!("import_pem: convert private key to EcKey");

                // Create tag from public key sha1 digest
                let spki = create_ec_spki_tag(tags, &private_key)?;
                let links = create_certificate_link(&spki, kms, owner, params).await;

                let recommended_curve = match private_key.group().curve_name() {
                    Some(nid) => match nid {
                        Nid::X9_62_PRIME192V1 => RecommendedCurve::P192,
                        Nid::SECP224R1 => RecommendedCurve::P224,
                        Nid::X9_62_PRIME256V1 => RecommendedCurve::P256,
                        Nid::SECP384R1 => RecommendedCurve::P384,
                        _ => {
                            kms_bail!("Elliptic curve not supported: {}", nid.long_name()?);
                        }
                    },
                    None => kms_bail!("No curve name for this EC curve"),
                };
                let private_key_bytes = private_key.private_key().to_vec();
                debug!(
                    "import_pem: private_key_bytes len: {}",
                    private_key_bytes.len()
                );
                get_private_key_object(private_key_bytes, recommended_curve, links)
            }
            Id::ED25519 => {
                let spki = create_spki_tag(tags, &pkey.raw_public_key()?)?;
                let links = create_certificate_link(&spki, kms, owner, params).await;
                let private_key_bytes = pkey.raw_private_key()?;
                get_private_key_object(private_key_bytes, RecommendedCurve::CURVEED25519, links)
            }
            Id::X25519 => {
                let spki = create_spki_tag(tags, &pkey.raw_public_key()?)?;
                let links = create_certificate_link(&spki, kms, owner, params).await;
                let private_key_bytes = pkey.raw_private_key()?;
                get_private_key_object(private_key_bytes, RecommendedCurve::CURVE25519, links)
            }
            _ => kms_bail!("Private key id not supported: {:?}", pkey.id()),
        }
    } else {
        kms_bail!("Unsupported PEM format: found {}", pem.label);
    };

    Ok(object)
}

/// Import a new object
pub async fn import(
    kms: &KMS,
    request: Import,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ImportResponse> {
    trace!("Entering import KMIP operation: {:?}", request);
    // Unique identifiers starting with `[` are reserved for queries on tags
    // see tagging
    // For instance, a request for unique identifier `[tag1]` will
    // attempt to find a valid single object tagged with `tag1`
    if request.unique_identifier.starts_with('[') {
        kms_bail!("Importing objects with unique identifiers starting with `[` is not supported");
    }

    // recover user tags
    let mut tags = get_tags(&request.attributes);
    check_user_tags(&tags)?;

    let object_type = request.object.object_type();
    let object = match object_type {
        ObjectType::SymmetricKey | ObjectType::PublicKey | ObjectType::PrivateKey => {
            let mut object = request.object;
            let object_key_block = object.key_block_mut()?;
            // unwrap before storing if requested
            if request.key_wrap_type == Some(KeyWrapType::NotWrapped) {
                unwrap_key(object_type, object_key_block, kms, owner, params).await?;
            }
            // replace attributes
            object_key_block.key_value = KeyValue {
                key_material: object_key_block.key_value.key_material.clone(),
                attributes: Some(request.attributes),
            };
            // insert the tag corresponding to the object type
            match object_type {
                ObjectType::SymmetricKey => {
                    tags.insert("_kk".to_string());
                }
                ObjectType::PublicKey => {
                    tags.insert("_pk".to_string());
                }
                ObjectType::PrivateKey => {
                    tags.insert("_sk".to_string());
                }
                _ => unreachable!(),
            }
            object
        }
        ObjectType::Certificate => {
            debug!("Import with _cert system tag");
            tags.insert("_cert".to_string());
            let certificate_pem_bytes = match &request.object {
                Object::Certificate {
                    certificate_value, ..
                } => Ok(certificate_value),
                _ => Err(KmsError::Certificate(format!(
                    "Invalid object type {object_type:?} when importing a certificate"
                ))),
            }?;
            import_pem(&mut tags, certificate_pem_bytes, kms, owner, params).await?
        }
        x => {
            return Err(KmsError::InvalidRequest(format!(
                "Import is not yet supported for objects of type : {x}"
            )))
        }
    };

    // check if the object will be replaced if it already exists
    let replace_existing = if let Some(v) = request.replace_existing {
        v
    } else {
        false
    };

    // insert or update the object
    let uid = if replace_existing {
        debug!(
            "Upserting object of type: {}, with uid: {}",
            request.object_type, request.unique_identifier
        );

        kms.db
            .upsert(
                &request.unique_identifier,
                owner,
                &object,
                &tags,
                StateEnumeration::Active,
                params,
            )
            .await?;
        request.unique_identifier
    } else {
        debug!("Inserting object of type: {}", request.object_type);
        let id = if request.unique_identifier.is_empty() {
            None
        } else {
            Some(request.unique_identifier)
        };

        kms.db.create(id, owner, &object, &tags, params).await?
    };
    Ok(ImportResponse {
        unique_identifier: uid,
    })
}

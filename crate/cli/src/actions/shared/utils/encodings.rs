use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
    kmip_objects::{Object, ObjectType},
    kmip_types::{CertificateType, KeyFormatType},
};
use pem::{EncodeConfig, LineEnding};
use zeroize::Zeroizing;

use crate::{cli_bail, error::CliError};

/// Build KMIP Objects from a PEM file.
/// The PEM file can contain multiple objects.
///
/// The PEM content is not verified.
///
/// The vector of objects is ordered child to parent:
///  - In a keypair: the private keys is appended at the end of the vector, the public key is inserted at the beginning.
///  - The certificates chain have the leaf at the beginning and the root at the end
/// (i.e. as they are submitted).
///
/// # Arguments
/// * `bytes` - The PEM file bytes
///
/// # Returns
/// * `Ok(Vec<Object>)` - The KMIP objects
/// * `Err(CliError)` - The error
///
/// # PEM Tags
///
/// | PEM Tag | PKCS Name |
/// |---------|-----------|
/// | RSA PRIVATE KEY | PKCS#1 |
/// | RSA PUBLIC KEY | PKCS#1 |
/// | PRIVATE KEY | PKCS#8 |
/// | PUBLIC KEY | PKCS#8 |
/// | ENCRYPTED PRIVATE KEY | PKCS#8 |
/// | ENCRYPTED PUBLIC KEY | PKCS#8 |
/// | EC PRIVATE KEY | SEC1 |
/// | CERTIFICATE | X.509 |
/// | X509 CRL | X.509 |
/// | NEW CERTIFICATE REQUEST | PKCS#10 |
/// | CERTIFICATE REQUEST | PKCS#10 |
/// | PKCS12 | PKCS#12 |
///
pub(crate) fn objects_from_pem(bytes: &[u8]) -> Result<Vec<Object>, CliError> {
    let mut objects = Vec::<Object>::new();
    let pem_s = pem::parse_many(bytes)?;
    for pem in pem_s {
        match pem.tag() {
            "RSA PRIVATE KEY" => objects.push(Object::PrivateKey {
                key_block: key_block(KeyFormatType::PKCS1, pem.into_contents()),
            }),
            "RSA PUBLIC KEY" => objects.insert(
                0,
                Object::PublicKey {
                    key_block: key_block(KeyFormatType::PKCS1, pem.into_contents()),
                },
            ),
            "PRIVATE KEY" => objects.push(Object::PrivateKey {
                key_block: key_block(KeyFormatType::PKCS8, pem.into_contents()),
            }),
            "PUBLIC KEY" => objects.insert(
                0,
                Object::PublicKey {
                    key_block: key_block(KeyFormatType::PKCS8, pem.into_contents()),
                },
            ),
            "EC PRIVATE KEY" => objects.push(Object::PrivateKey {
                key_block: key_block(KeyFormatType::ECPrivateKey, pem.into_contents()),
            }),
            "EC PUBLIC KEY" => {
                return Err(CliError::KmsClientError(
                    "PEM files with EC PUBLIC KEY are not supported: SEC1 should be reserved for \
                     EC private keys only"
                        .to_string(),
                ))
            }
            "CERTIFICATE" => objects.push(Object::Certificate {
                certificate_type: CertificateType::X509,
                certificate_value: pem.into_contents(),
            }),
            "X509 CRL" => {
                return Err(CliError::KmsClientError(
                    "X509 CRL not supported on this server".to_string(),
                ))
            }
            "NEW CERTIFICATE REQUEST" => {
                return Err(CliError::KmsClientError(
                    "NEW CERTIFICATE REQUEST not supported on this server".to_string(),
                ))
            }
            "CERTIFICATE REQUEST" => {
                return Err(CliError::KmsClientError(
                    "CERTIFICATE REQUEST not supported on this server".to_string(),
                ))
            }
            x => {
                return Err(CliError::KmsClientError(format!(
                    "PEM tag {x} not supported"
                )))
            }
        }
    }
    Ok(objects)
}

fn key_block(key_format_type: KeyFormatType, bytes: Vec<u8>) -> KeyBlock {
    KeyBlock {
        key_format_type,
        key_compression_type: None,
        key_value: KeyValue {
            key_material: KeyMaterial::ByteString(bytes),
            attributes: None,
        },
        // According to the KMIP spec, the cryptographic algorithm is not required
        // as long as it can be recovered from the Key Format Type or the Key Value.
        // Also it should not be specified if the cryptographic length is not specified.
        cryptographic_algorithm: None,
        // See comment above
        cryptographic_length: None,
        key_wrapping_data: None,
    }
}

/// Converts DER bytes to PEM bytes for keys
pub(crate) fn der_to_pem(
    bytes: &[u8],
    key_format_type: KeyFormatType,
    object_type: ObjectType,
) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let pem = match key_format_type {
        KeyFormatType::PKCS1 => {
            let tag = match object_type {
                ObjectType::PrivateKey => "RSA PRIVATE KEY",
                ObjectType::PublicKey => "RSA PUBLIC KEY",
                x => {
                    cli_bail!(
                        "Object type {x:?} not supported for PKCS1. Must be a private key or \
                         public key"
                    )
                }
            };
            pem::Pem::new(tag, bytes)
        }
        KeyFormatType::PKCS8 => {
            let tag = match object_type {
                ObjectType::PrivateKey => "PRIVATE KEY",
                ObjectType::PublicKey => "PUBLIC KEY",
                x => {
                    cli_bail!(
                        "Object type {x:?} not supported for PKCS#8 / SPKI. Must be a private key \
                         (PKCS#8) or public key (SPKI)"
                    )
                }
            };
            pem::Pem::new(tag, bytes)
        }
        KeyFormatType::ECPrivateKey => {
            let tag = match object_type {
                ObjectType::PrivateKey => "EC PRIVATE KEY",
                x => {
                    cli_bail!("Object type {x:?} not supported for SEC1. Must be a private key.")
                }
            };
            pem::Pem::new(tag, bytes)
        }
        _ => {
            cli_bail!("Key format type {key_format_type:?} not supported for PEM conversion")
        }
    };
    Ok(Zeroizing::new(
        pem::encode_config(&pem, EncodeConfig::new().set_line_ending(LineEnding::LF)).into_bytes(),
    ))
}

use cloudproof::reexport::cover_crypt::Covercrypt;
#[cfg(not(feature = "fips"))]
use cosmian_kmip::crypto::elliptic_curves::ecies::ecies_encrypt;
#[cfg(not(feature = "fips"))]
use cosmian_kmip::crypto::rsa::ckm_rsa_pkcs::ckm_rsa_pkcs_encrypt;
use cosmian_kmip::{
    crypto::{
        cover_crypt::encryption::CoverCryptEncryption,
        rsa::{
            ckm_rsa_aes_key_wrap::ckm_rsa_aes_key_wrap,
            ckm_rsa_pkcs_oaep::ckm_rsa_pkcs_oaep_encrypt, default_cryptographic_parameters,
        },
        symmetric::symmetric_ciphers::{encrypt as sym_encrypt, random_nonce, SymCipher},
        EncryptionSystem,
    },
    kmip::{
        extra::BulkData,
        kmip_objects::Object,
        kmip_operations::{Encrypt, EncryptResponse, ErrorReason},
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, CryptographicUsageMask, KeyFormatType,
            PaddingMethod, StateEnumeration, UniqueIdentifier,
        },
        KmipOperation,
    },
    openssl::kmip_public_key_to_openssl,
    KmipError,
};
use cosmian_kms_server_database::{ExtraStoreParams, ObjectWithMetadata};
use openssl::{
    pkey::{Id, PKey, Public},
    x509::X509,
};
use tracing::{debug, trace};
use zeroize::Zeroizing;

use crate::{
    core::{
        to_cryptographic_algorithm,
        uid_utils::{has_prefix, uids_from_unique_identifier},
        KMS,
    },
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

const EMPTY_SLICE: &[u8] = &[];

pub(crate) async fn encrypt(
    kms: &KMS,
    request: Encrypt,
    user: &str,
    params: Option<&ExtraStoreParams>,
) -> KResult<EncryptResponse> {
    trace!("Encrypt: {}", serde_json::to_string(&request)?);

    // we do not (yet) support continuation cases
    let data = request.data.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest("Encrypt: data to encrypt must be provided".to_owned())
    })?;

    // Get the uids from the unique identifier
    let unique_identifier = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?;
    let uids = uids_from_unique_identifier(unique_identifier, kms, params)
        .await
        .context("Encrypt")?;
    debug!("Encrypt: candidate uids: {uids:?}");

    // Determine which uid to select. The decision process is as follows: loop through the uids
    // 1. if the uid has a prefix, try using that
    // 2. if the uid does not have a prefix, fetch the corresponding object and check that
    //   a- the object is active
    //   b- the object is a public Key, a Symmetric Key or a Certificate
    //
    // Permissions check are done AFTER the object is fetched in the default database
    // to avoid calling `database.is_object_owned_by()` and hence a double call to the DB
    // for each uid. This also is based on the high probability that there sill be a single object
    // in the candidate list.

    let mut selected_owm = None;
    for uid in uids {
        if let Some(prefix) = has_prefix(&uid) {
            if !kms.database.is_object_owned_by(&uid, user, params).await? {
                let ops = kms
                    .database
                    .list_user_operations_on_object(&uid, user, false, params)
                    .await?;
                if !ops
                    .iter()
                    .any(|p| [KmipOperation::Encrypt, KmipOperation::Get].contains(p))
                {
                    continue
                }
            }
            debug!("Encrypt: user: {user} is authorized to encrypt using: {uid}");
            return encrypt_using_encryption_oracle(kms, &request, data, &uid, prefix).await;
        }
        let owm = kms
            .database
            .retrieve_object(&uid, params)
            .await?
            .ok_or_else(|| {
                KmsError::InvalidRequest(format!("Encrypt: failed to retrieve key: {uid}"))
            })?;
        if owm.state() != StateEnumeration::Active {
            continue
        }
        //check user permissions - owner can always encrypt
        if owm.owner() != user {
            let ops = kms
                .database
                .list_user_operations_on_object(&uid, user, false, params)
                .await?;
            if !ops
                .iter()
                .any(|p| [KmipOperation::Encrypt, KmipOperation::Get].contains(p))
            {
                continue
            }
        }
        debug!("Encrypt: user: {user} is authorized to encrypt using: {uid}");
        //TODO check why usage masks are not checked for certificates
        if let Object::Certificate { .. } = owm.object() {
            selected_owm = Some(owm);
            break
        }
        if let Object::SymmetricKey { .. } | Object::PublicKey { .. } = owm.object() {
            let attributes = owm.object().attributes().cloned().unwrap_or_default();
            if !attributes.is_usage_authorized_for(CryptographicUsageMask::Encrypt)? {
                continue
            }
            selected_owm = Some(owm);
            break
        }
    }
    let mut owm = selected_owm.ok_or_else(|| {
        KmsError::KmipError(
            ErrorReason::Item_Not_Found,
            format!("Encrypt: no valid key for id: {unique_identifier}"),
        )
    })?;

    // unwrap if wrapped
    match owm.object() {
        Object::Certificate { .. } => {}
        _ => {
            owm.set_object(
                kms.get_unwrapped(owm.id(), owm.object(), user, params)
                    .await?,
            );
        }
    }
    // it may be a bulk encryption request, if not, fallback to single encryption
    match BulkData::deserialize(data) {
        Ok(bulk_data) => {
            // it is a bulk encryption request
            encrypt_bulk(&owm, request, bulk_data)
        }
        Err(_) => {
            // fallback to single encryption
            encrypt_single(&owm, &request)
        }
    }
}

/// Encrypt using an encryption oracle.
/// # Arguments
/// * `kms` - the KMS
/// * `request` - the encrypt request
/// * `data` - the data to encrypt
/// * `uid` - the unique identifier of the key
/// * `prefix` - the prefix of the encryption oracle
/// # Returns
/// * the encrypt response
async fn encrypt_using_encryption_oracle(
    kms: &KMS,
    request: &Encrypt,
    data: &Zeroizing<Vec<u8>>,
    uid: &str,
    prefix: &str,
) -> KResult<EncryptResponse> {
    let lock = kms.encryption_oracles.read().await;
    let encryption_oracle = lock.get(prefix).ok_or_else(|| {
        KmsError::InvalidRequest(format!(
            "Encrypt: unknown encryption oracle prefix: {prefix}"
        ))
    })?;
    let ca = request
        .cryptographic_parameters
        .as_ref()
        .and_then(|cp| to_cryptographic_algorithm(cp).transpose())
        .transpose()?;
    let encrypted_content = encryption_oracle
        .encrypt(
            uid,
            data,
            ca.clone(),
            request.authenticated_encryption_additional_data.as_deref(),
        )
        .await?;
    let ciphertext_len = encrypted_content.ciphertext.len();
    debug!("Encrypted using oracle: algorithm: {ca:?}, ciphertext length: {ciphertext_len}");
    if ciphertext_len < 28 {
        return Err(KmsError::CryptographicError(
            "Encrypt: encryption oracle returned invalid ciphertext".to_owned(),
        ))
    }

    Ok(EncryptResponse {
        unique_identifier: UniqueIdentifier::TextString(uid.to_owned()),
        data: Some(encrypted_content.ciphertext.clone()),
        iv_counter_nonce: encrypted_content.iv,
        correlation_value: request.correlation_value.clone(),
        authenticated_encryption_tag: encrypted_content.tag,
    })
}

/// Encrypt a single plaintext with the key
/// and return the corresponding ciphertext.
/// The key can be a symmetric key, a public key or a certificate.
/// # Arguments
///  * `owm` - the object with metadata of the key
///  * `request` - the encryption request
/// # Returns
/// * the encrypt response
fn encrypt_single(owm: &ObjectWithMetadata, request: &Encrypt) -> KResult<EncryptResponse> {
    match owm.object() {
        Object::SymmetricKey { .. } => encrypt_with_symmetric_key(request, owm),
        Object::PublicKey { .. } => encrypt_with_public_key(request, owm),
        Object::Certificate {
            certificate_value, ..
        } => encrypt_with_certificate(request, owm.id(), certificate_value),
        other => kms_bail!(KmsError::NotSupported(format!(
            "encrypt: encryption with keys of type: {} is not supported",
            other.object_type()
        ))),
    }
}

/// Encrypt multiple plaintexts with the same key
/// and return the corresponding ciphertexts.
///
/// This is a hack where `request.data` is a serialized `BulkData` object.
/// The `BulkData` object is deserialized and each plaintext is encrypted.
/// The ciphertexts are concatenated and returned as a single `BulkData` object.
/// # Arguments
/// * `owm` - the object with metadata of the key
/// * `request` - the encrypt request
/// * `bulk_data` - the bulk data to encrypt
/// # Returns
/// * the encrypt response
// TODO: Covercrypt already has a bulk encryption method; maybe this should be merged here
pub(crate) fn encrypt_bulk(
    owm: &ObjectWithMetadata,
    mut request: Encrypt,
    bulk_data: BulkData,
) -> KResult<EncryptResponse> {
    debug!(
        "encrypt_bulk: ==> encrypting {} clear texts",
        bulk_data.len()
    );
    let mut ciphertexts = Vec::with_capacity(bulk_data.len());

    match owm.object() {
        Object::SymmetricKey { .. } => {
            let aad = request
                .authenticated_encryption_additional_data
                .as_deref()
                .unwrap_or(EMPTY_SLICE);
            for plaintext in <BulkData as Into<Vec<Zeroizing<Vec<u8>>>>>::into(bulk_data) {
                request.data = Some(plaintext.clone());
                let (key_bytes, cipher) = get_cipher_and_key(&request, owm)?;
                let nonce = request
                    .iv_counter_nonce
                    .clone()
                    .unwrap_or(random_nonce(cipher)?);
                let (ciphertext, tag) = sym_encrypt(cipher, &key_bytes, &nonce, aad, &plaintext)?;
                // concatenate nonce || ciphertext || tag
                let nct = [nonce.as_slice(), ciphertext.as_slice(), tag.as_slice()].concat();
                ciphertexts.push(Zeroizing::new(nct));
            }
        }
        Object::PublicKey { .. } => {
            for plaintext in <BulkData as Into<Vec<Zeroizing<Vec<u8>>>>>::into(bulk_data) {
                request.data = Some(plaintext.clone());
                let response = encrypt_with_public_key(&request, owm)?;
                ciphertexts.push(Zeroizing::new(response.data.unwrap_or_default()));
            }
        }
        Object::Certificate {
            certificate_value, ..
        } => {
            for plaintext in <BulkData as Into<Vec<Zeroizing<Vec<u8>>>>>::into(bulk_data) {
                request.data = Some(plaintext.clone());
                let response = encrypt_with_certificate(&request, owm.id(), certificate_value)?;
                ciphertexts.push(Zeroizing::new(response.data.unwrap_or_default()));
            }
        }
        other => kms_bail!(KmsError::NotSupported(format!(
            "Encrypt bulk: encryption with keys of type: {} is not supported",
            other.object_type()
        ))),
    };

    debug!(
        "encrypt_bulk: <== encrypted {} ciphertexts",
        ciphertexts.len()
    );
    Ok(EncryptResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
        data: Some(BulkData::new(ciphertexts).serialize()?.to_vec()),
        iv_counter_nonce: None,
        correlation_value: request.correlation_value,
        authenticated_encryption_tag: None,
    })
}

fn encrypt_with_symmetric_key(
    request: &Encrypt,
    owm: &ObjectWithMetadata,
) -> KResult<EncryptResponse> {
    let (key_bytes, aead) = get_cipher_and_key(request, owm)?;
    let plaintext = request.data.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest("Encrypt: data to encrypt must be provided".to_owned())
    })?;
    let nonce = request
        .iv_counter_nonce
        .clone()
        .unwrap_or(random_nonce(aead)?);
    let aad = request
        .authenticated_encryption_additional_data
        .as_deref()
        .unwrap_or(EMPTY_SLICE);
    let (ciphertext, tag) = sym_encrypt(aead, &key_bytes, &nonce, aad, plaintext)?;
    Ok(EncryptResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
        data: Some(ciphertext),
        iv_counter_nonce: Some(nonce),
        correlation_value: request.correlation_value.clone(),
        authenticated_encryption_tag: Some(tag),
    })
}

fn get_cipher_and_key(
    request: &Encrypt,
    owm: &ObjectWithMetadata,
) -> KResult<(Zeroizing<Vec<u8>>, SymCipher)> {
    // Make sure that the key used to encrypt can be used to encrypt.
    if !owm
        .object()
        .attributes()?
        .is_usage_authorized_for(CryptographicUsageMask::Encrypt)?
    {
        return Err(KmsError::KmipError(
            ErrorReason::Incompatible_Cryptographic_Usage_Mask,
            "CryptographicUsageMask not authorized for Encrypt".to_owned(),
        ))
    }
    let key_block = owm.object().key_block()?;
    let key_bytes = key_block.key_bytes()?;
    let aead = match key_block.key_format_type {
        KeyFormatType::TransparentSymmetricKey | KeyFormatType::Raw => {
            // recover the cryptographic algorithm from the request or the key block or default to AES
            let cryptographic_algorithm = request
                .cryptographic_parameters
                .as_ref()
                .and_then(|cp| cp.cryptographic_algorithm)
                .unwrap_or_else(|| {
                    key_block
                        .cryptographic_algorithm()
                        .copied()
                        .unwrap_or(CryptographicAlgorithm::AES)
                });
            let block_cipher_mode = request
                .cryptographic_parameters
                .as_ref()
                .and_then(|cp| cp.block_cipher_mode);
            SymCipher::from_algorithm_and_key_size(
                cryptographic_algorithm,
                block_cipher_mode,
                key_bytes.len(),
            )?
        }
        other => {
            return Err(KmsError::NotSupported(format!(
                "symmetric encryption with keys of format: {other}"
            )))
        }
    };
    Ok((key_bytes, aead))
}

fn encrypt_with_public_key(
    request: &Encrypt,
    owm: &ObjectWithMetadata,
) -> KResult<EncryptResponse> {
    // Make sure that the key used to encrypt can be used to encrypt.
    if !owm
        .object()
        .attributes()?
        .is_usage_authorized_for(CryptographicUsageMask::Encrypt)?
    {
        return Err(KmsError::KmipError(
            ErrorReason::Incompatible_Cryptographic_Usage_Mask,
            "CryptographicUsageMask not authorized for Encrypt".to_owned(),
        ))
    }

    let key_block = owm.object().key_block()?;
    match &key_block.key_format_type {
        KeyFormatType::CoverCryptPublicKey => {
            CoverCryptEncryption::instantiate(Covercrypt::default(), owm.id(), owm.object())?
                .encrypt(request)
                .map_err(Into::into)
        }
        KeyFormatType::TransparentECPublicKey
        | KeyFormatType::TransparentRSAPublicKey
        | KeyFormatType::PKCS1
        | KeyFormatType::PKCS8 => {
            let plaintext = request.data.as_ref().ok_or_else(|| {
                KmsError::InvalidRequest("Encrypt: data to encrypt must be provided".to_owned())
            })?;
            trace!(
                "get_encryption_system: matching on key format type: {:?}",
                key_block.key_format_type
            );
            let public_key = kmip_public_key_to_openssl(owm.object())?;
            trace!("get_encryption_system: OpenSSL Public Key instantiated before encryption");
            encrypt_with_pkey(request, owm.id(), plaintext, &public_key)
        }
        other => Err(KmsError::NotSupported(format!(
            "encryption with public keys of format: {other}"
        ))),
    }
}

fn encrypt_with_pkey(
    request: &Encrypt,
    key_id: &str,
    plaintext: &[u8],
    public_key: &PKey<Public>,
) -> KResult<EncryptResponse> {
    let ciphertext = match public_key.id() {
        Id::RSA => encrypt_with_rsa(
            public_key,
            request.cryptographic_parameters.as_ref(),
            plaintext,
        )?,
        #[cfg(not(feature = "fips"))]
        Id::EC | Id::X25519 | Id::ED25519 => ecies_encrypt(public_key, plaintext)?,
        other => {
            kms_bail!("Encrypt: public key type not supported: {other:?}")
        }
    };
    Ok(EncryptResponse {
        unique_identifier: UniqueIdentifier::TextString(key_id.to_owned()),
        data: Some(ciphertext),
        iv_counter_nonce: None,
        correlation_value: request.correlation_value.clone(),
        authenticated_encryption_tag: None,
    })
}

fn encrypt_with_rsa(
    public_key: &PKey<Public>,
    cryptographic_parameters: Option<&CryptographicParameters>,
    plaintext: &[u8],
) -> KResult<Vec<u8>> {
    let (algorithm, padding, hashing_fn) =
        default_cryptographic_parameters(cryptographic_parameters);
    debug!("encrypt_with_rsa: encrypting with RSA {algorithm:?} {padding:?} {hashing_fn:?}");

    let ciphertext = match algorithm {
        CryptographicAlgorithm::AES => match padding {
            PaddingMethod::OAEP => ckm_rsa_aes_key_wrap(public_key, hashing_fn, plaintext)?,
            _ => kms_bail!(
                "Unable to encrypt with RSA AES KEY WRAP: padding method not supported: \
                 {padding:?}"
            ),
        },
        CryptographicAlgorithm::RSA => match padding {
            PaddingMethod::OAEP => ckm_rsa_pkcs_oaep_encrypt(public_key, hashing_fn, plaintext)?,
            #[cfg(not(feature = "fips"))]
            PaddingMethod::PKCS1v15 => ckm_rsa_pkcs_encrypt(public_key, plaintext)?,
            _ => kms_bail!("Unable to encrypt with RSA: padding method not supported: {padding:?}"),
        },
        x => {
            kms_bail!("Unable to encrypt with RSA: algorithm not supported for encrypting: {x:?}")
        }
    };
    Ok(ciphertext)
}

fn encrypt_with_certificate(
    request: &Encrypt,
    key_id: &str,
    certificate_value: &[u8],
) -> KResult<EncryptResponse> {
    let plaintext = request.data.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest("Encrypt: data to encrypt must be provided".to_owned())
    })?;
    let cert = X509::from_der(certificate_value)
        .map_err(|e| KmipError::ConversionError(format!("invalid X509 DER: {e:?}")))?;
    let public_key = cert.public_key().map_err(|e| {
        KmipError::ConversionError(format!("invalid certificate public key: error: {e:?}"))
    })?;
    encrypt_with_pkey(request, key_id, plaintext, &public_key)
}

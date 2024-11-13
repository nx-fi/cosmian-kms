use cloudproof::reexport::cover_crypt::Covercrypt;
#[cfg(not(feature = "fips"))]
use cosmian_kmip::crypto::elliptic_curves::ecies::ecies_decrypt;
#[cfg(not(feature = "fips"))]
use cosmian_kmip::crypto::rsa::ckm_rsa_pkcs::ckm_rsa_pkcs_decrypt;
use cosmian_kmip::{
    crypto::{
        cover_crypt::{attributes, decryption::CovercryptDecryption},
        rsa::{
            ckm_rsa_aes_key_wrap::ckm_rsa_aes_key_unwrap,
            ckm_rsa_pkcs_oaep::ckm_rsa_pkcs_oaep_key_decrypt, default_cryptographic_parameters,
        },
        symmetric::symmetric_ciphers::{decrypt as sym_decrypt, SymCipher},
        DecryptionSystem,
    },
    kmip::{
        extra::BulkData,
        kmip_objects::{Object, ObjectType},
        kmip_operations::{Decrypt, DecryptResponse, ErrorReason},
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, CryptographicUsageMask, KeyFormatType,
            PaddingMethod, StateEnumeration, UniqueIdentifier,
        },
        KmipOperation,
    },
    openssl::kmip_private_key_to_openssl,
};
use cosmian_kms_server_database::{ExtraStoreParams, ObjectWithMetadata};
use openssl::pkey::{Id, PKey, Private};
use tracing::{debug, trace};
use zeroize::Zeroizing;

use crate::{
    core::KMS,
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

const EMPTY_SLICE: &[u8] = &[];

pub(crate) async fn decrypt(
    kms: &KMS,
    request: Decrypt,
    user: &str,
    params: Option<&ExtraStoreParams>,
) -> KResult<DecryptResponse> {
    trace!("decrypt: {}", serde_json::to_string(&request)?);

    let owm = get_key(kms, &request, user, params).await?;

    // Make sure that the key used to decrypt can be used to decrypt.
    if !owm
        .object()
        .attributes()?
        .is_usage_authorized_for(CryptographicUsageMask::Decrypt)?
    {
        return Err(KmsError::KmipError(
            ErrorReason::Incompatible_Cryptographic_Usage_Mask,
            "CryptographicUsageMask not authorized for Decrypt".to_owned(),
        ))
    }

    match owm.object() {
        Object::SymmetricKey { .. } | Object::PrivateKey { .. } => {
            // we do not (yet) support continuation cases
            let data = request.data.as_ref().ok_or_else(|| {
                KmsError::InvalidRequest("Encrypt: data to encrypt must be provided".to_owned())
            })?;

            // it may be a bulk decryption request, if not, fallback to single decryption
            BulkData::deserialize(data).map_or_else(
                |_| decrypt_single(&owm, &request),
                |bulk_data| decrypt_bulk(&owm, &request, bulk_data),
            )
        }
        other => kms_bail!(KmsError::NotSupported(format!(
            "decrypt: decryption with keys of type: {} is not supported",
            other.object_type()
        ))),
    }
}

async fn get_key(
    kms: &KMS,
    request: &Decrypt,
    user: &str,
    params: Option<&ExtraStoreParams>,
) -> KResult<ObjectWithMetadata> {
    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("Get Key: unique_identifier must be a string")?;
    trace!("get_key: uid_or_tags: {uid_or_tags}");

    for owm in kms
        .database
        .retrieve_objects(uid_or_tags, params)
        .await?
        .values()
    {
        let object_type = owm.object().object_type();
        if !(object_type == ObjectType::SymmetricKey || object_type == ObjectType::PrivateKey) {
            continue
        }
        if owm.state() != StateEnumeration::Active {
            continue
        }

        if object_type == ObjectType::PrivateKey {
            if let Ok(attributes) = owm.object().attributes() {
                // is it a Covercrypt secret key?
                if attributes.key_format_type == Some(KeyFormatType::CoverCryptSecretKey) {
                    // does it have an access policy that allows decryption?
                    if attributes::access_policy_from_attributes(attributes).is_err() {
                        continue
                    }
                }
            }
        }
        // if the user is not the owner, we need to check if the user has the right to decrypt
        // or get the key (in which case it can decrypt on its side)
        if user != owm.owner() {
            let permissions = kms
                .database
                .list_user_operations_on_object(owm.id(), user, false, params)
                .await?;
            if !(permissions.contains(&KmipOperation::Decrypt)
                || permissions.contains(&KmipOperation::Get))
            {
                continue
            }
        }

        // we found a key
        let mut key_wm = owm.to_owned();
        debug!(
            "Decrypt: found key: {} of type: {}",
            key_wm.id(),
            key_wm.object().object_type()
        );
        // if the key is wrapped, we need to unwrap it
        key_wm.set_object(
            kms.get_unwrapped(key_wm.id(), owm.object(), user, params)
                .await
                .with_context(|| format!("The key: {}, cannot be unwrapped.", key_wm.id()))?,
        );
        return Ok(key_wm)
    }

    // there can only be one key
    Err(KmsError::KmipError(
        ErrorReason::Item_Not_Found,
        format!(
            "Get Key: no available key found (must be an active symmetric key or private key) for \
             object identifier {uid_or_tags}"
        ),
    ))
}

fn decrypt_bulk(
    owm: &ObjectWithMetadata,
    request: &Decrypt,
    bulk_data: BulkData,
) -> KResult<DecryptResponse> {
    debug!(
        "decrypt_bulk: ==> decrypting {} ciphertexts",
        bulk_data.len()
    );
    let key_block = owm.object().key_block()?;
    let mut plaintexts = Vec::with_capacity(bulk_data.len());

    match &key_block.key_format_type {
        KeyFormatType::CoverCryptSecretKey => {
            for ciphertext in <BulkData as Into<Vec<Zeroizing<Vec<u8>>>>>::into(bulk_data) {
                let request = Decrypt {
                    data: Some(ciphertext.to_vec()),
                    ..request.clone()
                };
                let response = decrypt_with_covercrypt(owm, &request)?;
                plaintexts.push(response.data.unwrap_or_default());
            }
        }

        KeyFormatType::TransparentECPrivateKey
        | KeyFormatType::TransparentRSAPrivateKey
        | KeyFormatType::PKCS1
        | KeyFormatType::PKCS8 => {
            for ciphertext in <BulkData as Into<Vec<Zeroizing<Vec<u8>>>>>::into(bulk_data) {
                let request = Decrypt {
                    data: Some(ciphertext.to_vec()),
                    ..request.clone()
                };
                let response = decrypt_with_public_key(owm, &request)?;
                plaintexts.push(response.data.unwrap_or_default());
            }
        }

        KeyFormatType::TransparentSymmetricKey | KeyFormatType::Raw => {
            let (key_bytes, sym_cipher) = get_aead_and_key(owm, request)?;
            for nonce_ciphertext_tag in <BulkData as Into<Vec<Zeroizing<Vec<u8>>>>>::into(bulk_data)
            {
                if nonce_ciphertext_tag.len() < sym_cipher.nonce_size() + sym_cipher.tag_size() {
                    return Err(KmsError::InvalidRequest(
                        "Decrypt bulk: invalid nonce/ciphertext/tag length".to_owned(),
                    ))
                }
                let nonce = &nonce_ciphertext_tag[0..sym_cipher.nonce_size()];
                let ciphertext = &nonce_ciphertext_tag
                    [sym_cipher.nonce_size()..nonce_ciphertext_tag.len() - sym_cipher.tag_size()];
                let tag =
                    &nonce_ciphertext_tag[nonce_ciphertext_tag.len() - sym_cipher.tag_size()..];
                let plaintext = sym_decrypt(sym_cipher, &key_bytes, nonce, &[], ciphertext, tag)?;
                plaintexts.push(plaintext);
            }
        }

        other => {
            return Err(KmsError::NotSupported(format!(
                "decryption with keys of format: {other}"
            )))
        }
    };

    debug!(
        "decrypt_bulk: ==> decrypted {} plaintexts",
        plaintexts.len()
    );
    Ok(DecryptResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
        data: Some(BulkData::new(plaintexts).serialize()?),
        correlation_value: request.correlation_value.clone(),
    })
}

fn decrypt_single(owm: &ObjectWithMetadata, request: &Decrypt) -> KResult<DecryptResponse> {
    trace!("decrypt_single");
    let key_block = owm.object().key_block()?;
    match &key_block.key_format_type {
        KeyFormatType::CoverCryptSecretKey => decrypt_with_covercrypt(owm, request),

        KeyFormatType::TransparentECPrivateKey
        | KeyFormatType::TransparentRSAPrivateKey
        | KeyFormatType::PKCS1
        | KeyFormatType::PKCS8 => {
            trace!(
                "dispatch_decrypt: matching on public key format type: {:?}",
                key_block.key_format_type
            );
            decrypt_with_public_key(owm, request)
        }

        KeyFormatType::TransparentSymmetricKey | KeyFormatType::Raw => {
            decrypt_single_with_symmetric_key(owm, request)?
        }

        other => Err(KmsError::NotSupported(format!(
            "decryption with keys of format: {other}"
        ))),
    }
}

fn decrypt_with_covercrypt(
    owm: &ObjectWithMetadata,
    request: &Decrypt,
) -> Result<DecryptResponse, KmsError> {
    trace!("Decrypt with Covercrypt key {}", owm.id());
    CovercryptDecryption::instantiate(Covercrypt::default(), owm.id(), owm.object())?
        .decrypt(request)
        .map_err(Into::into)
}

fn decrypt_single_with_symmetric_key(
    owm: &ObjectWithMetadata,
    request: &Decrypt,
) -> Result<Result<DecryptResponse, KmsError>, KmsError> {
    let ciphertext = request.data.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest(
            "Decrypt single with symmetric key: data to decrypt must be provided".to_owned(),
        )
    })?;
    trace!(
        "Decrypt single with symmetric key: ciphertext size: {:?}",
        ciphertext.len()
    );
    let (key_bytes, aead) = get_aead_and_key(owm, request)?;
    let nonce = request.iv_counter_nonce.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest("Decrypt: the nonce/IV must be provided".to_owned())
    })?;
    let aad = request
        .authenticated_encryption_additional_data
        .as_deref()
        .unwrap_or(EMPTY_SLICE);
    let tag = request
        .authenticated_encryption_tag
        .as_deref()
        .unwrap_or(EMPTY_SLICE);
    let plaintext = sym_decrypt(aead, &key_bytes, nonce, aad, ciphertext, tag)?;
    Ok(Ok(DecryptResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
        data: Some(plaintext),
        correlation_value: request.correlation_value.clone(),
    }))
}

fn get_aead_and_key(
    owm: &ObjectWithMetadata,
    request: &Decrypt,
) -> Result<(Zeroizing<Vec<u8>>, SymCipher), KmsError> {
    let key_block = owm.object().key_block()?;
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
    let key_bytes = key_block.key_bytes()?;
    let aead = SymCipher::from_algorithm_and_key_size(
        cryptographic_algorithm,
        block_cipher_mode,
        key_bytes.len(),
    )?;
    Ok((key_bytes, aead))
}

fn decrypt_with_public_key(
    owm: &ObjectWithMetadata,
    request: &Decrypt,
) -> KResult<DecryptResponse> {
    let ciphertext = request.data.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest("Decrypt: data to decrypt must be provided".to_owned())
    })?;
    let private_key = kmip_private_key_to_openssl(owm.object())?;

    let plaintext = match private_key.id() {
        Id::RSA => decrypt_with_rsa(
            &private_key,
            request.cryptographic_parameters.as_ref(),
            ciphertext,
        )?,
        #[cfg(not(feature = "fips"))]
        Id::EC | Id::X25519 | Id::ED25519 => ecies_decrypt(&private_key, ciphertext)?,
        other => {
            kms_bail!("Decrypt with PKey: private key type not supported: {other:?}")
        }
    };
    Ok(DecryptResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
        data: Some(plaintext),
        correlation_value: request.correlation_value.clone(),
    })
}

fn decrypt_with_rsa(
    private_key: &PKey<Private>,
    cryptographic_parameters: Option<&CryptographicParameters>,
    ciphertext: &[u8],
) -> KResult<Zeroizing<Vec<u8>>> {
    let (algorithm, padding, hashing_fn) =
        default_cryptographic_parameters(cryptographic_parameters);
    trace!(
        "Decrypt with RSA: algorithm: {:?}, padding: {:?}, hashing_fn: {:?}",
        algorithm,
        padding,
        hashing_fn
    );

    Ok(match (algorithm, padding) {
        (CryptographicAlgorithm::AES, PaddingMethod::OAEP) => {
            ckm_rsa_aes_key_unwrap(private_key, hashing_fn, ciphertext)?
        }
        (CryptographicAlgorithm::RSA, PaddingMethod::OAEP) => {
            ckm_rsa_pkcs_oaep_key_decrypt(private_key, hashing_fn, ciphertext)?
        }
        #[cfg(not(feature = "fips"))]
        (CryptographicAlgorithm::RSA, PaddingMethod::PKCS1v15) => {
            ckm_rsa_pkcs_decrypt(private_key, ciphertext)?
        }
        _ => kms_bail!("Decrypt: algorithm or padding method not supported for RSA decryption"),
    })
}

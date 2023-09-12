use cloudproof::reexport::{
    cover_crypt::{CleartextHeader, Covercrypt, EncryptedHeader, UserSecretKey},
    crypto_core::bytes_ser_de::{Deserializer, Serializable},
};
use cosmian_kmip::{
    error::KmipError,
    kmip::{
        kmip_objects::Object,
        kmip_operations::{Decrypt, DecryptResponse, DecryptedData, ErrorReason},
        kmip_types::{CryptographicAlgorithm, CryptographicParameters},
    },
};
use tracing::{debug, trace};

use super::user_key::unwrap_user_decryption_key_object;
use crate::{error::KmipUtilsError, DecryptionSystem};

/// Decrypt a single block of data encrypted using an hybrid encryption mode
/// Cannot be used as a stream decipher
pub struct CovercryptDecryption {
    cover_crypt: Covercrypt,
    user_decryption_key_uid: String,
    user_decryption_key_bytes: Vec<u8>,
}

impl CovercryptDecryption {
    pub fn instantiate(
        cover_crypt: Covercrypt,
        user_decryption_key_uid: &str,
        user_decryption_key: &Object,
    ) -> Result<Self, KmipUtilsError> {
        trace!("CovercryptDecryption::instantiate entering");
        let (user_decryption_key_bytes, _access_policy, _attributes) =
            unwrap_user_decryption_key_object(user_decryption_key)?;

        debug!(
            "Instantiated hybrid CoverCrypt decipher for user decryption key id: \
             {user_decryption_key_uid}"
        );

        Ok(Self {
            cover_crypt,
            user_decryption_key_uid: user_decryption_key_uid.into(),
            user_decryption_key_bytes,
        })
    }

    /// Decrypt a single payload
    fn decrypt(
        &self,
        encrypted_bytes: &[u8],
        aead: Option<&[u8]>,
        user_decryption_key: &UserSecretKey,
    ) -> Result<(CleartextHeader, Vec<u8>), KmipUtilsError> {
        let mut de = Deserializer::new(encrypted_bytes);
        let encrypted_header = EncryptedHeader::read(&mut de).map_err(|e| {
            KmipUtilsError::Kmip(
                ErrorReason::Invalid_Message,
                format!("Bad or corrupted encrypted data: {e}"),
            )
        })?;
        let encrypted_block = de.finalize();

        let header = encrypted_header
            .decrypt(&self.cover_crypt, user_decryption_key, aead)
            .map_err(|e| KmipUtilsError::Kmip(ErrorReason::Invalid_Message, e.to_string()))?;

        let cleartext = self
            .cover_crypt
            .decrypt(&header.symmetric_key, &encrypted_block, aead)
            .map_err(|e| KmipUtilsError::Kmip(ErrorReason::Invalid_Message, e.to_string()))?;

        debug!(
            "Decrypted data with user key {} of len (CT/Enc): {}/{}",
            &self.user_decryption_key_uid,
            cleartext.len(),
            encrypted_bytes.len(),
        );

        Ok((header, cleartext))
    }

    /// Decrypt multiple payloads encoded using LEB128
    ///
    /// A custom protocol is used to serialize these data.
    ///
    /// Bulk encryption / decryption scheme
    ///
    /// ENC request
    /// | nb_chunks (LEB128) | chunk_size (LEB128) | chunk_data (plaintext)
    ///                        <------------- nb_chunks times ------------>
    ///
    /// ENC response
    /// | EH | nb_chunks (LEB128) | chunk_size (LEB128) | chunk_data (encrypted)
    ///                             <------------- nb_chunks times ------------>
    ///
    /// DEC request
    /// | nb_chunks (LEB128) | size(EH + chunk_data) (LEB128) | EH | chunk_data (encrypted)
    ///                                                         <----- chunk with EH ----->
    ///                        <---------------------- nb_chunks times ------------------->
    ///
    /// DEC response
    /// | nb_chunks (LEB128) | chunk_size (LEB128) | chunk_data (plaintext)
    ///                        <------------- nb_chunks times ------------>
    fn bulk_decrypt(
        &self,
        mut encrypted_bytes: &[u8],
        aead: Option<&[u8]>,
        user_decryption_key: &UserSecretKey,
    ) -> Result<(CleartextHeader, Vec<u8>), KmipUtilsError> {
        let mut decrypted_data = Vec::new();

        // number of encrypted chunks
        let nb_chunks = leb128::read::unsigned(&mut encrypted_bytes).map_err(|_| {
            KmipError::KmipError(
                ErrorReason::Invalid_Message,
                "expected a LEB128 encoded number (number of encrypted chunks) at the beginning \
                 of the data to encrypt"
                    .to_string(),
            )
        })? as usize;

        leb128::write::unsigned(&mut decrypted_data, nb_chunks as u64).map_err(|_| {
            KmipError::KmipError(
                ErrorReason::Invalid_Message,
                "Cannot write the number of chunks".to_string(),
            )
        })?;

        let mut cleartext_header = None;

        for _ in 0..nb_chunks {
            let chunk_size = leb128::read::unsigned(&mut encrypted_bytes).map_err(|_| {
                KmipError::KmipError(
                    ErrorReason::Invalid_Message,
                    "Cannot read the chunk size from bulk data".to_string(),
                )
            })? as usize;

            #[allow(clippy::needless_borrow)]
            let chunk_data = (&mut encrypted_bytes).take(..chunk_size).ok_or_else(|| {
                KmipUtilsError::Kmip(
                    ErrorReason::Internal_Server_Error,
                    "unable to get right chunk slice from bulk data".to_string(),
                )
            })?;

            let mut de = Deserializer::new(chunk_data);
            let encrypted_header = EncryptedHeader::read(&mut de).map_err(|e| {
                KmipUtilsError::Kmip(
                    ErrorReason::Invalid_Message,
                    format!("Bad or corrupted bulk encrypted data: {e}"),
                )
            })?;
            let encrypted_block = de.finalize();

            let header = encrypted_header
                .decrypt(&self.cover_crypt, user_decryption_key, aead)
                .map_err(|e| KmipUtilsError::Kmip(ErrorReason::Invalid_Message, e.to_string()))?;

            let mut cleartext = self
                .cover_crypt
                .decrypt(&header.symmetric_key, &encrypted_block, aead)
                .map_err(|e| KmipUtilsError::Kmip(ErrorReason::Invalid_Message, e.to_string()))?;

            // All the headers are the same
            cleartext_header = Some(header);

            debug!(
                "Decrypted bulk data with user key {} of len (CT/Enc): {}/{}",
                self.user_decryption_key_uid,
                cleartext.len(),
                encrypted_block.len(),
            );

            leb128::write::unsigned(&mut decrypted_data, cleartext.len() as u64).map_err(|_| {
                KmipError::KmipError(
                    ErrorReason::Invalid_Message,
                    "Cannot write the size of encrypted block".to_string(),
                )
            })?;
            decrypted_data.append(&mut cleartext);
        }

        let cleartext_header = cleartext_header.ok_or_else(|| {
            KmipUtilsError::Kmip(
                ErrorReason::Internal_Server_Error,
                "unable to recover any header".to_string(),
            )
        })?;

        Ok((cleartext_header, decrypted_data))
    }
}

impl DecryptionSystem for CovercryptDecryption {
    fn decrypt(&self, request: &Decrypt) -> Result<DecryptResponse, KmipUtilsError> {
        let user_decryption_key = UserSecretKey::deserialize(&self.user_decryption_key_bytes)
            .map_err(|e| {
                KmipUtilsError::Kmip(
                    ErrorReason::Codec_Error,
                    format!("cover crypt decipher: failed recovering the user key: {e}"),
                )
            })?;

        let encrypted_bytes = request.data.as_ref().ok_or_else(|| {
            KmipUtilsError::Kmip(
                ErrorReason::Invalid_Message,
                "The decryption request should contain encrypted data".to_string(),
            )
        })?;

        let (header, plaintext) = if let Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCryptBulk),
            ..
        }) = request.cryptographic_parameters
        {
            self.bulk_decrypt(
                encrypted_bytes.as_slice(),
                request.authenticated_encryption_additional_data.as_deref(),
                &user_decryption_key,
            )?
        } else {
            self.decrypt(
                encrypted_bytes.as_slice(),
                request.authenticated_encryption_additional_data.as_deref(),
                &user_decryption_key,
            )?
        };

        let decrypted_data = DecryptedData {
            metadata: header.metadata.unwrap_or_default(),
            plaintext,
        };

        Ok(DecryptResponse {
            unique_identifier: self.user_decryption_key_uid.clone(),
            data: Some(decrypted_data.try_into()?),
            correlation_value: None,
        })
    }
}

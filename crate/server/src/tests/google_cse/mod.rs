use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose, Engine};
use cosmian_kmip::{
    crypto::rsa::rsa_oaep_aes_gcm::rsa_oaep_aes_gcm_encrypt,
    kmip::{
        kmip_objects::Object,
        kmip_operations::{Import, ImportResponse},
        kmip_types::UniqueIdentifier,
        ttlv::{deserializer::from_ttlv, TTLV},
    },
};
use cosmian_kms_client::access::{Access, ObjectOperationType, SuccessResponse};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::{Padding, Rsa},
    sign::{Signer, Verifier},
    x509::X509,
};

use crate::{
    result::{KResult, KResultHelper},
    routes::google_cse::operations::{
        PrivateKeyDecryptRequest, PrivateKeyDecryptResponse, PrivateKeySignRequest,
        PrivateKeySignResponse,
    },
    tests::{google_cse::utils::generate_google_jwt, test_utils},
};

pub mod utils;

/// Read all bytes from a file
pub fn read_bytes_from_file(file: &impl AsRef<Path>) -> KResult<Vec<u8>> {
    let mut buffer = Vec::new();
    File::open(file)
        .with_context(|| format!("could not open the file {}", file.as_ref().display()))?
        .read_to_end(&mut buffer)
        .with_context(|| format!("could not read the file {}", file.as_ref().display()))?;

    Ok(buffer)
}

/// Read an object from KMIP JSON TTLV bytes slice
pub fn read_object_from_json_ttlv_bytes(bytes: &[u8]) -> KResult<Object> {
    // Read the object from the file
    let ttlv = serde_json::from_slice::<TTLV>(bytes)
        .with_context(|| "failed parsing the object from the json file".to_owned())?;
    // Deserialize the object
    let object: Object = from_ttlv(&ttlv)?;
    Ok(object)
}

fn import_google_cse_symmetric_key() -> Import {
    let symmetric_key = read_bytes_from_file(&PathBuf::from(
        "../../documentation/docs/google_cse/17fd53a2-a753-4ec4-800b-ccc68bc70480.demo.key.json",
    ))
    .unwrap();

    let object = read_object_from_json_ttlv_bytes(&symmetric_key).unwrap();

    let request = Import {
        unique_identifier: UniqueIdentifier::TextString("google_cse".to_string()),
        object_type: object.object_type(),
        replace_existing: Some(false),
        key_wrap_type: None,
        attributes: object.attributes().cloned().unwrap_or_default(),
        object,
    };

    tracing::debug!("request: {request:?}");
    request
}

#[tokio::test]
async fn test_ossl_sign_verify() -> KResult<()> {
    // cosmian_logger::log_utils::log_init("debug,cosmian_kms_server=trace");

    let digest =
        general_purpose::STANDARD.decode("9lb4w0UM8hTxaEWSRKbu1sMVxE4KD2Y4m7n7DvFlHW4=")?;
    // The RSA blue private key
    let blue_private_key = read_bytes_from_file(&PathBuf::from(
        "src/routes/google_cse/python/openssl/blue.key",
    ))
    .unwrap();

    let rsa_private_key = Rsa::<Private>::private_key_from_pem(&blue_private_key)?;
    let private_key = PKey::from_rsa(rsa_private_key)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &private_key)?;
    signer.set_rsa_padding(Padding::PKCS1_PSS)?;

    tracing::debug!("padding method: {:?}", signer.rsa_padding());

    signer.update(&digest)?;
    let signature = signer.sign_to_vec()?;

    // The RSA blue public key
    let blue_public_key = read_bytes_from_file(&PathBuf::from(
        "src/routes/google_cse/python/openssl/blue.pem",
    ))
    .unwrap();
    let rsa_public_key = X509::from_pem(&blue_public_key)?;
    let public_key = rsa_public_key.public_key()?;

    // Verify the signature
    let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key)?;
    verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
    verifier.update(&digest)?;

    assert!(verifier.verify(&signature)?);

    Ok(())
}

#[tokio::test]
async fn test_cse_private_key_sign() -> KResult<()> {
    cosmian_logger::log_utils::log_init("debug,cosmian_kms_server=trace");

    let jwt = generate_google_jwt().await;

    let app = test_utils::test_app(Some("http://127.0.0.1/".to_string())).await;

    let import_request = import_google_cse_symmetric_key();
    tracing::debug!("import_request created");

    let response: ImportResponse = test_utils::post(&app, import_request).await?;
    tracing::debug!("import response: {response:?}");

    tracing::debug!("grant post");
    let access = Access {
        unique_identifier: Some(UniqueIdentifier::TextString("google_cse".to_string())),
        user_id: "*".to_string(),
        operation_types: vec![
            ObjectOperationType::Create,
            ObjectOperationType::Destroy,
            ObjectOperationType::Get,
            ObjectOperationType::Encrypt,
            ObjectOperationType::Decrypt,
        ],
    };

    let access_response: SuccessResponse =
        test_utils::post_with_uri(&app, access, "/access/grant").await?;
    tracing::debug!("grant response post: {access_response:?}");

    // The RSA blue private key has been AES256 wrapped with `demo.key.json`
    let wrapped_private_key =
        include_str!("../../../../../documentation/docs/google_cse/blue_wrapped_private_key");
    let digest = "9lb4w0UM8hTxaEWSRKbu1sMVxE4KD2Y4m7n7DvFlHW4=";

    let pksr = PrivateKeySignRequest {
        authentication: jwt.clone(),
        authorization: jwt,
        algorithm: "SHA256withRSA".to_string(),
        digest: digest.to_string(),
        e_key: Some("e_key".to_string()),
        rsa_pss_salt_length: None,
        reason: "Gmail".to_string(),
        wrapped_private_key: wrapped_private_key.to_string(),
    };

    tracing::debug!("private key sign request post");
    let pksr_response: PrivateKeySignResponse =
        test_utils::post_with_uri(&app, pksr, "/google_cse/privatekeysign").await?;
    tracing::debug!("private key sign response post: {pksr_response:?}");

    // The RSA blue private key has been AES256 wrapped with `demo.key.json`
    let blue_public_key = read_bytes_from_file(&PathBuf::from(
        "src/routes/google_cse/python/openssl/blue.pem",
    ))
    .unwrap();

    let rsa_public_key = X509::from_pem(&blue_public_key)?;
    let public_key = rsa_public_key.public_key()?;

    // Verify the data
    let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key)?;

    let signature = general_purpose::STANDARD.decode(pksr_response.signature)?;
    verifier.update(&general_purpose::STANDARD.decode(digest)?)?;
    assert!(verifier.verify(&signature)?);

    Ok(())
}

#[tokio::test]
async fn test_cse_private_key_decrypt() -> KResult<()> {
    // cosmian_logger::log_utils::log_init("debug,cosmian_kms_server=trace");

    let jwt = generate_google_jwt().await;

    let app = test_utils::test_app(Some("http://127.0.0.1/".to_string())).await;

    let path = std::env::current_dir()?;
    println!("The current directory is {}", path.display());

    // The RSA blue private key has been AES256 wrapped with `demo.key.json`
    let blue_public_key = read_bytes_from_file(&PathBuf::from(
        "src/routes/google_cse/python/openssl/blue.pem",
    ))
    .unwrap();

    let rsa_public_key = X509::from_pem(&blue_public_key)?;

    let public_key = rsa_public_key.public_key()?;

    let dek = vec![0_u8; 32];
    let encrypted_data_encryption_key = rsa_oaep_aes_gcm_encrypt(
        &public_key,
        cosmian_kmip::kmip::kmip_types::HashingAlgorithm::SHA256,
        &dek,
        None,
    )?;
    tracing::debug!(
        "rsa_oaep_aes_gcm: dek={dek:?}\nencrypted_dek={encrypted_data_encryption_key:?}"
    );

    let import_request = import_google_cse_symmetric_key();
    tracing::debug!("import_request created");

    let response: ImportResponse = test_utils::post(&app, import_request).await?;
    tracing::debug!("import response: {response:?}");

    tracing::debug!("grant post");
    let access = Access {
        unique_identifier: Some(UniqueIdentifier::TextString("google_cse".to_string())),
        user_id: "*".to_string(),
        operation_types: vec![
            ObjectOperationType::Create,
            ObjectOperationType::Destroy,
            ObjectOperationType::Get,
            ObjectOperationType::Encrypt,
            ObjectOperationType::Decrypt,
        ],
    };

    let access_response: SuccessResponse =
        test_utils::post_with_uri(&app, access, "/access/grant").await?;
    tracing::debug!("grant response post: {access_response:?}");

    // The RSA blue private key has been AES256 wrapped with `demo.key.json`
    let wrapped_private_key =
        include_str!("../../../../../documentation/docs/google_cse/blue_wrapped_private_key");

    let request = PrivateKeyDecryptRequest {
        authentication: jwt.clone(),
        authorization: jwt,
        algorithm: "SHA256withRSA".to_string(),
        encrypted_data_encryption_key: general_purpose::STANDARD
            .encode(encrypted_data_encryption_key),
        rsa_oaep_label: String::new(),
        reason: "Gmail".to_string(),
        wrapped_private_key: wrapped_private_key.to_string(),
    };

    tracing::debug!("private key decrypt request post");
    let response: PrivateKeyDecryptResponse =
        test_utils::post_with_uri(&app, request, "/google_cse/privatekeydecrypt").await?;
    tracing::debug!("private key decrypt response post: {response:?}"); //TODO: remove it

    Ok(())
}
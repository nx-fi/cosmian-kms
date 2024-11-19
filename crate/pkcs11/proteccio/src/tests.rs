//! Tests are ignored by default because they reqauire a connection to a working HSM.
//! To run the tests, cd into the crate directory and run:
//! ```
//! HSM_USER_PASSWORD=password cargo test --target x86_64-unknown-linux-gnu -- tests::test_whatever
//! ```

use std::{
    collections::HashMap,
    ptr,
    sync::{Arc, Once},
    thread,
};

use cosmian_kms_plugins::{HsmObjectFilter, KeyMaterial, KeyType};
use libloading::Library;
use pkcs11_sys::{CKF_OS_LOCKING_OK, CKR_OK, CK_C_INITIALIZE_ARGS, CK_RV, CK_VOID_PTR};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use crate::{
    proteccio::{Proteccio, SlotManager},
    session::{AesKeySize, ProteccioEncryptionAlgorithm, RsaKeySize},
    PError, PResult,
};

static TRACING_INIT: Once = Once::new();
fn initialize_logging() {
    TRACING_INIT.call_once(|| {
        let subscriber = FmtSubscriber::builder()
            .with_max_level(Level::INFO) // Adjust the level as needed
            .with_writer(std::io::stdout)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("Setting default subscriber failed");
    });
}

fn get_hsm_password() -> PResult<String> {
    let user_password = option_env!("HSM_USER_PASSWORD")
        .ok_or_else(|| {
            PError::Default(
                "The user password for the HSM is not set. Please set the HSM_USER_PASSWORD \
                 environment variable"
                    .to_string(),
            )
        })?
        .to_string();
    Ok(user_password)
}

fn get_slot() -> PResult<Arc<SlotManager>> {
    let user_password = get_hsm_password()?;
    let passwords = HashMap::from([(0x04, Some(user_password.clone()))]);
    let hsm = Proteccio::instantiate("/lib/libnethsm64.so", passwords)?;
    let manager = hsm.get_slot(0x04)?;
    Ok(manager)
}

#[cfg(feature = "proteccio")]
#[test]
fn low_level_test() -> PResult<()> {
    let path = "/lib/libnethsm64.so";
    let library = unsafe { Library::new(path) }?;
    let init = unsafe { library.get::<fn(pInitArgs: CK_VOID_PTR) -> CK_RV>(b"C_Initialize") }?;

    let mut pInitArgs = CK_C_INITIALIZE_ARGS {
        CreateMutex: None,
        DestroyMutex: None,
        LockMutex: None,
        UnlockMutex: None,
        flags: CKF_OS_LOCKING_OK,
        pReserved: ptr::null_mut(),
    };
    let rv = init(&mut pInitArgs as *const CK_C_INITIALIZE_ARGS as CK_VOID_PTR);
    assert_eq!(rv, CKR_OK);

    Ok(())
}

#[cfg(feature = "proteccio")]
#[test]
fn test_hsm_get_info() -> PResult<()> {
    initialize_logging();
    let hsm = Proteccio::instantiate("/lib/libnethsm64.so", HashMap::new())?;
    let info = hsm.get_info()?;
    info!("Connected to the HSM: {info}");
    Ok(())
}

#[cfg(feature = "proteccio")]
#[test]
fn test_generate_aes_key() -> PResult<()> {
    initialize_logging();
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    let key_handle = session.generate_aes_key(AesKeySize::Aes256, "label", false)?;
    info!("Generated exportable AES key: {}", key_handle);
    // re-export the key
    let key = session
        .export_key(key_handle)?
        .expect("Failed to find the key");
    let key_bytes = match key.key_material() {
        KeyMaterial::AesKey(v) => v,
        KeyMaterial::RsaPrivateKey(_) | KeyMaterial::RsaPublicKey(_) => {
            panic!("Expected an AES key");
        }
    };
    assert_eq!(key_bytes.len() * 8, 256);
    assert_eq!(key.label(), "label");
    match key.key_material() {
        KeyMaterial::AesKey(v) => {
            assert_eq!(v.len(), 32);
        }
        KeyMaterial::RsaPrivateKey(_) | KeyMaterial::RsaPublicKey(_) => {
            panic!("Expected an AES key");
        }
    }

    // Generate a sensitive AES key
    let key_handle = session.generate_aes_key(AesKeySize::Aes256, "label", true)?;
    info!("Generated non-exportable AES key: {}", key_handle);
    // it should not be exportable
    assert!(session.export_key(key_handle).is_err());
    Ok(())
}

#[cfg(feature = "proteccio")]
#[test]
fn test_generate_rsa_keypair() -> PResult<()> {
    initialize_logging();
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    let (sk, pk) = session.generate_rsa_key_pair(RsaKeySize::Rsa2048, "label", false)?;
    info!("Generated exportable RSA key: sk: {sk}, pk: {pk}");
    // export the private key
    let key = session
        .export_key(sk)?
        .expect("Failed to find the private key");
    assert_eq!(key.label(), "label");
    match key.key_material() {
        KeyMaterial::RsaPrivateKey(v) => {
            assert_eq!(v.modulus.len() * 8, 2048);
        }
        KeyMaterial::RsaPublicKey(_) | KeyMaterial::AesKey(_) => {
            panic!("Expected an RSA private key");
        }
    }
    // export the public key
    let key = session
        .export_key(pk)?
        .expect("Failed to find the public key");
    assert_eq!(key.label(), "label");
    match key.key_material() {
        KeyMaterial::RsaPublicKey(v) => {
            assert_eq!(v.modulus.len() * 8, 2048);
        }
        KeyMaterial::RsaPrivateKey(_) | KeyMaterial::AesKey(_) => {
            panic!("Expected an RSA public key");
        }
    }
    // Generate a sensitive AES key
    let (sk, pk) = session.generate_rsa_key_pair(RsaKeySize::Rsa2048, "label", true)?;
    info!("Generated exportable RSA key: sk: {sk}, pk: {pk}");
    // the private key should not be exportable
    assert!(session.export_key(sk).is_err());
    // the public key should be exportable
    let _key = session.export_key(pk)?;
    Ok(())
}

#[cfg(feature = "proteccio")]
#[test]
fn test_rsa_key_wrap() -> PResult<()> {
    initialize_logging();
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    let symmetric_key = session.generate_aes_key(AesKeySize::Aes256, "label", true)?;
    info!("Symmetric key handle: {symmetric_key}");
    let (sk, pk) = session.generate_rsa_key_pair(RsaKeySize::Rsa2048, "label", true)?;
    info!("RSA handles sk: {sk}, pl: {pk}");
    let encrypted_key = session.wrap_aes_key_with_rsa_oaep(pk, symmetric_key)?;
    assert_eq!(encrypted_key.len(), 2048 / 8);
    let decrypted_key =
        session.unwrap_aes_key_with_rsa_oaep(sk, &encrypted_key, "another_label")?;
    info!("Unwrapped symmetric key handle: {}", decrypted_key);
    Ok(())
}

#[cfg(feature = "proteccio")]
#[test]
fn test_rsa_pkcs_encrypt() -> PResult<()> {
    initialize_logging();
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    let data = b"Hello, World!";
    let (sk, pk) = session.generate_rsa_key_pair(RsaKeySize::Rsa2048, "label", true)?;
    info!("RSA handles sk: {sk}, pl: {pk}");
    let ciphertext = session.encrypt(pk, ProteccioEncryptionAlgorithm::RsaPkcsV15, data)?;
    assert_eq!(ciphertext.len(), 2048 / 8);
    let plaintext = session.decrypt(sk, ProteccioEncryptionAlgorithm::RsaPkcsV15, &ciphertext)?;
    assert_eq!(&plaintext, data);
    Ok(())
}

#[cfg(feature = "proteccio")]
#[test]
fn test_rsa_oaep_encrypt() -> PResult<()> {
    initialize_logging();
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    let data = b"Hello, World!";
    let (sk, pk) = session.generate_rsa_key_pair(RsaKeySize::Rsa2048, "label", true)?;
    info!("RSA handles sk: {sk}, pl: {pk}");
    let ciphertext = session.encrypt(pk, ProteccioEncryptionAlgorithm::RsaOaep, data)?;
    assert_eq!(ciphertext.len(), 2048 / 8);
    let plaintext = session.decrypt(sk, ProteccioEncryptionAlgorithm::RsaOaep, &ciphertext)?;
    assert_eq!(&plaintext, data);
    Ok(())
}

#[cfg(feature = "proteccio")]
#[test]
fn test_aes_gcm_encrypt() -> PResult<()> {
    initialize_logging();
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    let data = b"Hello, World!";
    let sk = session.generate_aes_key(AesKeySize::Aes256, "label", true)?;
    info!("AES key handle: {sk}");
    let ciphertext = session.encrypt(sk, ProteccioEncryptionAlgorithm::AesGcm, data)?;
    assert_eq!(ciphertext.len(), data.len() + 12 + 16);
    let plaintext = session.decrypt(sk, ProteccioEncryptionAlgorithm::AesGcm, &ciphertext)?;
    assert_eq!(&plaintext, data);
    Ok(())
}

#[cfg(feature = "proteccio")]
#[test]
fn multi_threaded_rsa_encrypt_decrypt_test() -> PResult<()> {
    initialize_logging();

    // Initialize the HSM once and share it across threads
    let slot = get_slot()?;

    let mut handles = vec![];
    for _ in 0..4 {
        let slot = slot.clone();
        let handle = thread::spawn(move || {
            let session = slot.open_session(true)?;
            let data = b"Hello, World!";
            let (sk, pk) = session.generate_rsa_key_pair(RsaKeySize::Rsa2048, "label", true)?;
            info!("RSA handles sk: {sk}, pk: {pk}");
            let ciphertext = session.encrypt(pk, ProteccioEncryptionAlgorithm::RsaOaep, data)?;
            assert_eq!(ciphertext.len(), 2048 / 8);
            let plaintext =
                session.decrypt(sk, ProteccioEncryptionAlgorithm::RsaOaep, &ciphertext)?;
            assert_eq!(&plaintext, data);
            Ok::<(), PError>(())
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread panicked")?;
    }

    Ok(())
}

#[cfg(feature = "proteccio")]
#[test]
fn test_list_objects() -> PResult<()> {
    initialize_logging();
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    let objects = session.list_objects(HsmObjectFilter::Any)?;
    for object in objects.iter() {
        session.destroy_object(*object)?;
    }
    let objects = session.list_objects(HsmObjectFilter::Any)?;
    assert_eq!(objects.len(), 0);
    let (_sk, _pk) = session.generate_rsa_key_pair(RsaKeySize::Rsa2048, "label", false)?;
    let objects = session.list_objects(HsmObjectFilter::Any)?;
    assert_eq!(objects.len(), 2);
    let objects = session.list_objects(HsmObjectFilter::RsaKey)?;
    assert_eq!(objects.len(), 2);
    let objects = session.list_objects(HsmObjectFilter::RsaPublicKey)?;
    assert_eq!(objects.len(), 1);
    let objects = session.list_objects(HsmObjectFilter::RsaPrivateKey)?;
    assert_eq!(objects.len(), 1);
    let objects = session.list_objects(HsmObjectFilter::AesKey)?;
    assert_eq!(objects.len(), 0);
    // add another keypair
    let (_sk, _pk) = session.generate_rsa_key_pair(RsaKeySize::Rsa3072, "label", false)?;
    let objects = session.list_objects(HsmObjectFilter::Any)?;
    assert_eq!(objects.len(), 4);
    let objects = session.list_objects(HsmObjectFilter::RsaKey)?;
    assert_eq!(objects.len(), 4);
    let objects = session.list_objects(HsmObjectFilter::RsaPublicKey)?;
    assert_eq!(objects.len(), 2);
    let objects = session.list_objects(HsmObjectFilter::RsaPrivateKey)?;
    assert_eq!(objects.len(), 2);
    let objects = session.list_objects(HsmObjectFilter::AesKey)?;
    assert_eq!(objects.len(), 0);
    // add an AES key
    let _key = session.generate_aes_key(AesKeySize::Aes256, "label", false)?;
    let objects = session.list_objects(HsmObjectFilter::Any)?;
    assert_eq!(objects.len(), 5);
    let objects = session.list_objects(HsmObjectFilter::AesKey)?;
    assert_eq!(objects.len(), 1);
    Ok(())
}

#[cfg(feature = "proteccio")]
#[test]
fn test_get_key_metadata() -> PResult<()> {
    initialize_logging();
    let slot = get_slot()?;
    let session = slot.open_session(true)?;

    // generate an AES key
    let key_handle = session.generate_aes_key(AesKeySize::Aes256, "label", true)?;
    // get the key basics
    let key_type = session
        .get_key_type(key_handle)?
        .ok_or_else(|| PError::Default("Key not found".to_string()))?;
    assert_eq!(key_type, KeyType::AesKey);
    // get the metadata
    let metadata = session
        .get_key_metadata(key_handle)?
        .ok_or_else(|| PError::Default("Key not found".to_string()))?;
    assert_eq!(metadata.key_type, KeyType::AesKey);
    assert!(metadata.sensitive);
    assert_eq!(metadata.key_length_in_bits, 256);
    assert_eq!(metadata.label, Some("label".to_string()));

    // generate an RSA keypair
    let (sk, pk) = session.generate_rsa_key_pair(RsaKeySize::Rsa2048, "label", true)?;

    // get the private key basics
    let key_type = session
        .get_key_type(sk)?
        .ok_or_else(|| PError::Default("Key not found".to_string()))?;
    assert_eq!(key_type, KeyType::RsaPrivateKey);

    // get the private key metadata
    let metadata = session
        .get_key_metadata(sk)?
        .ok_or_else(|| PError::Default("Key not found".to_string()))?;
    assert_eq!(metadata.key_type, KeyType::RsaPrivateKey);
    assert_eq!(metadata.key_length_in_bits, 2048);
    assert!(metadata.sensitive);

    // get the public key basics
    let key_type = session
        .get_key_type(pk)?
        .ok_or_else(|| PError::Default("Key not found".to_string()))?;
    assert_eq!(key_type, KeyType::RsaPublicKey);

    // get the public key metadata
    let metadata = session
        .get_key_metadata(pk)?
        .ok_or_else(|| PError::Default("Key not found".to_string()))?;
    assert_eq!(metadata.key_type, KeyType::RsaPublicKey);
    // assert!(metadata.sensitive);
    assert_eq!(metadata.key_length_in_bits, 2048);
    assert_eq!(metadata.label, Some("label".to_string()));
    Ok(())
}

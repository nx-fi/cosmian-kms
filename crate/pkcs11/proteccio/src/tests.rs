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

use cosmian_hsm_traits::{HsmObjectFilter, KeyMaterial};
use libloading::Library;
use pkcs11_sys::{CKF_OS_LOCKING_OK, CKR_OK, CK_C_INITIALIZE_ARGS, CK_RV, CK_VOID_PTR};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use crate::{
    proteccio::{Proteccio, SlotManager},
    session::{AesKeySize, EncryptionAlgorithm, RsaKeySize},
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
    let hsm = Proteccio::instantiate("/lib/libnethsm.so", passwords)?;
    let manager = hsm.get_slot(0x04)?;
    Ok(manager)
}

#[test]
#[ignore]
fn low_level_test() -> PResult<()> {
    let path = "/lib/libnethsm.so";
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

#[test]
#[ignore]
fn test_hsm_get_info() -> PResult<()> {
    initialize_logging();
    let hsm = Proteccio::instantiate("/lib/libnethsm.so", HashMap::new())?;
    let info = hsm.get_info()?;
    info!("Connected to the HSM: {info}");
    Ok(())
}

#[test]
#[ignore]
fn test_generate_aes_key() -> PResult<()> {
    initialize_logging();
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    let key_handle = session.generate_aes_key(AesKeySize::Aes256, "label", true)?;
    info!("Generated exportable AES key: {}", key_handle);
    // re-export the key
    let key = session.export_key(key_handle)?;
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
    let key_handle = session.generate_aes_key(AesKeySize::Aes256, "label", false)?;
    info!("Generated non-exportable AES key: {}", key_handle);
    // it should not be exportable
    assert!(session.export_key(key_handle).is_err());
    Ok(())
}

#[test]
#[ignore]
fn test_generate_rsa_keypair() -> PResult<()> {
    initialize_logging();
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    let (sk, pk) = session.generate_rsa_key_pair(RsaKeySize::Rsa2048, "label", true)?;
    info!("Generated exportable RSA key: sk: {sk}, pk: {pk}");
    // export the private key
    let key = session.export_key(sk)?;
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
    let key = session.export_key(pk)?;
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
    let (sk, pk) = session.generate_rsa_key_pair(RsaKeySize::Rsa2048, "label", false)?;
    info!("Generated exportable RSA key: sk: {sk}, pk: {pk}");
    // the private key should not be exportable
    assert!(session.export_key(sk).is_err());
    // the public key should be exportable
    let _key = session.export_key(pk)?;
    Ok(())
}

#[test]
#[ignore]
fn test_rsa_key_wrap() -> PResult<()> {
    initialize_logging();
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    let symmetric_key = session.generate_aes_key(AesKeySize::Aes256, "label", false)?;
    info!("Symmetric key handle: {symmetric_key}");
    let (sk, pk) = session.generate_rsa_key_pair(RsaKeySize::Rsa2048, "label", false)?;
    info!("RSA handles sk: {sk}, pl: {pk}");
    let encrypted_key = session.wrap_aes_key_with_rsa_oaep(pk, symmetric_key)?;
    assert_eq!(encrypted_key.len(), 2048 / 8);
    let decrypted_key =
        session.unwrap_aes_key_with_rsa_oaep(sk, &encrypted_key, "another_label")?;
    info!("Unwrapped symmetric key handle: {}", decrypted_key);
    Ok(())
}

#[test]
#[ignore]
fn test_rsa_pkcs_encrypt() -> PResult<()> {
    initialize_logging();
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    let data = b"Hello, World!";
    let (sk, pk) = session.generate_rsa_key_pair(RsaKeySize::Rsa2048, "label", false)?;
    info!("RSA handles sk: {sk}, pl: {pk}");
    let ciphertext = session.encrypt(pk, EncryptionAlgorithm::RsaPkcsv15, data)?;
    assert_eq!(ciphertext.len(), 2048 / 8);
    let plaintext = session.decrypt(sk, EncryptionAlgorithm::RsaPkcsv15, &ciphertext)?;
    assert_eq!(&plaintext, data);
    Ok(())
}

#[test]
#[ignore]
fn test_rsa_oaep_encrypt() -> PResult<()> {
    initialize_logging();
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    let data = b"Hello, World!";
    let (sk, pk) = session.generate_rsa_key_pair(RsaKeySize::Rsa2048, "label", false)?;
    info!("RSA handles sk: {sk}, pl: {pk}");
    let ciphertext = session.encrypt(pk, EncryptionAlgorithm::RsaOaep, data)?;
    assert_eq!(ciphertext.len(), 2048 / 8);
    let plaintext = session.decrypt(sk, EncryptionAlgorithm::RsaOaep, &ciphertext)?;
    assert_eq!(&plaintext, data);
    Ok(())
}

#[test]
#[ignore]
fn test_aes_gcm_encrypt() -> PResult<()> {
    initialize_logging();
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    let data = b"Hello, World!";
    let sk = session.generate_aes_key(AesKeySize::Aes256, "label", false)?;
    info!("AES key handle: {sk}");
    let ciphertext = session.encrypt(sk, EncryptionAlgorithm::AesGcm, data)?;
    assert_eq!(ciphertext.len(), data.len() + 12 + 16);
    let plaintext = session.decrypt(sk, EncryptionAlgorithm::AesGcm, &ciphertext)?;
    assert_eq!(&plaintext, data);
    Ok(())
}

#[test]
#[ignore]
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
            let (sk, pk) = session.generate_rsa_key_pair(RsaKeySize::Rsa2048, "label", false)?;
            info!("RSA handles sk: {sk}, pk: {pk}");
            let ciphertext = session.encrypt(pk, EncryptionAlgorithm::RsaOaep, data)?;
            assert_eq!(ciphertext.len(), 2048 / 8);
            let plaintext = session.decrypt(sk, EncryptionAlgorithm::RsaOaep, &ciphertext)?;
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

#[test]
#[ignore]
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

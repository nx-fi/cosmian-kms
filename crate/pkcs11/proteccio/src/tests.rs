//! Tests are ignored by default because they reqauire a connection to a working HSM.
//! To run the tests, cd into the crate directory and run:
//! ```
//! HSM_USER_PASSWORD=password cargo test --target x86_64-unknown-linux-gnu -- tests::test_whatever
//! ```

use std::{
    ptr,
    sync::{Arc, Once},
    thread,
};

use libloading::Library;
use pkcs11_sys::{CKF_OS_LOCKING_OK, CKR_OK, CK_C_INITIALIZE_ARGS, CK_RV, CK_VOID_PTR};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use crate::{
    hsm::{Hsm, SlotManager},
    session::{AesKeySize, EncryptionAlgorithm, ObjectType, RsaKeySize},
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
    let hsm = Hsm::instantiate("/lib/libnethsm.so")?;
    let manager = hsm.get_slot(0x04, Some(&user_password))?;
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
    let hsm = Hsm::instantiate("/lib/libnethsm.so")?;
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
    let key = session.generate_aes_key(AesKeySize::Aes256, "label")?;
    info!("Generated AES key: {}", key);
    Ok(())
}

#[test]
#[ignore]
fn test_rsa_key_wrap() -> PResult<()> {
    initialize_logging();
    let slot = get_slot()?;
    let session = slot.open_session(true)?;
    let symmetric_key = session.generate_aes_key(AesKeySize::Aes256, "label")?;
    info!("Symmetric key handle: {symmetric_key}");
    let (sk, pk) = session.generate_rsa_key_pair(RsaKeySize::Rsa2048, "label")?;
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
    let (sk, pk) = session.generate_rsa_key_pair(RsaKeySize::Rsa2048, "label")?;
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
    let (sk, pk) = session.generate_rsa_key_pair(RsaKeySize::Rsa2048, "label")?;
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
    let sk = session.generate_aes_key(AesKeySize::Aes256, "label")?;
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
            let (sk, pk) = session.generate_rsa_key_pair(RsaKeySize::Rsa2048, "label")?;
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
    let objects = session.list_objects(ObjectType::Any)?;
    for object in objects.iter() {
        session.destroy_object(*object)?;
    }
    let objects = session.list_objects(ObjectType::Any)?;
    assert_eq!(objects.len(), 0);
    let (_sk, _pk) = session.generate_rsa_key_pair(RsaKeySize::Rsa2048, "label")?;
    let objects = session.list_objects(ObjectType::Any)?;
    assert_eq!(objects.len(), 2);
    let objects = session.list_objects(ObjectType::RsaKey)?;
    assert_eq!(objects.len(), 2);
    let objects = session.list_objects(ObjectType::RsaPublicKey)?;
    assert_eq!(objects.len(), 1);
    let objects = session.list_objects(ObjectType::RsaPrivateKey)?;
    assert_eq!(objects.len(), 1);
    let objects = session.list_objects(ObjectType::AesKey)?;
    assert_eq!(objects.len(), 0);
    // add another keypair
    let (_sk, _pk) = session.generate_rsa_key_pair(RsaKeySize::Rsa3072, "label")?;
    let objects = session.list_objects(ObjectType::Any)?;
    assert_eq!(objects.len(), 4);
    let objects = session.list_objects(ObjectType::RsaKey)?;
    assert_eq!(objects.len(), 4);
    let objects = session.list_objects(ObjectType::RsaPublicKey)?;
    assert_eq!(objects.len(), 2);
    let objects = session.list_objects(ObjectType::RsaPrivateKey)?;
    assert_eq!(objects.len(), 2);
    let objects = session.list_objects(ObjectType::AesKey)?;
    assert_eq!(objects.len(), 0);
    // add an AES key
    let _key = session.generate_aes_key(AesKeySize::Aes256, "label")?;
    let objects = session.list_objects(ObjectType::Any)?;
    assert_eq!(objects.len(), 5);
    let objects = session.list_objects(ObjectType::AesKey)?;
    assert_eq!(objects.len(), 1);
    Ok(())
}

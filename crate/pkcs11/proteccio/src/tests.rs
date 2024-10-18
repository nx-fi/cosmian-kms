use std::{ptr, sync::Once};

use libloading::Library;
use pkcs11_sys::{
    CKF_OS_LOCKING_OK, CKR_OK, CK_C_INITIALIZE_ARGS, CK_FUNCTION_LIST_PTR_PTR, CK_INFO, CK_RV,
    CK_VOID_PTR,
};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use crate::{hsm::Hsm, PResult};

static TRACING_INIT: Once = Once::new();
pub fn initialize_logging() {
    TRACING_INIT.call_once(|| {
        let subscriber = FmtSubscriber::builder()
            .with_max_level(Level::INFO) // Adjust the level as needed
            .with_writer(std::io::stdout)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("Setting default subscriber failed");
    });
}

#[test]
fn low_level_test() -> PResult<()> {
    let path = "/lib/libnethsm.so";
    let library = unsafe { Library::new(path) }?;
    let init = unsafe { library.get::<fn(pInitArgs: CK_VOID_PTR) -> CK_RV>(b"C_Initialize") }?;
    let finalize = unsafe { library.get::<fn() -> CK_RV>(b"C_Finalize") }?;
    let get_info = unsafe { library.get::<fn(*mut CK_INFO) -> CK_RV>(b"C_GetInfo") }?;
    let get_function_list =
        unsafe { library.get::<fn(*mut CK_FUNCTION_LIST_PTR_PTR) -> CK_RV>(b"C_GetFunctionList") }?;

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
fn get_initialize() -> PResult<()> {
    initialize_logging();
    let hsm = Hsm::instantiate("/lib/libnethsm.so")?;
    let manager = hsm.get_manager()?;
    let info = manager.get_info()?;
    info!("Connected to the HSM: {info:#?}");
    let session = manager.open_session()?;
    let random = session.generate_random(32)?;
    assert_eq!(random.len(), 32);
    info!("Random bytes: {}", hex::encode(random));

    Ok(())
}

use std::{os::raw::c_void, ptr, sync::Arc};

use libloading::Library;
use pkcs11_sys::{CKF_OS_LOCKING_OK, CK_C_INITIALIZE_ARGS, CK_SLOT_ID};

use crate::{PError, PResult};

pub struct Hsm {
    hsm: Arc<HsmLib>,
}

impl Hsm {
    pub fn instantiate<P>(path: P) -> PResult<Self>
    where
        P: AsRef<std::ffi::OsStr>,
    {
        let hsm = HsmLib::load_from_path(path)?;
        Ok(Hsm { hsm: Arc::new(hsm) })
    }

    pub fn get_manager(&self) -> PResult<HsmManager> {
        Ok(HsmManager {
            hsm: self.hsm.clone(),
        })
    }
}

struct HsmLib {
    library: Library,
    C_Initialize: pkcs11_sys::CK_C_Initialize,
    C_OpenSession: pkcs11_sys::CK_C_OpenSession,
    C_CloseSession: pkcs11_sys::CK_C_CloseSession,
    C_GenerateRandom: pkcs11_sys::CK_C_GenerateRandom,
}

impl HsmLib {
    fn load_from_path<P>(path: P) -> PResult<Self>
    where
        P: AsRef<std::ffi::OsStr>,
    {
        unsafe {
            let library = Library::new(path)?;
            Ok(HsmLib {
                C_Initialize: *library.get(b"C_Initialize")?,
                C_OpenSession: *library.get(b"C_OpenSession")?,
                C_CloseSession: *library.get(b"C_CloseSession")?,
                C_GenerateRandom: *library.get(b"C_GenerateRandom")?,
                library,
            })
        }
    }
}

pub struct HsmManager {
    hsm: Arc<HsmLib>,
}

impl HsmManager {
    pub fn initialize(&self) -> PResult<()> {
        let pInitArgs = CK_C_INITIALIZE_ARGS {
            CreateMutex: None,
            DestroyMutex: None,
            LockMutex: None,
            UnlockMutex: None,
            flags: CKF_OS_LOCKING_OK,
            pReserved: ptr::null_mut(),
        };
        let pInitArgsPtr = &pInitArgs as *const CK_C_INITIALIZE_ARGS as *mut c_void;
        unsafe {
            let rv = self.hsm.C_Initialize.ok_or_else(|| {
                PError::Default("C_Initialize not available on library".to_string())
            })?(pInitArgsPtr);
            if rv != pkcs11_sys::CKR_OK {
                return Err(PError::Default("Failed initializing the HSM".to_string()));
            }
            Ok(())
        }
    }

    pub fn open_session(&self) -> PResult<Session> {
        let slot_id: CK_SLOT_ID = 0;
        let flags: pkcs11_sys::CK_FLAGS = 0;
        let mut session_handle: pkcs11_sys::CK_SESSION_HANDLE = 0;

        unsafe {
            let rv = self.hsm.C_OpenSession.ok_or_else(|| {
                PError::Default("C_OpenSession not available on library".to_string())
            })?(slot_id, flags, ptr::null_mut(), None, *session_handle);
            if rv != pkcs11_sys::CKR_OK {
                return Err(PError::Default("Failed opening a session".to_string()));
            }
            Ok(Session {
                hsm: self.hsm.clone(),
                session_handle,
            })
        }
    }
}

pub struct Session {
    hsm: Arc<HsmLib>,
    session_handle: pkcs11_sys::CK_SESSION_HANDLE,
}

impl Session {
    pub fn close(&self) -> PResult<()> {
        unsafe {
            let rv = self.hsm.C_CloseSession.ok_or_else(|| {
                PError::Default("C_CloseSession not available on library".to_string())
            })?(self.session_handle);
            if rv != pkcs11_sys::CKR_OK {
                return Err(PError::Default("Failed closing a session".to_string()));
            }
            Ok(())
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

use std::{ffi::CStr, ptr, sync::Arc};

use libloading::Library;
use pkcs11_sys::{
    CKF_OS_LOCKING_OK, CKF_SERIAL_SESSION, CK_C_INITIALIZE_ARGS, CK_FLAGS, CK_INFO, CK_SLOT_ID,
    CK_VOID_PTR,
};

use crate::{PError, PResult};

pub struct Hsm {
    hsm: Arc<HsmLib>,
}

impl Hsm {
    pub fn instantiate<P>(path: P) -> PResult<Self>
    where
        P: AsRef<std::ffi::OsStr>,
    {
        let hsmLib = HsmLib::load_from_path(path)?;
        Ok(Hsm {
            hsm: Arc::new(hsmLib),
        })
    }

    pub fn get_manager(&self) -> PResult<HsmManager> {
        let hsmLib = self.hsm.clone();
        let manager = HsmManager {
            hsm: self.hsm.clone(),
        };
        manager.initialize()?;
        Ok(manager)
    }
}

struct HsmLib {
    library: Library,
    C_Initialize: pkcs11_sys::CK_C_Initialize,
    C_OpenSession: pkcs11_sys::CK_C_OpenSession,
    C_CloseSession: pkcs11_sys::CK_C_CloseSession,
    C_GenerateRandom: pkcs11_sys::CK_C_GenerateRandom,
    C_GetInfo: pkcs11_sys::CK_C_GetInfo,
}

impl HsmLib {
    fn load_from_path<P>(path: P) -> PResult<Self>
    where
        P: AsRef<std::ffi::OsStr>,
    {
        unsafe {
            let library = Library::new(path)?;
            Ok(HsmLib {
                C_Initialize: Some(*library.get(b"C_Initialize")?),
                C_OpenSession: Some(*library.get(b"C_OpenSession")?),
                C_CloseSession: Some(*library.get(b"C_CloseSession")?),
                C_GenerateRandom: Some(*library.get(b"C_GenerateRandom")?),
                C_GetInfo: Some(*library.get(b"C_GetInfo")?),
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
        // let pInitArgsPtr = &pInitArgs as *const CK_C_INITIALIZE_ARGS as *mut c_void;
        unsafe {
            // let rv = self.hsm.C_Initialize.deref()(&pInitArgs);
            let rv = self.hsm.C_Initialize.ok_or_else(|| {
                PError::Default("C_Initialize not available on library".to_string())
            })?(&pInitArgs as *const CK_C_INITIALIZE_ARGS as CK_VOID_PTR);
            if rv != pkcs11_sys::CKR_OK {
                return Err(PError::Default("Failed initializing the HSM".to_string()));
            }
            Ok(())
        }
    }

    pub fn get_info(&self) -> PResult<Info> {
        unsafe {
            let mut info = CK_INFO::default();
            let rv =
                self.hsm.C_GetInfo.ok_or_else(|| {
                    PError::Default("C_GetInfo not available on library".to_string())
                })?(&mut info);
            if rv != pkcs11_sys::CKR_OK {
                return Err(PError::Default("Failed getting HSM info".to_string()));
            }
            Ok(info.into())
        }
    }

    pub fn open_session(&self) -> PResult<Session> {
        let slot_id: CK_SLOT_ID = 0x01;
        let flags: CK_FLAGS = CKF_SERIAL_SESSION;
        let mut session_handle: pkcs11_sys::CK_SESSION_HANDLE = 0;

        unsafe {
            let rv = self.hsm.C_OpenSession.ok_or_else(|| {
                PError::Default("C_OpenSession not available on library".to_string())
            })?(slot_id, flags, ptr::null_mut(), None, &mut session_handle);
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

    pub fn generate_random(&self, len: usize) -> PResult<Vec<u8>> {
        unsafe {
            let mut values = vec![0u8; len];
            let values_ptr: *mut u8 = values.as_mut_ptr();
            let rv = self.hsm.C_GenerateRandom.ok_or_else(|| {
                PError::Default("C_GenerateRandom not available on library".to_string())
            })?(self.session_handle, values_ptr, len as u64);
            if rv != pkcs11_sys::CKR_OK {
                return Err(PError::Default("Failed generating random data".to_string()));
            }
            Ok(values)
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[derive(Debug)]
pub struct Info {
    pub cryptokiVersion: (u8, u8),
    pub manufacturerID: String,
    pub flags: u64,
    pub libraryDescription: String,
    pub libraryVersion: (u8, u8),
}

impl From<CK_INFO> for Info {
    fn from(info: CK_INFO) -> Self {
        unsafe {
            Info {
                cryptokiVersion: (info.cryptokiVersion.major, info.cryptokiVersion.minor),
                manufacturerID: CStr::from_bytes_until_nul(&info.manufacturerID)
                    .unwrap()
                    .to_string_lossy()
                    .to_string(),
                flags: info.flags,
                libraryDescription: CStr::from_bytes_until_nul(&info.libraryDescription)
                    .unwrap()
                    .to_string_lossy()
                    .to_string(),
                libraryVersion: (info.libraryVersion.major, info.libraryVersion.minor),
            }
        }
    }
}

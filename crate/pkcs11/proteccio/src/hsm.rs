use std::{
    ffi::CStr,
    fmt,
    fmt::{Display, Formatter},
    ptr,
    sync::Arc,
};

use libloading::Library;
use pkcs11_sys::*;
use tracing::warn;

use crate::{session::Session, PError, PResult};

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

pub(crate) struct HsmLib {
    _library: Library,
    pub(crate) C_Initialize: CK_C_Initialize,
    pub(crate) C_OpenSession: CK_C_OpenSession,
    pub(crate) C_CloseSession: CK_C_CloseSession,
    pub(crate) C_Decrypt: CK_C_Decrypt,
    pub(crate) C_DecryptInit: CK_C_DecryptInit,
    pub(crate) C_DecryptUpdate: CK_C_DecryptUpdate,
    pub(crate) C_DecryptFinal: CK_C_DecryptFinal,
    pub(crate) C_Encrypt: CK_C_Encrypt,
    pub(crate) C_EncryptInit: CK_C_EncryptInit,
    pub(crate) C_EncryptUpdate: CK_C_EncryptUpdate,
    pub(crate) C_EncryptFinal: CK_C_EncryptFinal,
    pub(crate) C_GenerateKey: CK_C_GenerateKey,
    pub(crate) C_GenerateKeyPair: CK_C_GenerateKeyPair,
    pub(crate) C_GenerateRandom: CK_C_GenerateRandom,
    pub(crate) C_GetInfo: CK_C_GetInfo,
    pub(crate) C_Login: CK_C_Login,
    pub(crate) C_Logout: CK_C_Logout,
    pub(crate) C_WrapKey: CK_C_WrapKey,
    pub(crate) C_UnwrapKey: CK_C_UnwrapKey,
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
                C_Encrypt: Some(*library.get(b"C_Encrypt")?),
                C_EncryptInit: Some(*library.get(b"C_EncryptInit")?),
                C_EncryptUpdate: Some(*library.get(b"C_EncryptUpdate")?),
                C_EncryptFinal: Some(*library.get(b"C_EncryptFinal")?),
                C_Decrypt: Some(*library.get(b"C_Decrypt")?),
                C_DecryptInit: Some(*library.get(b"C_DecryptInit")?),
                C_DecryptUpdate: Some(*library.get(b"C_DecryptUpdate")?),
                C_DecryptFinal: Some(*library.get(b"C_DecryptFinal")?),
                C_GenerateKey: Some(*library.get(b"C_GenerateKey")?),
                C_GenerateKeyPair: Some(*library.get(b"C_GenerateKeyPair")?),
                C_GenerateRandom: Some(*library.get(b"C_GenerateRandom")?),
                C_GetInfo: Some(*library.get(b"C_GetInfo")?),
                C_Login: Some(*library.get(b"C_Login")?),
                C_Logout: Some(*library.get(b"C_Logout")?),
                C_WrapKey: Some(*library.get(b"C_WrapKey")?),
                C_UnwrapKey: Some(*library.get(b"C_UnwrapKey")?),
                // we need to keep the library alive
                _library: library,
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
            if rv != CKR_OK {
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
            if rv != CKR_OK {
                return Err(PError::Default("Failed getting HSM info".to_string()));
            }
            Ok(info.into())
        }
    }

    pub fn open_session(
        &self,
        slot_id: usize,
        read_write: bool,
        login_password: Option<String>,
    ) -> PResult<Session> {
        let slot_id: CK_SLOT_ID = slot_id as CK_SLOT_ID;
        let flags: CK_FLAGS = if read_write {
            CKF_RW_SESSION | CKF_SERIAL_SESSION
        } else {
            CKF_SERIAL_SESSION
        };
        let mut session_handle: CK_SESSION_HANDLE = 0;

        unsafe {
            let rv = self.hsm.C_OpenSession.ok_or_else(|| {
                PError::Default("C_OpenSession not available on library".to_string())
            })?(slot_id, flags, ptr::null_mut(), None, &mut session_handle);
            if rv != CKR_OK {
                return Err(PError::Default("Failed opening a session".to_string()));
            }
            if let Some(password) = &login_password {
                let mut pwd_bytes = password.as_bytes().to_vec();
                let rv = self.hsm.C_Login.ok_or_else(|| {
                    PError::Default("C_Login not available on library".to_string())
                })?(
                    session_handle,
                    CKU_USER,
                    pwd_bytes.as_mut_ptr() as CK_UTF8CHAR_PTR,
                    pwd_bytes.len() as CK_ULONG,
                );
                if rv == CKR_USER_ALREADY_LOGGED_IN {
                    warn!("user already logged in, ignoring logging");
                } else if rv != CKR_OK {
                    return Err(PError::Default("Failed logging in".to_string()));
                }
            }
            Ok(Session::new(
                self.hsm.clone(),
                session_handle,
                login_password.is_some(),
            ))
        }
    }
}

pub struct Info {
    pub cryptokiVersion: (u8, u8),
    pub manufacturerID: String,
    pub flags: u64,
    pub libraryDescription: String,
    pub libraryVersion: (u8, u8),
}

impl From<CK_INFO> for Info {
    fn from(info: CK_INFO) -> Self {
        Info {
            cryptokiVersion: (info.cryptokiVersion.major, info.cryptokiVersion.minor),
            manufacturerID: CStr::from_bytes_until_nul(&info.manufacturerID)
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            flags: info.flags,
            libraryDescription: CStr::from_bytes_until_nul(&info.libraryDescription)
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            libraryVersion: (info.libraryVersion.major, info.libraryVersion.minor),
        }
    }
}

impl Display for Info {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Cryptoki Version: {}.{}\nManufacturer ID: {}\nFlags: {}\nLibrary Description: \
             {}\nLibrary Version: {}.{}",
            self.cryptokiVersion.0,
            self.cryptokiVersion.1,
            self.manufacturerID,
            self.flags,
            self.libraryDescription,
            self.libraryVersion.0,
            self.libraryVersion.1
        )
    }
}

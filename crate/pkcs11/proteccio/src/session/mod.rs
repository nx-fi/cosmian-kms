mod aes;
mod rsa;

use std::sync::Arc;

pub use aes::AesKeySize;
use pkcs11_sys::*;
pub use rsa::{RsaAlgorithm, RsaKeySize};

use crate::{PError, PResult};

pub struct Session {
    hsm: Arc<crate::hsm::HsmLib>,
    session_handle: CK_SESSION_HANDLE,
    is_logged_in: bool,
}

impl Session {
    pub fn new(
        hsm: Arc<crate::hsm::HsmLib>,
        session_handle: CK_SESSION_HANDLE,
        is_logged_in: bool,
    ) -> Self {
        Session {
            hsm,
            session_handle,
            is_logged_in,
        }
    }

    pub fn close(&self) -> PResult<()> {
        unsafe {
            if self.is_logged_in {
                let rv = self.hsm.C_Logout.ok_or_else(|| {
                    PError::Default("C_Logout not available on library".to_string())
                })?(self.session_handle);
                if rv != CKR_OK {
                    return Err(PError::Default("Failed logging out".to_string()));
                }
            }
            let rv = self.hsm.C_CloseSession.ok_or_else(|| {
                PError::Default("C_CloseSession not available on library".to_string())
            })?(self.session_handle);
            if rv != CKR_OK {
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
            if rv != CKR_OK {
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

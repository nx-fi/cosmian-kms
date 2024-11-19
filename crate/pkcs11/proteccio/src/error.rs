//! Copyright 2024 Cosmian Tech SAS

use cosmian_kms_plugins::PluginError;
use thiserror::Error;

pub type PResult<T> = Result<T, PError>;

#[derive(Error, Debug)]
pub enum PError {
    #[error("{0}")]
    Default(String),

    #[error("Error loading the library: {0}")]
    LibLoading(#[from] libloading::Error),

    #[error("PKCS#11 Error: {0}")]
    Pkcs11(String),

    #[error("HSM Error: {0}")]
    Hsm(String),
}

impl From<PluginError> for PError {
    fn from(e: PluginError) -> Self {
        PError::Hsm(e.to_string())
    }
}

impl From<PError> for PluginError {
    fn from(e: PError) -> Self {
        PluginError::Default(e.to_string())
    }
}

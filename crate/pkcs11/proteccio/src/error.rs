//! Copyright 2024 Cosmian Tech SAS

use thiserror::Error;

pub type PResult<T> = Result<T, PError>;

#[derive(Error, Debug)]
pub enum PError {
    #[error("{0}")]
    Default(String),

    #[error("Error loading the library: {0}")]
    LibLoadingError(#[from] libloading::Error),

    #[error("PKCS#11Error: {0}")]
    Pkcs11Error(String),
}

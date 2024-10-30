//! Copyright 2024 Cosmian Tech SAS

use thiserror::Error;

pub type HsmResult<T> = Result<T, HsmError>;

#[derive(Error, Debug)]
pub enum HsmError {
    #[error("{0}")]
    Default(String),
}

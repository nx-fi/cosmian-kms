//! Copyright 2024 Cosmian Tech SAS

use cosmian_kms_plugins::PluginError;
use thiserror::Error;

pub type HsmResult<T> = Result<T, HsmError>;

#[derive(Error, Debug)]
pub enum HsmError {
    #[error("{0}")]
    Default(String),
}

impl From<HsmError> for PluginError {
    fn from(value: HsmError) -> Self {
        Self::Hsm(value.to_string())
    }
}

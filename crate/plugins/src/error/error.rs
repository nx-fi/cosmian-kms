//! Copyright 2024 Cosmian Tech SAS

use thiserror::Error;

pub type PluginResult<T> = Result<T, PluginError>;

#[derive(Error, Debug)]
pub enum PluginError {
    #[error("{0}")]
    Default(String),

    #[error("Invalid Request: {0}")]
    InvalidRequest(String),
}

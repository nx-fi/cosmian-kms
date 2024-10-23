//! Copyright 2024 Cosmian Tech SAS

#![allow(non_snake_case)]
#![allow(clippy::missing_safety_doc)]
#![deny(unsafe_op_in_unsafe_fn)]
//avoid renaming all unused parameters with _ in all unused functions
#![allow(unused_variables)]

mod error;

pub use error::{PError, PResult};

mod hsm;
mod session;
#[cfg(test)]
mod tests;

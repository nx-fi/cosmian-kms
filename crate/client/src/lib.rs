#![allow(clippy::upper_case_acronyms)]
//required to detect generic type in Serializer
#![feature(min_specialization)]

pub mod access;
mod certificate_verifier;
mod error;
mod kms_rest_client;
mod result;

pub use cosmian_kmip;
pub use error::RestClientError;
pub use kms_rest_client::KmsRestClient;
pub use result::{RestClientResult, RestClientResultHelper};

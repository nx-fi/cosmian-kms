use cosmian_kmip::{
    error::KmipError,
    kmip::{
        kmip_objects::ObjectType,
        kmip_operations::Create,
        kmip_types::{
            AttributeReference, Attributes, CryptographicAlgorithm, KeyFormatType,
            VendorAttributeReference,
        },
    },
};
use cosmian_mcfe::lwe;

use crate::crypto::mcfe::operation::vendor_attributes_from_mcfe_setup;

/// Build a `CreateRequest` for an LWE Secret Key
pub fn lwe_secret_key_create_request(setup: &lwe::Setup) -> Result<Create, KmipError> {
    Ok(Create {
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::LWE),
            key_format_type: Some(KeyFormatType::McfeSecretKey),
            vendor_attributes: Some(vec![vendor_attributes_from_mcfe_setup(setup)?]),
            ..Attributes::new(ObjectType::SymmetricKey)
        },
        protection_storage_masks: None,
    })
}

// The `AttributeReference` to recover the LWE `Setup` of a stored LWE Key
pub fn lwe_setup_attribute_reference() -> AttributeReference {
    AttributeReference::Vendor(VendorAttributeReference {
        vendor_identification: "cosmian".to_owned(),
        attribute_name: "mcfe_setup".to_owned(),
    })
}
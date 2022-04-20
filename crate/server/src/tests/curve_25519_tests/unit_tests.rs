use std::sync::Arc;

use cosmian_kmip::kmip::{
    kmip_data_structures::KeyValue,
    kmip_objects::{Object, ObjectType},
    kmip_operations::Import,
    kmip_types::{
        Attributes, CryptographicAlgorithm, KeyFormatType, LinkType, LinkedObjectIdentifier,
    },
};
use cosmian_kms_utils::crypto::curve_25519::{
    kmip_requests::{
        create_key_pair_request, extract_key_bytes, get_private_key_request,
        get_public_key_request, parse_public_key,
    },
    operation,
};

use crate::{
    config::init_config,
    error::KmsError,
    kmip::kmip_server::{server::kmip_server::KmipServer, KMSServer},
    result::KResult,
};

#[actix_rt::test]
async fn test_curve_25519_key_pair() -> KResult<()> {
    let config = crate::config::Config {
        delegated_authority_domain: Some("dev-1mbsbmin.us.auth0.com".to_string()),
        ..Default::default()
    };
    init_config(&config).await?;

    let kms = Arc::new(KMSServer::instantiate().await?);
    let owner = "eyJhbGciOiJSUzI1Ni";

    // request key pair creation
    let request = create_key_pair_request();
    let response = kms.create_key_pair(request, owner).await?;
    // check that the private and public key exist
    // check secret key
    let sk_response = kms
        .get(
            get_private_key_request(&response.private_key_unique_identifier),
            owner,
        )
        .await?;
    let sk = &sk_response.object;
    let sk_key_block = match sk {
        Object::PrivateKey { key_block } => key_block.clone(),
        _ => {
            return Err(KmsError::ServerError(
                "Expected a KMIP Private Key".to_owned(),
            ))
        }
    };
    assert_eq!(
        sk_key_block.cryptographic_algorithm,
        CryptographicAlgorithm::EC,
    );
    assert_eq!(sk_key_block.cryptographic_length, operation::Q_LENGTH_BITS,);
    assert_eq!(
        sk_key_block.key_format_type,
        KeyFormatType::TransparentECPrivateKey
    );
    //check link to public key
    let attributes = match &sk_key_block.key_value {
        KeyValue::PlainText { attributes, .. } => attributes,
        _ => {
            return Err(KmsError::ServerError(
                "The private key should be a plain text key value".to_owned(),
            ))
        }
    };
    let attr = attributes.clone().ok_or_else(|| {
        KmsError::ServerError("This should never happen. There should be attributes".to_owned())
    })?;
    assert_eq!(attr.link.len(), 1);
    let link = &attr.link[0];
    assert_eq!(link.link_type, LinkType::PublicKeyLink);
    assert_eq!(
        link.linked_object_identifier,
        LinkedObjectIdentifier::TextString(response.public_key_unique_identifier.clone())
    );

    // check public key
    let pk_response = kms
        .get(
            get_public_key_request(&response.public_key_unique_identifier),
            owner,
        )
        .await?;
    let pk = &pk_response.object;
    let pk_key_block = match &pk {
        Object::PublicKey { key_block } => key_block.clone(),
        _ => {
            return Err(KmsError::ServerError(
                "Expected a KMIP Public Key".to_owned(),
            ))
        }
    };
    assert_eq!(
        pk_key_block.cryptographic_algorithm,
        CryptographicAlgorithm::EC,
    );
    assert_eq!(pk_key_block.cryptographic_length, operation::Q_LENGTH_BITS,);
    assert_eq!(
        pk_key_block.key_format_type,
        KeyFormatType::TransparentECPublicKey
    );
    //check link to secret key
    let attributes = match &pk_key_block.key_value {
        KeyValue::PlainText { attributes, .. } => attributes,
        _ => {
            return Err(KmsError::ServerError(
                "The public key should be a plain text key value".to_owned(),
            ))
        }
    };
    let attr = attributes.clone().ok_or_else(|| {
        KmsError::ServerError("This should never happen. There should be attributes".to_owned())
    })?;
    assert_eq!(attr.link.len(), 1);
    let link = &attr.link[0];
    assert_eq!(link.link_type, LinkType::PrivateKeyLink);
    assert_eq!(
        link.linked_object_identifier,
        LinkedObjectIdentifier::TextString(response.private_key_unique_identifier)
    );
    // test import of public key
    let pk_bytes = extract_key_bytes(pk)?;
    let pk = parse_public_key(&pk_bytes)?;
    let request = Import {
        unique_identifier: "".to_string(),
        object_type: ObjectType::PublicKey,
        replace_existing: None,
        key_wrap_type: None,
        attributes: Attributes::new(ObjectType::PublicKey),
        object: pk,
    };
    let new_uid = kms.import(request, owner).await?.unique_identifier;
    // update

    let pk = parse_public_key(&pk_bytes)?;
    let request = Import {
        unique_identifier: new_uid.clone(),
        object_type: ObjectType::PublicKey,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: Attributes::new(ObjectType::PublicKey),
        object: pk,
    };
    let update_response = kms.import(request, owner).await?;
    assert_eq!(new_uid, update_response.unique_identifier);
    Ok(())
}
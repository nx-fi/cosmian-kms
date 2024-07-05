use cosmian_kmip::kmip::{
    kmip_operations::{
        Certify, Create, CreateKeyPair, Decrypt, Destroy, Encrypt, Export, Get, GetAttributes,
        Import, Locate, Operation, ReKeyKeyPair, Revoke, Validate,
    },
    ttlv::{deserializer::from_ttlv, TTLV},
};

use crate::{
    core::{extra_database_params::ExtraDatabaseParams, KMS},
    error::KmsError,
    kms_bail,
    result::KResult,
};

/// Dispatch operation depending on the TTLV tag
pub async fn dispatch(
    kms: &KMS,
    ttlv: &TTLV,
    user: &str,
    database_params: Option<&ExtraDatabaseParams>,
) -> KResult<Operation> {
    Ok(match ttlv.tag.as_str() {
        "Certify" => {
            let req = from_ttlv::<Certify>(ttlv)?;
            let resp = kms.certify(req, user, database_params).await?;
            Operation::CertifyResponse(resp)
        }
        "Create" => {
            let req = from_ttlv::<Create>(ttlv)?;
            let resp = kms.create(req, user, database_params).await?;
            Operation::CreateResponse(resp)
        }
        "CreateKeyPair" => {
            let req = from_ttlv::<CreateKeyPair>(ttlv)?;
            let resp = kms.create_key_pair(req, user, database_params).await?;
            Operation::CreateKeyPairResponse(resp)
        }
        "Decrypt" => {
            let req = from_ttlv::<Decrypt>(ttlv)?;
            let resp = kms.decrypt(req, user, database_params).await?;
            Operation::DecryptResponse(resp)
        }
        "Destroy" => {
            let req = from_ttlv::<Destroy>(ttlv)?;
            let resp = kms.destroy(req, user, database_params).await?;
            Operation::DestroyResponse(resp)
        }
        "Encrypt" => {
            let req = from_ttlv::<Encrypt>(ttlv)?;
            let resp = kms.encrypt(req, user, database_params).await?;
            Operation::EncryptResponse(resp)
        }
        "Export" => {
            let req = from_ttlv::<Export>(ttlv)?;
            let resp = kms.export(req, user, database_params).await?;
            Operation::ExportResponse(resp)
        }
        "Get" => {
            let req = from_ttlv::<Get>(ttlv)?;
            let resp = kms.get(req, user, database_params).await?;
            Operation::GetResponse(resp)
        }
        "GetAttributes" => {
            let req = from_ttlv::<GetAttributes>(ttlv)?;
            let resp = kms.get_attributes(req, user, database_params).await?;
            Operation::GetAttributesResponse(resp)
        }
        "Import" => {
            let req = from_ttlv::<Import>(ttlv)?;
            let resp = kms.import(req, user, database_params).await?;
            Operation::ImportResponse(resp)
        }
        "Locate" => {
            let req = from_ttlv::<Locate>(ttlv)?;
            let resp = kms.locate(req, user, database_params).await?;
            Operation::LocateResponse(resp)
        }
        "ReKeyKeyPair" => {
            let req = from_ttlv::<ReKeyKeyPair>(ttlv)?;
            let resp = kms.rekey_keypair(req, user, database_params).await?;
            Operation::ReKeyKeyPairResponse(resp)
        }
        "Revoke" => {
            let req = from_ttlv::<Revoke>(ttlv)?;
            let resp = kms.revoke(req, user, database_params).await?;
            Operation::RevokeResponse(resp)
        }
        "Validate" => {
            let req = from_ttlv::<Validate>(ttlv)?;
            let resp = kms.validate(req, user, database_params).await?;
            Operation::ValidateResponse(resp)
        }
        x => kms_bail!(KmsError::RouteNotFound(format!("Operation: {x}"))),
    })
}

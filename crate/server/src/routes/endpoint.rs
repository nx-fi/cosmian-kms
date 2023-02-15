use std::sync::Arc;

use actix_web::{
    delete, get, post,
    web::{Data, Json, Path, Query},
    HttpMessage, HttpRequest, HttpResponse, HttpResponseBuilder,
};
use base64::{engine::general_purpose, Engine as _};
use clap::crate_version;
use cosmian_kmip::kmip::{
    kmip_operations::{
        Create, CreateKeyPair, Decrypt, Destroy, Encrypt, Get, GetAttributes, Import, Locate,
        ReKeyKeyPair, Revoke,
    },
    kmip_types::UniqueIdentifier,
    ttlv::{deserializer::from_ttlv, serializer::to_ttlv, TTLV},
};
use cosmian_kms_utils::types::{
    Access, ExtraDatabaseParams, ObjectOwnedResponse, ObjectSharedResponse, QuoteParams,
    SuccessResponse, UserAccessResponse,
};
use http::{header, StatusCode};
use tracing::{debug, error, warn};

use crate::{
    config::{DbParams, SharedConfig},
    core::crud::KmipServer,
    database::KMSServer,
    error::KmsError,
    kms_bail,
    middlewares::auth::AuthClaim,
    result::KResult,
};

impl actix_web::error::ResponseError for KmsError {
    fn error_response(&self) -> HttpResponse {
        let status_code = self.status_code();
        let message = self.to_string();

        if status_code >= StatusCode::INTERNAL_SERVER_ERROR {
            error!("{status_code} - {message}");
        } else {
            warn!("{status_code} - {message}");
        }

        HttpResponseBuilder::new(status_code)
            .insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"))
            .body(message)
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Self::RouteNotFound(_) => StatusCode::NOT_FOUND,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::ServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::KmipError(..) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::NotSupported(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::UnsupportedProtectionMasks => StatusCode::UNPROCESSABLE_ENTITY,
            Self::UnsupportedPlaceholder => StatusCode::UNPROCESSABLE_ENTITY,
            Self::InconsistentOperation(..) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::InvalidRequest(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::ItemNotFound(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::SGXError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ConversionError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// Generate KMIP generic key pair
#[post("/kmip/2_1")]
pub async fn kmip(
    req_http: HttpRequest,
    item: Json<TTLV>,
    kms_client: Data<Arc<KMSServer>>,
) -> KResult<Json<TTLV>> {
    let ttlv_req = item.into_inner();
    let database_params = get_database_secrets(&req_http)?;
    let owner = get_owner(req_http)?;

    debug!("POST /kmip. Request: {:?}", ttlv_req.tag.as_str());

    let ttlv_resp = match ttlv_req.tag.as_str() {
        "Create" => {
            let req = from_ttlv::<Create>(&ttlv_req)?;
            let resp = kms_client
                .create(req, &owner, database_params.as_ref())
                .await?;
            to_ttlv(&resp)?
        }
        "CreateKeyPair" => {
            let req = from_ttlv::<CreateKeyPair>(&ttlv_req)?;
            let resp = kms_client
                .create_key_pair(req, &owner, database_params.as_ref())
                .await?;
            to_ttlv(&resp)?
        }
        "Decrypt" => {
            let req = from_ttlv::<Decrypt>(&ttlv_req)?;
            let resp = kms_client
                .decrypt(req, &owner, database_params.as_ref())
                .await?;
            to_ttlv(&resp)?
        }
        "Encrypt" => {
            let req = from_ttlv::<Encrypt>(&ttlv_req)?;
            let resp = kms_client
                .encrypt(req, &owner, database_params.as_ref())
                .await?;
            to_ttlv(&resp)?
        }
        "Get" => {
            let req = from_ttlv::<Get>(&ttlv_req)?;
            let resp = kms_client
                .get(req, &owner, database_params.as_ref())
                .await?;
            to_ttlv(&resp)?
        }
        "GetAttributes" => {
            let req = from_ttlv::<GetAttributes>(&ttlv_req)?;
            let resp = kms_client
                .get_attributes(req, &owner, database_params.as_ref())
                .await?;
            to_ttlv(&resp)?
        }
        "Import" => {
            let req = from_ttlv::<Import>(&ttlv_req)?;
            let resp = kms_client
                .import(req, &owner, database_params.as_ref())
                .await?;
            to_ttlv(&resp)?
        }
        "Revoke" => {
            let req = from_ttlv::<Revoke>(&ttlv_req)?;
            let resp = kms_client
                .revoke(req, &owner, database_params.as_ref())
                .await?;
            to_ttlv(&resp)?
        }
        "Locate" => {
            let req = from_ttlv::<Locate>(&ttlv_req)?;
            let resp = kms_client
                .locate(req, &owner, database_params.as_ref())
                .await?;
            to_ttlv(&resp)?
        }
        "ReKeyKeyPair" => {
            let req = from_ttlv::<ReKeyKeyPair>(&ttlv_req)?;
            let resp = kms_client
                .rekey_keypair(req, &owner, database_params.as_ref())
                .await?;
            to_ttlv(&resp)?
        }
        "Destroy" => {
            let req = from_ttlv::<Destroy>(&ttlv_req)?;
            let resp = kms_client
                .destroy(req, &owner, database_params.as_ref())
                .await?;
            to_ttlv(&resp)?
        }
        x => kms_bail!(KmsError::RouteNotFound(format!("Operation: {x}"))),
    };
    Ok(Json(ttlv_resp))
}

/// List objects owned by the current user
#[get("/objects/owned")]
pub async fn list_owned_objects(
    req: HttpRequest,
    kms_client: Data<Arc<KMSServer>>,
) -> KResult<Json<Vec<ObjectOwnedResponse>>> {
    let database_params = get_database_secrets(&req)?;
    let owner = get_owner(req)?;
    let list = kms_client
        .list_owned_objects(&owner, database_params.as_ref())
        .await?;

    Ok(Json(list))
}

/// List objects owned by the current user
#[get("/objects/shared")]
pub async fn list_shared_objects(
    req: HttpRequest,
    kms_client: Data<Arc<KMSServer>>,
) -> KResult<Json<Vec<ObjectSharedResponse>>> {
    let database_params = get_database_secrets(&req)?;
    let owner = get_owner(req)?;
    let list = kms_client
        .list_shared_objects(&owner, database_params.as_ref())
        .await?;

    Ok(Json(list))
}

/// List access authorization for an object
#[get("/accesses/{object_id}")]
pub async fn list_accesses(
    req: HttpRequest,
    object_id: Path<(UniqueIdentifier,)>,
    kms_client: Data<Arc<KMSServer>>,
) -> KResult<Json<Vec<UserAccessResponse>>> {
    let database_params = get_database_secrets(&req)?;
    let owner = get_owner(req)?;
    let object_id = object_id.to_owned().0;
    let list = kms_client
        .list_accesses(&object_id, &owner, database_params.as_ref())
        .await?;

    Ok(Json(list))
}

/// Add an access authorization for an object, given a `userid`
#[post("/accesses/{object_id}")]
pub async fn insert_access(
    req: HttpRequest,
    access: Json<Access>,
    kms_client: Data<Arc<KMSServer>>,
) -> KResult<Json<SuccessResponse>> {
    let access = access.into_inner();
    let database_params = get_database_secrets(&req)?;
    let owner = get_owner(req)?;

    kms_client
        .insert_access(&access, &owner, database_params.as_ref())
        .await?;
    debug!(
        "Access granted on {:?} for {:?} to {}",
        &access.unique_identifier, &access.operation_type, &access.user_id
    );

    Ok(Json(SuccessResponse {
        success: format!("Access for {} successfully added", access.user_id),
    }))
}

/// Revoke an access authorization for an object, given a `userid`
#[delete("/accesses/{object_id}")]
pub async fn delete_access(
    req: HttpRequest,
    access: Json<Access>,
    kms_client: Data<Arc<KMSServer>>,
) -> KResult<Json<SuccessResponse>> {
    let access = access.into_inner();
    let database_params = get_database_secrets(&req)?;
    let owner = get_owner(req)?;

    kms_client
        .delete_access(&access, &owner, database_params.as_ref())
        .await?;
    debug!(
        "Access revoke on {:?} for {:?} to {}",
        &access.unique_identifier, &access.operation_type, &access.user_id
    );

    Ok(Json(SuccessResponse {
        success: format!("Access for {} successfully deleted", access.user_id),
    }))
}

/// Get the the server X09 certificate in PEM format
#[get("/certificate")]
pub async fn get_certificate(
    _req: HttpRequest,
    kms_client: Data<Arc<KMSServer>>,
) -> KResult<Json<Option<String>>> {
    debug!("Requesting the X509 certificate");
    Ok(Json(kms_client.get_server_x509_certificate()?))
}

/// Get the quote of the server running inside an enclave
///
/// This service is only enabled when the server is running SGX
#[get("/enclave_quote")]
pub async fn get_enclave_quote(
    req: HttpRequest,
    kms_client: Data<Arc<KMSServer>>,
) -> KResult<Json<String>> {
    debug!("Requesting the enclave quote");
    let params = Query::<QuoteParams>::from_query(req.query_string())?;
    Ok(Json(kms_client.get_quote(&params.nonce)?))
}

/// Get the public key of the  enclave
///
/// This service is only enabled when the server is running SGX
#[get("/enclave_public_key")]
pub async fn get_enclave_public_key(
    _req: HttpRequest,
    kms_client: Data<Arc<KMSServer>>,
) -> KResult<Json<String>> {
    debug!("Requesting the enclave public key");
    Ok(Json(kms_client.get_enclave_public_key()?))
}

/// Get the manifest of the server running inside an enclave
///
/// This service is only enabled when the server is running SGX
#[get("/enclave_manifest")]
pub async fn get_enclave_manifest(
    _req: HttpRequest,
    kms_client: Data<Arc<KMSServer>>,
) -> KResult<Json<String>> {
    debug!("Requesting the manifest");
    Ok(Json(kms_client.get_manifest()?))
}

/// Add a new group to the KMS = add a new database
#[post("/new_database")]
pub async fn add_new_database(
    _req: HttpRequest,
    kms_client: Data<Arc<KMSServer>>,
) -> KResult<Json<String>> {
    debug!("Requesting a new database creation");
    Ok(Json(kms_client.add_new_database().await?))
}

/// Get the KMS version
#[get("/version")]
pub async fn get_version(
    _req: HttpRequest,
    _kms_client: Data<Arc<KMSServer>>,
) -> KResult<Json<String>> {
    debug!("Requesting the version");
    Ok(Json(crate_version!().to_string()))
}

fn get_owner(req_http: HttpRequest) -> KResult<String> {
    match SharedConfig::auth0_authority_domain() {
        Some(_) => match req_http.extensions().get::<AuthClaim>() {
            Some(claim) => Ok(claim.email.clone()),
            None => Err(KmsError::Unauthorized(
                "No valid auth claim owner (email) from JWT".to_owned(),
            )),
        },
        None => match SharedConfig::default_username() {
            Some(username) => Ok(username),
            None => Err(KmsError::Unauthorized(
                "Authentication incorrectly set-up on KMS server".to_owned(),
            )),
        },
    }
}

fn get_database_secrets(req_http: &HttpRequest) -> KResult<Option<ExtraDatabaseParams>> {
    Ok(match SharedConfig::db_params() {
        DbParams::SqliteEnc(_) => {
            let secrets = req_http
                .headers()
                .get("KmsDatabaseSecret")
                .and_then(|h| h.to_str().ok().map(std::string::ToString::to_string))
                .ok_or_else(|| {
                    KmsError::Unauthorized(
                        "Missing KmsDatabaseSecret header in the query".to_owned(),
                    )
                })?;

            let secrets = general_purpose::STANDARD.decode(secrets).map_err(|e| {
                KmsError::Unauthorized(format!("KmsDatabaseSecret header cannot be decoded: {e}"))
            })?;

            Some(
                serde_json::from_slice::<ExtraDatabaseParams>(&secrets).map_err(|e| {
                    KmsError::Unauthorized(format!(
                        "KmsDatabaseSecret header cannot be read: {}",
                        e
                    ))
                })?,
            )
        }
        _ => None,
    })
}

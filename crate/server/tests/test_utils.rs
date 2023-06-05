use std::sync::Arc;

use actix_http::Request;
use actix_web::{
    body::MessageBody,
    dev::{Service, ServiceResponse},
    test,
    web::Data,
    App,
};
use cosmian_kmip::kmip::ttlv::{deserializer::from_ttlv, serializer::to_ttlv, TTLV};
use cosmian_kms_server::{middlewares::auth::Auth0, result::KResult, routes::endpoint, KMSServer};
use serde::{de::DeserializeOwned, Serialize};

/// Test auth0 token (expired) -
/// bnjjj: I know it's ugly but it's easy and sufficient for now
pub static AUTH0_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjVVU1FrSVlULW9QMWZrcjQtNnRrciJ9.eyJuaWNrbmFtZSI6InRlY2giLCJuYW1lIjoidGVjaEBjb3NtaWFuLmNvbSIsInBpY3R1cmUiOiJodHRwczovL3MuZ3JhdmF0YXIuY29tL2F2YXRhci81MmZiMzFjOGNjYWQzNDU4MTIzZDRmYWQxNDA4NTRjZj9zPTQ4MCZyPXBnJmQ9aHR0cHMlM0ElMkYlMkZjZG4uYXV0aDAuY29tJTJGYXZhdGFycyUyRnRlLnBuZyIsInVwZGF0ZWRfYXQiOiIyMDIzLTA1LTMwVDA5OjMxOjExLjM4NloiLCJlbWFpbCI6InRlY2hAY29zbWlhbi5jb20iLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImlzcyI6Imh0dHBzOi8va21zLWNvc21pYW4uZXUuYXV0aDAuY29tLyIsImF1ZCI6IkszaXhldXhuVDVrM0Roa0tocWhiMXpYbjlFNjJGRXdJIiwiaWF0IjoxNjg1NDM5MDc0LCJleHAiOjE2ODU0NzUwNzQsInN1YiI6ImF1dGgwfDYzZDNkM2VhOTNmZjE2NDJjNzdkZjkyOCIsInNpZCI6ImJnVUNuTTNBRjVxMlpaVHFxMTZwclBCMi11Z0NNaUNPIiwibm9uY2UiOiJVRUZWTlZWeVluWTVUbHBwWjJScGNqSmtVMEZ4TmxkUFEwc3dTVGMwWHpaV2RVVmtkVnBEVGxSMldnPT0ifQ.HmU9fFwZ-JjJVlSy_PTei3ys0upeWQbWWiESmKBtRSClGnAXJNCpwuP4Jw7fgKn-8IBf-PYmP1_54u2Rw3RcJFVl7EblVoGMghYxVq5hViGpd00st3VwZmyCwOUz2CE5RBnBAoES4C8xA3zWg6oau0xjFQbC3jNU20eyFYMDewXA8UXCHQrEiQ56ylqSbyqlBbQIWbmOO4m5w2WDkx0bVyyJ893JfIJr_NANEQMJITYo8Mp_iHCyKp7llsfgCt07xN8ZqnsrMsJ15zC1n50bHGrTQisxURS1dpuFXF1hfrxhzogxYMX8CEISjsFgROjPY84GRMmvpYZfyaJbDDql3A";

pub async fn test_app()
-> impl Service<Request, Response = ServiceResponse<impl MessageBody>, Error = actix_web::Error> {
    let kms_server = Arc::new(
        KMSServer::instantiate()
            .await
            .expect("cannot instantiate KMS server"),
    );

    test::init_service(
        App::new()
            .wrap(Auth0)
            .app_data(Data::new(kms_server.clone()))
            .service(endpoint::kmip)
            .service(endpoint::insert_access)
            .service(endpoint::delete_access),
    )
    .await
}

pub async fn post<B, O, R, S>(app: &S, operation: O) -> KResult<R>
where
    O: Serialize,
    R: DeserializeOwned,
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: MessageBody,
{
    let req = test::TestRequest::post()
        .uri("/kmip/2_1")
        .insert_header(("Authorization", format!("Bearer {AUTH0_TOKEN}")))
        .set_json(to_ttlv(&operation)?)
        .to_request();
    let body = test::call_and_read_body(&app, req).await;
    let json: TTLV = serde_json::from_slice(&body)?;
    let result: R = from_ttlv(&json)?;
    Ok(result)
}

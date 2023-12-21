use std::sync::{mpsc, Arc, RwLock};

use actix_cors::Cors;
use actix_identity::IdentityMiddleware;
use actix_web::{
    dev::ServerHandle,
    middleware::Condition,
    web::{self, Data, JsonConfig, PayloadConfig},
    App, HttpServer,
};
use openssl::{
    ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod, SslVerifyMode},
    x509::store::X509StoreBuilder,
};
use tracing::info;

use crate::{
    config::{self, ServerParams},
    core::KMS,
    kms_bail, kms_error,
    middlewares::{
        ssl_auth::{extract_peer_certificate, SslAuth},
        JwtAuth, JwtConfig,
    },
    result::{KResult, KResultHelper},
    routes::{
        self,
        google_cse::{self, GoogleCseConfig},
    },
    KMSServer,
};

/// Starts the Key Management System (KMS) server based on the provided configuration.
///
/// The server is started using one of three methods:
/// 1. Plain HTTP,
/// 2. HTTPS with PKCS#12,
///
/// The method used depends on the server settings specified in the `ServerParams` instance provided.
///
/// # Arguments
///
/// * `server_params` - An instance of `ServerParams` that contains the settings for the server.
/// * `server_handle_transmitter` - An optional sender channel of type `mpsc::Sender<ServerHandle>` that can be used to manage server state.
///
/// # Errors
///
/// This function will return an error if any of the server starting methods fails.
pub async fn start_kms_server(
    server_params: ServerParams,
    kms_server_handle_tx: Option<mpsc::Sender<ServerHandle>>,
) -> KResult<()> {
    // Log the server configuration
    info!("KMS Server configuration: {:#?}", server_params);
    match &server_params.http_params {
        config::HttpParams::Https(_) => {
            start_https_kms_server(server_params, kms_server_handle_tx).await
        }
        config::HttpParams::Http => {
            start_plain_http_kms_server(server_params, kms_server_handle_tx).await
        }
    }
}

/// Start a plain HTTP KMS server
///
/// This function will instantiate and prepare the KMS server and run it on a plain HTTP connection
///
/// # Arguments
///
/// * `server_params` - An instance of `ServerParams` that contains the settings for the server.
/// * `server_handle_transmitter` - An optional sender channel of type `mpsc::Sender<ServerHandle>` that can be used to manage server state.
///
/// # Errors
///
/// This function returns an error if:
/// - The KMS server cannot be instantiated or prepared
/// - The server fails to run
async fn start_plain_http_kms_server(
    server_params: ServerParams,
    server_handle_transmitter: Option<mpsc::Sender<ServerHandle>>,
) -> KResult<()> {
    // Instantiate and prepare the KMS server
    let kms_server = Arc::new(KMSServer::instantiate(server_params).await?);

    // Prepare the server
    let server = prepare_kms_server(kms_server, None).await?;

    // send the server handle to the caller
    if let Some(tx) = &server_handle_transmitter {
        tx.send(server.handle())?;
    }

    info!("Starting the HTTP KMS server...");
    // Run the server and return the result
    server.await.map_err(Into::into)
}

/// Start an HTTPS KMS server using a PKCS#12 certificate file
///
/// # Arguments
///
/// * `server_params` - An instance of `ServerParams` that contains the settings for the server.
/// * `server_handle_transmitter` - An optional sender channel of type `mpsc::Sender<ServerHandle>` that can be used to manage server state.
///
/// # Errors
///
/// This function returns an error if:
/// - The path to the PKCS#12 certificate file is not provided in the config
/// - The file cannot be opened or read
/// - The file is not a valid PKCS#12 format or the password is incorrect
/// - The SSL acceptor cannot be created or configured with the certificate and key
/// - The KMS server cannot be instantiated or prepared
/// - The server fails to run
async fn start_https_kms_server(
    server_params: ServerParams,
    server_handle_transmitter: Option<mpsc::Sender<ServerHandle>>,
) -> KResult<()> {
    let p12 = match &server_params.http_params {
        config::HttpParams::Https(p12) => p12,
        _ => kms_bail!("http/s: a PKCS#12 file must be provided"),
    };

    // Create and configure an SSL acceptor with the certificate and key
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    if let Some(pkey) = &p12.pkey {
        builder.set_private_key(pkey)?;
    }
    if let Some(cert) = &p12.cert {
        builder.set_certificate(cert)?;
    }
    if let Some(chain) = &p12.ca {
        for x in chain {
            builder.add_extra_chain_cert(x.to_owned())?;
        }
    }

    if let Some(verify_cert) = &server_params.client_cert {
        // This line sets the mode to verify peer (client) certificates
        builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        let mut store_builder = X509StoreBuilder::new()?;
        store_builder.add_cert(verify_cert.clone())?;
        builder.set_verify_cert_store(store_builder.build())?;
    }

    // Instantiate and prepare the KMS server
    let kms_server = Arc::new(KMSServer::instantiate(server_params).await?);
    let server = prepare_kms_server(kms_server, Some(builder)).await?;

    // send the server handle to the caller
    if let Some(tx) = &server_handle_transmitter {
        tx.send(server.handle())?;
    }

    info!("Starting the HTTPS KMS server...");

    // Run the server and return the result
    server.await.map_err(Into::into)
}

/**
 * This function prepares a server for the application. It creates an `HttpServer` instance,
 * configures the routes for the application, and sets the request timeout. The server can be
 * configured to use OpenSSL for SSL encryption by providing an `SslAcceptorBuilder`.
 *
 * # Arguments
 *
 * * `kms_server`: A shared reference to the `KMS` instance to be used by the application.
 * * `builder`: An optional `SslAcceptorBuilder` to configure the SSL encryption for the server.
 *
 * # Returns
 *
 * Returns a `Result` type that contains a `Server` instance if successful, or an error if
 * something went wrong.
 *
 */
pub async fn prepare_kms_server(
    kms_server: Arc<KMS>,
    builder: Option<SslAcceptorBuilder>,
) -> KResult<actix_web::dev::Server> {
    // Determine if JWT Auth should be used for authentication.
    let (use_jwt_auth, jwt_config) = if let Some(jwt_issuer_uri) = &kms_server.params.jwt_issuer_uri
    {
        (
            true,
            Some(Arc::new(JwtConfig {
                jwt_issuer_uri: jwt_issuer_uri.clone(),
                jwks: RwLock::new(
                    kms_server
                        .params
                        .jwks
                        .as_ref()
                        .ok_or_else(|| {
                            kms_error!("The JWKS must be provided when using JWT authentication")
                        })?
                        .clone(),
                ),
                jwt_audience: kms_server.params.jwt_audience.clone(),
            })),
        )
    } else {
        (false, None)
    };
    // Determine if Client Cert Auth should be used for authentication.
    let use_cert_auth = kms_server.params.client_cert.is_some();

    // Determine if the application is using an encrypted SQLite database.
    let is_using_sqlite_enc = matches!(
        kms_server.params.db_params,
        Some(config::DbParams::SqliteEnc(_))
    );

    // Determine the address to bind the server to.
    let address = format!("{}:{}", kms_server.params.hostname, kms_server.params.port);

    // Check if this auth server is enabled for Google Client-Side Encryption
    let enable_google_cse = kms_server.params.google_cse_kacls_url.is_some();

    // Get the Google Client-Side Encryption JWT authorization config
    let google_cse_jwt_config = if enable_google_cse {
        Some(GoogleCseConfig {
            authentication: jwt_config.clone().context(
                "When using Google client-side encryption, an identity provider used to \
                 authenticate Google Workspace users must be configured.",
            )?,
            authorization: google_cse::jwt_authorization_config().await?,
            kacls_url: kms_server.params.google_cse_kacls_url.clone().context(
                "The Google Workspace Client Side Encryption KACLS URL must be provided",
            )?,
        })
    } else {
        None
    };

    // Create the `HttpServer` instance.
    let server = HttpServer::new(move || {
        // Create an `App` instance and configure the passed data and the various scopes
        let mut app = App::new()
            .wrap(IdentityMiddleware::default())
            .app_data(Data::new(kms_server.clone())) // Set the shared reference to the `KMS` instance.
            .app_data(PayloadConfig::new(10_000_000_000)) // Set the maximum size of the request payload.
            .app_data(JsonConfig::default().limit(10_000_000_000)); // Set the maximum size of the JSON request payload.;

        if enable_google_cse {
            // The scope for the Google Client-Side Encryption endpoints served from /google_cse
            let google_cse_scope = web::scope("/google_cse")
                .app_data(Data::new(google_cse_jwt_config.clone()))
                .wrap(Cors::permissive())
                .service(routes::google_cse::get_status)
                .service(routes::google_cse::wrap)
                .service(routes::google_cse::unwrap);
            app = app.service(google_cse_scope);
        }

        // The default scope serves from the root / the KMIP, permissions and tee endpoints
        let default_scope = web::scope("")
            .wrap(Condition::new(
                use_jwt_auth,
                JwtAuth::new(jwt_config.clone()),
            )) // Use JWT for authentication if necessary.
            .wrap(Condition::new(use_cert_auth, SslAuth)) // Use certificates for authentication if necessary.
            // Enable CORS for the application.
            // Since Actix is running the middlewares in reverse order, it's important that the
            // CORS middleware is the last one so that the auth middlewares do not run on
            // preflight (OPTION) requests.
            .wrap(Cors::permissive())
            .service(routes::kmip::kmip)
            .service(routes::access::list_owned_objects)
            .service(routes::access::list_access_rights_obtained)
            .service(routes::access::list_accesses)
            .service(routes::access::grant_access)
            .service(routes::access::revoke_access)
            .service(routes::get_version);

        // The default scope is extended with the /new_database endpoint if the application is using an encrypted SQLite database.
        let default_scope = if is_using_sqlite_enc {
            default_scope.service(routes::add_new_database)
        } else {
            default_scope
        };

        app.service(default_scope)
    })
    .client_request_timeout(std::time::Duration::from_secs(10));

    Ok(match builder {
        Some(b) => {
            if use_cert_auth {
                // Start an HTTPS server with PKCS#12 with client cert auth
                server
                    .on_connect(extract_peer_certificate)
                    .bind_openssl(address, b)?
                    .run()
            } else {
                // Start an HTTPS server with PKCS#12 but not client cert auth
                server.bind_openssl(address, b)?.run()
            }
        }
        _ => server.bind(address)?.run(),
    })
}

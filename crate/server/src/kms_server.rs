use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    time::Duration,
};

use actix_cors::Cors;
use actix_web::{
    dev::ServerHandle,
    middleware::Condition,
    rt::{spawn, time::sleep},
    web::{self, Data, JsonConfig, PayloadConfig},
    App, HttpServer,
};
use openssl::{
    ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod, SslVerifyMode},
    x509::store::X509StoreBuilder,
};
use tee_attestation::is_running_inside_tee;
use tracing::{debug, error, info};

use crate::{
    config::{self, HttpParams, ServerParams},
    core::{certbot::Certbot, KMS},
    kms_bail, kms_error,
    middlewares::{
        ssl_auth::{extract_peer_certificate, SslAuth},
        JwtAuth, JwtConfig,
    },
    result::KResult,
    routes::{self},
    KMSServer,
};

/// Starts the Key Management System (KMS) server based on the provided configuration.
///
/// The server is started using one of three methods:
/// 1. Plain HTTP,
/// 2. HTTPS with PKCS#12,
/// 3. HTTPS with certbot.
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
        config::HttpParams::Certbot(_) => {
            start_certbot_https_kms_server(server_params, kms_server_handle_tx).await
        }
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
    let server = prepare_kms_server(kms_server, None)?;

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

    if let Some(verify_cert) = &server_params.verify_cert {
        // This line sets the mode to verify peer (client) certificates
        builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        let mut store_builder = X509StoreBuilder::new()?;
        store_builder.add_cert(verify_cert.clone())?;
        builder.set_verify_cert_store(store_builder.build())?;
    }

    // Instantiate and prepare the KMS server
    let kms_server = Arc::new(KMSServer::instantiate(server_params).await?);
    let server = prepare_kms_server(kms_server, Some(builder))?;

    // send the server handle to the caller
    if let Some(tx) = &server_handle_transmitter {
        tx.send(server.handle())?;
    }

    info!("Starting the HTTPS KMS server...");

    // Run the server and return the result
    server.await.map_err(Into::into)
}

/// Start and https server with the ability to renew its certificates
async fn start_auto_renew_https(
    server_params: ServerParams,
    certbot: &Arc<Mutex<Certbot>>,
    server_handle_transmitter: Option<mpsc::Sender<ServerHandle>>,
) -> KResult<()> {
    let kms_server = Arc::new(KMSServer::instantiate(server_params).await?);

    // The loop is designed to restart the server in case it stops.
    // It stops when we renew the certificates
    loop {
        // Define an HTTPS server
        let (pk, x509) = certbot
            .lock()
            .expect("can't lock certificate mutex")
            .get_cert()?;

        debug!("Building the HTTPS server... ");
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        builder.set_private_key(&pk)?;
        builder.set_certificate(&x509[0])?;
        for x in x509 {
            builder.add_extra_chain_cert(x)?;
        }

        let server = prepare_kms_server(kms_server.clone(), Some(builder))?;

        // send the server handle to the caller
        if let Some(tx) = &server_handle_transmitter {
            tx.send(server.handle())?;
        }

        let restart = Arc::new(AtomicBool::new(false));
        let restart_me = Arc::clone(&restart);
        let srv = server.handle();
        let cert_copy = Arc::clone(certbot);

        // Define and start the thread renewing the certificate
        spawn(async move {
            let days_before_renew = cert_copy
                .lock()
                .expect("can't lock certificate mutex")
                .get_days_before_renew();
            let renew_in = match days_before_renew {
                Ok(x) => x,
                Err(error) => {
                    error!("Error when asking for renewing the certificate {error}");
                    0 // force the renew
                }
            };

            // Wait for the renew date.
            if renew_in > 0 {
                info!("Waiting {renew_in} days before renewing the certificate!");
                sleep(Duration::from_secs(renew_in as u64 * 3600 * 24)).await;
            }

            // It's time to renew!!
            info!("Updating certificate now...");
            let request_cert = cert_copy
                .lock()
                .expect("can't lock certificate mutex")
                .request_cert();
            match request_cert {
                Ok(()) => restart_me.store(true, Ordering::Relaxed),
                Err(error) => {
                    error!("Error when renewing the certificate {error}");
                    restart_me.store(false, Ordering::Relaxed);
                }
            }

            info!("Stopping the HTTPS server...");
            // Stop the HTTPS server. We don't need it anymore
            srv.stop(true).await;
        });

        // Run server until stopped (either by ctrl-c or stopped by the previous thread)
        info!("Starting the HTTPS KMS server...");
        server.await?;

        // We reach that part of the code when the thread renewing the certificates stops.
        if restart.load(Ordering::Relaxed) {
            restart.store(false, Ordering::Relaxed);
        } else {
            // If we reach that point, we don't want to restart.
            // Contact the administrator
            error!("Can't restart the HTTPS server (no valid certificate)...");
            kms_bail!("Can't restart the HTTPS server (no valid certificate)...")

            // Note: we could decide another behavior such as:
            // Let the server up. Then the web browser or the wget will raise a security error the user can ignore
            // That way, we don't stop our service.
        }
    }
}

async fn start_certbot_https_kms_server(
    server_params: ServerParams,
    server_handle_transmitter: Option<mpsc::Sender<ServerHandle>>,
) -> KResult<()> {
    // Before starting any servers, check the status of our SSL certificates
    let certbot = match &server_params.http_params {
        HttpParams::Certbot(certbot) => certbot.clone(),
        _ => kms_bail!("trying to start a TLS server but certbot is not used !"),
    };

    debug!("Initializing certbot");
    // Recover the previous certificate if exist
    certbot
        .lock()
        .expect("can't lock certificate mutex")
        .init()?;

    debug!("Checking certificates...");
    let mut has_valid_cert = certbot
        .lock()
        .expect("can't lock certificate mutex")
        .check();

    let http_root_path = certbot
        .lock()
        .expect("can't lock certificate mutex")
        .http_root_path
        .clone();

    if !has_valid_cert {
        info!("No valid certificate found!");
        info!("Starting certification process...");

        // Start a HTTP server, to negotiate a certificate
        let server = HttpServer::new(move || {
            App::new().service(actix_files::Files::new("/", &http_root_path).use_hidden_files())
        })
        .workers(1)
        .bind(("0.0.0.0", 80))?
        .run();
        // The server is not started yet here!

        let succeed = Arc::new(AtomicBool::new(false));
        let succeed_me = Arc::clone(&succeed);
        let srv = server.handle();
        let cert_copy = Arc::clone(&certbot);

        spawn(async move {
            // Generate the certificate in another thread
            info!("Requesting acme...");
            let request_cert = cert_copy
                .lock()
                .expect("can't lock certificate mutex")
                .request_cert();
            match request_cert {
                Ok(()) => succeed_me.store(true, Ordering::Relaxed),
                Err(error) => {
                    error!("Error when generating the certificate: {error}");
                    succeed_me.store(false, Ordering::Relaxed);
                }
            }

            // Stop the HTTP server. We don't need it anymore
            srv.stop(true).await;
        });

        // Run server until stopped (either by ctrl-c or stopped by the previous thread)
        info!("Starting the HTTP KMS server...");
        server.await?;

        // Note: cert_copy is a ref to cert. So `cert.certificates` contains the new certificates
        // Therefore, we do not need to call `cert.init()`. That way, we avoid several acme useless queries
        has_valid_cert = succeed.load(Ordering::Relaxed)
            && certbot
                .lock()
                .expect("can't lock certificate mutex")
                .check();

        info!("Stop the HTTP server");
    }

    if has_valid_cert {
        // Use it and start SSL Server
        info!("Certificate is valid");
        start_auto_renew_https(server_params, &certbot, server_handle_transmitter).await?;
    } else {
        error!("Abort program, failed to get a valid certificate");
        kms_bail!("Abort program, failed to get a valid certificate")
    }

    Ok(())
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
pub fn prepare_kms_server(
    kms_server: Arc<KMS>,
    builder: Option<SslAcceptorBuilder>,
) -> KResult<actix_web::dev::Server> {
    // Determine if JWT Auth should be used for authentication.
    let (use_jwt_auth, jwt_config) = if let Some(jwt_issuer_uri) = &kms_server.params.jwt_issuer_uri
    {
        (
            true,
            Some(JwtConfig {
                jwt_issuer_uri: jwt_issuer_uri.clone(),
                jwks: kms_server
                    .params
                    .jwks
                    .as_ref()
                    .ok_or_else(|| {
                        kms_error!("The JWKS must be provided when using JWT authentication")
                    })?
                    .clone(),
                jwt_audience: kms_server.params.jwt_audience.clone(),
            }),
        )
    } else {
        (false, None)
    };
    // Determine if Client Cert Auth should be used for authentication.
    let use_cert_auth = kms_server.params.verify_cert.is_some();
    // Determine if the application is running inside an enclave.
    // Determine if the application is using an encrypted SQLite database.
    let is_using_sqlite_enc = matches!(
        kms_server.params.db_params,
        Some(config::DbParams::SqliteEnc(_))
    );

    // Determine the address to bind the server to.
    let address = format!("{}:{}", kms_server.params.hostname, kms_server.params.port);

    // Create the `HttpServer` instance.
    let server = HttpServer::new(move || {
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
        // The default scope is extended with the /tee endpoints if the application is running inside an enclave.
        let default_scope = if is_running_inside_tee() {
            default_scope
                .service(routes::tee::get_enclave_public_key)
                .service(routes::tee::get_attestation_report)
        } else {
            default_scope
        };

        // The scope for the Google Client-Side Encryption endpoints served from /google_cse
        let google_cse_scope = web::scope("/google_cse")
            // The /status endpoint is not protected by authentication (but requires CORS)
            .service(routes::google_cse::get_status)
            .wrap(
                Cors::default()
                    .allowed_origin("https://admin.google.com")
                    .allowed_methods(vec!["GET", "POST"]),
            )
            // The other Google CSE endpoints are protected by authentication (and require CORS)
            .service(
                web::scope("")
                    // Use JWT for authentication if necessary.
                    .wrap(Condition::new(
                        use_jwt_auth,
                        JwtAuth::new(jwt_config.clone()),
                    ))
                    // CORS must come after  JWT since wrapper are tested in reverse order
                    .wrap(
                        Cors::default()
                            .allowed_origin("https://admin.google.com")
                            .allowed_methods(vec!["GET", "POST"]),
                    )
                    .service(routes::google_cse::say_blah),
            );

        // Create an `App` instance and configure the passed data and the various scopes
        App::new()
            .app_data(Data::new(kms_server.clone())) // Set the shared reference to the `KMS` instance.
            .app_data(PayloadConfig::new(10_000_000_000)) // Set the maximum size of the request payload.
            .app_data(JsonConfig::default().limit(10_000_000_000)) // Set the maximum size of the JSON request payload.
            .service(google_cse_scope)
            .service(default_scope)
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

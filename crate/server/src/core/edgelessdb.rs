use std::{fs, path::PathBuf};

use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    encrypt::Decrypter,
    error::ErrorStack,
    hash::MessageDigest,
    pkcs12::Pkcs12,
    pkey::{PKey, PKeyRef, Private},
    rsa::{Padding, Rsa},
    x509::{
        extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier},
        X509NameBuilder, X509Ref, X509Req, X509ReqBuilder, X509,
    },
};
use serde::{Deserialize, Serialize};

use crate::{error::KmsError, kms_bail, result::KResult};

// TODO: doc that
pub struct EdgelessDB {
    /// The path to the https certificate
    pub ssl_cert: PathBuf,

    /// The CA certificate
    ca_cert: PathBuf,
    /// The CA private key
    ca_key: PathBuf,
    /// The CA key size
    ca_key_size: u32,
    /// The CA certificate common name
    ca_cn: String,
    /// The CA certificate expiration date
    ca_exp: u32,

    /// The p12 envelop containing the certificate and the key pair
    pub user_p12: PathBuf,
    /// The user key size
    user_key_size: u32,
    /// The user certificate common name
    username: String,
    /// The user certificate expiration date
    user_exp: u32,

    /// The recovery key
    recovery_key: PathBuf,

    /// The manifest
    manifest: PathBuf,

    /// The url of the database
    pub url: String,

    /// The port to use when connecting through MYSQL
    pub sql_port: u16,
    /// The port to use when connecting through HTTP
    pub http_port: u16,
}

impl EdgelessDB {
    /// Fill the field of the structure
    pub fn new(
        private_path: PathBuf,
        public_path: PathBuf,
        url: String,
        sql_port: u16,
        http_port: u16,
    ) -> EdgelessDB {
        EdgelessDB {
            ssl_cert: private_path.join("ssl-cert.pem"),
            ca_cert: public_path.join("ca-cert.pem"),
            ca_key: public_path.join("ca-key.pem"),
            ca_key_size: 2048,
            ca_cn: "kms.edgeless".to_string(),
            // The CA certificate can't be changed later, so we put a very large
            // expiration date
            ca_exp: 360 * 10,
            user_p12: private_path.join("user.p12"),
            user_key_size: 2048,
            username: "kms_user".to_string(),
            user_exp: 360,
            recovery_key: public_path.join("master_key.plain"),
            manifest: private_path.join("manifest.json"),
            url,
            sql_port,
            http_port,
        }
    }
}

// TODO: how (why) to use the endpoint /signature?

/// Structure send by the edgeless when initializing the db
#[derive(Serialize, Deserialize, Debug)]
struct EdgelessManifest {
    sql: Vec<String>,
    ca: String,
    recovery: Option<String>,
}

/// Structure returned by the edgeless when querying the quote
#[derive(Serialize, Deserialize, Debug)]
struct EdgelessQuoteResponse {
    status: String,
    data: EdgelessQuotePayloadResponse,
}

/// Structure returned by the edgeless when querying the recover action
#[derive(Serialize, Deserialize, Debug)]
struct EdgelessRecoverResponse {
    status: String,
    data: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct EdgelessQuotePayloadResponse {
    #[serde(alias = "Cert")]
    cert: String,
    #[serde(alias = "Quote")]
    quote: Option<String>,
}

impl EdgelessDB {
    /// Make a CA certificate and private key
    fn generate_ca_cert(&self) -> Result<(X509, PKey<Private>), ErrorStack> {
        let rsa = Rsa::generate(self.ca_key_size)?;
        let key_pair = PKey::from_rsa(rsa)?;

        let mut x509_name = X509NameBuilder::new()?;
        x509_name.append_entry_by_text("CN", &self.ca_cn)?;
        let x509_name = x509_name.build();

        let mut cert_builder = X509::builder()?;
        cert_builder.set_version(2)?;
        let serial_number = {
            let mut serial = BigNum::new()?;
            serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
            serial.to_asn1_integer()?
        };
        cert_builder.set_serial_number(&serial_number)?;
        cert_builder.set_subject_name(&x509_name)?;
        cert_builder.set_issuer_name(&x509_name)?;
        cert_builder.set_pubkey(&key_pair)?;
        let not_before = Asn1Time::days_from_now(0)?;
        cert_builder.set_not_before(&not_before)?;
        let not_after = Asn1Time::days_from_now(self.ca_exp)?;
        cert_builder.set_not_after(&not_after)?;

        cert_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
        cert_builder.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()?,
        )?;

        let subject_key_identifier =
            SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
        cert_builder.append_extension(subject_key_identifier)?;

        cert_builder.sign(&key_pair, MessageDigest::sha256())?;
        let cert = cert_builder.build();

        Ok((cert, key_pair))
    }

    /// Make a X509 request with the given private key
    fn generate_user_cert(&self, key_pair: &PKey<Private>) -> Result<X509Req, ErrorStack> {
        let mut req_builder = X509ReqBuilder::new()?;
        req_builder.set_pubkey(key_pair)?;

        let mut x509_name = X509NameBuilder::new()?;
        x509_name.append_entry_by_text("CN", &self.username)?;
        let x509_name = x509_name.build();
        req_builder.set_subject_name(&x509_name)?;

        req_builder.sign(key_pair, MessageDigest::sha256())?;
        let req = req_builder.build();
        Ok(req)
    }

    /// Make a certificate and private key signed by the given CA cert and private key
    fn generate_ca_signed_user_cert(
        &self,
        ca_cert: &X509Ref,
        ca_key_pair: &PKeyRef<Private>,
    ) -> Result<(X509, PKey<Private>), ErrorStack> {
        let rsa = Rsa::generate(self.user_key_size)?;
        let key_pair = PKey::from_rsa(rsa)?;

        let req = self.generate_user_cert(&key_pair)?;

        let mut cert_builder = X509::builder()?;
        cert_builder.set_version(2)?;
        let serial_number = {
            let mut serial = BigNum::new()?;
            serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
            serial.to_asn1_integer()?
        };
        cert_builder.set_serial_number(&serial_number)?;
        cert_builder.set_subject_name(req.subject_name())?;
        cert_builder.set_issuer_name(ca_cert.subject_name())?;
        cert_builder.set_pubkey(&key_pair)?;
        let not_before = Asn1Time::days_from_now(0)?;
        cert_builder.set_not_before(&not_before)?;
        let not_after = Asn1Time::days_from_now(self.user_exp)?;
        cert_builder.set_not_after(&not_after)?;

        cert_builder.append_extension(BasicConstraints::new().build()?)?;

        cert_builder.append_extension(
            KeyUsage::new()
                .critical()
                .non_repudiation()
                .digital_signature()
                .key_encipherment()
                .build()?,
        )?;

        let subject_key_identifier =
            SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
        cert_builder.append_extension(subject_key_identifier)?;

        let auth_key_identifier = AuthorityKeyIdentifier::new()
            .keyid(false)
            .issuer(false)
            .build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
        cert_builder.append_extension(auth_key_identifier)?;

        /*
           let subject_alt_name = SubjectAlternativeName::new()
               .dns("*.example.com")
               .dns("hello.com")
               .build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
           cert_builder.append_extension(subject_alt_name)?;
        */

        cert_builder.sign(ca_key_pair, MessageDigest::sha256())?;
        let cert = cert_builder.build();

        Ok((cert, key_pair))
    }

    /// Create the manifest from the CA certificate and the recover key
    fn generate_manifest(&self, ca_cert: X509, recovery_key: &PKey<Private>) -> KResult<String> {
        let manifest = EdgelessManifest {
            // TODO: not too much rights
            sql: vec![
                format!(
                    "CREATE USER root REQUIRE ISSUER '/CN={}' SUBJECT '/CN={}'",
                    &self.ca_cn, &self.username
                ),
                "GRANT ALL ON *.* TO root WITH GRANT OPTION".to_string(),
                "CREATE DATABASE kms".to_string(),
            ],
            ca: std::str::from_utf8(&ca_cert.to_pem()?)?.to_string(),
            recovery: Some(std::str::from_utf8(&recovery_key.public_key_to_pem()?)?.to_string()),
        };

        let manifest = serde_json::to_string_pretty(&manifest)?;

        fs::write(&self.manifest, &manifest)?;

        Ok(manifest)
    }

    // Generate a recovery key for the EdgelessDB
    fn generate_recovery_key(&self) -> Result<PKey<Private>, ErrorStack> {
        let rsa = Rsa::generate(3072)?;
        PKey::from_rsa(rsa)
    }

    /// Send the manifest to the Edgeless in order to initialise it
    async fn initialize_edgeless_db(
        &self,
        ca_cert: X509,
        recovery_key: PKey<Private>,
        edgeless_ssl_cert: X509,
    ) -> KResult<()> {
        // Forge a manifest
        let manifest = self.generate_manifest(ca_cert, &recovery_key)?;

        // Send the manifest to the edgeless
        let cert = reqwest::Certificate::from_pem(&edgeless_ssl_cert.to_pem()?)?;
        let build = reqwest::Client::builder().add_root_certificate(cert);

        let res = build
            .build()?
            .post(format!(
                "https://{}:{}/manifest",
                &self.url, &self.http_port
            ))
            .body(manifest)
            .send()
            .await?;

        let status_code = res.status();
        if !status_code.is_success() {
            kms_bail!(KmsError::EdgelessDBError(format!(
                "Failed to send manifest (status_code={status_code} | error={})",
                res.text().await?
            )))
        }

        // Recover the master key (to recover the db later)
        let master_key = res.text().await?;
        let master_key = base64::decode(master_key)?;

        // Decrypt the recovery master key with the recovery private key
        let mut decrypter = Decrypter::new(&recovery_key)?;
        decrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
        decrypter.set_rsa_oaep_md(MessageDigest::sha256())?;

        // Get the length of the output buffer
        let buffer_len = decrypter.decrypt_len(&master_key)?;
        let mut decoded = vec![0u8; buffer_len];

        // Decrypt the data and get its length
        let decoded_len = decrypter.decrypt(&master_key, &mut decoded)?;

        // Use only the part of the buffer with the decrypted data
        let decoded = &decoded[..decoded_len];

        // Save it for later
        fs::write(&self.recovery_key, decoded)?;

        Ok(())
    }

    /// Get the EdgelessDB ssl cert from the database
    async fn get_edgeless_ssl_cert(&self) -> KResult<X509> {
        let build = reqwest::Client::builder().danger_accept_invalid_certs(true);

        let res = build
            .build()?
            .get(format!("https://{}:{}/quote", &self.url, &self.http_port))
            .send()
            .await?;

        let status_code = res.status();
        if !status_code.is_success() {
            kms_bail!(KmsError::EdgelessDBError(format!(
                "Failed to get the EdgelessDB ssl cert (status_code={status_code} | error={})",
                res.text().await?
            )))
        }

        let res = res.json::<EdgelessQuoteResponse>().await?;

        Ok(X509::from_pem(res.data.cert.as_bytes())?)
        // TODO: check the quote before proceeding
    }

    /// Recover a EdgelessDB if it requires it
    pub async fn recover_after_migration(&self) -> KResult<()> {
        // Note: to generate such a case for test purposes, proceed as follow:
        // 1. The edgeless docker should have been firstly started using  -v /home/user/local_dir:/data and stopped
        // 2. Rm file /home/user/local_dir/edb-persistence/sealed_key as root user
        // 3. Restart the docker. The edgeless should be entered into recovery mode

        // Get the temporary ssl certs
        let cert = self.get_edgeless_ssl_cert().await?;

        let cert = reqwest::Certificate::from_pem(&cert.to_pem()?)?;
        let build = reqwest::Client::builder().add_root_certificate(cert);

        let res = build
            .build()?
            .post(format!("https://{}:{}/recover", &self.url, &self.http_port))
            .body(fs::read(&self.recovery_key)?)
            .send()
            .await?;

        let status_code = res.status();
        if !status_code.is_success() {
            kms_bail!(KmsError::EdgelessDBError(format!(
                "Failed to query the EdgelessDB recover endpoint (status_code={status_code} | \
                 error={})",
                res.text().await?
            )))
        }

        let res = res.json::<EdgelessRecoverResponse>().await?;
        if res.data != "Recovery successful." {
            kms_bail!(KmsError::EdgelessDBError(format!(
                "Failed to recover the EdgelessDB (output={res:?})"
            ),))
        }

        // Note: {"status":"success","data":"Recovery failed: edb is not in expected state"}

        Ok(())
    }

    /// Initialize the EdgelessDB
    pub async fn init_first_time(&self) -> KResult<()> {
        // First of all: generate the CA certificate
        let (ca_cert, ca_key_pair) = self.generate_ca_cert()?;

        fs::write(&self.ca_cert, &ca_cert.to_pem()?)?;
        fs::write(&self.ca_key, &ca_key_pair.private_key_to_pem_pkcs8()?)?;

        // Generate a recover key
        let recovery_key = self.generate_recovery_key()?;

        // Get the SSL cert from the edgeless
        let edgeless_ssl_cert = self.get_edgeless_ssl_cert().await?;

        fs::write(&self.ssl_cert, &edgeless_ssl_cert.to_pem()?)?;

        // Send the manifest to the edgeless and get the recovery master key
        self.initialize_edgeless_db(ca_cert, recovery_key, edgeless_ssl_cert)
            .await?;

        Ok(())
    }

    /// Intiliaze a new user connection to the EdgelessDB
    pub async fn connect_after_init(&self) -> KResult<Pkcs12> {
        // Generate a user certificate and sign it with the CA
        let ca_cert = fs::read(&self.ca_cert)?;
        let ca_key_pair = fs::read(&self.ca_key)?;

        let ca_cert = X509::from_pem(&ca_cert)?;
        let ca_key_pair = PKey::private_key_from_pem(&ca_key_pair)?;

        let (cert, key_pair) = self.generate_ca_signed_user_cert(&ca_cert, &ca_key_pair)?;

        let pkcs12_builder = Pkcs12::builder();
        let pkcs12 = pkcs12_builder.build("", "", &key_pair, &cert)?;

        fs::write(&self.user_p12, &pkcs12.to_der()?)?;

        Ok(pkcs12)
    }
}

#[cfg(test)]
mod tests {
    use core::time;
    use std::{
        fs::{create_dir_all, remove_dir_all, remove_file},
        path::PathBuf,
        process::{Command, Stdio},
        thread,
    };

    // use mysql::ClientIdentity;
    use mysql::{prelude::*, SslOpts, *};
    use serial_test::serial;

    use super::EdgelessDB;
    use crate::{error::KmsError, result::KResult};

    const WORKDIR: &str = "/tmp/data";
    const DOCKERNAME: &str = "edgelessdb-test";

    fn query_edgeless(db: &EdgelessDB) -> KResult<Vec<String>> {
        let client = SslOpts::default();
        let ssl_opts = client
            .with_pkcs12_path(Some(db.user_p12.clone()))
            .with_root_cert_path(Some(db.ssl_cert.clone()));

        let opts = Opts::from_url(&format!("mysql://root@{}:{}/kms", db.url, db.sql_port))
            .map_err(|e| KmsError::ServerError(e.to_string()))?;

        let builder = OptsBuilder::from_opts(opts).ssl_opts(ssl_opts);

        let pool = Pool::new(builder)?;
        let mut conn = pool.get_conn()?;

        let val: Vec<String> = conn.query("SHOW DATABASES")?;

        Ok(val)
    }

    fn get_user_and_group() -> KResult<(String, String)> {
        let id = Command::new("id").arg("-u").output()?;
        let group = Command::new("id").arg("-g").output()?;

        Ok((
            String::from_utf8(id.stdout).unwrap().trim().to_string(),
            String::from_utf8(group.stdout).unwrap().trim().to_string(),
        ))
    }

    fn start_edgeless_docker(sql_port: u16, http_port: u16) -> KResult<()> {
        _ = Command::new("docker")
            .arg("pull")
            .arg("ghcr.io/edgelesssys/edgelessdb-sgx-1gb")
            .output()?;

        create_dir_all(WORKDIR).expect("Can't create WORKDIR dir");

        Command::new("docker")
            .arg("run")
            .arg("--rm")
            .arg("--name")
            .arg(DOCKERNAME)
            .arg("-v")
            .arg(format!("{WORKDIR}:/data"))
            .arg(format!("-p{}:3306", sql_port))
            .arg(format!("-p{}:8080", http_port))
            .arg("-e")
            .arg("OE_SIMULATION=1")
            .arg("-t")
            .arg("ghcr.io/edgelesssys/edgelessdb-sgx-1gb")
            .stdout(Stdio::null())
            .spawn()?;

        thread::sleep(time::Duration::from_secs(10));
        Ok(())
    }

    fn fix_workspace_owner() -> KResult<()> {
        // We need to fix the ownership of the database files before being able to remove them
        let (id, group) = get_user_and_group()?;

        _ = Command::new("docker")
            .arg("exec")
            .arg(DOCKERNAME)
            .arg("chown")
            .arg("-R")
            .arg(format!("{id}:{group}"))
            .arg("/data")
            .output()?;

        Ok(())
    }

    fn stop_edgeless_docker() -> KResult<()> {
        fix_workspace_owner()?;

        _ = Command::new("docker")
            .arg("stop")
            .arg(DOCKERNAME)
            .output()?;

        _ = Command::new("docker").arg("rm").arg(DOCKERNAME).output()?;

        remove_dir_all(WORKDIR)?;
        Ok(())
    }

    fn delete_edgeless_docker() -> KResult<()> {
        Command::new("docker")
            .arg("rmi")
            .arg("ghcr.io/edgelesssys/edgelessdb-sgx-1gb")
            .output()?;

        Ok(())
    }

    #[actix_rt::test]
    #[serial(edgelessdb)]
    pub async fn test_edgelessdb_0_initialize() {
        stop_edgeless_docker().ok();
        delete_edgeless_docker().ok();

        // We use non standard port to avoid any conflicts with other tests outside this file
        let db = EdgelessDB::new(
            PathBuf::from(WORKDIR),
            PathBuf::from(WORKDIR),
            "localhost".to_string(),
            3307,
            8081,
        );

        // No edgeless started
        let r = db.init_first_time().await;
        assert!(r.is_err());

        // Edgeless started
        start_edgeless_docker(db.sql_port, db.http_port).expect("Fail to start edgeless");
        let r = db.init_first_time().await;
        assert!(r.is_ok());

        // Edgeless already initialized
        let r = db.init_first_time().await;
        thread::sleep(time::Duration::from_secs(5));
        assert!(r.is_err());

        stop_edgeless_docker().expect("Fail to stop edgeless");
    }

    #[actix_rt::test]
    #[serial(edgelessdb)]
    pub async fn test_edgelessdb_1_connect_after_init() {
        stop_edgeless_docker().ok();
        delete_edgeless_docker().ok();

        // We use non standard port to avoid any conflicts with other tests outside this file
        let db = EdgelessDB::new(
            PathBuf::from(WORKDIR),
            PathBuf::from(WORKDIR),
            "localhost".to_string(),
            3307,
            8081,
        );

        // No edgeless started
        let r = db.connect_after_init().await;
        assert!(r.is_err());

        // Edgeless started but not init
        start_edgeless_docker(db.sql_port, db.http_port).expect("Fail to start edgeless");
        let r = db.connect_after_init().await;
        assert!(r.is_err());

        // Edgeless started
        _ = db.init_first_time().await.expect("Can't init the database");
        thread::sleep(time::Duration::from_secs(5));
        let r = db.connect_after_init().await;
        assert!(r.is_ok());
        let r = query_edgeless(&db);
        assert!(r.is_ok());
        assert_eq!(
            r.unwrap(),
            ["$edgeless", "information_schema", "kms", "mysql",]
        );

        stop_edgeless_docker().expect("Fail to stop edgeless");
    }

    #[actix_rt::test]
    #[serial(edgelessdb)]
    pub async fn test_edgelessdb_2_recover_after_migration() {
        stop_edgeless_docker().ok();
        delete_edgeless_docker().ok();

        // We use non standard port to avoid any conflicts with other tests outside this file
        let db = EdgelessDB::new(
            PathBuf::from(WORKDIR),
            PathBuf::from(WORKDIR),
            "localhost".to_string(),
            3307,
            8081,
        );

        // No edgeless started
        let r = db.recover_after_migration().await;
        assert!(r.is_err());

        // Edgeless started but not init
        start_edgeless_docker(db.sql_port, db.http_port).expect("Fail to start edgeless");
        let r = db.recover_after_migration().await;
        assert!(r.is_err());

        // Edgeless started&init but not in recovery mode
        _ = db.init_first_time().await.expect("Can't init the database");
        thread::sleep(time::Duration::from_secs(5));
        db.connect_after_init().await.expect("Can't init the user");
        let r = db.recover_after_migration().await;
        assert!(r.is_err());

        // Edgeless started and put in recovery mode
        fix_workspace_owner().expect("Can't fix permissions");
        remove_file(format!("{WORKDIR}/edb-persistence/sealed_key"))
            .expect("Can't remove file WORKDIR the database");

        let r = query_edgeless(&db);
        assert!(r.is_ok());

        Command::new("docker")
            .arg("stop")
            .arg(DOCKERNAME)
            .output()
            .expect("Can't stop database");

        start_edgeless_docker(db.sql_port, db.http_port).expect("Fail to start edgeless");

        let r = query_edgeless(&db);
        assert!(r.is_err());
        let r = db.recover_after_migration().await;
        assert!(r.is_ok());
        let r = query_edgeless(&db);
        assert!(r.is_ok());

        stop_edgeless_docker().expect("Fail to stop edgeless");
    }
}

use openssl::{
    pkey::{PKey, Private},
    x509::X509,
};
use ratls::generate::{generate_ratls_cert, RatlsKeyGenerationType};

use crate::{error, result::KResult};
pub(crate) fn generate_self_signed_ra_tls_cert(
    subject: &str,
    expiration_days: u64,
) -> KResult<(PKey<Private>, X509)> {
    let (private_key, cert) = generate_ratls_cert(
        subject,
        vec![],
        expiration_days,
        None,
        RatlsKeyGenerationType::Random,
    )
    .map_err(|e| error::KmsError::RatlsError(e.to_string()))?;

    let cert = X509::from_pem(cert.as_bytes())?;
    let private_key = PKey::private_key_from_pem(private_key.as_bytes())?;

    Ok((private_key, cert))
}
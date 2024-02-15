// This file exists to standardize key-derivation across all KMS crates
#[cfg(not(feature = "fips"))]
use argon2::Argon2;
use openssl::rand::rand_bytes;
#[cfg(feature = "fips")]
use openssl::{hash::MessageDigest, pkcs5::pbkdf2_hmac};

use super::secret::Secret;
use crate::error::KmipError;
#[cfg(feature = "fips")]
use crate::kmip_bail;

const FIPS_MIN_SALT_SIZE: usize = 16;
#[cfg(feature = "fips")]
const FIPS_HLEN_BITS: usize = 512;
#[cfg(feature = "fips")]
const FIPS_MIN_KLEN: usize = 14;
#[cfg(feature = "fips")]
/// Max key length authorized is (2^32 - 1) x hLen.
/// Source: NIST.FIPS.800-132 - Section 5.3.
const FIPS_MAX_KLEN: usize = ((1 << 32) - 1) * FIPS_HLEN_BITS;

#[cfg(feature = "fips")]
/// OWASP recommended parameter for SHA-512 chosen following NIST.FIPS.800-132
/// recommendations.
const FIPS_MIN_ITER: usize = 210_000;

/// Derive a key into a LENGTH bytes key using Argon 2 by default, and PBKDF2
/// with SHA512 in FIPS mode.
#[cfg(feature = "fips")]
pub fn derive_key_from_password<const LENGTH: usize>(
    password: &[u8],
) -> Result<Secret<LENGTH>, KmipError> {
    // Check requested key length is in the authorized bounds.
    if LENGTH < FIPS_MIN_KLEN || LENGTH * 8 > FIPS_MAX_KLEN {
        kmip_bail!("Password derivation error: wrong output length argument, got {LENGTH}")
    }

    let mut output_key_material = Secret::<LENGTH>::new();

    // Generate 128 bits of random salt.
    let mut salt = vec![0u8; FIPS_MIN_SALT_SIZE];
    rand_bytes(&mut salt)?;

    pbkdf2_hmac(
        password,
        &salt,
        FIPS_MIN_ITER,
        MessageDigest::sha512(),
        output_key_material.as_mut(),
    )?;

    Ok(output_key_material)
}

/// Derive a key into a LENGTH bytes key using Argon 2 by default, and PBKDF2
/// with SHA512 in FIPS mode.
#[cfg(not(feature = "fips"))]
pub fn derive_key_from_password<const LENGTH: usize>(
    password: &[u8],
) -> Result<Secret<LENGTH>, KmipError> {
    let mut output_key_material = Secret::<LENGTH>::new();

    // Generate 128 bits of random salt
    let mut salt = vec![0u8; FIPS_MIN_SALT_SIZE];
    rand_bytes(&mut salt)?;

    Argon2::default()
        .hash_password_into(password, &salt, output_key_material.as_mut())
        .map_err(|e| KmipError::Derivation(e.to_string()))?;

    Ok(output_key_material)
}

#[test]
fn test_password_derivation() {
    #[cfg(feature = "fips")]
    // Load FIPS provider module from OpenSSL.
    openssl::provider::Provider::load(None, "fips").unwrap();

    let my_weak_password = "doglover1234".as_bytes().to_vec();
    let secure_mk = derive_key_from_password::<32>(&my_weak_password).unwrap();

    assert_eq!(secure_mk.len(), 32);
}

#[test]
#[cfg(feature = "fips")]
fn test_password_derivation_bad_size() {
    // Load FIPS provider module from OpenSSL.
    openssl::provider::Provider::load(None, "fips").unwrap();

    let my_weak_password = "123princ3ss".as_bytes().to_vec();
    let secure_mk_res = derive_key_from_password::<13>(&my_weak_password);

    assert!(secure_mk_res.is_err());

    const BIG_KEY_LENGTH: usize = (((1 << 32) - 1) * 512) / 8 + 1;
    let secure_mk_res = derive_key_from_password::<BIG_KEY_LENGTH>(&my_weak_password);

    assert!(secure_mk_res.is_err());
}

use std::collections::HashSet;

use cloudproof::reexport::cover_crypt::Covercrypt;
use cosmian_hsm_traits::{HsmKeypairAlgorithm, HSM};
#[cfg(not(feature = "fips"))]
use cosmian_kmip::crypto::elliptic_curves::operation::{
    create_x25519_key_pair, create_x448_key_pair,
};
use cosmian_kmip::{
    crypto::{
        cover_crypt::master_keys::create_master_keypair,
        elliptic_curves::operation::{
            create_approved_ecc_key_pair, create_ed25519_key_pair, create_ed448_key_pair,
        },
        rsa::operation::create_rsa_key_pair,
        KeyPair,
    },
    kmip::{
        kmip_operations::{CreateKeyPair, CreateKeyPairResponse},
        kmip_types::{Attributes, CryptographicAlgorithm, RecommendedCurve, UniqueIdentifier},
    },
};
#[cfg(not(feature = "fips"))]
use tracing::warn;
use tracing::{debug, trace};
use uuid::Uuid;

use crate::{
    core::{extra_database_params::ExtraStoreParams, KMS},
    database::AtomicOperation,
    error::KmsError,
    kms_bail,
    result::KResult,
};

pub(crate) async fn create_key_pair(
    kms: &KMS,
    request: CreateKeyPair,
    owner: &str,
    params: Option<&ExtraStoreParams>,
) -> KResult<CreateKeyPairResponse> {
    trace!("Create key pair: {}", serde_json::to_string(&request)?);

    // An HSM CreateKeyPair request will have a uid in the form of "ham::<slot_id>"
    if let Some(uid) = request
        .private_key_attributes
        .as_ref()
        .and_then(|attrs| attrs.unique_identifier.as_ref())
        .or_else(|| {
            request
                .common_attributes
                .as_ref()
                .and_then(|attrs| attrs.unique_identifier.as_ref())
        })
        .map(|x| x.to_string())
    {
        if uid.starts_with("hsm::") {
            return if let Some(hsm) = &kms.hsm {
                if owner != kms.params.hsm_admin {
                    return Err(KmsError::InvalidRequest(
                        "Only the Super Admin can create HSM objects".to_owned(),
                    ));
                }
                create_hsm_keypair(&request, hsm, &uid).await
            } else {
                Err(KmsError::NotSupported(
                    "This server does not support HSM operations".to_owned(),
                ))
            }
        }
    }

    create_kms_keypair(kms, request, owner, params).await
}

async fn create_hsm_keypair(
    request: &CreateKeyPair,
    hsm: &Box<dyn HSM + Send + Sync>,
    uid: &str,
) -> KResult<CreateKeyPairResponse> {
    // try converting the rest of the uid into a slot_id
    let slot_id = uid
        .trim_start_matches("hsm::")
        .parse::<usize>()
        .map_err(|e| {
            KmsError::InvalidRequest(format!(
                "An HSM create request must have a uid in the form of 'hsm::<slot_id>': {e}"
            ))
        })?;
    let attributes = request
        .private_key_attributes
        .as_ref()
        .or_else(|| request.common_attributes.as_ref())
        .ok_or_else(|| {
            KmsError::InvalidRequest(
                "Attributes must be provided in a CreateKeyPair request".to_owned(),
            )
        })?;
    let algorithm = attributes.cryptographic_algorithm.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest(
            "Symmetric key must have a cryptographic algorithm specified".to_owned(),
        )
    })?;
    if *algorithm != CryptographicAlgorithm::RSA {
        return Err(KmsError::InvalidRequest(
            "Only RSA keypairs can be created on the HSM in this server".to_owned(),
        ));
    }
    let key_length = attributes.cryptographic_length.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest("RSA keys must have a cryptographic length specified".to_owned())
    })?;
    // recover tags
    let tags = attributes.get_tags();
    Attributes::check_user_tags(&tags)?;
    let label = if tags.is_empty() {
        String::new()
    } else {
        serde_json::to_string(&tags)?
    };
    let (sk, pk) = hsm
        .create_keypair(
            slot_id,
            HsmKeypairAlgorithm::RSA,
            *key_length as usize,
            tags.contains("exportable"),
            label.as_str(),
        )
        .await?;
    let sk = format!("hsm::{slot_id}::{sk}");
    let pk = format!("hsm::{slot_id}::{pk}");
    debug!("Created HSM {algorithm} Key of type with sk: {sk} and pk: {pk}",);
    Ok(CreateKeyPairResponse {
        private_key_unique_identifier: UniqueIdentifier::TextString(sk),
        public_key_unique_identifier: UniqueIdentifier::TextString(pk),
    })
}

async fn create_kms_keypair(
    kms: &KMS,
    request: CreateKeyPair,
    owner: &str,
    params: Option<&ExtraStoreParams>,
) -> KResult<CreateKeyPairResponse> {
    if request.common_protection_storage_masks.is_some()
        || request.private_protection_storage_masks.is_some()
        || request.public_protection_storage_masks.is_some()
    {
        kms_bail!(KmsError::UnsupportedPlaceholder)
    }

    // generate uids and create the key pair and tags
    let sk_uid = request
        .private_key_attributes
        .as_ref() // Convert Option to Option reference
        .and_then(|attrs| attrs.unique_identifier.as_ref()) // Safely access unique_identifier
        .map_or_else(
            || Uuid::new_v4().to_string(),
            std::string::ToString::to_string,
        );
    let pk_uid = Uuid::new_v4().to_string();
    let (key_pair, sk_tags, pk_tags) = generate_key_pair_and_tags(request, &sk_uid, &pk_uid)?;

    trace!("create_key_pair: sk_uid: {sk_uid}, pk_uid: {pk_uid}");

    let private_key_attributes = key_pair.private_key().attributes()?.clone();
    let public_key_attributes = key_pair.public_key().attributes()?.clone();

    let operations = vec![
        AtomicOperation::Create((
            sk_uid.clone(),
            key_pair.private_key().to_owned(),
            private_key_attributes,
            sk_tags,
        )),
        AtomicOperation::Create((
            pk_uid.clone(),
            key_pair.public_key().to_owned(),
            public_key_attributes,
            pk_tags,
        )),
    ];
    kms.store.atomic(owner, &operations, params).await?;

    debug!("Created key pair: {}/{}", &sk_uid, &pk_uid);
    Ok(CreateKeyPairResponse {
        private_key_unique_identifier: UniqueIdentifier::TextString(sk_uid),
        public_key_unique_identifier: UniqueIdentifier::TextString(pk_uid),
    })
}

/// Generate a key pair and the corresponding system tags.
/// Generate FIPS-140-3 compliant Key Pair for key agreement and digital signature.
///
/// Sources:
/// - NIST.SP.800-56Ar3 - Appendix D.
/// - NIST.SP.800-186 - Section 3.1.2 table 2.
///
/// The tags will contain the user tags and the following:
///  - "_sk" for the private key
///  - "_pk" for the public key
///  - the KMIP cryptographic algorithm in lower case prepended with "_"
///
/// Only Covercrypt master keys can be created using this function
pub(crate) fn generate_key_pair_and_tags(
    request: CreateKeyPair,
    private_key_uid: &str,
    public_key_uid: &str,
) -> KResult<(KeyPair, HashSet<String>, HashSet<String>)> {
    trace!("Internal create key pair");

    let mut common_attributes = request.common_attributes.unwrap_or_default();

    // recover tags and clean them up from the common attributes
    let tags = common_attributes.remove_tags().unwrap_or_default();
    Attributes::check_user_tags(&tags)?;
    // Update the tags for the private key and the public key.
    let mut sk_tags = tags.clone();
    sk_tags.insert("_sk".to_owned());
    let mut pk_tags = tags;
    pk_tags.insert("_pk".to_owned());

    // Grab whatever attributes were supplied on the  create request.
    let any_attributes = Some(&common_attributes)
        .or(request.private_key_attributes.as_ref())
        .or(request.public_key_attributes.as_ref())
        .ok_or_else(|| {
            KmsError::InvalidRequest(
                "Attributes must be provided in a CreateKeyPair request".to_owned(),
            )
        })?;

    let private_key_mask = request
        .private_key_attributes
        .as_ref()
        .and_then(|attr| attr.cryptographic_usage_mask);

    let public_key_mask = request
        .public_key_attributes
        .as_ref()
        .and_then(|attr| attr.cryptographic_usage_mask);

    // Check that the cryptographic algorithm is specified.
    let cryptographic_algorithm = any_attributes.cryptographic_algorithm.ok_or_else(|| {
        KmsError::InvalidRequest(
            "the cryptographic algorithm must be specified for key pair creation".to_owned(),
        )
    })?;

    let key_pair = match cryptographic_algorithm {
        // EC, ECDSA and ECDH possess the same FIPS restrictions for curves.
        CryptographicAlgorithm::EC
        | CryptographicAlgorithm::ECDH
        | CryptographicAlgorithm::ECDSA => {
            let domain_parameters = any_attributes
                .cryptographic_domain_parameters
                .unwrap_or_default();
            let curve = domain_parameters.recommended_curve.unwrap_or_default();

            match curve {
                #[cfg(not(feature = "fips"))]
                // Generate a P-192 Key Pair. Not FIPS-140-3 compliant. **This curve is for
                // legacy-use only** as it provides less than 112 bits of security.
                //
                // Sources:
                // - NIST.SP.800-186 - Section 3.2.1.1
                RecommendedCurve::P192 => create_approved_ecc_key_pair(
                    private_key_uid,
                    public_key_uid,
                    curve,
                    any_attributes.cryptographic_algorithm,
                    private_key_mask,
                    public_key_mask,
                ),
                RecommendedCurve::P224
                | RecommendedCurve::P256
                | RecommendedCurve::P384
                | RecommendedCurve::P521 => create_approved_ecc_key_pair(
                    private_key_uid,
                    public_key_uid,
                    curve,
                    any_attributes.cryptographic_algorithm,
                    private_key_mask,
                    public_key_mask,
                ),
                #[cfg(not(feature = "fips"))]
                RecommendedCurve::CURVE25519 => create_x25519_key_pair(
                    private_key_uid,
                    public_key_uid,
                    any_attributes.cryptographic_algorithm,
                    private_key_mask,
                    public_key_mask,
                ),
                #[cfg(not(feature = "fips"))]
                RecommendedCurve::CURVE448 => create_x448_key_pair(
                    private_key_uid,
                    public_key_uid,
                    any_attributes.cryptographic_algorithm,
                    private_key_mask,
                    public_key_mask,
                ),
                #[cfg(not(feature = "fips"))]
                RecommendedCurve::CURVEED25519 => {
                    if cryptographic_algorithm == CryptographicAlgorithm::ECDSA
                        || cryptographic_algorithm == CryptographicAlgorithm::EC
                    {
                        kms_bail!(KmsError::NotSupported(
                            "Edwards curve can't be created for EC or ECDSA".to_owned()
                        ))
                    }
                    warn!(
                        "An Edwards Keypair on curve 25519 should not be requested to perform \
                         ECDH. Creating anyway."
                    );
                    create_ed25519_key_pair(
                        private_key_uid,
                        public_key_uid,
                        any_attributes.cryptographic_algorithm,
                        private_key_mask,
                        public_key_mask,
                    )
                }
                #[cfg(feature = "fips")]
                // Ed25519 not allowed for ECDH nor ECDSA.
                // see NIST.SP.800-186 - Section 3.1.2 table 2.
                RecommendedCurve::CURVEED25519 => {
                    kms_bail!(KmsError::NotSupported(
                        "An Edwards Keypair on curve 25519 should not be requested to perform \
                         Elliptic Curves operations in FIPS mode"
                            .to_owned()
                    ))
                }
                #[cfg(not(feature = "fips"))]
                RecommendedCurve::CURVEED448 => {
                    if cryptographic_algorithm == CryptographicAlgorithm::ECDSA
                        || cryptographic_algorithm == CryptographicAlgorithm::EC
                    {
                        kms_bail!(KmsError::NotSupported(
                            "Edwards curve can't be created for EC or ECDSA".to_owned()
                        ))
                    }
                    warn!(
                        "An Edwards Keypair on curve 448 should not be requested to perform ECDH. \
                         Creating anyway."
                    );
                    create_ed448_key_pair(
                        private_key_uid,
                        public_key_uid,
                        any_attributes.cryptographic_algorithm,
                        private_key_mask,
                        public_key_mask,
                    )
                }
                #[cfg(feature = "fips")]
                // Ed448 not allowed for ECDH nor ECDSA.
                // see NIST.SP.800-186 - Section 3.1.2 table 2.
                RecommendedCurve::CURVEED448 => {
                    kms_bail!(KmsError::NotSupported(
                        "An Edwards Keypair on curve 448 should not be requested to perform ECDH \
                         in FIPS mode."
                            .to_owned()
                    ))
                }
                other => kms_bail!(KmsError::NotSupported(format!(
                    "Generation of Key Pair for curve: {other:?}, is not supported"
                ))),
            }
        }
        CryptographicAlgorithm::RSA => {
            let key_size_in_bits = u32::try_from(
                any_attributes
                    .cryptographic_length
                    .ok_or_else(|| KmsError::InvalidRequest("RSA key size: error".to_owned()))?,
            )?;
            trace!("RSA key pair generation: size in bits: {key_size_in_bits}");

            create_rsa_key_pair(
                key_size_in_bits,
                public_key_uid,
                private_key_uid,
                any_attributes.cryptographic_algorithm,
                private_key_mask,
                public_key_mask,
            )
        }
        CryptographicAlgorithm::Ed25519 => create_ed25519_key_pair(
            private_key_uid,
            public_key_uid,
            any_attributes.cryptographic_algorithm,
            private_key_mask,
            public_key_mask,
        ),
        CryptographicAlgorithm::Ed448 => create_ed448_key_pair(
            private_key_uid,
            public_key_uid,
            any_attributes.cryptographic_algorithm,
            private_key_mask,
            public_key_mask,
        ),
        CryptographicAlgorithm::CoverCrypt => create_master_keypair(
            &Covercrypt::default(),
            private_key_uid,
            public_key_uid,
            &Some(common_attributes),
            &request.private_key_attributes,
            &request.public_key_attributes,
        )
        .map_err(Into::into),
        other => {
            kms_bail!(KmsError::NotSupported(format!(
                "The creation of a key pair for algorithm: {other:?} is not supported"
            )))
        }
    }?;
    Ok((key_pair, sk_tags, pk_tags))
}

use cosmian_crypto_base::{
    entropy::CsRng,
    symmetric_crypto::{aes_256_gcm_pure::Nonce, nonce::NonceTrait},
};
use cosmian_kmip::kmip::{
    kmip_operations::{Decrypt, Encrypt},
    kmip_types::{CryptographicAlgorithm, CryptographicParameters},
};

use super::AesGcmCipher;
use crate::{crypto::aes::create_aes_symmetric_key, DeCipher, EnCipher};

#[test]
pub fn test_aes() {
    let key = create_aes_symmetric_key(None).unwrap();
    let aes = AesGcmCipher::instantiate("blah", &key).unwrap();
    let mut rng = CsRng::new();
    let data = rng.generate_random_bytes(42);
    let uid = rng.generate_random_bytes(32);
    let nonce = Nonce::new(&mut rng);
    // encrypt
    let enc_res = aes
        .encrypt(&Encrypt {
            unique_identifier: Some("blah".to_owned()),
            cryptographic_parameters: Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                initial_counter_value: Some(42),
                ..Default::default()
            }),
            data: Some(data.clone()),
            iv_counter_nonce: Some(nonce.into()),
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
            authenticated_encryption_additional_data: Some(uid.clone()),
        })
        .unwrap();
    // decrypt
    let dec_res = aes
        .decrypt(&Decrypt {
            unique_identifier: Some("blah".to_owned()),
            cryptographic_parameters: Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                initial_counter_value: Some(42),
                ..Default::default()
            }),
            data: Some(enc_res.data.unwrap()),
            iv_counter_nonce: Some(enc_res.iv_counter_nonce.unwrap()),
            init_indicator: None,
            final_indicator: None,
            authenticated_encryption_additional_data: Some(uid),
            authenticated_encryption_tag: Some(enc_res.authenticated_encryption_tag.unwrap()),
        })
        .unwrap();

    assert_eq!(&data, &dec_res.data.unwrap());
}
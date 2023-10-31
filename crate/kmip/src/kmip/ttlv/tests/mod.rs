use cosmian_logger::log_utils::log_init;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::kmip::{
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
    kmip_messages::{
        Message, MessageBatchItem, MessageHeader, MessageResponse, MessageResponseBatchItem,
        MessageResponseHeader,
    },
    kmip_objects::{Object, ObjectType},
    kmip_operations::{
        Create, DecryptResponse, Encrypt, ErrorReason, Import, ImportResponse, Locate,
        LocateResponse, Operation,
    },
    kmip_types::{
        AsynchronousIndicator, AttestationType, Attributes, BatchErrorContinuationOption,
        Credential, CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType, Link,
        LinkedObjectIdentifier, MessageExtension, Nonce, OperationEnumeration, ProtocolVersion,
        ResultStatusEnumeration,
    },
    ttlv::{deserializer::from_ttlv, serializer::to_ttlv, TTLVEnumeration, TTLValue, TTLV},
};

pub fn aes_key_material(key_value: &[u8]) -> KeyMaterial {
    KeyMaterial::TransparentSymmetricKey {
        key: key_value.to_vec(),
    }
}

pub fn aes_key_value(key_value: &[u8]) -> KeyValue {
    KeyValue {
        key_material: aes_key_material(key_value),
        attributes: Some(Attributes {
            object_type: Some(ObjectType::SymmetricKey),
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(256),
            cryptographic_usage_mask: Some(CryptographicUsageMask::Encrypt),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            ..Attributes::default()
        }),
    }
}

pub fn aes_key_block(key_value: &[u8]) -> KeyBlock {
    KeyBlock {
        key_format_type: KeyFormatType::TransparentSymmetricKey,
        key_compression_type: None,
        key_value: aes_key_value(key_value),
        cryptographic_algorithm: CryptographicAlgorithm::AES,
        cryptographic_length: 256,
        key_wrapping_data: None,
    }
}

pub fn aes_key(key_value: &[u8]) -> Object {
    Object::SymmetricKey {
        key_block: aes_key_block(key_value),
    }
}

pub fn aes_key_material_ttlv(key_value: &[u8]) -> TTLV {
    TTLV {
        tag: "KeyMaterial".to_string(),
        value: TTLValue::Structure(vec![TTLV {
            tag: "Key".to_string(),
            value: TTLValue::ByteString(key_value.to_vec()),
        }]),
    }
}

pub fn aes_key_value_ttlv(key_value: &[u8]) -> TTLV {
    TTLV {
        tag: "KeyValue".to_string(),
        value: TTLValue::Structure(vec![
            aes_key_material_ttlv(key_value),
            TTLV {
                tag: "Attributes".to_string(),
                value: TTLValue::Structure(vec![
                    TTLV {
                        tag: "CryptographicAlgorithm".to_string(),
                        value: TTLValue::Enumeration(TTLVEnumeration::Name("AES".to_string())),
                    },
                    TTLV {
                        tag: "CryptographicLength".to_string(),
                        value: TTLValue::Integer(256),
                    },
                    TTLV {
                        tag: "CryptographicUsageMask".to_string(),
                        value: TTLValue::Integer(4),
                    },
                    TTLV {
                        tag: "KeyFormatType".to_string(),
                        value: TTLValue::Enumeration(TTLVEnumeration::Name(
                            "TransparentSymmetricKey".to_string(),
                        )),
                    },
                    TTLV {
                        tag: "ObjectType".to_string(),
                        value: TTLValue::Enumeration(TTLVEnumeration::Name(
                            "SymmetricKey".to_string(),
                        )),
                    },
                ]),
            },
        ]),
    }
}

pub fn aes_key_block_ttlv(key_value: &[u8]) -> TTLV {
    TTLV {
        tag: "KeyBlock".to_string(),
        value: TTLValue::Structure(vec![
            TTLV {
                tag: "KeyFormatType".to_string(),
                value: TTLValue::Enumeration(TTLVEnumeration::Name(
                    "TransparentSymmetricKey".to_string(),
                )),
            },
            aes_key_value_ttlv(key_value),
            TTLV {
                tag: "CryptographicAlgorithm".to_string(),
                value: TTLValue::Enumeration(TTLVEnumeration::Name("AES".to_string())),
            },
            TTLV {
                tag: "CryptographicLength".to_string(),
                value: TTLValue::Integer(256),
            },
        ]),
    }
}

pub fn aes_key_ttlv(key_value: &[u8]) -> TTLV {
    TTLV {
        tag: "Object".to_string(),
        value: TTLValue::Structure(vec![aes_key_block_ttlv(key_value)]),
    }
}

#[test]
fn test_enumeration() {
    let es = TTLVEnumeration::Name("blah".to_string());
    let s = serde_json::to_string_pretty(&es).unwrap();
    assert_eq!(es, serde_json::from_str(&s).unwrap());

    let i_plus = TTLVEnumeration::Integer(1);
    let s = serde_json::to_string_pretty(&i_plus).unwrap();
    assert_eq!(i_plus, serde_json::from_str(&s).unwrap());

    let i_minus = TTLVEnumeration::Integer(-1);
    let s = serde_json::to_string_pretty(&i_minus).unwrap();
    assert_eq!(i_minus, serde_json::from_str(&s).unwrap());
}

#[test]
fn test_serialization_deserialization() {
    let now = OffsetDateTime::now_utc();
    let ttlv = TTLV {
        tag: "Test".to_string(),
        value: TTLValue::Structure(vec![
            TTLV {
                tag: "AnInt".to_string(),
                value: TTLValue::Integer(42),
            },
            TTLV {
                tag: "ABitMask".to_string(),
                value: TTLValue::BitMask(42),
            },
            TTLV {
                tag: "ALongInt".to_string(),
                value: TTLValue::LongInteger(-42_i64),
            },
            TTLV {
                tag: "ABigInteger".to_string(),
                value: TTLValue::BigInteger(BigUint::from(2_487_678_887_987_987_798_676_u128)),
            },
            TTLV {
                tag: "AnEnumeration_1".to_string(),
                value: TTLValue::Enumeration(TTLVEnumeration::Integer(54)),
            },
            TTLV {
                tag: "AnEnumeration_2".to_string(),
                value: TTLValue::Enumeration(TTLVEnumeration::Name("blah".to_string())),
            },
            TTLV {
                tag: "ABoolean".to_string(),
                value: TTLValue::Boolean(true),
            },
            TTLV {
                tag: "ATextString".to_string(),
                value: TTLValue::TextString("blah".to_string()),
            },
            TTLV {
                tag: "AnByteString".to_string(),
                value: TTLValue::ByteString(b"hello".to_vec()),
            },
            TTLV {
                tag: "ADateTime".to_string(),
                value: TTLValue::DateTime(now),
            },
            TTLV {
                tag: "AnInterval".to_string(),
                value: TTLValue::Interval(27),
            },
            TTLV {
                tag: "ADateTimeExtended".to_string(),
                value: TTLValue::DateTimeExtended(now),
            },
        ]),
    };
    let j = serde_json::to_string_pretty(&ttlv).unwrap();
    let rec: TTLV = serde_json::from_str(&j).unwrap();
    match rec.value {
        TTLValue::Structure(s) => match &s[0].value {
            TTLValue::Integer(i) => assert_eq!(42, *i),
            x => panic!("unexpected 2nd level type : {x:?}"),
        },
        x => panic!("unexpected type : {x:?}"),
    };
}

#[test]
fn test_ser_int() {
    log_init("info,hyper=info,reqwest=info");
    #[derive(Serialize)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        an_int: u32,
    }

    let test = Test {
        an_int: 1,
        // seq: vec!["a", "b"],
    };
    let ttlv = to_ttlv(&test).unwrap();
    let expected =
        r#"TTLV { tag: "Test", value: Structure([TTLV { tag: "AnInt", value: Integer(1) }]) }"#;
    let ttlv_s = format!("{ttlv:?}");
    assert_eq!(ttlv_s, expected);
}

#[test]
fn test_ser_array() {
    log_init("info,hyper=info,reqwest=info");
    #[derive(Serialize)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        seq: Vec<&'static str>,
    }

    let test = Test {
        seq: vec!["a", "b"],
    };
    let ttlv = to_ttlv(&test).unwrap();
    let expected = r#"TTLV { tag: "Test", value: Structure([TTLV { tag: "Seq", value: Structure([TTLV { tag: "Seq", value: TextString("a") }, TTLV { tag: "Seq", value: TextString("b") }]) }]) }"#;
    let ttlv_s = format!("{ttlv:?}");
    assert_eq!(ttlv_s, expected);
}

#[test]
fn test_ser_big_int() {
    log_init("info,hyper=info,reqwest=info");
    #[derive(Serialize)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        big_int: BigUint,
    }

    let test = Test {
        big_int: BigUint::from(0x1111_1111_1222_2222_u128),
    };
    let ttlv = to_ttlv(&test).unwrap();
    let expected = r#"TTLV {
    tag: "Test",
    value: Structure(
        [
            TTLV {
                tag: "BigInt",
                value: BigInteger(
                    1229782938265199138,
                ),
            },
        ],
    ),
}"#;
    let ttlv_s = format!("{ttlv:#?}");
    assert_eq!(ttlv_s, expected);
}

#[test]
fn test_ser_aes_key() {
    log_init("info,hyper=info,reqwest=info");
    let key_bytes: &[u8] = b"this_is_a_test";
    let aes_key = aes_key(key_bytes);
    let ttlv = to_ttlv(&aes_key).unwrap();
    assert_eq!(aes_key_ttlv(key_bytes), ttlv);
}

#[test]
fn test_des_int() {
    log_init("info,hyper=info,reqwest=info");

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        an_int: i32,
        another_int: u32,
    }

    let ttlv = TTLV {
        tag: "Test".to_string(),
        value: TTLValue::Structure(vec![
            TTLV {
                tag: "AnInt".to_string(),
                value: TTLValue::Integer(2),
            },
            TTLV {
                tag: "AnotherInt".to_string(),
                value: TTLValue::BitMask(4),
            },
        ]),
    };

    let rec: Test = from_ttlv(&ttlv).unwrap();
    assert_eq!(
        &Test {
            an_int: 2,
            another_int: 4
        },
        &rec
    );
}

#[test]
fn test_des_array() {
    log_init("info,hyper=info,reqwest=info");

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        ints: Vec<i32>,
    }

    let ttlv = TTLV {
        tag: "Test".to_string(),
        value: TTLValue::Structure(vec![TTLV {
            tag: "Ints".to_string(),
            value: TTLValue::Structure(vec![
                TTLV {
                    tag: "Ints".to_string(),
                    value: TTLValue::Integer(2),
                },
                TTLV {
                    tag: "Ints".to_string(),
                    value: TTLValue::Integer(4),
                },
            ]),
        }]),
    };

    let rec: Test = from_ttlv(&ttlv).unwrap();
    assert_eq!(&Test { ints: vec![2, 4] }, &rec);
}

#[test]
fn test_des_enum() {
    log_init("info,hyper=info,reqwest=info");

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        crypto_algo: CryptographicAlgorithm,
    }

    let ttlv = TTLV {
        tag: "Test".to_string(),
        value: TTLValue::Structure(vec![TTLV {
            tag: "CryptoAlgo".to_string(),
            value: TTLValue::Enumeration(TTLVEnumeration::Name("AES".to_string())),
        }]),
    };

    let rec: Test = from_ttlv(&ttlv).unwrap();
    assert_eq!(
        &Test {
            crypto_algo: CryptographicAlgorithm::AES
        },
        &rec
    );
}

#[test]
fn test_key_material_vec_deserialization() {
    log_init("info,hyper=info,reqwest=info");
    let bytes = vec![
        116, 104, 105, 115, 95, 105, 115, 95, 97, 95, 116, 101, 115, 116,
    ];
    let ttlv = TTLV {
        tag: "KeyMaterial".to_string(),
        value: TTLValue::Structure(vec![TTLV {
            tag: "Key".to_string(),
            value: TTLValue::ByteString(bytes.clone()),
        }]),
    };
    let km_: KeyMaterial = from_ttlv(&ttlv).unwrap();
    let km = KeyMaterial::TransparentSymmetricKey { key: bytes };
    assert_eq!(km, km_);
}

#[test]
fn test_key_material_big_int_deserialization() {
    log_init("info,hyper=info,reqwest=info");
    let ttlv = TTLV {
        tag: "KeyMaterial".to_string(),
        value: TTLValue::Structure(vec![
            TTLV {
                tag: "P".to_string(),
                value: TTLValue::BigInteger(BigUint::from(u32::MAX)),
            },
            TTLV {
                tag: "Q".to_string(),
                value: TTLValue::BigInteger(BigUint::from(1_u32)),
            },
            TTLV {
                tag: "G".to_string(),
                value: TTLValue::BigInteger(BigUint::from(2_u32)),
            },
            TTLV {
                tag: "X".to_string(),
                value: TTLValue::BigInteger(BigUint::from(u128::MAX)),
            },
        ]),
    };
    let km = KeyMaterial::TransparentDHPrivateKey {
        p: BigUint::from(u32::MAX),
        q: Some(BigUint::from(1_u64)),
        g: BigUint::from(2_u32),
        j: None,
        x: BigUint::from(u128::MAX),
    };
    let ttlv_ = to_ttlv(&km).unwrap();
    assert_eq!(ttlv, ttlv_);
    let km_: KeyMaterial = from_ttlv(&ttlv_).unwrap();
    assert_eq!(km, km_);
}

#[test]
fn test_big_int_deserialization() {
    let km = KeyMaterial::TransparentDHPrivateKey {
        p: BigUint::from(u32::MAX),
        q: Some(BigUint::from(1_u64)),
        g: BigUint::from(2_u32),
        j: None,
        x: BigUint::from(u128::MAX - 1),
    };
    let j = serde_json::to_value(&km).unwrap();
    let km_: KeyMaterial = serde_json::from_value(j).unwrap();
    assert_eq!(km, km_);
}

#[test]
fn test_des_aes_key() {
    log_init("info,hyper=info,reqwest=info");
    let key_bytes: &[u8] = b"this_is_a_test";

    let json = serde_json::to_value(aes_key(key_bytes)).unwrap();
    let o: Object = serde_json::from_value(json).unwrap();
    // Deserialization cannot make the difference
    // between a `SymmetricKey` or a `PrivateKey`
    assert_eq!(
        aes_key(key_bytes),
        Object::post_fix(ObjectType::SymmetricKey, o)
    );

    let ttlv = aes_key_ttlv(key_bytes);
    let rec: Object = from_ttlv(&ttlv).unwrap();
    // Deserialization cannot make the difference
    // between a `SymmetricKey` or a `PrivateKey`
    assert_eq!(
        aes_key(key_bytes),
        Object::post_fix(ObjectType::SymmetricKey, rec)
    );
}

#[test]
fn test_aes_key_block() {
    log_init("info,hyper=info,reqwest=info");
    let key_bytes: &[u8] = b"this_is_a_test";
    //
    let json = serde_json::to_value(aes_key_block(key_bytes)).unwrap();
    let kv: KeyBlock = serde_json::from_value(json).unwrap();
    assert_eq!(aes_key_block(key_bytes), kv);
    //
    let ttlv = aes_key_block_ttlv(key_bytes);
    let rec: KeyBlock = from_ttlv(&ttlv).unwrap();
    assert_eq!(aes_key_block(key_bytes), rec);
}

#[test]
fn test_aes_key_value() {
    log_init("info,hyper=info,reqwest=info");
    let key_bytes: &[u8] = b"this_is_a_test";
    //
    let json = serde_json::to_value(aes_key_value(key_bytes)).unwrap();
    let kv: KeyValue = serde_json::from_value(json).unwrap();
    assert_eq!(aes_key_value(key_bytes), kv);

    let ttlv = aes_key_value_ttlv(key_bytes);
    let rec: KeyValue = from_ttlv(&ttlv).unwrap();
    assert_eq!(aes_key_value(key_bytes), rec);
}

#[test]
fn test_aes_key_material() {
    log_init("info,hyper=info,reqwest=info");
    let key_bytes: &[u8] = b"this_is_a_test";
    let ttlv = aes_key_material_ttlv(key_bytes);
    let rec: KeyMaterial = from_ttlv(&ttlv).unwrap();
    assert_eq!(aes_key_material(key_bytes), rec);
}

#[test]
fn test_some_attributes() {
    log_init("info,hyper=info,reqwest=info");
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
    #[serde(untagged)]
    enum Wrapper {
        Attr {
            #[serde(skip_serializing_if = "Option::is_none", rename = "Attributes")]
            attributes: Option<Box<Attributes>>,
        },
        NoAttr {
            whatever: i32,
        },
    }
    let value = Wrapper::Attr {
        attributes: Some(Box::new(Attributes {
            object_type: Some(ObjectType::SymmetricKey),
            ..Attributes::default()
        })),
    };
    let ttlv = to_ttlv(&value).unwrap();
    let json = serde_json::to_value(&ttlv).unwrap();
    let ttlv_: TTLV = serde_json::from_value(json).unwrap();
    assert_eq!(ttlv, ttlv_);
    let rec: Wrapper = from_ttlv(&ttlv_).unwrap();
    assert_eq!(value, rec);
}

#[test]
fn test_java_import_request() {
    log_init("info,hyper=info,reqwest=info");
    let ir_java = r#"
{
  "tag" : "Import",
  "value" : [ {
    "tag" : "UniqueIdentifier",
    "type" : "TextString",
    "value" : "unique_identifier"
  }, {
    "tag" : "ObjectType",
    "type" : "Enumeration",
    "value" : "SymmetricKey"
  }, {
    "tag" : "ReplaceExisting",
    "type" : "Boolean",
    "value" : true
  }, {
    "tag" : "KeyWrapType",
    "type" : "Enumeration",
    "value" : "AsRegistered"
  }, {
    "tag" : "Attributes",
    "value" : [ {
      "tag" : "Link",
      "value" : [ ]
    }, {
      "tag" : "ObjectType",
      "type" : "Enumeration",
      "value" : "OpaqueObject"
    } ]
  }, {
    "tag" : "Object",
    "value" : [ {
      "tag" : "KeyBlock",
      "value" : [ {
        "tag" : "KeyFormatType",
        "type" : "Enumeration",
        "value" : "TransparentSymmetricKey"
      }, {
        "tag" : "KeyValue",
        "value" : [ {
          "tag" : "KeyMaterial",
          "value" : [ {
            "tag" : "Key",
            "type" : "ByteString",
            "value" : "6279746573"
          } ]
        } ]
      }, {
        "tag" : "CryptographicAlgorithm",
        "type" : "Enumeration",
        "value" : "AES"
      }, {
        "tag" : "CryptographicLength",
        "type" : "Integer",
        "value" : 256
      } ]
    } ]
  } ]
}
"#;
    let ttlv: TTLV = serde_json::from_str(ir_java).unwrap();
    let _import_request: Import = from_ttlv(&ttlv).unwrap();
}

#[test]
fn test_java_import_response() {
    log_init("info");
    let ir = ImportResponse {
        unique_identifier: "blah".to_string(),
    };
    let json = serde_json::to_string(&to_ttlv(&ir).unwrap()).unwrap();
    let ir_ = from_ttlv(&serde_json::from_str::<TTLV>(&json).unwrap()).unwrap();
    assert_eq!(ir, ir_);
}

#[test]
fn test_byte_string_key_material() {
    log_init("info");
    let key_bytes: &[u8] = b"this_is_a_test";
    let key_value = KeyValue {
        key_material: KeyMaterial::ByteString(key_bytes.to_vec()),
        attributes: Some(Attributes {
            object_type: Some(ObjectType::SymmetricKey),
            ..Attributes::default()
        }),
    };
    let ttlv = to_ttlv(&key_value).unwrap();
    let key_value_: KeyValue = from_ttlv(&ttlv).unwrap();
    assert_eq!(key_value, key_value_);
}

#[test]
fn test_aes_key_full() {
    log_init("info");
    let key_bytes: &[u8] = b"this_is_a_test";
    let aes_key = aes_key(key_bytes);
    let ttlv = to_ttlv(&aes_key).unwrap();
    let aes_key_: Object = from_ttlv(&ttlv).unwrap();
    assert_eq!(
        aes_key,
        Object::post_fix(ObjectType::SymmetricKey, aes_key_)
    );
}

#[test]
pub fn test_attributes_with_links() {
    log_init("info");
    let json = include_str!("./attributes_with_links.json");
    let ttlv: TTLV = serde_json::from_str(json).unwrap();
    let _attributes: Attributes = from_ttlv(&ttlv).unwrap();
}

#[test]
pub fn test_import_correct_object() {
    log_init("info,hyper=info,reqwest=info");

    // This file was migrated from GPSW without touching the keys (just changing the `CryptographicAlgorithm` and `KeyFormatType`)
    // It cannot be used to do crypto stuff, it's just for testing the serialization/deserialisation of TTLV.
    let json = include_str!("./import.json");
    let ttlv: TTLV = serde_json::from_str(json).unwrap();
    let import: Import = from_ttlv(&ttlv).unwrap();

    assert_eq!(ObjectType::PublicKey, import.object_type);
    assert_eq!(ObjectType::PublicKey, import.object.object_type());
    assert_eq!(
        CryptographicAlgorithm::CoverCrypt,
        import.object.key_block().unwrap().cryptographic_algorithm
    );
}

#[test]
pub fn test_create() {
    let attributes = Attributes {
        object_type: Some(ObjectType::SymmetricKey),
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        link: Some(vec![Link {
            link_type: crate::kmip::kmip_types::LinkType::ParentLink,
            linked_object_identifier: crate::kmip::kmip_types::LinkedObjectIdentifier::TextString(
                "SK".to_string(),
            ),
        }]),
        ..Attributes::default()
    };
    let create = Create {
        object_type: ObjectType::SymmetricKey,
        attributes,
        protection_storage_masks: None,
    };
    let ttlv = to_ttlv(&create).unwrap();
    let create_: Create = from_ttlv(&ttlv).unwrap();
    assert_eq!(ObjectType::SymmetricKey, create_.object_type);
    assert_eq!(
        CryptographicAlgorithm::AES,
        create_.attributes.cryptographic_algorithm.unwrap()
    );
    assert_eq!(
        LinkedObjectIdentifier::TextString("SK".to_string()),
        create_.attributes.link.as_ref().unwrap()[0].linked_object_identifier
    );
}

#[test]
pub fn test_message_request() {
    log_init("info,hyper=info,reqwest=info");

    let req = Message {
        header: MessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 2,
            },
            maximum_response_size: Some(9999),
            batch_count: 1,
            client_correlation_value: Some("client_123".to_string()),
            server_correlation_value: Some("server_234".to_string()),
            asynchronous_indicator: Some(AsynchronousIndicator::Optional),
            attestation_capable_indicator: Some(true),
            attestation_type: Some(vec![AttestationType::TPM_Quote]),
            authentication: Some(vec![Credential::Attestation {
                nonce: Nonce {
                    nonce_id: vec![9, 8, 7],
                    nonce_value: vec![10, 11, 12],
                },
                attestation_type: AttestationType::TCG_Integrity_Report,
                attestation_measurement: Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
                attestation_assertion: Some(vec![11, 12, 13, 14, 15, 16, 17, 18, 19, 20]),
            }]),
            batch_error_continuation_option: Some(BatchErrorContinuationOption::Undo),
            batch_order_option: Some(true),
            timestamp: Some(1950940403),
        },
        items: vec![MessageBatchItem {
            operation: OperationEnumeration::Encrypt,
            ephemeral: None,
            unique_batch_item_id: None,
            request_payload: Operation::Encrypt(Encrypt {
                data: Some(b"to be enc".to_vec()),
                ..Default::default()
            }),
            message_extension: Some(vec![MessageExtension {
                vendor_identification: "CosmianVendor".to_string(),
                criticality_indicator: false,
                vendor_extension: vec![42_u8],
            }]),
        }],
    };
    let ttlv = to_ttlv(&req).unwrap();
    let req_: Message = from_ttlv(&ttlv).unwrap();
    assert_eq!(req_.items[0].operation, OperationEnumeration::Encrypt);
    let Operation::Encrypt(encrypt) = &req_.items[0].request_payload else {
        panic!(
            "not an encrypt operation's request payload: {:?}",
            req_.items[0]
        );
    };
    assert_eq!(encrypt.data, Some(b"to be enc".to_vec()));
    assert_eq!(req, req_);
}

#[test]
pub fn test_message_response() {
    log_init("info,hyper=info,reqwest=info");

    let res = MessageResponse {
        header: MessageResponseHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            batch_count: 2,
            client_correlation_value: Some("client_123".to_string()),
            server_correlation_value: Some("server_234".to_string()),
            attestation_type: Some(vec![AttestationType::TPM_Quote]),
            timestamp: 1697201574,
            nonce: Some(Nonce {
                nonce_id: vec![5, 6, 7],
                nonce_value: vec![8, 9, 0],
            }),
            server_hashed_password: Some("5e8953ab".to_string()),
        },
        items: vec![
            MessageResponseBatchItem {
                operation: Some(OperationEnumeration::Locate),
                unique_batch_item_id: Some(1234),
                response_payload: Some(Operation::LocateResponse(LocateResponse {
                    located_items: Some(134),
                    unique_identifiers: Some(vec!["some_id".to_string()]),
                })),
                message_extension: Some(MessageExtension {
                    vendor_identification: "CosmianVendor".to_string(),
                    criticality_indicator: false,
                    vendor_extension: vec![42_u8],
                }),
                result_status: ResultStatusEnumeration::OperationPending,
                result_reason: None,
                result_message: None,
                asynchronous_correlation_value: Some(vec![42_u8, 5]),
            },
            MessageResponseBatchItem {
                operation: Some(OperationEnumeration::Decrypt),
                unique_batch_item_id: Some(1235),
                response_payload: Some(Operation::DecryptResponse(DecryptResponse {
                    unique_identifier: "id_12345".to_string(),
                    data: Some(b"decrypted_data".to_vec()),
                    correlation_value: Some(vec![9_u8, 13]),
                })),
                message_extension: Some(MessageExtension {
                    vendor_identification: "CosmianVendor".to_string(),
                    criticality_indicator: true,
                    vendor_extension: vec![42_u8],
                }),
                result_status: ResultStatusEnumeration::OperationUndone,
                result_reason: Some(ErrorReason::Response_Too_Large),
                result_message: Some("oversized data".to_string()),
                asynchronous_correlation_value: Some(vec![43_u8, 6]),
            },
        ],
    };
    let ttlv = to_ttlv(&res).unwrap();
    let res_: MessageResponse = from_ttlv(&ttlv).unwrap();
    assert_eq!(res_.items.len(), 2);
    assert_eq!(res_.items[0].operation, Some(OperationEnumeration::Locate));
    assert_eq!(
        res_.items[0].result_status,
        ResultStatusEnumeration::OperationPending
    );
    assert_eq!(res_.items[1].operation, Some(OperationEnumeration::Decrypt));
    assert_eq!(
        res_.items[1].result_status,
        ResultStatusEnumeration::OperationUndone
    );

    let Some(Operation::DecryptResponse(decrypt)) = &res_.items[1].response_payload else {
        panic!("not a decrypt operation's response payload");
    };
    assert_eq!(decrypt.data, Some(b"decrypted_data".to_vec()));
    assert_eq!(decrypt.unique_identifier, "id_12345".to_string());
    assert_eq!(res, res_);
}

#[test]
pub fn test_message_enforce_enum() {
    log_init("info,hyper=info,reqwest=info");

    // check Message request serializer reinforcement
    let req = Message {
        header: MessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            maximum_response_size: Some(9999),
            batch_count: 1,
            ..Default::default()
        },
        items: vec![MessageBatchItem {
            operation: OperationEnumeration::Create,
            ephemeral: None,
            unique_batch_item_id: None,
            // mismatch operation regarding the enum
            request_payload: Operation::Locate(Locate::default()),
            message_extension: None,
        }],
    };
    assert_eq!(
        to_ttlv(&req).unwrap_err().to_string(),
        "operation enum (`Create`) doesn't correspond to request payload (`Locate`)".to_string()
    );

    let req = Message {
        header: MessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            maximum_response_size: Some(9999),
            // mismatch number of batch items
            batch_count: 15,
            ..Default::default()
        },
        items: vec![MessageBatchItem::new(Operation::Locate(Locate::default()))],
    };
    assert_eq!(
        to_ttlv(&req).unwrap_err().to_string(),
        "mismatch number of batch items between header (`15`) and items list (`1`)".to_string()
    );

    let req = Message {
        header: MessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 3,
                protocol_version_minor: 0,
            },
            batch_count: 1,
            ..Default::default()
        },
        items: vec![MessageBatchItem::new(Operation::Locate(Locate::default()))],
    };
    assert_eq!(
        to_ttlv(&req).unwrap_err().to_string(),
        "item's protocol version is greater (`3.0`) than header's protocol version (`2.1`)"
            .to_string()
    );

    let req = Message {
        header: MessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            batch_count: 1,
            ..Default::default()
        },
        items: vec![MessageBatchItem {
            operation: OperationEnumeration::Decrypt,
            ephemeral: None,
            unique_batch_item_id: None,
            // mismatch operation regarding the enum
            request_payload: Operation::DecryptResponse(DecryptResponse {
                unique_identifier: "id_12345".to_string(),
                data: Some(b"decrypted_data".to_vec()),
                correlation_value: None,
            }),
            message_extension: None,
        }],
    };
    assert_eq!(
        to_ttlv(&req).unwrap_err().to_string(),
        "request payload operation is not a request type operation (`Response`)".to_string()
    );

    // check Message response serializer reinforcement
    let res = MessageResponse {
        header: MessageResponseHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            batch_count: 1,
            timestamp: 1697201574,
            ..Default::default()
        },
        items: vec![MessageResponseBatchItem {
            operation: Some(OperationEnumeration::Decrypt),
            unique_batch_item_id: None,
            // mismatch operation regarding the enum
            response_payload: Some(Operation::Locate(Locate::default())),
            message_extension: None,
            result_status: ResultStatusEnumeration::OperationPending,
            result_reason: None,
            result_message: None,
            asynchronous_correlation_value: None,
        }],
    };
    assert_eq!(
        to_ttlv(&res).unwrap_err().to_string(),
        "missing `AsynchronousCorrelationValue` with pending status (`ResultStatus` is set to \
         `OperationPending`)"
            .to_string()
    );

    let res = MessageResponse {
        header: MessageResponseHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            batch_count: 1,
            timestamp: 1697201574,
            ..Default::default()
        },
        items: vec![MessageResponseBatchItem {
            operation: Some(OperationEnumeration::Decrypt),
            unique_batch_item_id: None,
            // mismatch operation regarding the enum
            response_payload: Some(Operation::Locate(Locate::default())),
            message_extension: None,
            result_status: ResultStatusEnumeration::OperationPending,
            result_reason: None,
            result_message: None,
            asynchronous_correlation_value: Some(vec![0, 0, 1]),
        }],
    };
    assert_eq!(
        to_ttlv(&res).unwrap_err().to_string(),
        "operation enum (`Decrypt`) doesn't correspond to response payload (`Locate`)".to_string()
    );

    let res = MessageResponse {
        header: MessageResponseHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            // mismatch number of items
            batch_count: 22,
            timestamp: 1697201574,
            ..Default::default()
        },
        items: vec![
            MessageResponseBatchItem::new(ResultStatusEnumeration::OperationPending),
            MessageResponseBatchItem::new(ResultStatusEnumeration::OperationPending),
        ],
    };
    assert_eq!(
        to_ttlv(&res).unwrap_err().to_string(),
        "mismatch number of batch items between header (`22`) and items list (`1`)".to_string()
    );

    let res = MessageResponse {
        header: MessageResponseHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 128,
                protocol_version_minor: 128,
            },
            batch_count: 1,
            timestamp: 1697201574,
            ..Default::default()
        },
        items: vec![MessageResponseBatchItem::new_with_response(
            ResultStatusEnumeration::OperationPending,
            Operation::Locate(Locate::default()),
        )],
    };
    assert_eq!(
        to_ttlv(&res).unwrap_err().to_string(),
        "item's protocol version is greater (`128.128`) than header's protocol version (`2.1`)"
            .to_string()
    );

    let res = MessageResponse {
        header: MessageResponseHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            batch_count: 1,
            client_correlation_value: Some("client_123".to_string()),
            server_correlation_value: Some("server_234".to_string()),
            attestation_type: Some(vec![AttestationType::TPM_Quote]),
            timestamp: 1697201574,
            nonce: Some(Nonce {
                nonce_id: vec![5, 6, 7],
                nonce_value: vec![8, 9, 0],
            }),
            server_hashed_password: Some("5e8953ab".to_string()),
        },
        items: vec![MessageResponseBatchItem {
            operation: Some(OperationEnumeration::Locate),
            unique_batch_item_id: Some(1234),
            // in a message response, we can't have `Operation::Locate`,
            // we could only have an `Operation::LocateResponse`
            response_payload: Some(Operation::Locate(Locate::default())),
            message_extension: Some(MessageExtension {
                vendor_identification: "CosmianVendor".to_string(),
                criticality_indicator: false,
                vendor_extension: vec![42_u8],
            }),
            result_status: ResultStatusEnumeration::OperationPending,
            result_reason: None,
            result_message: None,
            asynchronous_correlation_value: Some(vec![42_u8, 5]),
        }],
    };
    assert_eq!(
        to_ttlv(&res).unwrap_err().to_string(),
        "response payload operation is not a response type operation (`Request`)".to_string()
    );
}

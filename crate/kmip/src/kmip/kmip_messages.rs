/// The messages in the protocol consist of a message header,
/// one or more batch items (which contain OPTIONAL message payloads),
/// and OPTIONAL message extensions. The message headers contain fields whose
/// presence is determined by the protocol features used (e.g., asynchronous responses).
/// The field contents are also determined by whether the message is a request or a response.
/// The message payload is determined by the specific operation being
/// requested or to which is being replied.
///
/// The message headers are structures that contain some of the following objects.
///
/// Messages contain the following objects and fields.
/// All fields SHALL appear in the order specified.
///
/// If the client is capable of accepting asynchronous responses,
/// then it MAY set the Asynchronous
///
/// Indicator in the header of a batched request.
/// The batched responses MAY contain a mixture of synchronous and
/// asynchronous responses only if the Asynchronous Indicator is present in the header.
use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Serialize,
};

use super::{
    kmip_operations::{ErrorReason, Operation},
    kmip_types::{
        AsynchronousIndicator, AttestationType, BatchErrorContinuationOption, Credential,
        MessageExtension, Nonce, OperationEnumeration, ProtocolVersion, ResultStatusEnumeration,
    },
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RequestMessage {
    /// Header of the request
    pub header: RequestHeader,
    /// Batch items of the request
    pub items: Vec<RequestBatchItem>,
}

/// Header of the request
///
/// Contains fields whose presence is determined by the protocol features used.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RequestHeader {
    pub protocol_version: ProtocolVersion,
    /// This is an OPTIONAL field contained in a request message,
    /// and is used to indicate the maximum size of a response, in bytes,
    /// that the requester SHALL be able to handle.
    ///
    /// It SHOULD only be sent in requests that possibly return large replies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_response_size: Option<u32>,
    /// The Client Correlation Value is a string that MAY be added to messages by clients
    /// to provide additional information to the server. It need not be unique.
    /// The server SHOULD log this information.
    ///
    /// For client to server operations, the Client Correlation Value is provided in the request.
    /// For server to client operations, the Client Correlation Value is provided in the response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_correlation_value: Option<String>,
    /// The Server Correlation Value SHOULD be provided by the server and
    /// SHOULD be globally unique, and SHOULD be logged by the server with each request.
    ///
    /// For client to server operations, the Server Correlation Value is provided in the response.
    /// For server to client operations, the Server Correlation Value is provided in the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_correlation_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asynchronous_indicator: Option<AsynchronousIndicator>,
    /// Indicates whether the client is able to create
    /// an Attestation Credential Object.
    ///
    /// If not present, the value `false` is assumed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_capable_indicator: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_type: Option<Vec<AttestationType>>,
    /// Used to authenticate the requester
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<Credential>>,
    /// If omitted, then `Stop` is assumed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_error_continuation_option: Option<BatchErrorContinuationOption>,
    /// If omitted, then `true` is assumed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_order_option: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>, // epoch millis
    /// This field contains the number of Batch Items in a message and is REQUIRED.
    ///
    /// If only a single operation is being requested, then the batch count SHALL be set to 1.
    /// The Message Payload, which follows the Message Header, contains one or more batch items.
    pub batch_count: u32,
}

/// Batch item for a message request
///
/// `request_payload` depends on the request
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RequestBatchItem {
    pub operation: OperationEnumeration,
    /// Indicates that the Data output of the operation should not
    /// be returned to the client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral: Option<bool>,
    /// Required if `batch_count` > 1
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_batch_item_id: Option<u32>,
    /// The KMIP request, which depends on the KMIP Operation
    pub request_payload: Operation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_extension: Option<Vec<MessageExtension>>,
}

impl<'de> Deserialize<'de> for RequestBatchItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier)]
        enum Field {
            Operation,
            Ephemeral,
            UniqueBatchItemId,
            RequestPayload,
            MessageExtension,
        }

        struct RequestBatchItemVisitor;

        impl<'de> Visitor<'de> for RequestBatchItemVisitor {
            type Value = RequestBatchItem;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct RequestBatchItem")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut operation: Option<OperationEnumeration> = None;
                let mut ephemeral: Option<bool> = None;
                let mut unique_batch_item_id: Option<u32> = None;
                let mut request_payload: Option<Operation> = None;
                let mut message_extension: Option<Vec<MessageExtension>> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Operation => {
                            if operation.is_some() {
                                return Err(de::Error::duplicate_field("operation"))
                            }
                            operation = Some(map.next_value()?);
                        }
                        Field::Ephemeral => {
                            if ephemeral.is_some() {
                                return Err(de::Error::duplicate_field("ephemeral"))
                            }
                            ephemeral = Some(map.next_value()?);
                        }
                        Field::UniqueBatchItemId => {
                            if unique_batch_item_id.is_some() {
                                return Err(de::Error::duplicate_field("unique_batch_item_id"))
                            }
                            unique_batch_item_id = Some(map.next_value()?);
                        }
                        Field::MessageExtension => {
                            if message_extension.is_some() {
                                return Err(de::Error::duplicate_field("message_extension"))
                            }
                            message_extension = Some(map.next_value()?);
                        }
                        Field::RequestPayload => {
                            if request_payload.is_some() {
                                return Err(de::Error::duplicate_field("request_payload"))
                            }
                            // we must have parsed the `operation` field before
                            // TODO: handle the case where the keys are not in right order
                            let Some(operation) = operation else {
                                return Err(de::Error::missing_field("operation"))
                            };
                            // recover by hand the proper type of `request_payload`
                            // the default derived deserializer does not have enough
                            // information to properly recover which type has been
                            // serialized, we need to do the job by hand,
                            // using the `operation` enum.
                            request_payload = Some(match operation {
                                OperationEnumeration::Encrypt => {
                                    Operation::Encrypt(map.next_value()?)
                                }
                                OperationEnumeration::Create => {
                                    Operation::Create(map.next_value()?)
                                }
                                OperationEnumeration::CreateKeyPair => {
                                    Operation::CreateKeyPair(map.next_value()?)
                                }
                                OperationEnumeration::Certify => {
                                    Operation::Certify(map.next_value()?)
                                }
                                OperationEnumeration::Locate => {
                                    Operation::Locate(map.next_value()?)
                                }
                                OperationEnumeration::Get => Operation::Get(map.next_value()?),
                                OperationEnumeration::GetAttributes => {
                                    Operation::GetAttributes(map.next_value()?)
                                }
                                OperationEnumeration::Revoke => {
                                    Operation::Revoke(map.next_value()?)
                                }
                                OperationEnumeration::Destroy => {
                                    Operation::Destroy(map.next_value()?)
                                }
                                OperationEnumeration::Decrypt => {
                                    Operation::Decrypt(map.next_value()?)
                                }
                                OperationEnumeration::Import => {
                                    Operation::Import(map.next_value()?)
                                }
                                OperationEnumeration::Export => {
                                    Operation::Export(map.next_value()?)
                                }
                                _ => return Err(de::Error::missing_field("valid enum operation")),
                            });
                        }
                    }
                }
                let operation = operation.ok_or_else(|| de::Error::missing_field("operation"))?;
                tracing::trace!("RequestBatchItem operation: {operation:?}");

                let request_payload =
                    request_payload.ok_or_else(|| de::Error::missing_field("request_payload"))?;
                tracing::trace!("RequestBatchItem request payload: {request_payload:?}");

                Ok(RequestBatchItem {
                    operation,
                    ephemeral,
                    unique_batch_item_id,
                    request_payload,
                    message_extension,
                })
            }
        }

        const FIELDS: &[&str] = &[
            "operation",
            "ephemeral",
            "unique_batch_item_id",
            "request_payload",
            "message_extension",
        ];
        deserializer.deserialize_struct("RequestBatchItem", FIELDS, RequestBatchItemVisitor)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ResponseMessage {
    /// Header of the response
    pub header: ResponseHeader,
    /// Batch items of the response
    pub items: Vec<ResponseBatchItem>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ResponseHeader {
    pub protocol_version: ProtocolVersion,
    pub timestamp: u64, // epoch millis
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<Nonce>,
    /// Mandatory only if Hashed Password credential was used
    ///
    /// Hash(Timestamp || S1 || Hash(S2)), where S1, S2 and
    /// the Hash algorithm are defined in the Hashed Password credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_hashed_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_type: Option<Vec<AttestationType>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_correlation_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_correlation_value: Option<String>,
    /// This field contains the number of Batch Items in a message and is REQUIRED.
    ///
    /// If only a single operation is being requested, then the batch count SHALL be set to 1.
    /// The Message Payload, which follows the Message Header, contains one or more batch items.
    pub batch_count: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ResponseBatchItem {
    /// Required if present in Request Batch Item
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<OperationEnumeration>,
    /// Required if present in Request Batch Item
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_batch_item_id: Option<u32>,
    /// Indicates the success or failure of a request
    pub result_status: ResultStatusEnumeration,
    /// Indicates a reason for failure or a modifier for a
    /// partially successful operation and SHALL be present in
    /// responses that return a Result Status of Failure.
    ///
    /// Required if `result_status` is `Failure`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_reason: Option<ErrorReason>,
    /// Contains a more descriptive error message,
    /// which MAY be provided to an end user or used for logging/auditing purposes.
    ///
    /// Required if `result_status` is NOT `Pending` or `Success`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_message: Option<String>,
    /// Returned in the immediate response to an operation that is pending and
    /// that requires asynchronous polling. Note: the server decides which
    /// operations are performed synchronously or asynchronously.
    ///
    /// A server-generated correlation value SHALL be specified in any subsequent
    /// Poll or Cancel operations that pertain to the original operation.
    ///
    /// Required if `result_status` is `Pending`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asynchronous_correlation_value: Option<Vec<u8>>,
    /// The KMIP response, which depends on the KMIP Operation
    ///
    /// Mandatory if a success, `None` in case of failure.
    ///
    /// Content depends on Operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_payload: Option<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_extension: Option<MessageExtension>,
}

impl<'de> Deserialize<'de> for ResponseBatchItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier)]
        enum Field {
            Operation,
            UniqueBatchItemId,
            ResultStatus,
            ResultReason,
            ResultMessage,
            AsynchronousCorrelationValue,
            ResponsePayload,
            MessageExtension,
        }

        struct ResponseBatchItemVisitor;

        impl<'de> Visitor<'de> for ResponseBatchItemVisitor {
            type Value = ResponseBatchItem;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct ResponseBatchItem")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut operation: Option<OperationEnumeration> = None;
                let mut unique_batch_item_id: Option<u32> = None;
                let mut result_status: Option<ResultStatusEnumeration> = None;
                let mut result_reason: Option<ErrorReason> = None;
                let mut result_message: Option<String> = None;
                let mut asynchronous_correlation_value: Option<Vec<u8>> = None;
                let mut response_payload: Option<Operation> = None;
                let mut message_extension: Option<MessageExtension> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Operation => {
                            if operation.is_some() {
                                return Err(de::Error::duplicate_field("operation"))
                            }
                            operation = Some(map.next_value()?);
                        }
                        Field::UniqueBatchItemId => {
                            if unique_batch_item_id.is_some() {
                                return Err(de::Error::duplicate_field("unique_batch_item_id"))
                            }
                            unique_batch_item_id = Some(map.next_value()?);
                        }
                        Field::MessageExtension => {
                            if message_extension.is_some() {
                                return Err(de::Error::duplicate_field("message_extension"))
                            }
                            message_extension = Some(map.next_value()?);
                        }
                        Field::ResultStatus => {
                            if result_status.is_some() {
                                return Err(de::Error::duplicate_field("result_status"))
                            }
                            result_status = Some(map.next_value()?);
                        }
                        Field::ResultReason => {
                            if result_reason.is_some() {
                                return Err(de::Error::duplicate_field("result_reason"))
                            }
                            result_reason = Some(map.next_value()?);
                        }
                        Field::ResultMessage => {
                            if result_message.is_some() {
                                return Err(de::Error::duplicate_field("result_message"))
                            }
                            result_message = Some(map.next_value()?);
                        }
                        Field::AsynchronousCorrelationValue => {
                            if asynchronous_correlation_value.is_some() {
                                return Err(de::Error::duplicate_field(
                                    "asynchronous_correlation_value",
                                ))
                            }
                            asynchronous_correlation_value = Some(map.next_value()?);
                        }
                        Field::ResponsePayload => {
                            if response_payload.is_some() {
                                return Err(de::Error::duplicate_field("response_payload"))
                            }
                            // we must have parsed the `operation` field before
                            // TODO: handle the case where the keys are not in right order
                            let Some(operation) = operation else {
                                return Err(de::Error::missing_field("operation"))
                            };
                            // recover by hand the proper type of `response_payload`
                            // the default derived deserializer does not have enough
                            // information to properly recover which type has been
                            // serialized, we need to do the job by hand,
                            // using the `operation` enum.
                            response_payload = Some(match operation {
                                OperationEnumeration::Encrypt => {
                                    Operation::Encrypt(map.next_value()?)
                                }
                                OperationEnumeration::Create => {
                                    Operation::Create(map.next_value()?)
                                }
                                OperationEnumeration::CreateKeyPair => {
                                    Operation::CreateKeyPair(map.next_value()?)
                                }
                                OperationEnumeration::Certify => {
                                    Operation::Certify(map.next_value()?)
                                }
                                OperationEnumeration::Locate => {
                                    Operation::Locate(map.next_value()?)
                                }
                                OperationEnumeration::Get => Operation::Get(map.next_value()?),
                                OperationEnumeration::GetAttributes => {
                                    Operation::GetAttributes(map.next_value()?)
                                }
                                OperationEnumeration::Revoke => {
                                    Operation::Revoke(map.next_value()?)
                                }
                                OperationEnumeration::Destroy => {
                                    Operation::Destroy(map.next_value()?)
                                }
                                OperationEnumeration::Decrypt => {
                                    Operation::Decrypt(map.next_value()?)
                                }
                                OperationEnumeration::Import => {
                                    Operation::Import(map.next_value()?)
                                }
                                OperationEnumeration::Export => {
                                    Operation::Export(map.next_value()?)
                                }
                                _ => {
                                    return Err(de::Error::missing_field(
                                        "valid enum operation (unsupported operation ?)",
                                    ))
                                }
                            });
                        }
                    }
                }

                let result_status =
                    result_status.ok_or_else(|| de::Error::missing_field("result_status"))?;

                tracing::trace!("ResponseBatchItem operation: {operation:?}");
                tracing::trace!("ResponseBatchItem response payload: {response_payload:?}");

                Ok(ResponseBatchItem {
                    operation,
                    unique_batch_item_id,
                    result_status,
                    result_reason,
                    result_message,
                    asynchronous_correlation_value,
                    response_payload,
                    message_extension,
                })
            }
        }

        const FIELDS: &[&str] = &[
            "operation",
            "unique_batch_item_id",
            "result_status",
            "result_reason",
            "result_message",
            "asynchronous_correlation_value",
            "response_payload",
            "message_extension",
        ];
        deserializer.deserialize_struct("ResponseBatchItem", FIELDS, ResponseBatchItemVisitor)
    }
}

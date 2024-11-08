use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Hash, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum KmipOperation {
    Create,
    Certify,
    Decrypt,
    Destroy,
    Encrypt,
    Export,
    Get,
    GetAttributes,
    Import,
    Locate,
    Revoke,
    Rekey,
    Validate,
}

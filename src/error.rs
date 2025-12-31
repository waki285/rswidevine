//! Error types for rswidevine.

use thiserror::Error;

/// Main error type for rswidevine operations.
#[derive(Debug, Error)]
pub enum Error {
    /// Too many sessions are open.
    #[error("Too many sessions open (max {max})")]
    TooManySessions { max: usize },

    /// No session is open with the specified identifier.
    #[error("Session identifier {0:?} is invalid")]
    InvalidSession(Vec<u8>),

    /// The Widevine Cenc Header Data is invalid or empty.
    #[error("Invalid init data: {0}")]
    InvalidInitData(String),

    /// The License Type is an invalid value.
    #[error("Invalid license type: {0}")]
    InvalidLicenseType(String),

    /// The License Message is invalid or missing.
    #[error("Invalid license message: {0}")]
    InvalidLicenseMessage(String),

    /// The Context is invalid or missing.
    #[error("Invalid context: {0}")]
    InvalidContext(String),

    /// The Signature did not match.
    #[error("Signature mismatch: {0}")]
    SignatureMismatch(String),

    /// No License was parsed for this Session, No Keys available.
    #[error("No keys loaded for this session")]
    NoKeysLoaded,

    /// The Remote CDM's Device information and the API's Device information did not match.
    #[error("Device mismatch: {0}")]
    DeviceMismatch(String),

    /// Failed to decode data.
    #[error("Decode error: {0}")]
    DecodeError(String),

    /// Failed to parse protobuf message.
    #[error("Protobuf decode error: {0}")]
    ProtobufDecodeError(#[from] prost::DecodeError),

    /// RSA error.
    #[error("RSA error: {0}")]
    RsaError(#[from] rsa::Error),

    /// PKCS8 error.
    #[error("PKCS8 error: {0}")]
    Pkcs8Error(#[from] rsa::pkcs8::Error),

    /// Base64 decode error.
    #[error("Base64 decode error: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),

    /// IO error.
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Invalid WVD file.
    #[error("Invalid WVD file: {0}")]
    InvalidWvdFile(String),

    /// Generic error.
    #[error("{0}")]
    Other(String),
}

/// Result type alias for rswidevine operations.
pub type Result<T> = std::result::Result<T, Error>;

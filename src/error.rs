use thiserror::Error;

#[derive(Error, Debug)]
pub enum LotlError {
    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Signal protocol error: {0}")]
    SignalProtocol(#[from] libsignal_protocol::SignalProtocolError),

    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),

    #[error("Cryptography error: {0}")]
    Crypto(String),

    #[error("Invalid fingerprint: {0}")]
    InvalidFingerprint(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Contact not found: {0}")]
    ContactNotFound(String),

    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("UTF-8 encoding error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("Hex decoding error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("Base64 decoding error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, LotlError>;

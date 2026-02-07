/// Configuration for lotl session manager
#[derive(Clone, Debug)]
pub struct LotlConfig {
    /// SQLite database path
    pub db_path: String,

    /// Fingerprint generation salt (default: "signal-identity-fingerprint")
    pub fingerprint_salt: String,

    /// Optional prefix for generated fingerprints (default: "" for no prefix)
    pub fingerprint_prefix: String,
}

impl Default for LotlConfig {
    fn default() -> Self {
        Self {
            db_path: String::new(),
            fingerprint_salt: "signal-identity-fingerprint".to_string(),
            fingerprint_prefix: String::new(),
        }
    }
}

/// Contact information
#[derive(Clone, Debug)]
pub struct ContactInfo {
    pub fingerprint: String,
    pub signal_identity_key: Vec<u8>,
    pub user_alias: Option<String>,
    pub first_seen: i64,
    pub last_updated: i64,
}

/// Message direction
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessageDirection {
    Sent,
    Received,
}

/// Message record
#[derive(Clone, Debug)]
pub struct MessageRecord {
    pub id: i64,
    pub fingerprint: String,
    pub direction: MessageDirection,
    pub plaintext: Vec<u8>,
    pub timestamp: i64,
}

/// Conversation record
#[derive(Clone, Debug)]
pub struct ConversationRecord {
    pub id: i64,
    pub fingerprint: String,
    pub last_message_timestamp: i64,
}

/// Key maintenance result
#[derive(Clone, Debug)]
pub struct MaintenanceResult {
    pub pre_keys_generated: u32,
    pub signed_pre_key_rotated: bool,
    pub kyber_pre_key_rotated: bool,
}

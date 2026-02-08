//! Nostr integration types

#[cfg(feature = "nostr")]
use nostr::{PublicKey, SecretKey};

/// Configuration for Nostr integration
#[cfg(feature = "nostr")]
#[derive(Debug, Clone)]
pub struct NostrConfig {
    /// Application-specific HKDF context for key derivation
    pub derivation_context: String,
    /// Nostr event d-tag for bundle announcements
    pub bundle_tag: String,
}

#[cfg(feature = "nostr")]
impl Default for NostrConfig {
    fn default() -> Self {
        Self {
            derivation_context: "lotl_nostr_derivation".to_string(),
            bundle_tag: "lotl_prekey_bundle_v1".to_string(),
        }
    }
}

/// Nostr keypair derived from Signal Protocol identity
#[cfg(feature = "nostr")]
#[derive(Debug)]
pub struct NostrKeys {
    /// Nostr secret key
    pub secret_key: SecretKey,
    /// Nostr public key
    pub public_key: PublicKey,
}

#[cfg(all(test, feature = "nostr"))]
mod tests {
    use super::*;

    #[test]
    fn test_nostr_config_default() {
        let config = NostrConfig::default();
        assert_eq!(config.derivation_context, "lotl_nostr_derivation");
        assert_eq!(config.bundle_tag, "lotl_prekey_bundle_v1");
    }

    #[test]
    fn test_nostr_config_custom() {
        let config = NostrConfig {
            derivation_context: "custom_context".to_string(),
            bundle_tag: "custom_tag".to_string(),
        };
        assert_eq!(config.derivation_context, "custom_context");
        assert_eq!(config.bundle_tag, "custom_tag");
    }
}

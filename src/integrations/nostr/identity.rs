//! Nostr identity derivation from Signal Protocol keys
//!
//! This module handles deriving Nostr keypairs from Signal Protocol identity keys
//! using HKDF, ensuring deterministic key generation with configurable derivation context.

#[cfg(feature = "nostr")]
use crate::error::{LotlError, Result};
#[cfg(feature = "nostr")]
use crate::integrations::nostr::types::{NostrConfig, NostrKeys};
#[cfg(feature = "nostr")]
use hkdf::Hkdf;
#[cfg(feature = "nostr")]
use nostr::{Keys, SecretKey};
#[cfg(feature = "nostr")]
use sha2::Sha256;

/// Derives a Nostr keypair from a Signal Protocol identity key
///
/// Uses HKDF-SHA256 to deterministically derive a Nostr secret key from
/// the Signal identity key bytes. The derivation context is configurable
/// via the NostrConfig parameter.
///
/// # Arguments
/// * `signal_identity_key` - The Signal Protocol identity key bytes
/// * `config` - Configuration containing the derivation context
///
/// # Returns
/// A NostrKeys struct containing both the secret and public keys
///
/// # Errors
/// Returns an error if HKDF expansion fails or the derived key is invalid
#[cfg(feature = "nostr")]
pub fn derive_nostr_keypair(signal_identity_key: &[u8], config: &NostrConfig) -> Result<NostrKeys> {
    let hk = Hkdf::<Sha256>::new(None, signal_identity_key);
    let mut derived_key = [0u8; 32];

    hk.expand(config.derivation_context.as_bytes(), &mut derived_key)
        .map_err(|_| LotlError::Crypto("HKDF expansion failed".to_string()))?;

    let secret_key = SecretKey::from_slice(&derived_key)
        .map_err(|e| LotlError::Crypto(format!("Invalid secret key: {}", e)))?;

    let keys = Keys::new(secret_key.clone());
    let public_key = keys.public_key();

    Ok(NostrKeys { secret_key, public_key })
}

#[cfg(all(test, feature = "nostr"))]
mod tests {
    use super::*;

    #[test]
    fn test_derive_nostr_keypair_deterministic() {
        let identity_key = [0x42u8; 32];
        let config = NostrConfig::default();

        let keys1 = derive_nostr_keypair(&identity_key, &config).unwrap();
        let keys2 = derive_nostr_keypair(&identity_key, &config).unwrap();

        assert_eq!(keys1.secret_key.to_secret_bytes(), keys2.secret_key.to_secret_bytes());
        assert_eq!(keys1.public_key, keys2.public_key);
    }

    #[test]
    fn test_derive_nostr_keypair_different_contexts() {
        let identity_key = [0x42u8; 32];

        let config1 = NostrConfig {
            derivation_context: "context1".to_string(),
            bundle_tag: "tag1".to_string(),
        };

        let config2 = NostrConfig {
            derivation_context: "context2".to_string(),
            bundle_tag: "tag1".to_string(),
        };

        let keys1 = derive_nostr_keypair(&identity_key, &config1).unwrap();
        let keys2 = derive_nostr_keypair(&identity_key, &config2).unwrap();

        assert_ne!(keys1.secret_key.to_secret_bytes(), keys2.secret_key.to_secret_bytes());
        assert_ne!(keys1.public_key, keys2.public_key);
    }

    #[test]
    fn test_derive_nostr_keypair_different_inputs() {
        let identity_key1 = [0x42u8; 32];
        let identity_key2 = [0x43u8; 32];
        let config = NostrConfig::default();

        let keys1 = derive_nostr_keypair(&identity_key1, &config).unwrap();
        let keys2 = derive_nostr_keypair(&identity_key2, &config).unwrap();

        assert_ne!(keys1.secret_key.to_secret_bytes(), keys2.secret_key.to_secret_bytes());
        assert_ne!(keys1.public_key, keys2.public_key);
    }

    #[test]
    fn test_public_key_matches_secret_key() {
        let identity_key = [0x42u8; 32];
        let config = NostrConfig::default();

        let nostr_keys = derive_nostr_keypair(&identity_key, &config).unwrap();
        let keys_from_secret = Keys::new(nostr_keys.secret_key.clone());

        assert_eq!(nostr_keys.public_key, keys_from_secret.public_key());
    }
}

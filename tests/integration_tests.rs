//! Integration tests for lotl

use lotl::{Config, Lotl};
use tempfile::TempDir;

fn create_test_config(temp_dir: &TempDir) -> Config {
    Config {
        db_path: temp_dir.path().join("test.db").to_str().unwrap().to_string(),
        fingerprint_salt: "test_salt".to_string(),
        fingerprint_prefix: String::new(),
    }
}

#[tokio::test]
async fn test_lotl_creation_and_identity() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let config = create_test_config(&temp_dir);

    let lotl = Lotl::new(config).await?;

    let identity_key = lotl.get_identity_key()?;
    assert!(!identity_key.is_empty());
    assert_eq!(identity_key.len(), 33);

    let fingerprint = lotl.get_fingerprint()?;
    assert!(!fingerprint.is_empty());
    assert_eq!(fingerprint.len(), 64);

    Ok(())
}

#[tokio::test]
async fn test_identity_persistence() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let config = create_test_config(&temp_dir);

    let lotl1 = Lotl::new(config.clone()).await?;
    let identity1 = lotl1.get_identity_key()?;
    let fingerprint1 = lotl1.get_fingerprint()?;
    drop(lotl1);

    let lotl2 = Lotl::new(config).await?;
    let identity2 = lotl2.get_identity_key()?;
    let fingerprint2 = lotl2.get_fingerprint()?;

    assert_eq!(identity1, identity2, "Identity should persist across restarts");
    assert_eq!(fingerprint1, fingerprint2, "Fingerprint should persist across restarts");

    Ok(())
}

#[tokio::test]
async fn test_generate_prekey_bundle() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let config = create_test_config(&temp_dir);

    let mut lotl = Lotl::new(config).await?;

    let bundle = lotl.generate_prekey_bundle().await?;
    assert!(!bundle.is_empty());

    let bundle2 = lotl.generate_prekey_bundle().await?;
    assert!(!bundle2.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_session_establishment_and_encryption() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir_alice = TempDir::new()?;
    let temp_dir_bob = TempDir::new()?;

    let config_alice = Config {
        db_path: temp_dir_alice.path().join("alice.db").to_str().unwrap().to_string(),
        ..Default::default()
    };

    let config_bob = Config {
        db_path: temp_dir_bob.path().join("bob.db").to_str().unwrap().to_string(),
        ..Default::default()
    };

    let mut alice = Lotl::new(config_alice).await?;
    let mut bob = Lotl::new(config_bob).await?;

    let alice_fingerprint = alice.get_fingerprint()?;
    let bob_fingerprint = bob.get_fingerprint()?;

    assert!(!alice.has_session(bob_fingerprint.clone()));
    assert!(!bob.has_session(alice_fingerprint.clone()));

    let bob_bundle = bob.generate_prekey_bundle().await?;
    alice.process_prekey_bundle(bob_fingerprint.clone(), &bob_bundle).await?;

    assert!(alice.has_session(bob_fingerprint.clone()));

    let plaintext = b"Hello, Bob!";
    let ciphertext = alice.encrypt(bob_fingerprint.clone(), plaintext).await?;
    assert!(!ciphertext.is_empty());
    assert_ne!(ciphertext, plaintext);

    let decrypted = bob.decrypt(alice_fingerprint.clone(), &ciphertext).await?;
    assert_eq!(decrypted, plaintext);

    assert!(bob.has_session(alice_fingerprint.clone()));

    Ok(())
}

#[tokio::test]
async fn test_bidirectional_messaging() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir_alice = TempDir::new()?;
    let temp_dir_bob = TempDir::new()?;

    let config_alice = Config {
        db_path: temp_dir_alice.path().join("alice.db").to_str().unwrap().to_string(),
        ..Default::default()
    };

    let config_bob = Config {
        db_path: temp_dir_bob.path().join("bob.db").to_str().unwrap().to_string(),
        ..Default::default()
    };

    let mut alice = Lotl::new(config_alice).await?;
    let mut bob = Lotl::new(config_bob).await?;

    let alice_fingerprint = alice.get_fingerprint()?;
    let bob_fingerprint = bob.get_fingerprint()?;

    let alice_bundle = alice.generate_prekey_bundle().await?;
    let bob_bundle = bob.generate_prekey_bundle().await?;

    alice.process_prekey_bundle(bob_fingerprint.clone(), &bob_bundle).await?;
    bob.process_prekey_bundle(alice_fingerprint.clone(), &alice_bundle).await?;

    let msg1 = b"Hello from Alice";
    let ciphertext1 = alice.encrypt(bob_fingerprint.clone(), msg1).await?;
    let decrypted1 = bob.decrypt(alice_fingerprint.clone(), &ciphertext1).await?;
    assert_eq!(decrypted1, msg1);

    let msg2 = b"Hello from Bob";
    let ciphertext2 = bob.encrypt(alice_fingerprint.clone(), msg2).await?;
    let decrypted2 = alice.decrypt(bob_fingerprint.clone(), &ciphertext2).await?;
    assert_eq!(decrypted2, msg2);

    let msg3 = b"Another message from Alice";
    let ciphertext3 = alice.encrypt(bob_fingerprint.clone(), msg3).await?;
    let decrypted3 = bob.decrypt(alice_fingerprint.clone(), &ciphertext3).await?;
    assert_eq!(decrypted3, msg3);

    Ok(())
}

#[tokio::test]
async fn test_session_deletion() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir_alice = TempDir::new()?;
    let temp_dir_bob = TempDir::new()?;

    let config_alice = Config {
        db_path: temp_dir_alice.path().join("alice.db").to_str().unwrap().to_string(),
        ..Default::default()
    };

    let config_bob = Config {
        db_path: temp_dir_bob.path().join("bob.db").to_str().unwrap().to_string(),
        ..Default::default()
    };

    let mut alice = Lotl::new(config_alice).await?;
    let mut bob = Lotl::new(config_bob).await?;

    let bob_fingerprint = bob.get_fingerprint()?;
    let bob_bundle = bob.generate_prekey_bundle().await?;

    alice.process_prekey_bundle(bob_fingerprint.clone(), &bob_bundle).await?;

    assert!(alice.has_session(bob_fingerprint.clone()));

    alice.delete_session(bob_fingerprint.clone()).await?;

    assert!(!alice.has_session(bob_fingerprint.clone()));

    Ok(())
}

#[tokio::test]
async fn test_key_maintenance() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let config = create_test_config(&temp_dir);

    let mut lotl = Lotl::new(config).await?;

    let result = lotl.perform_key_maintenance().await?;

    assert!(!result.signed_pre_key_rotated);
    assert!(!result.kyber_pre_key_rotated);

    Ok(())
}

#[tokio::test]
async fn test_contact_management() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let config = create_test_config(&temp_dir);

    let lotl = Lotl::new(config).await?;

    let contacts = lotl.list_contacts()?;
    assert_eq!(contacts.len(), 0);

    let identity_key = b"test_identity_key_1";
    let fingerprint = lotl.add_contact(identity_key, Some("Alice".to_string()))?;

    assert!(!fingerprint.is_empty());

    let contact = lotl.lookup_contact(&fingerprint)?.unwrap();
    assert_eq!(contact.fingerprint, fingerprint);
    assert_eq!(contact.signal_identity_key, identity_key);
    assert_eq!(contact.user_alias, Some("Alice".to_string()));

    let contacts = lotl.list_contacts()?;
    assert_eq!(contacts.len(), 1);

    let identity_key2 = b"test_identity_key_2";
    let _fingerprint2 = lotl.add_contact(identity_key2, Some("Bob".to_string()))?;

    let contacts = lotl.list_contacts()?;
    assert_eq!(contacts.len(), 2);

    let nonexistent = lotl.lookup_contact("nonexistent")?;
    assert!(nonexistent.is_none());

    Ok(())
}

#[tokio::test]
async fn test_add_contact_from_bundle() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir_alice = TempDir::new()?;
    let temp_dir_bob = TempDir::new()?;

    let config_alice = Config {
        db_path: temp_dir_alice.path().join("alice.db").to_str().unwrap().to_string(),
        ..Default::default()
    };

    let config_bob = Config {
        db_path: temp_dir_bob.path().join("bob.db").to_str().unwrap().to_string(),
        ..Default::default()
    };

    let alice = Lotl::new(config_alice).await?;
    let bob = Lotl::new(config_bob).await?;

    let bob_identity_key = bob.get_identity_key()?;
    let bob_fingerprint = bob.get_fingerprint()?;

    let stored_fingerprint = alice.add_contact(&bob_identity_key, Some("Bob".to_string()))?;

    assert_eq!(stored_fingerprint, bob_fingerprint);

    let contact = alice.lookup_contact(&bob_fingerprint)?.unwrap();
    assert_eq!(contact.user_alias, Some("Bob".to_string()));

    Ok(())
}

#[tokio::test]
async fn test_multiple_messages_same_session() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir_alice = TempDir::new()?;
    let temp_dir_bob = TempDir::new()?;

    let config_alice = Config {
        db_path: temp_dir_alice.path().join("alice.db").to_str().unwrap().to_string(),
        ..Default::default()
    };

    let config_bob = Config {
        db_path: temp_dir_bob.path().join("bob.db").to_str().unwrap().to_string(),
        ..Default::default()
    };

    let mut alice = Lotl::new(config_alice).await?;
    let mut bob = Lotl::new(config_bob).await?;

    let alice_fingerprint = alice.get_fingerprint()?;
    let bob_fingerprint = bob.get_fingerprint()?;

    let bob_bundle = bob.generate_prekey_bundle().await?;
    alice.process_prekey_bundle(bob_fingerprint.clone(), &bob_bundle).await?;

    for i in 0..10 {
        let message = format!("Message number {}", i);
        let ciphertext = alice.encrypt(bob_fingerprint.clone(), message.as_bytes()).await?;
        let decrypted = bob.decrypt(alice_fingerprint.clone(), &ciphertext).await?;
        assert_eq!(decrypted, message.as_bytes());
    }

    Ok(())
}

#[tokio::test]
async fn test_empty_message() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir_alice = TempDir::new()?;
    let temp_dir_bob = TempDir::new()?;

    let config_alice = Config {
        db_path: temp_dir_alice.path().join("alice.db").to_str().unwrap().to_string(),
        ..Default::default()
    };

    let config_bob = Config {
        db_path: temp_dir_bob.path().join("bob.db").to_str().unwrap().to_string(),
        ..Default::default()
    };

    let mut alice = Lotl::new(config_alice).await?;
    let mut bob = Lotl::new(config_bob).await?;

    let alice_fingerprint = alice.get_fingerprint()?;
    let bob_fingerprint = bob.get_fingerprint()?;

    let bob_bundle = bob.generate_prekey_bundle().await?;
    alice.process_prekey_bundle(bob_fingerprint.clone(), &bob_bundle).await?;

    let empty_message = b"";
    let ciphertext = alice.encrypt(bob_fingerprint.clone(), empty_message).await?;
    let decrypted = bob.decrypt(alice_fingerprint.clone(), &ciphertext).await?;
    assert_eq!(decrypted, empty_message);

    Ok(())
}

#[tokio::test]
async fn test_large_message() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir_alice = TempDir::new()?;
    let temp_dir_bob = TempDir::new()?;

    let config_alice = Config {
        db_path: temp_dir_alice.path().join("alice.db").to_str().unwrap().to_string(),
        ..Default::default()
    };

    let config_bob = Config {
        db_path: temp_dir_bob.path().join("bob.db").to_str().unwrap().to_string(),
        ..Default::default()
    };

    let mut alice = Lotl::new(config_alice).await?;
    let mut bob = Lotl::new(config_bob).await?;

    let alice_fingerprint = alice.get_fingerprint()?;
    let bob_fingerprint = bob.get_fingerprint()?;

    let bob_bundle = bob.generate_prekey_bundle().await?;
    alice.process_prekey_bundle(bob_fingerprint.clone(), &bob_bundle).await?;

    let large_message = vec![0x42u8; 1024 * 100];
    let ciphertext = alice.encrypt(bob_fingerprint.clone(), &large_message).await?;
    let decrypted = bob.decrypt(alice_fingerprint.clone(), &ciphertext).await?;
    assert_eq!(decrypted, large_message);

    Ok(())
}

#[tokio::test]
async fn test_invalid_config() {
    let config = Config { db_path: "".to_string(), ..Default::default() };

    let result = Lotl::new(config).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_encrypt_without_session() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let config = create_test_config(&temp_dir);

    let mut lotl = Lotl::new(config).await?;

    let result = lotl.encrypt("nonexistent_peer".to_string(), b"test").await;
    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_decrypt_invalid_ciphertext() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let config = create_test_config(&temp_dir);

    let mut lotl = Lotl::new(config).await?;

    let invalid_ciphertext = b"invalid_ciphertext_data";
    let result = lotl.decrypt("peer".to_string(), invalid_ciphertext).await;
    assert!(result.is_err());

    Ok(())
}

#[cfg(feature = "nostr")]
mod nostr_tests {
    use super::*;
    use lotl::NostrConfig;

    #[tokio::test]
    async fn test_derive_nostr_keypair() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let config = create_test_config(&temp_dir);

        let lotl = Lotl::new(config).await?;

        let nostr_config = NostrConfig::default();
        let nostr_keys = lotl.derive_nostr_keypair(&nostr_config)?;

        assert_eq!(nostr_keys.secret_key.to_secret_bytes().len(), 32);

        let nostr_keys2 = lotl.derive_nostr_keypair(&nostr_config)?;
        assert_eq!(
            nostr_keys.secret_key.to_secret_bytes(),
            nostr_keys2.secret_key.to_secret_bytes(),
            "Derivation should be deterministic"
        );
        assert_eq!(nostr_keys.public_key, nostr_keys2.public_key, "Public keys should match");

        Ok(())
    }

    #[tokio::test]
    async fn test_store_and_retrieve_nostr_identity() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let config = create_test_config(&temp_dir);

        let lotl = Lotl::new(config).await?;

        let nostr_config = NostrConfig::default();
        let nostr_keys = lotl.derive_nostr_keypair(&nostr_config)?;

        let peer_identity_key = vec![5u8; 33];
        let peer_fingerprint =
            lotl.add_contact(&peer_identity_key, Some("test_peer".to_string()))?;
        let nostr_pubkey = nostr_keys.public_key.to_string();

        lotl.store_nostr_identity(&peer_fingerprint, &nostr_pubkey, &nostr_config)?;

        let retrieved = lotl.get_peer_nostr_pubkey(&peer_fingerprint)?;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), nostr_pubkey);

        Ok(())
    }

    #[tokio::test]
    async fn test_nostr_identity_not_found() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let config = create_test_config(&temp_dir);

        let lotl = Lotl::new(config).await?;

        let result = lotl.get_peer_nostr_pubkey("nonexistent_fingerprint")?;
        assert!(result.is_none());

        Ok(())
    }
}

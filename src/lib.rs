//! lotl - Signal Protocol session management
//!
//! This library provides batteries-included Signal Protocol (X3DH + Double Ratchet)
//! session management with plug-in transport integrations.
//!
//! # Quick Start
//!
//! ```no_run
//! use lotl::{Lotl, Config};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Config {
//!     db_path: "/path/to/database.db".to_string(),
//!     ..Default::default()
//! };
//!
//! let mut lotl = Lotl::new(config).await?;
//!
//! let my_identity = lotl.get_identity_key()?;
//! let my_fingerprint = lotl.get_fingerprint()?;
//!
//! let bundle = lotl.generate_prekey_bundle().await?;
//!
//! # Ok(())
//! # }
//! ```

#![allow(missing_docs)]
#![deny(unsafe_code)]

pub mod contact_manager;
pub mod db_connection;
pub mod db_encryption;
pub mod error;
pub mod integrations;
pub mod key_rotation;
pub mod keys;
pub mod memory_storage;
pub mod message_history;
pub mod signal_storage;
pub mod storage_trait;
pub mod types;

use crate::contact_manager::{generate_fingerprint, init_contacts_table};
use crate::db_connection::DbConnection;
use crate::error::{LotlError, Result};
use crate::key_rotation::{
    cleanup_expired_kyber_pre_keys, cleanup_expired_signed_pre_keys, kyber_pre_key_needs_rotation,
    replenish_pre_keys, rotate_kyber_pre_key, rotate_signed_pre_key, signed_pre_key_needs_rotation,
};
use crate::keys::{generate_identity_key_pair, generate_signed_pre_key};
use crate::signal_storage::SqliteStorage;
use crate::storage_trait::{
    ExtendedIdentityStore, ExtendedKyberPreKeyStore, ExtendedPreKeyStore, ExtendedSessionStore,
    ExtendedSignedPreKeyStore, ExtendedStorageOps, SignalStorageContainer,
};
use crate::types::{ContactInfo, LotlConfig, MaintenanceResult};
use libsignal_protocol::{
    kem, DeviceId, GenericSignedPreKey, IdentityKeyStore, KyberPreKeyId, KyberPreKeyRecord,
    KyberPreKeyStore, PreKeyBundle, PreKeyId, PreKeyStore, ProtocolAddress, SignedPreKeyId,
    SignedPreKeyStore,
};
use rand::Rng;
use serde::{Deserialize, Serialize};

pub use crate::error::LotlError as Error;
pub use crate::types::{
    ContactInfo as Contact, LotlConfig as Config, MaintenanceResult as Maintenance,
};

#[cfg(feature = "nostr")]
pub use crate::integrations::nostr::{NostrConfig, NostrKeys};

/// Main API entry point for lotl
///
/// The `Lotl` struct provides a high-level API for managing Signal Protocol
/// sessions, contacts, and cryptographic operations. It handles:
///
/// - Identity key management
/// - Pre-key bundle generation and processing
/// - Message encryption and decryption
/// - Session management
/// - Contact management
/// - Key rotation and maintenance
pub struct Lotl {
    db_connection: DbConnection,
    config: LotlConfig,
    storage: Option<SqliteStorage>,
}

/// Serializable prekey bundle format
#[derive(Serialize, Deserialize)]
struct SerializableBundle {
    version: String,
    registration_id: u32,
    device_id: u8,
    pre_key_id: u32,
    pre_key_public: Vec<u8>,
    signed_pre_key_id: u32,
    signed_pre_key_public: Vec<u8>,
    signed_pre_key_signature: Vec<u8>,
    identity_key: Vec<u8>,
    kyber_pre_key_id: u32,
    kyber_pre_key_public: Vec<u8>,
    kyber_pre_key_signature: Vec<u8>,
}

impl Lotl {
    /// Creates a new Lotl instance
    ///
    /// Initializes the database connection and sets up the storage backend.
    /// This will create the database file if it doesn't exist.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for the Lotl instance
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Database connection fails
    /// - Schema initialization fails
    /// - Identity key generation fails (on first run)
    pub async fn new(config: LotlConfig) -> Result<Self> {
        if config.db_path.is_empty() {
            return Err(LotlError::InvalidConfig("db_path cannot be empty".to_string()));
        }

        let db_connection = DbConnection::new(&config.db_path)?;

        let mut lotl = Self { db_connection, config, storage: None };

        lotl.ensure_storage_initialized().await?;
        lotl.ensure_identity_initialized().await?;
        lotl.ensure_contacts_table_initialized()?;
        lotl.ensure_message_history_initialized()?;

        Ok(lotl)
    }

    async fn ensure_storage_initialized(&mut self) -> Result<()> {
        if self.storage.is_none() {
            let connection = self.db_connection.connection();
            let mut storage = SqliteStorage::new(connection).await?;
            storage.initialize_schema()?;
            self.storage = Some(storage);
        }
        Ok(())
    }

    async fn ensure_identity_initialized(&mut self) -> Result<()> {
        let storage = self
            .storage
            .as_mut()
            .ok_or_else(|| LotlError::Storage("Storage not initialized".to_string()))?;

        let has_identity = storage.identity_store().get_identity_key_pair().await.is_ok();

        if !has_identity {
            let identity_key_pair = generate_identity_key_pair()
                .await
                .map_err(|e| LotlError::Storage(e.to_string()))?;
            storage
                .identity_store()
                .set_local_identity_key_pair(&identity_key_pair)
                .await
                .map_err(|e| LotlError::Storage(e.to_string()))?;

            let registration_id = rand::rng().random::<u32>() & 0x3FFF;
            storage
                .identity_store()
                .set_local_registration_id(registration_id)
                .await
                .map_err(|e| LotlError::Storage(e.to_string()))?;

            let signed_pre_key = generate_signed_pre_key(&identity_key_pair, 1)
                .await
                .map_err(|e| LotlError::Storage(e.to_string()))?;
            storage
                .signed_pre_key_store()
                .save_signed_pre_key(signed_pre_key.id()?, &signed_pre_key)
                .await?;

            let kyber_record = KyberPreKeyRecord::generate(
                kem::KeyType::Kyber1024,
                KyberPreKeyId::from(1u32),
                identity_key_pair.private_key(),
            )?;
            storage
                .kyber_pre_key_store()
                .save_kyber_pre_key(KyberPreKeyId::from(1u32), &kyber_record)
                .await?;

            replenish_pre_keys(storage).await.map_err(|e| LotlError::Storage(e.to_string()))?;
        }

        Ok(())
    }

    fn ensure_contacts_table_initialized(&self) -> Result<()> {
        let conn = self.db_connection.connection();
        let conn = conn.lock().unwrap();
        init_contacts_table(&conn)?;
        Ok(())
    }

    fn ensure_message_history_initialized(&self) -> Result<()> {
        let conn = self.db_connection.connection();
        let conn = conn.lock().unwrap();
        message_history::init_message_history_tables(&conn)?;
        Ok(())
    }

    /// Returns the local identity key
    ///
    /// # Returns
    ///
    /// The serialized public identity key bytes
    pub fn get_identity_key(&self) -> Result<Vec<u8>> {
        let conn = self.db_connection.connection();
        let conn = conn.lock().unwrap();

        let mut stmt = conn.prepare("SELECT public_key FROM local_identity WHERE id = 1")?;
        let result = stmt.query_row([], |row| {
            let public_key: Vec<u8> = row.get(0)?;
            Ok(public_key)
        });

        match result {
            Ok(public_key) => Ok(public_key),
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                Err(LotlError::Storage("Local identity not initialized".to_string()))
            }
            Err(e) => Err(LotlError::Database(e)),
        }
    }

    /// Returns the fingerprint of the local identity
    ///
    /// The fingerprint is a SHA-256 hash of the identity key with the configured salt.
    ///
    /// # Returns
    ///
    /// A lowercase hexadecimal string representing the fingerprint
    pub fn get_fingerprint(&self) -> Result<String> {
        let identity_key = self.get_identity_key()?;
        Ok(generate_fingerprint(
            &identity_key,
            &self.config.fingerprint_salt,
            &self.config.fingerprint_prefix,
        ))
    }

    /// Generates a serialized prekey bundle for distribution
    ///
    /// The bundle contains all necessary public keys for peers to establish
    /// a session with this instance. The bundle is serialized using bincode.
    ///
    /// # Returns
    ///
    /// A byte vector containing the serialized prekey bundle
    ///
    /// # Errors
    ///
    /// Returns an error if key retrieval or serialization fails
    pub async fn generate_prekey_bundle(&mut self) -> Result<Vec<u8>> {
        self.ensure_storage_initialized().await?;

        let storage = self
            .storage
            .as_mut()
            .ok_or_else(|| LotlError::Storage("Storage not initialized".to_string()))?;

        let identity_key_pair = storage.identity_store().get_identity_key_pair().await?;
        let registration_id = storage.identity_store().get_local_registration_id().await?;

        let pre_key_id = storage
            .pre_key_store()
            .get_max_pre_key_id()
            .await
            .map_err(|e| LotlError::Storage(e.to_string()))?
            .ok_or_else(|| LotlError::KeyNotFound("No pre-keys available".to_string()))?;
        let pre_key_record =
            storage.pre_key_store().get_pre_key(PreKeyId::from(pre_key_id)).await?;

        let signed_pre_key_id = storage
            .signed_pre_key_store()
            .get_max_signed_pre_key_id()
            .await
            .map_err(|e| LotlError::Storage(e.to_string()))?
            .ok_or_else(|| LotlError::KeyNotFound("No signed pre-key available".to_string()))?;
        let signed_pre_key_record = storage
            .signed_pre_key_store()
            .get_signed_pre_key(SignedPreKeyId::from(signed_pre_key_id))
            .await?;

        let kyber_pre_key_id = storage
            .kyber_pre_key_store()
            .get_max_kyber_pre_key_id()
            .await
            .map_err(|e| LotlError::Storage(e.to_string()))?
            .ok_or_else(|| LotlError::KeyNotFound("No kyber pre-key available".to_string()))?;
        let kyber_pre_key_record = storage
            .kyber_pre_key_store()
            .get_kyber_pre_key(KyberPreKeyId::from(kyber_pre_key_id))
            .await?;

        let bundle = SerializableBundle {
            version: env!("CARGO_PKG_VERSION").to_string(),
            registration_id,
            device_id: 1,
            pre_key_id,
            pre_key_public: pre_key_record.public_key()?.serialize().to_vec(),
            signed_pre_key_id,
            signed_pre_key_public: signed_pre_key_record.public_key()?.serialize().to_vec(),
            signed_pre_key_signature: signed_pre_key_record.signature()?.to_vec(),
            identity_key: identity_key_pair.identity_key().serialize().to_vec(),
            kyber_pre_key_id,
            kyber_pre_key_public: kyber_pre_key_record.public_key()?.serialize().to_vec(),
            kyber_pre_key_signature: kyber_pre_key_record.signature()?.to_vec(),
        };

        Ok(bincode::serialize(&bundle)?)
    }

    /// Processes a peer's prekey bundle to establish a session
    ///
    /// This parses the serialized bundle and establishes a Signal Protocol
    /// session with the peer. After this completes successfully, messages
    /// can be encrypted to this peer using their peer_id.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - Unique identifier for the peer (typically their fingerprint)
    /// * `bundle` - Serialized prekey bundle from the peer
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Bundle deserialization fails
    /// - Session establishment fails
    /// - Identity key verification fails
    pub async fn process_prekey_bundle(&mut self, peer_id: String, bundle: &[u8]) -> Result<()> {
        self.ensure_storage_initialized().await?;

        let serialized_bundle: SerializableBundle = bincode::deserialize(bundle)?;

        let storage = self
            .storage
            .as_mut()
            .ok_or_else(|| LotlError::Storage("Storage not initialized".to_string()))?;

        let identity_key =
            libsignal_protocol::IdentityKey::decode(&serialized_bundle.identity_key)?;
        let pre_key_public = libsignal_protocol::PublicKey::deserialize(
            &serialized_bundle.pre_key_public,
        )
        .map_err(|e| LotlError::Crypto(format!("Failed to deserialize pre-key public: {}", e)))?;
        let signed_pre_key_public =
            libsignal_protocol::PublicKey::deserialize(&serialized_bundle.signed_pre_key_public)
                .map_err(|e| {
                    LotlError::Crypto(format!("Failed to deserialize signed pre-key public: {}", e))
                })?;
        let kyber_pre_key_public = libsignal_protocol::kem::PublicKey::deserialize(
            &serialized_bundle.kyber_pre_key_public,
        )
        .map_err(|e| {
            LotlError::Crypto(format!("Failed to deserialize kyber pre-key public: {}", e))
        })?;

        let bundle = PreKeyBundle::new(
            serialized_bundle.registration_id,
            DeviceId::new(serialized_bundle.device_id)
                .map_err(|e| LotlError::Storage(format!("Invalid device ID: {}", e)))?,
            Some((PreKeyId::from(serialized_bundle.pre_key_id), pre_key_public)),
            SignedPreKeyId::from(serialized_bundle.signed_pre_key_id),
            signed_pre_key_public,
            serialized_bundle.signed_pre_key_signature.clone(),
            KyberPreKeyId::from(serialized_bundle.kyber_pre_key_id),
            kyber_pre_key_public,
            serialized_bundle.kyber_pre_key_signature.clone(),
            identity_key,
        )?;

        let address = ProtocolAddress::new(
            peer_id,
            DeviceId::new(serialized_bundle.device_id)
                .map_err(|e| LotlError::Storage(format!("Invalid device ID: {}", e)))?,
        );
        storage
            .establish_session_from_bundle(&address, &bundle)
            .await
            .map_err(|e| LotlError::Storage(e.to_string()))?;

        Ok(())
    }

    /// Encrypts a message for a peer
    ///
    /// # Arguments
    ///
    /// * `peer_id` - Unique identifier for the peer
    /// * `plaintext` - The message to encrypt
    ///
    /// # Returns
    ///
    /// The encrypted ciphertext as bytes
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No session exists with this peer
    /// - Encryption fails
    pub async fn encrypt(&mut self, peer_id: String, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.ensure_storage_initialized().await?;

        let storage = self
            .storage
            .as_mut()
            .ok_or_else(|| LotlError::Storage("Storage not initialized".to_string()))?;

        let address = ProtocolAddress::new(
            peer_id,
            DeviceId::new(1)
                .map_err(|e| LotlError::Storage(format!("Invalid device ID: {}", e)))?,
        );
        let ciphertext = storage.encrypt_message(&address, plaintext).await?;

        Ok(ciphertext.serialize().to_vec())
    }

    /// Decrypts a message from a peer
    ///
    /// # Arguments
    ///
    /// * `peer_id` - Unique identifier for the peer
    /// * `ciphertext` - The encrypted message
    ///
    /// # Returns
    ///
    /// The decrypted plaintext as bytes
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Decryption fails
    /// - Message authentication fails
    pub async fn decrypt(&mut self, peer_id: String, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.ensure_storage_initialized().await?;

        let storage = self
            .storage
            .as_mut()
            .ok_or_else(|| LotlError::Storage("Storage not initialized".to_string()))?;

        let address = ProtocolAddress::new(
            peer_id.clone(),
            DeviceId::new(1)
                .map_err(|e| LotlError::Storage(format!("Invalid device ID: {}", e)))?,
        );

        let ciphertext_message = match libsignal_protocol::PreKeySignalMessage::try_from(ciphertext)
        {
            Ok(prekey_msg) => {
                libsignal_protocol::CiphertextMessage::PreKeySignalMessage(prekey_msg)
            }
            Err(_) => libsignal_protocol::CiphertextMessage::SignalMessage(
                libsignal_protocol::SignalMessage::try_from(ciphertext)?,
            ),
        };

        let plaintext = storage.decrypt_message(&address, &ciphertext_message).await?;

        Ok(plaintext)
    }

    /// Checks if a session exists with a peer
    ///
    /// # Arguments
    ///
    /// * `peer_id` - Unique identifier for the peer
    ///
    /// # Returns
    ///
    /// `true` if a session exists, `false` otherwise
    pub fn has_session(&self, peer_id: String) -> bool {
        let conn = match &self.storage {
            Some(storage) => storage.connection(),
            None => return false,
        };
        let conn_guard = match conn.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };

        let mut stmt = match conn_guard
            .prepare("SELECT COUNT(*) FROM sessions WHERE address = ?1 AND device_id = 1")
        {
            Ok(s) => s,
            Err(_) => return false,
        };

        let count: i64 = match stmt.query_row([&peer_id], |row| row.get(0)) {
            Ok(c) => c,
            Err(_) => return false,
        };

        count > 0
    }

    /// Deletes a session with a peer
    ///
    /// # Arguments
    ///
    /// * `peer_id` - Unique identifier for the peer
    ///
    /// # Errors
    ///
    /// Returns an error if session deletion fails
    pub async fn delete_session(&mut self, peer_id: String) -> Result<()> {
        self.ensure_storage_initialized().await?;

        let storage = self
            .storage
            .as_mut()
            .ok_or_else(|| LotlError::Storage("Storage not initialized".to_string()))?;

        let address = ProtocolAddress::new(
            peer_id,
            DeviceId::new(1)
                .map_err(|e| LotlError::Storage(format!("Invalid device ID: {}", e)))?,
        );
        storage
            .session_store()
            .delete_session(&address)
            .await
            .map_err(|e| LotlError::Storage(e.to_string()))?;

        Ok(())
    }

    /// Performs key rotation and maintenance tasks
    ///
    /// This function:
    /// - Rotates signed pre-key if needed (every 7 days)
    /// - Rotates kyber pre-key if needed (every 7 days)
    /// - Replenishes one-time pre-keys if below threshold
    /// - Cleans up expired keys
    ///
    /// # Returns
    ///
    /// A `MaintenanceResult` containing counts of operations performed
    ///
    /// # Errors
    ///
    /// Returns an error if any maintenance operation fails
    pub async fn perform_key_maintenance(&mut self) -> Result<MaintenanceResult> {
        self.ensure_storage_initialized().await?;

        let storage = self
            .storage
            .as_mut()
            .ok_or_else(|| LotlError::Storage("Storage not initialized".to_string()))?;

        let identity_key_pair = storage.identity_store().get_identity_key_pair().await?;

        let signed_pre_key_rotated = if signed_pre_key_needs_rotation(storage)
            .await
            .map_err(|e| LotlError::Storage(e.to_string()))?
        {
            rotate_signed_pre_key(storage, &identity_key_pair)
                .await
                .map_err(|e| LotlError::Storage(e.to_string()))?;
            true
        } else {
            false
        };

        let kyber_pre_key_rotated = if kyber_pre_key_needs_rotation(storage)
            .await
            .map_err(|e| LotlError::Storage(e.to_string()))?
        {
            rotate_kyber_pre_key(storage, &identity_key_pair)
                .await
                .map_err(|e| LotlError::Storage(e.to_string()))?;
            true
        } else {
            false
        };

        let pre_key_count_before = storage.pre_key_store().pre_key_count().await;
        if pre_key_count_before < key_rotation::MIN_PRE_KEY_COUNT {
            replenish_pre_keys(storage).await.map_err(|e| LotlError::Storage(e.to_string()))?;
        }
        let pre_key_count_after = storage.pre_key_store().pre_key_count().await;
        let pre_keys_generated = (pre_key_count_after.saturating_sub(pre_key_count_before)) as u32;

        cleanup_expired_signed_pre_keys(storage)
            .await
            .map_err(|e| LotlError::Storage(e.to_string()))?;
        cleanup_expired_kyber_pre_keys(storage)
            .await
            .map_err(|e| LotlError::Storage(e.to_string()))?;

        Ok(MaintenanceResult { pre_keys_generated, signed_pre_key_rotated, kyber_pre_key_rotated })
    }

    /// Adds a contact to the database
    ///
    /// # Arguments
    ///
    /// * `identity_key` - The peer's identity key bytes
    /// * `alias` - Optional user-friendly name for the contact
    ///
    /// # Returns
    ///
    /// The fingerprint of the added contact
    ///
    /// # Errors
    ///
    /// Returns an error if database insertion fails
    pub fn add_contact(&self, identity_key: &[u8], alias: Option<String>) -> Result<String> {
        let conn = self.db_connection.connection();
        let conn = conn.lock().unwrap();

        contact_manager::add_contact(
            &conn,
            identity_key,
            alias.as_deref(),
            &self.config.fingerprint_salt,
            &self.config.fingerprint_prefix,
        )
    }

    /// Looks up a contact by fingerprint
    ///
    /// # Arguments
    ///
    /// * `fingerprint` - The contact's fingerprint
    ///
    /// # Returns
    ///
    /// `Some(ContactInfo)` if found, `None` if not found
    pub fn lookup_contact(&self, fingerprint: &str) -> Result<Option<ContactInfo>> {
        let conn = self.db_connection.connection();
        let conn = conn.lock().unwrap();

        contact_manager::lookup_contact(&conn, fingerprint)
    }

    /// Lists all contacts
    ///
    /// # Returns
    ///
    /// A vector of all contacts, ordered by most recently updated
    pub fn list_contacts(&self) -> Result<Vec<ContactInfo>> {
        let conn = self.db_connection.connection();
        let conn = conn.lock().unwrap();

        contact_manager::list_contacts(&conn)
    }

    /// Returns the shared database connection for app-specific queries
    pub fn connection(&self) -> std::sync::Arc<std::sync::Mutex<rusqlite::Connection>> {
        self.db_connection.connection()
    }

    /// Returns a mutable reference to the storage backend
    pub fn storage_mut(&mut self) -> Option<&mut SqliteStorage> {
        self.storage.as_mut()
    }

    /// Returns the configuration
    pub fn config(&self) -> &LotlConfig {
        &self.config
    }

    /// Generates a serialized prekey bundle with key ID metadata
    ///
    /// Returns the bundle bytes alongside the individual key IDs,
    /// useful for tracking which keys were published.
    ///
    /// # Returns
    /// A tuple of (bundle_bytes, pre_key_id, signed_pre_key_id, kyber_pre_key_id)
    pub async fn generate_prekey_bundle_with_metadata(
        &mut self,
    ) -> Result<(Vec<u8>, u32, u32, u32)> {
        self.ensure_storage_initialized().await?;

        let storage = self
            .storage
            .as_mut()
            .ok_or_else(|| LotlError::Storage("Storage not initialized".to_string()))?;

        let identity_key_pair = storage.identity_store().get_identity_key_pair().await?;
        let registration_id = storage.identity_store().get_local_registration_id().await?;

        let pre_key_id = storage
            .pre_key_store()
            .get_max_pre_key_id()
            .await
            .map_err(|e| LotlError::Storage(e.to_string()))?
            .ok_or_else(|| LotlError::KeyNotFound("No pre-keys available".to_string()))?;
        let pre_key_record =
            storage.pre_key_store().get_pre_key(PreKeyId::from(pre_key_id)).await?;

        let signed_pre_key_id = storage
            .signed_pre_key_store()
            .get_max_signed_pre_key_id()
            .await
            .map_err(|e| LotlError::Storage(e.to_string()))?
            .ok_or_else(|| LotlError::KeyNotFound("No signed pre-key available".to_string()))?;
        let signed_pre_key_record = storage
            .signed_pre_key_store()
            .get_signed_pre_key(SignedPreKeyId::from(signed_pre_key_id))
            .await?;

        let kyber_pre_key_id = storage
            .kyber_pre_key_store()
            .get_max_kyber_pre_key_id()
            .await
            .map_err(|e| LotlError::Storage(e.to_string()))?
            .ok_or_else(|| LotlError::KeyNotFound("No kyber pre-key available".to_string()))?;
        let kyber_pre_key_record = storage
            .kyber_pre_key_store()
            .get_kyber_pre_key(KyberPreKeyId::from(kyber_pre_key_id))
            .await?;

        let bundle = SerializableBundle {
            version: env!("CARGO_PKG_VERSION").to_string(),
            registration_id,
            device_id: 1,
            pre_key_id,
            pre_key_public: pre_key_record.public_key()?.serialize().to_vec(),
            signed_pre_key_id,
            signed_pre_key_public: signed_pre_key_record.public_key()?.serialize().to_vec(),
            signed_pre_key_signature: signed_pre_key_record.signature()?.to_vec(),
            identity_key: identity_key_pair.identity_key().serialize().to_vec(),
            kyber_pre_key_id,
            kyber_pre_key_public: kyber_pre_key_record.public_key()?.serialize().to_vec(),
            kyber_pre_key_signature: kyber_pre_key_record.signature()?.to_vec(),
        };

        let bytes = bincode::serialize(&bundle)?;
        Ok((bytes, pre_key_id, signed_pre_key_id, kyber_pre_key_id))
    }

    /// Returns the identity key bytes from a serialized bundle
    pub fn identity_key_from_bundle(bundle_bytes: &[u8]) -> Result<Vec<u8>> {
        let bundle: SerializableBundle = bincode::deserialize(bundle_bytes)?;
        Ok(bundle.identity_key)
    }

    /// Extracts the version string from a serialized bundle without full processing
    ///
    /// The version corresponds to the lotl library version (from Cargo.toml) that
    /// created the bundle. This allows applications to check bundle version
    /// compatibility before calling `process_prekey_bundle()`.
    ///
    /// Applications should validate that the version is supported according to
    /// their own compatibility policy (e.g., semver major version matching).
    ///
    /// # Arguments
    ///
    /// * `bundle_bytes` - Serialized prekey bundle
    ///
    /// # Returns
    ///
    /// The lotl version string embedded in the bundle (e.g., "0.1.0")
    ///
    /// # Errors
    ///
    /// Returns an error if the bundle cannot be deserialized
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use lotl::Lotl;
    /// # fn example(bundle: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    /// let version = Lotl::bundle_version(bundle)?;
    /// // Check if major version matches (semver compatibility)
    /// if !version.starts_with("0.1.") {
    ///     return Err("Incompatible bundle version".into());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn bundle_version(bundle_bytes: &[u8]) -> Result<String> {
        let bundle: SerializableBundle = bincode::deserialize(bundle_bytes)?;
        Ok(bundle.version)
    }
}

#[cfg(feature = "nostr")]
impl Lotl {
    /// Derives a Nostr keypair from the local Signal identity
    ///
    /// This uses HKDF to deterministically derive Nostr keys from
    /// the Signal Protocol identity key.
    ///
    /// # Arguments
    ///
    /// * `config` - Nostr-specific configuration for key derivation
    ///
    /// # Returns
    ///
    /// A `NostrKeys` struct containing the derived keypair
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation fails
    pub fn derive_nostr_keypair(&self, config: &NostrConfig) -> Result<NostrKeys> {
        let identity_key = self.get_identity_key()?;
        integrations::nostr::derive_nostr_keypair(&identity_key, config)
    }

    /// Gets the Nostr public key for a peer by fingerprint
    ///
    /// # Arguments
    ///
    /// * `fingerprint` - The peer's Signal Protocol fingerprint
    ///
    /// # Returns
    ///
    /// The Nostr public key if stored, `None` otherwise
    pub fn get_peer_nostr_pubkey(&self, fingerprint: &str) -> Result<Option<String>> {
        let conn = self.db_connection.connection();
        let conn = conn.lock().unwrap();

        integrations::nostr::init_nostr_tables(&conn)?;
        integrations::nostr::get_nostr_pubkey(&conn, fingerprint)
    }

    /// Stores a Nostr identity mapping for a peer
    ///
    /// # Arguments
    ///
    /// * `fingerprint` - The peer's Signal Protocol fingerprint
    /// * `nostr_pubkey` - The peer's Nostr public key (hex or npub)
    /// * `config` - Nostr configuration
    ///
    /// # Errors
    ///
    /// Returns an error if database insertion fails
    pub fn store_nostr_identity(
        &self,
        fingerprint: &str,
        nostr_pubkey: &str,
        config: &NostrConfig,
    ) -> Result<()> {
        let conn = self.db_connection.connection();
        let conn = conn.lock().unwrap();

        integrations::nostr::init_nostr_tables(&conn)?;
        integrations::nostr::store_nostr_identity(
            &conn,
            fingerprint,
            nostr_pubkey,
            &config.derivation_context,
        )?;

        Ok(())
    }
}

/// Returns the library name
pub fn name() -> &'static str {
    "lotl"
}

/// Returns the library version
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name() {
        assert_eq!(name(), "lotl");
    }

    #[test]
    fn test_version() {
        assert_eq!(version(), "0.1.0");
    }

    #[tokio::test]
    async fn test_bundle_version_extraction() {
        let config = LotlConfig { db_path: ":memory:".to_string(), ..Default::default() };

        let mut lotl = Lotl::new(config).await.unwrap();
        let bundle = lotl.generate_prekey_bundle().await.unwrap();

        let version = Lotl::bundle_version(&bundle).unwrap();
        assert_eq!(version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_bundle_version_invalid_data() {
        let invalid_data = b"not a valid bundle";
        let result = Lotl::bundle_version(invalid_data);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_bundle_interoperability() {
        let config1 = LotlConfig { db_path: ":memory:".to_string(), ..Default::default() };

        let config2 = LotlConfig { db_path: ":memory:".to_string(), ..Default::default() };

        let mut lotl1 = Lotl::new(config1).await.unwrap();
        let mut lotl2 = Lotl::new(config2).await.unwrap();

        let bundle1 = lotl1.generate_prekey_bundle().await.unwrap();
        let bundle2 = lotl2.generate_prekey_bundle().await.unwrap();

        let version1 = Lotl::bundle_version(&bundle1).unwrap();
        let version2 = Lotl::bundle_version(&bundle2).unwrap();

        assert_eq!(version1, env!("CARGO_PKG_VERSION"));
        assert_eq!(version2, env!("CARGO_PKG_VERSION"));
        assert_eq!(version1, version2, "Same lotl version should produce same bundle version");

        let identity1 = lotl1.get_identity_key().unwrap();
        let identity2 = lotl2.get_identity_key().unwrap();

        let fingerprint1 = generate_fingerprint(&identity1, "test_salt", "");
        let fingerprint2 = generate_fingerprint(&identity2, "test_salt", "");

        lotl1.process_prekey_bundle(fingerprint2.clone(), &bundle2).await.unwrap();
        lotl2.process_prekey_bundle(fingerprint1.clone(), &bundle1).await.unwrap();

        assert!(lotl1.has_session(fingerprint2));
        assert!(lotl2.has_session(fingerprint1));
    }

    #[tokio::test]
    async fn test_identity_key_from_bundle() {
        let config = LotlConfig { db_path: ":memory:".to_string(), ..Default::default() };

        let mut lotl = Lotl::new(config).await.unwrap();
        let bundle = lotl.generate_prekey_bundle().await.unwrap();

        let identity_from_bundle = Lotl::identity_key_from_bundle(&bundle).unwrap();
        let identity_direct = lotl.get_identity_key().unwrap();

        assert_eq!(identity_from_bundle, identity_direct);
    }
}

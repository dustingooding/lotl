//! Nostr protocol integration for lotl
//!
//! This module provides Nostr-specific functionality including:
//! - Identity key derivation from Signal Protocol keys
//! - Database storage for Nostr identity mappings
//! - Configuration types

#[cfg(feature = "nostr")]
pub mod identity;

#[cfg(feature = "nostr")]
pub mod storage;

#[cfg(feature = "nostr")]
pub mod types;

#[cfg(feature = "nostr")]
pub use identity::derive_nostr_keypair;

#[cfg(feature = "nostr")]
pub use storage::{
    get_fingerprint_by_nostr_pubkey, get_nostr_pubkey, init_nostr_tables, store_nostr_identity,
};

#[cfg(feature = "nostr")]
pub use types::{NostrConfig, NostrKeys};

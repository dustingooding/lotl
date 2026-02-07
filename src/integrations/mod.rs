//! Transport integrations for lotl
//!
//! This module provides optional transport integrations that can be
//! feature-gated at compile time.

#[cfg(feature = "nostr")]
pub mod nostr;

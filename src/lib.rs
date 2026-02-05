//! lotl - Signal Protocol session management
//!
//! This library provides batteries-included Signal Protocol (X3DH + Double Ratchet)
//! session management with plug-in transport integrations.

#![warn(missing_docs)]
#![deny(unsafe_code)]

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
}

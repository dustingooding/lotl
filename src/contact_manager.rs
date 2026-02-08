//! Contact management and fingerprint generation
//!
//! This module provides contact storage with configurable fingerprint generation.
//! Fingerprints are SHA-256 hashes of identity keys with a configurable salt.

use crate::error::{LotlError, Result};
use crate::types::ContactInfo;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Generate a fingerprint from an identity key, salt, and optional prefix
///
/// The fingerprint is a lowercase hexadecimal SHA-256 hash of the identity key
/// concatenated with the salt, optionally prepended with a prefix string.
///
/// # Arguments
/// * `identity_key` - The Signal identity key bytes
/// * `salt` - The salt string to use for fingerprint generation
/// * `prefix` - Optional prefix to prepend (e.g. "RDX:" or "")
///
/// # Returns
/// A string in the format `{prefix}{hex_hash}`
pub fn generate_fingerprint(identity_key: &[u8], salt: &str, prefix: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(identity_key);
    hasher.update(salt.as_bytes());
    let hash = hasher.finalize();
    format!("{}{}", prefix, hex::encode(hash))
}

/// Initialize the contacts table schema
///
/// Creates the contacts table if it doesn't exist. This should be called
/// once during database initialization.
///
/// # Arguments
/// * `conn` - SQLite database connection
pub fn init_contacts_table(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS contacts (
            fingerprint TEXT PRIMARY KEY,
            signal_identity_key BLOB NOT NULL,
            user_alias TEXT,
            first_seen INTEGER NOT NULL,
            last_updated INTEGER NOT NULL
        )",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_contacts_last_updated
         ON contacts(last_updated)",
        [],
    )?;

    Ok(())
}

/// Add a new contact to the database
///
/// If a contact with the same fingerprint already exists, this will update
/// the identity key and last_updated timestamp. The alias is only updated if
/// provided and different from the existing value.
///
/// # Arguments
/// * `conn` - SQLite database connection
/// * `identity_key` - The Signal identity key bytes
/// * `alias` - Optional user-friendly alias for the contact
/// * `salt` - The salt string to use for fingerprint generation
/// * `prefix` - Optional prefix to prepend to the fingerprint
///
/// # Returns
/// The fingerprint of the contact (new or existing)
pub fn add_contact(
    conn: &Connection,
    identity_key: &[u8],
    alias: Option<&str>,
    salt: &str,
    prefix: &str,
) -> Result<String> {
    let fingerprint = generate_fingerprint(identity_key, salt, prefix);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| LotlError::Crypto(format!("System time error: {}", e)))?
        .as_secs() as i64;

    let existing: Option<i64> = conn
        .query_row(
            "SELECT first_seen FROM contacts WHERE fingerprint = ?1",
            [&fingerprint],
            |row| row.get(0),
        )
        .ok();

    if let Some(_first_seen) = existing {
        conn.execute(
            "UPDATE contacts
             SET signal_identity_key = ?1, user_alias = ?2, last_updated = ?3
             WHERE fingerprint = ?4",
            rusqlite::params![identity_key, alias, now, &fingerprint],
        )?;
    } else {
        conn.execute(
            "INSERT INTO contacts (fingerprint, signal_identity_key, user_alias, first_seen, last_updated)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![&fingerprint, identity_key, alias, now, now],
        )?;
    }

    Ok(fingerprint)
}

/// Look up a contact by fingerprint
///
/// # Arguments
/// * `conn` - SQLite database connection
/// * `fingerprint` - The contact's fingerprint
///
/// # Returns
/// `Some(ContactInfo)` if found, `None` if not found
pub fn lookup_contact(conn: &Connection, fingerprint: &str) -> Result<Option<ContactInfo>> {
    let result = conn.query_row(
        "SELECT fingerprint, signal_identity_key, user_alias, first_seen, last_updated
         FROM contacts
         WHERE fingerprint = ?1",
        [fingerprint],
        |row| {
            Ok(ContactInfo {
                fingerprint: row.get(0)?,
                signal_identity_key: row.get(1)?,
                user_alias: row.get(2)?,
                first_seen: row.get(3)?,
                last_updated: row.get(4)?,
            })
        },
    );

    match result {
        Ok(contact) => Ok(Some(contact)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// List all contacts ordered by last update time (most recent first)
///
/// # Arguments
/// * `conn` - SQLite database connection
///
/// # Returns
/// A vector of all contacts in the database
pub fn list_contacts(conn: &Connection) -> Result<Vec<ContactInfo>> {
    let mut stmt = conn.prepare(
        "SELECT fingerprint, signal_identity_key, user_alias, first_seen, last_updated
         FROM contacts
         ORDER BY last_updated DESC",
    )?;

    let contacts = stmt
        .query_map([], |row| {
            Ok(ContactInfo {
                fingerprint: row.get(0)?,
                signal_identity_key: row.get(1)?,
                user_alias: row.get(2)?,
                first_seen: row.get(3)?,
                last_updated: row.get(4)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(contacts)
}

/// Update a contact's alias
///
/// # Arguments
/// * `conn` - SQLite database connection
/// * `fingerprint` - The contact's fingerprint
/// * `alias` - The new alias (or None to clear)
///
/// # Returns
/// An error if the contact doesn't exist
pub fn update_contact_alias(
    conn: &Connection,
    fingerprint: &str,
    alias: Option<&str>,
) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| LotlError::Crypto(format!("System time error: {}", e)))?
        .as_secs() as i64;

    let rows_affected = conn.execute(
        "UPDATE contacts SET user_alias = ?1, last_updated = ?2 WHERE fingerprint = ?3",
        rusqlite::params![alias, now, fingerprint],
    )?;

    if rows_affected == 0 {
        Err(LotlError::ContactNotFound(fingerprint.to_string()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_contacts_table(&conn).unwrap();
        conn
    }

    #[test]
    fn test_generate_fingerprint() {
        let identity_key = b"test_identity_key";
        let salt = "test_salt";

        let fp1 = generate_fingerprint(identity_key, salt, "");
        let fp2 = generate_fingerprint(identity_key, salt, "");

        assert_eq!(fp1, fp2, "Fingerprints should be deterministic");
        assert_eq!(fp1.len(), 64, "SHA-256 hex should be 64 characters");
        assert!(!fp1.contains("RDX:"), "Should not contain prefix");
    }

    #[test]
    fn test_generate_fingerprint_different_salts() {
        let identity_key = b"test_identity_key";
        let salt1 = "salt1";
        let salt2 = "salt2";

        let fp1 = generate_fingerprint(identity_key, salt1, "");
        let fp2 = generate_fingerprint(identity_key, salt2, "");

        assert_ne!(fp1, fp2, "Different salts should produce different fingerprints");
    }

    #[test]
    fn test_add_and_lookup_contact() {
        let conn = create_test_db();
        let identity_key = b"test_identity_key_1";
        let alias = Some("Alice");
        let salt = "test_salt";

        let fingerprint = add_contact(&conn, identity_key, alias, salt, "").unwrap();

        assert!(!fingerprint.is_empty());

        let contact = lookup_contact(&conn, &fingerprint).unwrap().unwrap();
        assert_eq!(contact.fingerprint, fingerprint);
        assert_eq!(contact.signal_identity_key, identity_key);
        assert_eq!(contact.user_alias, Some("Alice".to_string()));
        assert!(contact.first_seen > 0);
        assert!(contact.last_updated > 0);
    }

    #[test]
    fn test_add_contact_no_alias() {
        let conn = create_test_db();
        let identity_key = b"test_identity_key_2";
        let salt = "test_salt";

        let fingerprint = add_contact(&conn, identity_key, None, salt, "").unwrap();

        let contact = lookup_contact(&conn, &fingerprint).unwrap().unwrap();
        assert_eq!(contact.user_alias, None);
    }

    #[test]
    fn test_add_contact_idempotent() {
        let conn = create_test_db();
        let identity_key = b"test_identity_key_3";
        let salt = "test_salt";

        let fp1 = add_contact(&conn, identity_key, Some("Alice"), salt, "").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let fp2 = add_contact(&conn, identity_key, Some("Alice Updated"), salt, "").unwrap();

        assert_eq!(fp1, fp2, "Same identity key should produce same fingerprint");

        let contact = lookup_contact(&conn, &fp1).unwrap().unwrap();
        assert_eq!(contact.user_alias, Some("Alice Updated".to_string()));
    }

    #[test]
    fn test_lookup_nonexistent_contact() {
        let conn = create_test_db();
        let result = lookup_contact(&conn, "nonexistent_fingerprint").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_list_contacts() {
        let conn = create_test_db();
        let salt = "test_salt";

        add_contact(&conn, b"key1", Some("Alice"), salt, "").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        add_contact(&conn, b"key2", Some("Bob"), salt, "").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        add_contact(&conn, b"key3", Some("Charlie"), salt, "").unwrap();

        let contacts = list_contacts(&conn).unwrap();
        assert_eq!(contacts.len(), 3);

        assert_eq!(contacts[0].user_alias, Some("Charlie".to_string()));
        assert_eq!(contacts[1].user_alias, Some("Bob".to_string()));
        assert_eq!(contacts[2].user_alias, Some("Alice".to_string()));
    }

    #[test]
    fn test_list_contacts_empty() {
        let conn = create_test_db();
        let contacts = list_contacts(&conn).unwrap();
        assert_eq!(contacts.len(), 0);
    }

    #[test]
    fn test_update_contact_alias() {
        let conn = create_test_db();
        let identity_key = b"test_identity_key_4";
        let salt = "test_salt";

        let fingerprint = add_contact(&conn, identity_key, Some("Alice"), salt, "").unwrap();

        let contact_before = lookup_contact(&conn, &fingerprint).unwrap().unwrap();
        let last_updated_before = contact_before.last_updated;

        std::thread::sleep(std::time::Duration::from_secs(1));

        update_contact_alias(&conn, &fingerprint, Some("Alice Smith")).unwrap();

        let contact_after = lookup_contact(&conn, &fingerprint).unwrap().unwrap();
        assert_eq!(contact_after.user_alias, Some("Alice Smith".to_string()));
        assert!(contact_after.last_updated > last_updated_before);
        assert_eq!(contact_after.first_seen, contact_before.first_seen);
    }

    #[test]
    fn test_update_contact_alias_to_none() {
        let conn = create_test_db();
        let identity_key = b"test_identity_key_5";
        let salt = "test_salt";

        let fingerprint = add_contact(&conn, identity_key, Some("Alice"), salt, "").unwrap();

        update_contact_alias(&conn, &fingerprint, None).unwrap();

        let contact = lookup_contact(&conn, &fingerprint).unwrap().unwrap();
        assert_eq!(contact.user_alias, None);
    }

    #[test]
    fn test_update_nonexistent_contact() {
        let conn = create_test_db();
        let result = update_contact_alias(&conn, "nonexistent", Some("Alias"));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), LotlError::ContactNotFound(_)));
    }

    #[test]
    fn test_init_contacts_table_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        init_contacts_table(&conn).unwrap();
        init_contacts_table(&conn).unwrap();
    }
}

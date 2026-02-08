//! Nostr identity storage
//!
//! This module provides database storage for Nostr identity mappings,
//! linking Signal Protocol fingerprints to Nostr public keys.

#[cfg(feature = "nostr")]
use crate::error::Result;
#[cfg(feature = "nostr")]
use rusqlite::Connection;

/// Initializes Nostr-specific database tables
///
/// Creates the nostr_identities table with a foreign key relationship
/// to the contacts table. This ensures Nostr identities are automatically
/// cleaned up when contacts are deleted.
///
/// # Arguments
/// * `conn` - SQLite database connection
///
/// # Returns
/// Ok(()) on success
#[cfg(feature = "nostr")]
pub fn init_nostr_tables(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS nostr_identities (
            fingerprint TEXT PRIMARY KEY,
            nostr_pubkey TEXT UNIQUE NOT NULL,
            derivation_context TEXT NOT NULL,
            FOREIGN KEY (fingerprint) REFERENCES contacts(fingerprint) ON DELETE CASCADE
        )",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_nostr_identities_pubkey
         ON nostr_identities(nostr_pubkey)",
        [],
    )?;

    Ok(())
}

/// Stores a Nostr identity mapping
///
/// Associates a Signal Protocol fingerprint with its derived Nostr public key
/// and the derivation context used. Uses INSERT OR REPLACE on the primary key
/// (fingerprint), but enforces the UNIQUE constraint on nostr_pubkey, so attempting
/// to store a different fingerprint with the same nostr_pubkey will fail.
///
/// # Arguments
/// * `conn` - SQLite database connection
/// * `fingerprint` - Signal Protocol identity fingerprint
/// * `nostr_pubkey` - Derived Nostr public key (hex encoded)
/// * `derivation_context` - HKDF context used for derivation
///
/// # Returns
/// Ok(()) on success, Error if the nostr_pubkey is already associated with a different fingerprint
#[cfg(feature = "nostr")]
pub fn store_nostr_identity(
    conn: &Connection,
    fingerprint: &str,
    nostr_pubkey: &str,
    derivation_context: &str,
) -> Result<()> {
    if let Some(existing_fingerprint) = get_fingerprint_by_nostr_pubkey(conn, nostr_pubkey)? {
        if existing_fingerprint != fingerprint {
            return Err(crate::error::LotlError::Storage(format!(
                "Nostr pubkey {} is already associated with fingerprint {}",
                nostr_pubkey, existing_fingerprint
            )));
        }
    }

    conn.execute(
        "INSERT OR REPLACE INTO nostr_identities (fingerprint, nostr_pubkey, derivation_context)
         VALUES (?1, ?2, ?3)",
        [fingerprint, nostr_pubkey, derivation_context],
    )?;
    Ok(())
}

/// Retrieves the Nostr public key for a given fingerprint
///
/// # Arguments
/// * `conn` - SQLite database connection
/// * `fingerprint` - Signal Protocol identity fingerprint
///
/// # Returns
/// Some(nostr_pubkey) if found, None otherwise
#[cfg(feature = "nostr")]
pub fn get_nostr_pubkey(conn: &Connection, fingerprint: &str) -> Result<Option<String>> {
    let mut stmt =
        conn.prepare("SELECT nostr_pubkey FROM nostr_identities WHERE fingerprint = ?1")?;

    let result = stmt.query_row([fingerprint], |row| row.get(0));

    match result {
        Ok(pubkey) => Ok(Some(pubkey)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Retrieves the fingerprint for a given Nostr public key
///
/// Performs reverse lookup from Nostr public key to Signal Protocol fingerprint.
///
/// # Arguments
/// * `conn` - SQLite database connection
/// * `nostr_pubkey` - Nostr public key (hex encoded)
///
/// # Returns
/// Some(fingerprint) if found, None otherwise
#[cfg(feature = "nostr")]
pub fn get_fingerprint_by_nostr_pubkey(
    conn: &Connection,
    nostr_pubkey: &str,
) -> Result<Option<String>> {
    let mut stmt =
        conn.prepare("SELECT fingerprint FROM nostr_identities WHERE nostr_pubkey = ?1")?;

    let result = stmt.query_row([nostr_pubkey], |row| row.get(0));

    match result {
        Ok(fingerprint) => Ok(Some(fingerprint)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

#[cfg(all(test, feature = "nostr"))]
mod tests {
    use super::*;

    fn setup_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();

        conn.execute(
            "CREATE TABLE contacts (
                fingerprint TEXT PRIMARY KEY,
                signal_identity_key BLOB NOT NULL,
                user_alias TEXT,
                first_seen INTEGER NOT NULL,
                last_updated INTEGER NOT NULL
            )",
            [],
        )
        .unwrap();

        init_nostr_tables(&conn).unwrap();
        conn
    }

    fn insert_test_contact(conn: &Connection, fingerprint: &str) {
        let identity_key = vec![0x42u8; 32];
        let now = 1234567890i64;

        conn.execute(
            "INSERT INTO contacts (fingerprint, signal_identity_key, first_seen, last_updated)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![fingerprint, identity_key, now, now],
        )
        .unwrap();
    }

    #[test]
    fn test_init_nostr_tables() {
        let conn = Connection::open_in_memory().unwrap();

        conn.execute(
            "CREATE TABLE contacts (
                fingerprint TEXT PRIMARY KEY,
                signal_identity_key BLOB NOT NULL,
                user_alias TEXT,
                first_seen INTEGER NOT NULL,
                last_updated INTEGER NOT NULL
            )",
            [],
        )
        .unwrap();

        let result = init_nostr_tables(&conn);
        assert!(result.is_ok());

        let table_exists: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='nostr_identities'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(table_exists);
    }

    #[test]
    fn test_store_and_get_nostr_identity() {
        let conn = setup_test_db();
        let fingerprint = "test_fingerprint";
        let nostr_pubkey = "npub1test123";
        let context = "test_context";

        insert_test_contact(&conn, fingerprint);

        let store_result = store_nostr_identity(&conn, fingerprint, nostr_pubkey, context);
        assert!(store_result.is_ok());

        let retrieved_pubkey = get_nostr_pubkey(&conn, fingerprint).unwrap();
        assert_eq!(retrieved_pubkey, Some(nostr_pubkey.to_string()));
    }

    #[test]
    fn test_get_nostr_pubkey_not_found() {
        let conn = setup_test_db();
        let result = get_nostr_pubkey(&conn, "nonexistent").unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_get_fingerprint_by_nostr_pubkey() {
        let conn = setup_test_db();
        let fingerprint = "test_fingerprint";
        let nostr_pubkey = "npub1test123";
        let context = "test_context";

        insert_test_contact(&conn, fingerprint);
        store_nostr_identity(&conn, fingerprint, nostr_pubkey, context).unwrap();

        let retrieved_fingerprint = get_fingerprint_by_nostr_pubkey(&conn, nostr_pubkey).unwrap();
        assert_eq!(retrieved_fingerprint, Some(fingerprint.to_string()));
    }

    #[test]
    fn test_get_fingerprint_by_nostr_pubkey_not_found() {
        let conn = setup_test_db();
        let result = get_fingerprint_by_nostr_pubkey(&conn, "nonexistent").unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_store_nostr_identity_replace() {
        let conn = setup_test_db();
        let fingerprint = "test_fingerprint";
        let nostr_pubkey1 = "npub1test123";
        let nostr_pubkey2 = "npub1test456";
        let context = "test_context";

        insert_test_contact(&conn, fingerprint);

        store_nostr_identity(&conn, fingerprint, nostr_pubkey1, context).unwrap();
        let retrieved1 = get_nostr_pubkey(&conn, fingerprint).unwrap();
        assert_eq!(retrieved1, Some(nostr_pubkey1.to_string()));

        store_nostr_identity(&conn, fingerprint, nostr_pubkey2, context).unwrap();
        let retrieved2 = get_nostr_pubkey(&conn, fingerprint).unwrap();
        assert_eq!(retrieved2, Some(nostr_pubkey2.to_string()));
    }

    #[test]
    fn test_cascade_delete() {
        let conn = setup_test_db();
        let fingerprint = "test_fingerprint";
        let nostr_pubkey = "npub1test123";
        let context = "test_context";

        insert_test_contact(&conn, fingerprint);
        store_nostr_identity(&conn, fingerprint, nostr_pubkey, context).unwrap();

        let retrieved = get_nostr_pubkey(&conn, fingerprint).unwrap();
        assert!(retrieved.is_some());

        conn.execute("DELETE FROM contacts WHERE fingerprint = ?1", [fingerprint]).unwrap();

        let after_delete = get_nostr_pubkey(&conn, fingerprint).unwrap();
        assert_eq!(after_delete, None);
    }

    #[test]
    fn test_unique_nostr_pubkey_constraint() {
        let conn = setup_test_db();
        let fingerprint1 = "fingerprint1";
        let fingerprint2 = "fingerprint2";
        let nostr_pubkey = "npub1test123";
        let context = "test_context";

        insert_test_contact(&conn, fingerprint1);
        insert_test_contact(&conn, fingerprint2);

        store_nostr_identity(&conn, fingerprint1, nostr_pubkey, context).unwrap();

        let result = store_nostr_identity(&conn, fingerprint2, nostr_pubkey, context);
        assert!(result.is_err());
    }
}

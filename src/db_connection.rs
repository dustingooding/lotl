//! Database connection management with SQLCipher encryption
//!
//! This module provides database connection creation and schema versioning
//! for SQLite with SQLCipher encryption. The connection uses WAL (Write-Ahead
//! Logging) mode for better performance and concurrency characteristics.

use crate::db_encryption;
use crate::error::{LotlError, Result};
use rusqlite::Connection;
use std::sync::{Arc, Mutex};

/// Database connection with encryption support
pub struct DbConnection {
    connection: Arc<Mutex<Connection>>,
}

impl DbConnection {
    /// Creates a new database connection with SQLCipher encryption
    ///
    /// For in-memory databases (":memory:"), encryption is not applied.
    /// For file-based databases, a key is automatically generated or retrieved.
    pub fn new(db_path: &str) -> Result<Self> {
        let connection = Connection::open(db_path).map_err(LotlError::Database)?;

        if db_path != ":memory:" {
            let key = db_encryption::get_or_create_db_key(db_path)
                .map_err(|e| LotlError::Storage(e.to_string()))?;
            connection.pragma_update(None, "key", hex::encode(key)).map_err(LotlError::Database)?;
        }

        // Enable WAL mode for better concurrency and performance
        connection.pragma_update(None, "journal_mode", "WAL").map_err(LotlError::Database)?;

        Ok(Self { connection: Arc::new(Mutex::new(connection)) })
    }

    /// Returns a clone of the connection Arc
    pub fn connection(&self) -> Arc<Mutex<Connection>> {
        self.connection.clone()
    }

    /// Initializes schema_info table and returns current schema version
    pub fn initialize_schema_info(&self) -> Result<i32> {
        let conn = self.connection.lock().unwrap();

        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_info (
                version INTEGER NOT NULL DEFAULT 1,
                updated_at INTEGER DEFAULT (strftime('%s', 'now'))
            )",
            [],
        )
        .map_err(LotlError::Database)?;

        conn.execute("INSERT OR IGNORE INTO schema_info (version) VALUES (1)", [])
            .map_err(LotlError::Database)?;

        let current_version: i32 = conn
            .query_row("SELECT version FROM schema_info", [], |row| row.get(0))
            .map_err(LotlError::Database)?;

        Ok(current_version)
    }

    /// Gets the current schema version
    pub fn get_schema_version(&self) -> Result<i32> {
        let conn = self.connection.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT version FROM schema_info").map_err(LotlError::Database)?;
        let version: i32 = stmt.query_row([], |row| row.get(0)).map_err(LotlError::Database)?;
        Ok(version)
    }

    /// Updates the schema version
    pub fn update_schema_version(&self, version: i32) -> Result<()> {
        let conn = self.connection.lock().unwrap();
        conn.execute(
            "UPDATE schema_info SET version = ?1, updated_at = strftime('%s', 'now')",
            [version],
        )
        .map_err(LotlError::Database)?;
        Ok(())
    }

    /// Optimizes the database
    pub fn optimize(&self) -> Result<()> {
        let conn = self.connection.lock().unwrap();
        conn.execute("PRAGMA optimize", []).map_err(LotlError::Database)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_connection_creation_in_memory() -> Result<()> {
        let db = DbConnection::new(":memory:")?;
        let version = db.initialize_schema_info()?;
        assert_eq!(version, 1);
        Ok(())
    }

    #[test]
    fn test_schema_version_operations() -> Result<()> {
        let db = DbConnection::new(":memory:")?;
        db.initialize_schema_info()?;

        let version = db.get_schema_version()?;
        assert_eq!(version, 1);

        db.update_schema_version(2)?;
        let updated_version = db.get_schema_version()?;
        assert_eq!(updated_version, 2);

        Ok(())
    }

    #[test]
    fn test_connection_sharing() -> Result<()> {
        let db = DbConnection::new(":memory:")?;
        db.initialize_schema_info()?;

        let conn1 = db.connection();
        let conn2 = db.connection();

        {
            let c1 = conn1.lock().unwrap();
            c1.execute("CREATE TABLE test (id INTEGER PRIMARY KEY)", [])
                .map_err(LotlError::Database)?;
        }

        {
            let c2 = conn2.lock().unwrap();
            let count: i32 = c2
                .query_row("SELECT COUNT(*) FROM sqlite_master WHERE name='test'", [], |row| {
                    row.get(0)
                })
                .map_err(LotlError::Database)?;
            assert_eq!(count, 1);
        }

        Ok(())
    }

    #[test]
    fn test_optimize_does_not_fail() -> Result<()> {
        let db = DbConnection::new(":memory:")?;
        db.optimize()?;
        Ok(())
    }
}

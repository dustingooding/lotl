//! Message history storage and retrieval
//!
//! This module provides persistent storage for message history using SQLite database.
//! Messages are stored as plaintext (already decrypted by Signal Protocol) with
//! optional database encryption via SQLCipher.

use crate::error::{LotlError, Result};
use crate::types::{ConversationRecord, MessageDirection};
use rusqlite::Connection;

/// Message type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// Regular text message
    Text = 0,
    /// Bundle announcement message
    BundleAnnouncement = 1,
    /// System message
    System = 2,
}

impl From<i64> for MessageType {
    fn from(value: i64) -> Self {
        match value {
            0 => MessageType::Text,
            1 => MessageType::BundleAnnouncement,
            2 => MessageType::System,
            _ => MessageType::Text,
        }
    }
}

/// Delivery status for outgoing messages
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeliveryStatus {
    /// Message pending send
    Pending = 0,
    /// Message sent to transport
    Sent = 1,
    /// Message delivered to recipient
    Delivered = 2,
    /// Message failed to send
    Failed = 3,
}

impl From<i64> for DeliveryStatus {
    fn from(value: i64) -> Self {
        match value {
            0 => DeliveryStatus::Pending,
            1 => DeliveryStatus::Sent,
            2 => DeliveryStatus::Delivered,
            3 => DeliveryStatus::Failed,
            _ => DeliveryStatus::Pending,
        }
    }
}

/// Extended message record with additional metadata
#[derive(Debug, Clone)]
pub struct StoredMessage {
    /// Message ID
    pub id: i64,
    /// Conversation ID
    pub conversation_id: i64,
    /// Contact fingerprint
    pub fingerprint: String,
    /// Message direction
    pub direction: MessageDirection,
    /// Timestamp in seconds since UNIX epoch
    pub timestamp: i64,
    /// Message type
    pub message_type: MessageType,
    /// Message content (plaintext)
    pub plaintext: Vec<u8>,
    /// Delivery status (for outgoing messages)
    pub delivery_status: DeliveryStatus,
    /// Whether this was a prekey message
    pub was_prekey_message: bool,
    /// Whether this message established a new session
    pub session_established: bool,
}

/// Extended conversation record with unread count and archived status
#[derive(Debug, Clone)]
pub struct ExtendedConversationRecord {
    /// Conversation ID
    pub id: i64,
    /// Contact fingerprint
    pub fingerprint: String,
    /// Timestamp of last message in seconds since UNIX epoch
    pub last_message_timestamp: i64,
    /// Number of unread messages
    pub unread_count: u32,
    /// Whether conversation is archived
    pub archived: bool,
}

/// Initialize message history tables
///
/// Creates conversations and messages tables if they don't exist.
/// This should be called once during database initialization.
///
/// # Arguments
/// * `conn` - SQLite database connection
pub fn init_message_history_tables(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL UNIQUE,
            last_message_timestamp INTEGER NOT NULL DEFAULT 0,
            unread_count INTEGER NOT NULL DEFAULT 0,
            archived INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (fingerprint) REFERENCES contacts(fingerprint) ON DELETE CASCADE
        )",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_conversations_fingerprint
         ON conversations(fingerprint)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_conversations_last_message
         ON conversations(last_message_timestamp)",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id INTEGER NOT NULL,
            direction INTEGER NOT NULL,
            timestamp INTEGER NOT NULL,
            message_type INTEGER NOT NULL DEFAULT 0,
            content BLOB NOT NULL,
            delivery_status INTEGER NOT NULL DEFAULT 0,
            was_prekey_message INTEGER NOT NULL DEFAULT 0,
            session_established INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
        )",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_conversation
         ON messages(conversation_id, timestamp)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_timestamp
         ON messages(timestamp)",
        [],
    )?;

    Ok(())
}

/// Get or create a conversation for a contact
///
/// # Arguments
/// * `conn` - SQLite database connection
/// * `fingerprint` - Contact fingerprint
///
/// # Returns
/// The conversation ID
fn get_or_create_conversation(conn: &Connection, fingerprint: &str) -> Result<i64> {
    let result: std::result::Result<i64, rusqlite::Error> = conn.query_row(
        "SELECT id FROM conversations WHERE fingerprint = ?1",
        [fingerprint],
        |row| row.get(0),
    );

    match result {
        Ok(id) => Ok(id),
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            conn.execute(
                "INSERT INTO conversations (fingerprint, last_message_timestamp)
                 VALUES (?1, 0)",
                [fingerprint],
            )?;

            Ok(conn.last_insert_rowid())
        }
        Err(e) => Err(e.into()),
    }
}

/// Update conversation timestamp and optionally increment unread count
///
/// # Arguments
/// * `conn` - SQLite database connection
/// * `conversation_id` - Conversation ID
/// * `timestamp` - New timestamp
/// * `increment_unread` - Whether to increment unread count
fn update_conversation(
    conn: &Connection,
    conversation_id: i64,
    timestamp: i64,
    increment_unread: bool,
) -> Result<()> {
    if increment_unread {
        conn.execute(
            "UPDATE conversations
             SET last_message_timestamp = ?1, unread_count = unread_count + 1
             WHERE id = ?2",
            rusqlite::params![timestamp, conversation_id],
        )?;
    } else {
        conn.execute(
            "UPDATE conversations
             SET last_message_timestamp = ?1
             WHERE id = ?2",
            rusqlite::params![timestamp, conversation_id],
        )?;
    }

    Ok(())
}

/// Store an incoming message
///
/// # Arguments
/// * `conn` - SQLite database connection
/// * `fingerprint` - Contact fingerprint
/// * `timestamp` - Message timestamp in seconds since UNIX epoch
/// * `plaintext` - Decrypted message content
/// * `was_prekey_message` - Whether this was a prekey message
/// * `session_established` - Whether this message established a new session
///
/// # Returns
/// The message ID
pub fn store_incoming_message(
    conn: &Connection,
    fingerprint: &str,
    timestamp: i64,
    plaintext: &[u8],
    was_prekey_message: bool,
    session_established: bool,
) -> Result<i64> {
    let conversation_id = get_or_create_conversation(conn, fingerprint)?;

    conn.execute(
        "INSERT INTO messages
         (conversation_id, direction, timestamp, message_type, content,
          was_prekey_message, session_established)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            conversation_id,
            0,
            timestamp,
            MessageType::Text as i64,
            plaintext,
            was_prekey_message,
            session_established,
        ],
    )?;

    let message_id = conn.last_insert_rowid();

    update_conversation(conn, conversation_id, timestamp, true)?;

    Ok(message_id)
}

/// Store an outgoing message
///
/// # Arguments
/// * `conn` - SQLite database connection
/// * `fingerprint` - Contact fingerprint
/// * `timestamp` - Message timestamp in seconds since UNIX epoch
/// * `plaintext` - Message content before encryption
///
/// # Returns
/// The message ID
pub fn store_outgoing_message(
    conn: &Connection,
    fingerprint: &str,
    timestamp: i64,
    plaintext: &[u8],
) -> Result<i64> {
    let conversation_id = get_or_create_conversation(conn, fingerprint)?;

    conn.execute(
        "INSERT INTO messages
         (conversation_id, direction, timestamp, message_type, content, delivery_status)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            conversation_id,
            1,
            timestamp,
            MessageType::Text as i64,
            plaintext,
            DeliveryStatus::Pending as i64,
        ],
    )?;

    let message_id = conn.last_insert_rowid();

    update_conversation(conn, conversation_id, timestamp, false)?;

    Ok(message_id)
}

/// Update message delivery status
///
/// # Arguments
/// * `conn` - SQLite database connection
/// * `message_id` - Message ID
/// * `status` - New delivery status
pub fn update_delivery_status(
    conn: &Connection,
    message_id: i64,
    status: DeliveryStatus,
) -> Result<()> {
    conn.execute(
        "UPDATE messages SET delivery_status = ?1 WHERE id = ?2",
        rusqlite::params![status as i64, message_id],
    )?;
    Ok(())
}

/// Retrieve message by ID
///
/// # Arguments
/// * `conn` - SQLite database connection
/// * `message_id` - Message ID
///
/// # Returns
/// The stored message with all metadata
pub fn get_message(conn: &Connection, message_id: i64) -> Result<StoredMessage> {
    let result = conn.query_row(
        "SELECT m.id, m.conversation_id, c.fingerprint, m.direction, m.timestamp,
                m.message_type, m.content, m.delivery_status, m.was_prekey_message,
                m.session_established
         FROM messages m
         JOIN conversations c ON m.conversation_id = c.id
         WHERE m.id = ?1",
        [message_id],
        |row| {
            Ok(StoredMessage {
                id: row.get(0)?,
                conversation_id: row.get(1)?,
                fingerprint: row.get(2)?,
                direction: if row.get::<_, i64>(3)? == 0 {
                    MessageDirection::Received
                } else {
                    MessageDirection::Sent
                },
                timestamp: row.get(4)?,
                message_type: row.get::<_, i64>(5)?.into(),
                plaintext: row.get(6)?,
                delivery_status: row.get::<_, i64>(7)?.into(),
                was_prekey_message: row.get(8)?,
                session_established: row.get(9)?,
            })
        },
    );

    match result {
        Ok(msg) => Ok(msg),
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            Err(LotlError::Storage(format!("Message not found: {}", message_id)))
        }
        Err(e) => Err(e.into()),
    }
}

/// Get messages for a conversation (paginated, newest first)
///
/// # Arguments
/// * `conn` - SQLite database connection
/// * `fingerprint` - Contact fingerprint
/// * `limit` - Maximum number of messages to return
/// * `offset` - Number of messages to skip
///
/// # Returns
/// A vector of message records ordered by timestamp descending
pub fn get_conversation_messages(
    conn: &Connection,
    fingerprint: &str,
    limit: u32,
    offset: u32,
) -> Result<Vec<StoredMessage>> {
    let conversation_id_result: std::result::Result<i64, rusqlite::Error> = conn.query_row(
        "SELECT id FROM conversations WHERE fingerprint = ?1",
        [fingerprint],
        |row| row.get(0),
    );

    let conversation_id = match conversation_id_result {
        Ok(id) => id,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };

    let mut stmt = conn.prepare(
        "SELECT id, direction, timestamp, message_type, content,
                delivery_status, was_prekey_message, session_established
         FROM messages
         WHERE conversation_id = ?1
         ORDER BY timestamp DESC
         LIMIT ?2 OFFSET ?3",
    )?;

    let messages = stmt
        .query_map(rusqlite::params![conversation_id, limit, offset], |row| {
            Ok(StoredMessage {
                id: row.get(0)?,
                conversation_id,
                fingerprint: fingerprint.to_string(),
                direction: if row.get::<_, i64>(1)? == 0 {
                    MessageDirection::Received
                } else {
                    MessageDirection::Sent
                },
                timestamp: row.get(2)?,
                message_type: row.get::<_, i64>(3)?.into(),
                plaintext: row.get(4)?,
                delivery_status: row.get::<_, i64>(5)?.into(),
                was_prekey_message: row.get(6)?,
                session_established: row.get(7)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(messages)
}

/// Get all conversations ordered by recent activity
///
/// # Arguments
/// * `conn` - SQLite database connection
/// * `include_archived` - Whether to include archived conversations
///
/// # Returns
/// A vector of extended conversation records
pub fn get_conversations(
    conn: &Connection,
    include_archived: bool,
) -> Result<Vec<ExtendedConversationRecord>> {
    let query = if include_archived {
        "SELECT id, fingerprint, last_message_timestamp, unread_count, archived
         FROM conversations
         ORDER BY last_message_timestamp DESC"
    } else {
        "SELECT id, fingerprint, last_message_timestamp, unread_count, archived
         FROM conversations
         WHERE archived = 0
         ORDER BY last_message_timestamp DESC"
    };

    let mut stmt = conn.prepare(query)?;

    let conversations = stmt
        .query_map([], |row| {
            Ok(ExtendedConversationRecord {
                id: row.get(0)?,
                fingerprint: row.get(1)?,
                last_message_timestamp: row.get(2)?,
                unread_count: row.get::<_, i64>(3)? as u32,
                archived: row.get(4)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(conversations)
}

/// Get simple conversation records (for compatibility with types::ConversationRecord)
///
/// # Arguments
/// * `conn` - SQLite database connection
/// * `include_archived` - Whether to include archived conversations
///
/// # Returns
/// A vector of conversation records
pub fn list_conversations(
    conn: &Connection,
    include_archived: bool,
) -> Result<Vec<ConversationRecord>> {
    let extended = get_conversations(conn, include_archived)?;
    Ok(extended
        .into_iter()
        .map(|e| ConversationRecord {
            id: e.id,
            fingerprint: e.fingerprint,
            last_message_timestamp: e.last_message_timestamp,
        })
        .collect())
}

/// Get unread message count for a conversation
///
/// # Arguments
/// * `conn` - SQLite database connection
/// * `fingerprint` - Contact fingerprint
///
/// # Returns
/// The number of unread messages
pub fn get_unread_count(conn: &Connection, fingerprint: &str) -> Result<u32> {
    let result: std::result::Result<i64, rusqlite::Error> = conn.query_row(
        "SELECT unread_count FROM conversations WHERE fingerprint = ?1",
        [fingerprint],
        |row| row.get(0),
    );

    match result {
        Ok(count) => Ok(count as u32),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
        Err(e) => Err(e.into()),
    }
}

/// Mark conversation as read (reset unread count to 0)
///
/// # Arguments
/// * `conn` - SQLite database connection
/// * `fingerprint` - Contact fingerprint
pub fn mark_conversation_read(conn: &Connection, fingerprint: &str) -> Result<()> {
    conn.execute(
        "UPDATE conversations SET unread_count = 0 WHERE fingerprint = ?1",
        [fingerprint],
    )?;
    Ok(())
}

/// Mark messages as read up to a specific timestamp
///
/// This prevents race conditions where new messages arrive after loading history
/// but before marking as read. Only incoming messages with timestamp <= up_to_timestamp
/// are considered read.
///
/// # Arguments
/// * `conn` - SQLite database connection
/// * `fingerprint` - Contact fingerprint
/// * `up_to_timestamp` - Timestamp in seconds since UNIX epoch
pub fn mark_conversation_read_up_to(
    conn: &Connection,
    fingerprint: &str,
    up_to_timestamp: i64,
) -> Result<()> {
    let conversation_id: i64 = conn.query_row(
        "SELECT id FROM conversations WHERE fingerprint = ?1",
        [fingerprint],
        |row| row.get(0),
    )?;

    let unread_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM messages
         WHERE conversation_id = ?1
           AND direction = 0
           AND timestamp > ?2",
        rusqlite::params![conversation_id, up_to_timestamp],
        |row| row.get(0),
    )?;

    conn.execute(
        "UPDATE conversations SET unread_count = ?1 WHERE id = ?2",
        rusqlite::params![unread_count, conversation_id],
    )?;

    Ok(())
}

/// Delete a specific message
///
/// # Arguments
/// * `conn` - SQLite database connection
/// * `message_id` - Message ID
pub fn delete_message(conn: &Connection, message_id: i64) -> Result<()> {
    conn.execute("DELETE FROM messages WHERE id = ?1", [message_id])?;
    Ok(())
}

/// Delete entire conversation and all its messages
///
/// # Arguments
/// * `conn` - SQLite database connection
/// * `fingerprint` - Contact fingerprint
pub fn delete_conversation(conn: &Connection, fingerprint: &str) -> Result<()> {
    let conversation_id_result: std::result::Result<i64, rusqlite::Error> = conn.query_row(
        "SELECT id FROM conversations WHERE fingerprint = ?1",
        [fingerprint],
        |row| row.get(0),
    );

    if let Ok(id) = conversation_id_result {
        conn.execute("DELETE FROM messages WHERE conversation_id = ?1", [id])?;
        conn.execute("DELETE FROM conversations WHERE id = ?1", [id])?;
    }

    Ok(())
}

/// Archive a conversation
///
/// # Arguments
/// * `conn` - SQLite database connection
/// * `fingerprint` - Contact fingerprint
/// * `archived` - Whether to archive (true) or unarchive (false)
pub fn archive_conversation(conn: &Connection, fingerprint: &str, archived: bool) -> Result<()> {
    conn.execute(
        "UPDATE conversations SET archived = ?1 WHERE fingerprint = ?2",
        rusqlite::params![archived, fingerprint],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contact_manager;

    fn create_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        contact_manager::init_contacts_table(&conn).unwrap();
        init_message_history_tables(&conn).unwrap();

        contact_manager::add_contact(&conn, b"alice_key", Some("Alice"), "test_salt", "").unwrap();
        contact_manager::add_contact(&conn, b"bob_key", Some("Bob"), "test_salt", "").unwrap();

        conn
    }

    #[test]
    fn test_init_message_history_tables() {
        let conn = Connection::open_in_memory().unwrap();
        init_message_history_tables(&conn).unwrap();
        init_message_history_tables(&conn).unwrap();
    }

    #[test]
    fn test_store_and_get_incoming_message() {
        let conn = create_test_db();
        let alice_fp = contact_manager::generate_fingerprint(b"alice_key", "test_salt", "");

        let msg_id =
            store_incoming_message(&conn, &alice_fp, 1000, b"Hello", false, false).unwrap();

        let msg = get_message(&conn, msg_id).unwrap();
        assert_eq!(msg.id, msg_id);
        assert_eq!(msg.fingerprint, alice_fp);
        assert_eq!(msg.direction, MessageDirection::Received);
        assert_eq!(msg.plaintext, b"Hello");
        assert_eq!(msg.timestamp, 1000);
    }

    #[test]
    fn test_store_and_get_outgoing_message() {
        let conn = create_test_db();
        let bob_fp = contact_manager::generate_fingerprint(b"bob_key", "test_salt", "");

        let msg_id = store_outgoing_message(&conn, &bob_fp, 2000, b"Hi Bob").unwrap();

        let msg = get_message(&conn, msg_id).unwrap();
        assert_eq!(msg.direction, MessageDirection::Sent);
        assert_eq!(msg.plaintext, b"Hi Bob");
        assert_eq!(msg.delivery_status, DeliveryStatus::Pending);
    }

    #[test]
    fn test_update_delivery_status() {
        let conn = create_test_db();
        let bob_fp = contact_manager::generate_fingerprint(b"bob_key", "test_salt", "");

        let msg_id = store_outgoing_message(&conn, &bob_fp, 2000, b"Hi Bob").unwrap();

        update_delivery_status(&conn, msg_id, DeliveryStatus::Delivered).unwrap();

        let msg = get_message(&conn, msg_id).unwrap();
        assert_eq!(msg.delivery_status, DeliveryStatus::Delivered);
    }

    #[test]
    fn test_get_conversation_messages() {
        let conn = create_test_db();
        let alice_fp = contact_manager::generate_fingerprint(b"alice_key", "test_salt", "");

        store_incoming_message(&conn, &alice_fp, 1000, b"Message 1", false, false).unwrap();
        store_outgoing_message(&conn, &alice_fp, 2000, b"Message 2").unwrap();
        store_incoming_message(&conn, &alice_fp, 3000, b"Message 3", false, false).unwrap();

        let messages = get_conversation_messages(&conn, &alice_fp, 10, 0).unwrap();
        assert_eq!(messages.len(), 3);

        assert_eq!(messages[0].timestamp, 3000);
        assert_eq!(messages[1].timestamp, 2000);
        assert_eq!(messages[2].timestamp, 1000);
    }

    #[test]
    fn test_get_conversation_messages_pagination() {
        let conn = create_test_db();
        let alice_fp = contact_manager::generate_fingerprint(b"alice_key", "test_salt", "");

        for i in 0..5 {
            store_incoming_message(&conn, &alice_fp, 1000 + i, b"Message", false, false).unwrap();
        }

        let page1 = get_conversation_messages(&conn, &alice_fp, 2, 0).unwrap();
        assert_eq!(page1.len(), 2);
        assert_eq!(page1[0].timestamp, 1004);

        let page2 = get_conversation_messages(&conn, &alice_fp, 2, 2).unwrap();
        assert_eq!(page2.len(), 2);
        assert_eq!(page2[0].timestamp, 1002);
    }

    #[test]
    fn test_get_conversations() {
        let conn = create_test_db();
        let alice_fp = contact_manager::generate_fingerprint(b"alice_key", "test_salt", "");
        let bob_fp = contact_manager::generate_fingerprint(b"bob_key", "test_salt", "");

        store_incoming_message(&conn, &alice_fp, 1000, b"Hello", false, false).unwrap();
        store_incoming_message(&conn, &bob_fp, 2000, b"Hi", false, false).unwrap();

        let conversations = get_conversations(&conn, false).unwrap();
        assert_eq!(conversations.len(), 2);

        assert_eq!(conversations[0].fingerprint, bob_fp);
        assert_eq!(conversations[0].last_message_timestamp, 2000);
        assert_eq!(conversations[1].fingerprint, alice_fp);
    }

    #[test]
    fn test_unread_count() {
        let conn = create_test_db();
        let alice_fp = contact_manager::generate_fingerprint(b"alice_key", "test_salt", "");

        store_incoming_message(&conn, &alice_fp, 1000, b"Message 1", false, false).unwrap();
        store_incoming_message(&conn, &alice_fp, 2000, b"Message 2", false, false).unwrap();
        store_outgoing_message(&conn, &alice_fp, 3000, b"Reply").unwrap();

        let count = get_unread_count(&conn, &alice_fp).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_mark_conversation_read() {
        let conn = create_test_db();
        let alice_fp = contact_manager::generate_fingerprint(b"alice_key", "test_salt", "");

        store_incoming_message(&conn, &alice_fp, 1000, b"Message", false, false).unwrap();

        let count_before = get_unread_count(&conn, &alice_fp).unwrap();
        assert_eq!(count_before, 1);

        mark_conversation_read(&conn, &alice_fp).unwrap();

        let count_after = get_unread_count(&conn, &alice_fp).unwrap();
        assert_eq!(count_after, 0);
    }

    #[test]
    fn test_mark_conversation_read_up_to() {
        let conn = create_test_db();
        let alice_fp = contact_manager::generate_fingerprint(b"alice_key", "test_salt", "");

        store_incoming_message(&conn, &alice_fp, 1000, b"Message 1", false, false).unwrap();
        store_incoming_message(&conn, &alice_fp, 2000, b"Message 2", false, false).unwrap();
        store_incoming_message(&conn, &alice_fp, 3000, b"Message 3", false, false).unwrap();

        mark_conversation_read_up_to(&conn, &alice_fp, 2000).unwrap();

        let count = get_unread_count(&conn, &alice_fp).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_delete_message() {
        let conn = create_test_db();
        let alice_fp = contact_manager::generate_fingerprint(b"alice_key", "test_salt", "");

        let msg_id =
            store_incoming_message(&conn, &alice_fp, 1000, b"Message", false, false).unwrap();

        delete_message(&conn, msg_id).unwrap();

        let result = get_message(&conn, msg_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_delete_conversation() {
        let conn = create_test_db();
        let alice_fp = contact_manager::generate_fingerprint(b"alice_key", "test_salt", "");

        store_incoming_message(&conn, &alice_fp, 1000, b"Message 1", false, false).unwrap();
        store_incoming_message(&conn, &alice_fp, 2000, b"Message 2", false, false).unwrap();

        delete_conversation(&conn, &alice_fp).unwrap();

        let messages = get_conversation_messages(&conn, &alice_fp, 10, 0).unwrap();
        assert_eq!(messages.len(), 0);

        let conversations = get_conversations(&conn, false).unwrap();
        assert!(!conversations.iter().any(|c| c.fingerprint == alice_fp));
    }

    #[test]
    fn test_archive_conversation() {
        let conn = create_test_db();
        let alice_fp = contact_manager::generate_fingerprint(b"alice_key", "test_salt", "");

        store_incoming_message(&conn, &alice_fp, 1000, b"Message", false, false).unwrap();

        archive_conversation(&conn, &alice_fp, true).unwrap();

        let all_convs = get_conversations(&conn, true).unwrap();
        assert_eq!(all_convs.len(), 1);
        assert!(all_convs[0].archived);

        let active_convs = get_conversations(&conn, false).unwrap();
        assert_eq!(active_convs.len(), 0);
    }

    #[test]
    fn test_get_message_nonexistent() {
        let conn = create_test_db();
        let result = get_message(&conn, 99999);
        assert!(result.is_err());
    }

    #[test]
    fn test_list_conversations() {
        let conn = create_test_db();
        let alice_fp = contact_manager::generate_fingerprint(b"alice_key", "test_salt", "");
        let bob_fp = contact_manager::generate_fingerprint(b"bob_key", "test_salt", "");

        store_incoming_message(&conn, &alice_fp, 1000, b"Hello", false, false).unwrap();
        store_incoming_message(&conn, &bob_fp, 2000, b"Hi", false, false).unwrap();

        let conversations = list_conversations(&conn, false).unwrap();
        assert_eq!(conversations.len(), 2);
        assert_eq!(conversations[0].fingerprint, bob_fp);
        assert_eq!(conversations[0].last_message_timestamp, 2000);
    }
}

import Database from 'better-sqlite3';

/**
 * Creates an in-memory SQLite database with the same schema as production.
 * Mirrors the schema and migrations in server/db.ts.
 */
export function createTestDb(): Database.Database {
  const db = new Database(':memory:');

  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      password_changed_at TEXT DEFAULT (datetime('now')),
      failed_login_attempts INTEGER DEFAULT 0,
      locked_until TEXT DEFAULT NULL
    );

    CREATE TABLE IF NOT EXISTS identity_keys (
      user_id INTEGER UNIQUE NOT NULL REFERENCES users(id),
      registration_id INTEGER NOT NULL,
      identity_key TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS signed_pre_keys (
      user_id INTEGER NOT NULL REFERENCES users(id),
      key_id INTEGER NOT NULL,
      public_key TEXT NOT NULL,
      signature TEXT NOT NULL,
      PRIMARY KEY (user_id, key_id)
    );

    CREATE TABLE IF NOT EXISTS one_time_pre_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id),
      key_id INTEGER NOT NULL,
      public_key TEXT NOT NULL,
      UNIQUE(user_id, key_id)
    );

    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sender_id INTEGER NOT NULL REFERENCES users(id),
      recipient_id INTEGER NOT NULL REFERENCES users(id),
      type INTEGER NOT NULL,
      body TEXT NOT NULL,
      timestamp TEXT DEFAULT (datetime('now')),
      delivered INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT DEFAULT (datetime('now')),
      event TEXT NOT NULL,
      user_id INTEGER,
      username TEXT,
      ip TEXT,
      details TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_messages_recipient_pending ON messages(recipient_id, delivered, timestamp);
    CREATE INDEX IF NOT EXISTS idx_messages_delivered_timestamp ON messages(delivered, timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id);
  `);

  return db;
}

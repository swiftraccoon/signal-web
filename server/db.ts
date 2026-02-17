import Database from 'better-sqlite3';
import config from './config';
import logger from './logger';
import { incr, DB_SLOW_THRESHOLD_MS } from './metrics';
import type {
  DbIdentityKey, DbSignedPreKey, DbOneTimePreKey,
  PreKeyBundleUpload,
  PreKeyBundleResponse,
} from '../shared/types';

const db: Database.Database = new Database(config.DB_PATH);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    password_changed_at TEXT DEFAULT (datetime('now')),
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TEXT DEFAULT NULL,
    token_version INTEGER DEFAULT 1
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
    original_id TEXT,
    timestamp TEXT DEFAULT (datetime('now')),
    delivered INTEGER DEFAULT 0,
    expires_at INTEGER
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

  CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  -- Indexes for query performance
  CREATE INDEX IF NOT EXISTS idx_messages_recipient_pending ON messages(recipient_id, delivered, timestamp);
  CREATE INDEX IF NOT EXISTS idx_messages_delivered_timestamp ON messages(delivered, timestamp);
  CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
  CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id);
  CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
  CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);

  CREATE TABLE IF NOT EXISTS conversation_settings (
    user_id_1 INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_id_2 INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    disappearing_timer_ms INTEGER DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (user_id_1, user_id_2),
    CHECK (user_id_1 < user_id_2)
  );

  CREATE INDEX IF NOT EXISTS idx_messages_expires ON messages(expires_at) WHERE expires_at IS NOT NULL;
`);

// Add columns to existing tables if they don't exist (migration-safe)
try { db.exec("ALTER TABLE users ADD COLUMN password_changed_at TEXT DEFAULT (datetime('now'))"); } catch { /* column exists */ }
try { db.exec('ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0'); } catch { /* column exists */ }
try { db.exec('ALTER TABLE users ADD COLUMN locked_until TEXT DEFAULT NULL'); } catch { /* column exists */ }
try { db.exec("ALTER TABLE one_time_pre_keys ADD COLUMN uploaded_at INTEGER DEFAULT (unixepoch())"); } catch { /* column exists */ }
try { db.exec("ALTER TABLE signed_pre_keys ADD COLUMN uploaded_at INTEGER DEFAULT (unixepoch())"); } catch { /* column exists */ }
try { db.exec('ALTER TABLE messages ADD COLUMN expires_at INTEGER'); } catch { /* column exists */ }
try { db.exec('ALTER TABLE messages ADD COLUMN original_id TEXT'); } catch { /* column exists */ }
try { db.exec('ALTER TABLE users ADD COLUMN token_version INTEGER DEFAULT 1'); } catch { /* column exists */ }

// Instrumented statement wrapper - tracks query timing
interface TimedStatement {
  get(...args: unknown[]): unknown;
  all(...args: unknown[]): unknown[];
  run(...args: unknown[]): Database.RunResult;
}

function timedStmt(rawStmt: Database.Statement, name: string): TimedStatement {
  return {
    get(...args: unknown[]) {
      const start = performance.now();
      const result = rawStmt.get(...args);
      trackQuery(name, start);
      return result;
    },
    all(...args: unknown[]) {
      const start = performance.now();
      const result = rawStmt.all(...args);
      trackQuery(name, start);
      return result;
    },
    run(...args: unknown[]) {
      const start = performance.now();
      const result = rawStmt.run(...args);
      trackQuery(name, start);
      return result;
    },
  };
}

function trackQuery(name: string, startTime: number): void {
  const duration = performance.now() - startTime;
  incr('dbQueries');
  if (duration > DB_SLOW_THRESHOLD_MS) {
    incr('dbSlowQueries');
    logger.warn({ query: name, durationMs: Math.round(duration) }, 'Slow DB query');
  }
}

const stmt = {
  createUser: timedStmt(db.prepare('INSERT INTO users (username, password) VALUES (?, ?)'), 'createUser'),
  getUserByUsername: timedStmt(db.prepare('SELECT * FROM users WHERE username = ?'), 'getUserByUsername'),
  getUserById: timedStmt(db.prepare('SELECT id, username, created_at, token_version FROM users WHERE id = ?'), 'getUserById'),
  searchUsers: timedStmt(db.prepare("SELECT id, username FROM users WHERE username LIKE ? ESCAPE '\\' LIMIT 20"), 'searchUsers'),
  updatePassword: timedStmt(db.prepare("UPDATE users SET password = ?, password_changed_at = datetime('now'), token_version = token_version + 1 WHERE id = ?"), 'updatePassword'),

  // Account lockout (atomic increment + return to prevent TOCTOU race)
  incrementFailedLoginsAndGet: timedStmt(db.prepare('UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ? RETURNING failed_login_attempts'), 'incrementFailedLoginsAndGet'),
  lockAccount: timedStmt(db.prepare("UPDATE users SET locked_until = datetime('now', '+' || ? || ' minutes') WHERE id = ?"), 'lockAccount'),
  resetFailedLogins: timedStmt(db.prepare('UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?'), 'resetFailedLogins'),

  upsertIdentityKey: timedStmt(db.prepare(`
    INSERT INTO identity_keys (user_id, registration_id, identity_key)
    VALUES (?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET registration_id=excluded.registration_id, identity_key=excluded.identity_key
  `), 'upsertIdentityKey'),
  getIdentityKey: timedStmt(db.prepare('SELECT * FROM identity_keys WHERE user_id = ?'), 'getIdentityKey'),

  upsertSignedPreKey: timedStmt(db.prepare(`
    INSERT INTO signed_pre_keys (user_id, key_id, public_key, signature)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(user_id, key_id) DO UPDATE SET public_key=excluded.public_key, signature=excluded.signature
  `), 'upsertSignedPreKey'),
  getSignedPreKey: timedStmt(db.prepare('SELECT * FROM signed_pre_keys WHERE user_id = ? ORDER BY key_id DESC LIMIT 1'), 'getSignedPreKey'),

  insertOneTimePreKey: timedStmt(db.prepare('INSERT OR IGNORE INTO one_time_pre_keys (user_id, key_id, public_key) VALUES (?, ?, ?)'), 'insertOneTimePreKey'),
  consumeOneTimePreKey: timedStmt(db.prepare('DELETE FROM one_time_pre_keys WHERE id = (SELECT id FROM one_time_pre_keys WHERE user_id = ? LIMIT 1) RETURNING *'), 'consumeOneTimePreKey'),
  countOneTimePreKeys: timedStmt(db.prepare('SELECT COUNT(*) as count FROM one_time_pre_keys WHERE user_id = ?'), 'countOneTimePreKeys'),

  storeMessage: timedStmt(db.prepare('INSERT INTO messages (sender_id, recipient_id, type, body) VALUES (?, ?, ?, ?)'), 'storeMessage'),
  getPendingMessages: timedStmt(db.prepare('SELECT m.id, m.sender_id, m.type, m.body, m.timestamp, u.username as sender_username FROM messages m JOIN users u ON m.sender_id = u.id WHERE m.recipient_id = ? AND m.delivered = 0 ORDER BY m.timestamp'), 'getPendingMessages'),
  markDelivered: timedStmt(db.prepare('UPDATE messages SET delivered = 1 WHERE id = ? AND recipient_id = ?'), 'markDelivered'),
  // ACK handler: atomically mark delivered and return actual sender_id (prevents spoofing)
  markDeliveredAndGetSender: timedStmt(db.prepare('UPDATE messages SET delivered = 1 WHERE id = ? AND recipient_id = ? AND delivered = 0 RETURNING sender_id, original_id'), 'markDeliveredAndGetSender'),
  // Check if two users have exchanged messages (for typing/timer authorization)
  hasConversation: timedStmt(db.prepare('SELECT 1 FROM messages WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?) LIMIT 1'), 'hasConversation'),
  purgeDelivered: timedStmt(db.prepare("DELETE FROM messages WHERE delivered = 1 AND timestamp < datetime('now', '-1 hour')"), 'purgeDelivered'),
  purgeStale: timedStmt(db.prepare("DELETE FROM messages WHERE delivered = 0 AND timestamp < datetime('now', '-7 days')"), 'purgeStale'),

  // Audit logging
  insertAudit: timedStmt(db.prepare('INSERT INTO audit_log (event, user_id, username, ip, details) VALUES (?, ?, ?, ?, ?)'), 'insertAudit'),

  // Refresh tokens
  createRefreshToken: timedStmt(db.prepare('INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)'), 'createRefreshToken'),
  getRefreshToken: timedStmt(db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ? AND expires_at > unixepoch()'), 'getRefreshToken'),
  deleteRefreshToken: timedStmt(db.prepare('DELETE FROM refresh_tokens WHERE token_hash = ?'), 'deleteRefreshToken'),
  deleteUserRefreshTokens: timedStmt(db.prepare('DELETE FROM refresh_tokens WHERE user_id = ?'), 'deleteUserRefreshTokens'),
  purgeExpiredRefreshTokens: timedStmt(db.prepare('DELETE FROM refresh_tokens WHERE expires_at < unixepoch()'), 'purgeExpiredRefreshTokens'),

  // Disappearing messages / conversation settings
  upsertConversationTimer: timedStmt(db.prepare(`
    INSERT INTO conversation_settings (user_id_1, user_id_2, disappearing_timer_ms, updated_at)
    VALUES (MIN(?, ?), MAX(?, ?), ?, unixepoch())
    ON CONFLICT(user_id_1, user_id_2) DO UPDATE SET disappearing_timer_ms=excluded.disappearing_timer_ms, updated_at=excluded.updated_at
  `), 'upsertConversationTimer'),
  getConversationTimer: timedStmt(db.prepare('SELECT disappearing_timer_ms FROM conversation_settings WHERE user_id_1 = MIN(?, ?) AND user_id_2 = MAX(?, ?)'), 'getConversationTimer'),
  storeMessageWithExpiry: timedStmt(db.prepare('INSERT INTO messages (sender_id, recipient_id, type, body, expires_at, original_id) VALUES (?, ?, ?, ?, ?, ?)'), 'storeMessageWithExpiry'),
  purgeExpiredMessages: timedStmt(db.prepare('DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at < unixepoch()'), 'purgeExpiredMessages'),
};

const getPreKeyBundle: (userId: number) => PreKeyBundleResponse | null = db.transaction((userId: number): PreKeyBundleResponse | null => {
  const identity = stmt.getIdentityKey.get(userId) as DbIdentityKey | undefined;
  if (!identity) return null;

  const signedPreKey = stmt.getSignedPreKey.get(userId) as DbSignedPreKey | undefined;
  if (!signedPreKey) return null;

  const oneTimePreKey = stmt.consumeOneTimePreKey.get(userId) as DbOneTimePreKey | undefined;

  return {
    registrationId: identity.registration_id,
    identityKey: identity.identity_key,
    signedPreKey: {
      keyId: signedPreKey.key_id,
      publicKey: signedPreKey.public_key,
      signature: signedPreKey.signature,
      uploadedAt: signedPreKey.uploaded_at ?? null,
    },
    preKey: oneTimePreKey ? {
      keyId: oneTimePreKey.key_id,
      publicKey: oneTimePreKey.public_key,
    } : null,
  };
});

const uploadBundle: (userId: number, bundle: PreKeyBundleUpload) => void = db.transaction((userId: number, bundle: PreKeyBundleUpload): void => {
  stmt.upsertIdentityKey.run(userId, bundle.registrationId, bundle.identityKey);
  stmt.upsertSignedPreKey.run(userId, bundle.signedPreKey.keyId, bundle.signedPreKey.publicKey, bundle.signedPreKey.signature);
  for (const pk of bundle.preKeys) {
    stmt.insertOneTimePreKey.run(userId, pk.keyId, pk.publicKey);
  }
});

const deleteUser: (userId: number) => void = db.transaction((userId: number): void => {
  db.prepare('DELETE FROM one_time_pre_keys WHERE user_id = ?').run(userId);
  db.prepare('DELETE FROM signed_pre_keys WHERE user_id = ?').run(userId);
  db.prepare('DELETE FROM identity_keys WHERE user_id = ?').run(userId);
  db.prepare('DELETE FROM messages WHERE sender_id = ? OR recipient_id = ?').run(userId, userId);
  db.prepare('DELETE FROM users WHERE id = ?').run(userId);
});

export { db, stmt, getPreKeyBundle, uploadBundle, deleteUser };

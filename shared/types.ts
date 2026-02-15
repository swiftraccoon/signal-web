import type { WS_MSG_TYPE } from './constants';

// ===== DB Row Types =====

export interface DbUser {
  id: number;
  username: string;
  password: string;
  created_at: string;
  password_changed_at: string | null;
  failed_login_attempts: number;
  locked_until: string | null;
}

export interface DbIdentityKey {
  user_id: number;
  registration_id: number;
  identity_key: string;
}

export interface DbSignedPreKey {
  user_id: number;
  key_id: number;
  public_key: string;
  signature: string;
}

export interface DbOneTimePreKey {
  id: number;
  user_id: number;
  key_id: number;
  public_key: string;
}

export interface DbMessage {
  id: number;
  sender_id: number;
  recipient_id: number;
  type: number;
  body: string;
  timestamp: string;
  delivered: number;
}

export interface DbPendingMessageRow {
  id: number;
  sender_id: number;
  type: number;
  body: string;
  timestamp: string;
  sender_username: string;
}

export interface DbCount {
  count: number;
}

export interface DbConversationPartner {
  partner_id: number;
}

export interface DbMarkDeliveredResult {
  sender_id: number;
}

// ===== API Types =====

export interface ApiUser {
  id: number;
  username: string;
}

export interface AuthResponse {
  token: string;
  user: ApiUser;
}

export interface PreKeyPublic {
  keyId: number;
  publicKey: string;
}

export interface SignedPreKeyPublic {
  keyId: number;
  publicKey: string;
  signature: string;
}

export interface PreKeyBundleUpload {
  registrationId: number;
  identityKey: string;
  signedPreKey: SignedPreKeyPublic;
  preKeys: PreKeyPublic[];
}

export interface PreKeyBundleResponse {
  registrationId: number;
  identityKey: string;
  signedPreKey: SignedPreKeyPublic;
  preKey: PreKeyPublic | null;
  userId?: number;
  username?: string;
}

export interface PendingMessage {
  from: string;
  fromId: number;
  message: { type: number; body: string };
  timestamp: string;
  dbId: number;
}

export interface KeyCountResponse {
  count: number;
}

export interface WsTicketResponse {
  ticket: string;
}

// ===== Server Types =====

export interface ServerConfig {
  PORT: number;
  JWT_SECRET: string;
  JWT_ALGORITHM: string;
  DB_PATH: string;
  BCRYPT_ROUNDS: number;
  JWT_EXPIRY: string;
  IS_PRODUCTION: boolean;
  MAX_FAILED_LOGINS: number;
  LOCKOUT_DURATION_MIN: number;
  ALLOWED_WS_ORIGINS: string[];
}

export interface JwtTokenPayload {
  id: number;
  username: string;
  iat?: number;
  exp?: number;
}

export interface WsTicketEntry {
  userId: number;
  username: string;
  expiresAt: number;
}

export interface AuditOptions {
  userId?: number | null;
  username?: string | null;
  ip?: string | null;
  details?: string | null;
}

export interface BundleFetchEntry {
  count: number;
  windowStart: number;
}

export interface UserRateLimitEntry {
  count: number;
  windowStart: number;
}

// ===== WS User =====

export interface WsUser {
  id: number;
  username: string;
}

// ===== WS Message Types (Discriminated Unions) =====

// Client -> Server
export type WsClientMessage =
  | WsClientChatMessage
  | WsClientAckMessage
  | WsClientTypingMessage
  | WsClientReadReceiptMessage
  | WsClientDisappearingTimerMessage;

export interface WsClientChatMessage {
  type: typeof WS_MSG_TYPE.MESSAGE;
  to: string;
  message: { type: number; body: string };
  id: string;
}

export interface WsClientAckMessage {
  type: typeof WS_MSG_TYPE.ACK;
  dbId: number;
  from: string;
  originalId: string;
}

export interface WsClientTypingMessage {
  type: typeof WS_MSG_TYPE.TYPING;
  to: string;
  isTyping: boolean;
}

export interface WsClientReadReceiptMessage {
  type: typeof WS_MSG_TYPE.READ_RECEIPT;
  to: string;
  messageIds: string[];
}

export interface WsClientDisappearingTimerMessage {
  type: typeof WS_MSG_TYPE.DISAPPEARING_TIMER;
  to: string;
  timer: number;
}

// Server -> Client
export type WsServerMessage =
  | WsServerChatMessage
  | WsServerStoredMessage
  | WsServerDeliveredMessage
  | WsServerTypingMessage
  | WsServerReadReceiptMessage
  | WsServerDisappearingTimerMessage
  | WsServerPrekeyLowMessage
  | WsServerErrorMessage
  | WsServerPresenceMessage;

export interface WsServerChatMessage {
  type: typeof WS_MSG_TYPE.MESSAGE;
  from: string;
  fromId: number;
  message: { type: number; body: string };
  timestamp: string;
  id: string;
  dbId: number;
}

export interface WsServerStoredMessage {
  type: typeof WS_MSG_TYPE.STORED;
  id: string;
  timestamp: string;
}

export interface WsServerDeliveredMessage {
  type: typeof WS_MSG_TYPE.DELIVERED;
  id: string;
}

export interface WsServerTypingMessage {
  type: typeof WS_MSG_TYPE.TYPING;
  from: string;
  isTyping: boolean;
}

export interface WsServerReadReceiptMessage {
  type: typeof WS_MSG_TYPE.READ_RECEIPT;
  from: string;
  messageIds: string[];
}

export interface WsServerDisappearingTimerMessage {
  type: typeof WS_MSG_TYPE.DISAPPEARING_TIMER;
  from: string;
  timer: number;
}

export interface WsServerPrekeyLowMessage {
  type: typeof WS_MSG_TYPE.PREKEY_LOW;
  remaining: number;
}

export interface WsServerErrorMessage {
  type: typeof WS_MSG_TYPE.ERROR;
  message: string;
}

export interface WsServerPresenceMessage {
  type: typeof WS_MSG_TYPE.PRESENCE;
  onlineUserIds?: number[];
  userId?: number;
  username?: string;
  online?: boolean;
}

// ===== Client Types =====

export interface Contact {
  id: number;
  username: string;
  unread: number;
  lastMessage: string;
  lastTime: string;
}

export interface ChatMessage {
  text: string;
  sent: boolean;
  time: string;
  id?: string;
  status?: 'sent' | 'delivered' | 'read';
  disappearAt?: number;
  error?: boolean;
  system?: boolean;
  readReceiptSent?: boolean;
}

export interface EncryptedValue {
  __encrypted: true;
  iv: string;
  data: string;
}

// ===== Metrics Types =====

export interface MetricsCounters {
  httpRequests: number;
  httpErrors: number;
  wsConnections: number;
  wsMessagesIn: number;
  wsMessagesOut: number;
  dbQueries: number;
  dbSlowQueries: number;
  messagesStored: number;
  messagesDelivered: number;
  authSuccess: number;
  authFailure: number;
  startedAt: number;
}

export type MetricsKey = keyof MetricsCounters;

export interface EndpointStats {
  count: number;
  avgMs: number;
  maxMs: number;
  p99Ms: number;
}

export interface MetricsSnapshot extends MetricsCounters {
  uptimeMs: number;
  uptimeSec: number;
  endpoints: Record<string, EndpointStats>;
}

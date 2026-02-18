/**
 * Automated E2E test for Signal-Web
 * Tests the full Signal Protocol flow: key generation, session establishment,
 * encryption, WebSocket relay, and decryption — all without a browser.
 */
import http from 'http';
import WebSocket from 'ws';
import crypto from 'crypto';
import {
  KeyHelper,
  SignalProtocolAddress,
  SessionBuilder,
  SessionCipher,
  setWebCrypto,
} from '@privacyresearch/libsignal-protocol-typescript';

const BASE = process.env.E2E_BASE_URL || 'http://localhost:3001';
const DEVICE_ID = 1;

// Provide Node.js Web Crypto to the Signal library
setWebCrypto(crypto.webcrypto as unknown as Crypto);

// --- In-memory SignalProtocolStore for Node ---
class TestStore {
  _identityKeyPair: { pubKey: ArrayBuffer; privKey: ArrayBuffer } | undefined = undefined;
  _registrationId: number | undefined = undefined;
  _preKeys: Record<number, { pubKey: ArrayBuffer; privKey: ArrayBuffer }> = {};
  _signedPreKeys: Record<number, { pubKey: ArrayBuffer; privKey: ArrayBuffer }> = {};
  _sessions: Record<string, string> = {};
  _identityKeys: Record<string, string> = {};

  async getIdentityKeyPair() { return this._identityKeyPair; }
  async getLocalRegistrationId() { return this._registrationId; }
  async isTrustedIdentity(id: string, key: ArrayBuffer, _dir: unknown) {
    const stored = this._identityKeys[id];
    if (!stored) return true;
    return ab2hex(key) === stored;
  }
  async saveIdentity(addr: string, key: ArrayBuffer) {
    const existing = this._identityKeys[addr];
    const hex = ab2hex(key);
    this._identityKeys[addr] = hex;
    return existing !== undefined && existing !== hex;
  }
  async loadPreKey(keyId: number) { return this._preKeys[keyId]; }
  async storePreKey(keyId: number, keyPair: { pubKey: ArrayBuffer; privKey: ArrayBuffer }) { this._preKeys[keyId] = keyPair; }
  async removePreKey(keyId: number) { delete this._preKeys[keyId]; }
  async loadSignedPreKey(keyId: number) { return this._signedPreKeys[keyId]; }
  async storeSignedPreKey(keyId: number, keyPair: { pubKey: ArrayBuffer; privKey: ArrayBuffer }) { this._signedPreKeys[keyId] = keyPair; }
  async removeSignedPreKey(keyId: number) { delete this._signedPreKeys[keyId]; }
  async loadSession(addr: string) { return this._sessions[addr]; }
  async storeSession(addr: string, record: string) { this._sessions[addr] = record; }
}

// --- Helpers ---
function ab2b64(buf: ArrayBuffer): string {
  return Buffer.from(buf).toString('base64');
}
function b642ab(b64: string): ArrayBuffer {
  const buf = Buffer.from(b64, 'base64');
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}
function ab2hex(buf: ArrayBuffer): string {
  return Buffer.from(buf).toString('hex');
}

interface HttpResponse<T> {
  status: number;
  body: T;
}

function request<T>(method: string, path: string, body?: unknown, token?: string): Promise<HttpResponse<T>> {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE);
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const req = http.request(url, { method, headers }, (res) => {
      let data = '';
      res.on('data', (d: Buffer) => data += d);
      res.on('end', () => {
        try { resolve({ status: res.statusCode!, body: JSON.parse(data) as T }); }
        catch { resolve({ status: res.statusCode!, body: data as unknown as T }); }
      });
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

async function connectWS(token: string): Promise<WebSocket> {
  // Get a one-time ticket for WS auth (never pass JWT in URL)
  const ticketRes = await request<{ ticket: string }>('POST', '/api/auth/ws-ticket', null, token);
  if (ticketRes.status !== 200 || !ticketRes.body.ticket) {
    throw new Error('Failed to get WS ticket');
  }
  const ticket = ticketRes.body.ticket;

  return new Promise((resolve, reject) => {
    const wsUrl = BASE.replace('http', 'ws');
    const ws = new WebSocket(`${wsUrl}?ticket=${ticket}`);
    ws.on('open', () => resolve(ws));
    ws.on('error', reject);
  });
}

function waitForMessage<T extends { type: string }>(ws: WebSocket, type: string, timeout = 5000): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Timeout waiting for ${type}`)), timeout);
    const handler = (data: WebSocket.Data) => {
      const msg = JSON.parse(data.toString()) as T;
      if (!type || (msg as { type: string }).type === type) {
        clearTimeout(timer);
        ws.off('message', handler);
        resolve(msg);
      }
    };
    ws.on('message', handler);
  });
}

// --- Main Test ---
async function runTest() {
  let passed = 0;
  let failed = 0;

  function assert(condition: boolean, name: string) {
    if (condition) {
      console.log(`  PASS: ${name}`);
      passed++;
    } else {
      console.log(`  FAIL: ${name}`);
      failed++;
    }
  }

  // ===== PHASE 1: Registration =====
  console.log('\n=== PHASE 1: User Registration ===');

  const aliceReg = await request<{ token: string; user: { id: number; username: string } }>('POST', '/api/auth/register', {
    username: 'alice', password: 'AliceSecure123A',
  });
  assert(aliceReg.status === 201, 'Alice registered');
  const aliceToken = aliceReg.body.token;
  void aliceReg.body.user.id; // Used only for registration verification

  const bobReg = await request<{ token: string; user: { id: number; username: string } }>('POST', '/api/auth/register', {
    username: 'bob', password: 'BobbySecure123B',
  });
  assert(bobReg.status === 201, 'Bob registered');
  const bobToken = bobReg.body.token;
  const bobId = bobReg.body.user.id;

  // ===== PHASE 2: Signal Key Generation =====
  console.log('\n=== PHASE 2: Signal Protocol Key Generation ===');

  const aliceStore = new TestStore();
  const bobStore = new TestStore();

  // Alice generates keys
  const aliceIdentity = await KeyHelper.generateIdentityKeyPair();
  const aliceRegId = KeyHelper.generateRegistrationId();
  aliceStore._identityKeyPair = aliceIdentity;
  aliceStore._registrationId = aliceRegId;

  const aliceSignedPreKey = await KeyHelper.generateSignedPreKey(aliceIdentity, 1);
  await aliceStore.storeSignedPreKey(aliceSignedPreKey.keyId, aliceSignedPreKey.keyPair);

  const alicePreKeys: { keyId: number; publicKey: string }[] = [];
  for (let i = 1; i <= 10; i++) {
    const pk = await KeyHelper.generatePreKey(i);
    await aliceStore.storePreKey(pk.keyId, pk.keyPair);
    alicePreKeys.push({ keyId: pk.keyId, publicKey: ab2b64(pk.keyPair.pubKey) });
  }

  assert(aliceIdentity.pubKey.byteLength === 33, 'Alice identity key is 33 bytes (Curve25519)');
  assert(aliceSignedPreKey.signature.byteLength > 0, 'Alice signed pre-key has signature');

  // Bob generates keys
  const bobIdentity = await KeyHelper.generateIdentityKeyPair();
  const bobRegId = KeyHelper.generateRegistrationId();
  bobStore._identityKeyPair = bobIdentity;
  bobStore._registrationId = bobRegId;

  const bobSignedPreKey = await KeyHelper.generateSignedPreKey(bobIdentity, 1);
  await bobStore.storeSignedPreKey(bobSignedPreKey.keyId, bobSignedPreKey.keyPair);

  const bobPreKeys: { keyId: number; publicKey: string }[] = [];
  for (let i = 1; i <= 10; i++) {
    const pk = await KeyHelper.generatePreKey(i);
    await bobStore.storePreKey(pk.keyId, pk.keyPair);
    bobPreKeys.push({ keyId: pk.keyId, publicKey: ab2b64(pk.keyPair.pubKey) });
  }

  assert(bobIdentity.pubKey.byteLength === 33, 'Bob identity key is 33 bytes (Curve25519)');

  // ===== PHASE 3: Upload Bundles to Server =====
  console.log('\n=== PHASE 3: Upload Key Bundles ===');

  const aliceBundleUpload = await request<{ success: boolean }>('PUT', '/api/keys/bundle', {
    registrationId: aliceRegId,
    identityKey: ab2b64(aliceIdentity.pubKey),
    signedPreKey: {
      keyId: aliceSignedPreKey.keyId,
      publicKey: ab2b64(aliceSignedPreKey.keyPair.pubKey),
      signature: ab2b64(aliceSignedPreKey.signature),
    },
    preKeys: alicePreKeys,
  }, aliceToken);
  assert(aliceBundleUpload.body.success === true, 'Alice bundle uploaded');

  const bobBundleUpload = await request<{ success: boolean }>('PUT', '/api/keys/bundle', {
    registrationId: bobRegId,
    identityKey: ab2b64(bobIdentity.pubKey),
    signedPreKey: {
      keyId: bobSignedPreKey.keyId,
      publicKey: ab2b64(bobSignedPreKey.keyPair.pubKey),
      signature: ab2b64(bobSignedPreKey.signature),
    },
    preKeys: bobPreKeys,
  }, bobToken);
  assert(bobBundleUpload.body.success === true, 'Bob bundle uploaded');

  // ===== PHASE 4: Session Establishment (X3DH) =====
  console.log('\n=== PHASE 4: X3DH Session Establishment ===');

  interface BundleResponse {
    registrationId: number;
    identityKey: string;
    signedPreKey: { keyId: number; publicKey: string; signature: string };
    preKey: { keyId: number; publicKey: string } | null;
  }

  // Alice fetches Bob's bundle from server
  const fetchedBundle = await request<BundleResponse>('GET', `/api/keys/bundle/${bobId}`, null, aliceToken);
  assert(fetchedBundle.status === 200, 'Alice fetched Bob bundle from server');
  assert(fetchedBundle.body.preKey !== null, 'Bundle includes one-time pre-key');
  assert(fetchedBundle.body.registrationId === bobRegId, 'Registration ID matches');

  // Verify Bob's OTP key was consumed
  const bobKeyCount = await request<{ count: number }>('GET', '/api/keys/count', null, bobToken);
  assert(bobKeyCount.body.count === 9, 'One OTP key consumed (10 -> 9)');

  // Alice builds session with Bob using fetched bundle
  const bobAddress = new SignalProtocolAddress('bob', DEVICE_ID);
  const aliceSessionBuilder = new SessionBuilder(aliceStore as never, bobAddress);

  const deviceBundle: {
    registrationId: number;
    identityKey: ArrayBuffer;
    signedPreKey: { keyId: number; publicKey: ArrayBuffer; signature: ArrayBuffer };
    preKey?: { keyId: number; publicKey: ArrayBuffer };
  } = {
    registrationId: fetchedBundle.body.registrationId,
    identityKey: b642ab(fetchedBundle.body.identityKey),
    signedPreKey: {
      keyId: fetchedBundle.body.signedPreKey.keyId,
      publicKey: b642ab(fetchedBundle.body.signedPreKey.publicKey),
      signature: b642ab(fetchedBundle.body.signedPreKey.signature),
    },
  };
  if (fetchedBundle.body.preKey) {
    deviceBundle.preKey = {
      keyId: fetchedBundle.body.preKey.keyId,
      publicKey: b642ab(fetchedBundle.body.preKey.publicKey),
    };
  }

  await aliceSessionBuilder.processPreKey(deviceBundle);

  const aliceCipher = new SessionCipher(aliceStore as never, bobAddress);
  assert(await aliceCipher.hasOpenSession(), 'Alice has open session with Bob');

  // ===== PHASE 5: Encrypt & Send Message =====
  console.log('\n=== PHASE 5: Message Encryption & WebSocket Delivery ===');

  const plaintext = 'Hello Bob! This is an end-to-end encrypted message.';
  const plaintextBytes = new TextEncoder().encode(plaintext);
  const encrypted = await aliceCipher.encrypt(plaintextBytes.buffer);

  assert(encrypted.type === 3, 'First message is PreKeyWhisperMessage (type 3)');
  assert(typeof encrypted.body === 'string', 'Encrypted body is binary string');
  assert(encrypted.body !== plaintext, 'Encrypted body is NOT plaintext');

  // Base64 encode for transport (same as client code does)
  const transportBody = Buffer.from(encrypted.body!, 'binary').toString('base64');

  // Connect both users via WebSocket
  const aliceWs = await connectWS(aliceToken);
  const bobWs = await connectWS(bobToken);

  // Alice sends encrypted message to Bob via WebSocket
  interface ReceivedMessage { type: string; from: string; message: { type: number; body: string }; id: string; dbId: number }
  interface StoredAck { type: string; id: string; timestamp: string }
  interface DeliveredAck { type: string; id: string }

  const bobMsgPromise = waitForMessage<ReceivedMessage>(bobWs, 'message');
  const aliceStoredPromise = waitForMessage<StoredAck>(aliceWs, 'stored');

  aliceWs.send(JSON.stringify({
    type: 'message',
    to: 'bob',
    message: { type: encrypted.type, body: transportBody },
    id: 'test-msg-001',
  }));

  const bobReceived = await bobMsgPromise;
  const aliceStored = await aliceStoredPromise;

  assert(aliceStored.type === 'stored', 'Alice got store confirmation (store-then-send)');
  assert(aliceStored.id === 'test-msg-001', 'Store ACK has correct message ID');
  assert(bobReceived.from === 'alice', 'Bob received message from alice');
  assert(bobReceived.message.type === 3, 'Message type preserved through server');
  assert(bobReceived.message.body === transportBody, 'Ciphertext preserved exactly through server');
  assert(bobReceived.dbId !== undefined, 'Bob received dbId for ACK');

  // Bob sends ACK to confirm delivery -> Alice should get 'delivered'
  const aliceDeliveredPromise = waitForMessage<DeliveredAck>(aliceWs, 'delivered');
  bobWs.send(JSON.stringify({
    type: 'ack',
    dbId: bobReceived.dbId,
    from: bobReceived.from,
    originalId: bobReceived.id,
  }));
  const aliceDelivered = await aliceDeliveredPromise;
  assert(aliceDelivered.type === 'delivered', 'Alice got delivery confirmation after Bob ACK');
  assert(aliceDelivered.id === 'test-msg-001', 'Delivery ACK has correct message ID');

  // ===== PHASE 6: Decrypt Message =====
  console.log('\n=== PHASE 6: Message Decryption ===');

  // Bob decrypts the message
  const aliceAddress = new SignalProtocolAddress('alice', DEVICE_ID);
  const bobCipher = new SessionCipher(bobStore as never, aliceAddress);

  const receivedBinary = Buffer.from(bobReceived.message.body, 'base64').toString('binary');
  let decrypted: ArrayBuffer;
  if (bobReceived.message.type === 3) {
    decrypted = await bobCipher.decryptPreKeyWhisperMessage(receivedBinary, 'binary');
  } else {
    decrypted = await bobCipher.decryptWhisperMessage(receivedBinary, 'binary');
  }

  const decryptedText = new TextDecoder().decode(decrypted);
  assert(decryptedText === plaintext, `Decrypted text matches original: "${decryptedText}"`);

  // ===== PHASE 7: Double Ratchet (subsequent messages) =====
  console.log('\n=== PHASE 7: Double Ratchet - Subsequent Messages ===');

  // Bob replies to Alice (this creates the ratchet)
  const replyPlaintext = 'Hi Alice! Got your encrypted message!';
  const replyBytes = new TextEncoder().encode(replyPlaintext);
  const replyEncrypted = await bobCipher.encrypt(replyBytes.buffer);

  assert(replyEncrypted.type === 1, 'Reply is WhisperMessage (type 1) - ratchet established');

  const replyTransport = Buffer.from(replyEncrypted.body!, 'binary').toString('base64');

  const aliceMsgPromise = waitForMessage<ReceivedMessage>(aliceWs, 'message');
  bobWs.send(JSON.stringify({
    type: 'message',
    to: 'alice',
    message: { type: replyEncrypted.type, body: replyTransport },
    id: 'test-msg-002',
  }));

  const aliceReceived = await aliceMsgPromise;
  // ACK Bob's reply
  if (aliceReceived.dbId) {
    aliceWs.send(JSON.stringify({ type: 'ack', dbId: aliceReceived.dbId, from: aliceReceived.from, originalId: aliceReceived.id }));
  }
  const replyBinary = Buffer.from(aliceReceived.message.body, 'base64').toString('binary');
  const replyDecrypted = await aliceCipher.decryptWhisperMessage(replyBinary, 'binary');
  const replyDecryptedText = new TextDecoder().decode(replyDecrypted);

  assert(replyDecryptedText === replyPlaintext, `Bob's reply decrypted: "${replyDecryptedText}"`);

  // Alice sends another message (should also be type 1 now)
  const msg3Plaintext = 'Great, the Double Ratchet is working!';
  const msg3Bytes = new TextEncoder().encode(msg3Plaintext);
  const msg3Encrypted = await aliceCipher.encrypt(msg3Bytes.buffer);

  assert(msg3Encrypted.type === 1, 'Third message is also WhisperMessage (type 1)');

  const msg3Transport = Buffer.from(msg3Encrypted.body!, 'binary').toString('base64');
  const bobMsg3Promise = waitForMessage<ReceivedMessage>(bobWs, 'message');
  aliceWs.send(JSON.stringify({
    type: 'message',
    to: 'bob',
    message: { type: msg3Encrypted.type, body: msg3Transport },
    id: 'test-msg-003',
  }));

  const bobMsg3 = await bobMsg3Promise;
  // ACK msg3
  if (bobMsg3.dbId) {
    bobWs.send(JSON.stringify({ type: 'ack', dbId: bobMsg3.dbId, from: bobMsg3.from, originalId: bobMsg3.id }));
  }
  const msg3Binary = Buffer.from(bobMsg3.message.body, 'base64').toString('binary');
  const msg3Decrypted = await bobCipher.decryptWhisperMessage(msg3Binary, 'binary');
  const msg3DecryptedText = new TextDecoder().decode(msg3Decrypted);

  assert(msg3DecryptedText === msg3Plaintext, `Third message decrypted: "${msg3DecryptedText}"`);

  // Wait briefly for ACKs to be processed
  await new Promise(r => setTimeout(r, 200));

  // ===== PHASE 8: Offline Message Delivery =====
  console.log('\n=== PHASE 8: Offline Message Storage & Retrieval ===');

  // Disconnect Bob
  bobWs.close();
  await new Promise(r => setTimeout(r, 500));

  // Alice sends while Bob is offline
  const offlinePlaintext = 'Bob, are you there? This should be stored.';
  const offlineBytes = new TextEncoder().encode(offlinePlaintext);
  const offlineEncrypted = await aliceCipher.encrypt(offlineBytes.buffer);
  const offlineTransport = Buffer.from(offlineEncrypted.body!, 'binary').toString('base64');

  const storedPromise = waitForMessage<StoredAck>(aliceWs, 'stored');
  aliceWs.send(JSON.stringify({
    type: 'message',
    to: 'bob',
    message: { type: offlineEncrypted.type, body: offlineTransport },
    id: 'test-msg-004',
  }));

  const storedAck = await storedPromise;
  assert(storedAck.type === 'stored', 'Server stored message for offline Bob');

  // Bob comes back online and fetches pending messages
  interface PendingMsg { from: string; message: { type: number; body: string } }
  const pending = await request<PendingMsg[]>('GET', '/api/messages/pending', null, bobToken);
  assert(pending.body.length === 1, `One pending message for Bob`);
  assert(pending.body[0]!.from === 'alice', 'Pending message from alice');
  assert(pending.body[0]!.message.body === offlineTransport, 'Stored ciphertext matches');

  // Bob decrypts the offline message
  const offlineBinary = Buffer.from(pending.body[0]!.message.body, 'base64').toString('binary');
  const offlineDecrypted = await bobCipher.decryptWhisperMessage(offlineBinary, 'binary');
  const offlineDecryptedText = new TextDecoder().decode(offlineDecrypted);

  assert(offlineDecryptedText === offlinePlaintext, `Offline message decrypted: "${offlineDecryptedText}"`);

  // ===== PHASE 9: Verify Server Never Sees Plaintext =====
  console.log('\n=== PHASE 9: Zero-Knowledge Verification ===');

  // Query the database directly to verify stored message is ciphertext
  const Database = require('better-sqlite3');
  const dbPath = process.env.DB_PATH || './signal-web.db';
  const dbInst = new Database(dbPath);
  const storedMsg = dbInst.prepare('SELECT body FROM messages ORDER BY id DESC LIMIT 1').get() as { body: string } | undefined;
  if (storedMsg) {
    assert(storedMsg.body !== offlinePlaintext, 'DB body is NOT plaintext');
    assert(storedMsg.body === offlineTransport, 'DB body matches encrypted transport format');
  }
  dbInst.close();

  // ===== PHASE 10: Forward Secrecy Verification =====
  console.log('\n=== PHASE 10: Forward Secrecy Properties ===');

  // Each message should have unique ciphertext even with same plaintext
  const repeat1 = await aliceCipher.encrypt(new TextEncoder().encode('same message').buffer);
  const repeat2 = await aliceCipher.encrypt(new TextEncoder().encode('same message').buffer);
  assert(repeat1.body !== repeat2.body, 'Same plaintext produces different ciphertext (unique message keys)');

  // Cleanup
  aliceWs.close();

  // ===== RESULTS =====
  console.log('\n' + '='.repeat(50));
  console.log(`RESULTS: ${passed} passed, ${failed} failed out of ${passed + failed} tests`);
  console.log('='.repeat(50));

  if (failed > 0) {
    process.exit(1);
  }
}

// Wait for server to be ready
setTimeout(() => {
  runTest().catch(err => {
    console.error('\nTEST CRASHED:', err);
    process.exit(1);
  });
}, 1000);

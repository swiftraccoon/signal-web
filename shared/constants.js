const WS_MSG_TYPE = {
  MESSAGE: 'message',
  DELIVERED: 'delivered',
  STORED: 'stored',
  TYPING: 'typing',
  PREKEY_LOW: 'prekey_low',
  ERROR: 'error',
  READ_RECEIPT: 'read_receipt',
  PRESENCE: 'presence',
  DISAPPEARING_TIMER: 'disappearing_timer',
  ACK: 'ack',
};

const SIGNAL_MSG_TYPE = {
  WHISPER: 1,
  PREKEY: 3,
};

const PREKEY_LOW_THRESHOLD = 10;
const PREKEY_BATCH_SIZE = 100;
const MAX_WS_MESSAGE_SIZE = 64 * 1024; // 64KB

const DISAPPEARING_TIMERS = {
  OFF: 0,
  THIRTY_SEC: 30,
  FIVE_MIN: 300,
  ONE_HOUR: 3600,
  ONE_DAY: 86400,
  SEVEN_DAYS: 604800,
};

module.exports = { WS_MSG_TYPE, SIGNAL_MSG_TYPE, PREKEY_LOW_THRESHOLD, PREKEY_BATCH_SIZE, MAX_WS_MESSAGE_SIZE, DISAPPEARING_TIMERS };

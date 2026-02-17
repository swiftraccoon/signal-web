export const WS_MSG_TYPE = {
  MESSAGE: 'message',
  DELIVERED: 'delivered',
  STORED: 'stored',
  PREKEY_LOW: 'prekey_low',
  PREKEY_STALE: 'prekey_stale',
  ERROR: 'error',
  DISAPPEARING_TIMER: 'disappearing_timer',
  ACK: 'ack',
} as const;

export type WsMsgType = (typeof WS_MSG_TYPE)[keyof typeof WS_MSG_TYPE];

export const SIGNAL_MSG_TYPE = {
  WHISPER: 1,
  PREKEY: 3,
} as const;

export type SignalMsgType = (typeof SIGNAL_MSG_TYPE)[keyof typeof SIGNAL_MSG_TYPE];

export const PREKEY_LOW_THRESHOLD = 10;
export const PREKEY_BATCH_SIZE = 100;
export const MAX_WS_MESSAGE_SIZE = 64 * 1024; // 64KB

export const DISAPPEARING_TIMERS = {
  OFF: 0,
  THIRTY_SEC: 30,
  FIVE_MIN: 300,
  ONE_HOUR: 3600,
  ONE_DAY: 86400,
  SEVEN_DAYS: 604800,
} as const;

export type DisappearingTimer = (typeof DISAPPEARING_TIMERS)[keyof typeof DISAPPEARING_TIMERS];

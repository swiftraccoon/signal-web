import crypto from 'crypto';
import type { WsTicketEntry } from '../../shared/types';

// One-time WS connection tickets (avoids JWT in URL query string)
const wsTickets = new Map<string, WsTicketEntry>();
const WS_TICKET_TTL_MS = 30000; // 30 seconds

// Periodic cleanup of expired tickets (prevents memory leak)
setInterval(() => {
  const now = Date.now();
  for (const [t, v] of wsTickets) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-argument -- Map<string, WsTicketEntry> iteration; type not resolved by project service
    if (v.expiresAt < now) wsTickets.delete(t);
  }
}, WS_TICKET_TTL_MS);

function createWsTicket(userId: number, username: string): string {
  const ticket = crypto.randomBytes(32).toString('hex');
  wsTickets.set(ticket, {
    userId,
    username,
    expiresAt: Date.now() + WS_TICKET_TTL_MS,
  });
  return ticket;
}

function consumeWsTicket(ticket: string): WsTicketEntry | null {
  const entry = wsTickets.get(ticket);
  if (!entry) return null;
  wsTickets.delete(ticket); // one-time use
  if (entry.expiresAt < Date.now()) return null; // expired
  return entry;
}

export { createWsTicket, consumeWsTicket };

// Cached sender certificate management.
// Fetches from server on first use, refreshes when approaching expiry.

import { api } from '../api';
import type { SenderCertificate } from '../../../shared/types';

let cachedCert: SenderCertificate | null = null;
let certExpiry = 0; // unix epoch seconds

const REFRESH_BUFFER_SECONDS = 3600; // refresh 1 hour before expiry

export async function getSenderCertificate(): Promise<SenderCertificate> {
  const now = Math.floor(Date.now() / 1000);

  if (cachedCert && certExpiry > now + REFRESH_BUFFER_SECONDS) {
    return cachedCert;
  }

  // Fetch fresh certificate
  cachedCert = await api.getSenderCert();

  // Parse expiry from payload
  try {
    const payload = JSON.parse(atob(cachedCert.payload)) as { expires: number };
    certExpiry = payload.expires;
  } catch {
    // If we can't parse, assume 23h expiry from now
    certExpiry = now + 23 * 3600;
  }

  return cachedCert;
}

export function clearSenderCertCache(): void {
  cachedCert = null;
  certExpiry = 0;
}

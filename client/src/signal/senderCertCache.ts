// Cached sender certificate management.
// Fetches from server on first use, refreshes when approaching expiry.
// CRIT-4 fix: verifies Ed25519 signature before caching.

import { api } from '../api';
import { verifySenderCertificate } from './sealed';
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
  const cert = await api.getSenderCert();

  // CRIT-4 fix: verify the signature before trusting the cert
  const verified = await verifySenderCertificate(cert);
  if (!verified) {
    throw new Error('Server returned an invalid or unverifiable sender certificate');
  }

  cachedCert = cert;
  certExpiry = verified.expires;

  return cachedCert;
}

export function clearSenderCertCache(): void {
  cachedCert = null;
  certExpiry = 0;
}

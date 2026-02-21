import type {
  ApiUser, AuthResponse, PreKeyBundleUpload, PreKeyBundleResponse,
  PreKeyPublic, KeyCountResponse, PendingMessage, PendingSealedMessage,
  WsTicketResponse, SenderCertificate, ServerKeyResponse, KeyLogEntry,
} from '../../shared/types';

// Token is kept in memory only -- never persisted to localStorage.
// This prevents XSS-based token theft. Users re-authenticate on page
// reload, which also re-derives the storage encryption key.
let token: string | null = null;
let currentUser: ApiUser | null = null;

function setToken(t: string | null): void {
  token = t;
}

function getToken(): string | null {
  return token;
}

function setCurrentUser(u: ApiUser | null): void {
  currentUser = u;
}

function getCurrentUser(): ApiUser | null {
  return currentUser;
}

async function fetchWithRefresh(url: string, options: RequestInit): Promise<Response> {
  let res = await fetch(url, options);

  if (res.status === 401 && token) {
    // Attempt token refresh — cookie sent automatically
    const refreshRes = await fetch('/api/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
    });

    if (refreshRes.ok) {
      const data = await refreshRes.json() as { token: string };
      token = data.token;

      // Retry original request with new token
      const newHeaders = new Headers(options.headers);
      newHeaders.set('Authorization', `Bearer ${token}`);
      res = await fetch(url, { ...options, headers: newHeaders });
    }
  }

  return res;
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetchWithRefresh(path, {
    ...options,
    credentials: 'same-origin',
    headers: { ...headers, ...(options.headers as Record<string, string> | undefined) },
  });

  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment -- Response.json() returns Promise<any>
  const data = await res.json();

  if (!res.ok) {
    throw new Error((data as { error?: string }).error || `Request failed: ${res.status}`);
  }

  return data as T;
}

const api = {
  register: (username: string, password: string) =>
    request<AuthResponse>('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),

  login: (username: string, password: string) =>
    request<AuthResponse>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),

  uploadBundle: (bundle: PreKeyBundleUpload) =>
    request<{ success: boolean }>('/api/keys/bundle', {
      method: 'PUT',
      body: JSON.stringify(bundle),
    }),

  getBundle: (userId: number) =>
    request<PreKeyBundleResponse>(`/api/keys/bundle/${userId}`),

  replenishKeys: (preKeys: PreKeyPublic[]) =>
    request<{ success: boolean; remaining: number }>('/api/keys/replenish', {
      method: 'POST',
      body: JSON.stringify({ preKeys }),
    }),

  getKeyCount: () =>
    request<KeyCountResponse>('/api/keys/count'),

  searchUsers: (search: string) =>
    request<ApiUser[]>(`/api/users?search=${encodeURIComponent(search)}`),

  getPendingMessages: () =>
    request<PendingMessage[]>('/api/messages/pending'),

  getPendingSealedMessages: () =>
    request<PendingSealedMessage[]>('/api/messages/pending-sealed'),

  deleteAccount: (password: string) =>
    request<{ success: boolean }>('/api/auth/account', {
      method: 'DELETE',
      body: JSON.stringify({ password }),
    }),

  changePassword: (currentPassword: string, newPassword: string) =>
    request<{ success: boolean }>('/api/auth/password', {
      method: 'PUT',
      body: JSON.stringify({ currentPassword, newPassword }),
    }),

  getWsTicket: () =>
    request<WsTicketResponse>('/api/auth/ws-ticket', { method: 'POST' }),

  getSenderCert: () =>
    request<SenderCertificate>('/api/keys/sender-cert', { method: 'POST' }),

  getServerKey: () =>
    request<ServerKeyResponse>('/api/keys/server-key'),

  getKeyLog: (userId: number) =>
    request<KeyLogEntry[]>(`/api/keys/key-log/${userId}`),

  getKeyLogRange: (after: number, limit = 100) =>
    request<KeyLogEntry[]>(`/api/keys/key-log?after=${after}&limit=${limit}`),
};

export { api, setToken, getToken, setCurrentUser, getCurrentUser };

// Token is kept in memory only -- never persisted to localStorage.
// This prevents XSS-based token theft. Users re-authenticate on page
// reload, which also re-derives the storage encryption key.
let token = null;
let currentUser = null;

function setToken(t) {
  token = t;
}

function getToken() {
  return token;
}

function setCurrentUser(u) {
  currentUser = u;
}

function getCurrentUser() {
  return currentUser;
}

async function request(path, options = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetch(path, {
    ...options,
    headers: { ...headers, ...options.headers },
  });

  const data = await res.json();

  if (!res.ok) {
    throw new Error(data.error || `Request failed: ${res.status}`);
  }

  return data;
}

const api = {
  register: (username, password) =>
    request('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),

  login: (username, password) =>
    request('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),

  uploadBundle: (bundle) =>
    request('/api/keys/bundle', {
      method: 'PUT',
      body: JSON.stringify(bundle),
    }),

  getBundle: (userId) =>
    request(`/api/keys/bundle/${userId}`),

  replenishKeys: (preKeys) =>
    request('/api/keys/replenish', {
      method: 'POST',
      body: JSON.stringify({ preKeys }),
    }),

  getKeyCount: () =>
    request('/api/keys/count'),

  searchUsers: (search) =>
    request(`/api/users?search=${encodeURIComponent(search)}`),

  getPendingMessages: () =>
    request('/api/messages/pending'),

  deleteAccount: (password) =>
    request('/api/auth/account', {
      method: 'DELETE',
      body: JSON.stringify({ password }),
    }),

  changePassword: (currentPassword, newPassword) =>
    request('/api/auth/password', {
      method: 'PUT',
      body: JSON.stringify({ currentPassword, newPassword }),
    }),

  getWsTicket: () =>
    request('/api/auth/ws-ticket', { method: 'POST' }),
};

export { api, setToken, getToken, setCurrentUser, getCurrentUser };

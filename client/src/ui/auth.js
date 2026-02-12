import { api, setToken } from '../api.js';
import { showToast } from './notifications.js';

let isRegisterMode = false;
let onAuthSuccess = null;

export function initAuth(callback) {
  onAuthSuccess = callback;

  const form = document.getElementById('auth-form');
  const submitBtn = document.getElementById('auth-submit');
  const switchLink = document.getElementById('auth-switch');

  switchLink.addEventListener('click', (e) => {
    e.preventDefault();
    isRegisterMode = !isRegisterMode;
    submitBtn.textContent = isRegisterMode ? 'Register' : 'Log In';
    switchLink.textContent = isRegisterMode ? 'Log In' : 'Register';
    switchLink.previousSibling.textContent = isRegisterMode
      ? 'Already have an account? '
      : "Don't have an account? ";
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('auth-username').value.trim();
    const password = document.getElementById('auth-password').value;

    if (!username || !password) return;

    submitBtn.disabled = true;
    try {
      const result = isRegisterMode
        ? await api.register(username, password)
        : await api.login(username, password);

      setToken(result.token);
      localStorage.setItem('user', JSON.stringify(result.user));
      // Pass password to callback for storage encryption key derivation
      onAuthSuccess(result.user, isRegisterMode, password);
      // Clear password from DOM immediately
      document.getElementById('auth-password').value = '';
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      submitBtn.disabled = false;
    }
  });
}

export function showAuth() {
  document.getElementById('auth-view').classList.remove('hidden');
  document.getElementById('chat-view').classList.add('hidden');
}

export function hideAuth() {
  document.getElementById('auth-view').classList.add('hidden');
  document.getElementById('chat-view').classList.remove('hidden');
}

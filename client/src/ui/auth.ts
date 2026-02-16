import { api, setToken, setRefreshToken, setCurrentUser } from '../api';
import { showToast } from './notifications';
import type { ApiUser } from '../../../shared/types';

let isRegisterMode = false;
let onAuthSuccess: ((user: ApiUser, isNew: boolean, password: string) => void) | null = null;

export function initAuth(callback: (user: ApiUser, isNew: boolean, password: string) => void): void {
  onAuthSuccess = callback;

  const form = document.getElementById('auth-form') as HTMLFormElement;
  const submitBtn = document.getElementById('auth-submit') as HTMLButtonElement;
  const switchLink = document.getElementById('auth-switch') as HTMLAnchorElement;

  switchLink.addEventListener('click', (e) => {
    e.preventDefault();
    isRegisterMode = !isRegisterMode;
    submitBtn.textContent = isRegisterMode ? 'Register' : 'Log In';
    switchLink.textContent = isRegisterMode ? 'Log In' : 'Register';
    switchLink.previousSibling!.textContent = isRegisterMode
      ? 'Already have an account? '
      : "Don't have an account? ";
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = (document.getElementById('auth-username') as HTMLInputElement).value.trim();
    const password = (document.getElementById('auth-password') as HTMLInputElement).value;

    if (!username || !password) return;

    submitBtn.disabled = true;
    try {
      const result = isRegisterMode
        ? await api.register(username, password)
        : await api.login(username, password);

      setToken(result.token);
      setRefreshToken(result.refreshToken);
      setCurrentUser(result.user);
      // Pass password to callback for storage encryption key derivation
      onAuthSuccess!(result.user, isRegisterMode, password);
      // Clear password from DOM immediately
      (document.getElementById('auth-password') as HTMLInputElement).value = '';
    } catch (err) {
      showToast((err as Error).message, 'error');
    } finally {
      submitBtn.disabled = false;
    }
  });
}

export function showAuth(): void {
  document.getElementById('auth-view')!.classList.remove('hidden');
  document.getElementById('chat-view')!.classList.add('hidden');
}

export function hideAuth(): void {
  document.getElementById('auth-view')!.classList.add('hidden');
  document.getElementById('chat-view')!.classList.remove('hidden');
}

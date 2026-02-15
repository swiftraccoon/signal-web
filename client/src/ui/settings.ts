import { api, getCurrentUser } from '../api';
import { showToast } from './notifications';
import { requestNotificationPermission, setNotificationsEnabled, getNotificationsEnabled } from './notifications';
import { reEncryptAllStores } from '../storage/indexeddb';

let onAccountDeleted: (() => void) | null = null;

export function initSettings(deleteCallback: () => void): void {
  onAccountDeleted = deleteCallback;

  // Settings modal open/close
  const settingsBtn = document.getElementById('settings-btn')!;
  const settingsModal = document.getElementById('settings-modal')!;

  settingsBtn.addEventListener('click', () => {
    settingsModal.classList.remove('hidden');
    // Sync notification toggle state
    (document.getElementById('notifications-toggle') as HTMLInputElement).checked = getNotificationsEnabled();
  });

  // Close buttons for all modals
  document.querySelectorAll('.modal-close, .modal-cancel').forEach(btn => {
    btn.addEventListener('click', () => {
      btn.closest('.modal')!.classList.add('hidden');
    });
  });

  // Close modal on backdrop click
  document.querySelectorAll('.modal-backdrop').forEach(backdrop => {
    backdrop.addEventListener('click', () => {
      backdrop.closest('.modal')!.classList.add('hidden');
    });
  });

  // Escape key closes modals
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      document.querySelectorAll('.modal:not(.hidden)').forEach(modal => {
        modal.classList.add('hidden');
      });
    }
  });

  // Change password form
  document.getElementById('change-password-form')!.addEventListener('submit', async (e) => {
    e.preventDefault();
    const currentPw = (document.getElementById('current-password') as HTMLInputElement).value;
    const newPw = (document.getElementById('new-password') as HTMLInputElement).value;
    const confirmPw = (document.getElementById('confirm-password') as HTMLInputElement).value;

    if (newPw !== confirmPw) {
      showToast('Passwords do not match', 'error');
      return;
    }

    if (newPw.length < 12) {
      showToast('Password must be at least 12 characters', 'error');
      return;
    }
    if (!/[a-z]/.test(newPw) || !/[A-Z]/.test(newPw) || !/[0-9]/.test(newPw)) {
      showToast('Password must include lowercase, uppercase, and a number', 'error');
      return;
    }

    try {
      await api.changePassword(currentPw, newPw);
      // C1: Re-encrypt local IndexedDB with new password-derived key
      const user = getCurrentUser();
      if (user) {
        showToast('Re-encrypting local data...', 'info');
        await reEncryptAllStores(currentPw, newPw, user.username);
      }
      showToast('Password changed successfully', 'success');
      (e.target as HTMLFormElement).reset();
    } catch (err) {
      showToast((err as Error).message, 'error');
    }
  });

  // Notification toggle
  document.getElementById('notifications-toggle')!.addEventListener('change', async (e) => {
    const target = e.target as HTMLInputElement;
    if (target.checked) {
      const granted = await requestNotificationPermission();
      if (!granted) {
        target.checked = false;
        showToast('Notification permission denied', 'error');
        return;
      }
    }
    setNotificationsEnabled(target.checked);
  });

  // Delete account flow
  document.getElementById('delete-account-btn')!.addEventListener('click', () => {
    settingsModal.classList.add('hidden');
    document.getElementById('delete-modal')!.classList.remove('hidden');
  });

  document.getElementById('delete-account-form')!.addEventListener('submit', async (e) => {
    e.preventDefault();
    const password = (document.getElementById('delete-password') as HTMLInputElement).value;

    try {
      await api.deleteAccount(password);
      document.getElementById('delete-modal')!.classList.add('hidden');
      showToast('Account deleted', 'success');
      if (onAccountDeleted) onAccountDeleted();
    } catch (err) {
      showToast((err as Error).message, 'error');
    }
  });
}

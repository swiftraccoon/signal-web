import { api } from '../api.js';
import { showToast } from './notifications.js';
import { requestNotificationPermission, setNotificationsEnabled, getNotificationsEnabled } from './notifications.js';

let onAccountDeleted = null;

export function initSettings(deleteCallback) {
  onAccountDeleted = deleteCallback;

  // Settings modal open/close
  const settingsBtn = document.getElementById('settings-btn');
  const settingsModal = document.getElementById('settings-modal');

  settingsBtn.addEventListener('click', () => {
    settingsModal.classList.remove('hidden');
    // Sync notification toggle state
    document.getElementById('notifications-toggle').checked = getNotificationsEnabled();
  });

  // Close buttons for all modals
  document.querySelectorAll('.modal-close, .modal-cancel').forEach(btn => {
    btn.addEventListener('click', () => {
      btn.closest('.modal').classList.add('hidden');
    });
  });

  // Close modal on backdrop click
  document.querySelectorAll('.modal-backdrop').forEach(backdrop => {
    backdrop.addEventListener('click', () => {
      backdrop.closest('.modal').classList.add('hidden');
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
  document.getElementById('change-password-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const currentPw = document.getElementById('current-password').value;
    const newPw = document.getElementById('new-password').value;
    const confirmPw = document.getElementById('confirm-password').value;

    if (newPw !== confirmPw) {
      showToast('Passwords do not match', 'error');
      return;
    }

    if (newPw.length < 12) {
      showToast('Password must be at least 12 characters', 'error');
      return;
    }

    try {
      await api.changePassword(currentPw, newPw);
      showToast('Password changed successfully', 'success');
      e.target.reset();
    } catch (err) {
      showToast(err.message, 'error');
    }
  });

  // Notification toggle
  document.getElementById('notifications-toggle').addEventListener('change', async (e) => {
    if (e.target.checked) {
      const granted = await requestNotificationPermission();
      if (!granted) {
        e.target.checked = false;
        showToast('Notification permission denied', 'error');
        return;
      }
    }
    setNotificationsEnabled(e.target.checked);
  });

  // Delete account flow
  document.getElementById('delete-account-btn').addEventListener('click', () => {
    settingsModal.classList.add('hidden');
    document.getElementById('delete-modal').classList.remove('hidden');
  });

  document.getElementById('delete-account-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const password = document.getElementById('delete-password').value;

    try {
      await api.deleteAccount(password);
      document.getElementById('delete-modal').classList.add('hidden');
      showToast('Account deleted', 'success');
      if (onAccountDeleted) onAccountDeleted();
    } catch (err) {
      showToast(err.message, 'error');
    }
  });
}

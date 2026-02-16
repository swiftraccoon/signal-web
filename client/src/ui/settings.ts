import { api, getCurrentUser } from '../api';
import { showToast } from './notifications';
import { requestNotificationPermission, setNotificationsEnabled, getNotificationsEnabled } from './notifications';
import { reEncryptAllStores } from '../storage/indexeddb';
import { exportKeys, importKeys } from '../signal/store';

let onAccountDeleted: (() => void) | null = null;

function setLoading(btn: HTMLButtonElement, loading: boolean, originalText: string): void {
  if (loading) {
    btn.classList.add('btn-loading');
    btn.textContent = '';
    const spinner = document.createElement('span');
    spinner.className = 'spinner';
    btn.appendChild(spinner);
  } else {
    btn.classList.remove('btn-loading');
    btn.textContent = originalText;
  }
}

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
  const changePwForm = document.getElementById('change-password-form') as HTMLFormElement;
  const changePwBtn = changePwForm.querySelector('button[type="submit"]') as HTMLButtonElement;

  changePwForm.addEventListener('submit', async (e) => {
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

    setLoading(changePwBtn, true, 'Change Password');
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
    } finally {
      setLoading(changePwBtn, false, 'Change Password');
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

  // Key Backup: Export Keys
  document.getElementById('export-keys-btn')!.addEventListener('click', async () => {
    const user = getCurrentUser();
    if (!user) {
      showToast('Not logged in', 'error');
      return;
    }

    const password = window.prompt('Enter a password to encrypt your key backup:');
    if (!password) return;

    if (password.length < 8) {
      showToast('Backup password must be at least 8 characters', 'error');
      return;
    }

    const confirmPassword = window.prompt('Confirm backup password:');
    if (password !== confirmPassword) {
      showToast('Passwords do not match', 'error');
      return;
    }

    try {
      const blob = await exportKeys(password, user.username);
      const filename = `signal-web-keys-${user.username}-${new Date().toISOString().slice(0, 10)}.json`;
      const file = new Blob([JSON.stringify({ backup: blob })], { type: 'application/json' });
      const url = URL.createObjectURL(file);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showToast('Keys exported successfully', 'success');
    } catch (err) {
      showToast(`Export failed: ${(err as Error).message}`, 'error');
    }
  });

  // Key Backup: Import Keys
  const importFileInput = document.getElementById('import-keys-file') as HTMLInputElement;

  document.getElementById('import-keys-btn')!.addEventListener('click', () => {
    importFileInput.value = '';
    importFileInput.click();
  });

  importFileInput.addEventListener('change', async () => {
    const file = importFileInput.files?.[0];
    if (!file) return;

    const user = getCurrentUser();
    if (!user) {
      showToast('Not logged in', 'error');
      return;
    }

    const password = window.prompt('Enter the password used to encrypt this backup:');
    if (!password) return;

    try {
      const text = await file.text();
      let parsed: { backup: string };
      try {
        parsed = JSON.parse(text) as { backup: string };
      } catch {
        throw new Error('Invalid backup file format');
      }

      if (!parsed.backup) {
        throw new Error('Invalid backup file: missing backup data');
      }

      await importKeys(parsed.backup, password, user.username);
      showToast('Keys imported successfully. Reload the page to use restored keys.', 'success');
    } catch (err) {
      showToast(`Import failed: ${(err as Error).message}`, 'error');
    }
  });
}

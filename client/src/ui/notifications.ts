const container = document.getElementById('notifications')!;

let notificationsEnabled = false;

// Runtime validation of toast type to prevent CSS class injection
const ALLOWED_TOAST_TYPES = new Set(['info', 'success', 'error', 'warning']);

export function showToast(message: string, type = 'info'): void {
  const safeType = ALLOWED_TOAST_TYPES.has(type) ? type : 'info';
  const toast = document.createElement('div');
  toast.className = `toast ${safeType}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 3000);
}

export async function requestNotificationPermission(): Promise<boolean> {
  if (!('Notification' in window)) return false;
  if (Notification.permission === 'granted') {
    notificationsEnabled = true;
    return true;
  }
  if (Notification.permission === 'denied') return false;

  const result = await Notification.requestPermission();
  notificationsEnabled = result === 'granted';
  return notificationsEnabled;
}

export function setNotificationsEnabled(enabled: boolean): void {
  notificationsEnabled = enabled;
  localStorage.setItem('notificationsEnabled', enabled ? '1' : '0');
}

export function getNotificationsEnabled(): boolean {
  const stored = localStorage.getItem('notificationsEnabled');
  if (stored !== null) {
    notificationsEnabled = stored === '1';
  }
  return notificationsEnabled;
}

export function showDesktopNotification(from: string, _text: string): void {
  if (!notificationsEnabled) return;
  if (!('Notification' in window)) return;
  if (Notification.permission !== 'granted') return;

  // Don't show if the page is visible and focused
  if (document.visibilityState === 'visible' && document.hasFocus()) return;

  // Don't expose message content or contact identity in desktop notifications
  // Use a simple hash of username for the tag (so same-sender notifications
  // replace each other without leaking the raw username to other apps)
  let tagHash = 0;
  for (let i = 0; i < from.length; i++) {
    tagHash = ((tagHash << 5) - tagHash + from.charCodeAt(i)) | 0;
  }
  const notification = new Notification('Signal Web', {
    body: 'New message',
    icon: undefined, // no custom icon
    tag: `sw-${tagHash.toString(36)}`, // obfuscated tag for same-sender dedup
    requireInteraction: false,
  });

  notification.onclick = () => {
    window.focus();
    notification.close();
  };

  // Auto-close after 5 seconds
  setTimeout(() => notification.close(), 5000);
}

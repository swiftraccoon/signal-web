const container = document.getElementById('notifications');

let notificationsEnabled = false;

export function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 3000);
}

export async function requestNotificationPermission() {
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

export function setNotificationsEnabled(enabled) {
  notificationsEnabled = enabled;
  localStorage.setItem('notificationsEnabled', enabled ? '1' : '0');
}

export function getNotificationsEnabled() {
  const stored = localStorage.getItem('notificationsEnabled');
  if (stored !== null) {
    notificationsEnabled = stored === '1';
  }
  return notificationsEnabled;
}

export function showDesktopNotification(from, text) {
  if (!notificationsEnabled) return;
  if (!('Notification' in window)) return;
  if (Notification.permission !== 'granted') return;

  // Don't show if the page is visible and focused
  if (document.visibilityState === 'visible' && document.hasFocus()) return;

  // Don't expose message content in desktop notifications for privacy
  const notification = new Notification('Signal Web', {
    body: 'New message',
    icon: undefined, // no custom icon
    tag: `signal-web-${from}`, // replace existing notification from same user
    requireInteraction: false,
  });

  notification.onclick = () => {
    window.focus();
    notification.close();
  };

  // Auto-close after 5 seconds
  setTimeout(() => notification.close(), 5000);
}

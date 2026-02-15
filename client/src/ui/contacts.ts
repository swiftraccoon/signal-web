import { api } from '../api';
import { STORES, put, putDebounced, getAll } from '../storage/indexeddb';
import type { ApiUser, Contact } from '../../../shared/types';

let contacts: Record<string, Contact> = {};
let activeContact: string | null = null;
let onSelectContact: ((username: string, contact?: Contact) => void) | null = null;
let onlineUsers = new Set<number>();
let contactRenderScheduled = false;

export function initContacts(callback: (username: string) => void): void {
  onSelectContact = callback;

  const searchInput = document.getElementById('user-search') as HTMLInputElement;
  const searchResults = document.getElementById('search-results')!;
  let searchTimeout: ReturnType<typeof setTimeout> | null = null;

  searchInput.addEventListener('input', () => {
    if (searchTimeout) clearTimeout(searchTimeout);
    const query = searchInput.value.trim();
    if (query.length < 2) {
      searchResults.classList.add('hidden');
      return;
    }
    searchTimeout = setTimeout(async () => {
      try {
        const users = await api.searchUsers(query);
        renderSearchResults(users, searchResults);
      } catch {
        searchResults.classList.add('hidden');
      }
    }, 300);
  });

  document.addEventListener('click', (e) => {
    if (!searchResults.contains(e.target as Node) && e.target !== searchInput) {
      searchResults.classList.add('hidden');
    }
  });
}

function renderSearchResults(users: ApiUser[], container: HTMLElement): void {
  while (container.firstChild) container.removeChild(container.firstChild);
  if (users.length === 0) {
    container.classList.add('hidden');
    return;
  }
  for (const user of users) {
    const item = document.createElement('div');
    item.className = 'search-result-item';
    item.textContent = user.username;
    item.addEventListener('click', () => {
      addContact(user);
      selectContact(user.username);
      container.classList.add('hidden');
      (document.getElementById('user-search') as HTMLInputElement).value = '';
    });
    container.appendChild(item);
  }
  container.classList.remove('hidden');
}

export async function loadContacts(): Promise<void> {
  const { keys, values } = await getAll(STORES.CONTACTS);
  for (let i = 0; i < keys.length; i++) {
    contacts[keys[i] as string] = values[i] as Contact;
  }
  renderContacts();
}

export function addContact(user: ApiUser): void {
  if (!contacts[user.username]) {
    contacts[user.username] = {
      id: user.id,
      username: user.username,
      unread: 0,
      lastMessage: '',
      lastTime: '',
    };
    put(STORES.CONTACTS, user.username, contacts[user.username]);
    scheduleContactRender();
  }
}

export function selectContact(username: string): void {
  activeContact = username;
  if (contacts[username]) {
    contacts[username]!.unread = 0;
    putDebounced(STORES.CONTACTS, username, contacts[username]);
  }
  renderContacts(); // immediate for active selection
  if (onSelectContact) onSelectContact(username, contacts[username]);
}

export function getActiveContact(): string | null {
  return activeContact;
}

export function getContactInfo(username: string): Contact | undefined {
  return contacts[username];
}

export function incrementUnread(username: string): void {
  if (contacts[username]) {
    contacts[username]!.unread++;
    putDebounced(STORES.CONTACTS, username, contacts[username]);
    scheduleContactRender();
  }
}

export function updateLastMessage(username: string, text: string, time: string): void {
  if (contacts[username]) {
    contacts[username]!.lastMessage = text;
    contacts[username]!.lastTime = time || new Date().toISOString();
    putDebounced(STORES.CONTACTS, username, contacts[username]);
    scheduleContactRender();
  }
}

// Presence management
export function setUserOnline(userId: number): void {
  onlineUsers.add(userId);
  scheduleContactRender();
}

export function setUserOffline(userId: number): void {
  onlineUsers.delete(userId);
  scheduleContactRender();
}

export function setOnlineUsers(userIds: number[]): void {
  onlineUsers = new Set(userIds);
  scheduleContactRender();
}

export function isContactOnline(username: string): boolean {
  const contact = contacts[username];
  if (!contact) return false;
  return onlineUsers.has(contact.id);
}

function scheduleContactRender(): void {
  if (contactRenderScheduled) return;
  contactRenderScheduled = true;
  requestAnimationFrame(() => {
    contactRenderScheduled = false;
    renderContacts();
  });
}

function renderContacts(): void {
  const list = document.getElementById('contacts-list')!;
  while (list.firstChild) list.removeChild(list.firstChild);

  // Sort contacts: those with most recent messages first
  const sorted = Object.values(contacts).sort((a, b) => {
    if (a.lastTime && b.lastTime) {
      return new Date(b.lastTime).getTime() - new Date(a.lastTime).getTime();
    }
    if (a.lastTime) return -1;
    if (b.lastTime) return 1;
    return a.username.localeCompare(b.username);
  });

  for (const contact of sorted) {
    const item = document.createElement('div');
    item.className = `contact-item${contact.username === activeContact ? ' active' : ''}`;
    item.addEventListener('click', () => selectContact(contact.username));

    const avatar = document.createElement('div');
    avatar.className = 'contact-avatar';
    avatar.textContent = contact.username[0]!.toUpperCase();

    // Online dot
    if (onlineUsers.has(contact.id)) {
      const dot = document.createElement('div');
      dot.className = 'online-dot';
      avatar.appendChild(dot);
    }

    const info = document.createElement('div');
    info.className = 'contact-info';

    const name = document.createElement('div');
    name.className = 'contact-name';
    name.textContent = contact.username;

    const preview = document.createElement('div');
    preview.className = 'contact-preview';
    preview.textContent = contact.lastMessage || '';

    info.appendChild(name);
    info.appendChild(preview);

    item.appendChild(avatar);
    item.appendChild(info);

    // Meta column (time + badge)
    const meta = document.createElement('div');
    meta.className = 'contact-meta';

    if (contact.lastTime) {
      const timeEl = document.createElement('span');
      timeEl.className = 'contact-time';
      timeEl.textContent = formatContactTime(contact.lastTime);
      meta.appendChild(timeEl);
    }

    if (contact.unread > 0) {
      const badge = document.createElement('span');
      badge.className = 'contact-badge';
      badge.textContent = String(contact.unread);
      meta.appendChild(badge);
    }

    item.appendChild(meta);
    list.appendChild(item);
  }
}

function formatContactTime(isoString: string): string {
  try {
    const d = new Date(isoString);
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const msgDate = new Date(d.getFullYear(), d.getMonth(), d.getDate());
    const diff = (today.getTime() - msgDate.getTime()) / (1000 * 60 * 60 * 24);

    if (diff === 0) return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    if (diff === 1) return 'Yesterday';
    if (diff < 7) return d.toLocaleDateString([], { weekday: 'short' });
    return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
  } catch {
    return '';
  }
}

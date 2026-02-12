import { api } from '../api.js';
import { STORES, put, putDebounced, getAll } from '../storage/indexeddb.js';

let contacts = {}; // username -> { id, username, unread, lastMessage, lastTime }
let activeContact = null;
let onSelectContact = null;
let onlineUsers = new Set(); // Set of user IDs that are online
let contactRenderScheduled = false;

export function initContacts(callback) {
  onSelectContact = callback;

  const searchInput = document.getElementById('user-search');
  const searchResults = document.getElementById('search-results');
  let searchTimeout = null;

  searchInput.addEventListener('input', () => {
    clearTimeout(searchTimeout);
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
    if (!searchResults.contains(e.target) && e.target !== searchInput) {
      searchResults.classList.add('hidden');
    }
  });
}

function renderSearchResults(users, container) {
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
      document.getElementById('user-search').value = '';
    });
    container.appendChild(item);
  }
  container.classList.remove('hidden');
}

export async function loadContacts() {
  const { keys, values } = await getAll(STORES.CONTACTS);
  for (let i = 0; i < keys.length; i++) {
    contacts[keys[i]] = values[i];
  }
  renderContacts();
}

export function addContact(user) {
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

export function selectContact(username) {
  activeContact = username;
  if (contacts[username]) {
    contacts[username].unread = 0;
    putDebounced(STORES.CONTACTS, username, contacts[username]);
  }
  renderContacts(); // immediate for active selection
  if (onSelectContact) onSelectContact(username, contacts[username]);
}

export function getActiveContact() {
  return activeContact;
}

export function getContactInfo(username) {
  return contacts[username];
}

export function incrementUnread(username) {
  if (contacts[username]) {
    contacts[username].unread++;
    putDebounced(STORES.CONTACTS, username, contacts[username]);
    scheduleContactRender();
  }
}

export function updateLastMessage(username, text, time) {
  if (contacts[username]) {
    contacts[username].lastMessage = text;
    contacts[username].lastTime = time || new Date().toISOString();
    putDebounced(STORES.CONTACTS, username, contacts[username]);
    scheduleContactRender();
  }
}

// Presence management
export function setUserOnline(userId) {
  onlineUsers.add(userId);
  scheduleContactRender();
}

export function setUserOffline(userId) {
  onlineUsers.delete(userId);
  scheduleContactRender();
}

export function setOnlineUsers(userIds) {
  onlineUsers = new Set(userIds);
  scheduleContactRender();
}

export function isContactOnline(username) {
  const contact = contacts[username];
  if (!contact) return false;
  return onlineUsers.has(contact.id);
}

function scheduleContactRender() {
  if (contactRenderScheduled) return;
  contactRenderScheduled = true;
  requestAnimationFrame(() => {
    contactRenderScheduled = false;
    renderContacts();
  });
}

function renderContacts() {
  const list = document.getElementById('contacts-list');
  while (list.firstChild) list.removeChild(list.firstChild);

  // Sort contacts: those with most recent messages first
  const sorted = Object.values(contacts).sort((a, b) => {
    if (a.lastTime && b.lastTime) {
      return new Date(b.lastTime) - new Date(a.lastTime);
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
    avatar.textContent = contact.username[0].toUpperCase();

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
      badge.textContent = contact.unread;
      meta.appendChild(badge);
    }

    item.appendChild(meta);
    list.appendChild(item);
  }
}

function formatContactTime(isoString) {
  try {
    const d = new Date(isoString);
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const msgDate = new Date(d.getFullYear(), d.getMonth(), d.getDate());
    const diff = (today - msgDate) / (1000 * 60 * 60 * 24);

    if (diff === 0) return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    if (diff === 1) return 'Yesterday';
    if (diff < 7) return d.toLocaleDateString([], { weekday: 'short' });
    return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
  } catch {
    return '';
  }
}

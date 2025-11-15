// ============================================
// SecureVault - Advanced Password Manager
// ============================================

// Global State
let key = null; // derived encryption key
let sessionTimeout = null;
let clipboardTimeout = null;
let inactivityTimer = null;
let decryptedPasswords = []; // Cache decrypted passwords for editing
let editingIndex = null;

// Constants
const saltKey = "vault_salt";
const dataKey = "vault_data";
const SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes
const INACTIVITY_TIMEOUT = 15 * 60 * 1000; // 15 minutes
const CLIPBOARD_CLEAR_TIME = 30 * 1000; // 30 seconds
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_ATTEMPT_WINDOW = 15 * 60 * 1000; // 15 minutes

// Utility Functions
function bufToBase64(buf) {
  const bytes = (buf instanceof Uint8Array) ? buf : new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function base64ToBuf(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

// Toast Notification System
function showToast(message, type = 'info', duration = 3000) {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.setAttribute('role', 'alert');
  toast.textContent = message;
  
  container.appendChild(toast);
  
  // Trigger animation
  setTimeout(() => toast.classList.add('show'), 10);
  
  // Remove after duration
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => container.removeChild(toast), 300);
  }, duration);
}

// Loading Overlay
function showLoading() {
  document.getElementById('loading-overlay').style.display = 'flex';
}

function hideLoading() {
  document.getElementById('loading-overlay').style.display = 'none';
}

// Message Helpers
function setAuthMessage(msg, type = 'info') {
  const el = document.getElementById('auth-message');
  el.textContent = msg;
  el.className = `message message-${type}`;
  if (msg) showToast(msg, type);
}

function setVaultMessage(msg, type = 'info') {
  const el = document.getElementById('vault-message');
  el.textContent = msg;
  el.className = `message message-${type}`;
  if (msg) showToast(msg, type);
}

// Password Strength Calculator
function calculatePasswordStrength(password) {
  let strength = 0;
  let feedback = [];
  
  if (password.length >= 8) strength += 1;
  else feedback.push('Use at least 8 characters');
  
  if (password.length >= 12) strength += 1;
  if (password.length >= 16) strength += 1;
  
  if (/[a-z]/.test(password)) strength += 1;
  else feedback.push('Add lowercase letters');
  
  if (/[A-Z]/.test(password)) strength += 1;
  else feedback.push('Add uppercase letters');
  
  if (/[0-9]/.test(password)) strength += 1;
  else feedback.push('Add numbers');
  
  if (/[^a-zA-Z0-9]/.test(password)) strength += 1;
  else feedback.push('Add special characters');
  
  if (password.length >= 8 && /[a-z]/.test(password) && /[A-Z]/.test(password) && /[0-9]/.test(password) && /[^a-zA-Z0-9]/.test(password)) {
    strength += 1;
  }
  
  return { strength: Math.min(strength, 5), feedback };
}

function updatePasswordStrength(password) {
  const { strength, feedback } = calculatePasswordStrength(password);
  const indicator = document.getElementById('password-strength-indicator');
  const bar = document.getElementById('strength-bar');
  
  if (!indicator || !bar) return;
  
  const levels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very Strong'];
  const colors = ['#e74c3c', '#e67e22', '#f39c12', '#3498db', '#2ecc71', '#27ae60'];
  
  indicator.textContent = password ? levels[strength] : '';
  indicator.style.color = password ? colors[strength] : '';
  bar.style.width = password ? `${(strength / 5) * 100}%` : '0%';
  bar.style.backgroundColor = password ? colors[strength] : '';
  
  if (password && strength < 3) {
    indicator.title = feedback.join(', ');
  }
}

// Password Visibility Toggle
function togglePasswordVisibility(inputId, buttonId) {
  const input = document.getElementById(inputId);
  const button = document.getElementById(buttonId);
  
  if (input.type === 'password') {
    input.type = 'text';
    button.textContent = '🙈';
  } else {
    input.type = 'password';
    button.textContent = '👁️';
  }
}

// Session Management
function startSession() {
  clearSessionTimers();
  
  sessionTimeout = setTimeout(() => {
    showToast('Session expired. Logging out for security.', 'warning');
    logout();
  }, SESSION_TIMEOUT);
  
  resetInactivityTimer();
  
  // Update session timer display
  updateSessionTimer();
  const timerInterval = setInterval(() => {
    if (!key) {
      clearInterval(timerInterval);
      return;
    }
    updateSessionTimer();
  }, 1000);
}

function resetInactivityTimer() {
  clearTimeout(inactivityTimer);
  inactivityTimer = setTimeout(() => {
    showToast('Inactivity detected. Logging out for security.', 'warning');
    logout();
  }, INACTIVITY_TIMEOUT);
}

function clearSessionTimers() {
  if (sessionTimeout) clearTimeout(sessionTimeout);
  if (inactivityTimer) clearTimeout(inactivityTimer);
  if (clipboardTimeout) clearTimeout(clipboardTimeout);
}

function updateSessionTimer() {
  const timerEl = document.getElementById('session-timer');
  if (!timerEl || !sessionTimeout) return;
  
  const remaining = SESSION_TIMEOUT - (Date.now() - (Date.now() - SESSION_TIMEOUT + (sessionTimeout._idleStart || 0)));
  const minutes = Math.floor(remaining / 60000);
  const seconds = Math.floor((remaining % 60000) / 1000);
  
  if (minutes < 5) {
    timerEl.className = 'session-timer warning';
  } else {
    timerEl.className = 'session-timer';
  }
  
  timerEl.textContent = `Session: ${minutes}:${seconds.toString().padStart(2, '0')}`;
}

function showSessionInfo() {
  const remaining = SESSION_TIMEOUT - (Date.now() - (Date.now() - SESSION_TIMEOUT + (sessionTimeout._idleStart || 0)));
  const minutes = Math.floor(remaining / 60000);
  showToast(`Session expires in ${minutes} minutes`, 'info', 2000);
}

// Clipboard Management
async function copyToClipboard(text, label = 'Password') {
  try {
    await navigator.clipboard.writeText(text);
    showToast(`${label} copied to clipboard. Will clear in 30 seconds.`, 'success');
    
    // Clear clipboard after timeout
    if (clipboardTimeout) clearTimeout(clipboardTimeout);
    clipboardTimeout = setTimeout(async () => {
      try {
        await navigator.clipboard.writeText('');
        showToast('Clipboard cleared for security', 'info', 2000);
      } catch (e) {
        console.warn('Could not clear clipboard:', e);
      }
    }, CLIPBOARD_CLEAR_TIME);
  } catch (e) {
    showToast('Clipboard unavailable. Please copy manually.', 'error');
    console.error('Clipboard error:', e);
  }
}

// Login Attempt Tracking
function getLoginAttempts() {
  const attempts = localStorage.getItem('login_attempts');
  if (!attempts) return { count: 0, resetTime: Date.now() };
  return JSON.parse(attempts);
}

function recordLoginAttempt() {
  const attempts = getLoginAttempts();
  attempts.count += 1;
  attempts.resetTime = Date.now();
  localStorage.setItem('login_attempts', JSON.stringify(attempts));
}

function resetLoginAttempts() {
  localStorage.removeItem('login_attempts');
}

function checkLoginAttempts() {
  const attempts = getLoginAttempts();
  const timeSinceReset = Date.now() - attempts.resetTime;
  
  if (timeSinceReset > LOGIN_ATTEMPT_WINDOW) {
    resetLoginAttempts();
    return true;
  }
  
  if (attempts.count >= MAX_LOGIN_ATTEMPTS) {
    const remainingMinutes = Math.ceil((LOGIN_ATTEMPT_WINDOW - timeSinceReset) / 60000);
    setAuthMessage(`Too many failed attempts. Try again in ${remainingMinutes} minutes.`, 'error');
    return false;
  }
  
  return true;
}

// Crypto Functions
async function getKey(password, salt) {
  const saltBuf = (typeof salt === 'string') ? base64ToBuf(salt) : salt;
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBuf, iterations: 100000, hash: "SHA-256" },
    keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
}

async function encryptData(obj) {
  if (!key) throw new Error('Vault not unlocked');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(obj)));
  return { iv: bufToBase64(iv), data: bufToBase64(new Uint8Array(cipher)) };
}

async function decryptData(entry) {
  if (!key) throw new Error('Vault not unlocked');
  const iv = base64ToBuf(entry.iv);
  const data = base64ToBuf(entry.data);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
  return JSON.parse(new TextDecoder().decode(plain));
}

// Storage Helpers with Error Handling
function saveVault(vault) {
  try {
    localStorage.setItem(dataKey, JSON.stringify(vault));
    return true;
  } catch (e) {
    if (e.name === 'QuotaExceededError') {
      showToast('Storage quota exceeded. Please export and clear some data.', 'error');
      return false;
    }
    showToast('Failed to save vault data.', 'error');
    console.error('Storage error:', e);
    return false;
  }
}

function loadVault() {
  try {
    const data = localStorage.getItem(dataKey);
    return data ? JSON.parse(data) : [];
  } catch (e) {
    console.error('Failed to load vault:', e);
    showToast('Failed to load vault data. It may be corrupted.', 'error');
    return [];
  }
}

// Auth Functions
async function register() {
  const pass = document.getElementById("master-pass").value || "";
  const { strength } = calculatePasswordStrength(pass);
  
  if (pass.length < 8) {
    setAuthMessage('Password must be at least 8 characters long.', 'error');
    return;
  }
  
  if (strength < 2) {
    setAuthMessage('Please use a stronger password for better security.', 'error');
    return;
  }
  
  if (localStorage.getItem(saltKey)) {
    if (!confirm('A vault already exists. Registering will reset the vault. Continue?')) return;
  }
  
  showLoading();
  try {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const saltB64 = bufToBase64(salt);
    localStorage.setItem(saltKey, saltB64);
    key = await getKey(pass, salt);
    saveVault([]);
    resetLoginAttempts();
    setAuthMessage('Registered successfully. Vault initialized.', 'success');
    
    await loadPasswords();
    document.getElementById("auth-section").style.display = "none";
    document.getElementById("vault").style.display = "block";
    setVaultMessage('Vault unlocked', 'success');
    startSession();
    document.getElementById("master-pass").value = '';
  } catch (e) {
    console.error('Registration error:', e);
    setAuthMessage('Registration failed. Please try again.', 'error');
  } finally {
    hideLoading();
  }
}

async function login() {
  if (!checkLoginAttempts()) return;
  
  const pass = document.getElementById("master-pass").value || "";
  const saltB64 = localStorage.getItem(saltKey);
  
  if (!saltB64) {
    setAuthMessage('No vault found. Please register first.', 'error');
    return;
  }
  
  if (!pass) {
    setAuthMessage('Please enter your master password.', 'error');
    return;
  }
  
  showLoading();
  try {
    key = await getKey(pass, saltB64);
    await loadPasswords(); // Validate decryption
    resetLoginAttempts();
    document.getElementById("auth-section").style.display = "none";
    document.getElementById("vault").style.display = "block";
    setAuthMessage('', 'success');
    setVaultMessage('Vault unlocked', 'success');
    startSession();
    document.getElementById("master-pass").value = '';
  } catch (err) {
    key = null;
    recordLoginAttempt();
    setAuthMessage('Incorrect password or corrupted vault.', 'error');
    console.error('Login error:', err);
  } finally {
    hideLoading();
  }
}

function resetVault() {
  if (!confirm('⚠️ WARNING: This will permanently delete all your vault data and cannot be undone. Continue?')) return;
  if (!confirm('Are you absolutely sure? All passwords and encrypted files will be lost.')) return;
  
  try {
    localStorage.removeItem(saltKey);
    localStorage.removeItem(dataKey);
    resetLoginAttempts();
    key = null;
    decryptedPasswords = [];
    clearSessionTimers();
    setAuthMessage('Vault reset. You can now register with a new master password.', 'success');
    document.getElementById("master-pass").value = '';
  } catch (e) {
    showToast('Failed to reset vault.', 'error');
    console.error('Reset error:', e);
  }
}

function logout() {
  key = null;
  decryptedPasswords = [];
  clearSessionTimers();
  document.getElementById("auth-section").style.display = "block";
  document.getElementById("vault").style.display = "none";
  setVaultMessage('');
  setAuthMessage('Logged out successfully', 'info');
  document.getElementById("master-pass").value = '';
  
  // Clear form fields
  document.getElementById('site')?.value && (document.getElementById('site').value = '');
  document.getElementById('user')?.value && (document.getElementById('user').value = '');
  document.getElementById('pass')?.value && (document.getElementById('pass').value = '');
}

// Password Management
async function addPassword() {
  if (!key) {
    setVaultMessage('Vault not unlocked.', 'error');
    return;
  }
  
  const site = (document.getElementById("site").value || "").trim();
  const user = (document.getElementById("user").value || "").trim();
  const pass = (document.getElementById("pass").value || "").trim();
  const category = document.getElementById("category").value || "";
  
  if (!site || !user || !pass) {
    setVaultMessage('Please fill in all required fields.', 'error');
    return;
  }
  
  // Validate URL format if it looks like a URL
  if (site.includes('.') && !site.startsWith('http')) {
    if (!confirm(`Site "${site}" doesn't look like a valid URL. Continue anyway?`)) return;
  }
  
  showLoading();
  try {
    const vault = loadVault();
    const timestamp = Date.now();
    const enc = await encryptData({ site, user, pass, category, timestamp });
    vault.push(enc);
    
    if (!saveVault(vault)) {
      return;
    }
    
    // Clear form
    document.getElementById('site').value = '';
    document.getElementById('user').value = '';
    document.getElementById('pass').value = '';
    document.getElementById('category').value = '';
    
    setVaultMessage('Password saved successfully', 'success');
    await loadPasswords();
  } catch (e) {
    console.error('Add password error:', e);
    setVaultMessage('Failed to save password.', 'error');
  } finally {
    hideLoading();
  }
}

async function loadPasswords() {
  if (!key) return;
  
  const vault = loadVault();
  const list = document.getElementById("password-list");
  const emptyState = document.getElementById("empty-state");
  list.innerHTML = "";
  decryptedPasswords = [];
  
  if (vault.length === 0) {
    emptyState.style.display = 'block';
    updatePasswordCount(0);
    return;
  }
  
  emptyState.style.display = 'none';
  
  for (let i = 0; i < vault.length; i++) {
    const entry = vault[i];
    let dec;
    try {
      dec = await decryptData(entry);
      decryptedPasswords.push(dec);
    } catch (e) {
      console.error('Failed to decrypt entry', e);
      const liFail = document.createElement('div');
      liFail.className = 'password-item error';
      liFail.innerHTML = `
        <div class="item-content">
          <div class="item-title">⚠️ Corrupted Entry</div>
          <div class="item-subtitle">Unable to decrypt (wrong key or corrupted data)</div>
        </div>
        <button class="btn btn-danger btn-sm" onclick="deletePassword(${i})" aria-label="Delete corrupted entry">Delete</button>
      `;
      list.appendChild(liFail);
      continue;
    }
    
    const item = createPasswordItem(dec, i);
    list.appendChild(item);
  }
  
  updatePasswordCount(vault.length);
}

function createPasswordItem(dec, index) {
  const item = document.createElement('div');
  item.className = 'password-item';
  item.setAttribute('data-index', index);
  item.setAttribute('data-site', dec.site.toLowerCase());
  item.setAttribute('data-category', dec.category || '');
  
  const categoryBadge = dec.category ? `<span class="category-badge category-${dec.category}">${dec.category}</span>` : '';
  
  item.innerHTML = `
    <div class="item-content">
      <div class="item-header">
        <div class="item-title">${escapeHtml(dec.site)}</div>
        ${categoryBadge}
      </div>
      <div class="item-subtitle">${escapeHtml(dec.user)}</div>
      <div class="password-display-wrapper">
        <div class="password-display masked" data-password="${escapeHtml(dec.pass)}">••••••••</div>
      </div>
    </div>
    <div class="item-actions">
      <button class="btn btn-icon btn-sm" onclick="togglePasswordItem(${index})" aria-label="Toggle password visibility">
        👁️
      </button>
      <button class="btn btn-icon btn-sm" onclick="copyPassword(${index})" aria-label="Copy password">
        📋
      </button>
      <button class="btn btn-icon btn-sm" onclick="copyUsername(${index})" aria-label="Copy username">
        👤
      </button>
      <button class="btn btn-icon btn-sm" onclick="editPassword(${index})" aria-label="Edit password">
        ✏️
      </button>
      <button class="btn btn-icon btn-sm btn-danger" onclick="confirmDeletePassword(${index})" aria-label="Delete password">
        🗑️
      </button>
    </div>
  `;
  
  return item;
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function togglePasswordItem(index) {
  const item = document.querySelector(`[data-index="${index}"]`);
  if (!item) return;
  
  const passDisplay = item.querySelector('.password-display');
  if (!passDisplay) return;
  
  const isMasked = passDisplay.classList.contains('masked');
  const actualPassword = passDisplay.getAttribute('data-password') || (decryptedPasswords[index]?.pass || '');
  
  if (isMasked) {
    passDisplay.textContent = actualPassword;
    passDisplay.classList.remove('masked');
  } else {
    passDisplay.textContent = '••••••••';
    passDisplay.classList.add('masked');
  }
}

async function copyPassword(index) {
  await copyToClipboard(decryptedPasswords[index].pass, 'Password');
}

async function copyUsername(index) {
  await copyToClipboard(decryptedPasswords[index].user, 'Username');
}

function editPassword(index) {
  const dec = decryptedPasswords[index];
  document.getElementById('site').value = dec.site;
  document.getElementById('user').value = dec.user;
  document.getElementById('pass').value = dec.pass;
  document.getElementById('category').value = dec.category || '';
  
  editingIndex = index;
  
  // Scroll to form
  document.getElementById('password-form').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  document.getElementById('site').focus();
  
  showToast('Password loaded for editing. Modify and save.', 'info');
}

async function confirmDeletePassword(index) {
  const dec = decryptedPasswords[index];
  if (!confirm(`Delete password for "${dec.site}" (${dec.user})?`)) return;
  await deletePassword(index);
}

async function deletePassword(index) {
  const vault = loadVault();
  vault.splice(index, 1);
  
  if (!saveVault(vault)) {
    return;
  }
  
  setVaultMessage('Password deleted', 'success');
  await loadPasswords();
}

// Search and Filter
function filterPasswords() {
  const searchTerm = document.getElementById('search-input').value.toLowerCase();
  const categoryFilter = document.getElementById('category-filter').value;
  const items = document.querySelectorAll('.password-item');
  let visibleCount = 0;
  
  items.forEach(item => {
    const site = item.getAttribute('data-site') || '';
    const category = item.getAttribute('data-category') || '';
    const matchesSearch = !searchTerm || site.includes(searchTerm);
    const matchesCategory = !categoryFilter || category === categoryFilter;
    
    if (matchesSearch && matchesCategory) {
      item.style.display = '';
      visibleCount++;
    } else {
      item.style.display = 'none';
    }
  });
  
  updatePasswordCount(visibleCount, items.length);
}

function clearFilters() {
  document.getElementById('search-input').value = '';
  document.getElementById('category-filter').value = '';
  filterPasswords();
}

function updatePasswordCount(visible, total) {
  const countEl = document.getElementById('password-count');
  if (!countEl) return;
  
  if (total && visible !== total) {
    countEl.textContent = `Showing ${visible} of ${total} passwords`;
  } else if (total) {
    countEl.textContent = `${total} password${total !== 1 ? 's' : ''} saved`;
  } else {
    countEl.textContent = '';
  }
}

// Password Generator
function showPasswordGenerator() {
  document.getElementById('password-generator-modal').style.display = 'flex';
  generateAdvancedPassword();
}

function closePasswordGenerator() {
  document.getElementById('password-generator-modal').style.display = 'none';
}

function updateGeneratorLength(value) {
  document.getElementById('length-value').textContent = value;
  generateAdvancedPassword();
}

function generateAdvancedPassword() {
  const length = parseInt(document.getElementById('gen-length').value) || 16;
  const uppercase = document.getElementById('gen-uppercase').checked;
  const lowercase = document.getElementById('gen-lowercase').checked;
  const numbers = document.getElementById('gen-numbers').checked;
  const symbols = document.getElementById('gen-symbols').checked;
  
  let chars = '';
  if (uppercase) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (lowercase) chars += 'abcdefghijklmnopqrstuvwxyz';
  if (numbers) chars += '0123456789';
  if (symbols) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';
  
  if (!chars) {
    showToast('Please select at least one character type', 'error');
    return;
  }
  
  let password = '';
  const rnd = crypto.getRandomValues(new Uint8Array(length));
  for (let i = 0; i < length; i++) {
    password += chars[rnd[i] % chars.length];
  }
  
  document.getElementById('generated-password').value = password;
}

function copyGeneratedPassword() {
  const password = document.getElementById('generated-password').value;
  if (password) {
    copyToClipboard(password, 'Generated password');
  }
}

function useGeneratedPassword() {
  const password = document.getElementById('generated-password').value;
  if (password) {
    document.getElementById('pass').value = password;
    document.getElementById('pass').type = 'text';
    closePasswordGenerator();
    showToast('Password applied to form', 'success');
  }
}

// File Encryption
async function encryptFile() {
  const file = document.getElementById("fileInput").files[0];
  if (!file) {
    setVaultMessage('Please select a file first.', 'error');
    return;
  }
  if (!key) {
    setVaultMessage('Vault not unlocked.', 'error');
    return;
  }
  
  // Check file size (warn if > 100MB)
  if (file.size > 100 * 1024 * 1024) {
    if (!confirm('Large file detected. Encryption may take a while. Continue?')) return;
  }
  
  showLoading();
  try {
    const arrayBuffer = await file.arrayBuffer();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, arrayBuffer);
    const blob = new Blob([iv, new Uint8Array(encrypted)], { type: "application/octet-stream" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = file.name + ".enc";
    a.click();
    URL.revokeObjectURL(a.href);
    setVaultMessage('File encrypted and downloaded successfully', 'success');
    document.getElementById("fileInput").value = '';
  } catch (e) {
    console.error('Encryption error:', e);
    setVaultMessage('Failed to encrypt file. File may be too large.', 'error');
  } finally {
    hideLoading();
  }
}

async function decryptFileInput() {
  const f = document.getElementById('encFileInput').files[0];
  if (!f) {
    setVaultMessage('Please select an encrypted (.enc) file', 'error');
    return;
  }
  if (!key) {
    setVaultMessage('Vault not unlocked.', 'error');
    return;
  }
  
  showLoading();
  try {
    const ab = await f.arrayBuffer();
    const iv = new Uint8Array(ab.slice(0, 12));
    const cipher = ab.slice(12);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipher);
    const blob = new Blob([plain]);
    const a = document.createElement('a');
    const name = f.name.replace(/\.enc$/i, '') || 'decrypted.bin';
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
    setVaultMessage('File decrypted and downloaded successfully', 'success');
    document.getElementById('encFileInput').value = '';
  } catch (e) {
    console.error('Decryption error:', e);
    setVaultMessage('Failed to decrypt file. Wrong key or corrupted file.', 'error');
  } finally {
    hideLoading();
  }
}

// Export/Import
function exportVault() {
  if (!key) {
    setVaultMessage('Vault not unlocked.', 'error');
    return;
  }
  
  // Export both salt and vault data together
  const vaultData = localStorage.getItem(dataKey) || '[]';
  const salt = localStorage.getItem(saltKey);
  
  if (!salt) {
    setVaultMessage('No salt found. Cannot export vault.', 'error');
    showToast('Vault is corrupted. Cannot export.', 'error');
    return;
  }
  
  const exportData = {
    version: '2.0',
    salt: salt,
    vault: JSON.parse(vaultData),
    exportDate: new Date().toISOString()
  };
  
  const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `vault-backup-${new Date().toISOString().split('T')[0]}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
  showToast('Vault exported successfully (includes salt)', 'success');
}

function importVault(evt) {
  const f = evt.target.files[0];
  if (!f) return;
  
  if (!confirm('Importing will replace your current vault and salt. Make sure you have a backup. Continue?')) {
    evt.target.value = '';
    return;
  }
  
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const parsed = JSON.parse(reader.result);
      
      let vaultData, saltData;
      
      // Check if it's the new format (with salt) or old format (array only)
      if (parsed.version && parsed.salt && parsed.vault) {
        // New format (v2.0) - includes salt
        vaultData = parsed.vault;
        saltData = parsed.salt;
        
        if (!Array.isArray(vaultData)) {
          throw new Error('Invalid vault format: vault must be an array');
        }
        
        // Validate vault structure
        if (vaultData.length > 0 && (!vaultData[0].iv || !vaultData[0].data)) {
          throw new Error('Invalid vault structure: missing encryption data');
        }
        
        // Validate salt format
        if (typeof saltData !== 'string' || saltData.length < 10) {
          throw new Error('Invalid salt format');
        }
        
        // Save both salt and vault
        try {
          localStorage.setItem(saltKey, saltData);
        } catch (e) {
          if (e.name === 'QuotaExceededError') {
            showToast('Storage quota exceeded. Cannot import.', 'error');
            return;
          }
          throw e;
        }
        
        if (!saveVault(vaultData)) {
          return;
        }
        
        setVaultMessage('Vault and salt imported successfully. Please login with your master password.', 'success');
        showToast('Vault imported successfully. Please login.', 'success');
        
      } else if (Array.isArray(parsed)) {
        // Old format (v1.0) - array only, no salt
        // This means user needs to use the SAME master password and salt from original browser
        if (parsed.length > 0 && (!parsed[0].iv || !parsed[0].data)) {
          throw new Error('Invalid vault structure: missing encryption data');
        }
        
        // Check if salt exists in current browser
        const existingSalt = localStorage.getItem(saltKey);
        if (!existingSalt) {
          throw new Error('Old format detected: Cannot import without salt. Please export from the original browser using the new export format (v2.0) that includes salt.');
        }
        
        // Warn user about old format
        if (!confirm('⚠️ Old format detected (no salt included).\n\nYou MUST use the SAME master password and browser where this was exported.\n\nIf you\'re importing to a different browser, you need to export again using the new format.\n\nContinue anyway?')) {
          evt.target.value = '';
          return;
        }
        
        if (!saveVault(parsed)) {
          return;
        }
        
        setVaultMessage('Vault imported (old format). Using existing salt. Please login with original master password.', 'warning');
        showToast('Old format imported. Use original master password.', 'warning');
        
      } else {
        throw new Error('Invalid vault format: must be array or object with version');
      }
      
      // Clear current session
      key = null;
      decryptedPasswords = [];
      clearSessionTimers();
      
      // Logout to force re-authentication
      document.getElementById("auth-section").style.display = "block";
      document.getElementById("vault").style.display = "none";
      setAuthMessage('Vault imported. Please login with your master password.', 'info');
      
    } catch (e) {
      console.error('Import error:', e);
      const errorMsg = e.message || 'Invalid vault file format.';
      setVaultMessage(`Import failed: ${errorMsg}`, 'error');
      showToast(`Import failed: ${errorMsg}`, 'error');
    }
    evt.target.value = '';
  };
  reader.readAsText(f);
}

// Theme Management
function toggleTheme() {
  const body = document.body;
  const isDark = body.classList.toggle('dark-theme');
  localStorage.setItem('theme', isDark ? 'dark' : 'light');
  showToast(`Switched to ${isDark ? 'dark' : 'light'} mode`, 'info', 2000);
}

function loadTheme() {
  const savedTheme = localStorage.getItem('theme') || 'light';
  if (savedTheme === 'dark') {
    document.body.classList.add('dark-theme');
  }
}

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
  loadTheme();
  
  const saltExists = !!localStorage.getItem(saltKey);
  if (saltExists) {
    setAuthMessage('Vault found. Enter master password to login.', 'info');
  } else {
    setAuthMessage('No vault found. Register to create one.', 'info');
  }

  const masterInput = document.getElementById('master-pass');
  const regBtn = document.getElementById('registerBtn');
  const loginBtn = document.getElementById('loginBtn');
  
  if (masterInput && regBtn && loginBtn) {
    const updateButtons = () => {
      const v = masterInput.value || '';
      loginBtn.disabled = v.length === 0;
      regBtn.disabled = v.length < 8;
      updatePasswordStrength(v);
    };
    
    masterInput.addEventListener('input', updateButtons);
    masterInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        if (saltExists) login();
        else if (masterInput.value.length >= 8) register();
      }
    });
    updateButtons();
  }
  
  // Activity tracking for inactivity timer
  ['mousedown', 'keydown', 'scroll', 'touchstart'].forEach(event => {
    document.addEventListener(event, resetInactivityTimer, { passive: true });
  });
  
  // Handle editing - if editing, update instead of add
  const passwordForm = document.getElementById('password-form');
  if (passwordForm) {
    passwordForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (editingIndex !== null) {
        await updatePassword();
      } else {
        await addPassword();
      }
    });
  }
});

async function updatePassword() {
  if (editingIndex === null || !key) return;
  
  const site = (document.getElementById("site").value || "").trim();
  const user = (document.getElementById("user").value || "").trim();
  const pass = (document.getElementById("pass").value || "").trim();
  const category = document.getElementById("category").value || "";
  
  if (!site || !user || !pass) {
    setVaultMessage('Please fill in all required fields.', 'error');
    return;
  }
  
  showLoading();
  try {
    const vault = loadVault();
    const timestamp = Date.now();
    const enc = await encryptData({ site, user, pass, category, timestamp });
    vault[editingIndex] = enc;
    
    if (!saveVault(vault)) {
      return;
    }
    
    // Clear form and editing state
    document.getElementById('site').value = '';
    document.getElementById('user').value = '';
    document.getElementById('pass').value = '';
    document.getElementById('category').value = '';
    editingIndex = null;
    
    setVaultMessage('Password updated successfully', 'success');
    await loadPasswords();
  } catch (e) {
    console.error('Update password error:', e);
    setVaultMessage('Failed to update password.', 'error');
  } finally {
    hideLoading();
  }
}

// Close modal on outside click
document.addEventListener('click', (e) => {
  const modal = document.getElementById('password-generator-modal');
  if (e.target === modal) {
    closePasswordGenerator();
  }
});

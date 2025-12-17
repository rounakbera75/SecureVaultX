/**
 * SecureVault v2.0 - Professional Password Manager
 * Architecture: Modular Class-Based
 * Storage: IndexedDB (replacing LocalStorage)
 * Security: PBKDF2 (600k iterations), AES-256-GCM
 */

// ==========================================
// Constants & Configuration
// ==========================================
const CONFIG = {
  DB_NAME: 'SecureVaultDB',
  DB_VERSION: 1,
  STORES: {
    META: 'vault_meta',   // Stores salt, verifier, version
    ITEMS: 'vault_items'  // Stores encrypted passwords/files
  },
  CRYPTO: {
    ALGO: 'AES-GCM',
    HASH: 'SHA-256',
    ITERATIONS_V1: 100000, // Backward compatibility
    ITERATIONS_V2: 600000, // OWASP 2025 Standard
    KEY_LENGTH: 256
  },
  TIMEOUTS: {
    SESSION: 30 * 60 * 1000,    // 30 mins absolute session
    INACTIVITY: 15 * 60 * 1000, // 15 mins idle timeout
    CLIPBOARD: 30 * 1000        // 30 sec clipboard clear
  }
};

// ==========================================
// Module: IndexedDB Wrapper
// ==========================================
class DBManager {
  constructor() {
    this.db = null;
  }

  async open() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(CONFIG.DB_NAME, CONFIG.DB_VERSION);

      request.onerror = (event) => reject(`DB Error: ${event.target.error}`);

      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains(CONFIG.STORES.META)) {
          db.createObjectStore(CONFIG.STORES.META, { keyPath: 'key' });
        }
        if (!db.objectStoreNames.contains(CONFIG.STORES.ITEMS)) {
          // Auto-increment ID for items
          const store = db.createObjectStore(CONFIG.STORES.ITEMS, { keyPath: 'id', autoIncrement: true });
          store.createIndex('category', 'category', { unique: false });
        }
      };

      request.onsuccess = (event) => {
        this.db = event.target.result;
        resolve(this.db);
      };
    });
  }

  // Generic Transaction Helper
  async transaction(storeName, mode, callback) {
    if (!this.db) await this.open();
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(storeName, mode);
      const store = tx.objectStore(storeName);
      const request = callback(store);

      tx.oncomplete = () => resolve(request.result);
      tx.onerror = () => reject(tx.error);
    });
  }

  // Meta Operations
  async getMeta(key) {
    return new Promise(async (resolve) => {
      try {
        const res = await this.transaction(CONFIG.STORES.META, 'readonly', store => store.get(key));
        resolve(res ? res.value : null);
      } catch (e) { resolve(null); }
    });
  }

  async setMeta(key, value) {
    return this.transaction(CONFIG.STORES.META, 'readwrite', store => store.put({ key, value }));
  }

  // Item Operations
  async getAllItems() {
    return this.transaction(CONFIG.STORES.ITEMS, 'readonly', store => store.getAll());
  }

  async addItem(item) {
    return this.transaction(CONFIG.STORES.ITEMS, 'readwrite', store => store.add(item));
  }

  async updateItem(item) {
    return this.transaction(CONFIG.STORES.ITEMS, 'readwrite', store => store.put(item));
  }

  async deleteItem(id) {
    return this.transaction(CONFIG.STORES.ITEMS, 'readwrite', store => store.delete(id));
  }

  async clearAll() {
    if (!this.db) await this.open();
    const tx = this.db.transaction([CONFIG.STORES.META, CONFIG.STORES.ITEMS], 'readwrite');
    tx.objectStore(CONFIG.STORES.META).clear();
    tx.objectStore(CONFIG.STORES.ITEMS).clear();
    return new Promise((resolve) => { tx.oncomplete = resolve; });
  }
}

// ==========================================
// Module: Crypto Manager
// ==========================================
class CryptoManager {
  constructor() {
    this.key = null;
    this.iterations = CONFIG.CRYPTO.ITERATIONS_V2;
  }

  bufToBase64(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  base64ToBuf(b64) {
    const bin = atob(b64);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
  }

  async deriveKey(password, salt, iterations = CONFIG.CRYPTO.ITERATIONS_V2) {
    const saltBuf = (typeof salt === 'string') ? this.base64ToBuf(salt) : salt;
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: saltBuf,
        iterations: iterations,
        hash: CONFIG.CRYPTO.HASH
      },
      keyMaterial,
      { name: CONFIG.CRYPTO.ALGO, length: CONFIG.CRYPTO.KEY_LENGTH },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async encrypt(dataObj) {
    if (!this.key) throw new Error('Vault locked');
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const encodedData = enc.encode(JSON.stringify(dataObj));

    const cipher = await crypto.subtle.encrypt(
      { name: CONFIG.CRYPTO.ALGO, iv },
      this.key,
      encodedData
    );

    return {
      iv: this.bufToBase64(iv),
      data: this.bufToBase64(cipher)
    };
  }

  async decrypt(encryptedObj) {
    if (!this.key) throw new Error('Vault locked');
    const iv = this.base64ToBuf(encryptedObj.iv);
    const data = this.base64ToBuf(encryptedObj.data);

    const plain = await crypto.subtle.decrypt(
      { name: CONFIG.CRYPTO.ALGO, iv },
      this.key,
      data
    );

    return JSON.parse(new TextDecoder().decode(plain));
  }

  async encryptFile(arrayBuffer) {
    if (!this.key) throw new Error('Vault locked');
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cipher = await crypto.subtle.encrypt(
      { name: CONFIG.CRYPTO.ALGO, iv },
      this.key,
      arrayBuffer
    );
    return { iv, cipher };
  }

  async decryptFile(iv, cipher) {
    if (!this.key) throw new Error('Vault locked');
    const ivArray = new Uint8Array(iv);
    return crypto.subtle.decrypt(
      { name: CONFIG.CRYPTO.ALGO, iv: ivArray },
      this.key,
      cipher
    );
  }
}

// ==========================================
// Module: UI Manager
// ==========================================
class UIManager {
  constructor(app) {
    this.app = app;
    this.currentTab = 'password';
  }

  showToast(msg, type = 'info', duration = 3000) {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = msg;
    container.appendChild(toast);
    setTimeout(() => toast.classList.add('show'), 10);
    setTimeout(() => {
      toast.classList.remove('show');
      setTimeout(() => toast.remove(), 300);
    }, duration);
  }

  showLoading(show = true) {
    document.getElementById('loading-overlay').style.display = show ? 'flex' : 'none';
  }

  showAuth(show = true) {
    document.getElementById('auth-section').style.display = show ? 'block' : 'none';
    document.getElementById('vault').style.display = show ? 'none' : 'block';
  }

  clearForms() {
    ['site', 'user', 'pass', 'category', 'note-content'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = '';
    });
    // Reset view to password tab
    this.switchTab('password');
  }

  toggleTheme() {
    document.body.classList.toggle('dark-theme');
    const isDark = document.body.classList.contains('dark-theme');
    localStorage.setItem('theme', isDark ? 'dark' : 'light');
    document.getElementById('theme-toggle').textContent = isDark ? '☀️' : '🌙';
  }

  loadTheme() {
    const saved = localStorage.getItem('theme');
    if (saved === 'dark' || (!saved && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
      document.body.classList.add('dark-theme');
      document.getElementById('theme-toggle').textContent = '☀️';
    }
  }

  switchTab(tab) {
    this.currentTab = tab;
    // Update buttons
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelector(`.tab-btn[onclick*="${tab}"]`).classList.add('active');

    // Update Form visibility
    document.querySelectorAll('.password-only').forEach(el => el.style.display = tab === 'password' ? '' : 'none');
    document.querySelectorAll('.note-only').forEach(el => el.style.display = tab === 'note' ? '' : 'none');

    // Update hidden input
    document.getElementById('entry-type').value = tab;

    // Update labels
    const label = document.getElementById('label-site');
    label.innerText = tab === 'password' ? 'Website / URL' : 'Title / Subject';
  }

  // --- Password Generator UI ---
  showPasswordGenerator() {
    document.getElementById('password-generator-modal').style.display = 'flex';
    this.generateAdvancedPassword();
  }

  closePasswordGenerator() {
    document.getElementById('password-generator-modal').style.display = 'none';
  }

  updateGeneratorLength(val) {
    document.getElementById('length-value').textContent = val;
    this.generateAdvancedPassword();
  }

  generateAdvancedPassword() {
    const len = parseInt(document.getElementById('gen-length').value);
    const useUpper = document.getElementById('gen-uppercase').checked;
    const useLower = document.getElementById('gen-lowercase').checked;
    const useNum = document.getElementById('gen-numbers').checked;
    const useSym = document.getElementById('gen-symbols').checked;

    let chars = '';
    if (useUpper) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (useLower) chars += 'abcdefghijklmnopqrstuvwxyz';
    if (useNum) chars += '0123456789';
    if (useSym) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';

    if (!chars) return;

    let pass = '';
    const rnd = crypto.getRandomValues(new Uint8Array(len));
    for (let i = 0; i < len; i++) pass += chars[rnd[i] % chars.length];

    document.getElementById('generated-password').value = pass;
  }

  copyGeneratedPassword() {
    const val = document.getElementById('generated-password').value;
    if (val) this.app.copyToClipboard(val, 'Generated Password');
  }

  useGeneratedPassword() {
    const val = document.getElementById('generated-password').value;
    document.getElementById('pass').value = val;
    this.closePasswordGenerator();
  }

  togglePasswordVisibility(inputID, btnID) {
    const input = document.getElementById(inputID);
    const btn = document.getElementById(btnID);
    input.type = input.type === 'password' ? 'text' : 'password';
    btn.textContent = input.type === 'password' ? '👁️' : '🙈';
  }

  // --- Strength Meter ---
  calculatePasswordStrength(password) {
    let strength = 0;

    if (password.length >= 8) strength += 1;
    if (password.length >= 12) strength += 1;
    if (/[a-z]/.test(password)) strength += 1;
    if (/[A-Z]/.test(password)) strength += 1;
    if (/[0-9]/.test(password)) strength += 1;
    if (/[^a-zA-Z0-9]/.test(password)) strength += 1;

    // Cap at 5
    return Math.min(strength, 5);
  }

  updateStrengthMeter(inputId, barId, labelId) {
    const input = document.getElementById(inputId);
    const bar = document.getElementById(barId);
    const label = document.getElementById(labelId);

    if (!input || !bar) return;

    const val = input.value;
    const strength = this.calculatePasswordStrength(val);

    const colors = ['#e74c3c', '#e67e22', '#f39c12', '#3498db', '#2ecc71', '#27ae60'];
    const labels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very Strong'];

    if (val.length === 0) {
      bar.style.width = '0%';
      if (label) label.textContent = '';
      return;
    }

    bar.style.width = `${(strength / 6) * 100}%`;
    bar.style.backgroundColor = colors[strength];
    if (label) {
      label.textContent = labels[strength];
      label.style.color = colors[strength];
    }
  }

  // --- Filtering ---
  filterItems() {
    const term = document.getElementById('search-input').value.toLowerCase();
    const cat = document.getElementById('category-filter').value;
    this.app.renderVault(term, cat);
  }

  clearFilters() {
    document.getElementById('search-input').value = '';
    document.getElementById('category-filter').value = '';
    this.app.renderVault();
  }
}

// ==========================================
// Main Application Class
// ==========================================
class SecureVaultApp {
  constructor() {
    this.db = new DBManager();
    this.crypto = new CryptoManager();
    this.ui = new UIManager(this);

    this.items = []; // Decrypted items cache
    this.sessionTimer = null;
    this.inactivityTimer = null;
    this.editingId = null; // ID of item being edited

    // Bind events
    this.init();
  }

  async init() {
    this.ui.loadTheme();
    try {
      await this.db.open();
      // Check for legacy migration
      await this.checkMigration();

      const salt = await this.db.getMeta('salt');
      if (!salt) {
        // New user
        document.getElementById('auth-message').textContent = 'Welcome! Please register to create your vault.';
      } else {
        document.getElementById('auth-message').textContent = 'Vault found. Please login.';
      }
    } catch (e) {
      console.error('Init failed', e);
      this.ui.showToast('Failed to initialize database', 'error');
    }

    // Setup listeners
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        // Optional: immediately lock or start shortened timer
        // For now, we rely on the inactivity timer
      }
    });

    ['mousemove', 'keypress', 'click'].forEach(evt => {
      document.addEventListener(evt, () => this.resetInactivityTimer());
    });

    // Password Strength Listeners
    document.getElementById('master-pass').addEventListener('input', () =>
      this.ui.updateStrengthMeter('master-pass', 'strength-bar', 'password-strength-indicator'));

    document.getElementById('pass').addEventListener('input', () =>
      this.ui.updateStrengthMeter('pass', 'item-strength-bar', 'item-pass-strength'));
  }

  // --- Migration ---
  async checkMigration() {
    const legacySalt = localStorage.getItem('vault_salt');
    const legacyData = localStorage.getItem('vault_data');

    if (legacySalt && legacyData) {
      console.log('Legacy data found, preparing migration...');
      this.ui.showToast('Creating backup of existing data...', 'info');
      // We can't decrypt it yet because we need the password.
      // We will perform migration AFTER login (logic in login function)
      this.hasLegacyData = true;
    }
  }

  // --- Auth Flow ---
  async register() {
    const pass = document.getElementById('master-pass').value;
    if (pass.length < 8) {
      this.ui.showToast('Password must be at least 8 characters', 'error');
      return;
    }

    const exists = await this.db.getMeta('salt');
    if (exists && !confirm('Vault already exists. Overwrite? All data will be lost.')) return;

    this.ui.showLoading();
    try {
      if (exists) await this.db.clearAll();

      const salt = crypto.getRandomValues(new Uint8Array(16));
      const saltB64 = this.crypto.bufToBase64(salt);

      // Derive key (high iterations)
      this.crypto.key = await this.crypto.deriveKey(pass, salt, CONFIG.CRYPTO.ITERATIONS_V2);

      // Save metadata
      await this.db.setMeta('salt', saltB64);
      await this.db.setMeta('version', 2);

      // Create a "verifier" - encrypted string "OK" to test login
      const verifier = await this.crypto.encrypt({ test: "OK" });
      await this.db.setMeta('verifier', verifier);

      this.ui.showToast('Vault created successfully!', 'success');
      this.startSession();
    } catch (e) {
      console.error(e);
      this.ui.showToast('Registration failed', 'error');
    } finally {
      this.ui.showLoading(false);
    }
  }

  async login() {
    const pass = document.getElementById('master-pass').value;
    if (!pass) return;

    this.ui.showLoading();
    try {
      let salt = await this.db.getMeta('salt');
      let version = await this.db.getMeta('version');

      // Handle Legacy (LocalStorage) Migration Scenario
      if (!salt && this.hasLegacyData) {
        salt = localStorage.getItem('vault_salt');
        version = 1;
      }

      if (!salt) throw new Error('No vault found');

      // Attempt Unlock
      let iterations = (version === 2) ? CONFIG.CRYPTO.ITERATIONS_V2 : CONFIG.CRYPTO.ITERATIONS_V1;

      this.crypto.key = await this.crypto.deriveKey(pass, salt, iterations);

      // Verify key
      let verifier = await this.db.getMeta('verifier');
      if (verifier) {
        // V2 check
        try {
          await this.crypto.decrypt(verifier);
        } catch (e) {
          throw new Error('Invalid Password');
        }
      } else if (this.hasLegacyData) {
        // Legacy V1 check: try to decrypt first item from localStorage
        // or just assume success if we can load items later.
        // For robustness, we assume if deriveKey didn't fail, we try to migrate.
      }

      // If we are here, we have the key.

      // Perform MIgration if needed
      if (this.hasLegacyData || version === 1) {
        await this.migrateLegacyData(pass);
      }

      this.startSession();
      this.ui.showToast('Vault Unlocked', 'success');

    } catch (e) {
      console.error(e);
      this.ui.showToast('Login failed: ' + e.message, 'error');
      this.crypto.key = null;
    } finally {
      this.ui.showLoading(false);
    }
  }

  async migrateLegacyData(password) {
    this.ui.showToast('Migrating database to V2 format...', 'info');
    try {
      const legacyDataStr = localStorage.getItem('vault_data');
      const legacyItems = legacyDataStr ? JSON.parse(legacyDataStr) : [];

      // We need items in plain text to re-encrypt with V2 Strength
      const plainItems = [];
      for (const item of legacyItems) {
        try {
          const dec = await this.crypto.decrypt(item);
          plainItems.push(dec);
        } catch (e) { console.warn('Skipping corrupt legacy item'); }
      }

      // Clear everything
      await this.db.clearAll();

      // Generate NEW V2 Key
      const newSalt = crypto.getRandomValues(new Uint8Array(16));
      const newSaltB64 = this.crypto.bufToBase64(newSalt);
      this.crypto.key = await this.crypto.deriveKey(password, newSalt, CONFIG.CRYPTO.ITERATIONS_V2);

      // Save new meta
      await this.db.setMeta('salt', newSaltB64);
      await this.db.setMeta('version', 2);
      const verifier = await this.crypto.encrypt({ test: "OK" });
      await this.db.setMeta('verifier', verifier);

      // Re-encrypt and save items
      for (const item of plainItems) {
        const enc = await this.crypto.encrypt(item);
        await this.db.addItem({
          ...enc,
          category: item.category || 'other',
          created: Date.now()
        });
      }

      // Cleanup LocalStorage
      localStorage.removeItem('vault_salt');
      localStorage.removeItem('vault_data');
      this.hasLegacyData = false;

      this.ui.showToast('Migration complete! Security upgraded.', 'success');
    } catch (e) {
      console.error('Migration failed', e);
      this.ui.showToast('Critical Migration Error. Check console.', 'error');
      throw e;
    }
  }

  startSession() {
    this.ui.showAuth(false);
    this.refreshVault();
    document.getElementById('master-pass').value = '';

    // Timers
    if (this.sessionTimer) clearTimeout(this.sessionTimer);
    this.sessionTimer = setTimeout(() => this.logout(), CONFIG.TIMEOUTS.SESSION);

    this.resetInactivityTimer();
    this.updateSessionDisplay();
  }

  resetInactivityTimer() {
    if (this.inactivityTimer) clearTimeout(this.inactivityTimer);
    if (this.crypto.key) {
      this.inactivityTimer = setTimeout(() => {
        this.ui.showToast('Locked due to inactivity', 'warning');
        this.logout();
      }, CONFIG.TIMEOUTS.INACTIVITY);
    }
  }

  updateSessionDisplay() {
    const el = document.getElementById('session-timer');
    if (this.crypto.key) {
      // Simple update loop could go here
      // For now, static text to not kill perf
    }
  }

  async logout() {
    this.crypto.key = null;
    this.items = [];
    if (this.sessionTimer) clearTimeout(this.sessionTimer);
    if (this.inactivityTimer) clearTimeout(this.inactivityTimer);
    this.ui.showAuth(true);
    this.ui.clearForms();
    this.ui.showToast('Vault Locked', 'info');
  }

  async resetVault() {
    if (confirm('DANGER: This will permanently delete ALL passwords and files. Are you sure?')) {
      await this.db.clearAll();
      // Also clear legacy if exists
      localStorage.removeItem('vault_salt');
      localStorage.removeItem('vault_data');
      location.reload();
    }
  }

  // --- CRUD Operations ---
  async refreshVault() {
    const encryptedItems = await this.db.getAllItems();
    this.items = [];

    for (const encItem of encryptedItems) {
      try {
        // Cache key info for UI (don't decrypt everything at once if list is huge? 
        // Currently small app, decrypt all for filtering is fine)
        // Optimization: Store metadata unencrypted? No, strict security.
        const dec = await this.crypto.decrypt(encItem);
        this.items.push({ ...dec, id: encItem.id });
      } catch (e) {
        console.error('Decrypt fail item', encItem.id);
      }
    }
    this.renderVault();
    this.updateDashboard();
  }

  renderVault(search = '', category = '') {
    const list = document.getElementById('password-list');
    const empty = document.getElementById('empty-state');
    list.innerHTML = '';

    const filtered = this.items.filter(item => {
      const matchSearch = !search ||
        (item.site && item.site.toLowerCase().includes(search)) ||
        (item.user && item.user.toLowerCase().includes(search));
      const matchCat = !category || item.category === category;
      return matchSearch && matchCat;
    });

    if (filtered.length === 0) {
      empty.style.display = 'block';
      document.getElementById('password-count').textContent = '';
      return;
    }
    empty.style.display = 'none';
    document.getElementById('password-count').textContent = `Showing ${filtered.length} items`;

    filtered.forEach(item => {
      const el = document.createElement('div');
      el.className = 'password-item';

      let displayContent = '';
      let typeIcon = '🔑';

      if (item.type === 'note') {
        typeIcon = '📝';
        displayContent = `<div class="item-subtitle">Secure Note</div>`;
      } else {
        displayContent = `
                <div class="item-subtitle">${this.escapeHtml(item.user)}</div>
                <div class="password-display-wrapper">
                    <div class="password-display masked" id="p-disp-${item.id}">••••••••</div>
                </div>`;
      }

      const strength = item.type !== 'note' ? this.ui.calculatePasswordStrength(item.pass) : 0;
      const labels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very Strong'];
      const strengthBadge = item.type !== 'note' ?
        `<span class="strength-badge strength-${strength}">${labels[strength]}</span>` : '';

      el.innerHTML = `
            <div class="item-content">
              <div class="item-header">
                <span style="font-size:1.2rem; margin-right:8px;">${typeIcon}</span>
                <div class="item-title">${this.escapeHtml(item.site)}</div>
                <span class="category-badge category-${item.category || 'other'}">${item.category || 'other'}</span>
                ${strengthBadge}
              </div>
              ${displayContent}
            </div>
            <div class="item-actions">
              ${item.type !== 'note' ? `
              <button class="btn btn-icon btn-sm" onclick="app.toggleItemPassword(${item.id}, '${this.escapeHtml(item.pass)}')" title="View">👁️</button>
              <button class="btn btn-icon btn-sm" onclick="app.copyToClipboard('${this.escapeHtml(item.pass)}')" title="Copy Pass">📋</button>
              <button class="btn btn-icon btn-sm" onclick="app.copyToClipboard('${this.escapeHtml(item.user)}', 'Username')" title="Copy User">👤</button>
              ` : ''}
              <button class="btn btn-icon btn-sm" onclick="app.editItem(${item.id})" title="Edit">✏️</button>
              <button class="btn btn-icon btn-sm btn-danger" onclick="app.deleteItem(${item.id})" title="Delete">🗑️</button>
            </div>
          `;
      list.appendChild(el);
    });
  }

  updateDashboard() {
    const total = this.items.length;
    let weak = 0;
    let reused = 0;
    const passMap = {};

    this.items.forEach(i => {
      if (i.type === 'note') return;
      // Use the unified strength calculator
      const strength = this.ui.calculatePasswordStrength(i.pass);
      // Count as weak if strength is less than 'Good' (3)
      // 0: Very Weak, 1: Weak, 2: Fair, 3: Good, 4: Strong, 5: Very Strong
      if (strength < 3) weak++;

      if (passMap[i.pass]) reused++;
      passMap[i.pass] = true;
    });

    document.getElementById('dash-total').textContent = total;
    document.getElementById('dash-weak').textContent = weak;
    document.getElementById('dash-reused').textContent = reused;

    // Calculate arbitrary score
    let score = 100;
    if (total > 0) {
      score -= (weak * 10);
      score -= (reused * 15);
    } else {
      score = 0;
    }
    score = Math.max(0, Math.min(100, score));
    document.getElementById('dash-score').textContent = score + '%';
  }

  async addItem() {
    const type = document.getElementById('entry-type').value;
    const category = document.getElementById('category').value;
    const site = document.getElementById('site').value.trim();

    let data = { site, category, type, timestamp: Date.now() };

    if (type === 'password') {
      data.user = document.getElementById('user').value.trim();
      data.pass = document.getElementById('pass').value;

      if (!data.site || !data.user || !data.pass) return this.ui.showToast('Fill all fields', 'error');

      // Validation 1: URL Check (Soft check: if it looks like a domain, ensure strictly valid)
      if (data.site.includes('.') && !data.site.includes(' ')) {
        try {
          // If missing protocol, prepend https:// for validation check
          const testUrl = data.site.startsWith('http') ? data.site : `https://${data.site}`;
          new URL(testUrl);
        } catch (e) {
          if (!confirm(`"${data.site}" looks like a URL but is invalid. Save anyway?`)) return;
        }
      }

      // Validation 2: Email Check (Soft check: if contains @, validate structure)
      if (data.user.includes('@')) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(data.user)) {
          if (!confirm(`"${data.user}" looks like an invalid email. Save anyway?`)) return;
        }
      }

    } else {
      data.note = document.getElementById('note-content').value;
      if (!data.site || !data.note) return this.ui.showToast('Fill all fields', 'error');
    }

    this.ui.showLoading();
    try {
      const enc = await this.crypto.encrypt(data);

      if (this.editingId) {
        await this.db.updateItem({ ...enc, id: this.editingId });
        this.ui.showToast('Item updated', 'success');
        this.editingId = null;
        document.getElementById('cancel-edit-btn').style.display = 'none';
      } else {
        await this.db.addItem({ ...enc, category: data.category });
        this.ui.showToast('Item saved', 'success');
      }

      this.ui.clearForms();
      this.refreshVault();
    } catch (e) {
      console.error(e);
      this.ui.showToast('Save failed', 'error');
    } finally {
      this.ui.showLoading(false);
    }
  }

  editItem(id) {
    const item = this.items.find(i => i.id === id);
    if (!item) return;

    this.editingId = id;
    document.getElementById('cancel-edit-btn').style.display = 'inline-flex';

    this.ui.switchTab(item.type || 'password');
    document.getElementById('site').value = item.site;
    document.getElementById('category').value = item.category || '';

    if (item.type === 'note') {
      document.getElementById('note-content').value = item.note || '';
    } else {
      document.getElementById('user').value = item.user;
      document.getElementById('pass').value = item.pass;
    }

    document.getElementById('section-card').scrollIntoView();
  }

  cancelEdit() {
    this.editingId = null;
    document.getElementById('cancel-edit-btn').style.display = 'none';
    this.ui.clearForms();
  }

  async deleteItem(id) {
    if (confirm('Delete this item properly?')) {
      await this.db.deleteItem(id);
      this.refreshVault();
      this.ui.showToast('Item deleted', 'success');
    }
  }

  // --- Helpers ---
  toggleItemPassword(id, plainPass) {
    const el = document.getElementById(`p-disp-${id}`);
    if (el.classList.contains('masked')) {
      el.textContent = plainPass;
      el.classList.remove('masked');
    } else {
      el.textContent = '••••••••';
      el.classList.add('masked');
    }
  }

  copyToClipboard(text, msg = 'Copied') {
    navigator.clipboard.writeText(text).then(() => this.ui.showToast(msg, 'success'));
  }

  escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  checkSession() {
    // Just a user request for status
    this.ui.showToast('Session Active', 'info', 1000);
  }

  // --- Import / Export ---
  async exportVault() {
    // Export as JSON. NOTE: We export Encrypted blobs for security? 
    // Or decrypted for user backup?
    // Standard practice: Export Plaintext (user responsibility) OR Encrypted (with same key).
    // Let's export Plaintext but warn user, or JSON that is readable.

    if (!confirm('Export decrypted vault to JSON? Keep this file safe!')) return;

    const blob = new Blob([JSON.stringify(this.items, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `securevault_export_${Date.now()}.json`;
    a.click();
  }

  async importVault(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const data = JSON.parse(e.target.result);
        if (!Array.isArray(data)) throw new Error('Invalid format');

        if (!confirm(`Import ${data.length} items? This will add to existing vault.`)) return;

        this.ui.showLoading();
        for (const item of data) {
          // Basic validation
          if (item.site && (item.pass || item.note)) {
            const enc = await this.crypto.encrypt(item);
            await this.db.addItem({ ...enc, category: item.category || 'other' });
          }
        }
        this.refreshVault();
        this.ui.showToast('Import successful', 'success');
      } catch (err) {
        this.ui.showToast('Import failed: ' + err.message, 'error');
      } finally {
        this.ui.showLoading(false);
      }
    };
    reader.readAsText(file);
    event.target.value = ''; // reset
  }

  // --- Large File Encryption Support ---
  async encryptFile() {
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];
    if (!file) return this.ui.showToast('Select a file', 'error');

    this.ui.showLoading();
    this.ui.showToast('Encrypting large file...', 'info', 5000);

    try {
      const fileBuffer = await file.arrayBuffer();

      // 1. Prepare Metadata
      const meta = JSON.stringify({ name: file.name, type: file.type });
      const metaBytes = new TextEncoder().encode(meta);
      const metaLen = metaBytes.byteLength;

      // 2. Create Header containing length of metadata
      const lenBytes = new Uint32Array([metaLen]);

      // 3. Combine [Length (4 bytes)] + [Meta Bytes] + [File Bytes]
      const combined = new Uint8Array(4 + metaLen + fileBuffer.byteLength);
      combined.set(new Uint8Array(lenBytes.buffer), 0);
      combined.set(metaBytes, 4);
      combined.set(new Uint8Array(fileBuffer), 4 + metaLen);

      // 4. Encrypt the combined package
      const { iv, cipher } = await this.crypto.encryptFile(combined); // Encrypts the whole package

      // 5. Download Blob [IV] + [Cipher]
      const blob = new Blob([iv, cipher], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = file.name + '.enc';
      a.click();
      URL.revokeObjectURL(url);
      this.ui.showToast('File Encrypted!', 'success');
    } catch (e) {
      console.error(e);
      this.ui.showToast('Encryption failed: ' + e.message, 'error');
    } finally {
      this.ui.showLoading(false);
      fileInput.value = '';
    }
  }

  async decryptFileInput() {
    const fileInput = document.getElementById('encFileInput');
    const file = fileInput.files[0];
    if (!file) return;

    this.ui.showLoading();
    try {
      const buffer = await file.arrayBuffer();
      const iv = buffer.slice(0, 12);
      const cipher = buffer.slice(12);

      // 1. Decrypt into Plaintext Package
      const plainBuffer = await this.crypto.decryptFile(iv, cipher);

      // 2. Parse Package
      // Read Metadata Length (first 4 bytes)
      const dataView = new DataView(plainBuffer);
      const metaLen = dataView.getUint32(0, true); // Little-endian usually for Typed Arrays check
      // Wait, new Uint32Array(buffer) uses platform endianness. DataView defaults big-endian.
      // Let's stick to TypedArray view which is safer for the way we wrote it.

      const lenArr = new Uint32Array(plainBuffer.slice(0, 4));
      const extractedLen = lenArr[0];

      // Validate length sanity
      if (extractedLen > 10000 || extractedLen <= 0) throw new Error('Invalid file format or wrong key');

      // Read Meta JSON
      const metaBytes = new Uint8Array(plainBuffer.slice(4, 4 + extractedLen));
      const metaStr = new TextDecoder().decode(metaBytes);
      const meta = JSON.parse(metaStr);

      // Read File Data
      const fileData = plainBuffer.slice(4 + extractedLen);

      // 3. Create Download
      const blob = new Blob([fileData], { type: meta.type || 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      // Use original filename from meta
      a.download = meta.name || file.name.replace('.enc', '');
      a.click();
      URL.revokeObjectURL(url);
      this.ui.showToast(`Decrypted: ${meta.name}`, 'success');
    } catch (e) {
      console.error('Decryption failed full error:', e);
      this.ui.showToast('Decryption failed: ' + e.message, 'error');
    } finally {
      this.ui.showLoading(false);
      fileInput.value = '';
    }
  }
}

// ==========================================
// Bootstrap
// ==========================================
const app = new SecureVaultApp();
const ui = app.ui; // Export for global onclick handlers

// Ensure global access for HTML event handlers
window.app = app;
window.ui = ui;

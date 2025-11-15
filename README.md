# 🔐 SecureVault - Professional Password Manager & File Protection

A modern, secure, client-side password manager and file encryption tool built with vanilla JavaScript. All encryption happens locally in your browser - your data never leaves your device.

## ✨ Features

### 🔒 Security Features
- **AES-256-GCM Encryption** - Military-grade encryption for all data
- **PBKDF2 Key Derivation** - 100,000 iterations for master password hashing
- **Session Management** - Auto-logout after 30 minutes of inactivity
- **Rate Limiting** - Protection against brute force attacks (5 attempts per 15 minutes)
- **Clipboard Auto-Clear** - Automatically clears clipboard after 30 seconds
- **Password Strength Meter** - Real-time password strength analysis
- **Secure Storage** - All data encrypted before storage in LocalStorage

### 🎨 Professional UI/UX
- **Modern Design** - Clean, professional interface with smooth animations
- **Dark Mode** - Full dark theme support with system preference detection
- **Responsive Design** - Works perfectly on desktop, tablet, and mobile
- **Toast Notifications** - Beautiful, non-intrusive notifications
- **Loading States** - Visual feedback during async operations
- **Accessibility** - ARIA labels, keyboard navigation, screen reader support

### 🚀 Advanced Features
- **Password Categories** - Organize passwords by category (Work, Personal, Finance, etc.)
- **Search & Filter** - Quickly find passwords by name or category
- **Edit Passwords** - Update existing password entries
- **Advanced Password Generator** - Customizable length and character types
- **Copy Username** - One-click copy for usernames
- **Export/Import** - Backup and restore your vault
- **File Encryption** - Encrypt any file with AES-256-GCM
- **Session Timer** - Visual countdown showing remaining session time

### 🛡️ Bug Fixes & Improvements
- ✅ Fixed password visibility toggle issues
- ✅ Added proper error handling for storage quota exceeded
- ✅ Improved file encryption for large files
- ✅ Added input validation and sanitization
- ✅ Fixed import/export functionality
- ✅ Added confirmation dialogs for destructive actions
- ✅ Improved error messages and user feedback
- ✅ Fixed memory leaks in event listeners
- ✅ Added proper cleanup on logout

## 🚀 Getting Started

1. **Clone or Download** this repository
2. **Open** `index.html` in a modern web browser (Chrome, Firefox, Edge, Safari)
3. **Register** with a strong master password (minimum 8 characters)
4. **Start** adding passwords and encrypting files!

## 📖 Usage Guide

### First Time Setup
1. Enter a strong master password (the app will show strength feedback)
2. Click "Register" to create your vault
3. You'll be automatically logged in after registration

### Managing Passwords
- **Add Password**: Fill in the form with website, username, and password
- **Search**: Use the search bar to find passwords quickly
- **Filter**: Filter by category using the dropdown
- **Edit**: Click the edit button on any password entry
- **Copy**: Click copy buttons to copy password or username
- **Delete**: Click delete button (with confirmation)

### Password Generator
1. Click "Generate Password" button
2. Adjust length (8-64 characters)
3. Select character types (uppercase, lowercase, numbers, symbols)
4. Click "Use This Password" to apply to form

### File Encryption
1. **Encrypt**: Select a file and click "Encrypt & Download"
2. **Decrypt**: Select an encrypted `.enc` file and click "Decrypt & Download"
3. Files are encrypted with the same key as your vault

### Export/Import
- **Export**: Click "Export" to download a JSON backup of your vault
- **Import**: Click "Import" to restore from a backup (replaces current vault)

## 🔧 Technical Details

### Encryption
- **Algorithm**: AES-256-GCM
- **Key Derivation**: PBKDF2 with SHA-256, 100,000 iterations
- **IV**: Random 12-byte IV for each encryption operation
- **Salt**: Random 16-byte salt stored with vault

### Storage
- **Format**: Encrypted JSON in LocalStorage
- **Structure**: Array of encrypted password objects
- **Each Entry**: Contains IV and encrypted data (site, username, password, category, timestamp)

### Security Considerations
- Master password is never stored
- Encryption key is only kept in memory while session is active
- All data is encrypted before storage
- Session automatically expires after inactivity
- Clipboard is automatically cleared after copying passwords
- Rate limiting prevents brute force attacks

## 🎨 UI Features

### Themes
- **Light Mode**: Clean, professional light theme
- **Dark Mode**: Easy on the eyes dark theme
- **Auto-save**: Theme preference saved in LocalStorage

### Responsive Breakpoints
- **Desktop**: Full feature layout
- **Tablet**: Optimized for medium screens
- **Mobile**: Single column, touch-friendly

### Animations
- Smooth fade-in animations
- Hover effects on interactive elements
- Loading spinners for async operations
- Toast notification slide-ins

## 🐛 Bug Fixes

### Security Fixes
- ✅ Fixed password visibility persistence
- ✅ Added session timeout handling
- ✅ Implemented rate limiting
- ✅ Added clipboard auto-clear
- ✅ Fixed memory leaks in event handlers

### Functionality Fixes
- ✅ Fixed password editing (was creating duplicates)
- ✅ Fixed import validation
- ✅ Added proper error handling for large files
- ✅ Fixed storage quota exceeded errors
- ✅ Improved delete confirmation

### UI Fixes
- ✅ Fixed responsive layout issues
- ✅ Improved accessibility
- ✅ Fixed modal closing behavior
- ✅ Improved form validation feedback

## 🔮 Future Enhancements

Potential features for future versions:
- [ ] IndexedDB support for larger files
- [ ] Password expiration reminders
- [ ] Duplicate password detection
- [ ] Password sharing (encrypted)
- [ ] Two-factor authentication
- [ ] Browser extension
- [ ] Cloud sync (optional, encrypted)
- [ ] Password audit (check for weak/reused passwords)
- [ ] Biometric authentication
- [ ] Password history/versioning

## 📝 Development

### File Structure
```
securevault/
├── index.html      # Main HTML structure
├── script.js       # Application logic
├── style.css       # Styling and themes
└── README.md       # Documentation
```

### Browser Compatibility
- Chrome/Edge 90+
- Firefox 88+
- Safari 14+
- Requires Web Crypto API support

## ⚠️ Important Notes

1. **Backup Your Vault**: Regularly export your vault as a backup
2. **Master Password**: If you forget your master password, your data cannot be recovered
3. **Browser Storage**: Data is stored in browser LocalStorage - clearing browser data will delete your vault
4. **Security**: This is a client-side application - ensure you trust the source code
5. **Large Files**: File encryption works best with files under 100MB

## 📄 License

This project is provided as-is for educational and personal use.

## 🙏 Credits

Built with:
- Web Crypto API for encryption
- Inter font family for typography
- Modern CSS for styling
- Vanilla JavaScript (no dependencies)

---

**Made with ❤️ for secure password management**

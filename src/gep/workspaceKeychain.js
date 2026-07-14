// Keychain-backed workspace-id resolver (issue #111 Phase 1).
//
// Layered with paths.js#getWorkspaceId(). The current FS-only secret
// (`<workspace>/.evolver/workspace-id`, mode 0600) closes the *forgery*
// gap from PR #109 but leaves a *readability* gap: any process running
// under the same uid can still read the file and impersonate a workspace
// it does not own. This module gates that secret behind the OS keychain
// (macOS Keychain Services / libsecret on Linux / Windows Credential
// Manager) via the optional `@napi-rs/keyring` native addon.
//
// PLATFORM NOTES:
//
//   macOS  — backed by Keychain Services (Security.framework). Entries
//            are encrypted by the OS and scoped to the user login session.
//
//   Linux  — backed by libsecret / GNOME Keyring (or the secret-service
//            D-Bus protocol). Unavailable on headless servers without a
//            D-Bus session; the addon load will succeed but getPassword()
//            throws, causing `available: false` and transparent FS fallback.
//
//   Windows — backed by Windows Credential Manager (CredRead/CredWrite via
//            DPAPI-encrypted blobs). No extra installation needed when the
//            @napi-rs/keyring addon is present. If the addon is absent (bun
//            binary, stripped package, etc.) the resolver falls back to
//            plaintext FS storage — see WINDOWS SECURITY NOTE below.
//
// WINDOWS SECURITY NOTE (fallback path):
//   When @napi-rs/keyring is unavailable on Windows (addon load fails),
//   getWorkspaceId() falls back to a plaintext file at
//   <workspace>/.evolver/workspace-id.  On Windows, mode 0o600 passed to
//   fs.writeFileSync / fs.openSync is silently ignored, so the file is NOT
//   restricted to the current user at the filesystem ACL level.  The only
//   isolation boundary is the Windows user-profile directory
//   (%USERPROFILE%\.evolver or the workspace path), which is ACL-protected
//   by default but grants access to the SYSTEM account and local Admins.
//   This is weaker than the Unix 0o600 guarantee.  Install @napi-rs/keyring
//   or set EVOLVER_WORKSPACE_KEYCHAIN=force to surface the missing-addon
//   error rather than silently degrade to FS.
//
// The keychain dep is OPTIONAL — if `require()` fails (addon missing,
// headless Linux without libsecret, bun-compiled binary that hasn't
// sideloaded `.node` yet), the resolver returns null and paths.js
// transparently falls back to the existing FS implementation. Behavior
// for *every* deployment that doesn't actively opt in stays identical
// to v1.85.x.
//
// Mode is controlled by `EVOLVER_WORKSPACE_KEYCHAIN`:
//   - `auto` (default) — try keychain, fall back to FS on any failure.
//   - `force`           — keychain only; throw if unavailable. Use in
//                         CI to assert the addon is loaded.
//   - `off`             — skip keychain entirely; use FS path.
//
// Service / account naming:
//   service = "evomap.evolver.workspace-id"
//   account = absolute path to the workspace root
// The account is the workspace-root path because that's the natural
// identity boundary — multiple evolver installs sharing the same
// workspace root must resolve to the SAME secret (writer/reader parity,
// PR #109 round-1 MEDIUM).

const KEYCHAIN_SERVICE = 'evomap.evolver.workspace-id';

// 32 hex chars (16 random bytes) — same shape as the FS impl, kept
// strict so a legacy migration from FS into keychain validates cleanly.
const ID_RE = /^[a-f0-9]{32,}$/i;

let _cachedAddon = undefined; // undefined = not tried, null = failed, fn = ok

function loadAddon() {
  if (_cachedAddon !== undefined) return _cachedAddon;
  try {
    // eslint-disable-next-line global-require
    const mod = require('@napi-rs/keyring');
    if (mod && typeof mod.Entry === 'function') {
      // On Windows this uses the Credential Manager (DPAPI-backed) backend
      // from keyring-rs — no extra setup required when the addon is present.
      _cachedAddon = mod;
      return _cachedAddon;
    }
    // Addon present but does not expose the expected Entry constructor —
    // treat as unavailable; callers fall back to FS storage.
    _cachedAddon = null;
    return null;
  } catch {
    // Addon absent or failed to load (bun binary, stripped package, Windows
    // without the prebuilt .node, etc.).  On Windows this means Credential
    // Manager is NOT used and the secret falls back to a plaintext file —
    // see WINDOWS SECURITY NOTE at the top of this file.
    _cachedAddon = null;
    return null;
  }
}

function getMode() {
  const raw = String(process.env.EVOLVER_WORKSPACE_KEYCHAIN || 'auto').toLowerCase().trim();
  if (raw === 'force' || raw === 'off' || raw === 'auto') return raw;
  return 'auto';
}

// Patterns indicating a clean "entry not present" miss across the
// platform backends keyring-rs talks to:
//   - Linux libsecret   → "No matching entry found in secure storage"
//   - macOS Keychain    → "The specified item could not be found in the keychain"
//   - Windows Cred Mgr  → "Element not found"
// Anything else thrown by getPassword (locked keyring, no D-Bus, version
// mismatch, ambiguous entry, …) means the keychain itself isn't usable
// and MUST surface as `available: false` so callers — particularly
// `force` mode — can refuse to fall back to FS instead of silently
// papering over the failure (Bugbot PR #121 round-3 MEDIUM: dead code
// in force-mode unavailable path).
const NO_ENTRY_PATTERNS = [
  /no\s+matching\s+entry/i,        // libsecret
  /could\s+not\s+be\s+found/i,     // macOS
  /element\s+not\s+found/i,        // Windows
  /\bnoentry\b/i,                  // keyring-rs NoEntry (CamelCase)
  /\bno\s*entry\b/i,               // generic spaced "no entry"
  /not\s+found\s+in\s+(?:secure|keychain)/i,
];

function _isNoEntryError(err) {
  const msg = (err && err.message) || '';
  return NO_ENTRY_PATTERNS.some((re) => re.test(msg));
}

// Read the secret for `account` from the OS keychain.
// Returns:
//   { available: true,  id: "<32-hex>" }  on hit
//   { available: true,  id: null }         on clean miss (NoEntry-class throw)
//   { available: false, id: null }         when the addon isn't loaded OR
//                                          the keychain throws any non-
//                                          NoEntry error (locked, no
//                                          backend, version mismatch, …)
function readFromKeychain(account) {
  const addon = loadAddon();
  if (!addon) return { available: false, id: null };
  try {
    const entry = new addon.Entry(KEYCHAIN_SERVICE, account);
    const raw = entry.getPassword();
    if (typeof raw === 'string' && ID_RE.test(raw.trim())) {
      return { available: true, id: raw.trim() };
    }
    // getPassword resolved with empty / non-hex — treat as miss; the
    // keychain itself is responding so we stay "available".
    return { available: true, id: null };
  } catch (err) {
    if (_isNoEntryError(err)) return { available: true, id: null };
    return { available: false, id: null };
  }
}

// Persist `id` for `account` in the OS keychain. Returns true on
// success, false on any failure (callers fall back to FS).
function writeToKeychain(account, id) {
  const addon = loadAddon();
  if (!addon) return false;
  try {
    const entry = new addon.Entry(KEYCHAIN_SERVICE, account);
    entry.setPassword(id);
    return true;
  } catch {
    return false;
  }
}

module.exports = {
  KEYCHAIN_SERVICE,
  getMode,
  loadAddon,
  readFromKeychain,
  writeToKeychain,
  // Exported for test coverage of the NoEntry-vs-PlatformFailure
  // discrimination (Bugbot PR #121 round-3 MEDIUM).
  _isNoEntryError,
};

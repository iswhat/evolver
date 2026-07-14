const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { hubFetch } = require('./hubFetch');
const { withFileLock } = require('./assetStore');

function hmacSha256(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest('hex');
}

function hashCompact(input) {
  return crypto.createHash('sha256').update(String(input || '')).digest('hex').slice(0, 16);
}

function buildRequestPayload({ geneId, signals, mutation }) {
  let nodeSecret = null;
  try {
    nodeSecret = require('./a2aProtocol').getHubNodeSecret();
  } catch (e) {}
  if (!nodeSecret) return null;

  let nodeId = null;
  try {
    nodeId = require('./a2aProtocol').getNodeId();
  } catch (e) {}
  if (!nodeId) return null;

  const secretHash = crypto.createHash('sha256').update(nodeSecret).digest('hex');

  const ts = Date.now();
  const signalsHash = hashCompact(JSON.stringify(Array.isArray(signals) ? signals.slice(0, 8) : []));
  const mutationHash = hashCompact(JSON.stringify(mutation || {}));

  const challengeData = [nodeId, geneId || '', signalsHash, mutationHash, String(ts)].join('|');
  const clientSignature = hmacSha256(secretHash, challengeData);

  return {
    nodeId,
    nodeSecret,
    body: {
      sender_id: nodeId,
      gene_id: geneId || '',
      signals_hash: signalsHash,
      mutation_hash: mutationHash,
      ts: ts,
      client_signature: clientSignature,
    },
  };
}


function requestSolidifyPermit({ geneId, signals, mutation }) {
  const hubUrl = (process.env.A2A_HUB_URL || '').replace(/\/+$/, '');
  if (!hubUrl) return Promise.resolve({ ok: false, error: 'no_hub_url', offline: true });

  const req = buildRequestPayload({ geneId, signals, mutation });
  if (!req) return Promise.resolve({ ok: false, error: 'no_credentials', offline: true });

  const endpoint = hubUrl + '/a2a/verify-solidify';
  const timeoutMs = require('../config').HTTP_TRANSPORT_TIMEOUT_MS || 10000;

  const headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + req.nodeSecret,
  };

  return hubFetch(endpoint, {
    method: 'POST',
    headers: headers,
    body: JSON.stringify(req.body),
    signal: AbortSignal.timeout(timeoutMs),
  })
    .then(function (res) {
      // Any non-5xx response proves the hub's application layer answered, so
      // the daemon is not actually offline — refresh lastOnlineVerify even on
      // 4xx and on 2xx envelopes that report ok=false. Previously this only
      // fired in the {ok:true} success branch, so a long streak of envelope
      // errors (quota_exceeded, rate_limited, validation) or 4xx responses
      // (bad auth, forbidden) would let the offline-duration counter run
      // past MAX_OFFLINE_DURATION_MS (7d) and falsely block consumeOfflinePermit
      // with offline_duration_exceeded. 5xx is left out — it can be a CDN /
      // load balancer up while the hub itself is down, so the conservative
      // "treat as offline" semantic is preserved there.
      if (res.status < 500) {
        recordLastOnlineVerify();
      }
      if (!res.ok) {
        return res.text().then(function (t) {
          // 5xx = hub/infra down → treat as offline so consumeOfflinePermit fires.
          // 4xx = explicit rejection (bad auth, quota exceeded) → not offline.
          const offline = res.status >= 500;
          return { ok: false, error: 'HTTP ' + res.status + ': ' + t.slice(0, 200), offline };
        });
      }
      return res.json().then(function (result) {
        if (result && result.ok && result.offline_token) {
          cacheOfflineToken(result.offline_token);
        }
        return result;
      });
    })
    .catch(function (err) {
      return { ok: false, error: err.message, offline: true };
    });
}

// --- Offline token management ---

var _OFFLINE_TOKEN_FILE = null;
var _LAST_VERIFY_FILE = null;

function getMemDir() {
  try {
    return require('./paths').getMemoryDir();
  } catch (e) {
    try {
      return path.join(require('./paths').getRepoRoot(), '.evolver', 'memory');
    } catch (e2) {
      return path.join(process.cwd(), '.evolver', 'memory');
    }
  }
}

function offlineTokenPath() {
  if (!_OFFLINE_TOKEN_FILE) {
    _OFFLINE_TOKEN_FILE = path.join(getMemDir(), '.ot');
  }
  return _OFFLINE_TOKEN_FILE;
}

function lastVerifyPath() {
  if (!_LAST_VERIFY_FILE) {
    _LAST_VERIFY_FILE = path.join(getMemDir(), '.lv');
  }
  return _LAST_VERIFY_FILE;
}

// Offline token integrity (C2): the .ot file is an anti-tamper quota counter,
// not a credential — encryption is the wrong primitive. Sign the token with
// HMAC-SHA256 keyed off nodeSecret instead. A cloned install carries a stale
// secret-signed token; HMAC verification fails on the first offline read and
// the token is rejected. Online verification rotates the secret, so legit
// re-issuance is automatic.
function getNodeSecret() {
  // Env var first — matches a2aProtocol.getHubNodeSecret() priority and lets
  // the HMAC path work in environments where a2aProtocol can't be required.
  if (process.env.A2A_NODE_SECRET) return process.env.A2A_NODE_SECRET;
  try { return require('./a2aProtocol').getHubNodeSecret() || null; } catch (e) { return null; }
}

function cacheOfflineToken(token) {
  try {
    const nodeSecret = getNodeSecret();
    if (!nodeSecret) return;
    const dir = path.dirname(offlineTokenPath());
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    // HMAC stability: token field names must NOT be integer-like strings.
    // V8's JSON.stringify sorts integer-keyed properties numerically while
    // preserving insertion order for non-integer keys; an all-digit field
    // would re-order between cache and load and break verification.
    const data = JSON.stringify(token);
    const hmac = hmacSha256(nodeSecret, data);
    fs.writeFileSync(offlineTokenPath(), JSON.stringify({ data: token, hmac }), 'utf8');
  } catch (e) {}
}

function loadOfflineToken() {
  try {
    if (!fs.existsSync(offlineTokenPath())) return null;
    const stored = JSON.parse(fs.readFileSync(offlineTokenPath(), 'utf8'));
    if (!stored || !stored.data || typeof stored.hmac !== 'string') return null;
    const nodeSecret = getNodeSecret();
    if (!nodeSecret) return null;
    const expected = hmacSha256(nodeSecret, JSON.stringify(stored.data));
    // Hex-encode the HMAC bytes for comparison: 32-byte buffers, not 64-byte
    // ASCII representations. Length pre-check guards timingSafeEqual which
    // throws on mismatched lengths.
    const expBuf = Buffer.from(expected, 'hex');
    const gotBuf = Buffer.from(stored.hmac, 'hex');
    if (expBuf.length !== gotBuf.length || !crypto.timingSafeEqual(expBuf, gotBuf)) {
      return null;
    }
    return stored.data;
  } catch (e) {
    return null;
  }
}

function recordLastOnlineVerify() {
  try {
    const dir = path.dirname(lastVerifyPath());
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(lastVerifyPath(), String(Date.now()), 'utf8');
  } catch (e) {}
}

function getLastOnlineVerifyTs() {
  try {
    if (!fs.existsSync(lastVerifyPath())) return 0;
    return parseInt(fs.readFileSync(lastVerifyPath(), 'utf8'), 10) || 0;
  } catch (e) {
    return 0;
  }
}

var MAX_OFFLINE_SOLIDIFIES = 10;
var MAX_OFFLINE_DURATION_MS = 7 * 24 * 60 * 60 * 1000;
var MAX_CLOCK_DRIFT_MS = 24 * 60 * 60 * 1000;

// The offline-permit pipeline is `loadOfflineToken → check cap →
// cacheOfflineToken` (read → check → write). Within a single Node process
// the chain is synchronous so no intra-process race, but two cooperating
// processes (daemon + CLI `evolver solidify`) hitting the path at the same
// moment could both read the same `usedCount`, both pass the cap check,
// and both increment-and-write — the local counter then trailed reality
// and the offline quota could be exceeded by N for N concurrent callers.
// Hub-side enforcement catches this on the next online verify, but the
// audit posture is wrong locally.
//
// Reuse `withFileLock` from assetStore.js — same `src/gep/` directory,
// already battle-tested for multi-process read-modify-write of memory-dir
// files, and uses PID-liveness (`process.kill(pid, 0)`) for stale
// detection plus an Atomics-or-busy-wait fallback for the retry sleep.
// withFileLock throws on acquire timeout; we map that to a specific
// `offline_permit_busy` result so callers (daemon heartbeat / CLI
// solidify) can distinguish "contended" from "permit denied" and retry
// next cycle.
function consumeOfflinePermit() {
  // Ensure the memory directory exists before withFileLock tries to
  // create `<memDir>/.ot.lock`. Pre-refactor, the function always
  // returned a structured envelope (loadOfflineToken / cacheOfflineToken
  // both swallow errors internally); after the refactor a fresh install
  // without the memory dir would throw ENOENT from _acquireLock and
  // bubble past the Lock-timeout catch below, breaking the never-throw
  // contract (Bugbot PR #157 R2 Low).
  try {
    var dir = path.dirname(offlineTokenPath());
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  } catch (_) { /* fall through — caught by the wrapper below */ }

  try {
    return withFileLock(offlineTokenPath(), function () {
      var token = loadOfflineToken();
      if (!token) return { ok: false, error: 'no_offline_token', offline: true };

      var maxSolidifies = token.maxOfflineSolidifies || MAX_OFFLINE_SOLIDIFIES;
      var expiresAt = token.expiresAt || 0;
      var usedCount = token.usedCount || 0;
      var now = Date.now();

      var lastOnline = getLastOnlineVerifyTs();
      if (lastOnline > 0 && now < lastOnline - MAX_CLOCK_DRIFT_MS) {
        return { ok: false, error: 'clock_drift_detected', offline: true };
      }

      if (expiresAt > 0 && now > expiresAt) {
        return { ok: false, error: 'offline_token_expired', offline: true };
      }

      if (lastOnline > 0 && (now - lastOnline) > MAX_OFFLINE_DURATION_MS) {
        return { ok: false, error: 'offline_duration_exceeded', offline: true };
      }

      if (usedCount >= maxSolidifies) {
        return { ok: false, error: 'offline_quota_exhausted', offline: true };
      }

      token.usedCount = usedCount + 1;
      cacheOfflineToken(token);
      return { ok: true, offline: true, remaining: maxSolidifies - token.usedCount };
    });
  } catch (e) {
    // Preserve the "always returns a structured envelope" contract that
    // the pre-refactor consumeOfflinePermit had (loadOfflineToken and
    // cacheOfflineToken both swallowed FS errors internally).
    //
    // - "Lock timeout" → another process holds the lock past the
    //   acquire deadline. Surface as busy so the caller's heartbeat
    //   loop can retry on the next cycle.
    // - Any other error (ENOENT/EACCES on the lock file, FS misconfig)
    //   → report as offline_lock_failed with the original message
    //   truncated. The daemon's solidify.js call site treats !ok as
    //   a recoverable hint, not a crash trigger.
    var msg = (e && e.message) || String(e);
    if (msg.indexOf('Lock timeout') !== -1) {
      return { ok: false, error: 'offline_permit_busy', offline: true };
    }
    return { ok: false, error: 'offline_lock_failed', offline: true, detail: msg.slice(0, 200) };
  }
}

function isSolidifyVerifyEnabled() {
  if (process.env.NODE_ENV === 'test') {
    var v = (process.env.EVOLVER_SOLIDIFY_VERIFY || '').toLowerCase();
    if (v === 'false' || v === '0' || v === 'off') return false;
  }
  var hubUrl = process.env.A2A_HUB_URL || '';
  return !!hubUrl;
}

module.exports = {
  requestSolidifyPermit,
  isSolidifyVerifyEnabled,
  consumeOfflinePermit,
  getLastOnlineVerifyTs,
};

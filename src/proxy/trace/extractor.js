'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { sanitizePayload } = require('../../gep/sanitize');

const SCHEMA_VERSION = 1;
const DEFAULT_MAX_UPLOAD_BYTES = 4 * 1024 * 1024;
// Keep the collector-side field cap aligned with the upload ceiling. Anything beyond that is explicitly marked
// incomplete and withheld from warehouse upload instead of being sent as a preview that looks complete.
const DEFAULT_MAX_FIELD_BYTES = DEFAULT_MAX_UPLOAD_BYTES;
// Memory bound for the partial trailing SSE line held between stream chunks. Must be generous: the OpenAI
// Responses `response.completed` event (codex) packs the FULL response — output + usage + response.id — onto a
// single `data:` line with no internal newline, so a big codex turn produces one line far larger than a small
// cap. Slicing that line's `data:` prefix would make the final usage/responseId/finishReason unparseable.
const SSE_SCAN_BUFFER_MAX = DEFAULT_MAX_FIELD_BYTES;
const STREAM_EVENT_CAPTURE_LIMIT = 1000;
const STREAM_OVERSIZED_LINE_CAPTURE_MAX = DEFAULT_MAX_FIELD_BYTES;
const REDACTION_VERSION = 'evolver-redact-v2';
const SENSITIVE_KEY_RE = /(?:^|[_-])(?:api[_-]?key|token|secret|password|credential|authorization|auth|bearer|access[_-]?key|private[_-]?key|client[_-]?secret|refresh[_-]?token|id[_-]?token|session[_-]?(?:token|id)|user[_-]?id|device[_-]?id|cookie|dsn)(?:$|[_-])|(?:api[_-]?key|token|secret|password|credential|authorization|auth|private[_-]?key|session[_-]?id|user[_-]?id|device[_-]?id)$/i;
const NODE_SECRET_RE = /^[a-f0-9]{64}$/i;
// AES-256-GCM authentication tag length, pinned explicitly (matches the
// 16-byte default the code already relied on) so decrypt rejects a truncated
// tag instead of accepting a weaker authenticator (Semgrep gcm-no-tag-length,
// issue #285). Named constant mirrors crypto.js's TAG_BYTES.
const GCM_TAG_BYTES = 16;
const TRACE_UPLOAD_CURSOR_STATE_KEY = 'proxy_trace_upload_cursor_v1';
const DEFAULT_TRACE_BACKFILL_MAX_ROWS = 100;
const DEFAULT_TRACE_BACKFILL_MAX_SCAN_BYTES = 8 * 1024 * 1024;
const DEFAULT_TRACE_BACKFILL_MAX_LONG_LINE_BYTES = 16 * 1024 * 1024;
const TRACE_PRODUCER_GENERATION = 'v1';
const TRACE_PRODUCER_COMPONENT = 'proxy';
const DEFAULT_TRACE_BACKFILL_MAX_ENQUEUE_BYTES = 2 * 1024 * 1024;
const ensuredTraceDirs = new Set();
// Warn at most once per process when hub profile analysis is enabled but a trace row cannot carry a
// hub_key_envelope, so the hub (which keeps only secretHash) could never decrypt it. See validateTraceUpload.
let warnedHubUndecryptable = false;
const chmoddedTraceFiles = new Set();
const TRACE_UPLOAD_SKIP_WARN_COOLDOWN_MS = 60 * 1000;
const traceUploadSkipWarnedAt = new WeakMap();
let scheduledTraceUploadEnqueues = 0;
const scheduledTraceUploadRefIds = new Set();
const disabledTraceFiles = new Set();
const reportedTraceFailureCodes = new Set();
const CWD_PATTERNS = [
  /workspace\s*path[:=]\s*([A-Za-z]:[\\/][^\s"'\n\r\\]+|\/[^\s"'\n\r\\]+)/i,
  /(?:current|primary)\s+working\s+directory(?:\s+is)?[:=]?\s*([A-Za-z]:[\\/][^\s"'\n\r\\]+|\/[^\s"'\n\r\\]+)/i,
  /working\s+directory[:=]\s*([A-Za-z]:[\\/][^\s"'\n\r\\]+|\/[^\s"'\n\r\\]+)/i,
  /\bcwd[:=]\s*([A-Za-z]:[\\/][^\s"'\n\r\\]+|\/[^\s"'\n\r\\]+)/i,
  /<cwd>\s*([A-Za-z]:[\\/][^\s<\n\r]+|\/[^\s<\n\r]+)\s*<\/cwd>/i,
];

function storeState(store, key) {
  try {
    return store && typeof store.getState === 'function' ? store.getState(key) : null;
  } catch {
    return null;
  }
}

function truthyState(value) {
  return value === true || value === 'true' || value === 1 || value === '1';
}

function truthyEnv(value) {
  const raw = String(value || '').trim().toLowerCase();
  return raw === '1' || raw === 'true' || raw === 'on' || raw === 'yes';
}

function falseyState(value) {
  return value === false || value === 'false' || value === 0 || value === '0' || value === 'off';
}

function parseNodeSecretVersion(value) {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : null;
}

let cachedProducerVersion;

function getTraceProducerVersion() {
  if (cachedProducerVersion !== undefined) return cachedProducerVersion;
  try {
    cachedProducerVersion = String((require('../../../package.json') || {}).version || '').slice(0, 32) || null;
  } catch {
    cachedProducerVersion = null;
  }
  return cachedProducerVersion;
}

function traceProducerMetadata() {
  const version = getTraceProducerVersion();
  return {
    producer_generation: TRACE_PRODUCER_GENERATION,
    ...(version ? { producer_version: version } : {}),
    producer_component: TRACE_PRODUCER_COMPONENT,
  };
}

function readStateFromContext(ctx = {}, env = process.env) {
  if (ctx.store) {
    return {
      trace_collection_enabled: storeState(ctx.store, 'trace_collection_enabled'),
      proxy_trace_collection_enabled: storeState(ctx.store, 'proxy_trace_collection_enabled'),
      trace_profile_analysis_enabled: storeState(ctx.store, 'trace_profile_analysis_enabled'),
      proxy_trace_profile_analysis_enabled: storeState(ctx.store, 'proxy_trace_profile_analysis_enabled'),
      trace_hub_public_key: storeState(ctx.store, 'trace_hub_public_key'),
      proxy_trace_hub_public_key: storeState(ctx.store, 'proxy_trace_hub_public_key'),
      node_secret: storeState(ctx.store, 'node_secret'),
      node_secret_version: storeState(ctx.store, 'node_secret_version'),
      node_secret_source: storeState(ctx.store, 'node_secret_source'),
      node_secret_env_suppressed: storeState(ctx.store, 'node_secret_env_suppressed'),
      trace_node_secret_version_decrypt_enabled: storeState(ctx.store, 'trace_node_secret_version_decrypt_enabled'),
      proxy_trace_node_secret_version_decrypt_enabled: storeState(ctx.store, 'proxy_trace_node_secret_version_decrypt_enabled'),
      trace_hub_keyring_decrypt_enabled: storeState(ctx.store, 'trace_hub_keyring_decrypt_enabled'),
      proxy_trace_hub_keyring_decrypt_enabled: storeState(ctx.store, 'proxy_trace_hub_keyring_decrypt_enabled'),
    };
  }
  const home = getEvomapHome(env);
  return readJsonFile(path.join(home, 'mailbox', 'state.json')) || {};
}

function readTraceCollectionEnabled(env = process.env, ctx = {}) {
  const state = readStateFromContext(ctx, env);
  const value = state.trace_collection_enabled ?? state.proxy_trace_collection_enabled;
  if (falseyState(value)) return false;
  return true;
}

function readTraceProfileConfig(env = process.env, ctx = {}) {
  const state = readStateFromContext(ctx, env);
  const rawEnabled = state.trace_profile_analysis_enabled ?? state.proxy_trace_profile_analysis_enabled;
  const enabled = truthyState(rawEnabled);
  // Hub public key (wraps the row AES key so the hub can decrypt). The pinned env var wins; otherwise we
  // accept a key delivered by the hub — but ONLY from trace_hub_public_key in store state, which TraceControl
  // writes exclusively after verifying the config signature. The unsigned runtime `hub_public_key` field is
  // still ignored (TraceControl never stores it), so an unsigned/forged config can never inject a key.
  const publicKey = String(
    env.EVOMAP_PROXY_TRACE_HUB_PUBLIC_KEY
    || state.trace_hub_public_key
    || state.proxy_trace_hub_public_key
    || ''
  ).trim();
  return { enabled, publicKey };
}

function readTraceNodeSecretVersionDecryptEnabled(env = process.env, ctx = {}) {
  const state = readStateFromContext(ctx, env);
  const candidates = [
    env.EVOMAP_PROXY_TRACE_NODE_SECRET_VERSION_DECRYPT,
    env.EVOMAP_PROXY_TRACE_HUB_KEYRING_DECRYPT,
    state.trace_node_secret_version_decrypt_enabled,
    state.proxy_trace_node_secret_version_decrypt_enabled,
    state.trace_hub_keyring_decrypt_enabled,
    state.proxy_trace_hub_keyring_decrypt_enabled,
  ];
  const rawEnabled = candidates.find((value) => value !== undefined && value !== null && value !== '');
  return truthyState(rawEnabled);
}

function resolveTraceMode(env = process.env, ctx = {}) {
  const raw = String(env.EVOMAP_PROXY_TRACE || '').trim().toLowerCase();
  if (!readTraceCollectionEnabled(env, ctx)) return null;
  if (raw === '0' || raw === 'false' || raw === 'off' || raw === 'none') return null;
  if (truthyEnv(env.EVOLVER_LLM_TRACE_CAPTURE_BODIES) || truthyEnv(env.EVOMAP_PROXY_TRACE_CAPTURE_BODIES)) return 'full';
  if (raw === '1' || raw === 'true' || raw === 'metadata') return 'metadata';
  if (raw === 'full') return 'full';
  if (raw === '') return 'full';
  return 'metadata';
}

function pathApiForPlatform(platform = process.platform) {
  return platform === 'win32' ? path.win32 : path.posix;
}

function resolveTraceHome(env = process.env, platform = process.platform) {
  if (platform === 'win32') {
    if (env.USERPROFILE) return env.USERPROFILE;
    if (env.HOMEDRIVE && env.HOMEPATH) return env.HOMEDRIVE + env.HOMEPATH;
    if (env.HOME) return env.HOME;
    return os.homedir();
  }
  return env.HOME || os.homedir();
}

function resolveDefaultTraceDir(env = process.env, platform = process.platform) {
  const pathApi = pathApiForPlatform(platform);
  if (env.EVOLVER_SETTINGS_DIR) return env.EVOLVER_SETTINGS_DIR;
  const home = resolveTraceHome(env, platform);
  if (platform === 'win32') {
    const localAppData = env.LOCALAPPDATA || pathApi.join(home, 'AppData', 'Local');
    return pathApi.join(localAppData, 'EvoMap', 'Evolver');
  }
  if (platform === 'linux') {
    const stateHome = env.XDG_STATE_HOME || pathApi.join(home, '.local', 'state');
    return pathApi.join(stateHome, 'evomap');
  }
  return pathApi.join(home, '.evolver');
}

function resolveTraceFile(env = process.env, platform = process.platform) {
  if (env.EVOMAP_PROXY_TRACE_FILE) return env.EVOMAP_PROXY_TRACE_FILE;
  const pathApi = pathApiForPlatform(platform);
  const defaultFile = pathApi.join(resolveDefaultTraceDir(env, platform), 'proxy-traces.jsonl');
  if (platform === 'linux' && !env.EVOLVER_SETTINGS_DIR) {
    const legacyFile = pathApi.join(resolveTraceHome(env, platform), '.evolver', 'proxy-traces.jsonl');
    try {
      if (!fs.existsSync(defaultFile) && fs.existsSync(legacyFile)) return legacyFile;
    } catch {
      // Fall through to the new platform-native default when probing fails.
    }
  }
  return defaultFile;
}

function resolveMaxFieldBytes(env = process.env) {
  const raw = Number(env.EVOMAP_PROXY_TRACE_MAX_FIELD_BYTES);
  if (Number.isFinite(raw) && raw > 0) return Math.floor(raw);
  return DEFAULT_MAX_FIELD_BYTES;
}

function resolveTraceEncryption(env = process.env) {
  const raw = String(env.EVOMAP_PROXY_TRACE_ENCRYPTION || '').trim().toLowerCase();
  if (raw === '0' || raw === 'false' || raw === 'off' || raw === 'none') return false;
  return true;
}

function resolveTraceKey(env = process.env, ctx = {}) {
  return resolveTraceKeyFromEvomapSecret(env, ctx);
}

function readJsonFile(file) {
  try {
    if (!fs.existsSync(file)) return null;
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

function getEvomapHome(env = process.env) {
  return env.EVOLVER_HOME || path.join(env.HOME || os.homedir(), '.evomap');
}

function resolveEvomapNodeSecret(env = process.env, ctx = {}) {
  const state = readStateFromContext(ctx, env);
  const storeSecret = String(state?.node_secret || '').trim();
  const storeSource = String(state?.node_secret_source || '').trim();
  const envSuppressed = truthyState(state?.node_secret_env_suppressed);
  const envSecret = String(env.A2A_NODE_SECRET || env.EVOMAP_NODE_SECRET || '').trim();
  if (envSuppressed) return NODE_SECRET_RE.test(storeSecret) ? storeSecret : null;
  if (storeSource === 'hub_rotate' && NODE_SECRET_RE.test(storeSecret)) return storeSecret;
  if (NODE_SECRET_RE.test(envSecret)) return envSecret;
  if (NODE_SECRET_RE.test(storeSecret)) return storeSecret;
  const home = getEvomapHome(env);
  try {
    const legacy = fs.readFileSync(path.join(home, 'node_secret'), 'utf8').trim();
    if (NODE_SECRET_RE.test(legacy)) return legacy;
  } catch { /* no legacy secret */ }
  return null;
}

function resolveEvomapNodeSecretVersion(env = process.env, ctx = {}) {
  const state = readStateFromContext(ctx, env);
  const storeVersion = parseNodeSecretVersion(state?.node_secret_version);
  const storeSecret = String(state?.node_secret || '').trim();
  const storeSource = String(state?.node_secret_source || '').trim();
  const envSuppressed = truthyState(state?.node_secret_env_suppressed);
  const envSecret = String(env.A2A_NODE_SECRET || env.EVOMAP_NODE_SECRET || '').trim();
  const envVersion = parseNodeSecretVersion(env.A2A_NODE_SECRET_VERSION || env.EVOMAP_NODE_SECRET_VERSION);
  const validStoreSecret = NODE_SECRET_RE.test(storeSecret);
  if (envSuppressed) return validStoreSecret ? storeVersion : null;
  if (storeSource === 'hub_rotate' && validStoreSecret) return storeVersion;
  if (NODE_SECRET_RE.test(envSecret)) {
    if (envVersion) return envVersion;
    if (storeSecret === envSecret && storeVersion) return storeVersion;
    const home = getEvomapHome(env);
    try {
      const legacySecret = fs.readFileSync(path.join(home, 'node_secret'), 'utf8').trim();
      if (legacySecret === envSecret) {
        return parseNodeSecretVersion(fs.readFileSync(path.join(home, 'node_secret_version'), 'utf8').trim());
      }
    } catch { /* no matching legacy secret/version pair */ }
    return null;
  }
  if (validStoreSecret) return storeVersion;
  const home = getEvomapHome(env);
  try {
    const legacySecret = fs.readFileSync(path.join(home, 'node_secret'), 'utf8').trim();
    if (NODE_SECRET_RE.test(legacySecret)) {
      return parseNodeSecretVersion(fs.readFileSync(path.join(home, 'node_secret_version'), 'utf8').trim());
    }
  } catch { /* no legacy version */ }
  return null;
}

function resolveTraceKeyFromEvomapSecret(env = process.env, ctx = {}) {
  const secret = resolveEvomapNodeSecret(env, ctx);
  if (!secret) return null;
  return crypto.createHash('sha256').update('evomap-proxy-trace-v1:' + secret, 'utf8').digest();
}

function encryptTraceEvent(event, env = process.env, ctx = {}) {
  const key = resolveTraceKey(env, ctx);
  if (!key) {
    throw new Error('EVOMAP_PROXY_TRACE_ENCRYPTION is enabled but EvoMap node secret is missing or invalid');
  }
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: GCM_TAG_BYTES });
  const plaintext = Buffer.from(JSON.stringify(event), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const envelope = {
    schema_version: SCHEMA_VERSION,
    prism_compatible: true,
    encrypted: true,
    payload_schema: 'prism_trace_row',
    algorithm: 'aes-256-gcm',
    key_id: crypto.createHash('sha256').update(key).digest('hex').slice(0, 16),
    ...traceProducerMetadata(),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
  if (event && event.payload_complete === false) {
    envelope.payload_complete = false;
    if (event.payload_incomplete_reason) envelope.payload_incomplete_reason = event.payload_incomplete_reason;
  }
  if (event && event.hub_uploadable === false) {
    envelope.hub_uploadable = false;
    if (event.hub_upload_blocked_reason) envelope.hub_upload_blocked_reason = event.hub_upload_blocked_reason;
    if (Number.isSafeInteger(event.hub_upload_size_bytes)) envelope.hub_upload_size_bytes = event.hub_upload_size_bytes;
    if (Number.isSafeInteger(event.hub_upload_max_bytes)) envelope.hub_upload_max_bytes = event.hub_upload_max_bytes;
  }
  const secretVersion = resolveEvomapNodeSecretVersion(env, ctx);
  if (secretVersion) envelope.secret_version = secretVersion;
  const hubEnvelope = wrapTraceKeyForHub(key, env, ctx);
  if (hubEnvelope) envelope.hub_key_envelope = hubEnvelope;
  return envelope;
}

function wrapTraceKeyForHub(key, env = process.env, ctx = {}) {
  const config = readTraceProfileConfig(env, ctx);
  if (!config.enabled || !config.publicKey) return null;
  try {
    const wrapped = crypto.publicEncrypt(
      {
        key: config.publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      key
    );
    return {
      algorithm: 'rsa-oaep-sha256',
      key_id: crypto.createHash('sha256').update(config.publicKey).digest('hex').slice(0, 16),
      wrapped_key: wrapped.toString('base64'),
    };
  } catch {
    return null;
  }
}

function decryptTraceEnvelope(envelope, keyInput) {
  const raw = String(keyInput || '').trim();
  if (!NODE_SECRET_RE.test(raw)) throw new Error('invalid trace key');
  const key = crypto.createHash('sha256').update('evomap-proxy-trace-v1:' + raw, 'utf8').digest();
  const iv = Buffer.from(envelope.iv, 'base64');
  const tag = Buffer.from(envelope.tag, 'base64');
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: GCM_TAG_BYTES });
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8'));
}

function detectClient(headers = {}) {
  const lower = {};
  for (const [key, value] of Object.entries(headers || {})) {
    lower[String(key).toLowerCase()] = Array.isArray(value) ? value.join(' ') : String(value || '');
  }
  const text = [
    lower['user-agent'],
    lower['x-client-name'],
    lower['x-stainless-package-version'],
    lower['x-app'],
    lower['x-goog-api-client'],
  ].filter(Boolean).join(' ').toLowerCase();
  if (text.includes('cursor')) return 'cursor';
  if (text.includes('codex')) return 'codex';
  if (text.includes('opencode')) return 'opencode'; // before 'claude' — opencode using a Claude model still IS opencode
  if (text.includes('ollama')) return 'ollama';
  if (text.includes('kiro')) return 'kiro'; // before 'claude' — Kiro (Anthropic BYOK mode) still routes /v1/messages
  if (text.includes('claude')) return 'claude-code';
  // Gemini CLI / google-genai SDK; the x-goog-api-key header is also a strong Gemini signal.
  if (text.includes('gemini') || text.includes('google-genai') || text.includes('genai') || lower['x-goog-api-key']) return 'gemini';
  return 'unknown';
}

function getHeader(headers = {}, name) {
  const want = String(name).toLowerCase();
  for (const [key, value] of Object.entries(headers || {})) {
    if (String(key).toLowerCase() === want) {
      return Array.isArray(value) ? value.join(', ') : String(value || '');
    }
  }
  return '';
}

function clipString(value, maxBytes) {
  return clipStringWithState(value, maxBytes).value;
}

function clipStringWithState(value, maxBytes) {
  const s = String(value);
  const buf = Buffer.from(s, 'utf8');
  if (buf.length <= maxBytes) return { value: s, truncated: false };
  return {
    value: buf.subarray(0, maxBytes).toString('utf8') + `...[truncated ${buf.length - maxBytes} bytes]`,
    truncated: true,
  };
}

function hashTraceValue(value, prefix) {
  const text = String(value || '');
  if (!text) return '';
  return `${prefix || 'hash'}:${crypto.createHash('sha256').update(text, 'utf8').digest('hex').slice(0, 16)}`;
}

function redactString(value) {
  return String(value)
    .replace(/(^|\r?\n)([ \t]*(?:Cookie|Set-Cookie)\s*:\s*)[^\r\n]*/gi, '$1$2[redacted]')
    .replace(/(^|\r?\n)([ \t]*(?:Authorization|Proxy-Authorization)\s*:\s*)[^\r\n]*/gi, '$1$2[redacted]')
    .replace(/((?:["'])(?:Authorization|Proxy-Authorization)(?:["'])\s*:\s*(?:["']))(?:(?!["'])[^\r\n])*/gi, '$1[redacted]')
    .replace(/((?:\\["'])(?:Authorization|Proxy-Authorization)(?:\\["'])\s*:\s*(?:\\["']))(?:(?!\\["'])[^\r\n])*/gi, '$1[redacted]')
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, '[redacted-private-key]')
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/gi, 'Bearer [redacted]')
    .replace(/\b(?:sk-ant|sk|ak)-[A-Za-z0-9._~+/=-]{12,}/g, '[redacted-api-key]')
    .replace(/\bghp_[A-Za-z0-9_]{20,}\b/g, '[redacted-github-token]')
    .replace(/\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, '[redacted-github-token]')
    .replace(/\bxox[abcprs]-[A-Za-z0-9-]{10,}\b/g, '[redacted-slack-token]')
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, '[redacted-aws-key]')
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, '[redacted-jwt]')
    .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, '[redacted-email]')
    .replace(/\b((?:api[_-]?key|token|secret|password|authorization)\s*[:=]\s*)([^\s,'"&}]{8,})/gi, '$1[redacted]')
    .replace(/((?:["'])(?:api[_-]?key|token|secret|password|authorization)(?:["'])\s*:\s*(?:["']))(?:(?!["'])[^\r\n])*/gi, '$1[redacted]')
    .replace(/((?:\\["'])(?:api[_-]?key|token|secret|password|authorization)(?:\\["'])\s*:\s*(?:\\["']))(?:(?!\\["'])[^\r\n])*/gi, '$1[redacted]')
    .replace(/\b((?:session[_-]?id|user[_-]?id|device[_-]?id)\s*[:=]\s*)([^\s,'"&}]{4,})/gi, '$1[redacted]')
    .replace(/((?:["'])(?:session[_-]?id|user[_-]?id|device[_-]?id)(?:["'])\s*:\s*(?:["']))(?:(?!["'])[^\r\n])*/gi, '$1[redacted]')
    .replace(/((?:\\["'])(?:session[_-]?id|user[_-]?id|device[_-]?id)(?:\\["'])\s*:\s*(?:\\["']))(?:(?!\\["'])[^\r\n])*/gi, '$1[redacted]')
    .replace(/\b(?:\d[ -]?){13,19}\b/g, '[redacted-card]');
}

function redactRawStreamText(value) {
  return redactString(value)
    .replace(/((?:^|["']|\\n|\r?\n)\s*(?:Cookie|Set-Cookie)\s*:\s*)[^\\\r\n"]+/gi, '$1[redacted]')
    .replace(/((?:^|["']|\\n|\r?\n)\s*(?:Authorization|Proxy-Authorization)\s*:\s*)[^\\\r\n"]+/gi, '$1[redacted]');
}

function sanitizeWithState(value, maxBytes, depth = 0) {
  if (value == null) return { value, truncated: false };
  if (depth > 20) return { value: '[max-depth]', truncated: true };
  if (typeof value === 'string') return clipStringWithState(redactString(value), maxBytes);
  if (typeof value === 'number' || typeof value === 'boolean') return { value, truncated: false };
  if (Array.isArray(value)) {
    let truncated = false;
    const arr = value.map((v) => {
      const child = sanitizeWithState(v, maxBytes, depth + 1);
      truncated = truncated || child.truncated;
      return child.value;
    });
    return { value: arr, truncated };
  }
  if (typeof value === 'object') {
    const out = {};
    let truncated = false;
    for (const [key, child] of Object.entries(value)) {
      if (SENSITIVE_KEY_RE.test(key)) {
        out[key] = '[redacted]';
        continue;
      }
      const sanitized = sanitizeWithState(child, maxBytes, depth + 1);
      out[key] = sanitized.value;
      truncated = truncated || sanitized.truncated;
    }
    return { value: out, truncated };
  }
  return clipStringWithState(String(value), maxBytes);
}

function sanitize(value, maxBytes, depth = 0) {
  return sanitizeWithState(value, maxBytes, depth).value;
}

function extractUsage(body) {
  if (!body || typeof body !== 'object') return {};
  // Gemini reports usage under usageMetadata.{promptTokenCount,candidatesTokenCount} (no `usage` object).
  const gm = body.usageMetadata;
  if (gm && typeof gm === 'object') {
    const gi = Number(gm.promptTokenCount);
    const go = Number(gm.candidatesTokenCount);
    return {
      input_tokens: Number.isFinite(gi) ? gi : null,
      output_tokens: Number.isFinite(go) ? go : null,
    };
  }
  // Ollama reports usage as top-level prompt_eval_count / eval_count (no `usage` object).
  if (body.prompt_eval_count != null || body.eval_count != null) {
    const oi = Number(body.prompt_eval_count);
    const oo = Number(body.eval_count);
    return {
      input_tokens: Number.isFinite(oi) ? oi : null,
      output_tokens: Number.isFinite(oo) ? oo : null,
    };
  }
  const usage = body.usage;
  if (!usage || typeof usage !== 'object') return {};
  // Anthropic + OpenAI Responses use input_tokens/output_tokens; OpenAI Chat Completions uses
  // prompt_tokens/completion_tokens. Accept both so OpenAI/codex traces aren't left with null usage.
  const input = Number(usage.input_tokens ?? usage.prompt_tokens);
  const output = Number(usage.output_tokens ?? usage.completion_tokens);
  return {
    input_tokens: Number.isFinite(input) ? input : null,
    output_tokens: Number.isFinite(output) ? output : null,
  };
}

function extractCacheTokens(body) {
  if (!body || typeof body !== 'object') return { cacheCreationTokens: 0, cacheReadTokens: 0 };
  const gm = body.usageMetadata; // Gemini: cachedContentTokenCount is the cache-read equivalent
  if (gm && typeof gm === 'object') {
    const cached = Number(gm.cachedContentTokenCount);
    return { cacheCreationTokens: 0, cacheReadTokens: Number.isFinite(cached) ? cached : 0 };
  }
  const usage = body.usage;
  if (!usage || typeof usage !== 'object') return { cacheCreationTokens: 0, cacheReadTokens: 0 };
  const creation = Number(usage.cache_creation_input_tokens);
  const read = Number(usage.cache_read_input_tokens);
  const openAiRead = Number(usage.prompt_tokens_details?.cached_tokens);
  return {
    cacheCreationTokens: Number.isFinite(creation) ? creation : 0,
    cacheReadTokens: Number.isFinite(read) ? read : (Number.isFinite(openAiRead) ? openAiRead : 0),
  };
}

// Merge usage/finish/response-id out of ONE parsed SSE data object into the running accumulator. Covers the
// Anthropic shapes (message_start -> message.usage.input_tokens + message.id, message_delta -> usage.output_tokens
// + delta.stop_reason) and the OpenAI shapes (Chat final chunk usage.prompt/completion_tokens + choices[].finish_reason;
// Responses response.completed -> response.usage + response.status / incomplete_details.reason + response.id).
function applyStreamUsageObj(acc, o) {
  if (!o || typeof o !== 'object') return;
  const u = o.usage || o.message?.usage || o.response?.usage;
  if (u && typeof u === 'object') {
    const it = Number(u.input_tokens ?? u.prompt_tokens);
    const ot = Number(u.output_tokens ?? u.completion_tokens);
    const cc = Number(u.cache_creation_input_tokens);
    const cr = Number(u.cache_read_input_tokens ?? u.prompt_tokens_details?.cached_tokens);
    if (Number.isFinite(it)) acc.input_tokens = it;
    if (Number.isFinite(ot)) acc.output_tokens = ot;
    if (Number.isFinite(cc)) acc.cacheCreationTokens = cc;
    if (Number.isFinite(cr)) acc.cacheReadTokens = cr;
  }
  // Gemini stream chunk: usageMetadata (cumulative, last chunk carries the final counts) + candidates[].finishReason.
  const gm = o.usageMetadata;
  if (gm && typeof gm === 'object') {
    const gi = Number(gm.promptTokenCount);
    const go = Number(gm.candidatesTokenCount);
    const gc = Number(gm.cachedContentTokenCount);
    if (Number.isFinite(gi)) acc.input_tokens = gi;
    if (Number.isFinite(go)) acc.output_tokens = go;
    if (Number.isFinite(gc)) acc.cacheReadTokens = gc;
  }
  // Ollama stream: the final NDJSON chunk (done:true) carries top-level prompt_eval_count / eval_count + done_reason.
  if (o.prompt_eval_count != null || o.eval_count != null) {
    const oi = Number(o.prompt_eval_count);
    const oo = Number(o.eval_count);
    if (Number.isFinite(oi)) acc.input_tokens = oi;
    if (Number.isFinite(oo)) acc.output_tokens = oo;
  }
  const fr = o.delta?.stop_reason || o.response?.incomplete_details?.reason || o.response?.status
    || o.choices?.[0]?.finish_reason || o.candidates?.[0]?.finishReason || o.done_reason;
  if (fr) acc.finishReason = fr;
  const rid = o.message?.id || o.response?.id || o.responseId || (typeof o.id === 'string' && o.id.startsWith('resp_') ? o.id : '');
  if (rid) acc.responseId = rid;
}

// Feed appended stream text; parses each complete line into the accumulator and returns the leftover
// (possibly-incomplete) trailing buffer. Handles both SSE (`data: {...}` lines, Anthropic/OpenAI/Gemini) and
// bare NDJSON (`{...}` per line, Ollama) — the latter is detected by a leading `{` (SSE framing lines never
// start with `{`). JSON parse failures are skipped (partial/non-JSON lines).
function scanSseUsage(acc, buffered) {
  const lines = buffered.split('\n');
  const leftover = lines.pop() ?? '';
  for (const line of lines) {
    const s = line.trim();
    let payload = '';
    if (s.startsWith('data:')) payload = s.slice(5).trim();
    else if (s.startsWith('{')) payload = s.replace(/,\s*$/, ''); // bare NDJSON (Ollama), drop a trailing array comma
    else continue;
    if (!payload || payload === '[DONE]') continue;
    try { applyStreamUsageObj(acc, JSON.parse(payload)); } catch { /* partial / non-JSON line */ }
  }
  return leftover;
}

function parseStreamPayloadLine(line) {
  const s = String(line || '').trim();
  let payload = '';
  if (s.startsWith('data:')) payload = s.slice(5).trim();
  else if (s.startsWith('{')) payload = s.replace(/,\s*$/, '');
  else return null;
  if (!payload || payload === '[DONE]') return null;
  try {
    return JSON.parse(payload);
  } catch {
    return null;
  }
}

function compactStreamEvent(evt) {
  if (!evt || typeof evt !== 'object') return null;
  const out = {};
  for (const key of ['type', 'id', 'responseId', 'item_id', 'output_index', 'call_id']) {
    if (evt[key] !== undefined) out[key] = evt[key];
  }
  if (evt.usage && typeof evt.usage === 'object') out.usage = evt.usage;
  if (evt.usageMetadata && typeof evt.usageMetadata === 'object') out.usageMetadata = evt.usageMetadata;
  if (Array.isArray(evt.choices)) out.choices = evt.choices;
  if (evt.message && typeof evt.message === 'object') {
    out.message = {
      ...(evt.message.id ? { id: evt.message.id } : {}),
      ...(evt.message.usage ? { usage: evt.message.usage } : {}),
    };
  }
  if (evt.response && typeof evt.response === 'object') {
    const response = evt.response;
    out.response = {
      ...(response.id ? { id: response.id } : {}),
      ...(response.status ? { status: response.status } : {}),
      ...(response.incomplete_details ? { incomplete_details: response.incomplete_details } : {}),
      ...(response.usage ? { usage: response.usage } : {}),
      ...(Array.isArray(response.output) ? { output: response.output } : {}),
    };
  }
  if (evt.item && typeof evt.item === 'object') out.item = evt.item;
  if (evt.delta !== undefined) out.delta = evt.delta;
  if (evt.content_block && typeof evt.content_block === 'object') out.content_block = evt.content_block;
  const geminiCandidates = compactGeminiCandidates(evt.candidates);
  if (geminiCandidates) out.candidates = geminiCandidates;
  return Object.keys(out).length > 0 ? out : null;
}

// Compact Gemini / Vertex candidates for the semantic tail: keep finishReason + tool-call parts
// (functionCall / functionResponse) which the export layer needs, and drop bulky pure-text/thought parts.
// Returns null when there is nothing worth retaining.
function compactGeminiCandidates(candidates) {
  if (!Array.isArray(candidates)) return null;
  const out = [];
  for (const cand of candidates) {
    if (!cand || typeof cand !== 'object') continue;
    const compact = {};
    if (cand.index !== undefined) compact.index = cand.index;
    if (cand.finishReason) compact.finishReason = cand.finishReason;
    const parts = cand.content?.parts;
    if (Array.isArray(parts)) {
      const keptParts = parts.filter((part) => part && typeof part === 'object'
        && ((part.functionCall && typeof part.functionCall === 'object')
          || (part.functionResponse && typeof part.functionResponse === 'object')));
      if (keptParts.length > 0) {
        compact.content = {
          ...(cand.content.role ? { role: cand.content.role } : {}),
          parts: keptParts,
        };
      }
    }
    if (Object.keys(compact).length > 0) out.push(compact);
  }
  return out.length > 0 ? out : null;
}

function compactStreamEventFromText(text) {
  const type = /"type"\s*:\s*"([^"]+)"/.exec(text)?.[1];
  const id = /"response"\s*:\s*\{[\s\S]*?"id"\s*:\s*"([^"]+)"/.exec(text)?.[1]
    || /"id"\s*:\s*"((?:resp_|chatcmpl-|msg_)[^"]+)"/.exec(text)?.[1];
  const status = /"response"\s*:\s*\{[\s\S]*?"status"\s*:\s*"([^"]+)"/.exec(text)?.[1]
    || /"status"\s*:\s*"(completed|failed|incomplete|cancelled)"/.exec(text)?.[1];
  const inputTokens = /"input_tokens"\s*:\s*(\d+)/.exec(text)?.[1] || /"prompt_tokens"\s*:\s*(\d+)/.exec(text)?.[1];
  const outputTokens = /"output_tokens"\s*:\s*(\d+)/.exec(text)?.[1] || /"completion_tokens"\s*:\s*(\d+)/.exec(text)?.[1];
  if (!type && !id && !status && !inputTokens && !outputTokens) return null;
  const response = {};
  if (id) response.id = id;
  if (status) response.status = status;
  if (inputTokens || outputTokens) {
    response.usage = {
      ...(inputTokens ? { input_tokens: Number(inputTokens) } : {}),
      ...(outputTokens ? { output_tokens: Number(outputTokens) } : {}),
    };
  }
  return {
    ...(type ? { type } : {}),
    ...(Object.keys(response).length > 0 ? { response } : {}),
  };
}

// Gemini / Vertex stream chunks carry tool calls under
// candidates[].content.parts[].{functionCall|functionResponse} (camelCase, no `type` discriminator). Returns
// true when any part is a tool call/result so the truncation whitelist keeps it.
function geminiStreamEventHasToolPart(evt) {
  if (!evt || !Array.isArray(evt.candidates)) return false;
  for (const cand of evt.candidates) {
    const parts = cand?.content?.parts;
    if (!Array.isArray(parts)) continue;
    for (const part of parts) {
      if (!part || typeof part !== 'object') continue;
      if (part.functionCall && typeof part.functionCall === 'object') return true;
      if (part.functionResponse && typeof part.functionResponse === 'object') return true;
    }
  }
  return false;
}

function streamEventHasSemanticValue(evt) {
  if (!evt || typeof evt !== 'object') return false;
  const type = String(evt.type || '');
  if (evt.usage || evt.usageMetadata || evt.message?.usage || evt.response?.usage) return true;
  if (evt.response?.id || evt.message?.id || evt.responseId) return true;
  if (evt.response?.status || evt.response?.incomplete_details) return true;
  if (Array.isArray(evt.choices) && evt.choices.some((choice) => choice?.finish_reason || choice?.delta?.tool_calls || choice?.message?.tool_calls)) return true;
  if (type === 'response.completed' || type === 'response.failed' || type === 'response.incomplete') return true;
  if (type.includes('function_call') || type.includes('tool')) return true;
  if (evt.item && typeof evt.item === 'object' && ['function_call', 'tool_use', 'function_call_output', 'tool_result'].includes(evt.item.type)) return true;
  if (evt.content_block && typeof evt.content_block === 'object' && ['tool_use', 'function_call'].includes(evt.content_block.type)) return true;
  if (evt.delta && typeof evt.delta === 'object' && evt.delta.type === 'input_json_delta') return true;
  // Gemini reports a finished candidate via finishReason; tool calls live in candidates[].content.parts[].
  if (Array.isArray(evt.candidates) && evt.candidates.some((cand) => cand?.finishReason)) return true;
  if (geminiStreamEventHasToolPart(evt)) return true;
  return false;
}

function pushStreamEvent(acc, evt, maxEvents) {
  if (!evt || typeof evt !== 'object') return;
  if (acc.length < maxEvents) {
    acc.push(evt);
    return;
  }
  acc.truncated = true;
  acc.limit = maxEvents;
  acc.dropped_event_count = (Number(acc.dropped_event_count) || 0) + 1;
  if (!streamEventHasSemanticValue(evt)) return;
  const compact = compactStreamEvent(evt);
  if (!compact) return;
  if (!Array.isArray(acc.semantic_tail_events)) acc.semantic_tail_events = [];
  acc.semantic_tail_events.push(compact);
}

function scanStreamEvents(acc, buffered, maxEvents = STREAM_EVENT_CAPTURE_LIMIT) {
  const lines = buffered.split('\n');
  const leftover = lines.pop() ?? '';
  for (const line of lines) {
    const evt = parseStreamPayloadLine(line);
    pushStreamEvent(acc, evt, maxEvents);
  }
  return leftover;
}

function recordOversizedStreamLine(acc, usage, line) {
  let evt = parseStreamPayloadLine(line);
  if (evt && typeof evt === 'object') {
    applyStreamUsageObj(usage, evt);
    evt = compactStreamEvent(evt) || compactStreamEventFromText(line);
  } else {
    evt = compactStreamEventFromText(line);
    if (evt) applyStreamUsageObj(usage, evt);
  }
  pushStreamEvent(acc, evt, STREAM_EVENT_CAPTURE_LIMIT);
}

function appendOversizedStreamText(current, chunk, maxBytes = STREAM_OVERSIZED_LINE_CAPTURE_MAX) {
  const combined = current + chunk;
  const limit = Math.max(1024, Math.floor(maxBytes || STREAM_OVERSIZED_LINE_CAPTURE_MAX));
  if (combined.length <= limit) return combined;
  const edge = Math.floor(limit / 2);
  return `${combined.slice(0, edge)}\n...[stream-line-truncated]...\n${combined.slice(-edge)}`;
}

function appendBoundedRawStreamCapture(capture, chunk, maxBytes) {
  if (!capture || !chunk) return capture;
  const text = redactRawStreamText(String(chunk));
  const bytes = Buffer.byteLength(text, 'utf8');
  capture.bytes += bytes;
  const limit = Math.max(0, Math.floor(maxBytes || 0));
  const tailLimit = Math.max(1024, Math.floor(limit / 2));
  const tailCombined = String(capture.tail || '') + text;
  const tailBuffer = Buffer.from(tailCombined, 'utf8');
  capture.tail = tailBuffer.length <= tailLimit
    ? tailCombined
    : tailBuffer.subarray(Math.max(0, tailBuffer.length - tailLimit)).toString('utf8');
  if (limit <= 0) {
    capture.truncated = capture.truncated || bytes > 0;
    return capture;
  }
  if (!capture.text) {
    if (bytes <= limit) {
      capture.text = text;
      return capture;
    }
    const edge = Math.max(1, Math.floor(limit / 2));
    capture.text = Buffer.from(text, 'utf8').subarray(0, edge).toString('utf8')
      + '\n...[raw-stream-truncated]...\n'
      + Buffer.from(text, 'utf8').subarray(Math.max(0, bytes - edge)).toString('utf8');
    capture.truncated = true;
    return capture;
  }
  const combined = capture.text + text;
  if (Buffer.byteLength(combined, 'utf8') <= limit) {
    capture.text = combined;
    return capture;
  }
  const edge = Math.max(1, Math.floor(limit / 2));
  const combinedBuf = Buffer.from(combined, 'utf8');
  capture.text = combinedBuf.subarray(0, edge).toString('utf8')
    + '\n...[raw-stream-truncated]...\n'
    + combinedBuf.subarray(Math.max(0, combinedBuf.length - edge)).toString('utf8');
  capture.truncated = true;
  return capture;
}

function streamTransportMessage(kind, value, maxBytes) {
  const message = value && value.message ? value.message : String(value || kind);
  return clipString(redactString(message), maxBytes);
}

function sessionIdFromUserField(value) {
  if (!value) return '';
  let obj = value;
  if (typeof value === 'string') {
    const s = value.trim();
    if (s[0] !== '{') return safePlainSessionId(value);
    try { obj = JSON.parse(s); } catch { return ''; }
  }
  if (obj && typeof obj === 'object' && typeof obj.session_id === 'string') return safePlainSessionId(obj.session_id);
  return '';
}

function safePlainSessionId(value) {
  if (typeof value !== 'string') return '';
  const s = value.trim();
  if (s !== value) return '';
  if (s.length < 4 || s.length > 128) return '';
  if (s.includes('@') || /\s/.test(s)) return '';
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9]$/.test(s)) return '';
  if (/^(?:bearer|basic|sk-|ghp_|github_pat_|gho_|ghu_|ghs_|glpat-|xox[baprs]-)/i.test(s)) return '';
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(s)) return '';
  if (/(?:^|[-_.])(?:token|secret|apikey|api[_-]?key|password|passwd|credential|auth)(?:$|[-_.])/i.test(s)) return '';
  if (/^[a-f0-9]{32,}$/i.test(s)) return '';
  if (/^[A-Za-z0-9_-]{40,}$/.test(s) && !/[-_.]/.test(s)) return '';
  if (/(?:session|sess)/i.test(s)) return s;
  return /[-_.]/.test(s) ? s : '';
}

// Pull the stable, cross-session account substring out of an identity field. Claude Code packs identity into
// metadata.user_id shaped like `user_<accountHash>_account__session_<uuid>`: the `__session_<uuid>` suffix
// rotates every session, but the leading `user_<accountHash>_account` stays constant for one account. Stripping
// the session suffix yields a deterministic per-account key we can hash so the same account is recognizable
// across sessions (anti-sybil / multi-account detection) while never exposing the plaintext id. Non-Claude
// shapes (a plain string id, or an object {user_id}/{id}) fall back to the whole trimmed value.
function userAccountKeyFromIdentityField(value) {
  if (value == null) return '';
  let raw = value;
  if (typeof raw === 'string') {
    const s = raw.trim();
    if (s[0] === '{') {
      try {
        const obj = JSON.parse(s);
        return userAccountKeyFromIdentityField(
          obj && typeof obj === 'object'
            ? (obj.user_id ?? obj.account_id ?? obj.id ?? obj.user ?? '')
            : ''
        );
      } catch {
        // Fall through and treat the JSON-looking string as an opaque id.
      }
    }
    raw = s;
  } else if (typeof raw === 'object') {
    return userAccountKeyFromIdentityField(raw.user_id ?? raw.account_id ?? raw.id ?? raw.user ?? '');
  } else {
    return '';
  }
  if (!raw) return '';
  // Drop the rotating session suffix. Claude Code's user_id is `user_<account>_account__session_<uuid>`, so the
  // boundary is the literal double-underscore `__session_`. Only split there: a single-underscore `_session_`
  // can occur legitimately inside a non-Claude account segment, and splitting on it would over-truncate and
  // collapse distinct accounts onto the same hash. Everything from `__session_` onward rotates per session.
  const stripped = raw.replace(/__session_.*$/i, '').trim();
  return stripped || raw;
}

// Deterministic cross-session account hash (sha256), redacted but stable. Empty when no usable identity exists.
function extractUserIdHash(headers = {}, body = {}) {
  let identity = '';
  if (body && typeof body === 'object') {
    identity = userAccountKeyFromIdentityField(body.metadata?.user_id)
      || userAccountKeyFromIdentityField(body.user)
      || userAccountKeyFromIdentityField(body.metadata?.account_id);
  }
  if (!identity) {
    for (const name of ['x-account-id', 'x-user-id']) {
      identity = userAccountKeyFromIdentityField(getHeader(headers, name));
      if (identity) break;
    }
  }
  return identity ? hashTraceValue(identity, 'user_id_sha256') : '';
}

function extractSessionID(headers = {}, body = {}) {
  for (const name of ['x-session-id', 'x-cursor-session-id', 'x-conversation-id']) {
    const sid = safePlainSessionId(getHeader(headers, name));
    if (sid) return clipString(sid, 96);
  }
  if (body && typeof body === 'object') {
    // Claude Code packs identity into metadata.user_id as a JSON object/string carrying a per-session
    // `session_id` uuid — the only field that distinguishes one agent session from another. The old code
    // stored the whole metadata.user_id and clipped to 96 bytes, which drops the session_id (the 64-hex
    // device_id alone fills the budget), leaving every row with the same unusable prefix and nothing to
    // thread a session together. Extract the inner session_id.
    const sid = sessionIdFromUserField(body.metadata?.user_id)
      || safePlainSessionId(body.metadata?.session_id)
      || sessionIdFromUserField(body.user);
    if (sid) return clipString(sid, 96);
  }
  return '';
}

function contentToText(content) {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return '';
  return content
    .filter((item) => item && (item.type === 'text' || item.type === 'input_text') && typeof item.text === 'string')
    .map((item) => item.text)
    .join('\n');
}

// Normalize the requested reasoning/thinking effort into a single short field across providers (FIX-9):
//   - Anthropic: body.thinking = { type: 'enabled', budget_tokens: N } -> 'enabled' or 'budget:N'
//   - OpenAI Responses / Chat: body.reasoning.effort | body.reasoning_effort = 'low'|'medium'|'high'|'minimal'
//   - body.output_config.effort / body.generationConfig.thinkingConfig (Gemini) / body.metadata.thinking_effort
// Returns '' when no effort signal is present. Bounded to keep the trace field small.
function extractThinkingEffort(body = {}) {
  if (!body || typeof body !== 'object') return '';
  const pickEffort = (value) => {
    if (typeof value === 'string' && value.trim()) return value.trim();
    if (typeof value === 'number' && Number.isFinite(value)) return String(value);
    return '';
  };
  // OpenAI reasoning effort (object or flat field).
  const reasoning = body.reasoning && typeof body.reasoning === 'object' ? body.reasoning : null;
  const openaiEffort = pickEffort(reasoning ? reasoning.effort : undefined) || pickEffort(body.reasoning_effort);
  if (openaiEffort) return clipString(openaiEffort, 32);
  // Anthropic thinking config.
  const thinking = body.thinking;
  if (thinking && typeof thinking === 'object') {
    if (Number.isFinite(Number(thinking.budget_tokens))) return clipString(`budget:${Number(thinking.budget_tokens)}`, 32);
    const type = pickEffort(thinking.type);
    if (type) return clipString(type, 32);
  } else {
    const thinkingType = pickEffort(thinking);
    if (thinkingType) return clipString(thinkingType, 32);
  }
  // output_config.effort (some Anthropic/Bedrock variants).
  const outputConfig = body.output_config && typeof body.output_config === 'object' ? body.output_config : null;
  const outputEffort = pickEffort(outputConfig ? outputConfig.effort : undefined);
  if (outputEffort) return clipString(outputEffort, 32);
  // Gemini thinkingConfig (budget / level).
  const genConfig = body.generationConfig && typeof body.generationConfig === 'object' ? body.generationConfig : null;
  const thinkingConfig = genConfig && genConfig.thinkingConfig && typeof genConfig.thinkingConfig === 'object'
    ? genConfig.thinkingConfig : null;
  if (thinkingConfig) {
    if (Number.isFinite(Number(thinkingConfig.thinkingBudget))) return clipString(`budget:${Number(thinkingConfig.thinkingBudget)}`, 32);
    const level = pickEffort(thinkingConfig.reasoningEffort || thinkingConfig.effort);
    if (level) return clipString(level, 32);
  }
  // metadata fallback.
  const metadata = body.metadata && typeof body.metadata === 'object' ? body.metadata : null;
  const metaEffort = pickEffort(metadata ? (metadata.thinking_effort || metadata.reasoning_effort) : undefined);
  if (metaEffort) return clipString(metaEffort, 32);
  return '';
}

function extractCWD(body = {}) {
  const candidates = [];
  if (body && typeof body === 'object') {
    candidates.push(contentToText(body.instructions));
    candidates.push(contentToText(body.system));
    candidates.push(contentToText(body.input));
    if (Array.isArray(body.messages)) {
      for (const msg of body.messages) {
        if (!msg || !['system', 'user', 'developer'].includes(msg.role)) continue;
        candidates.push(contentToText(msg.content));
      }
    }
    if (Array.isArray(body.input)) {
      for (const msg of body.input) {
        if (!msg || !['system', 'user', 'developer'].includes(msg.role)) continue;
        candidates.push(contentToText(msg.content));
      }
    }
  }
  for (const text of candidates) {
    if (!text) continue;
    for (const re of CWD_PATTERNS) {
      const match = re.exec(text);
      if (match && match[1]) return clipString(match[1].trim(), 512);
    }
  }
  return '';
}

function bodyToPrismString(body, maxBytes) {
  if (body === undefined) return '';
  const sanitizedState = sanitizeWithState(body, maxBytes);
  const sanitized = sanitizedState.value;
  const full = JSON.stringify(sanitized);
  if (full === undefined) return '';
  if (!sanitizedState.truncated && Buffer.byteLength(full, 'utf8') <= maxBytes) return full;
  // Over the cap: never hard-cut the JSON. Use the same envelope shape as v2 so exported trajectories can
  // interpret truncation consistently across generations.
  const previewBudget = Math.max(1024, maxBytes >> 1);
  const preview = Buffer.from(full, 'utf8').subarray(0, previewBudget).toString('utf8');
  const omittedBytes = Math.max(0, Buffer.byteLength(full, 'utf8') - Buffer.byteLength(preview, 'utf8'));
  return JSON.stringify({
    truncated: true,
    truncation_reason: sanitizedState.truncated ? 'field_truncated' : 'field_bytes_exceeded',
    preview,
    omitted_chars: Math.max(0, full.length - preview.length),
    omitted_bytes: omittedBytes,
    redaction: REDACTION_VERSION,
  });
}

function bodyStringWasTruncated(value) {
  if (typeof value !== 'string' || !value) return false;
  try {
    const parsed = JSON.parse(value);
    return !!(parsed && typeof parsed === 'object' && (parsed.truncated === true || parsed._truncated === true));
  } catch {
    return false;
  }
}

function streamEventTextDelta(evt) {
  if (!evt || typeof evt !== 'object') return '';
  if (evt.delta && typeof evt.delta === 'object') {
    if (typeof evt.delta.text === 'string') return evt.delta.text;
    if (typeof evt.delta.content === 'string') return evt.delta.content;
  }
  if (typeof evt.text === 'string') return evt.text;
  if (typeof evt.content === 'string') return evt.content;
  const choices = Array.isArray(evt.choices) ? evt.choices : [];
  return choices.map((choice) => {
    if (!choice || typeof choice !== 'object') return '';
    const delta = choice.delta && typeof choice.delta === 'object' ? choice.delta : {};
    const message = choice.message && typeof choice.message === 'object' ? choice.message : {};
    return typeof delta.content === 'string' ? delta.content : (typeof message.content === 'string' ? message.content : '');
  }).filter(Boolean).join('');
}

function streamEventsContentText(events) {
  return (events || []).map(streamEventTextDelta).filter(Boolean).join('');
}

function normalizeTraceHeaders(headers = {}, maxBytes = DEFAULT_MAX_FIELD_BYTES) {
  const out = {};
  if (headers && typeof headers.forEach === 'function') {
    headers.forEach((value, key) => {
      out[String(key).toLowerCase()] = Array.isArray(value) ? value.join(', ') : String(value || '');
    });
  } else {
    for (const [key, value] of Object.entries(headers || {})) {
      out[String(key).toLowerCase()] = Array.isArray(value) ? value.join(', ') : String(value || '');
    }
  }
  return Object.keys(out).length > 0 ? sanitize(out, maxBytes) : null;
}

function stripTraceBodies(event, reason) {
  const stripped = {
    ...event,
    ...traceProducerMetadata(),
    requestBody: '',
    responseBody: '',
    cwd: '',
    redaction: 'prism_metadata_only',
    trace_degraded: true,
    trace_degraded_reason: reason,
    body_stripped: true,
    body_stripped_reason: reason,
  };
  if (Array.isArray(event.attempts)) {
    stripped.attempts = event.attempts.map((attempt) => {
      const out = { ...attempt };
      delete out.requestBody;
      delete out.responseBody;
      delete out.request_body;
      delete out.response_body;
      out.body_stripped = true;
      out.body_stripped_reason = reason;
      return out;
    });
  }
  return stripped;
}

function isMissingTraceSecretError(err) {
  return /node secret is missing or invalid/i.test(String(err && err.message || err));
}

function materializeTraceRecord(event, env = process.env, ctx = {}) {
  if (!resolveTraceEncryption(env)) return event;
  try {
    return encryptTraceEvent(event, env, ctx);
  } catch (err) {
    if (isMissingTraceSecretError(err)) return stripTraceBodies(event, 'missing_node_secret');
    throw err;
  }
}

function traceFailureCode(err, fallback = 'PROXY_TRACE_FAILED') {
  const raw = err && err.code ? String(err.code).toUpperCase().replace(/[^A-Z0-9_]/g, '_') : '';
  return raw ? `${fallback}_${raw}` : fallback;
}

function reportTraceFailureOnce(code) {
  if (!code || reportedTraceFailureCodes.has(code)) return;
  reportedTraceFailureCodes.add(code);
  try {
    console.warn(JSON.stringify({
      event: 'proxy_trace_failed_once',
      code,
      message: 'proxy trace disabled or degraded; request handling continues',
    }));
  } catch (_) {}
}

function appendJsonlBestEffort(file, record) {
  if (!file || disabledTraceFiles.has(file)) return false;
  const dir = path.dirname(file);
  Promise.resolve().then(async () => {
    if (!ensuredTraceDirs.has(dir)) {
      await fs.promises.mkdir(dir, { recursive: true });
      ensuredTraceDirs.add(dir);
    }
    await fs.promises.appendFile(file, JSON.stringify(record) + '\n', { encoding: 'utf8', mode: 0o600 });
    if (!chmoddedTraceFiles.has(file)) {
      chmoddedTraceFiles.add(file);
      await fs.promises.chmod(file, 0o600).catch(() => {});
    }
  }).catch((err) => {
    disabledTraceFiles.add(file);
    reportTraceFailureOnce(traceFailureCode(err, 'PROXY_TRACE_WRITE_FAILED'));
  });
  return true;
}

function resolveMaxUploadBytes(env = process.env) {
  const raw = Number(env.EVOMAP_PROXY_TRACE_MAX_UPLOAD_BYTES);
  if (Number.isFinite(raw) && raw > 0) return Math.floor(raw);
  return 4 * 1024 * 1024; // >= field cap so a full body isn't dropped at the upload boundary
}

function resolveMaxPendingUploads(env = process.env) {
  const raw = Number(env.EVOMAP_PROXY_TRACE_MAX_PENDING_UPLOADS);
  if (Number.isFinite(raw) && raw >= 0) return Math.floor(raw);
  return 100;
}

function resolveTraceBackfillMaxRows(env = process.env) {
  const raw = Number(env.EVOMAP_PROXY_TRACE_BACKFILL_MAX_ROWS);
  if (Number.isFinite(raw) && raw > 0) return Math.floor(raw);
  return DEFAULT_TRACE_BACKFILL_MAX_ROWS;
}

function resolveTraceBackfillMaxScanBytes(env = process.env) {
  const raw = Number(env.EVOMAP_PROXY_TRACE_BACKFILL_MAX_SCAN_BYTES);
  if (Number.isFinite(raw) && raw > 0) return Math.floor(raw);
  return DEFAULT_TRACE_BACKFILL_MAX_SCAN_BYTES;
}

function resolveTraceBackfillMaxEnqueueBytes(env = process.env) {
  const raw = Number(env.EVOMAP_PROXY_TRACE_BACKFILL_MAX_ENQUEUE_BYTES);
  if (Number.isFinite(raw) && raw > 0) return Math.floor(raw);
  return DEFAULT_TRACE_BACKFILL_MAX_ENQUEUE_BYTES;
}

function pendingTraceUploads(store, stopAt = 101) {
  if (!store) return 0;
  if (typeof store.countPending === 'function') {
    try {
      return store.countPending({ type: 'proxy_trace', direction: 'outbound' });
    } catch {
      return 0;
    }
  }
  if (typeof store.list !== 'function') return 0;
  const maxCount = Math.max(1, Math.floor(Number(stopAt) || 1));
  let offset = 0;
  let count = 0;
  try {
    while (count < maxCount) {
      const rows = store.list({
        type: 'proxy_trace',
        direction: 'outbound',
        status: 'pending',
        limit: Math.min(100, maxCount - count),
        offset,
      });
      count += rows.length;
      if (rows.length === 0) break;
      offset += rows.length;
    }
    return count;
  } catch {
    return 0;
  }
}

function notifyTraceUpload(callback, status) {
  if (typeof callback !== 'function') return;
  try { callback(status); } catch { /* trace upload observers are best-effort */ }
}

function scheduleTraceUploadTask(task) {
  if (typeof setImmediate === 'function') {
    setImmediate(task);
    return;
  }
  setTimeout(task, 0);
}

// Stable across live enqueue and startup backfill so local and Hub-side ingest
// can de-dupe the same trace row by ref_id.
function traceUploadRefId(record) {
  return 'proxy_trace:' + crypto.createHash('sha256')
    .update(JSON.stringify(record || null), 'utf8')
    .digest('hex');
}

function isNonEmptyBase64(value) {
  return typeof value === 'string' && value.length > 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(value);
}

function isProducerGeneration(value) {
  return value === 'v1' || value === 'v2' || value === 'unknown';
}

function isOptionalShortString(value, max) {
  return value === undefined || (typeof value === 'string' && value.length > 0 && value.length <= max);
}

function isOptionalNonNegativeSafeInteger(value) {
  return value === undefined || (Number.isSafeInteger(value) && value >= 0);
}

function hasOnlyKeys(value, allowed) {
  return Object.keys(value).every((key) => allowed.has(key));
}

function isHubKeyEnvelope(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const allowed = new Set(['algorithm', 'key_id', 'wrapped_key']);
  if (!hasOnlyKeys(value, allowed)) return false;
  if (value.algorithm !== 'rsa-oaep-sha256') return false;
  if (typeof value.key_id !== 'string' || !/^[a-f0-9]{16}$/i.test(value.key_id)) return false;
  return isNonEmptyBase64(value.wrapped_key);
}

function isEncryptedTraceEnvelope(record) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) return false;
  if (record.encrypted !== true) return false;
  if (record.algorithm !== 'aes-256-gcm') return false;
  if (record.payload_schema !== 'prism_trace_row') return false;
  if (record.secret_version !== undefined && !parseNodeSecretVersion(record.secret_version)) return false;
  if (record.producer_generation !== undefined && !isProducerGeneration(record.producer_generation)) return false;
  if (!isOptionalShortString(record.producer_version, 32)) return false;
  if (!isOptionalShortString(record.producer_component, 32)) return false;
  if (!isNonEmptyBase64(record.iv) || !isNonEmptyBase64(record.tag) || !isNonEmptyBase64(record.ciphertext)) return false;
  const allowed = new Set([
    'schema_version',
    'prism_compatible',
    'encrypted',
    'payload_schema',
    'algorithm',
    'key_id',
    'secret_version',
    'producer_generation',
    'producer_version',
    'producer_component',
    'iv',
    'tag',
    'ciphertext',
    'hub_key_envelope',
    'payload_complete',
    'payload_incomplete_reason',
    'hub_uploadable',
    'hub_upload_blocked_reason',
    'hub_upload_size_bytes',
    'hub_upload_max_bytes',
  ]);
  if (!hasOnlyKeys(record, allowed)) return false;
  if (record.payload_complete !== undefined && record.payload_complete !== false) return false;
  if (!isOptionalShortString(record.payload_incomplete_reason, 64)) return false;
  if (record.hub_uploadable !== undefined && record.hub_uploadable !== false) return false;
  if (!isOptionalShortString(record.hub_upload_blocked_reason, 64)) return false;
  if (!isOptionalNonNegativeSafeInteger(record.hub_upload_size_bytes)) return false;
  if (!isOptionalNonNegativeSafeInteger(record.hub_upload_max_bytes)) return false;
  if (record.hub_key_envelope !== undefined && !isHubKeyEnvelope(record.hub_key_envelope)) return false;
  return true;
}

function traceUploadBlockedStatus(record) {
  if (!record || typeof record !== 'object') return null;
  if (record.hub_uploadable === false) {
    const reason = record.hub_upload_blocked_reason || 'hub_upload_blocked';
    if (reason === 'payload_incomplete') return null;
    return {
      queued: false,
      reason,
      sizeBytes: record.hub_upload_size_bytes,
      maxUploadBytes: record.hub_upload_max_bytes,
    };
  }
  return null;
}

function buildTraceUploadPayload(record) {
  const encrypted = isEncryptedTraceEnvelope(record);
  const payload = {
    schema: 'prism_trace_row.v1',
    encrypted,
    trace: record,
  };
  const secretVersion = parseNodeSecretVersion(record && record.secret_version);
  if (secretVersion) payload.node_secret_version = secretVersion;
  for (const key of ['producer_generation', 'producer_version', 'producer_component']) {
    if (record && typeof record[key] === 'string' && record[key]) payload[key] = record[key];
  }
  return encrypted ? payload : sanitizePayload(payload);
}

function tracePlaintextUploadAllowed(env = process.env) {
  return String(env.EVOMAP_PROXY_TRACE_UPLOAD_PLAINTEXT || '').trim().toLowerCase() === 'danger';
}

function secretVersionTraceDecryptAllowed(record, env = process.env, ctx = {}) {
  if (!record || typeof record !== 'object') return false;
  if (record.hub_key_envelope) return true;
  if (!parseNodeSecretVersion(record.secret_version)) return false;
  return readTraceNodeSecretVersionDecryptEnabled(env, ctx);
}

function isProxyTraceUploadPayloadAllowed(payload, env = process.env, ctx = {}) {
  if (!payload || typeof payload !== 'object') return false;
  const allowed = new Set([
    'schema',
    'encrypted',
    'trace',
    'node_secret_version',
    'secret_version',
    'producer_generation',
    'producer_version',
    'producer_component',
  ]);
  if (!hasOnlyKeys(payload, allowed)) return false;
  if (payload.schema !== 'prism_trace_row.v1') return false;
  if (payload.node_secret_version !== undefined && !parseNodeSecretVersion(payload.node_secret_version)) return false;
  if (payload.secret_version !== undefined && !parseNodeSecretVersion(payload.secret_version)) return false;
  if (payload.producer_generation !== undefined && !isProducerGeneration(payload.producer_generation)) return false;
  if (!isOptionalShortString(payload.producer_version, 32)) return false;
  if (!isOptionalShortString(payload.producer_component, 32)) return false;
  if (payload.encrypted === true) {
    if (!isEncryptedTraceEnvelope(payload.trace)) return false;
    if (traceUploadBlockedStatus(payload.trace)) return false;
    if (payload.trace.hub_key_envelope) return true;
    if (parseNodeSecretVersion(payload.trace.secret_version)) {
      return readTraceNodeSecretVersionDecryptEnabled(env, ctx);
    }
    return true;
  }
  if (payload.encrypted !== false) return false;
  if (traceUploadBlockedStatus(payload.trace)) return false;
  return tracePlaintextUploadAllowed(env);
}

function validateTraceUpload(store, record, env = process.env) {
  const blocked = traceUploadBlockedStatus(record);
  if (blocked) {
    return { ok: false, status: blocked };
  }
  if (!store || typeof store.send !== 'function') {
    return { ok: false, status: { queued: false, reason: 'missing_store' } };
  }
  if (!isEncryptedTraceEnvelope(record)) {
    if (!tracePlaintextUploadAllowed(env)) {
      return { ok: false, status: { queued: false, reason: 'plaintext_upload_disabled' } };
    }
  } else {
    // Fail closed until the hub explicitly advertises support for resolving
    // node_id + secret_version to historical node_secret material. Older hubs
    // only decrypt rows that carry a hub_key_envelope.
    if (parseNodeSecretVersion(record.secret_version) && !secretVersionTraceDecryptAllowed(record, env, { store })) {
      if (!warnedHubUndecryptable) {
        warnedHubUndecryptable = true;
        // eslint-disable-next-line no-console
        console.error('[proxy-trace] encrypted row has secret_version but no hub_key_envelope, and hub '
          + 'node-secret-version trace decrypt support is not enabled; refusing warehouse upload.');
      }
      return { ok: false, status: { queued: false, reason: 'hub_keyring_decrypt_unsupported' } };
    }
    const profile = readTraceProfileConfig(env, { store });
    if (profile.enabled && !record.hub_key_envelope && !parseNodeSecretVersion(record.secret_version)) {
      if (!warnedHubUndecryptable) {
        warnedHubUndecryptable = true;
        // eslint-disable-next-line no-console
        console.error('[proxy-trace] trace_profile_analysis_enabled but the encrypted row has no hub_key_envelope '
          + 'or enabled secret_version decrypt support; refusing warehouse upload because the hub could never '
          + 'decrypt it. Set the hub public key on this node or enable node-secret-version trace decrypt only '
          + 'after the hub supports it.');
      }
      return { ok: false, status: { queued: false, reason: 'hub_undecryptable' } };
    }
  }
  const sizeBytes = Buffer.byteLength(JSON.stringify(record || null), 'utf8');
  const maxUploadBytes = resolveMaxUploadBytes(env);
  if (sizeBytes > maxUploadBytes) {
    return {
      ok: false,
      status: { queued: false, reason: 'max_upload_bytes', sizeBytes, maxUploadBytes },
    };
  }
  const maxPendingUploads = resolveMaxPendingUploads(env);
  const pendingUploads = pendingTraceUploads(store, maxPendingUploads + 1);
  const effectivePendingUploads = pendingUploads + scheduledTraceUploadEnqueues;
  if (effectivePendingUploads >= maxPendingUploads) {
    return {
      ok: false,
      status: {
        queued: false,
        reason: 'max_pending_uploads',
        pendingUploads,
        maxPendingUploads,
      },
    };
  }
  return { ok: true, status: null };
}

function sendTraceUpload(store, record, opts = {}) {
  const notify = (status) => notifyTraceUpload(opts.onStatus, status);
  const refId = opts.refId || traceUploadRefId(record);
  const validation = validateTraceUpload(store, record, opts.env || process.env);
  if (!validation.ok) {
    notify(validation.status);
    return false;
  }
  try {
    const result = store.send({
      type: 'proxy_trace',
      payload: buildTraceUploadPayload(record),
      priority: 'low',
      refId,
      expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000,
    });
    notify({ queued: true, reason: 'queued', messageId: result && result.message_id });
    return true;
  } catch {
    notify({ queued: false, reason: 'send_failed' });
    return false;
  }
}

function shouldWarnTraceUploadSkipped(logger, reason, now = Date.now()) {
  const warn = logger && typeof logger.warn === 'function' ? logger.warn : null;
  if (!warn) return false;
  const key = String(reason || 'unknown');
  if (key === 'send_failed') return true;
  let warnedAtByReason = traceUploadSkipWarnedAt.get(warn);
  if (!warnedAtByReason) {
    warnedAtByReason = new Map();
    traceUploadSkipWarnedAt.set(warn, warnedAtByReason);
  }
  const last = warnedAtByReason.get(key) || 0;
  if (last && now - last < TRACE_UPLOAD_SKIP_WARN_COOLDOWN_MS) return false;
  warnedAtByReason.set(key, now);
  return true;
}

function enqueueTraceBestEffort(store, record, opts = {}) {
  const notify = (status) => notifyTraceUpload(opts.onStatus, status);
  const refId = opts.refId || traceUploadRefId(record);
  const validation = validateTraceUpload(store, record, opts.env || process.env);
  if (!validation.ok) {
    notify(validation.status);
    return false;
  }
  scheduledTraceUploadEnqueues += 1;
  scheduledTraceUploadRefIds.add(refId);
  scheduleTraceUploadTask(() => {
    try {
      const result = store.send({
        type: 'proxy_trace',
        payload: buildTraceUploadPayload(record),
        priority: 'low',
        refId,
        expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000,
      });
      notify({ queued: true, reason: 'queued', messageId: result && result.message_id });
    } catch {
      notify({ queued: false, reason: 'send_failed' });
    } finally {
      scheduledTraceUploadEnqueues = Math.max(0, scheduledTraceUploadEnqueues - 1);
      scheduledTraceUploadRefIds.delete(refId);
    }
  });
  // The trace passed preflight; disk-backed mailbox persistence continues async.
  return true;
}

function traceFileIdentity(stat) {
  return {
    dev: Number.isFinite(Number(stat.dev)) ? Number(stat.dev) : 0,
    ino: Number.isFinite(Number(stat.ino)) ? Number(stat.ino) : 0,
    birthtimeMs: Number.isFinite(Number(stat.birthtimeMs)) ? Math.floor(Number(stat.birthtimeMs)) : 0,
  };
}

function sameTraceFileIdentity(a, b) {
  if (!a || !b) return false;
  if (a.dev && b.dev && a.ino && b.ino) return a.dev === b.dev && a.ino === b.ino;
  if (a.birthtimeMs && b.birthtimeMs) return a.birthtimeMs === b.birthtimeMs;
  return false;
}

function traceCursorGuard(file, offset) {
  if (!offset || offset < 1) return '';
  let fd = null;
  try {
    fd = fs.openSync(file, 'r');
    const start = Math.max(0, offset - 1024);
    const len = offset - start;
    const buf = Buffer.alloc(len);
    const bytesRead = fs.readSync(fd, buf, 0, len, start);
    return crypto.createHash('sha256')
      .update(String(offset), 'utf8')
      .update(':')
      .update(buf.subarray(0, bytesRead))
      .digest('hex');
  } catch {
    return '';
  } finally {
    if (fd !== null) {
      try { fs.closeSync(fd); } catch { /* ignore close errors */ }
    }
  }
}

function parseTraceUploadCursor(raw, file, stat) {
  if (!raw) return 0;
  let cursor = raw;
  if (typeof raw === 'string') {
    try { cursor = JSON.parse(raw); } catch { return 0; }
  }
  if (!cursor || typeof cursor !== 'object') return 0;
  if (cursor.file !== file) return 0;
  if (!sameTraceFileIdentity(cursor.file_id, traceFileIdentity(stat))) return 0;
  const offset = Number(cursor.offset);
  if (!Number.isFinite(offset) || offset < 0 || offset > stat.size) return 0;
  if (offset > 0 && cursor.cursor_guard !== traceCursorGuard(file, Math.floor(offset))) return 0;
  return Math.floor(offset);
}

function persistTraceUploadCursor(store, file, offset, stat) {
  if (!store || typeof store.setState !== 'function') return;
  try {
    store.setState(TRACE_UPLOAD_CURSOR_STATE_KEY, {
      file,
      file_id: traceFileIdentity(stat),
      offset,
      cursor_guard: traceCursorGuard(file, offset),
      updated_at: new Date().toISOString(),
    });
  } catch { /* cursor persistence is best-effort */ }
}

function readLineRemainder(fd, fromOffset, fileSize, maxBytes) {
  const limit = Math.min(fileSize, fromOffset + maxBytes);
  const buf = Buffer.alloc(64 * 1024);
  let offset = fromOffset;
  const chunks = [];
  while (offset < limit) {
    const toRead = Math.min(buf.length, limit - offset);
    const bytesRead = fs.readSync(fd, buf, 0, toRead, offset);
    if (bytesRead <= 0) break;
    for (let i = 0; i < bytesRead; i++) {
      if (buf[i] === 10) {
        chunks.push(Buffer.from(buf.subarray(0, i)));
        return {
          found: true,
          bytes: Buffer.concat(chunks),
          offset: offset + i + 1,
        };
      }
    }
    chunks.push(Buffer.from(buf.subarray(0, bytesRead)));
    offset += bytesRead;
  }
  return {
    found: false,
    eof: offset >= fileSize,
    bytes: Buffer.concat(chunks),
    offset,
  };
}

function readTraceRowsBatch(file, startOffset, opts = {}) {
  const maxRows = Math.max(1, Math.floor(opts.maxRows || DEFAULT_TRACE_BACKFILL_MAX_ROWS));
  const maxScanBytes = Math.max(1, Math.floor(opts.maxScanBytes || DEFAULT_TRACE_BACKFILL_MAX_SCAN_BYTES));
  const maxLongLineBytes = Math.max(1, Math.floor(opts.maxLongLineBytes || DEFAULT_TRACE_BACKFILL_MAX_LONG_LINE_BYTES));
  const rows = [];
  let fd = null;
  let cursor = startOffset;
  let overlongLine = false;
  try {
    fd = fs.openSync(file, 'r');
    const stat = fs.fstatSync(fd);
    let readOffset = Math.max(0, Math.min(startOffset, stat.size));
    const scanEnd = Math.min(stat.size, readOffset + maxScanBytes);
    const buf = Buffer.alloc(64 * 1024);
    let carry = Buffer.alloc(0);
    while (readOffset < scanEnd && rows.length < maxRows) {
      const toRead = Math.min(buf.length, scanEnd - readOffset);
      const readStart = readOffset;
      const bytesRead = fs.readSync(fd, buf, 0, toRead, readOffset);
      if (bytesRead <= 0) break;
      readOffset += bytesRead;
      const chunk = Buffer.from(buf.subarray(0, bytesRead));
      const combined = carry.length ? Buffer.concat([carry, chunk]) : chunk;
      const combinedStart = readStart - carry.length;
      let lineStart = 0;
      for (let i = 0; i < combined.length && rows.length < maxRows; i++) {
        if (combined[i] !== 10) continue;
        const lineEndOffset = combinedStart + i + 1;
        const text = combined.subarray(lineStart, i).toString('utf8').replace(/\r$/, '').trim();
        cursor = lineEndOffset;
        if (text) rows.push({ text, offset: lineEndOffset });
        lineStart = i + 1;
      }
      carry = combined.subarray(lineStart);
    }
    const truncatedLine = rows.length === 0 && readOffset >= scanEnd && scanEnd < stat.size && carry.length > 0;
    if (truncatedLine) {
      const remainingLineBytes = Math.max(1, maxLongLineBytes - carry.length);
      const remainder = readLineRemainder(fd, scanEnd, stat.size, remainingLineBytes);
      if (remainder.found) {
        const fullLine = Buffer.concat([carry, remainder.bytes]);
        const text = fullLine.toString('utf8').replace(/\r$/, '').trim();
        cursor = remainder.offset;
        if (text) rows.push({ text, offset: remainder.offset });
      } else if (!remainder.eof) {
        cursor = remainder.offset;
        overlongLine = true;
      }
    }
    return {
      rows,
      cursor,
      fileSize: stat.size,
      overlongLine,
    };
  } finally {
    if (fd !== null) {
      try { fs.closeSync(fd); } catch { /* ignore close errors */ }
    }
  }
}

function collectExistingTraceUploadFingerprints(store, maxRows = 10_000) {
  const fingerprints = new Set();
  for (const refId of scheduledTraceUploadRefIds) fingerprints.add(refId);
  if (!store || typeof store.list !== 'function') return fingerprints;
  let offset = 0;
  while (offset < maxRows) {
    let rows = [];
    try {
      rows = store.list({ type: 'proxy_trace', direction: 'outbound', limit: 100, offset });
    } catch {
      return fingerprints;
    }
    if (!rows.length) return fingerprints;
    for (const row of rows) {
      const trace = row && row.payload && row.payload.trace;
      if (trace) fingerprints.add(traceUploadRefId(trace));
      if (row && row.ref_id && String(row.ref_id).startsWith('proxy_trace:')) {
        fingerprints.add(String(row.ref_id));
      }
    }
    offset += rows.length;
  }
  return fingerprints;
}

function backfillProxyTraceUploads(opts = {}) {
  const env = opts.env || process.env;
  const store = opts.store || null;
  const file = opts.traceFile || resolveTraceFile(env);
  const stats = {
    file,
    scanned: 0,
    queued: 0,
    skipped: 0,
    duplicates: 0,
    cursor: 0,
    reasons: {},
  };
  if (!store || typeof store.send !== 'function') {
    stats.reasons.missing_store = 1;
    return stats;
  }
  if (!resolveTraceMode(env, { store })) {
    stats.reasons.collection_disabled = 1;
    return stats;
  }
  let fileStat = null;
  try {
    fileStat = fs.statSync(file);
    if (!fileStat.isFile()) return stats;
  } catch {
    stats.reasons.missing_file = 1;
    return stats;
  }
  const rawCursor = typeof store.getState === 'function'
    ? store.getState(TRACE_UPLOAD_CURSOR_STATE_KEY)
    : null;
  const startOffset = parseTraceUploadCursor(rawCursor, file, fileStat);
  stats.cursor = startOffset;
  const pendingLimit = resolveMaxPendingUploads(env);
  const pending = pendingTraceUploads(store, pendingLimit + 1);
  const capacity = Math.max(0, pendingLimit - pending - scheduledTraceUploadEnqueues);
  if (capacity <= 0) {
    stats.reasons.max_pending_uploads = 1;
    return stats;
  }
  const existing = collectExistingTraceUploadFingerprints(store);
  let cursor = startOffset;
  let stoppedEarly = false;
  const scanRowLimit = resolveTraceBackfillMaxRows(env);
  const maxEnqueueBytes = resolveTraceBackfillMaxEnqueueBytes(env);
  let enqueuedBytes = 0;
  while (!stoppedEarly && stats.queued < capacity && stats.scanned < scanRowLimit) {
    let batch = null;
    try {
      batch = readTraceRowsBatch(file, cursor, {
        maxRows: scanRowLimit - stats.scanned,
        maxScanBytes: resolveTraceBackfillMaxScanBytes(env),
        maxLongLineBytes: Math.max(resolveMaxUploadBytes(env), resolveTraceBackfillMaxScanBytes(env)),
      });
    } catch {
      stats.reasons.read_failed = 1;
      break;
    }
    const batchStart = cursor;
    for (const row of batch.rows) {
      stats.scanned += 1;
      let record = null;
      try {
        record = JSON.parse(row.text);
      } catch {
        stats.skipped += 1;
        stats.reasons.invalid_json = (stats.reasons.invalid_json || 0) + 1;
        cursor = row.offset;
        continue;
      }
      const refId = traceUploadRefId(record);
      if (existing.has(refId)) {
        stats.duplicates += 1;
        cursor = row.offset;
        continue;
      }
      const uploadBytes = Buffer.byteLength(JSON.stringify(buildTraceUploadPayload(record)), 'utf8');
      if (stats.queued > 0 && enqueuedBytes + uploadBytes > maxEnqueueBytes) {
        stats.reasons.max_enqueue_bytes = (stats.reasons.max_enqueue_bytes || 0) + 1;
        stoppedEarly = true;
        break;
      }
      let status = null;
      const queued = sendTraceUpload(store, record, {
        env,
        refId,
        onStatus: (s) => { status = s; },
      });
      if (!queued) {
        const reason = status && status.reason || 'send_failed';
        stats.skipped += 1;
        stats.reasons[reason] = (stats.reasons[reason] || 0) + 1;
        if (reason === 'max_pending_uploads' || reason === 'missing_store' || reason === 'send_failed') {
          stoppedEarly = true;
          break;
        }
        cursor = row.offset;
        continue;
      }
      existing.add(refId);
      stats.queued += 1;
      enqueuedBytes += uploadBytes;
      cursor = row.offset;
      if (stats.queued >= capacity) {
        stoppedEarly = true;
        break;
      }
    }
    if (stoppedEarly) break;
    if (batch.overlongLine && batch.cursor > cursor) {
      stats.scanned += 1;
      stats.skipped += 1;
      stats.reasons.line_too_long = (stats.reasons.line_too_long || 0) + 1;
      cursor = batch.cursor;
      break;
    }
    if (batch.cursor > cursor) cursor = batch.cursor;
    if (cursor === batchStart) break;
    if (batch.rows.length === 0) break;
  }
  stats.cursor = cursor;
  if (cursor !== startOffset) persistTraceUploadCursor(store, file, cursor, fileStat);
  return stats;
}

function createProxyTrace({
  route,
  headers,
  body,
  upstreamMode,
  originalModel,
  chosenModel,
  store,
  logger,
  onTraceQueued,
} = {}) {
  const ctx = { store };
  const mode = resolveTraceMode(process.env, ctx);
  if (!mode) return null;
  const started = Date.now();
  const maxBytes = resolveMaxFieldBytes();
  const [method, pathName] = String(route || 'POST /v1/messages').split(/\s+/, 2);
  const requestBody = bodyToPrismString(body || {}, maxBytes);
  const event = {
    schema_version: SCHEMA_VERSION,
    prism_compatible: true,
    id: crypto.randomUUID(), // prism trace_id — was hardcoded null, leaving every row's trace id empty
    createdAt: Math.floor(started / 1000),
    createdAtIso: new Date(started).toISOString(),
    requestId: `prism-${crypto.randomBytes(8).toString('hex')}-${started}`,
    deviceId: process.env.EVOMAP_DEVICE_ID
      ? hashTraceValue(process.env.EVOMAP_DEVICE_ID, 'device_id_sha256')
      : 'evomap-proxy',
    method: method || 'POST',
    path: pathName || '/v1/messages',
    status: null,
    durationMs: null,
    isStream: !!(body && body.stream === true),
    finished: false,
    finishReason: '',
    chunkCount: 0,
    firstChunkAt: 0,
    lastChunkAt: 0,
    channelId: 0,
    channelType: 0,
    channelName: '',
    tokenName: process.env.EVOMAP_PROXY_TOKEN_NAME || '',
    model: chosenModel || originalModel || (body && body.model) || '',
    clientIp: '127.0.0.1',
    contentType: '',
    requestBytes: Buffer.byteLength(requestBody),
    responseBytes: 0,
    errorMessage: '',
    requestBody: mode === 'full' ? requestBody : '',
    responseBody: '',
    sessionId: hashTraceValue(extractSessionID(headers, body), 'session_id_sha256'),
    // Stable cross-session, cross-row account fingerprint (sha256 of the account substring with the rotating
    // __session_<uuid> suffix stripped). Lets downstream de-dupe/anti-sybil thread rows by account without
    // ever storing the plaintext user_id (which SENSITIVE_KEY_RE redacts to [redacted]).
    user_id_hash: extractUserIdHash(headers, body),
    // Normalized requested reasoning/thinking effort across providers (Anthropic thinking, OpenAI
    // reasoning.effort, output_config.effort, Gemini thinkingConfig, metadata). '' when not requested. (FIX-9)
    thinking_effort: extractThinkingEffort(body),
    userAgent: clipString(getHeader(headers, 'user-agent'), 256),
    cwd: mode === 'full' ? hashTraceValue(extractCWD(body), 'cwd_sha256') : '',
    cacheCreationTokens: 0,
    cacheReadTokens: 0,
    // EvoMap additions kept alongside Prism fields for quick filtering.
    timestamp: new Date(started).toISOString(),
    client: detectClient(headers),
    upstream: upstreamMode || 'anthropic',
    originalModel: originalModel || (body && body.model) || '',
    // Provider response id (Anthropic msg_…, OpenAI resp_…) + the codex previous_response_id it chains from.
    // codex (OpenAI Responses) threads a conversation by previous_response_id -> response.id, not session_id.
    responseId: '',
    previousResponseId: (body && typeof body === 'object' && typeof body.previous_response_id === 'string')
      ? body.previous_response_id : '',
    input_tokens: null,
    output_tokens: null,
    redaction: mode === 'full' ? REDACTION_VERSION : 'prism_metadata_only',
    body_truncated: bodyStringWasTruncated(requestBody) || undefined,
  };
  let emitted = false;
  const ensureAttempt = (attemptIndex) => {
    const numeric = Number(attemptIndex);
    const idx = Number.isInteger(numeric) && numeric >= 0
      ? numeric
      : (Array.isArray(event.attempts) ? event.attempts.length : 0);
    if (!Array.isArray(event.attempts)) event.attempts = [];
    let attempt = event.attempts.find((item) => Number(item && item.attempt_index) === idx);
    if (!attempt) {
      attempt = { attempt_index: idx };
      event.attempts.push(attempt);
      event.attempts.sort((a, b) => Number(a.attempt_index) - Number(b.attempt_index));
    }
    return attempt;
  };
  const recordAttemptBody = (attempt, key, value) => {
    if (value === undefined) return;
    const bodyString = bodyToPrismString(value, maxBytes);
    const bytesKey = key === 'requestBody' ? 'requestBytes' : 'responseBytes';
    attempt[bytesKey] = Buffer.byteLength(bodyString);
    if (bodyStringWasTruncated(bodyString)) {
      attempt.body_truncated = true;
      event.body_truncated = true;
    }
    if (mode === 'full') attempt[key] = bodyString;
  };
  let streamAttemptIndex = null;
  const markPayloadIncomplete = (reason = 'body_truncated') => {
    event.body_truncated = true;
    event.payload_complete = false;
    event.payload_incomplete_reason = reason;
  };
  const markHubUploadBlocked = (reason, details = {}) => {
    event.hub_uploadable = false;
    event.hub_upload_blocked_reason = reason;
    if (Number.isSafeInteger(details.sizeBytes)) event.hub_upload_size_bytes = details.sizeBytes;
    if (Number.isSafeInteger(details.maxUploadBytes)) event.hub_upload_max_bytes = details.maxUploadBytes;
  };
  const handleTraceUploadStatus = (status = {}) => {
    if (status.queued) {
      if (typeof onTraceQueued === 'function') {
        try { onTraceQueued(status); } catch { /* best-effort observer */ }
      }
      return;
    }
    if (!shouldWarnTraceUploadSkipped(logger, status.reason)) return;
    logger.warn(JSON.stringify({
      event: 'proxy_trace_upload_skipped',
      reason: status.reason,
      incomplete_reason: status.incomplete_reason,
      size_bytes: status.sizeBytes,
      max_upload_bytes: status.maxUploadBytes,
      pending_uploads: status.pendingUploads,
      max_pending_uploads: status.maxPendingUploads,
    }));
  };
  const materializeEvent = () => materializeTraceRecord(event, process.env, ctx);
  const emitTrace = () => {
    if (emitted) return event;
    emitted = true;
    if (event.body_truncated) markPayloadIncomplete(event.payload_incomplete_reason || 'body_truncated');
    let record = null;
    try {
      record = materializeEvent();
      const sizeBytes = Buffer.byteLength(JSON.stringify(record || null), 'utf8');
      const maxUploadBytes = resolveMaxUploadBytes();
      if (sizeBytes > maxUploadBytes) {
        markHubUploadBlocked('max_upload_bytes', { sizeBytes, maxUploadBytes });
        record = materializeEvent();
      }
    } catch (err) {
      reportTraceFailureOnce(traceFailureCode(err, 'PROXY_TRACE_MATERIALIZE_FAILED'));
      return event;
    }
    appendJsonlBestEffort(resolveTraceFile(), record);
    const blocked = traceUploadBlockedStatus(event) || traceUploadBlockedStatus(record);
    if (blocked) {
      handleTraceUploadStatus(blocked);
      return event;
    }
    enqueueTraceBestEffort(store, record, { onStatus: handleTraceUploadStatus });
    return event;
  };
  const api = {
    setRequestBody(nextBody) {
      const nextRequestBody = bodyToPrismString(nextBody || {}, maxBytes);
      event.requestBytes = Buffer.byteLength(nextRequestBody);
      if (mode === 'full') event.requestBody = nextRequestBody;
      if (bodyStringWasTruncated(nextRequestBody)) event.body_truncated = true;
      return api;
    },
    recordAttempt({
      attempt_index: attemptIndexSnake,
      attemptIndex,
      status,
      requestBody: attemptRequestBody,
      responseBody: attemptResponseBody,
      error,
      upstreamMode: attemptUpstreamMode,
      model,
      headers: responseHeaders,
    } = {}) {
      const attempt = ensureAttempt(attemptIndexSnake ?? attemptIndex);
      const numericStatus = Number(status);
      if (Number.isFinite(numericStatus)) attempt.status = numericStatus;
      if (model) attempt.model = model;
      if (attemptUpstreamMode) {
        attempt.upstreamMode = attemptUpstreamMode;
        attempt.upstream_mode = attemptUpstreamMode;
      }
      const contentType = getHeader(responseHeaders || {}, 'content-type');
      if (contentType) {
        attempt.contentType = contentType;
        attempt.content_type = contentType;
      }
      const normalizedHeaders = normalizeTraceHeaders(responseHeaders || {}, maxBytes);
      if (normalizedHeaders) attempt.headers = normalizedHeaders;
      if (error) {
        const message = clipString(redactString(error.message || String(error)), maxBytes);
        attempt.errorMessage = message;
        attempt.error_message = message;
      } else if (attempt.status >= 400 && attemptResponseBody !== undefined) {
        const rawError = mode === 'metadata'
          ? (attemptResponseBody && typeof attemptResponseBody === 'object'
            ? (attemptResponseBody?.error?.type || attemptResponseBody?.type || '')
            : '')
          : (typeof attemptResponseBody === 'string'
            ? attemptResponseBody
            : (attemptResponseBody?.error?.message || attemptResponseBody?.error || JSON.stringify(attemptResponseBody)));
        const message = clipString(redactString(rawError || `upstream_error_${attempt.status}`), maxBytes);
        attempt.errorMessage = message;
        attempt.error_message = message;
      }
      recordAttemptBody(attempt, 'requestBody', attemptRequestBody);
      recordAttemptBody(attempt, 'responseBody', attemptResponseBody);
      return api;
    },
    record({ status, responseBody, error, upstreamMode: finalUpstreamMode, model, headers: responseHeaders, finished, ttfb_ms: ttfbMs, ttfbMs: ttfbMsCamel } = {}) {
      event.status = Number.isFinite(Number(status)) ? Number(status) : null;
      event.durationMs = Date.now() - started;
      const explicitTtfbMs = Number(ttfbMs ?? ttfbMsCamel);
      if (Number.isFinite(explicitTtfbMs) && explicitTtfbMs >= 0) event.ttfb_ms = explicitTtfbMs;
      event.finished = typeof finished === 'boolean'
        ? finished
        : (event.status != null ? event.status < 400 : false);
      if (finalUpstreamMode) event.upstream = finalUpstreamMode;
      if (model) event.model = model;
      event.contentType = getHeader(responseHeaders || {}, 'content-type');
      const normalizedHeaders = normalizeTraceHeaders(responseHeaders || {}, maxBytes);
      if (normalizedHeaders) event.headers = normalizedHeaders;
      const usage = extractUsage(responseBody);
      if (usage.input_tokens != null) event.input_tokens = usage.input_tokens;
      if (usage.output_tokens != null) event.output_tokens = usage.output_tokens;
      const cache = extractCacheTokens(responseBody);
      event.cacheCreationTokens = cache.cacheCreationTokens;
      event.cacheReadTokens = cache.cacheReadTokens;
      if (responseBody && typeof responseBody === 'object') {
        // stop_reason (Anthropic) / finish_reason + choices[].finish_reason (OpenAI Chat) /
        // status + incomplete_details.reason (OpenAI Responses — codex) so codex finish state isn't blank.
        event.finishReason = responseBody.stop_reason
          || responseBody.finish_reason
          || responseBody.choices?.[0]?.finish_reason
          || responseBody.incomplete_details?.reason
          || responseBody.status
          || responseBody.candidates?.[0]?.finishReason   // Gemini (STOP / MAX_TOKENS / SAFETY / ...)
          || responseBody.done_reason                       // Ollama (stop / length / ...)
          || '';
        const rid = responseBody.id || responseBody.response?.id || responseBody.responseId; // responseId: Gemini
        if (typeof rid === 'string' && rid) event.responseId = rid;
      }
      if (event.isStream && responseBody === undefined && event.finished === false) {
        event.finishReason = 'stream_forwarded_unobserved';
      }
      if (error) {
        event.errorMessage = clipString(redactString(error.message || String(error)), maxBytes);
      } else if (event.status >= 400 && responseBody !== undefined) {
        if (mode === 'metadata') {
          const errType = responseBody && typeof responseBody === 'object'
            ? (responseBody?.error?.type || responseBody?.type || '')
            : '';
          event.errorMessage = clipString(errType || `upstream_error_${event.status}`, maxBytes);
        } else {
          const rawError = typeof responseBody === 'string'
            ? responseBody
            : (responseBody?.error?.message || responseBody?.error || JSON.stringify(responseBody));
          event.errorMessage = clipString(redactString(rawError), maxBytes);
        }
      }
      if (responseBody !== undefined) {
        const responseBodyString = bodyToPrismString(responseBody, maxBytes);
        event.responseBytes = Buffer.byteLength(responseBodyString);
        if (mode === 'full') {
          event.responseBody = responseBodyString;
          if (bodyStringWasTruncated(responseBodyString)) event.body_truncated = true;
        }
      }
      return emitTrace();
    },
    recordStreamStart({
      status,
      upstreamMode: finalUpstreamMode,
      model,
      headers: responseHeaders,
      attempt_index: attemptIndexSnake,
      attemptIndex,
    } = {}) {
      // Build the streamed-response event but DEFER the emit: usage/finish/response-id only arrive at the END of
      // the SSE body, so observeStream() scans the stream and finalizeStream() emits the row once. Until then
      // nothing is written, so the usage lands on the same row instead of being lost (0/190 streamed rows
      // carried tokens before this).
      event.status = Number.isFinite(Number(status)) ? Number(status) : null;
      event.durationMs = Date.now() - started;
      event.ttfb_ms = event.durationMs;
      event.finished = false;
      // recordStreamStart is called iff the upstream returned a stream, so this row IS streamed regardless of
      // how the client signalled it: Anthropic/OpenAI use body.stream===true, but Gemini signals streaming via
      // the path action (:streamGenerateContent) with no body flag — without this its rows looked non-streamed.
      event.isStream = true;
      if (finalUpstreamMode) event.upstream = finalUpstreamMode;
      if (model) event.model = model;
      event.contentType = getHeader(responseHeaders || {}, 'content-type');
      const normalizedHeaders = normalizeTraceHeaders(responseHeaders || {}, maxBytes);
      if (normalizedHeaders) event.headers = normalizedHeaders;
      event.finishReason = 'stream_forwarded_unobserved';
      const streamIndex = attemptIndexSnake ?? attemptIndex;
      if (streamIndex !== undefined && streamIndex !== null) {
        streamAttemptIndex = streamIndex;
        api.recordAttempt({
          attempt_index: streamIndex,
          status,
          upstreamMode: finalUpstreamMode,
          model,
          headers: responseHeaders,
        });
      }
      return api;
    },
    finalizeStream(usage = {}, completed = false) {
      if (usage.input_tokens != null) event.input_tokens = usage.input_tokens;
      if (usage.output_tokens != null) event.output_tokens = usage.output_tokens;
      if (usage.cacheCreationTokens != null) event.cacheCreationTokens = usage.cacheCreationTokens;
      if (usage.cacheReadTokens != null) event.cacheReadTokens = usage.cacheReadTokens;
      if (usage.finishReason) event.finishReason = usage.finishReason;
      if (usage.responseId) event.responseId = usage.responseId;
      event.finished = completed; // true only when the stream was observed to its end; cancel/error/unwrappable stay false
      event.durationMs = Date.now() - started;
      return emitTrace();
    },
    // Forward every chunk UNCHANGED to the client and passively scan the SSE body for the final usage/finish/
    // response-id, emitting the trace exactly once on end/error/cancel. Fails open: if the source can't be
    // wrapped, emit immediately (never lose the trace) and return it untouched. The scan never blocks or alters
    // the bytes.
    observeStream(source) {
      if (!source || typeof source.getReader !== 'function') { this.finalizeStream({}, false); return source; }
      let reader;
      try { reader = source.getReader(); } catch { this.finalizeStream({}, false); return source; }
      const self = this;
      const decoder = new TextDecoder();
      const usage = {};
      const streamEvents = [];
      const rawStreamCapture = { text: '', bytes: 0, truncated: false };
      const rawStreamCaptureMaxBytes = Math.max(1024, Math.floor(maxBytes));
      const streamScanBufferMaxBytes = Math.max(1024, Math.floor(maxBytes || SSE_SCAN_BUFFER_MAX));
      let buf = '';
      let eventBuf = '';
      let dropping = false; // inside a single SSE line longer than the cap: skip it cleanly, resync at the next \n
      let streamScanTruncated = false;
      let finalized = false;
      const finalize = (completed) => {
        if (finalized) return;
        finalized = true;
        try {
          if (mode === 'full' && (streamEvents.length > 0 || rawStreamCapture.text || streamScanTruncated) && !event.responseBody) {
            const contentText = streamEventsContentText(streamEvents);
            const rawStreamComplete = rawStreamCapture.bytes > 0 && !rawStreamCapture.truncated && !streamScanTruncated;
            const rawStreamPreview = rawStreamCapture.truncated
              ? clipString(rawStreamCapture.text, Math.max(1024, Math.floor(maxBytes / 4)))
              : '';
            const reconstructed = {
              reconstructed_stream: true,
              events: streamEvents,
              ...(Array.isArray(streamEvents.semantic_tail_events) && streamEvents.semantic_tail_events.length > 0
                ? { semantic_tail_events: streamEvents.semantic_tail_events }
                : {}),
              ...(rawStreamComplete && rawStreamCapture.text ? { raw_stream_body: rawStreamCapture.text } : {}),
              ...(rawStreamPreview ? { raw_stream_preview: rawStreamPreview } : {}),
              ...(rawStreamCapture.bytes > 0 ? { raw_stream_bytes: rawStreamCapture.bytes } : {}),
              ...(rawStreamCapture.bytes > 0 ? { raw_stream_complete: rawStreamComplete } : {}),
              ...(rawStreamCapture.truncated ? { raw_stream_truncated: true } : {}),
              ...(contentText ? { content_text: redactString(contentText) } : {}),
              ...(streamEvents.truncated ? { events_truncated: true, events_limit: streamEvents.limit || STREAM_EVENT_CAPTURE_LIMIT } : {}),
              ...(Number(streamEvents.dropped_event_count) > 0
                ? { dropped_event_count: Number(streamEvents.dropped_event_count) }
                : {}),
              ...(streamScanTruncated ? { events_truncated: true, provider_stream_truncated: true } : {}),
            };
            let responseBodyString = bodyToPrismString(reconstructed, maxBytes);
            let responseBodyTruncated = bodyStringWasTruncated(responseBodyString);
            if (responseBodyTruncated && rawStreamComplete && rawStreamCapture.text) {
              const rawOnly = {
                reconstructed_stream: true,
                raw_stream_body: rawStreamCapture.text,
                raw_stream_bytes: rawStreamCapture.bytes,
                raw_stream_complete: true,
                events_omitted_for_size: true,
              };
              const rawOnlyString = bodyToPrismString(rawOnly, maxBytes);
              if (!bodyStringWasTruncated(rawOnlyString)) {
                responseBodyString = rawOnlyString;
                responseBodyTruncated = false;
              }
            }
            event.responseBytes = Buffer.byteLength(responseBodyString);
            event.responseBody = responseBodyString;
            if (responseBodyTruncated || streamScanTruncated || rawStreamCapture.truncated) event.body_truncated = true;
            if (streamAttemptIndex !== null && streamAttemptIndex !== undefined) {
              const attempt = ensureAttempt(streamAttemptIndex);
              attempt.responseBytes = event.responseBytes;
              if (mode === 'full') attempt.responseBody = event.responseBody;
              if (responseBodyTruncated || streamScanTruncated || rawStreamCapture.truncated) {
                attempt.body_truncated = true;
              }
            }
          }
          self.finalizeStream(usage, completed);
        } catch { /* best-effort */ }
      };
      const scan = (text) => {
        let chunk = text;
        if (dropping) {
          // Discard the rest of the oversized line up to its terminating newline, then resume after it.
          const nl = chunk.indexOf('\n');
          if (nl === -1) {
            if (mode === 'full') eventBuf = appendOversizedStreamText(eventBuf, chunk, streamScanBufferMaxBytes);
            return; // still inside the oversized line
          }
          if (mode === 'full') recordOversizedStreamLine(streamEvents, usage, eventBuf + chunk.slice(0, nl));
          chunk = chunk.slice(nl + 1);
          eventBuf = '';
          dropping = false;
        }
        buf = scanSseUsage(usage, buf + chunk);
        if (mode === 'full') eventBuf = scanStreamEvents(streamEvents, eventBuf + chunk);
        if (buf.length > streamScanBufferMaxBytes) {
          // scanSseUsage already consumed every complete line, so `buf` is ONE incomplete line past the cap. It
          // can't be parsed until it ends and we won't buffer it unbounded; rather than tail-slice it (which
          // chops the `data:` prefix and loses/mis-parses the event), drop it and resync at the next newline.
          // Only triggers for a single SSE line > 1MB — far beyond any real codex response.completed.
          const oversizedLine = buf;
          buf = '';
          eventBuf = mode === 'full' ? appendOversizedStreamText('', eventBuf || oversizedLine, streamScanBufferMaxBytes) : '';
          dropping = true;
          streamScanTruncated = true;
        }
      };
      return new ReadableStream({
        async pull(controller) {
          try {
            const { value, done } = await reader.read();
            if (done) {
              controller.close();
              try {
                // Flush bytes held in the streaming decoder and scan the residual line: the final SSE event may
                // not be newline-terminated, so treat what remains as a complete line.
                const decoderTail = decoder.decode();
                const tail = buf + decoderTail;
                if (!dropping && tail) scanSseUsage(usage, tail + '\n');
              if (mode === 'full') {
                const eventTail = eventBuf + decoderTail;
                appendBoundedRawStreamCapture(rawStreamCapture, decoderTail, rawStreamCaptureMaxBytes);
                if (dropping && eventTail) recordOversizedStreamLine(streamEvents, usage, eventTail);
                else if (eventTail) scanStreamEvents(streamEvents, eventTail + '\n');
              }
              } catch { /* best-effort */ }
              finalize(true);
              return;
            }
            controller.enqueue(value); // forward UNCHANGED before any scanning
            try {
              const text = decoder.decode(value, { stream: true });
              if (mode === 'full') appendBoundedRawStreamCapture(rawStreamCapture, text, rawStreamCaptureMaxBytes);
              scan(text);
            } catch { /* scan is best-effort */ }
          } catch (err) {
            const message = streamTransportMessage('stream_read_error', err, maxBytes);
            event.errorMessage = message;
            event.stream_error = message;
            event.finishReason = 'stream_error';
            finalize(false);
            controller.error(err);
          }
        },
        cancel(reason) {
          const message = streamTransportMessage('stream_cancelled', reason, maxBytes);
          event.errorMessage = message;
          event.stream_cancelled = message;
          event.finishReason = 'stream_cancelled';
          finalize(false);
          try { return reader.cancel(reason); } catch { /* ignore */ }
        },
      });
    },
  };
  return api;
}

module.exports = {
  createProxyTrace,
  detectClient,
  resolveTraceMode,
  resolveDefaultTraceDir,
  resolveTraceFile,
  resolveTraceEncryption,
  resolveEvomapNodeSecret,
  resolveEvomapNodeSecretVersion,
  readTraceCollectionEnabled,
  readTraceProfileConfig,
  materializeTraceRecord,
  encryptTraceEvent,
  decryptTraceEnvelope,
  isEncryptedTraceEnvelope,
  isProxyTraceUploadPayloadAllowed,
  backfillProxyTraceUploads,
  enqueueTraceBestEffort,
  sanitize,
  extractCWD,
  extractUserIdHash,
  extractThinkingEffort,
  // Exported so the trajectory exporter can hash a plaintext transcript
  // session_id with the SAME scheme the proxy uses for trace rows
  // (`hashTraceValue(sid, 'session_id_sha256')`), enabling the "this session was
  // already captured by the gateway" join in the runtime-session gate.
  hashTraceValue,
  extractSessionID,
  // Exported for stream-truncation regression tests.
  scanStreamEvents,
  streamEventHasSemanticValue,
  compactStreamEvent,
  STREAM_EVENT_CAPTURE_LIMIT,
};

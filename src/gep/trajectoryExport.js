'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  collectTranscriptFiles,
  transcriptBelongsToWorkspace,
} = require('../evolve/utils');
const {
  decryptTraceEnvelope,
  resolveEvomapNodeSecret,
  resolveTraceFile,
  resolveDefaultTraceDir,
  sanitize,
  hashTraceValue,
} = require('../proxy/trace/extractor');

// AES-256-GCM authentication tag length, pinned explicitly (matches the
// 16-byte default this code already relied on) so decrypt rejects a truncated
// tag instead of accepting a weaker authenticator (Semgrep gcm-no-tag-length,
// issue #285). Mirrors extractor.js's GCM_TAG_BYTES / crypto.js's TAG_BYTES.
const GCM_TAG_BYTES = 16;
const SCHEMA = 'evomap.coding_trajectory.v1';
const RUNTIME_SESSION_REDACTION = 'evolver-redact-v2';
const RUNTIME_REDACTION_MAX_BYTES = 1024 * 1024;
const TRACE_FILE_RE = /(^|[/\\])llm-trace-[^/\\]*\.jsonl$/i;
const GENERIC_CHAT_FILE_RE = /(^|[/\\])(?:[^/\\]+\.)?(?:chat|messages|transcript)\.jsonl?$/i;
const CODEX_TEXT_TYPES = new Set(['input_text', 'output_text', 'text']);
const CODEX_META_TAGS = ['<environment_context>', '<permissions instructions>', '<user_instructions>'];
const META_MARKERS = ['HEARTBEAT_OK', 'NO_REPLY', 'NO_RESPONSE_NEEDED', '[META]'];
const RUNTIME_SESSION_DISCOVERY_ENV = 'EVOLVER_TRAJECTORY_RUNTIME_SESSIONS';
const RUNTIME_SESSION_DISCOVERY_ENV_LEGACY = 'EVOLVER_TRAJECTORY_EXPORT_RUNTIME_SESSIONS';
const RUNTIME_SESSION_DIRS_ENV = 'EVOLVER_TRAJECTORY_RUNTIME_SESSION_DIRS';
const RUNTIME_SESSION_DIRS_ENV_LEGACY = 'EVOLVER_TRAJECTORY_EXPORT_RUNTIME_SESSION_DIRS';
const RUNTIME_SESSION_DISCOVERY_DEPTH = 3;
// Strict-by-default marking gate (v1). The runtime-session discovery link only
// collects transcripts whose session_id was actively marked by evolver's
// session-start hook (recorded in marked-sessions.jsonl), AND that the gateway
// has not already captured (proxy-traces.jsonl). Both gates default ON; the env
// vars / opts below open them back up for fallback.
const MARKED_SESSIONS_FILE_ENV = 'EVOLVER_MARKED_SESSIONS_FILE';
const INCLUDE_UNMARKED_ENV = 'EVOLVER_TRAJECTORY_INCLUDE_UNMARKED';
const INCLUDE_GATEWAY_CAPTURED_ENV = 'EVOLVER_TRAJECTORY_INCLUDE_GATEWAY_CAPTURED';
const SESSION_ID_HASH_PREFIX = 'session_id_sha256';
// Cap how many bytes of a transcript we read just to harvest its session_id(s).
// The id lives in the first record (Codex session_meta) or the filename, so a
// small head read is enough; this keeps the gate cheap on multi-MB transcripts.
const MARK_GATE_HEAD_SCAN_BYTES = 64 * 1024;
const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

function safeJsonParse(text, fallback) {
  try {
    return JSON.parse(text);
  } catch {
    return fallback;
  }
}

function parseJsonish(value) {
  if (typeof value !== 'string') return value;
  const text = value.trim();
  if (!text || (!text.startsWith('{') && !text.startsWith('['))) return value;
  return safeJsonParse(text, value);
}

function firstString(record, keys) {
  if (!record || typeof record !== 'object') return undefined;
  for (const key of keys) {
    const value = record[key];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return undefined;
}

function plainObject(value) {
  const parsed = parseJsonish(value);
  return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : undefined;
}

function objectWithKeys(value) {
  const obj = plainObject(value);
  return obj && Object.keys(obj).length > 0 ? obj : undefined;
}

function mergePlainObjects(left, right) {
  const out = {};
  if (left && typeof left === 'object' && !Array.isArray(left)) Object.assign(out, left);
  if (right && typeof right === 'object' && !Array.isArray(right)) Object.assign(out, right);
  return Object.keys(out).length > 0 ? out : undefined;
}

function mergeSessionEnvelope(current, next) {
  const out = { ...(current || {}) };
  if (!out.sessionId && next && next.sessionId) out.sessionId = next.sessionId;
  if (!out.provider && next && next.provider) out.provider = next.provider;
  if (!out.model && next && next.model) out.model = next.model;
  if (!out.clientSource && next && next.clientSource) out.clientSource = next.clientSource;
  if (out.tools === undefined && next && next.tools !== undefined) out.tools = next.tools;
  if (!out.startedAt && next && next.startedAt) out.startedAt = next.startedAt;
  for (const key of ['usage', 'risk', 'fidelity', 'confidentiality', 'headers', 'ttfb_ms']) {
    if (out[key] === undefined && next && next[key] !== undefined) out[key] = next[key];
  }
  const metadata = mergePlainObjects(out.metadata, next && next.metadata);
  if (metadata) out.metadata = metadata;
  const nativeCalls = []
    .concat(Array.isArray(out.nativeCalls) ? out.nativeCalls : [])
    .concat(next && Array.isArray(next.nativeCalls) ? next.nativeCalls : []);
  if (nativeCalls.length > 0) out.nativeCalls = nativeCalls;
  return out;
}

function newReadStats() {
  return {
    rowsScanned: 0,
    rowsRead: 0,
    invalidJson: 0,
    sessionInvalidJson: 0,
    encryptedRows: 0,
    skippedMissingSecret: 0,
    decryptFailures: 0,
    nonPrismSkipped: 0,
    filesScanned: 0,
    sessionFilesScanned: 0,
    sessionTurnsRead: 0,
  };
}

function mergeReadStats(target, source) {
  for (const [key, value] of Object.entries(source || {})) {
    target[key] = (target[key] || 0) + (Number(value) || 0);
  }
  return target;
}

function parseNodeSecretVersion(value) {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : null;
}

function normalizeNodeSecretKeyring(raw) {
  const keyring = new Map();
  if (raw === undefined || raw === null) return keyring;
  if (raw instanceof Map) {
    for (const [version, secret] of raw.entries()) {
      const parsedVersion = parseNodeSecretVersion(version);
      const parsedSecret = String(secret || '').trim();
      if (!parsedVersion || !parsedSecret) throw new Error('node secret keyring is invalid');
      keyring.set(String(parsedVersion), parsedSecret);
    }
    return keyring;
  }
  if (Array.isArray(raw)) {
    for (const entry of raw) {
      if (!entry || typeof entry !== 'object') throw new Error('node secret keyring is invalid');
      const version = parseNodeSecretVersion(entry.version ?? entry.node_secret_version ?? entry.nodeSecretVersion);
      const secret = String(entry.node_secret ?? entry.nodeSecret ?? entry.secret ?? '').trim();
      if (!version || !secret) throw new Error('node secret keyring is invalid');
      keyring.set(String(version), secret);
    }
    return keyring;
  }
  if (typeof raw === 'object') {
    for (const [version, secret] of Object.entries(raw)) {
      const parsedVersion = parseNodeSecretVersion(version);
      const parsedSecret = String(secret || '').trim();
      if (!parsedVersion || !parsedSecret) throw new Error('node secret keyring is invalid');
      keyring.set(String(parsedVersion), parsedSecret);
    }
    return keyring;
  }
  throw new Error('node secret keyring is invalid');
}

function nodeSecretsForRow(row, keyring, fallbackSecret) {
  const secrets = [];
  const version = parseNodeSecretVersion(row && (row.secret_version ?? row.node_secret_version));
  if (version && keyring && keyring.has(String(version))) secrets.push(keyring.get(String(version)));
  if (fallbackSecret && !secrets.includes(fallbackSecret)) secrets.push(fallbackSecret);
  return secrets;
}

function decryptAesGcmPayload(envelope, key) {
  if (envelope.algorithm !== 'aes-256-gcm') throw new Error('unsupported trace payload algorithm');
  const iv = Buffer.from(envelope.iv, 'base64');
  const tag = Buffer.from(envelope.tag, 'base64');
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: GCM_TAG_BYTES });
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8'));
}

function decryptTraceEnvelopeWithHubPrivateKey(envelope, hubPrivateKey) {
  const hubEnvelope = envelope && envelope.hub_key_envelope;
  if (!hubEnvelope || typeof hubEnvelope !== 'object') throw new Error('missing hub key envelope');
  if (hubEnvelope.algorithm !== 'rsa-oaep-sha256') throw new Error('unsupported hub key envelope algorithm');
  const wrappedKey = Buffer.from(String(hubEnvelope.wrapped_key || ''), 'base64');
  const key = crypto.privateDecrypt(
    {
      key: hubPrivateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    wrappedKey,
  );
  if (key.length !== 32) throw new Error('invalid hub trace data key');
  return decryptAesGcmPayload(envelope, key);
}

function resolveTraceInputFiles(inputPath) {
  const stat = fs.statSync(inputPath);
  if (!stat.isDirectory()) return [inputPath];
  return fs.readdirSync(inputPath, { withFileTypes: true })
    .filter((entry) => entry.isFile() && /^llm-trace-.*\.jsonl$/.test(entry.name))
    .map((entry) => entry.name)
    .sort()
    .map((name) => path.join(inputPath, name));
}

function normalizeTraceReadOptions(opts = {}) {
  const hasExplicitSecret = opts.nodeSecret !== undefined;
  const secret = hasExplicitSecret ? opts.nodeSecret : (() => {
    try { return resolveEvomapNodeSecret(); } catch { return null; }
  })();
  return {
    ...opts,
    nodeSecret: secret,
    nodeSecretKeyring: normalizeNodeSecretKeyring(opts.nodeSecretKeyring),
  };
}

function hasOwn(row, key) {
  return !!row && Object.prototype.hasOwnProperty.call(row, key);
}

function firstPresent(row, keys) {
  for (const key of keys) {
    if (hasOwn(row, key) && row[key] !== undefined && row[key] !== null) return row[key];
  }
  return undefined;
}

function firstNonEmpty(row, keys) {
  for (const key of keys) {
    const value = firstPresent(row, [key]);
    if (value !== undefined && value !== '') return value;
  }
  return undefined;
}

function normalizeTimestamp(value) {
  if (value === undefined || value === null || value === '') return undefined;
  if (typeof value === 'number' && Number.isFinite(value)) {
    const ms = Math.abs(value) < 1000000000000 ? value * 1000 : value;
    const date = new Date(ms);
    return Number.isNaN(date.getTime()) ? String(value) : date.toISOString();
  }
  const text = String(value);
  const trimmed = text.trim();
  if (/^-?\d+(?:\.\d+)?$/.test(trimmed)) {
    const numeric = Number(trimmed);
    if (Number.isFinite(numeric)) return normalizeTimestamp(numeric);
  }
  return text;
}

function normalizeRoute(value) {
  if (value === undefined || value === null) return undefined;
  const text = String(value).trim();
  if (!text) return '';
  const parts = text.split(/\s+/);
  if (parts.length >= 2 && /^[A-Z]+$/i.test(parts[0])) return parts[1] || '';
  return text;
}

function normalizeBoolean(value) {
  if (value === undefined || value === null || value === '') return undefined;
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value !== 0;
  const text = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(text)) return true;
  if (['0', 'false', 'no', 'off'].includes(text)) return false;
  return Boolean(value);
}

function runtimeDiscoveryEnabled(value) {
  if (value === undefined || value === null || value === '') return false;
  if (typeof value === 'boolean') return value;
  const text = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on', 'auto'].includes(text)) return true;
  if (['0', 'false', 'no', 'off'].includes(text)) return false;
  return Boolean(text);
}

function findGitRoot(start) {
  let current;
  try {
    current = path.resolve(start || process.cwd());
  } catch {
    return '';
  }
  while (current && current !== path.dirname(current)) {
    if (fs.existsSync(path.join(current, '.git'))) return current;
    current = path.dirname(current);
  }
  return '';
}

function uniqueStrings(values) {
  const out = [];
  const seen = new Set();
  for (const value of values) {
    const text = String(value || '').trim();
    if (!text || seen.has(text)) continue;
    seen.add(text);
    out.push(text);
  }
  return out;
}

function runtimeWorkspaceCandidates(opts = {}) {
  return uniqueStrings([
    opts.workspaceRoot,
    process.env.EVOLVER_REPO_ROOT,
    process.cwd(),
    findGitRoot(process.cwd()),
  ]);
}

function splitRuntimeSessionDirs(value) {
  if (!value) return [];
  return String(value)
    .split(path.delimiter)
    .flatMap((part) => part.split(','))
    .map((dir) => dir.trim())
    .filter(Boolean);
}

// Platform-specific globalStorage dirs that hold Cursor's state.vscdb (FIX-4). Probed for the sqlite file
// during auto-discovery since the .jsonl-only transcript walker can't find a binary db.
function defaultCursorGlobalStorageDirs(opts = {}) {
  const home = opts.homedir || os.homedir();
  const platform = opts.platform || process.platform;
  const dirs = [];
  if (platform === 'darwin') {
    dirs.push(path.join(home, 'Library', 'Application Support', 'Cursor', 'User', 'globalStorage'));
  } else if (platform === 'win32') {
    const appData = (opts.env && opts.env.APPDATA) || process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
    dirs.push(path.join(appData, 'Cursor', 'User', 'globalStorage'));
  } else {
    dirs.push(path.join(home, '.config', 'Cursor', 'User', 'globalStorage'));
  }
  return dirs;
}

function defaultCursorVscdbFiles(opts = {}) {
  const out = [];
  for (const dir of defaultCursorGlobalStorageDirs(opts)) {
    const file = path.join(dir, 'state.vscdb');
    try {
      if (fs.existsSync(file) && fs.statSync(file).isFile()) out.push(file);
    } catch { /* unreadable */ }
  }
  return out;
}

function defaultRuntimeSessionDirs(opts = {}) {
  const home = opts.homedir || os.homedir();
  return [
    path.join(home, '.codex', 'sessions'),
    path.join(home, '.claude', 'projects'),
    // Gemini CLI chats: ~/.gemini/tmp/<project>/chats/session-*.jsonl (FIX-3). The collector only walks
    // .jsonl/.txt, so the .json variant is reachable via explicit export paths but not auto-discovery.
    path.join(home, '.gemini', 'tmp'),
    // Kimi CLI: ~/.kimi/sessions/<workspaceHash>/<sessionId>/wire.jsonl (FIX-5).
    path.join(home, '.kimi', 'sessions'),
  ].map((dir) => ({ path: dir, required: false })).filter((dir) => {
    try {
      return fs.existsSync(dir.path) && fs.statSync(dir.path).isDirectory();
    } catch {
      return false;
    }
  });
}

function runtimeSessionDirs(opts = {}) {
  const explicit = []
    .concat(Array.isArray(opts.runtimeSessionDirs) ? opts.runtimeSessionDirs : [])
    .concat(splitRuntimeSessionDirs(process.env[RUNTIME_SESSION_DIRS_ENV]))
    .concat(splitRuntimeSessionDirs(process.env[RUNTIME_SESSION_DIRS_ENV_LEGACY]))
    .concat(splitRuntimeSessionDirs(process.env.EVOLVER_CURSOR_TRANSCRIPTS_DIR))
    .map((dir) => ({ path: dir, required: true }));
  const enabled = runtimeDiscoveryEnabled(
    opts.runtimeSessions !== undefined
      ? opts.runtimeSessions
      : (process.env[RUNTIME_SESSION_DISCOVERY_ENV] ?? process.env[RUNTIME_SESSION_DISCOVERY_ENV_LEGACY]),
  ) || ['cursor', 'merge', 'runtime', 'codex', 'claude'].includes(String(process.env.EVOLVER_SESSION_SOURCE || '').trim().toLowerCase());
  const defaults = enabled ? defaultRuntimeSessionDirs(opts) : [];
  const out = [];
  const seen = new Set();
  for (const dir of explicit.concat(defaults)) {
    const resolved = path.resolve(dir.path);
    if (seen.has(resolved)) continue;
    seen.add(resolved);
    out.push({ path: resolved, required: dir.required });
  }
  return out;
}

function assertRuntimeSessionDirBoundary(dirPath, opts = {}) {
  const resolved = path.resolve(dirPath);
  const home = path.resolve(opts.homedir || os.homedir());
  const root = path.parse(resolved).root;
  if (resolved === root || resolved === home || home.startsWith(resolved + path.sep)) {
    throw new Error(`runtime session directory is too broad: ${resolved}`);
  }
  if (resolved === path.join(home, '.codex') || resolved === path.join(home, '.claude')) {
    throw new Error(`runtime session directory must be a session subdirectory: ${resolved}`);
  }
}

function traceRowError(row) {
  return firstNonEmpty(row, ['error', 'errorMessage', 'error_message']);
}

function traceRowStreamCancel(row) {
  return firstNonEmpty(row, ['stream_cancelled', 'streamCancelled']);
}

function traceRowStreamError(row) {
  return firstNonEmpty(row, ['stream_error', 'streamError']);
}

function normalizeAttempt(attempt) {
  if (!attempt || typeof attempt !== 'object') return null;
  const requestBody = firstPresent(attempt, ['request_body', 'requestBody']);
  const responseBody = firstPresent(attempt, ['response_body', 'responseBody']);
  const upstreamMode = firstPresent(attempt, ['upstream_mode', 'upstreamMode']);
  const contentType = firstPresent(attempt, ['content_type', 'contentType']);
  const error = traceRowError(attempt);
  const normalized = {
    ...attempt,
    attempt_index: firstPresent(attempt, ['attempt_index', 'attemptIndex']),
    ...(upstreamMode !== undefined ? { upstream_mode: upstreamMode } : {}),
    ...(contentType !== undefined ? { content_type: contentType } : {}),
    ...(requestBody !== undefined ? { request_body: normalizeBody(requestBody) } : {}),
    ...(responseBody !== undefined ? { response_body: normalizeBody(responseBody) } : {}),
    ...(error !== undefined ? { error } : {}),
  };
  delete normalized.attemptIndex;
  delete normalized.upstreamMode;
  delete normalized.contentType;
  delete normalized.requestBody;
  delete normalized.responseBody;
  delete normalized.errorMessage;
  return normalized;
}

function normalizeAttempts(attempts) {
  if (!Array.isArray(attempts)) return [];
  return attempts
    .map(normalizeAttempt)
    .filter(Boolean)
    .sort((a, b) => Number(a.attempt_index) - Number(b.attempt_index));
}

function isTrajectoryTraceRow(row) {
  return !!(
    row
    && typeof row === 'object'
    && (row.prism_compatible === true || row.event === 'llm_turn')
  );
}

function normalizeTraceRow(row) {
  if (!row || typeof row !== 'object') return row;
  const requestId = firstPresent(row, ['requestId', 'request_id']);
  const sessionId = firstPresent(row, ['sessionId', 'session_id']);
  const responseId = firstPresent(row, ['responseId', 'response_id']);
  const previousResponseId = firstPresent(row, ['previousResponseId', 'previous_response_id']);
  const timestamp = normalizeTimestamp(firstPresent(row, ['createdAtIso', 'timestamp', 'ts']));
  const pathValue = firstPresent(row, ['path', 'route']);
  const chosenModel = firstPresent(row, ['chosenModel', 'chosen_model']);
  const originalModel = firstPresent(row, ['originalModel', 'original_model']);
  const model = firstPresent(row, ['model']);
  const durationMs = firstPresent(row, ['durationMs', 'latency_ms']);
  const ttfbMs = firstPresent(row, ['ttfb_ms', 'ttfbMs', 'time_to_first_byte_ms', 'timeToFirstByteMs']);
  const headers = firstPresent(row, ['headers', 'response_headers', 'responseHeaders']);
  const stream = normalizeBoolean(firstPresent(row, ['isStream', 'stream']));
  const finishReason = firstPresent(row, ['finishReason', 'stop_reason']);
  const usage = row.usage && typeof row.usage === 'object' ? row.usage : {};
  const rowInputTokens = firstPresent(row, ['input_tokens']);
  const rowOutputTokens = firstPresent(row, ['output_tokens']);
  const inputTokens = rowInputTokens !== undefined ? rowInputTokens : firstPresent(usage, ['input_tokens']);
  const outputTokens = rowOutputTokens !== undefined ? rowOutputTokens : firstPresent(usage, ['output_tokens']);
  const requestBody = firstPresent(row, ['requestBody', 'request_body']);
  const responseBody = firstPresent(row, ['responseBody', 'response_body']);
  const attempts = normalizeAttempts(row.attempts);

  return {
    ...row,
    ...(requestId !== undefined ? { requestId } : {}),
    ...(sessionId !== undefined ? { sessionId } : {}),
    ...(responseId !== undefined ? { responseId } : {}),
    ...(previousResponseId !== undefined ? { previousResponseId } : {}),
    ...(timestamp !== undefined ? { createdAtIso: timestamp, timestamp } : {}),
    ...(pathValue !== undefined ? { path: normalizeRoute(pathValue) } : {}),
    ...(row.provider !== undefined && row.upstream === undefined ? { upstream: row.provider } : {}),
    ...(chosenModel !== undefined ? { chosenModel } : {}),
    ...(originalModel !== undefined ? { originalModel } : {}),
    ...(model !== undefined || chosenModel !== undefined || originalModel !== undefined
      ? { model: model ?? chosenModel ?? originalModel ?? '' }
      : {}),
    ...(durationMs !== undefined ? { durationMs } : {}),
    ...(ttfbMs !== undefined ? { ttfb_ms: ttfbMs } : {}),
    ...(headers !== undefined ? { headers } : {}),
    ...(stream !== undefined ? { isStream: stream } : {}),
    ...(finishReason !== undefined ? { finishReason } : {}),
    ...(inputTokens !== undefined ? { input_tokens: inputTokens } : {}),
    ...(outputTokens !== undefined ? { output_tokens: outputTokens } : {}),
    ...(requestBody !== undefined ? { requestBody } : {}),
    ...(responseBody !== undefined ? { responseBody } : {}),
    ...(attempts.length > 0 ? { attempts } : {}),
    ...(row.errorMessage === undefined && row.error !== undefined ? { errorMessage: row.error } : {}),
  };
}

function readTraceFileRowsDetailed(file, opts = {}) {
  let raw = '';
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch (err) {
    const wrapped = new Error(`trace input is not readable: ${file}`);
    wrapped.cause = err;
    throw wrapped;
  }
  const rows = [];
  const stats = newReadStats();
  stats.filesScanned += 1;
  for (const line of raw.split('\n')) {
    const s = line.trim();
    if (!s) continue;
    stats.rowsScanned += 1;
    let row = safeJsonParse(s, null);
    if (!row || typeof row !== 'object') {
      stats.invalidJson += 1;
      continue;
    }
    if (row.encrypted) {
      stats.encryptedRows += 1;
      const encryptedRow = row;
      const hubPrivateKey = String(opts.hubPrivateKey || '').trim();
      let decrypted = false;
      let hubDecryptFailed = false;
      if (hubPrivateKey && encryptedRow.hub_key_envelope) {
        try {
          row = decryptTraceEnvelopeWithHubPrivateKey(encryptedRow, hubPrivateKey);
          decrypted = true;
        } catch {
          hubDecryptFailed = true;
        }
      }
      if (!decrypted) {
        const secrets = nodeSecretsForRow(encryptedRow, opts.nodeSecretKeyring, opts.nodeSecret);
        if (secrets.length === 0) {
          if (hubDecryptFailed) {
            stats.decryptFailures += 1;
            if (!opts.allowPartial) throw new Error('failed to decrypt encrypted trace row with hub private key');
          } else {
            stats.skippedMissingSecret += 1;
            if (!opts.allowPartial) throw new Error('encrypted trace row cannot be exported without node secret or hub private key');
          }
          continue;
        }
        for (const secret of secrets) {
          try {
            row = decryptTraceEnvelope(encryptedRow, secret);
            decrypted = true;
            break;
          } catch {
            // Try the next configured secret before counting the row as failed.
          }
        }
        if (!decrypted) {
          stats.decryptFailures += 1;
          if (!opts.allowPartial) {
            throw new Error(hubDecryptFailed
              ? 'failed to decrypt encrypted trace row with hub private key or node secret'
              : 'failed to decrypt encrypted trace row');
          }
          continue;
        }
      }
    }
    if (isTrajectoryTraceRow(row)) {
      rows.push(normalizeTraceRow(row));
      stats.rowsRead += 1;
    } else {
      stats.nonPrismSkipped += 1;
    }
  }
  return { rows, stats };
}

function readTraceRowsDetailed(filePath, opts = {}) {
  const hasExplicitInput = filePath !== undefined && filePath !== null;
  const input = hasExplicitInput ? String(filePath) : resolveTraceFile();
  const hasExplicitSecret = opts.nodeSecret !== undefined;
  const secret = hasExplicitSecret ? opts.nodeSecret : (() => {
    try { return resolveEvomapNodeSecret(); } catch { return null; }
  })();
  const readOpts = {
    ...opts,
    nodeSecret: secret,
    nodeSecretKeyring: normalizeNodeSecretKeyring(opts.nodeSecretKeyring),
  };

  let files;
  if (hasExplicitInput) {
    try {
      files = resolveTraceInputFiles(input);
    } catch (err) {
      const wrapped = new Error(`trace input is not readable: ${input}`);
      wrapped.cause = err;
      throw wrapped;
    }
  } else {
    files = [input];
  }

  const rows = [];
  const stats = newReadStats();
  for (const file of files) {
    try {
      const result = readTraceFileRowsDetailed(file, readOpts);
      rows.push(...result.rows);
      mergeReadStats(stats, result.stats);
    } catch (err) {
      if (!hasExplicitInput) return { rows: [], stats: newReadStats() };
      throw err;
    }
  }
  return { rows, stats };
}

function readTraceRows(filePath, opts = {}) {
  return readTraceRowsDetailed(filePath, opts).rows;
}

function parseJsonlLines(chunk) {
  return parseJsonlLinesDetailed(chunk).rows;
}

function parseJsonlLinesDetailed(chunk) {
  const out = [];
  const stats = { rowsScanned: 0, rowsRead: 0, invalidJson: 0 };
  for (const line of String(chunk || '').split('\n')) {
    if (!line.trim()) continue;
    stats.rowsScanned += 1;
    const parsed = safeJsonParse(line, null);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      out.push(parsed);
      stats.rowsRead += 1;
    } else {
      stats.invalidJson += 1;
    }
  }
  return { rows: out, stats };
}

function isMetaText(text) {
  const value = String(text || '').trim();
  return value.length === 0 || META_MARKERS.some((marker) => value === marker || value.startsWith(marker));
}

function stringifyResult(content) {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content.map((item) => {
      if (typeof item === 'string') return item;
      if (item && typeof item === 'object' && typeof item.text === 'string') return item.text;
      return JSON.stringify(item);
    }).join('\n');
  }
  return JSON.stringify(content);
}

function extractContent(role, content) {
  if (typeof content === 'string') return [{ role, text: content, isMeta: isMetaText(content) }];
  if (!Array.isArray(content)) return [];
  const turns = [];
  for (const part of content) {
    if (!part || typeof part !== 'object') continue;
    if (part.type === 'text' && typeof part.text === 'string') {
      turns.push({ role, text: part.text, isMeta: isMetaText(part.text) });
    } else if (part.type === 'thinking' || part.type === 'redacted_thinking') {
      const text = typeof part.thinking === 'string' ? part.thinking : (typeof part.text === 'string' ? part.text : '');
      // Preserve the reasoning turn even when the visible thinking text is empty (redacted/encrypted-only
      // thinking blocks carry just a signature). Dropping it silently loses the signal that the model
      // reasoned at this step; instead mark it thinking_empty:true so downstream can account for it (FIX-7).
      turns.push({
        role: 'assistant',
        text,
        reasoning: true,
        ...(text ? {} : { thinking_empty: true }),
        ...runtimeMetadataFromSource(part),
        isMeta: false,
      });
    } else if (part.type === 'tool_use') {
      turns.push({
        role: 'assistant',
        text: '',
        toolName: String(part.name || ''),
        ...(part.id ? { toolUseId: String(part.id) } : {}),
        ...(part.input !== undefined ? { toolInput: part.input } : {}),
        isMeta: false,
      });
    } else if (part.type === 'tool_result') {
      const result = stringifyResult(part.content);
      turns.push({
        role: 'tool',
        text: '',
        toolResult: result,
        ...(part.tool_use_id ? { toolUseId: String(part.tool_use_id) } : {}),
        ...(part.is_error ? { errorMessage: result } : {}),
        isMeta: false,
      });
    }
  }
  return turns;
}

function normalizedTokenCount(value) {
  if (value === undefined || value === null || value === '') return undefined;
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : undefined;
}

function runtimeMetadataFromSource(source) {
  if (!source || typeof source !== 'object') return {};
  const meta = objectWithKeys(source.meta);
  const explicitMetadata = objectWithKeys(source.metadata);
  const metadata = mergePlainObjects(meta, explicitMetadata);
  const usage = source.usage && typeof source.usage === 'object' && !Array.isArray(source.usage)
    ? source.usage
    : (metadata && metadata.usage && typeof metadata.usage === 'object' && !Array.isArray(metadata.usage)
      ? metadata.usage
      : null);
  const inputRaw = firstPresent(source, ['input_tokens', 'inputTokens', 'prompt_tokens', 'promptTokens']);
  const outputRaw = firstPresent(source, ['output_tokens', 'outputTokens', 'completion_tokens', 'completionTokens']);
  const usageInputRaw = usage ? firstPresent(usage, ['input_tokens', 'inputTokens', 'prompt_tokens', 'promptTokens']) : undefined;
  const usageOutputRaw = usage ? firstPresent(usage, ['output_tokens', 'outputTokens', 'completion_tokens', 'completionTokens']) : undefined;
  const reasoningSignature = firstPresent(source, ['reasoning_signature', 'reasoningSignature', 'signature']);
  const encryptedSignature = firstPresent(source, ['encrypted_signature', 'encryptedSignature']);
  const encryptedContent = firstPresent(source, ['encrypted_content', 'encryptedContent']);
  const payload = firstPresent(source, ['payload']);
  const sourceRecord = firstPresent(source, ['source_record', 'sourceRecord', 'original_record', 'originalRecord']);
  const rawRow = firstPresent(source, ['raw_row', 'rawRow', 'raw_record', 'rawRecord']);
  const headers = firstPresent(source, ['headers', 'response_headers', 'responseHeaders']);
  const ttfbMs = firstPresent(source, ['ttfb_ms', 'ttfbMs', 'time_to_first_byte_ms', 'timeToFirstByteMs']);
  const risk = firstPresent(source, ['risk']) ?? (metadata ? metadata.risk : undefined);
  const fidelity = firstPresent(source, ['fidelity']) ?? (metadata ? metadata.fidelity : undefined);
  const confidentiality = firstPresent(source, ['confidentiality']) ?? (metadata ? metadata.confidentiality : undefined);
  const clientSource = firstString(source, ['client_source', 'clientSource'])
    || (metadata ? firstString(metadata, ['client_source', 'clientSource']) : undefined);
  const modelName = firstString(source, ['model', 'model_name', 'modelName'])
    || (metadata ? firstString(metadata, ['model', 'model_name', 'modelName']) : undefined);
  const inputTokens = normalizedTokenCount(inputRaw !== undefined ? inputRaw : usageInputRaw);
  const outputTokens = normalizedTokenCount(outputRaw !== undefined ? outputRaw : usageOutputRaw);
  return {
    ...(modelName !== undefined && modelName !== null && modelName !== '' ? { model: String(modelName) } : {}),
    ...(metadata ? { metadata } : {}),
    ...(usage ? { usage } : {}),
    ...(risk !== undefined ? { risk } : {}),
    ...(fidelity !== undefined ? { fidelity } : {}),
    ...(confidentiality !== undefined ? { confidentiality } : {}),
    ...(clientSource ? { client_source: clientSource } : {}),
    ...(inputTokens !== undefined ? { input_tokens: inputTokens } : {}),
    ...(outputTokens !== undefined ? { output_tokens: outputTokens } : {}),
    ...(reasoningSignature !== undefined ? { reasoning_signature: String(reasoningSignature) } : {}),
    ...(encryptedSignature !== undefined ? { encrypted_signature: String(encryptedSignature) } : {}),
    ...(encryptedContent !== undefined ? { encrypted_content: encryptedContent } : {}),
    ...(payload !== undefined ? { payload } : {}),
    ...(sourceRecord !== undefined ? { source_record: sourceRecord } : {}),
    ...(rawRow !== undefined ? { raw_row: rawRow } : {}),
    ...(headers !== undefined ? { headers } : {}),
    ...(ttfbMs !== undefined ? { ttfb_ms: ttfbMs } : {}),
  };
}

function applyRuntimeMessageMetadata(turns, metadata) {
  if (!Array.isArray(turns) || turns.length === 0) return turns;
  if (!metadata || typeof metadata !== 'object' || Object.keys(metadata).length === 0) return turns;
  let messageScopedApplied = false;
  return turns.map((turn) => {
    const out = { ...turn };
    if (metadata.model !== undefined && out.model === undefined) out.model = metadata.model;
    if (!messageScopedApplied) {
      for (const key of [
        'metadata',
        'usage',
        'risk',
        'fidelity',
        'confidentiality',
        'client_source',
        'input_tokens',
        'output_tokens',
        'payload',
        'reasoning_signature',
        'encrypted_signature',
        'encrypted_content',
        'source_record',
        'raw_row',
        'headers',
        'ttfb_ms',
      ]) {
        if (metadata[key] !== undefined && out[key] === undefined) out[key] = metadata[key];
      }
      messageScopedApplied = true;
    }
    return out;
  });
}

function correlateToolNames(turns) {
  const nameById = new Map();
  for (const turn of turns) {
    if (turn.toolUseId && turn.toolName) nameById.set(turn.toolUseId, turn.toolName);
  }
  if (nameById.size === 0) return turns;
  return turns.map((turn) => {
    if (turn.toolName || !turn.toolUseId || !nameById.has(turn.toolUseId)) return turn;
    return { ...turn, toolName: nameById.get(turn.toolUseId) };
  });
}

function anthropicStyleTranscript(chunk) {
  return correlateToolNames(parseJsonlLines(chunk).flatMap((obj) => {
    const type = obj.type ?? obj.role;
    if (type !== 'user' && type !== 'assistant') return [];
    const msg = obj.message && typeof obj.message === 'object' ? obj.message : {};
    const timestamp = typeof obj.timestamp === 'string'
      ? obj.timestamp
      : (typeof msg.timestamp === 'string' ? msg.timestamp : undefined);
    const turns = applyRuntimeMessageMetadata(
      extractContent(type, msg.content ?? obj.content),
      runtimeMetadataFromSource(msg),
    );
    return timestamp ? turns.map((turn) => ({ ...turn, timestamp })) : turns;
  }));
}

function codexMessageText(content) {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return '';
  return content
    .filter((part) => part && typeof part === 'object' && CODEX_TEXT_TYPES.has(String(part.type)))
    .map((part) => (typeof part.text === 'string' ? part.text : ''))
    .join('');
}

function exitCodeFailed(output) {
  const match = /^Exit code:\s*(-?\d+)/.exec(String(output || ''));
  return match ? Number(match[1]) !== 0 : false;
}

function stringifyReasoningSummary(summary) {
  if (typeof summary === 'string') return summary;
  if (!Array.isArray(summary)) return '';
  return summary.map((item) => {
    if (typeof item === 'string') return item;
    if (!item || typeof item !== 'object') return '';
    for (const key of ['text', 'summary', 'content']) {
      if (typeof item[key] === 'string') return item[key];
    }
    return '';
  }).filter(Boolean).join('\n');
}

function payloadWithoutKeys(payload, keys) {
  const out = { ...payload };
  for (const key of keys) delete out[key];
  return out;
}

function isCodexNativeToolCallType(type) {
  const value = String(type || '');
  return /(?:^|_)(?:tool|web_search|tool_search).*_call$/.test(value);
}

function isCodexNativeToolOutputType(type) {
  const value = String(type || '');
  return /(?:^|_)(?:tool|web_search|tool_search).*(?:_output|_result)$/.test(value);
}

function codexNativeToolCallTurn(payload) {
  return {
    role: 'assistant',
    text: '',
    toolName: String(payload.type || 'unknown'),
    ...(payload.call_id || payload.id ? { toolUseId: String(payload.call_id || payload.id) } : {}),
    toolInput: payloadWithoutKeys(payload, ['type', 'id', 'call_id']),
    isMeta: false,
  };
}

function codexNativeToolResultTurn(payload) {
  return {
    role: 'tool',
    text: '',
    toolName: String(payload.type || 'tool_result'),
    ...(payload.call_id || payload.id ? { toolUseId: String(payload.call_id || payload.id) } : {}),
    toolResult: JSON.stringify(payloadWithoutKeys(payload, ['type', 'id', 'call_id'])),
    isMeta: false,
  };
}

function codexTranscript(chunk) {
  return correlateToolNames(parseJsonlLines(chunk).flatMap((obj) => {
    if (obj.type !== 'response_item') return [];
    const payload = obj.payload && typeof obj.payload === 'object' ? obj.payload : null;
    if (!payload) return [];
    const timestamp = typeof obj.timestamp === 'string' ? obj.timestamp : undefined;
    const stamp = (turns) => (timestamp ? turns.map((turn) => ({ ...turn, timestamp })) : turns);
    const callId = payload.call_id || payload.id;
    switch (payload.type) {
      case 'message': {
        const rawRole = String(payload.role || 'user');
        const role = rawRole === 'developer'
          ? 'system'
          : (['user', 'assistant', 'tool', 'system'].includes(rawRole) ? rawRole : 'user');
        const text = codexMessageText(payload.content);
        if (!text) return [];
        const isMeta = role === 'system' || isMetaText(text) || CODEX_META_TAGS.some((tag) => text.startsWith(tag));
        return stamp(applyRuntimeMessageMetadata(
          [{ role, text, isMeta }],
          runtimeMetadataFromSource(payload),
        ));
      }
      case 'function_call':
      case 'custom_tool_call':
        return stamp(applyRuntimeMessageMetadata([{
          role: 'assistant',
          text: '',
          toolName: String(payload.name || ''),
          ...(callId ? { toolUseId: String(callId) } : {}),
          ...(payload.arguments !== undefined ? { toolInput: payload.arguments } : {}),
          ...(payload.input !== undefined ? { toolInput: payload.input } : {}),
          isMeta: false,
        }], runtimeMetadataFromSource(payload)));
      case 'function_call_output':
      case 'custom_tool_call_output': {
        const output = typeof payload.output === 'string' ? payload.output : JSON.stringify(payload.output ?? '');
        return stamp(applyRuntimeMessageMetadata([{
          role: 'tool',
          text: '',
          toolResult: output,
          ...(callId ? { toolUseId: String(callId) } : {}),
          ...(exitCodeFailed(output) ? { errorMessage: output } : {}),
          isMeta: false,
        }], runtimeMetadataFromSource(payload)));
      }
      case 'reasoning': {
        const text = stringifyReasoningSummary(payload.summary);
        const metadata = runtimeMetadataFromSource(payload);
        if (!text && Object.keys(metadata).length === 0) return [];
        return stamp(applyRuntimeMessageMetadata([{
          role: 'assistant',
          text,
          reasoning: true,
          isMeta: false,
        }], metadata));
      }
      default:
        if (isCodexNativeToolCallType(payload.type)) {
          return stamp(applyRuntimeMessageMetadata([codexNativeToolCallTurn(payload)], runtimeMetadataFromSource(payload)));
        }
        if (isCodexNativeToolOutputType(payload.type)) {
          return stamp(applyRuntimeMessageMetadata([codexNativeToolResultTurn(payload)], runtimeMetadataFromSource(payload)));
        }
        return [];
    }
  }));
}

function parseGenericChatContainers(chunk) {
  const text = String(chunk || '').trim();
  if (!text) return { messages: [], metadata: {} };
  const parsed = safeJsonParse(text, undefined);
  if (parsed !== undefined) return genericChatMessagesFromValue(parsed);
  return text.split('\n').reduce((acc, line) => {
    const row = line.trim();
    if (!row) return acc;
    const obj = safeJsonParse(row, null);
    if (!obj) return acc;
    const parsedRow = genericChatMessagesFromValue(obj);
    acc.messages.push(...parsedRow.messages);
    acc.metadata = mergeSessionEnvelope(acc.metadata, parsedRow.metadata);
    return acc;
  }, { messages: [], metadata: {} });
}

function genericSystemPromptFromRecord(value) {
  if (!value || typeof value !== 'object') return '';
  const meta = objectWithKeys(value.meta);
  const metadata = objectWithKeys(value.metadata);
  return firstString(value, ['system_prompt', 'systemPrompt'])
    || firstString(metadata, ['system_prompt', 'systemPrompt'])
    || firstString(meta, ['system_prompt', 'systemPrompt'])
    || '';
}

function withGenericSystemPrompt(messages, sourceRecord) {
  const prompt = genericSystemPromptFromRecord(sourceRecord);
  if (!prompt) return messages;
  const alreadyPresent = messages.some((msg) => (
    msg
    && typeof msg === 'object'
    && normalizeGenericChatRole(msg.role) === 'system'
    && genericChatText(msg.content) === prompt
  ));
  if (alreadyPresent) return messages;
  return [{ role: 'system', content: prompt }, ...messages];
}

function attachSourceRecordToMessages(messages, sourceRecord) {
  const explicitSource = firstPresent(sourceRecord, ['source_record', 'sourceRecord', 'original_record', 'originalRecord']);
  const explicitRaw = firstPresent(sourceRecord, ['raw_row', 'rawRow', 'raw_record', 'rawRecord']);
  const source = explicitSource !== undefined ? explicitSource : sourceRecord;
  const raw = explicitRaw !== undefined ? explicitRaw : sourceRecord;
  return messages.map((msg) => {
    if (!msg || typeof msg !== 'object') return msg;
    return {
      ...msg,
      ...(msg.source_record === undefined && msg.sourceRecord === undefined ? { source_record: source } : {}),
      ...(msg.raw_row === undefined && msg.rawRow === undefined ? { raw_row: raw } : {}),
    };
  });
}

function genericChatMessagesFromValue(value) {
  if (Array.isArray(value)) {
    return value.reduce((acc, item) => {
      const parsed = genericChatMessagesFromValue(item);
      acc.messages.push(...parsed.messages);
      acc.metadata = mergeSessionEnvelope(acc.metadata, parsed.metadata);
      return acc;
    }, { messages: [], metadata: {} });
  }
  if (!value || typeof value !== 'object') return { messages: [], metadata: {} };
  const metadata = genericChatMetadataFromRecord(value);
  if (Array.isArray(value.prompt)) {
    return {
      messages: attachSourceRecordToMessages(withGenericSystemPrompt(value.prompt
        .filter((item) => item && typeof item === 'object')
        .concat(candidateMessages(value.candidates)), value), value),
      metadata,
    };
  }
  if (Array.isArray(value.messages)) {
    return { messages: attachSourceRecordToMessages(withGenericSystemPrompt(value.messages.filter((item) => item && typeof item === 'object'), value), value), metadata };
  }
  if (Array.isArray(value.turns)) {
    return { messages: attachSourceRecordToMessages(withGenericSystemPrompt(value.turns.filter((item) => item && typeof item === 'object'), value), value), metadata };
  }
  const requestResponseMessages = requestResponseMessagesFromValue(value);
  if (requestResponseMessages.length > 0) return { messages: attachSourceRecordToMessages(withGenericSystemPrompt(requestResponseMessages, value), value), metadata };
  if (value.message && typeof value.message === 'object') {
    const parsed = genericChatMessagesFromValue(value.message);
    return { messages: parsed.messages, metadata: mergeSessionEnvelope(metadata, parsed.metadata) };
  }
  return typeof value.role === 'string' ? { messages: attachSourceRecordToMessages([value], value), metadata } : { messages: [], metadata };
}

function genericChatMetadataFromRecord(value) {
  const meta = objectWithKeys(value.meta) || {};
  const metadata = objectWithKeys(value.metadata) || {};
  const combinedMetadata = mergePlainObjects(meta, metadata);
  const request = parseJsonish(value.request);
  const requestBody = parseJsonish(value.request_body ?? value.requestBody);
  const response = parseJsonish(value.response);
  const responseBody = parseJsonish(value.response_body ?? value.responseBody);
  const responseData = response && typeof response === 'object' && !Array.isArray(response)
    ? parseJsonish(response.response_data ?? response.responseData)
    : undefined;
  const responseBodyData = responseBody && typeof responseBody === 'object' && !Array.isArray(responseBody)
    ? parseJsonish(responseBody.response_data ?? responseBody.responseData)
    : undefined;
  const sessionId = firstString(value, ['trajectory_id', 'trajectoryId', 'session_id', 'sessionId', 'task_id', 'taskId', 'id'])
    || firstString(metadata, ['trajectory_id', 'trajectoryId', 'session_id', 'sessionId'])
    || firstString(meta, ['trajectory_id', 'trajectoryId', 'session_id', 'sessionId']);
  const provider = firstString(value, ['provider', 'wire_api', 'wireApi', 'upstream', 'source'])
    || firstString(metadata, ['provider', 'wire_api', 'wireApi', 'upstream', 'source', 'client_source', 'clientSource'])
    || firstString(meta, ['provider', 'wire_api', 'wireApi', 'upstream', 'source']);
  const clientSource = firstString(value, ['client_source', 'clientSource'])
    || firstString(metadata, ['client_source', 'clientSource'])
    || firstString(meta, ['client_source', 'clientSource']);
  const modelKeys = ['model', 'model_name', 'modelName', 'chosen_model', 'chosenModel'];
  const model = firstString(value, modelKeys)
    || firstString(metadata, modelKeys)
    || firstString(meta, modelKeys)
    || firstString(request, modelKeys)
    || firstString(requestBody, modelKeys)
    || firstString(responseData, modelKeys)
    || firstString(responseBodyData, modelKeys)
    || firstString(responseBody, modelKeys)
    || firstString(response, modelKeys);
  const startedAt = firstString(value, ['created_at', 'createdAt', 'timestamp', 'request_time', 'requestTime'])
    || firstString(metadata, ['created_at', 'createdAt', 'create_time', 'createTime', 'timestamp', 'request_time', 'requestTime'])
    || firstString(meta, ['created_at', 'createdAt', 'create_time', 'createTime', 'timestamp', 'request_time', 'requestTime']);
  const requestTime = firstString(value, ['request_time', 'requestTime'])
    || firstString(metadata, ['request_time', 'requestTime'])
    || firstString(meta, ['request_time', 'requestTime']);
  const responseTime = firstString(value, ['response_time', 'responseTime'])
    || firstString(metadata, ['response_time', 'responseTime'])
    || firstString(meta, ['response_time', 'responseTime']);
  const tools = value.tools !== undefined
    ? value.tools
    : (request && typeof request === 'object' ? request.tools : (requestBody && typeof requestBody === 'object' ? requestBody.tools : undefined));
  const usage = firstPresent(value, ['usage']) ?? firstPresent(metadata, ['usage']) ?? firstPresent(meta, ['usage']);
  const risk = firstPresent(value, ['risk']) ?? firstPresent(metadata, ['risk']) ?? firstPresent(meta, ['risk']);
  const fidelity = firstPresent(value, ['fidelity']) ?? firstPresent(metadata, ['fidelity']) ?? firstPresent(meta, ['fidelity']);
  const confidentiality = firstPresent(value, ['confidentiality']) ?? firstPresent(metadata, ['confidentiality']) ?? firstPresent(meta, ['confidentiality']);
  const headers = firstPresent(value, ['headers', 'response_headers', 'responseHeaders'])
    ?? firstPresent(metadata, ['headers', 'response_headers', 'responseHeaders'])
    ?? firstPresent(meta, ['headers', 'response_headers', 'responseHeaders']);
  const ttfbMs = firstPresent(value, ['ttfb_ms', 'ttfbMs', 'time_to_first_byte_ms', 'timeToFirstByteMs'])
    ?? firstPresent(metadata, ['ttfb_ms', 'ttfbMs', 'time_to_first_byte_ms', 'timeToFirstByteMs'])
    ?? firstPresent(meta, ['ttfb_ms', 'ttfbMs', 'time_to_first_byte_ms', 'timeToFirstByteMs']);
  const nativeCall = nativeCallEnvelopeFromRecord(value, {
    provider,
    startedAt,
    requestTime,
    responseTime,
  });
  return {
    ...(sessionId ? { sessionId } : {}),
    ...(provider ? { provider } : {}),
    ...(clientSource ? { clientSource } : {}),
    ...(model ? { model } : {}),
    ...(tools !== undefined ? { tools } : {}),
    ...(startedAt ? { startedAt } : {}),
    ...(combinedMetadata ? { metadata: combinedMetadata } : {}),
    ...(usage !== undefined ? { usage } : {}),
    ...(risk !== undefined ? { risk } : {}),
    ...(fidelity !== undefined ? { fidelity } : {}),
    ...(confidentiality !== undefined ? { confidentiality } : {}),
    ...(headers !== undefined ? { headers } : {}),
    ...(ttfbMs !== undefined ? { ttfb_ms: ttfbMs } : {}),
    ...(nativeCall ? { nativeCalls: [nativeCall] } : {}),
  };
}

function nativeCallEnvelopeFromRecord(value, metadata = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const hasRequestBody = hasOwn(value, 'request') || hasOwn(value, 'request_body') || hasOwn(value, 'requestBody');
  const hasResponseBody = hasOwn(value, 'response') || hasOwn(value, 'response_body') || hasOwn(value, 'responseBody');
  if (!hasRequestBody && !hasResponseBody) return null;
  const requestBody = parseJsonish(firstPresent(value, ['request', 'request_body', 'requestBody']));
  const responseBody = parseJsonish(firstPresent(value, ['response', 'response_body', 'responseBody']));
  return {
    ...(metadata.provider ? { provider: metadata.provider } : {}),
    ...(metadata.startedAt ? { timestamp: metadata.startedAt } : {}),
    ...(metadata.requestTime ? { request_time: metadata.requestTime } : {}),
    ...(metadata.responseTime ? { response_time: metadata.responseTime } : {}),
    ...(hasRequestBody ? { request_body: requestBody } : {}),
    ...(hasResponseBody ? { response_body: responseBody } : {}),
  };
}

// Convert a Gemini part ({text} | {functionCall:{name,args}} | {functionResponse:{name,response}} | {thought})
// into the generic-chat content-part shape the rest of the pipeline understands (tool_use / function_call_output
// / thinking / text). Returns null for parts we don't map so callers can skip them.
function geminiPartToGenericContent(part) {
  if (!part || typeof part !== 'object') return null;
  const fc = part.functionCall;
  if (fc && typeof fc === 'object') {
    return {
      type: 'tool_use',
      ...(fc.id || part.id ? { id: String(fc.id || part.id) } : {}),
      name: String(fc.name || ''),
      input: fc.args,
    };
  }
  const fr = part.functionResponse;
  if (fr && typeof fr === 'object') {
    return {
      type: 'function_call_output',
      ...(fr.id || part.id ? { tool_use_id: String(fr.id || part.id) } : {}),
      ...(fr.name ? { name: String(fr.name) } : {}),
      content: fr.response !== undefined ? fr.response : fr,
    };
  }
  if (typeof part.text === 'string') {
    // Gemini marks reasoning parts with `thought: true`.
    if (part.thought === true) return { type: 'thinking', thinking: part.text };
    return { type: 'text', text: part.text };
  }
  return null;
}

function geminiCandidateMessages(candidates) {
  if (!Array.isArray(candidates)) return [];
  return candidates.flatMap((candidate) => {
    if (!candidate || typeof candidate !== 'object') return [];
    const content = candidate.content && typeof candidate.content === 'object' ? candidate.content : null;
    const parts = content && Array.isArray(content.parts) ? content.parts : [];
    const mapped = parts.map(geminiPartToGenericContent).filter(Boolean);
    if (mapped.length === 0) return [];
    // Gemini response content.role is "model" -> normalized to assistant downstream.
    return [{ role: content && content.role ? content.role : 'model', content: mapped }];
  });
}

function responseMessagesFromBody(value) {
  const body = parseJsonish(value);
  if (!body || typeof body !== 'object' || Array.isArray(body)) return [];
  // Gemini / Vertex non-streaming response: candidates[].content.parts (camelCase functionCall, no `type`).
  if (Array.isArray(body.candidates)) {
    const geminiMessages = geminiCandidateMessages(body.candidates);
    if (geminiMessages.length > 0) {
      return geminiMessages.flatMap((message) => {
        if (body.model !== undefined && message.model === undefined) message.model = body.model;
        if (body.usageMetadata !== undefined && message.usage === undefined) message.usage = body.usageMetadata;
        return genericChatMessagesFromValue(message).messages;
      });
    }
  }
  if (body.message && typeof body.message === 'object') return genericChatMessagesFromValue(body.message).messages;
  if (Array.isArray(body.choices)) {
    return body.choices.flatMap((choice) => {
      if (!choice || typeof choice !== 'object' || !choice.message || typeof choice.message !== 'object') return [];
      const message = { ...choice.message };
      if (body.model !== undefined && message.model === undefined) message.model = body.model;
      if (body.usage !== undefined && message.usage === undefined) message.usage = body.usage;
      return genericChatMessagesFromValue(message).messages;
    });
  }
  if (typeof body.role === 'string') return genericChatMessagesFromValue(body).messages;
  if (body.content !== undefined || body.output !== undefined || body.tool_calls !== undefined || body.usage !== undefined) {
    return [{
      role: 'assistant',
      ...(body.content !== undefined ? { content: body.content } : {}),
      ...(body.output !== undefined ? { content: body.output } : {}),
      ...(body.tool_calls !== undefined ? { tool_calls: body.tool_calls } : {}),
      ...(body.model !== undefined ? { model: body.model } : {}),
      ...(body.usage !== undefined ? { usage: body.usage } : {}),
    }];
  }
  return [];
}

function candidateMessages(value) {
  if (Array.isArray(value)) return value.flatMap(candidateMessages);
  if (value && typeof value === 'object') return genericChatMessagesFromValue(value).messages;
  return [];
}

function requestResponseMessagesFromValue(value) {
  const request = parseJsonish(value.request ?? value.request_body ?? value.requestBody);
  const responseEnvelope = parseJsonish(value.response ?? value.response_body ?? value.responseBody);
  const response = responseEnvelope && typeof responseEnvelope === 'object' && !Array.isArray(responseEnvelope)
    && (responseEnvelope.response_data !== undefined || responseEnvelope.responseData !== undefined)
    ? parseJsonish(responseEnvelope.response_data ?? responseEnvelope.responseData)
    : responseEnvelope;
  const messages = [];
  if (request && typeof request === 'object' && !Array.isArray(request)) {
    if (typeof request.instructions === 'string') messages.push({ role: 'system', content: request.instructions });
    messages.push(...genericChatMessagesFromValue(request).messages);
  }
  messages.push(...responseMessagesFromBody(response));
  return messages;
}

function isGenericSessionWrapper(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value) && (
    Array.isArray(value.messages)
    || Array.isArray(value.turns)
    || Array.isArray(value.prompt)
    || value.request !== undefined
    || value.request_body !== undefined
    || value.requestBody !== undefined
    || value.response !== undefined
    || value.response_body !== undefined
    || value.responseBody !== undefined
  );
}

function normalizeGenericChatRole(role) {
  const value = String(role || '').toLowerCase();
  if (value === 'developer') return 'system';
  if (value === 'human') return 'user';
  if (value === 'model') return 'assistant';
  if (value === 'function') return 'tool';
  if (['system', 'user', 'assistant', 'tool'].includes(value)) return value;
  return '';
}

function genericChatText(content) {
  if (typeof content === 'string') return content;
  if (content === undefined || content === null) return '';
  if (Array.isArray(content)) {
    return content.map((part) => {
      if (typeof part === 'string') return part;
      if (!part || typeof part !== 'object') return '';
      if (typeof part.text === 'string') return part.text;
      if (typeof part.content === 'string') return part.content;
      return '';
    }).filter(Boolean).join('\n');
  }
  if (typeof content === 'object') {
    if (typeof content.text === 'string') return content.text;
    if (typeof content.content === 'string') return content.content;
  }
  return '';
}

function genericChatContentToolTurns(role, content) {
  if (!Array.isArray(content)) return [];
  return content.flatMap((part) => {
    if (!part || typeof part !== 'object') return [];
    // Gemini / Vertex camelCase parts (functionCall / functionResponse, no `type`).
    if (part.functionCall && typeof part.functionCall === 'object') {
      const fc = part.functionCall;
      return [genericChatToolCallTurn({ id: fc.id || part.id, name: fc.name, args: fc.args })];
    }
    if (part.functionResponse && typeof part.functionResponse === 'object') {
      const fr = part.functionResponse;
      return [genericChatToolResultTurn({
        tool_use_id: fr.id || part.id,
        name: fr.name,
        content: fr.response !== undefined ? fr.response : fr,
      })];
    }
    if (part.type === 'tool_use' || part.type === 'function_call') {
      return [genericChatToolCallTurn(part)];
    }
    if (part.type === 'tool_result' || part.type === 'function_call_output') {
      return [genericChatToolResultTurn(part)];
    }
    if (role === 'assistant' && part.type === 'thinking') {
      const text = typeof part.thinking === 'string' ? part.thinking : genericChatText(part);
      return text ? [{
        role: 'assistant',
        text,
        reasoning: true,
        ...runtimeMetadataFromSource(part),
        isMeta: false,
      }] : [];
    }
    return [];
  });
}

function genericChatToolCallTurn(call) {
  const raw = call && typeof call === 'object' ? call : {};
  const fn = raw.function && typeof raw.function === 'object' ? raw.function : {};
  const toolInput = fn.arguments !== undefined
    ? fn.arguments
    : (raw.arguments !== undefined
      ? raw.arguments
      : (raw.input !== undefined ? raw.input : raw.args)); // raw.args: Gemini functionCall
  return {
    role: 'assistant',
    text: '',
    toolName: String(fn.name || raw.name || ''),
    ...(raw.id || raw.tool_use_id || raw.call_id || raw.tool_call_id
      ? { toolUseId: String(raw.id || raw.tool_use_id || raw.call_id || raw.tool_call_id) }
      : {}),
    ...(toolInput !== undefined ? { toolInput } : {}),
    isMeta: false,
  };
}

function genericChatToolResultTurn(msg) {
  const result = msg.output !== undefined
    ? stringifyResult(msg.output)
    : stringifyResult(msg.content ?? msg.result ?? '');
  return {
    role: 'tool',
    text: '',
    toolResult: result,
    ...(msg.tool_call_id || msg.tool_use_id || msg.call_id || msg.id
      ? { toolUseId: String(msg.tool_call_id || msg.tool_use_id || msg.call_id || msg.id) }
      : {}),
    ...(msg.name ? { toolName: String(msg.name) } : {}),
    ...(msg.is_error ? { errorMessage: result } : {}),
    isMeta: false,
  };
}

function genericChatMessageTurns(msg) {
  if (!msg || typeof msg !== 'object') return [];
  const role = normalizeGenericChatRole(msg.role);
  if (!role) return [];
  const timestamp = normalizeTimestamp(firstPresent(msg, ['timestamp', 'createdAt', 'created_at', 'ts']));
  const stamp = (turns) => timestamp ? turns.map((turn) => ({ ...turn, timestamp })) : turns;
  if (role === 'tool') return stamp(applyRuntimeMessageMetadata([genericChatToolResultTurn(msg)], runtimeMetadataFromSource(msg)));

  const turns = [];
  const reasoningContent = firstString(msg, ['reasoning_content', 'reasoningContent']);
  if (role === 'assistant' && reasoningContent) {
    turns.push({
      role: 'assistant',
      text: reasoningContent,
      reasoning: true,
      ...runtimeMetadataFromSource(msg),
      isMeta: false,
    });
  }
  const thinking = firstPresent(msg, ['thinking', 'thinking_text', 'thinkingText']);
  const thinkingText = typeof thinking === 'string' ? thinking : genericChatText(thinking);
  if (role === 'assistant' && thinkingText) {
    turns.push({
      role: 'assistant',
      text: thinkingText,
      reasoning: true,
      ...runtimeMetadataFromSource(msg),
      isMeta: false,
    });
  }
  const text = genericChatText(msg.content);
  if (text) turns.push({
    role,
    text,
    isMeta: role === 'system' || isMetaText(text),
  });
  turns.push(...genericChatContentToolTurns(role, msg.content));
  if (Array.isArray(msg.tool_calls)) {
    for (const call of msg.tool_calls) turns.push(genericChatToolCallTurn(call));
  }
  if (msg.function_call && typeof msg.function_call === 'object') {
    turns.push(genericChatToolCallTurn(msg.function_call));
  }
  return stamp(applyRuntimeMessageMetadata(turns, runtimeMetadataFromSource(msg)));
}

function applyGenericSessionMetadata(turns, metadata) {
  if (!metadata || typeof metadata !== 'object' || Object.keys(metadata).length === 0) return turns;
  let messageScopedApplied = false;
  const hasTurnUsage = turns.some((turn) => (
    turn
    && (
      turn.usage !== undefined
      || turn.input_tokens !== undefined
      || turn.output_tokens !== undefined
      || turn.inputTokens !== undefined
      || turn.outputTokens !== undefined
    )
  ));
  return turns.map((turn) => {
    const out = metadata.model && !turn.model ? { ...turn, model: metadata.model } : { ...turn };
    if (!messageScopedApplied) {
      for (const key of ['metadata', 'risk', 'fidelity', 'confidentiality', 'headers', 'ttfb_ms', 'clientSource']) {
        if (metadata[key] !== undefined && out[key] === undefined) out[key] = metadata[key];
      }
      if (!hasTurnUsage && metadata.usage !== undefined && out.usage === undefined) out.usage = metadata.usage;
      if (metadata.clientSource !== undefined && out.client_source === undefined) out.client_source = metadata.clientSource;
      messageScopedApplied = true;
    }
    return out;
  });
}

function genericChatSession(chunk) {
  const parsed = parseGenericChatContainers(chunk);
  const turns = correlateToolNames(parsed.messages.flatMap(genericChatMessageTurns));
  return {
    turns: applyGenericSessionMetadata(turns, parsed.metadata),
    ...parsed.metadata,
  };
}

function genericChatSessionFromMessages(parsed) {
  const turns = correlateToolNames(parsed.messages.flatMap(genericChatMessageTurns));
  return {
    turns: applyGenericSessionMetadata(turns, parsed.metadata),
    ...parsed.metadata,
  };
}

function genericChatSessionsFromValue(value) {
  if (Array.isArray(value) && value.every(isGenericSessionWrapper)) {
    return value
      .map((item) => genericChatSessionFromMessages(genericChatMessagesFromValue(item)))
      .filter((session) => session.turns.length > 0);
  }
  const session = genericChatSessionFromMessages(genericChatMessagesFromValue(value));
  return session.turns.length > 0 ? [session] : [];
}

function genericChatSessions(chunk) {
  const text = String(chunk || '').trim();
  if (!text) return [];
  const parsed = safeJsonParse(text, undefined);
  if (parsed !== undefined) return genericChatSessionsFromValue(parsed);
  const rows = parseJsonlLines(chunk);
  if (rows.length > 0 && rows.every(isGenericSessionWrapper)) {
    return rows
      .map((row) => genericChatSessionFromMessages(genericChatMessagesFromValue(row)))
      .filter((session) => session.turns.length > 0);
  }
  const session = genericChatSessionFromMessages(rows.reduce((acc, row) => {
    const parsedRow = genericChatMessagesFromValue(row);
    acc.messages.push(...parsedRow.messages);
    acc.metadata = mergeSessionEnvelope(acc.metadata, parsedRow.metadata);
    return acc;
  }, { messages: [], metadata: {} }));
  return session.turns.length > 0 ? [session] : [];
}

function genericChatTranscript(chunk) {
  return genericChatSessions(chunk).flatMap((session) => session.turns);
}

// --- Gemini CLI runtime adapter (FIX-3) -------------------------------------------------------------------
// Gemini CLI stores chats under ~/.gemini/tmp/<projectName>/chats/session-*.{json,jsonl}. NEVER reads logs.json.
// jsonl variant: a header line {sessionId,projectHash,startTime,...} then per-message lines, with `$set`
//   mutation lines ({"$set":{...}}) interspersed.
// json variant: a single object {sessionId,...,messages:[...]}.
// Message shape: { id, timestamp, type:'user'|'gemini'|'info', content, thoughts:[{subject,description}],
//   toolCalls:[{id,name,args,result:[{functionResponse:{response}}],status}], tokens:{input,output,...}, model }.
const GEMINI_CLI_FILE_RE = /(^|[/\\])\.gemini[/\\]tmp[/\\][^/\\]+[/\\]chats[/\\]session-[^/\\]*\.jsonl?$/i;

function geminiCliMessageRecords(chunk) {
  const text = String(chunk || '').trim();
  if (!text) return [];
  // json variant: the whole file is one (often pretty-printed) session object carrying messages[].
  const whole = safeJsonParse(text, undefined);
  if (whole !== undefined && whole && typeof whole === 'object' && !Array.isArray(whole)) {
    if (Array.isArray(whole.messages)) return whole.messages;
    if (whole.type) return [whole];
  }
  if (Array.isArray(whole)) {
    return whole.filter((record) => record && typeof record === 'object' && record.type && record.$set === undefined);
  }
  // jsonl variant: one record per line; skip the header line and `$set` mutation lines.
  const out = [];
  for (const line of text.split('\n')) {
    const s = line.trim();
    if (!s) continue;
    const obj = safeJsonParse(s, null);
    if (!obj || typeof obj !== 'object') continue;
    if (obj.$set !== undefined) continue; // mutation marker
    if (!obj.type) continue; // header / non-message line
    out.push(obj);
  }
  return out;
}

function geminiCliThoughtText(thought) {
  if (typeof thought === 'string') return thought;
  if (!thought || typeof thought !== 'object') return '';
  const subject = typeof thought.subject === 'string' ? thought.subject.trim() : '';
  const description = typeof thought.description === 'string' ? thought.description.trim() : '';
  if (subject && description) return `${subject}: ${description}`;
  return subject || description || '';
}

function geminiCliToolResultText(result) {
  // result is an array of { functionResponse: { id, name, response: {output|...} } } entries.
  if (!Array.isArray(result)) return result === undefined ? '' : stringifyResult(result);
  const parts = result.map((entry) => {
    const fr = entry && typeof entry === 'object' ? entry.functionResponse : null;
    if (fr && typeof fr === 'object') {
      const resp = fr.response;
      if (resp && typeof resp === 'object' && typeof resp.output === 'string') return resp.output;
      return resp !== undefined ? stringifyResult(resp) : '';
    }
    return stringifyResult(entry);
  }).filter(Boolean);
  return parts.join('\n');
}

function geminiCliMessageTurns(msg) {
  if (!msg || typeof msg !== 'object') return [];
  const type = String(msg.type || '');
  const timestamp = typeof msg.timestamp === 'string' ? msg.timestamp : undefined;
  const model = typeof msg.model === 'string' ? msg.model : undefined;
  const usage = msg.tokens && typeof msg.tokens === 'object'
    ? {
      ...(Number.isFinite(Number(msg.tokens.input)) ? { input_tokens: Number(msg.tokens.input) } : {}),
      ...(Number.isFinite(Number(msg.tokens.output)) ? { output_tokens: Number(msg.tokens.output) } : {}),
    }
    : undefined;
  const turns = [];
  const stamp = (turn) => ({ ...turn, ...(timestamp ? { timestamp } : {}) });

  if (type === 'user') {
    const text = genericChatText(msg.content);
    if (text) turns.push(stamp({ role: 'user', text, isMeta: isMetaText(text) }));
    return turns;
  }
  if (type === 'gemini') {
    // Reasoning (thoughts) first, then visible content, then tool calls + their results. The model tag goes on
    // every turn, but the message-level usage (tokens) must land on ONE turn only or buildTrajectory double/
    // triple-counts it — attach usage to the first emitted turn, model-only thereafter.
    const modelMeta = model ? { model } : {};
    const usageMeta = usage && Object.keys(usage).length > 0 ? { usage } : {};
    let usageAttached = false;
    const withMeta = (turn) => {
      const out = { ...turn, ...modelMeta };
      if (!usageAttached && Object.keys(usageMeta).length > 0) {
        Object.assign(out, usageMeta);
        usageAttached = true;
      }
      return out;
    };
    const thoughts = Array.isArray(msg.thoughts) ? msg.thoughts : [];
    for (const thought of thoughts) {
      const thoughtText = geminiCliThoughtText(thought);
      if (thoughtText) turns.push(stamp(withMeta({ role: 'assistant', text: thoughtText, reasoning: true, isMeta: false })));
    }
    const text = genericChatText(msg.content);
    if (text) turns.push(stamp(withMeta({ role: 'assistant', text, isMeta: false })));
    const toolCalls = Array.isArray(msg.toolCalls) ? msg.toolCalls : [];
    for (const call of toolCalls) {
      if (!call || typeof call !== 'object') continue;
      const toolUseId = call.id ? String(call.id) : '';
      turns.push(stamp(withMeta({
        role: 'assistant',
        text: '',
        toolName: String(call.name || ''),
        ...(toolUseId ? { toolUseId } : {}),
        ...(call.args !== undefined ? { toolInput: call.args } : {}),
        isMeta: false,
      })));
      const resultText = geminiCliToolResultText(call.result);
      const isError = String(call.status || '').toLowerCase() === 'error';
      if (resultText || isError) {
        turns.push(stamp({
          role: 'tool',
          text: '',
          toolResult: resultText,
          ...(toolUseId ? { toolUseId } : {}),
          toolName: String(call.name || ''),
          ...(isError ? { errorMessage: resultText } : {}),
          ...modelMeta,
          isMeta: false,
        }));
      }
    }
    return turns;
  }
  // 'info' and any other non-conversational record types are dropped (CLI update notices, cancellations).
  return turns;
}

function geminiCliSession(chunk) {
  const records = geminiCliMessageRecords(chunk);
  const turns = correlateToolNames(records.flatMap(geminiCliMessageTurns));
  let sessionModel = '';
  for (const record of records) {
    if (record && typeof record.model === 'string' && record.model) { sessionModel = record.model; break; }
  }
  return {
    turns,
    provider: 'gemini',
    clientSource: 'gemini-cli',
    ...(sessionModel ? { model: sessionModel } : {}),
  };
}

function geminiCliTranscript(chunk) {
  return geminiCliSession(chunk).turns;
}

// Walk <gemini-tmp>/<project>/chats/ for session-*.json files (the .jsonl variant is already surfaced by the
// generic transcript walker). Bounded and best-effort so a broken dir never throws during discovery.
function collectGeminiJsonSessionFiles(geminiTmpDir) {
  const out = [];
  let projects;
  try {
    projects = fs.readdirSync(geminiTmpDir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const project of projects) {
    if (!project.isDirectory()) continue;
    const chatsDir = path.join(geminiTmpDir, project.name, 'chats');
    let entries;
    try {
      entries = fs.readdirSync(chatsDir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (!entry.isFile()) continue;
      const full = path.join(chatsDir, entry.name);
      // Only the .json variant; .jsonl is handled by collectTranscriptFiles. GEMINI_CLI_FILE_RE guards
      // against logs.json etc.
      if (/\.json$/i.test(entry.name) && GEMINI_CLI_FILE_RE.test(full)) out.push(full);
    }
  }
  return out;
}

// --- Cursor adapter (FIX-4): read state.vscdb sqlite -------------------------------------------------------
// Real Cursor IDE conversations live in
//   ~/Library/Application Support/Cursor/User/globalStorage/state.vscdb   (macOS; analogous on Linux/Windows)
// in the `cursorDiskKV` table, NOT in agent-transcript .jsonl files (those don't exist in real installs).
// Coverage / known limits (Cursor's schema is undocumented and version-dependent):
//   - composerData:<composerId>  -> session envelope. Bubbles may be inlined under `conversationMap`
//     (older builds) and/or stored as separate `bubbleId:<composerId>:<bubbleId>` rows (newer builds). Both
//     are handled; conversation order follows `fullConversationHeadersOnly` when present, else map order.
//   - Bubble shape: { type: 1=user | 2=assistant, text, richText, thinking:{text}, toolFormerData:{name,
//     rawArgs|params, result} }.  We map these to generic-chat user/assistant/thinking/tool turns.
//   - Anything we don't recognize is skipped rather than dropping the whole session.
const CURSOR_VSCDB_FILE_RE = /(^|[/\\])state\.vscdb$/i;

function cursorParseJson(value) {
  if (value == null) return null;
  if (typeof value === 'object') return value;
  const text = typeof value === 'string' ? value : value.toString('utf8');
  return safeJsonParse(text, null);
}

function cursorBubbleToMessage(bubble) {
  if (!bubble || typeof bubble !== 'object') return null;
  // type: 1 = user, 2 = assistant (Cursor convention).
  const role = bubble.type === 1 ? 'user' : (bubble.type === 2 ? 'assistant' : null);
  if (!role) return null;
  const content = [];
  // Reasoning / thinking.
  const thinking = bubble.thinking && typeof bubble.thinking === 'object'
    ? (typeof bubble.thinking.text === 'string' ? bubble.thinking.text : '')
    : (typeof bubble.thinking === 'string' ? bubble.thinking : '');
  if (role === 'assistant' && thinking) content.push({ type: 'thinking', thinking });
  // Visible text.
  const text = typeof bubble.text === 'string' && bubble.text
    ? bubble.text
    : (typeof bubble.richText === 'string' ? bubble.richText : '');
  if (text) content.push({ type: 'text', text });
  // Tool call (Cursor stores one tool invocation per bubble under toolFormerData).
  const tool = bubble.toolFormerData && typeof bubble.toolFormerData === 'object' ? bubble.toolFormerData : null;
  if (tool) {
    const rawArgs = tool.rawArgs !== undefined ? tool.rawArgs : tool.params;
    const toolName = String(tool.name || tool.tool || 'unknown');
    const toolUseId = tool.toolCallId || tool.id || bubble.bubbleId || '';
    content.push({
      type: 'tool_use',
      ...(toolUseId ? { id: String(toolUseId) } : {}),
      name: toolName,
      input: cursorParseJson(rawArgs) ?? rawArgs,
    });
    if (tool.result !== undefined) {
      content.push({
        type: 'function_call_output',
        ...(toolUseId ? { tool_use_id: String(toolUseId) } : {}),
        name: toolName,
        content: cursorParseJson(tool.result) ?? tool.result,
      });
    }
  }
  if (content.length === 0) return null;
  return { role, content };
}

function cursorOrderedBubbleIds(composer) {
  const headers = Array.isArray(composer.fullConversationHeadersOnly) ? composer.fullConversationHeadersOnly : [];
  const ids = headers
    .map((h) => (h && typeof h === 'object' ? (h.bubbleId || h.id) : h))
    .filter((id) => typeof id === 'string' && id);
  return ids;
}

function cursorComposerMessages(composer, bubbleLookup) {
  const map = composer.conversationMap && typeof composer.conversationMap === 'object' ? composer.conversationMap : {};
  const ordered = cursorOrderedBubbleIds(composer);
  const bubbleIds = ordered.length > 0 ? ordered : Object.keys(map);
  const messages = [];
  for (const id of bubbleIds) {
    const bubble = map[id] || (bubbleLookup ? bubbleLookup(composer.composerId, id) : null);
    const message = cursorBubbleToMessage(bubble);
    if (message) messages.push(message);
  }
  // Fallback: if header order yielded nothing but the map has bubbles, scan the map directly.
  if (messages.length === 0) {
    for (const id of Object.keys(map)) {
      const message = cursorBubbleToMessage(map[id]);
      if (message) messages.push(message);
    }
  }
  return messages;
}

// Open state.vscdb read-only with node:sqlite (no external deps) and return one session per composer that has
// recoverable conversation content. Each session is { turns, sessionId, model, provider, clientSource }.
function cursorSessionsFromVscdb(dbPath) {
  let DatabaseSync;
  try {
    ({ DatabaseSync } = require('node:sqlite'));
  } catch {
    return [];
  }
  let db;
  try {
    db = new DatabaseSync(dbPath, { readOnly: true });
  } catch {
    return [];
  }
  const sessions = [];
  try {
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map((r) => r.name);
    if (!tables.includes('cursorDiskKV')) return [];
    // Pre-index separate bubble rows (bubbleId:<composerId>:<bubbleId>) for newer Cursor builds.
    const bubbleRows = db.prepare("SELECT key, value FROM cursorDiskKV WHERE key LIKE 'bubbleId:%'").all();
    const bubbleByComposer = new Map();
    for (const row of bubbleRows) {
      const parts = String(row.key).split(':');
      if (parts.length < 3) continue;
      const composerId = parts[1];
      const bubbleId = parts.slice(2).join(':');
      if (!bubbleByComposer.has(composerId)) bubbleByComposer.set(composerId, new Map());
      bubbleByComposer.get(composerId).set(bubbleId, cursorParseJson(row.value));
    }
    const bubbleLookup = (composerId, bubbleId) => {
      const map = bubbleByComposer.get(composerId);
      return map ? map.get(bubbleId) : null;
    };
    const composerRows = db.prepare("SELECT key, value FROM cursorDiskKV WHERE key LIKE 'composerData:%'").all();
    for (const row of composerRows) {
      const composer = cursorParseJson(row.value);
      if (!composer || typeof composer !== 'object') continue;
      const messages = cursorComposerMessages(composer, bubbleLookup);
      if (messages.length === 0) continue;
      const turns = correlateToolNames(messages.flatMap(genericChatMessageTurns));
      if (turns.length === 0) continue;
      const model = composer.modelConfig && typeof composer.modelConfig === 'object'
        ? firstString(composer.modelConfig, ['modelName', 'model', 'name'])
        : firstString(composer, ['model', 'modelName']);
      sessions.push({
        turns,
        sessionId: String(composer.composerId || row.key.replace(/^composerData:/, '')),
        provider: 'cursor',
        clientSource: 'cursor',
        ...(model ? { model } : {}),
      });
    }
  } catch {
    // Best effort: return whatever sessions we recovered before the failure.
  } finally {
    try { db.close(); } catch { /* already closed */ }
  }
  return sessions;
}

// --- Kimi CLI adapter (FIX-5): wire.jsonl --------------------------------------------------------------------
// Kimi CLI records each session under ~/.kimi/sessions/<workspaceHash>/<sessionId>/wire.jsonl.
// Line 0: { type:'metadata', protocol_version }. Then per-event lines: { timestamp, message:{ type, payload } }.
//   TurnBegin.payload.user_input:[{type:'text',text}]           -> user message
//   ContentPart.payload {type:'think', think} | {type:'text', text}  -> assistant thinking / text
//   ToolCall.payload {id, function:{name, arguments}}            -> tool call
//   ToolResult.payload {tool_call_id, return_value:{is_error, output}} -> tool result
//   ToolCallPart / StatusUpdate / StepBegin / TurnEnd / ...      -> skipped (streaming fragments / status)
const KIMI_WIRE_FILE_RE = /(^|[/\\])\.kimi[/\\]sessions[/\\][^/\\]+[/\\][^/\\]+[/\\]wire\.jsonl$/i;

function kimiWireTurns(message, timestamp) {
  if (!message || typeof message !== 'object') return [];
  const payload = message.payload && typeof message.payload === 'object' ? message.payload : {};
  const stamp = (turn) => (timestamp ? { ...turn, timestamp } : turn);
  switch (message.type) {
    case 'TurnBegin': {
      const text = genericChatText(payload.user_input);
      return text ? [stamp({ role: 'user', text, isMeta: isMetaText(text) })] : [];
    }
    case 'ContentPart': {
      if (payload.type === 'think') {
        const think = typeof payload.think === 'string' ? payload.think : '';
        return think ? [stamp({ role: 'assistant', text: think, reasoning: true, isMeta: false })] : [];
      }
      const text = typeof payload.text === 'string' ? payload.text : genericChatText(payload);
      return text ? [stamp({ role: 'assistant', text, isMeta: isMetaText(text) })] : [];
    }
    case 'ToolCall': {
      const fn = payload.function && typeof payload.function === 'object' ? payload.function : {};
      const toolUseId = payload.id ? String(payload.id) : '';
      return [stamp({
        role: 'assistant',
        text: '',
        toolName: String(fn.name || payload.name || ''),
        ...(toolUseId ? { toolUseId } : {}),
        ...(fn.arguments !== undefined ? { toolInput: fn.arguments } : {}),
        isMeta: false,
      })];
    }
    case 'ToolResult': {
      const ret = payload.return_value && typeof payload.return_value === 'object' ? payload.return_value : {};
      const output = typeof ret.output === 'string' ? ret.output : stringifyResult(ret.output ?? ret);
      const toolUseId = payload.tool_call_id ? String(payload.tool_call_id) : '';
      const isError = ret.is_error === true;
      return [stamp({
        role: 'tool',
        text: '',
        toolResult: output,
        ...(toolUseId ? { toolUseId } : {}),
        ...(isError ? { errorMessage: output } : {}),
        isMeta: false,
      })];
    }
    default:
      return [];
  }
}

function kimiWireSession(chunk) {
  const turns = [];
  for (const line of String(chunk || '').split('\n')) {
    const s = line.trim();
    if (!s) continue;
    const obj = safeJsonParse(s, null);
    if (!obj || typeof obj !== 'object') continue;
    if (obj.type === 'metadata' || !obj.message) continue; // header / non-event line
    const timestamp = typeof obj.timestamp === 'number' ? normalizeTimestamp(obj.timestamp) : undefined;
    turns.push(...kimiWireTurns(obj.message, timestamp));
  }
  return {
    turns: correlateToolNames(turns),
    provider: 'kimi',
    clientSource: 'kimi-cli',
  };
}

function kimiWireTranscript(chunk) {
  return kimiWireSession(chunk).turns;
}

const SESSION_LOG_ADAPTERS = [
  {
    agent: 'claude-code',
    detect: (file) => /\.claude[/\\]projects[/\\].*\.jsonl$/i.test(file) || /claude.*\.jsonl$/i.test(file),
    parse: anthropicStyleTranscript,
  },
  {
    agent: 'codex',
    detect: (file) => /\.codex[/\\].*\.jsonl$/i.test(file) || /(^|[/\\])rollout-.*\.jsonl$/i.test(file) || /codex.*\.jsonl$/i.test(file),
    parse: codexTranscript,
  },
  {
    agent: 'cursor',
    detect: (file) => /\.cursor[/\\].*\.jsonl$/i.test(file) || /cursor.*\.jsonl$/i.test(file),
    parse: anthropicStyleTranscript,
  },
  {
    agent: 'gemini-cli',
    // ~/.gemini/tmp/<project>/chats/session-*.{json,jsonl}. Never matches logs.json.
    detect: (file) => GEMINI_CLI_FILE_RE.test(file),
    parse: geminiCliTranscript,
    parseSession: geminiCliSession,
    // Gemini CLI chat records carry no cwd/path/workspace field (only sessionId + projectHash), so
    // transcriptBelongsToWorkspace can never match and would silently drop every session. Auto-discovery
    // therefore collects these unconditionally — the trace pipeline's goal is broad capture, and a project
    // sub-tree (`~/.gemini/tmp/<project>/chats`) is already a coarse workspace boundary. (FIX-3 discovery gap.)
    workspaceScoped: false,
  },
  {
    agent: 'cursor',
    // Cursor IDE conversations are in state.vscdb (sqlite). `binary: true` tells the reader to hand this
    // adapter the file PATH (read via node:sqlite) instead of a utf8 chunk.
    detect: (file) => CURSOR_VSCDB_FILE_RE.test(file),
    binary: true,
    parseSessionsFromFile: cursorSessionsFromVscdb,
  },
  {
    agent: 'kimi',
    // ~/.kimi/sessions/<workspaceHash>/<sessionId>/wire.jsonl
    detect: (file) => KIMI_WIRE_FILE_RE.test(file),
    parse: kimiWireTranscript,
    parseSession: kimiWireSession,
    // Kimi wire.jsonl records carry no cwd/path/workspace field (only a hashed workspace dir + sessionId),
    // so transcriptBelongsToWorkspace can never match and would silently drop every Kimi session. Treat Kimi
    // like Gemini CLI (workspaceScoped:false) so auto-discovery collects these unconditionally — the hashed
    // workspace sub-tree (`~/.kimi/sessions/<workspaceHash>`) is already a coarse workspace boundary. (FIX-5
    // discovery gap; the earlier FIX-3 residual commit only patched Gemini.)
    workspaceScoped: false,
  },
  {
    agent: 'generic-chat',
    detect: (file) => GENERIC_CHAT_FILE_RE.test(file),
    parse: genericChatTranscript,
    parseSession: genericChatSession,
    parseSessions: genericChatSessions,
  },
];

function adapterForPath(file) {
  return SESSION_LOG_ADAPTERS.find((adapter) => adapter.detect(file));
}

function isJsonCandidate(file) {
  const ext = path.extname(file).toLowerCase();
  const name = path.basename(file).toLowerCase();
  return ext === '.json' || ext === '.jsonl' || name === '.json' || name === '.jsonl';
}

function isJsonlCandidate(file) {
  const ext = path.extname(file).toLowerCase();
  return ext === '.jsonl' || path.basename(file).toLowerCase() === '.jsonl';
}

function isTraceLikeRow(row) {
  return !!row && typeof row === 'object' && (
    row.prism_compatible === true
    || row.event === 'llm_turn'
    || row.encrypted === true
    || row.event === 'llm_trace_envelope'
  );
}

function traceLikeContent(chunk) {
  return parseJsonlLines(chunk).some(isTraceLikeRow);
}

function adapterForContent(chunk) {
  const generic = SESSION_LOG_ADAPTERS.find((adapter) => adapter.agent === 'generic-chat');
  const ordered = [
    ...(generic ? [generic] : []),
    ...SESSION_LOG_ADAPTERS.filter((adapter) => adapter !== generic),
  // Binary adapters (no `parse`, e.g. Cursor's sqlite reader) are matched by path only, never by content.
  ].filter((adapter) => typeof adapter.parse === 'function');
  return ordered.find((adapter) => adapter.parse(chunk).some((turn) => turn.isMeta !== true));
}

function adapterParsesRuntimeTurns(adapter, chunk) {
  if (adapter.parseSessions) return adapter.parseSessions(chunk).some((session) => session.turns.some((turn) => turn.isMeta !== true));
  if (adapter.parseSession) return adapter.parseSession(chunk).turns.some((turn) => turn.isMeta !== true);
  return adapter.parse(chunk).some((turn) => turn.isMeta !== true);
}

function inputFileForPath(file, explicit, strictUnknownJson = false) {
  if (TRACE_FILE_RE.test(file)) return { path: file, kind: 'trace' };
  const adapter = adapterForPath(file);
  // Binary adapters (e.g. Cursor's state.vscdb) are read via their own loader, never as a utf8/jsonl chunk.
  if (adapter && adapter.binary) return { path: file, kind: 'session', adapter };
  if (adapter) {
    if (explicit && strictUnknownJson && isJsonCandidate(file)) {
      const chunk = fs.readFileSync(file, 'utf8');
      if (adapterParsesRuntimeTurns(adapter, chunk)) return { path: file, kind: 'session', adapter };
      if (traceLikeContent(chunk)) return { path: file, kind: 'trace' };
      const contentAdapter = adapterForContent(chunk);
      if (contentAdapter) return { path: file, kind: 'session', adapter: contentAdapter };
      if (isJsonlCandidate(file)) throw new Error(`trajectory input format is not recognized: ${file}`);
      return null;
    }
    return { path: file, kind: 'session', adapter };
  }
  if (!explicit || !isJsonCandidate(file)) return null;
  const chunk = fs.readFileSync(file, 'utf8');
  if (traceLikeContent(chunk)) return { path: file, kind: 'trace' };
  const contentAdapter = adapterForContent(chunk);
  if (contentAdapter) return { path: file, kind: 'session', adapter: contentAdapter };
  if (!strictUnknownJson && !isJsonlCandidate(file)) return null;
  throw new Error(`trajectory input format is not recognized: ${file}`);
}

function collectTrajectoryInputFiles(dir, explicit) {
  const out = [];
  const walk = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const fullPath = path.join(current, entry.name);
      const stat = fs.lstatSync(fullPath);
      if (stat.isSymbolicLink()) continue;
      if (stat.isDirectory()) {
        walk(fullPath);
        continue;
      }
      if (!stat.isFile()) continue;
      const file = inputFileForPath(fullPath, explicit, false);
      if (file) out.push(file);
    }
  };
  walk(dir);
  return out;
}

function resolveTrajectoryInputFiles(inputPath, explicit) {
  const stat = fs.statSync(inputPath);
  if (!stat.isDirectory()) {
    const file = inputFileForPath(inputPath, true, true);
    return file ? [file] : [];
  }
  if (!explicit) {
    return resolveTraceInputFiles(inputPath).map((file) => ({ path: file, kind: 'trace' }));
  }
  const files = collectTrajectoryInputFiles(inputPath, true);
  if (files.length === 0) throw new Error(`trajectory input format is not recognized: ${inputPath}`);
  return files;
}

function dedupeTrajectoryInputFiles(files) {
  const out = [];
  const seen = new Set();
  for (const file of files || []) {
    if (!file || !file.path || seen.has(file.path)) continue;
    seen.add(file.path);
    out.push(file);
  }
  return out;
}

// Resolve the evolver-marked-sessions registry path written by the session-start
// hook. Mirrors getMarkedSessionsPath() in evolver-session-start.js so both ends
// agree on the file. EVOLVER_MARKED_SESSIONS_FILE wins (tests / operator
// override); otherwise it sits in the proxy trace dir (EVOLVER_SETTINGS_DIR or
// the platform default), alongside proxy-traces.jsonl.
function resolveMarkedSessionsFile(opts = {}) {
  if (opts.markedSessionsFile) return String(opts.markedSessionsFile);
  if (process.env[MARKED_SESSIONS_FILE_ENV]) return process.env[MARKED_SESSIONS_FILE_ENV];
  const dir = resolveDefaultTraceDir();
  return path.join(dir, 'marked-sessions.jsonl');
}

// Build the set of plaintext session_ids evolver actively marked. Each line is a
// {session_id, cwd?, source?, marked_at} record appended by the session-start
// hook. Missing/unreadable file -> empty set (strict mode then drops everything,
// which is the intended fail-closed behavior).
function loadMarkedSessionIds(opts = {}) {
  const file = resolveMarkedSessionsFile(opts);
  const set = new Set();
  let raw;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch {
    return set;
  }
  for (const line of raw.split('\n')) {
    const s = line.trim();
    if (!s) continue;
    const row = safeJsonParse(s, null);
    if (!row || typeof row !== 'object') continue;
    const sid = String(row.session_id ?? row.sessionId ?? '').trim();
    if (sid) set.add(sid);
  }
  return set;
}

// Build the set of gateway-captured session ids, as `session_id_sha256:<hash>`
// strings (the exact form proxy-traces.jsonl stores per row). The exporter then
// hashes a transcript's plaintext session_id the same way and checks membership.
// Encrypted rows can't be read without the node secret; those simply don't
// contribute, which is safe (a session we can't prove was captured stays
// eligible). Missing/unreadable file -> empty set.
function loadGatewayCapturedSessionHashes(opts = {}) {
  const set = new Set();
  let traceFile;
  try {
    traceFile = resolveTraceFile();
  } catch {
    return set;
  }
  let raw;
  try {
    raw = fs.readFileSync(traceFile, 'utf8');
  } catch {
    return set;
  }
  for (const line of raw.split('\n')) {
    const s = line.trim();
    if (!s) continue;
    const row = safeJsonParse(s, null);
    if (!row || typeof row !== 'object') continue;
    const sid = String(row.sessionId ?? row.session_id ?? '').trim();
    // Proxy trace rows already store the hashed form; pass plaintext through the
    // hasher too (defensive) so both shapes normalize to the same key.
    if (!sid) continue;
    if (sid.startsWith(SESSION_ID_HASH_PREFIX + ':')) set.add(sid);
    else set.add(hashTraceValue(sid, SESSION_ID_HASH_PREFIX));
  }
  return set;
}

// Harvest candidate plaintext session_ids for a transcript file WITHOUT a full
// parse: the Claude Code / Gemini / Kimi filename basename IS (or contains) the
// session uuid, and Codex stores the authoritative id in the first
// session_meta record. We read a bounded head of the file and collect any
// session_id/id field plus the filename uuid, so the marking join is robust to
// which tool wrote the file. Returns an array (possibly empty).
function candidateSessionIdsForFile(file) {
  const ids = new Set();
  const base = path.basename(file).replace(/\.jsonl?$/i, '').replace(/\.json$/i, '');
  if (base) ids.add(base);
  // `rollout-2026-...-<uuid>.jsonl` (Codex) and any name embedding a uuid.
  const uuidMatch = UUID_RE.exec(path.basename(file));
  if (uuidMatch) ids.add(uuidMatch[0]);
  let head = '';
  try {
    const fd = fs.openSync(file, 'r');
    try {
      const buf = Buffer.alloc(MARK_GATE_HEAD_SCAN_BYTES);
      const bytes = fs.readSync(fd, buf, 0, buf.length, 0);
      head = buf.subarray(0, bytes).toString('utf8');
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return Array.from(ids);
  }
  // Scan complete leading lines for an id field (Codex session_meta.payload.id,
  // Claude/Gemini header sessionId, generic session_id). Tolerates the head
  // cutting a trailing partial line (we only parse lines before the last \n).
  const newlineIdx = head.lastIndexOf('\n');
  const scannable = newlineIdx >= 0 ? head.slice(0, newlineIdx) : head;
  for (const line of scannable.split('\n')) {
    const s = line.trim();
    if (!s || (s[0] !== '{' && s[0] !== '[')) continue;
    const row = safeJsonParse(s, null);
    if (!row || typeof row !== 'object') continue;
    const direct = firstString(row, ['session_id', 'sessionId', 'sessionID', 'trajectory_id', 'trajectoryId']);
    if (direct) ids.add(direct);
    const payload = row.payload && typeof row.payload === 'object' ? row.payload : null;
    if (payload) {
      const pid = firstString(payload, ['id', 'session_id', 'sessionId']);
      if (pid) ids.add(pid);
    }
  }
  return Array.from(ids);
}

function markGateEnabled(rawOpt, env) {
  // includeUnmarked / includeGatewayCaptured invert these gates. Default: gates ON.
  if (rawOpt !== undefined) return !runtimeDiscoveryEnabled(rawOpt);
  if (env !== undefined && env !== null && env !== '') return !runtimeDiscoveryEnabled(env);
  return true;
}

// The marking gate is applied per-file inside collectRuntimeSessionInputs (it
// needs to bump discovery counters), keyed on the context built below. Both
// gates are AND-ed:
//   - strict (default): keep only if some candidate id is in `marked` AND no
//     candidate id is already gateway-captured.
//   - includeUnmarked: skip the marked-membership requirement.
//   - includeGatewayCaptured: skip the gateway-exclusion.
function buildMarkGateContext(opts = {}) {
  const enforceMarked = markGateEnabled(opts.includeUnmarked, process.env[INCLUDE_UNMARKED_ENV]);
  const excludeGatewayCaptured = markGateEnabled(opts.includeGatewayCaptured, process.env[INCLUDE_GATEWAY_CAPTURED_ENV]);
  return {
    enforceMarked,
    excludeGatewayCaptured,
    marked: enforceMarked ? loadMarkedSessionIds(opts) : new Set(),
    gatewayHashes: excludeGatewayCaptured ? loadGatewayCapturedSessionHashes(opts) : new Set(),
  };
}

function collectRuntimeSessionInputs(opts = {}) {
  const hasExplicitDirs = (Array.isArray(opts.runtimeSessionDirs) && opts.runtimeSessionDirs.length > 0)
    || splitRuntimeSessionDirs(process.env[RUNTIME_SESSION_DIRS_ENV]).length > 0
    || splitRuntimeSessionDirs(process.env[RUNTIME_SESSION_DIRS_ENV_LEGACY]).length > 0
    || splitRuntimeSessionDirs(process.env.EVOLVER_CURSOR_TRANSCRIPTS_DIR).length > 0;
  const sessionSourceEnabled = ['cursor', 'merge', 'runtime', 'codex', 'claude']
    .includes(String(process.env.EVOLVER_SESSION_SOURCE || '').trim().toLowerCase());
  const enabled = hasExplicitDirs || sessionSourceEnabled || runtimeDiscoveryEnabled(
    opts.runtimeSessions !== undefined
      ? opts.runtimeSessions
      : (process.env[RUNTIME_SESSION_DISCOVERY_ENV] ?? process.env[RUNTIME_SESSION_DISCOVERY_ENV_LEGACY]),
  );
  const discovery = {
    enabled,
    dirsScanned: 0,
    filesMatched: 0,
  };
  if (!enabled) return { files: [], discovery };

  const workspaceCandidates = runtimeWorkspaceCandidates(opts);
  const runtimeDirs = runtimeSessionDirs(opts);
  discovery.dirsScanned = runtimeDirs.length;

  // Strict-by-default marking gate: only keep transcripts evolver actively
  // marked (session-start hook), minus those the gateway already captured.
  const markGate = buildMarkGateContext(opts);
  discovery.markGate = {
    enforceMarked: markGate.enforceMarked,
    excludeGatewayCaptured: markGate.excludeGatewayCaptured,
    markedSessionCount: markGate.marked.size,
    gatewayCapturedCount: markGate.gatewayHashes.size,
    excludedByMark: 0,
    excludedByGateway: 0,
  };
  // Apply the gate and bump the right counter when a file is dropped. Returns
  // true to keep. Files with no provable session id fail closed under strict
  // mode (counted as a mark exclusion) — that's the intended behavior.
  const passesMarkGate = (filePath) => {
    if (!markGate.enforceMarked && !markGate.excludeGatewayCaptured) return true;
    const ids = candidateSessionIdsForFile(filePath);
    if (markGate.enforceMarked && !ids.some((id) => markGate.marked.has(id))) {
      discovery.markGate.excludedByMark += 1;
      return false;
    }
    if (markGate.excludeGatewayCaptured
      && ids.some((id) => markGate.gatewayHashes.has(hashTraceValue(id, SESSION_ID_HASH_PREFIX)))) {
      discovery.markGate.excludedByGateway += 1;
      return false;
    }
    return true;
  };

  const files = [];
  const seen = new Set();
  for (const dir of runtimeDirs) {
    assertRuntimeSessionDirBoundary(dir.path, opts);
    let stat;
    try {
      stat = fs.lstatSync(dir.path);
    } catch (err) {
      if (dir.required) {
        const wrapped = new Error(`runtime session directory is not readable: ${dir.path}`);
        wrapped.cause = err;
        throw wrapped;
      }
      continue;
    }
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      if (dir.required) throw new Error(`runtime session directory is not readable: ${dir.path}`);
      continue;
    }
    for (const candidate of collectTranscriptFiles(dir.path, RUNTIME_SESSION_DISCOVERY_DEPTH)) {
      if (!candidate || !candidate.path || seen.has(candidate.path)) continue;
      seen.add(candidate.path);
      const candidateAdapter = adapterForPath(candidate.path);
      // .jsonl is the common runtime transcript form; allow an adapter to opt into .json too (Gemini CLI's
      // older sessions are .json). Other non-jsonl candidates are skipped as before.
      if (!isJsonlCandidate(candidate.path)
        && !(candidateAdapter && isJsonCandidate(candidate.path))) continue;
      // Skip the workspace gate for adapters that carry no cwd (Gemini CLI); see workspaceScoped note above.
      // Such sessions would otherwise be silently dropped because cwd extraction always fails for them.
      if (!(candidateAdapter && candidateAdapter.workspaceScoped === false)
        && !transcriptBelongsToWorkspace(candidate.path, workspaceCandidates)) continue;
      if (!passesMarkGate(candidate.path)) continue;
      const file = inputFileForPath(candidate.path, false, false);
      if (file && file.kind === 'session') files.push(file);
    }
  }
  // Gemini CLI's older sessions are written as `.json` (not `.jsonl`); collectTranscriptFiles only walks
  // .jsonl/.txt, so those files never reach the loop above. Probe the Gemini chats sub-trees directly so
  // auto-discovery surfaces them too (FIX-3 discovery gap).
  for (const dir of runtimeDirs) {
    if (!/(^|[/\\])\.gemini[/\\]tmp$/i.test(dir.path)) continue;
    for (const jsonFile of collectGeminiJsonSessionFiles(dir.path)) {
      if (seen.has(jsonFile)) continue;
      seen.add(jsonFile);
      if (!passesMarkGate(jsonFile)) continue;
      const file = inputFileForPath(jsonFile, false, false);
      if (file && file.kind === 'session') files.push(file);
    }
  }
  // Cursor state.vscdb is a binary db the .jsonl transcript walker can't surface; probe known locations
  // directly so auto-discovery still picks up Cursor conversations (FIX-4).
  for (const vscdb of defaultCursorVscdbFiles(opts)) {
    if (seen.has(vscdb)) continue;
    seen.add(vscdb);
    // Cursor's state.vscdb is a binary sqlite db whose filename carries no
    // session id, so the per-file gate cannot prove it was evolver-marked; under
    // strict mode it is excluded (consistent fail-closed behavior). Operators who
    // want Cursor's vscdb sessions can pass --include-unmarked.
    if (!passesMarkGate(vscdb)) continue;
    const file = inputFileForPath(vscdb, false, false);
    if (file && file.kind === 'session') {
      discovery.dirsScanned += 1;
      files.push(file);
    }
  }
  files.sort((a, b) => a.path.localeCompare(b.path));
  discovery.filesMatched = files.length;
  return { files, discovery };
}

// Pull a session-level system prompt out of raw runtime records (FIX-8). Codex stores it in session_meta
// (instructions / base_instructions, when a string) and/or threads it as a <user_instructions> tagged user/
// developer message; Claude Code may carry a system-role message with string content.
function codexSystemPromptFromRecords(rows) {
  const meta = rows.find((row) => row.type === 'session_meta' && row.payload && typeof row.payload === 'object');
  if (meta && meta.payload) {
    const direct = firstString(meta.payload, ['instructions', 'base_instructions', 'system_prompt']);
    if (direct) return direct;
  }
  for (const row of rows) {
    const payload = row && row.type === 'response_item' && row.payload && typeof row.payload === 'object' ? row.payload : null;
    if (!payload || payload.type !== 'message') continue;
    if (!['developer', 'system', 'user'].includes(String(payload.role || ''))) continue;
    const text = codexMessageText(payload.content);
    if (text && CODEX_META_TAGS.some((tag) => text.includes(tag))) return text;
  }
  return '';
}

function claudeSystemPromptFromRecords(rows) {
  for (const row of rows) {
    if (!row || typeof row !== 'object') continue;
    const msg = row.message && typeof row.message === 'object' ? row.message : row;
    if (String(msg.role || row.type || '') !== 'system') continue;
    if (typeof msg.content === 'string' && msg.content.trim()) return msg.content;
    const text = textFromContent(msg.content);
    if (text) return text;
  }
  return '';
}

function sessionMetadata(file, rows, sourceAgent) {
  const started = rows.find((row) => typeof row.timestamp === 'string')?.timestamp;
  if (sourceAgent === 'codex') {
    const meta = rows.find((row) => row.type === 'session_meta' && row.payload && typeof row.payload === 'object');
    const id = meta && meta.payload && typeof meta.payload.id === 'string' ? meta.payload.id : undefined;
    const systemPrompt = codexSystemPromptFromRecords(rows);
    return {
      ...(id ? { sessionId: id } : {}),
      ...(typeof started === 'string' ? { startedAt: started } : {}),
      ...(systemPrompt ? { system_prompt: systemPrompt } : {}),
    };
  }
  const fallback = path.basename(file).replace(/\.jsonl?$/i, '');
  const systemPrompt = sourceAgent === 'claude-code' ? claudeSystemPromptFromRecords(rows) : '';
  return {
    ...(fallback ? { sessionId: fallback } : {}),
    ...(typeof started === 'string' ? { startedAt: started } : {}),
    ...(systemPrompt ? { system_prompt: systemPrompt } : {}),
  };
}

function readTrajectoryInputsDetailed(filePath, opts = {}) {
  const hasExplicitInput = filePath !== undefined && filePath !== null;
  const input = hasExplicitInput ? String(filePath) : resolveTraceFile();
  const readOpts = normalizeTraceReadOptions(opts);
  let files;
  let runtimeSessionDiscovery = {
    enabled: runtimeDiscoveryEnabled(
      opts.runtimeSessions !== undefined ? opts.runtimeSessions : process.env[RUNTIME_SESSION_DISCOVERY_ENV],
    ),
    dirsScanned: 0,
    filesMatched: 0,
  };
  if (hasExplicitInput) {
    try {
      files = resolveTrajectoryInputFiles(input, true);
    } catch (err) {
      if (err && /trajectory input format is not recognized/.test(String(err.message || err))) throw err;
      const wrapped = new Error(`trace input is not readable: ${input}`);
      wrapped.cause = err;
      throw wrapped;
    }
  } else {
    try {
      files = resolveTrajectoryInputFiles(input, false);
    } catch {
      files = [];
    }
    const runtimeInputs = collectRuntimeSessionInputs(opts);
    runtimeSessionDiscovery = runtimeInputs.discovery;
    files = dedupeTrajectoryInputFiles(files.concat(runtimeInputs.files));
    if (files.length === 0) {
      return { rows: [], sessionTrajectories: [], stats: newReadStats(), files: [], runtimeSessionDiscovery };
    }
  }

  const rows = [];
  const sessionTrajectories = [];
  const stats = newReadStats();
  for (const file of files) {
    if (file.kind === 'trace') {
      try {
        const result = readTraceFileRowsDetailed(file.path, readOpts);
        rows.push(...result.rows);
        mergeReadStats(stats, result.stats);
      } catch (err) {
        throw err;
      }
      continue;
    }
    const adapter = file.adapter || adapterForPath(file.path);
    if (!adapter) continue;
    // Binary adapters (Cursor state.vscdb) load directly from the file path via their own reader.
    if (adapter.binary && typeof adapter.parseSessionsFromFile === 'function') {
      stats.filesScanned += 1;
      stats.sessionFilesScanned += 1;
      let binarySessions = [];
      try {
        binarySessions = adapter.parseSessionsFromFile(file.path) || [];
      } catch (err) {
        if (hasExplicitInput) {
          const wrapped = new Error(`trace input is not readable: ${file.path}`);
          wrapped.cause = err;
          throw wrapped;
        }
        binarySessions = [];
      }
      for (const runtimeSession of binarySessions) {
        const { turns, ...adapterMetadata } = runtimeSession;
        stats.sessionTurnsRead += turns.length;
        const trajectory = buildTrajectoryFromSessionLog({
          sourceAgent: adapter.agent,
          sourcePath: file.path,
          turns,
          ...adapterMetadata,
        });
        if (trajectory) sessionTrajectories.push(trajectory);
      }
      continue;
    }
    let chunk = '';
    try {
      chunk = fs.readFileSync(file.path, 'utf8');
    } catch (err) {
      if (!hasExplicitInput) continue;
      const wrapped = new Error(`trace input is not readable: ${file.path}`);
      wrapped.cause = err;
      throw wrapped;
    }
    stats.filesScanned += 1;
    stats.sessionFilesScanned += 1;
    const parsedSession = parseJsonlLinesDetailed(chunk);
    stats.rowsScanned += parsedSession.stats.rowsScanned;
    stats.invalidJson += parsedSession.stats.invalidJson;
    stats.sessionInvalidJson += parsedSession.stats.invalidJson;
    const runtimeSessions = adapter.parseSessions
      ? adapter.parseSessions(chunk)
      : [adapter.parseSession ? adapter.parseSession(chunk) : { turns: adapter.parse(chunk) }];
    for (const runtimeSession of runtimeSessions) {
      const { turns, ...adapterMetadata } = runtimeSession;
      stats.sessionTurnsRead += turns.length;
      const trajectory = buildTrajectoryFromSessionLog({
        sourceAgent: adapter.agent,
        sourcePath: file.path,
        turns,
        ...(parsedSession.stats.invalidJson > 0 ? { incompleteReasons: ['runtime_session_invalid_json'] } : {}),
        ...sessionMetadata(file.path, parsedSession.rows, adapter.agent),
        ...adapterMetadata,
      });
      if (trajectory) sessionTrajectories.push(trajectory);
    }
  }
  return { rows, sessionTrajectories, stats, files, runtimeSessionDiscovery };
}

function normalizeBody(raw) {
  if (!raw) return null;
  if (typeof raw === 'object') return raw;
  return safeJsonParse(String(raw), null);
}

function rawBodyIsInvalidJson(raw) {
  if (typeof raw !== 'string') return false;
  const text = raw.trim();
  if (!text) return false;
  try {
    JSON.parse(text);
    return false;
  } catch {
    return true;
  }
}

function bodyIsEmpty(value) {
  if (value === undefined || value === null) return true;
  if (typeof value === 'string') return value.trim().length === 0;
  if (Array.isArray(value)) return value.length === 0;
  if (typeof value === 'object') return Object.keys(value).length === 0;
  return false;
}

function inferProvider(row) {
  const upstream = String(row.upstream || '').toLowerCase();
  if (upstream === 'openai') return 'openai';
  if (
    upstream === 'bedrock'
    || upstream === 'aws-bedrock'
    || upstream === 'aws-bedrock-anthropic'
    || upstream === 'bedrock-anthropic'
  ) return 'aws-bedrock-anthropic';
  if (upstream === 'gemini') return 'gemini';
  if (upstream === 'ollama') return 'ollama';
  if (upstream === 'vertex') return 'vertex-gemini';
  return 'anthropic';
}

function textFromContent(content) {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return '';
  return content
    .map((part) => {
      if (!part || typeof part !== 'object') return '';
      if (typeof part.text === 'string') return part.text;
      if (typeof part.content === 'string') return part.content;
      return '';
    })
    .filter(Boolean)
    .join('\n');
}

function extractTask(body) {
  if (!body || typeof body !== 'object') return '';
  if (typeof body.instructions === 'string') return body.instructions.slice(0, 1000);
  if (typeof body.input === 'string') return body.input.slice(0, 1000);
  if (Array.isArray(body.input)) {
    return body.input
      .map((item) => item && typeof item === 'object' ? textFromContent(item.content) : '')
      .filter(Boolean)
      .join('\n')
      .slice(0, 1000);
  }
  const messages = Array.isArray(body.messages) ? body.messages : [];
  const firstUser = messages.find((m) => m && m.role === 'user');
  if (!firstUser) return '';
  return textFromContent(firstUser.content).slice(0, 1000);
}

function collectToolCalls(body) {
  const calls = [];
  const addCall = (call, opts = {}) => {
    if (!call || typeof call !== 'object') return;
    const normalized = {
      id: call.id || call.tool_use_id || call.call_id || call.tool_call_id || '',
      name: call.name || call.function?.name || call.type || 'unknown',
      input: call.input,
      arguments: call.arguments,
      function: call.function,
      bytes: Number.isFinite(Number(opts.bytes))
        ? Number(opts.bytes)
        : Buffer.byteLength(JSON.stringify(call), 'utf8'),
      declared: opts.declared === true || call.declared === true,
    };
    const existing = normalized.id && !normalized.declared
      ? calls.find((candidate) => candidate.id === normalized.id && !candidate.declared)
      : null;
    if (existing) {
      if ((!existing.name || existing.name === 'unknown') && normalized.name) existing.name = normalized.name;
      if (existing.input === undefined && normalized.input !== undefined) {
        existing.input = normalized.input;
      } else if (
        existing.input && typeof existing.input === 'object' && !Array.isArray(existing.input)
        && normalized.input && typeof normalized.input === 'object' && !Array.isArray(normalized.input)
      ) {
        existing.input = { ...existing.input, ...normalized.input };
      }
      if (
        (existing.arguments === undefined || existing.arguments === '')
        && normalized.arguments !== undefined
      ) {
        existing.arguments = normalized.arguments;
      }
      if (existing.function === undefined && normalized.function !== undefined) existing.function = normalized.function;
      existing.bytes = Math.max(Number(existing.bytes) || 0, Number(normalized.bytes) || 0);
      return;
    }
    calls.push(normalized);
  };
  const addToolResult = (call) => {
    if (!call || typeof call !== 'object') return;
    const normalized = {
      id: call.tool_use_id || call.call_id || call.tool_call_id || call.id || '',
      name: 'tool_result',
      bytes: Buffer.byteLength(JSON.stringify(call), 'utf8'),
    };
    if (call.content !== undefined) normalized.input = call.content;
    if (call.output !== undefined) normalized.arguments = call.output;
    calls.push(normalized);
  };
  // Gemini / Vertex parts carry a camelCase `functionCall {name,args}` or `functionResponse {name,response}`
  // with NO `type` discriminator, so the type-based branches below never see them. Recognize them explicitly.
  const addGeminiPart = (part) => {
    if (!part || typeof part !== 'object') return false;
    const fc = part.functionCall;
    if (fc && typeof fc === 'object') {
      addCall({
        id: fc.id || part.id || '',
        name: fc.name,
        // addCall() normalizes to {input, arguments, function}; map Gemini's `args` onto `input` (the canonical
        // arguments slot getToolArguments() reads first) so the call's arguments survive normalization.
        input: fc.args,
      });
      return true;
    }
    const fr = part.functionResponse;
    if (fr && typeof fr === 'object') {
      addToolResult({
        id: fr.id || part.id || '',
        name: fr.name,
        content: fr.response !== undefined ? fr.response : fr,
      });
      return true;
    }
    return false;
  };
  const scanContent = (content) => {
    const parts = Array.isArray(content) ? content : [];
    for (const part of parts) {
      if (!part || typeof part !== 'object') continue;
      if (addGeminiPart(part)) continue;
      if (part.type === 'tool_use' || part.type === 'function_call') addCall(part);
      if (part.type === 'tool_result' || part.type === 'function_call_output') addToolResult(part);
    }
  };
  // Gemini request bodies thread tool calls/results through contents[].parts; response bodies through
  // candidates[].content.parts. Iterate both so non-streaming Gemini turns surface their tool calls.
  const scanGeminiContainers = (value) => {
    if (!value || typeof value !== 'object') return;
    const contents = Array.isArray(value.contents) ? value.contents : [];
    for (const entry of contents) {
      if (entry && typeof entry === 'object') scanContent(entry.parts);
    }
    const candidates = Array.isArray(value.candidates) ? value.candidates : [];
    for (const candidate of candidates) {
      if (candidate && typeof candidate === 'object' && candidate.content && typeof candidate.content === 'object') {
        scanContent(candidate.content.parts);
      }
    }
  };
  const scanMessage = (msg) => {
    if (!msg || typeof msg !== 'object') return;
    scanContent(msg.content);
    if (Array.isArray(msg.tool_calls)) {
      for (const call of msg.tool_calls) addCall(call);
    }
    if (msg.function_call && typeof msg.function_call === 'object') addCall(msg.function_call);
    if (msg.role === 'tool' || msg.tool_call_id) addToolResult(msg);
  };
  const streamToolBlockKey = (evt) => {
    if (!evt || typeof evt !== 'object') return '';
    if (evt.index !== undefined) return `index:${evt.index}`;
    const block = evt.content_block;
    if (block && typeof block === 'object' && block.id) return `id:${block.id}`;
    return '';
  };
  const mergeStreamInputDeltas = (streamEvents) => {
    const blocks = new Map();
    for (const evt of streamEvents || []) {
      if (!evt || typeof evt !== 'object') continue;
      const key = streamToolBlockKey(evt);
      if (!key) continue;
      if (evt.type === 'content_block_start' && evt.content_block && typeof evt.content_block === 'object') {
        const block = evt.content_block;
        if (block.type === 'tool_use' || block.type === 'function_call') {
          blocks.set(key, { call: { ...block }, partialJson: '' });
        }
      }
      if (evt.type === 'content_block_delta' && evt.delta && typeof evt.delta === 'object') {
        const delta = evt.delta;
        if (delta.type === 'input_json_delta' && typeof delta.partial_json === 'string') {
          const current = blocks.get(key) || { call: { id: '', name: 'unknown' }, partialJson: '' };
          current.partialJson += delta.partial_json;
          blocks.set(key, current);
        }
      }
    }
    for (const { call, partialJson } of blocks.values()) {
      if (!partialJson) continue;
      const trimmed = partialJson.trim();
      const parsed = safeJsonParse(trimmed, null)
        || (!trimmed.startsWith('{') ? safeJsonParse(`{${trimmed}}`, null) : null);
      const rebuilt = { ...call };
      if (parsed && typeof parsed === 'object') {
        rebuilt.input = {
          ...((rebuilt.input && typeof rebuilt.input === 'object') ? rebuilt.input : {}),
          ...parsed,
        };
      } else if (rebuilt.arguments === undefined) {
        rebuilt.arguments = partialJson;
      }
      addCall(rebuilt, { bytes: Buffer.byteLength(JSON.stringify(rebuilt), 'utf8') + Buffer.byteLength(partialJson, 'utf8') });
    }
  };
  const openAIStreamToolCalls = new Map();
  const mergeOpenAIChatArguments = (currentArguments, incomingArguments) => {
    if (typeof incomingArguments !== 'string') return currentArguments || '';
    const currentText = currentArguments || '';
    if (!currentText) return incomingArguments;
    if (incomingArguments === currentText || incomingArguments.startsWith(currentText)) {
      return incomingArguments;
    }
    if (currentText.includes(incomingArguments)) return currentText;
    return `${currentText}${incomingArguments}`;
  };
  const mergeOpenAIStreamToolDeltas = (evt) => {
    if (!evt || typeof evt !== 'object' || !Array.isArray(evt.choices)) return;
    for (const choice of evt.choices) {
      if (!choice || typeof choice !== 'object' || !choice.delta || typeof choice.delta !== 'object') continue;
      const choiceIndex = choice.index ?? 0;
      const toolCalls = Array.isArray(choice.delta.tool_calls) ? choice.delta.tool_calls : [];
      for (const toolCall of toolCalls) {
        if (!toolCall || typeof toolCall !== 'object') continue;
        const key = `${choiceIndex}:${toolCall.index ?? 0}`;
        const current = openAIStreamToolCalls.get(key) || {
          id: '',
          type: 'function',
          function: { name: '', arguments: '' },
        };
        if (toolCall.id) current.id = toolCall.id;
        if (toolCall.type) current.type = toolCall.type;
        if (toolCall.function && typeof toolCall.function === 'object') {
          current.function = current.function && typeof current.function === 'object' ? current.function : {};
          if (toolCall.function.name) current.function.name = toolCall.function.name;
          if (typeof toolCall.function.arguments === 'string') {
            current.function.arguments = mergeOpenAIChatArguments(
              current.function.arguments,
              toolCall.function.arguments,
            );
          }
        }
        openAIStreamToolCalls.set(key, current);
      }
    }
  };
  const openAIResponsesStreamToolCalls = new Map();
  const openAIResponsesStreamAliases = new Map();
  const responseStreamCandidateKeys = (evt, item) => {
    const keys = [];
    const addKey = (prefix, value) => {
      if (value !== undefined && value !== null && value !== '') keys.push(`${prefix}:${value}`);
    };
    addKey('item', evt.item_id ?? item?.item_id);
    addKey('output', evt.output_index ?? item?.output_index);
    addKey('call', evt.call_id ?? item?.call_id ?? item?.id);
    return keys;
  };
  const responseStreamKey = (evt, item) => {
    const candidates = responseStreamCandidateKeys(evt, item);
    if (candidates.length === 0) return '';
    const existing = candidates.map((key) => openAIResponsesStreamAliases.get(key)).find(Boolean);
    const primary = existing || candidates[0];
    for (const candidate of candidates) openAIResponsesStreamAliases.set(candidate, primary);
    return primary;
  };
  const ensureOpenAIResponsesStreamCall = (evt, item) => {
    const key = responseStreamKey(evt, item);
    if (!key) return null;
    const current = openAIResponsesStreamToolCalls.get(key) || {
      call: { id: '', type: 'function_call', name: 'unknown', arguments: '' },
      argumentDeltas: '',
      finalArguments: undefined,
      bytes: 0,
    };
    openAIResponsesStreamToolCalls.set(key, current);
    return current;
  };
  const mergeOpenAIResponsesStreamEvent = (evt) => {
    if (!evt || typeof evt !== 'object') return false;
    const item = evt.item && typeof evt.item === 'object' ? evt.item : null;
    const isOutputItemEvent = evt.type === 'response.output_item.added' || evt.type === 'response.output_item.done';
    const isFunctionCallItem = item && (item.type === 'function_call' || item.type === 'tool_use');
    if (isOutputItemEvent && isFunctionCallItem) {
      const current = ensureOpenAIResponsesStreamCall(evt, item);
      if (!current) return false;
      current.call = {
        ...current.call,
        ...item,
        id: item.call_id || item.id || current.call.id || '',
        call_id: item.call_id || current.call.call_id,
        type: item.type || current.call.type,
        name: item.name || current.call.name,
      };
      if (typeof item.arguments === 'string' && item.arguments) current.finalArguments = item.arguments;
      current.bytes += Buffer.byteLength(JSON.stringify(evt), 'utf8');
      return true;
    }
    if (evt.type === 'response.function_call_arguments.delta') {
      const current = ensureOpenAIResponsesStreamCall(evt, item);
      if (!current) return false;
      if (typeof evt.delta === 'string') current.argumentDeltas += evt.delta;
      current.bytes += Buffer.byteLength(JSON.stringify(evt), 'utf8');
      return true;
    }
    if (evt.type === 'response.function_call_arguments.done') {
      const current = ensureOpenAIResponsesStreamCall(evt, item);
      if (!current) return false;
      if (typeof evt.arguments === 'string') current.finalArguments = evt.arguments;
      current.bytes += Buffer.byteLength(JSON.stringify(evt), 'utf8');
      return true;
    }
    return false;
  };

  const messages = Array.isArray(body && body.messages) ? body.messages : [];
  for (const msg of messages) scanMessage(msg);

  scanContent(body && body.content);
  scanGeminiContainers(body);

  const responseOutput = Array.isArray(body && body.output) ? body.output : [];
  for (const item of responseOutput) {
    if (!item || typeof item !== 'object') continue;
    if (item.type === 'function_call' || item.type === 'tool_use') addCall(item);
    if (item.type === 'function_call_output' || item.type === 'tool_result') addToolResult(item);
    scanContent(item.content);
    scanMessage(item);
  }

  const choices = Array.isArray(body && body.choices) ? body.choices : [];
  for (const choice of choices) {
    if (!choice || typeof choice !== 'object') continue;
    scanMessage(choice.message);
    scanMessage(choice.delta);
  }
  const scanStreamEvent = (evt) => {
    if (!evt || typeof evt !== 'object') return;
    mergeOpenAIStreamToolDeltas(evt);
    const responseStreamItemHandled = mergeOpenAIResponsesStreamEvent(evt);
    if (evt.type === 'function_call' || evt.type === 'tool_use') addCall(evt);
    if (evt.type === 'function_call_output' || evt.type === 'tool_result') addToolResult(evt);
    scanMessage(evt);
    scanMessage(evt.message);
    scanMessage(evt.delta);
    scanMessage(evt.item);
    scanContent(evt.content);
    scanContent(evt.delta?.content);
    if (evt.content_block && typeof evt.content_block === 'object') {
      if (evt.content_block.type === 'tool_use' || evt.content_block.type === 'function_call') addCall(evt.content_block);
      scanContent(evt.content_block.content);
    }
    if (evt.item && typeof evt.item === 'object') {
      if (!responseStreamItemHandled && (evt.item.type === 'function_call' || evt.item.type === 'tool_use')) addCall(evt.item);
      if (evt.item.type === 'function_call_output' || evt.item.type === 'tool_result') addToolResult(evt.item);
      scanContent(evt.item.content);
    }
    if (evt.response && typeof evt.response === 'object') {
      for (const call of collectToolCalls(evt.response)) calls.push(call);
    }
    // Gemini streaming chunk: each event is itself a {candidates:[{content:{parts:[...]}}]} object.
    scanGeminiContainers(evt);
  };

  const responseInput = Array.isArray(body && body.input) ? body.input : [];
  for (const item of responseInput) scanStreamEvent(item);
  mergeStreamInputDeltas(responseInput);
  const events = Array.isArray(body && body.events) ? body.events : [];
  for (const evt of events) scanStreamEvent(evt);
  mergeStreamInputDeltas(events);
  const semanticTailEvents = Array.isArray(body && body.semantic_tail_events) ? body.semantic_tail_events : [];
  for (const evt of semanticTailEvents) scanStreamEvent(evt);
  mergeStreamInputDeltas(semanticTailEvents);
  const chunks = Array.isArray(body && body.chunks) ? body.chunks : [];
  for (const evt of chunks) scanStreamEvent(evt);
  mergeStreamInputDeltas(chunks);
  for (const call of openAIStreamToolCalls.values()) addCall(call);
  for (const current of openAIResponsesStreamToolCalls.values()) {
    const call = { ...current.call };
    const finalArguments = current.finalArguments !== undefined ? current.finalArguments : current.argumentDeltas;
    if (finalArguments !== undefined && finalArguments !== '') call.arguments = finalArguments;
    addCall(call, { bytes: current.bytes || Buffer.byteLength(JSON.stringify(call), 'utf8') });
  }

  if (Array.isArray(body && body.tools)) {
    for (const tool of body.tools) addCall(tool, { declared: true });
  }
  return calls;
}

function collectRowLevelToolCalls(row) {
  const raw = row && Array.isArray(row.tool_calls) ? row.tool_calls : [];
  const calls = [];
  for (const call of raw) {
    if (!call || typeof call !== 'object') continue;
    const normalized = {
      id: call.id || call.tool_use_id || call.call_id || call.tool_call_id || '',
      name: call.name || call.function?.name || call.type || 'unknown',
      bytes: Number.isFinite(Number(call.bytes))
        ? Number(call.bytes)
        : Buffer.byteLength(JSON.stringify(call), 'utf8'),
      declared: call.declared === true,
    };
    if (call.input !== undefined) normalized.input = call.input;
    if (call.arguments !== undefined) normalized.arguments = call.arguments;
    if (call.function !== undefined) normalized.function = call.function;
    calls.push(normalized);
  }
  return calls;
}

function getToolArguments(call) {
  if (!call || typeof call !== 'object') return null;
  if (call.input !== undefined) return call.input;
  if (call.arguments !== undefined) return call.arguments;
  if (call.args !== undefined) return call.args;
  if (call.function && typeof call.function === 'object') {
    return call.function.arguments;
  }
  return null;
}

function extractCommandText(call) {
  const args = getToolArguments(call);
  if (typeof args === 'string') {
    const parsed = safeJsonParse(args, null);
    if (parsed && typeof parsed === 'object') return extractCommandText({ input: parsed });
    return args;
  }
  if (!args || typeof args !== 'object') return '';
  for (const key of ['cmd', 'command', 'script', 'input']) {
    if (typeof args[key] === 'string') return args[key];
  }
  return '';
}

function isEditToolName(name) {
  const normalized = String(name || '').toLowerCase();
  if (!normalized) return false;
  if (/(^|[^a-z0-9])apply[_-]?patch([^a-z0-9]|$)/.test(normalized)) return true;
  if (/(^|[^a-z0-9])multi[_-]?edit([^a-z0-9]|$)/.test(normalized)) return true;
  if (/(^|[^a-z0-9])notebook[_-]?edit([^a-z0-9]|$)/.test(normalized)) return true;
  if (/(^|[^a-z0-9])(edit|write|replace|patch)([^a-z0-9]|$)/.test(normalized)) return true;
  return false;
}

function commandLooksLikeCodeEdit(command) {
  const cmd = String(command || '').toLowerCase();
  if (!cmd.trim()) return false;
  if (/\bapply_patch\b/.test(cmd) || /\bgit\s+apply\b/.test(cmd)) return true;
  if (/\bsed\b[^;\n]*\s-i(?:\b|['"])/.test(cmd)) return true;
  if (/\bperl\b[^;\n]*(?:\s-pi\b|\s-i(?:\b|['"]))/.test(cmd)) return true;
  if (/\b(?:python|python3|node)\b[^;\n]*(?:writefilesync|writefile|open\([^)]*,\s*['"]w|path\.write_text|pathlib|fs\.)/.test(cmd)) {
    return true;
  }
  return false;
}

function toolCallLooksLikeCodeEdit(call) {
  if (!call || typeof call !== 'object' || call.declared) return false;
  if (isEditToolName(call.name)) return true;
  return commandLooksLikeCodeEdit(extractCommandText(call));
}

function commandLooksLikeTestExecution(command) {
  const cmd = String(command || '').toLowerCase();
  if (!cmd.trim()) return false;
  const probes = [
    /\b(?:pnpm|npm|yarn)\s+(?:run\s+)?(?:test|vitest|jest)(?:\b|:)/,
    /\b(?:vitest|jest|pytest)\b/,
    /\bgo\s+test\b/,
    /\bcargo\s+test\b/,
    /\bmvn(?:w)?\s+(?:[^;\n]*\s)?test\b/,
    /\bgradle(?:w)?\s+(?:[^;\n]*\s)?test\b/,
    /\bdotnet\s+test\b/,
    /\bswift\s+test\b/,
    /\bzig\s+test\b/,
    /\bnode\s+--test\b/,
  ];
  return probes.some((probe) => probe.test(cmd));
}

function toolCallTestCommand(call) {
  if (!call || typeof call !== 'object' || call.declared) return '';
  const name = String(call.name || '').toLowerCase();
  if (!/(bash|exec_command|shell_command|run_terminal_cmd|terminal|shell|command)/.test(name)) {
    return '';
  }
  const command = extractCommandText(call).trim();
  return commandLooksLikeTestExecution(command) ? command : '';
}

const FAILURE_OUTPUT_RE = /\b(?:assertionerror|traceback|test(?:s)? failed|failed tests?|exit(?:ed)? with code [1-9]\d*|exit code [1-9]\d*|non[- ]?zero|command failed|npm (?:test|run) failed|pytest\b[\s\S]{0,200}\bfailed|error: test failed)\b/i;

function textFromValue(value, depth = 0) {
  if (value == null || depth > 10) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) return value.map((item) => textFromValue(item, depth + 1)).filter(Boolean).join('\n');
  if (typeof value !== 'object') return '';
  return Object.entries(value)
    .filter(([key]) => !/^(?:id|call_id|tool_call_id|type|name)$/i.test(key))
    .map(([, child]) => textFromValue(child, depth + 1))
    .filter(Boolean)
    .join('\n');
}

function hasToolResultFailureSignal(body) {
  if (!body || typeof body !== 'object') return false;
  for (const call of collectToolCalls(body)) {
    if (call.declared) continue;
    if (String(call.name || '').toLowerCase() !== 'tool_result') continue;
    if (FAILURE_OUTPUT_RE.test(textFromValue(call))) return true;
  }
  return false;
}

function hasToolCallFailureSignal(body) {
  return hasToolResultFailureSignal(body);
}

function hasResponseFailureSignal(body) {
  if (!body || typeof body !== 'object') return false;
  if (hasToolResultFailureSignal(body)) return true;
  if (body.error || body.last_error) return true;
  const status = String(body.status || '').toLowerCase();
  if (/^(?:failed|error|errored|incomplete)$/.test(status)) return true;
  return false;
}

function isResponseBodyTruncated(response) {
  return !!(
    response
    && typeof response === 'object'
    && (
      response.events_truncated === true
      || response.content_truncated === true
      || response.provider_stream_truncated === true
      || response.raw_stream_truncated === true
      || response.truncated === true
      || Number(response.dropped_event_count) > 0
    )
  );
}

function rowHasField(row, key) {
  return !!row && Object.prototype.hasOwnProperty.call(row, key);
}

function bodyIncompleteReasons(name, raw, body, row) {
  const reasons = [];
  const missing = raw === undefined || raw === null || (typeof raw === 'string' && raw.trim() === '');
  if (missing) {
    if (name === 'response' && row && row.isStream) reasons.push('stream_response_body_missing');
    else reasons.push(`${name}_body_missing`);
    return reasons;
  }
  if (rawBodyIsInvalidJson(raw)) {
    reasons.push(`${name}_body_invalid_json`);
    return reasons;
  }
  if (bodyIsEmpty(body)) reasons.push(`${name}_body_empty`);
  return reasons;
}

const STREAM_CANCEL_RE = /cancel|abort/i;
const STREAM_ERROR_RE = /error/i;

function streamTransportIncompleteReason(row) {
  if (!row || row.isStream !== true) return '';
  const streamCancel = String(traceRowStreamCancel(row) || '');
  const streamError = String(traceRowStreamError(row) || '');
  const errorMessage = String(traceRowError(row) || '');
  const finishReason = String(row.finishReason || '');
  const transportText = `${streamCancel}\n${streamError}\n${errorMessage}\n${finishReason}`;
  if (STREAM_CANCEL_RE.test(transportText)) return 'stream_cancelled';
  if (STREAM_ERROR_RE.test(transportText)) return 'stream_error';
  if (finishReason === 'stream_forwarded_unobserved') return 'stream_forwarded_unobserved';
  if (row.finished === false) return 'stream_unfinished';
  return '';
}

function turnIncompleteReasons(row, request, response) {
  const reasons = [
    ...bodyIncompleteReasons('request', row && row.requestBody, request, row),
    ...bodyIncompleteReasons('response', row && row.responseBody, response, row),
  ];
  if (row && row.body_truncated === true) reasons.push('body_truncated');
  if (row && row.body_stripped === true) reasons.push('body_stripped');
  if (row && row.trace_degraded === true) reasons.push('trace_degraded');
  if (isResponseBodyTruncated(response)) reasons.push('response_body_truncated');
  const streamReason = streamTransportIncompleteReason(row);
  if (streamReason) reasons.push(streamReason);
  return Array.from(new Set(reasons));
}

function traceRowPassthrough(row) {
  const out = {};
  const metadata = firstPresent(row, ['metadata']);
  const headers = firstPresent(row, ['headers', 'response_headers', 'responseHeaders']);
  const ttfbMs = firstPresent(row, ['ttfb_ms', 'ttfbMs', 'time_to_first_byte_ms', 'timeToFirstByteMs']);
  for (const key of ['usage', 'risk', 'fidelity', 'confidentiality']) {
    if (row && row[key] !== undefined) out[key] = redactRuntimeValue(row[key]);
  }
  if (metadata !== undefined) out.metadata = redactRuntimeValue(metadata);
  if (headers !== undefined) out.headers = redactRuntimeValue(headers);
  if (ttfbMs !== undefined) out.ttfb_ms = ttfbMs;
  if (row && row.trace_degraded === true) out.trace_degraded = true;
  if (row && row.trace_degraded_reason) out.trace_degraded_reason = String(row.trace_degraded_reason);
  if (row && row.body_stripped === true) out.body_stripped = true;
  if (row && row.body_stripped_reason) out.body_stripped_reason = String(row.body_stripped_reason);
  return out;
}

function createRawRecordStore() {
  const objectIndexes = new WeakMap();
  const primitiveIndexes = new Map();
  const values = [];
  return {
    add(value) {
      if (value === undefined) return undefined;
      if (value && typeof value === 'object') {
        if (objectIndexes.has(value)) return objectIndexes.get(value);
        const index = values.length;
        objectIndexes.set(value, index);
        values.push(redactRuntimeValue(value));
        return index;
      }
      const key = `${typeof value}:${String(value)}`;
      if (primitiveIndexes.has(key)) return primitiveIndexes.get(key);
      const index = values.length;
      primitiveIndexes.set(key, index);
      values.push(redactRuntimeValue(value));
      return index;
    },
    values() {
      return values;
    },
  };
}

function recordIndexField(name, index) {
  return index === undefined ? {} : { [name]: index };
}

function collectLanguagesFromText(text) {
  const languages = new Set();
  const haystack = String(text || '').toLowerCase();
  const probes = [
    ['javascript', /\b(js|javascript|node|npm|pnpm|react|vue)\b/],
    ['typescript', /\b(ts|typescript|tsx)\b/],
    ['python', /\b(python|py|pytest|django|fastapi)\b/],
    ['go', /\b(golang|go test|go\.mod|go (?:code|file|files|parser|package|module))\b/],
    ['rust', /\b(rust|cargo|crates?)\b/],
    ['java', /\b(java|maven|gradle)\b/],
  ];
  for (const [name, re] of probes) {
    if (re.test(haystack)) languages.add(name);
  }
  return Array.from(languages);
}

function toolCallStatsKey(call) {
  if (!call || typeof call !== 'object' || call.declared) return '';
  const name = call.name || 'unknown';
  if (call.id) return `${name}:${call.id}`;
  return '';
}

function dedupeToolCalls(calls) {
  const seen = new Set();
  const out = [];
  for (const call of calls) {
    const key = toolCallStatsKey(call);
    if (key) {
      if (seen.has(key)) continue;
      seen.add(key);
    }
    out.push(call);
  }
  return out;
}

function buildTrajectoryFromRows(sessionId, rows) {
  const sorted = rows.map(normalizeTraceRow).sort((a, b) => {
    const at = Date.parse(a.createdAtIso || a.timestamp || 0) || 0;
    const bt = Date.parse(b.createdAtIso || b.timestamp || 0) || 0;
    return at - bt;
  });
  const turns = [];
  const toolTypes = {};
  let inputTokens = 0;
  let outputTokens = 0;
  let hasToolCalls = false;
  let hasCodeEdit = false;
  const testCommands = new Set();
  let hasFailureCorrection = false;
  let hasTruncatedStream = false;
  let hasIncompleteTurns = false;
  const languages = new Set();
  const providers = new Set();
  const endpoints = new Set();
  const countedToolCalls = new Set();
  const sourceRecordStore = createRawRecordStore();
  const rawRowStore = createRawRecordStore();
  let task = '';

  sorted.forEach((row, idx) => {
    const request = normalizeBody(row.requestBody);
    const response = normalizeBody(row.responseBody);
    const attempts = normalizeAttempts(row.attempts);
    const incompleteReasons = turnIncompleteReasons(row, request, response);
    if (incompleteReasons.length > 0) hasIncompleteTurns = true;
    const requestToolCalls = collectToolCalls(request);
    const requestDeclaredTools = requestToolCalls.filter((call) => call.declared);
    const requestActualToolCalls = requestToolCalls.filter((call) => !call.declared);
    const rowLevelToolCalls = collectRowLevelToolCalls(row);
    const rowDeclaredTools = rowLevelToolCalls.filter((call) => call.declared);
    const rowActualToolCalls = rowLevelToolCalls.filter((call) => !call.declared);
    const responseActualToolCalls = collectToolCalls(response).filter((call) => !call.declared);
    const actualToolCalls = dedupeToolCalls(responseActualToolCalls.concat(rowActualToolCalls, requestActualToolCalls));
    const toolCalls = requestDeclaredTools.concat(rowDeclaredTools, actualToolCalls);
    for (const call of toolCalls) {
      if (call.declared) continue;
      const statsKey = toolCallStatsKey(call);
      if (statsKey) {
        if (countedToolCalls.has(statsKey)) continue;
        countedToolCalls.add(statsKey);
      }
      hasToolCalls = true;
      toolTypes[call.name] = (toolTypes[call.name] || 0) + 1;
      if (toolCallLooksLikeCodeEdit(call)) hasCodeEdit = true;
      const testCommand = toolCallTestCommand(call);
      if (testCommand) testCommands.add(testCommand);
    }
    const provider = inferProvider(row);
    providers.add(provider);
    endpoints.add(row.path || '');
    const prompt = extractTask(request);
    if (!task && prompt) task = prompt;
    for (const lang of collectLanguagesFromText(JSON.stringify(request || {}) + '\n' + JSON.stringify(response || {}))) {
      languages.add(lang);
    }
    const input = Number(row.input_tokens) || 0;
    const output = Number(row.output_tokens) || 0;
    inputTokens += input;
    outputTokens += output;
    if (
      Number(row.status) >= 400
      || traceRowError(row)
      || hasToolCallFailureSignal(request)
      || hasResponseFailureSignal(response)
    ) hasFailureCorrection = true;
    const responseEventsTruncated = isResponseBodyTruncated(response);
    const attemptsBodyTruncated = attempts.some((attempt) => (
      attempt.body_truncated === true
      || isResponseBodyTruncated(attempt.request_body)
      || isResponseBodyTruncated(attempt.response_body)
    ));
    const truncatedStream = responseEventsTruncated || row.body_truncated === true || attemptsBodyTruncated;
    if (truncatedStream) hasTruncatedStream = true;
    const error = traceRowError(row);
    const sourceRecordIndex = sourceRecordStore.add(firstPresent(row, ['source_record', 'sourceRecord', 'original_record', 'originalRecord']));
    const rawRowIndex = rawRowStore.add(firstPresent(row, ['raw_row', 'rawRow', 'raw_record', 'rawRecord']));
    turns.push({
      turn_index: idx,
      request_id: row.requestId || '',
      timestamp: row.createdAtIso || row.timestamp || '',
      provider,
      endpoint: row.path || '',
      model: row.model || '',
      ...(rowHasField(row, 'chosenModel') ? { chosen_model: row.chosenModel } : {}),
      ...(rowHasField(row, 'originalModel') ? { original_model: row.originalModel } : {}),
      status: row.status,
      duration_ms: row.durationMs,
      is_stream: !!row.isStream,
      finish_reason: row.finishReason || '',
      response_id: row.responseId || '',
      previous_response_id: row.previousResponseId || '',
      input_tokens: input,
      output_tokens: output,
      request_body: request,
      response_body: response,
      ...(attempts.length > 0 ? { attempts } : {}),
      ...(error !== undefined ? { error } : {}),
      ...(traceRowStreamError(row) !== undefined ? { stream_error: traceRowStreamError(row) } : {}),
      ...(traceRowStreamCancel(row) !== undefined ? { stream_cancelled: traceRowStreamCancel(row) } : {}),
      ...(rowHasField(row, 'reasoning') ? { reasoning: row.reasoning } : {}),
      ...(rowHasField(row, 'diff') ? { diff: row.diff } : {}),
      ...(rowHasField(row, 'validation') ? { validation: row.validation } : {}),
      tool_calls: toolCalls,
      ...traceRowPassthrough(row),
      ...recordIndexField('source_record_index', sourceRecordIndex),
      ...recordIndexField('raw_row_index', rawRowIndex),
      ...(typeof row.redaction === 'string' ? { redaction: row.redaction } : {}),
      ...(row.body_truncated === true || attemptsBodyTruncated ? { body_truncated: true } : {}),
      ...(truncatedStream ? { response_events_truncated: true } : {}),
      complete: incompleteReasons.length === 0,
      ...(incompleteReasons.length > 0 ? { incomplete_reasons: incompleteReasons } : {}),
    });
  });

  return {
    schema: SCHEMA,
    session_id: sessionId || (sorted[0] && sorted[0].sessionId) || 'unknown',
    source_kind: 'proxy_trace',
    task,
    providers: Array.from(providers).filter(Boolean),
    endpoints: Array.from(endpoints).filter(Boolean),
    languages: Array.from(languages),
    stats: {
      turns: turns.length,
      input_tokens: inputTokens,
      output_tokens: outputTokens,
      total_tokens: inputTokens + outputTokens,
      tool_call_count: Object.values(toolTypes).reduce((sum, n) => sum + n, 0),
      tool_types: toolTypes,
      has_tool_calls: hasToolCalls,
      has_code_edit: hasCodeEdit,
      has_test_execution: testCommands.size > 0,
      test_commands: Array.from(testCommands),
      has_failure_correction: hasFailureCorrection,
      has_truncated_stream: hasTruncatedStream,
      has_incomplete_turns: hasIncompleteTurns,
    },
    ...(sourceRecordStore.values().length > 0 ? { source_records: sourceRecordStore.values() } : {}),
    ...(rawRowStore.values().length > 0 ? { raw_rows: rawRowStore.values() } : {}),
    turns,
  };
}

function jsonByteLength(value) {
  try {
    return Buffer.byteLength(JSON.stringify(value), 'utf8');
  } catch {
    return Buffer.byteLength(String(value || ''), 'utf8');
  }
}

function redactRuntimeValue(value) {
  return sanitize(value, RUNTIME_REDACTION_MAX_BYTES);
}

function noteRuntimeTruncation(truncation, omittedBytes) {
  if (!truncation || !Number.isFinite(Number(omittedBytes)) || Number(omittedBytes) <= 0) return;
  truncation.truncated = true;
  truncation.omittedBytes = (Number(truncation.omittedBytes) || 0) + Number(omittedBytes);
}

function redactRuntimeString(value, truncation) {
  const redacted = String(redactRuntimeValue(String(value || '')));
  const match = redacted.match(/\.\.\.\[truncated (\d+) bytes\]$/);
  if (match) noteRuntimeTruncation(truncation, Number(match[1]));
  return redacted;
}

function runtimeBody(turn, sessionModel, sessionTools, truncation) {
  const body = {
    source: 'runtime_session',
    role: turn.role,
  };
  const model = turn.model ? String(turn.model) : sessionModel;
  if (model) body.model = model;
  if ((turn.role === 'user' || turn.role === 'system') && sessionTools !== undefined) body.tools_ref = 'session_tools';
  if (turn.text) body.text = redactRuntimeString(turn.text, truncation);
  if (turn.reasoning === true) body.reasoning = true;
  if (turn.toolName) body.tool_name = turn.toolName;
  if (turn.toolUseId) body.tool_use_id = turn.toolUseId;
  if (turn.toolInput !== undefined) body.tool_input = redactRuntimeValue(turn.toolInput);
  if (turn.toolResult !== undefined) body.tool_result = redactRuntimeString(turn.toolResult, truncation);
  if (turn.errorMessage) body.error = redactRuntimeString(turn.errorMessage, truncation);
  if (truncation && truncation.truncated) {
    body.body_truncated = true;
    body.omitted_bytes = Number(truncation.omittedBytes) || 0;
    body.incomplete_reasons = ['body_truncated'];
  }
  return body;
}

function runtimeTurnHasContent(turn) {
  return Boolean(
    turn.text
    || turn.toolName
    || turn.toolInput !== undefined
    || turn.toolResult !== undefined
    || turn.errorMessage
    || turn.reasoning === true
    || turn.reasoning_signature !== undefined
    || turn.encrypted_signature !== undefined
    || turn.encrypted_content !== undefined
    || turn.payload !== undefined,
  );
}

function runtimeToolCall(turn) {
  if (turn.role !== 'assistant' || !turn.toolName) return null;
  const input = turn.toolInput !== undefined ? redactRuntimeValue(turn.toolInput) : undefined;
  return {
    id: turn.toolUseId || '',
    name: turn.toolName,
    ...(input !== undefined ? { input } : {}),
    bytes: jsonByteLength({ name: turn.toolName, input }),
  };
}

function signalValue(value) {
  if (value === undefined || value === null) return '';
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function runtimeTextForSignals(turn) {
  return [
    turn.text,
    signalValue(turn.toolInput),
    signalValue(turn.toolResult),
    turn.errorMessage,
  ].filter(Boolean).join('\n');
}

function runtimeTokenCounts(turn) {
  const usage = turn && turn.usage && typeof turn.usage === 'object' && !Array.isArray(turn.usage)
    ? turn.usage
    : null;
  const inputRaw = firstPresent(turn, ['input_tokens', 'inputTokens', 'prompt_tokens', 'promptTokens']);
  const outputRaw = firstPresent(turn, ['output_tokens', 'outputTokens', 'completion_tokens', 'completionTokens']);
  const usageInputRaw = usage ? firstPresent(usage, ['input_tokens', 'inputTokens', 'prompt_tokens', 'promptTokens']) : undefined;
  const usageOutputRaw = usage ? firstPresent(usage, ['output_tokens', 'outputTokens', 'completion_tokens', 'completionTokens']) : undefined;
  return {
    input: normalizedTokenCount(inputRaw !== undefined ? inputRaw : usageInputRaw) || 0,
    output: normalizedTokenCount(outputRaw !== undefined ? outputRaw : usageOutputRaw) || 0,
  };
}

function runtimeOpaqueMetadata(turn, sourceRecordStore, rawRowStore) {
  const out = {};
  if (turn.reasoning_signature !== undefined) out.reasoning_signature = String(turn.reasoning_signature);
  if (turn.encrypted_signature !== undefined) out.encrypted_signature = String(turn.encrypted_signature);
  if (turn.encrypted_content !== undefined) out.encrypted_content = turn.encrypted_content;
  if (turn.metadata !== undefined) out.metadata = redactRuntimeValue(turn.metadata);
  if (turn.usage !== undefined) out.usage = redactRuntimeValue(turn.usage);
  if (turn.risk !== undefined) out.risk = redactRuntimeValue(turn.risk);
  if (turn.fidelity !== undefined) out.fidelity = redactRuntimeValue(turn.fidelity);
  if (turn.confidentiality !== undefined) out.confidentiality = redactRuntimeValue(turn.confidentiality);
  if (turn.client_source !== undefined) out.client_source = String(turn.client_source);
  if (turn.payload !== undefined) out.payload = redactRuntimeValue(turn.payload);
  Object.assign(out, recordIndexField('source_record_index', sourceRecordStore && sourceRecordStore.add(turn.source_record)));
  Object.assign(out, recordIndexField('raw_row_index', rawRowStore && rawRowStore.add(turn.raw_row)));
  if (turn.headers !== undefined) out.headers = redactRuntimeValue(turn.headers);
  if (turn.ttfb_ms !== undefined) out.ttfb_ms = turn.ttfb_ms;
  return out;
}

function runtimeSessionId(input) {
  const explicit = String(input.sessionId || '').trim();
  if (explicit) return explicit;
  const sourcePath = String(input.sourcePath || '');
  const base = sourcePath.split(/[\\/]/).filter(Boolean).pop() || '';
  return base.replace(/\.jsonl?$/i, '') || 'unknown';
}

function nativeCallHasField(call, key) {
  return !!call && Object.prototype.hasOwnProperty.call(call, key);
}

function runtimeNativeCalls(input = {}) {
  const calls = [];
  for (const call of Array.isArray(input.nativeCalls) ? input.nativeCalls : []) {
    if (!call || typeof call !== 'object' || Array.isArray(call)) continue;
    const hasRequestBody = nativeCallHasField(call, 'request_body') || nativeCallHasField(call, 'request');
    const hasResponseBody = nativeCallHasField(call, 'response_body') || nativeCallHasField(call, 'response');
    if (!hasRequestBody && !hasResponseBody) continue;
    const requestBody = nativeCallHasField(call, 'request_body') ? call.request_body : call.request;
    const responseBody = nativeCallHasField(call, 'response_body') ? call.response_body : call.response;
    calls.push({
      call_index: calls.length,
      ...(call.provider ? { provider: String(call.provider) } : {}),
      ...(call.timestamp ? { timestamp: String(call.timestamp) } : {}),
      ...(call.request_time ? { request_time: String(call.request_time) } : {}),
      ...(call.response_time ? { response_time: String(call.response_time) } : {}),
      ...(hasRequestBody ? { request_body: redactRuntimeValue(normalizeBody(requestBody)) } : {}),
      ...(hasResponseBody ? { response_body: redactRuntimeValue(normalizeBody(responseBody)) } : {}),
      redaction: RUNTIME_SESSION_REDACTION,
    });
  }
  return calls;
}

function buildTrajectoryFromSessionLog(input = {}) {
  const sourceAgent = String(input.sourceAgent || '').trim() || 'unknown-runtime';
  const provider = String(input.provider || '').trim() || sourceAgent;
  const sessionModel = String(input.model || '').trim();
  const sessionTools = input.tools;
  const sourcePath = String(input.sourcePath || '');
  const sessionId = runtimeSessionId(input);
  const sessionIncompleteReasons = Array.from(new Set((Array.isArray(input.incompleteReasons) ? input.incompleteReasons : [])
    .map((reason) => String(reason || '').trim())
    .filter(Boolean)));
  const sessionDeclaredTools = sessionTools !== undefined
    ? collectToolCalls({ tools: redactRuntimeValue(sessionTools) }).filter((call) => call.declared)
    : [];
  const turns = [];
  const toolTypes = {};
  const testCommands = new Set();
  const languages = new Set();
  let task = '';
  let hasToolCalls = false;
  let hasCodeEdit = false;
  let hasFailureCorrection = false;
  let hasIncompleteTurns = false;
  let inputTokens = 0;
  let outputTokens = 0;
  const nativeCalls = runtimeNativeCalls(input);
  const sourceRecordStore = createRawRecordStore();
  const rawRowStore = createRawRecordStore();
  sourceRecordStore.add(firstPresent(input, ['source_record', 'sourceRecord', 'original_record', 'originalRecord']));
  rawRowStore.add(firstPresent(input, ['raw_row', 'rawRow', 'raw_record', 'rawRecord']));

  (Array.isArray(input.turns) ? input.turns : [])
    .filter((turn) => turn)
    .forEach((turn, idx) => {
      const isSignalTurn = turn.isMeta !== true;
      if (isSignalTurn && !task && turn.role === 'user' && turn.text) task = redactRuntimeString(turn.text).slice(0, 1000);
      if (isSignalTurn) for (const lang of collectLanguagesFromText(runtimeTextForSignals(turn))) languages.add(lang);
      const call = runtimeToolCall(turn);
      const isAssistantSide = turn.role === 'assistant' || turn.role === 'tool';
      const toolCalls = (!isAssistantSide ? sessionDeclaredTools : []).concat(call ? [call] : []);
      if (isSignalTurn && call) {
        hasToolCalls = true;
        toolTypes[call.name] = (toolTypes[call.name] || 0) + 1;
        if (toolCallLooksLikeCodeEdit(call)) hasCodeEdit = true;
        const testCommand = toolCallTestCommand(call);
        if (testCommand) testCommands.add(testCommand);
      }
      if (isSignalTurn && (
        turn.errorMessage
        || (turn.role === 'tool' && FAILURE_OUTPUT_RE.test(signalValue(turn.toolResult)))
      )) hasFailureCorrection = true;
      const truncation = { truncated: false, omittedBytes: 0 };
      const body = runtimeBody(turn, sessionModel, sessionTools, truncation);
      const incompleteReasons = [
        ...sessionIncompleteReasons,
        ...(truncation.truncated ? ['body_truncated'] : []),
        ...(runtimeTurnHasContent(turn) ? [] : ['runtime_turn_empty']),
      ];
      const dedupedIncompleteReasons = Array.from(new Set(incompleteReasons));
      if (dedupedIncompleteReasons.length > 0) hasIncompleteTurns = true;
      const tokenCounts = runtimeTokenCounts(turn);
      inputTokens += tokenCounts.input;
      outputTokens += tokenCounts.output;
      turns.push({
        turn_index: idx,
        request_id: turn.toolUseId ? `${sessionId}:${turn.toolUseId}` : `${sessionId}:turn:${idx}`,
        timestamp: String(turn.timestamp || input.startedAt || ''),
        provider,
        endpoint: 'runtime_session',
        model: turn.model ? String(turn.model) : sessionModel,
        status: null,
        duration_ms: null,
        is_stream: false,
        finish_reason: turn.errorMessage ? 'error' : '',
        response_id: '',
        previous_response_id: '',
        input_tokens: tokenCounts.input,
        output_tokens: tokenCounts.output,
        request_body: isAssistantSide ? null : body,
        response_body: isAssistantSide ? body : null,
        ...runtimeOpaqueMetadata(turn, sourceRecordStore, rawRowStore),
        ...(turn.reasoning === true ? { reasoning: redactRuntimeString(turn.text) } : {}),
        ...(turn.thinking_empty === true ? { thinking_empty: true } : {}),
        tool_calls: toolCalls,
        redaction: RUNTIME_SESSION_REDACTION,
        ...(turn.errorMessage ? { error: redactRuntimeString(turn.errorMessage) } : {}),
        ...(truncation.truncated ? { body_truncated: true, omitted_bytes: Number(truncation.omittedBytes) || 0 } : {}),
        complete: dedupedIncompleteReasons.length === 0,
        ...(dedupedIncompleteReasons.length > 0 ? { incomplete_reasons: dedupedIncompleteReasons } : {}),
      });
    });

  if (turns.length === 0) return null;
  return {
    schema: SCHEMA,
    session_id: sessionId,
    source_kind: 'runtime_session',
    source_agent: sourceAgent,
    source_path: sourcePath,
    ...(sessionModel ? { session_model: sessionModel } : {}),
    ...(provider !== sourceAgent ? { session_provider: provider } : {}),
    ...(input.system_prompt ? { system_prompt: redactRuntimeString(String(input.system_prompt)) } : {}),
    ...(sessionTools !== undefined ? { session_tools: redactRuntimeValue(sessionTools) } : {}),
    ...(input.clientSource ? { client_source: String(input.clientSource) } : {}),
    ...(input.metadata !== undefined ? { metadata: redactRuntimeValue(input.metadata) } : {}),
    ...(input.usage !== undefined ? { usage: redactRuntimeValue(input.usage) } : {}),
    ...(input.risk !== undefined ? { risk: redactRuntimeValue(input.risk) } : {}),
    ...(input.fidelity !== undefined ? { fidelity: redactRuntimeValue(input.fidelity) } : {}),
    ...(input.confidentiality !== undefined ? { confidentiality: redactRuntimeValue(input.confidentiality) } : {}),
    ...(input.headers !== undefined ? { headers: redactRuntimeValue(input.headers) } : {}),
    ...(input.ttfb_ms !== undefined ? { ttfb_ms: input.ttfb_ms } : {}),
    ...(sourceRecordStore.values().length > 0 ? { source_records: sourceRecordStore.values() } : {}),
    ...(rawRowStore.values().length > 0 ? { raw_rows: rawRowStore.values() } : {}),
    task,
    providers: [provider],
    endpoints: ['runtime_session'],
    languages: Array.from(languages),
    stats: {
      turns: turns.length,
      input_tokens: inputTokens,
      output_tokens: outputTokens,
      total_tokens: inputTokens + outputTokens,
      tool_call_count: Object.values(toolTypes).reduce((sum, n) => sum + n, 0),
      tool_types: toolTypes,
      has_tool_calls: hasToolCalls,
      has_code_edit: hasCodeEdit,
      has_test_execution: testCommands.size > 0,
      test_commands: Array.from(testCommands),
      has_failure_correction: hasFailureCorrection,
      has_truncated_stream: false,
      has_incomplete_turns: hasIncompleteTurns,
    },
    ...(nativeCalls.length > 0 ? { native_calls: nativeCalls } : {}),
    turns,
  };
}

function buildTrajectories(rows) {
  const list = Array.isArray(rows) ? rows.map(normalizeTraceRow) : [];
  const parent = list.map((_, idx) => idx);
  const rootSession = list.map((row) => (row && row.sessionId ? String(row.sessionId) : ''));
  const find = (idx) => {
    let cur = idx;
    while (parent[cur] !== cur) {
      parent[cur] = parent[parent[cur]];
      cur = parent[cur];
    }
    return cur;
  };
  const union = (a, b) => {
    const ra = find(a);
    const rb = find(b);
    if (ra === rb) return;
    const leftSession = rootSession[ra] || '';
    const rightSession = rootSession[rb] || '';
    if (leftSession && rightSession && leftSession !== rightSession) return;
    parent[rb] = ra;
    rootSession[ra] = leftSession || rightSession;
  };
  const explicitOwner = new Map();
  const responseOwners = new Map();
  const rememberResponseOwner = (responseId, idx) => {
    const key = String(responseId || '');
    if (!key) return;
    const owners = responseOwners.get(key) || [];
    owners.push(idx);
    responseOwners.set(key, owners);
  };
  const compatibleResponseOwnerRoots = (responseId, rowIdx) => {
    const owners = responseOwners.get(String(responseId || '')) || [];
    const rowRoot = find(rowIdx);
    const rowSessionId = rootSession[rowRoot] || '';
    const roots = new Set();
    for (const ownerIdx of owners) {
      if (ownerIdx === rowIdx) continue;
      const ownerRoot = find(ownerIdx);
      const ownerSessionId = rootSession[ownerRoot] || '';
      if (ownerSessionId && rowSessionId && ownerSessionId !== rowSessionId) continue;
      roots.add(ownerRoot);
    }
    return Array.from(roots);
  };

  list.forEach((row, idx) => {
    const explicit = row.sessionId ? `session:${row.sessionId}` : '';
    if (explicit) {
      if (explicitOwner.has(explicit)) union(explicitOwner.get(explicit), idx);
      else explicitOwner.set(explicit, idx);
    }
    rememberResponseOwner(row.responseId, idx);
  });

  list.forEach((row, idx) => {
    if (!row.previousResponseId) return;
    const roots = compatibleResponseOwnerRoots(row.previousResponseId, idx);
    if (roots.length !== 1) return;
    union(roots[0], idx);
  });

  const groups = new Map();
  list.forEach((row, idx) => {
    const root = find(idx);
    const owner = list[root] || {};
    const explicitSessionId = rootSession[root] || owner.sessionId;
    const fallbackId = owner.requestId || owner.responseId || 'unknown';
    const id = String(explicitSessionId || `${fallbackId}#${root}`);
    if (!groups.has(root)) groups.set(root, { sessionId: id, rows: [] });
    groups.get(root).rows.push(row);
  });
  return Array.from(groups.values()).map(({ sessionId, rows }) => (
    buildTrajectoryFromRows(sessionId, rows)
  ));
}

function writeTrajectories({
  input,
  output,
  nodeSecret,
  nodeSecretKeyring,
  hubPrivateKey,
  allowPartial,
  runtimeSessions,
  runtimeSessionDirs,
  workspaceRoot,
  homedir,
  markedSessionsFile,
  includeUnmarked,
  includeGatewayCaptured,
} = {}) {
  const { rows, sessionTrajectories, stats, files, runtimeSessionDiscovery } = readTrajectoryInputsDetailed(input, {
    nodeSecret,
    nodeSecretKeyring,
    hubPrivateKey,
    allowPartial,
    runtimeSessions,
    runtimeSessionDirs,
    workspaceRoot,
    homedir,
    markedSessionsFile,
    includeUnmarked,
    includeGatewayCaptured,
  });
  const trajectories = sessionTrajectories.concat(buildTrajectories(rows));
  const outputPath = output || path.join(process.cwd(), 'coding-trajectories.jsonl');
  // Write to an exclusive temp file ('wx' = O_CREAT|O_EXCL, mode 0o600) then atomically rename
  // into place. This avoids leaving the output world-readable for a window when the target
  // already exists, and prevents following a pre-placed symlink at outputPath.
  const tmpPath = `${outputPath}.tmp-${process.pid}-${Date.now()}`;
  const fd = fs.openSync(tmpPath, 'wx', 0o600);
  let closed = false;
  try {
    for (const trajectory of trajectories) {
      fs.writeSync(fd, `${JSON.stringify(trajectory)}\n`);
    }
  } catch (err) {
    fs.closeSync(fd);
    closed = true;
    try { fs.unlinkSync(tmpPath); } catch { /* ignore cleanup failure */ }
    throw err;
  } finally {
    if (!closed) fs.closeSync(fd);
  }
  try {
    fs.renameSync(tmpPath, outputPath);
  } catch (err) {
    try { fs.unlinkSync(tmpPath); } catch { /* ignore cleanup failure */ }
    throw err;
  }
  return {
    outputPath,
    trajectories,
    rowsRead: rows.length,
    sessionTurnsRead: stats.sessionTurnsRead || 0,
    sessionFilesRead: stats.sessionFilesScanned || 0,
    filesRead: Array.isArray(files) ? files.length : 0,
    stats,
    runtimeSessionDiscovery,
  };
}

module.exports = {
  SCHEMA,
  readTraceRows,
  readTraceRowsDetailed,
  readTrajectoryInputsDetailed,
  collectRuntimeSessionInputs,
  resolveMarkedSessionsFile,
  loadMarkedSessionIds,
  loadGatewayCapturedSessionHashes,
  candidateSessionIdsForFile,
  buildTrajectoryFromRows,
  buildTrajectoryFromSessionLog,
  buildTrajectories,
  writeTrajectories,
};

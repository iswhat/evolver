// GEP A2A Protocol - Standard message types and pluggable transport layer.
//
// Protocol messages:
//   hello    - capability advertisement and node discovery
//   publish  - broadcast an eligible asset (Capsule/Gene)
//   fetch    - request a specific asset by id or content hash
//   report   - send a ValidationReport for a received asset
//   decision - accept/reject/quarantine decision on a received asset
//   revoke   - withdraw a previously published asset
//
// Transport interface:
//   send(message, opts)    - send a protocol message
//   receive(opts)          - receive pending messages
//   list(opts)             - list available message files/streams
//
// Default transport: FileTransport (reads/writes JSONL to a2a/ directory).

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { TextDecoder } = require('util');
const { hubFetch, sanitizeHubResponseForLog } = require('./hubFetch');

// ---------------------------------------------------------------------------
// systemd sd_notify integration (Linux only).
//
// When evolver runs as a systemd service, the service manager injects
// NOTIFY_SOCKET into the environment.  Writing to that socket lets systemd
// know the process is ready (Type=notify), still alive (watchdog), or
// reloading (RELOADING=1).  Without READY=1 systemd waits until
// TimeoutStartSec (default 90 s) before declaring the service failed.
// Without periodic WATCHDOG=1 pings, WatchdogSec kills and restarts the unit.
//
// Node's `dgram` module does not support AF_UNIX SOCK_DGRAM (only udp4/udp6),
// so we cannot write to NOTIFY_SOCKET directly without a native addon. We shell
// out to systemd-notify(1), which ships with systemd and writes via socket(2).
// systemd-notify inherits NOTIFY_SOCKET from our env. Because the child PID
// will not match the unit's MainPID, the unit template ships NotifyAccess=all
// (not =main) — see scripts/evolver.service for the trade-off discussion.
//
// Spec: https://www.freedesktop.org/software/systemd/man/sd_notify.html
// ---------------------------------------------------------------------------
function _sdNotify(state) {
  // Only on Linux; NOTIFY_SOCKET is absent on macOS/Windows or when not
  // running under systemd.
  if (process.platform !== 'linux') return;
  const socketPath = process.env.NOTIFY_SOCKET;
  if (!socketPath || typeof socketPath !== 'string') return;
  try {
    const cp = require('child_process');
    cp.execFile('systemd-notify', [state], { stdio: 'ignore', timeout: 5000 },
      function () { /* fire-and-forget */ });
  } catch (_) {
    // sd_notify failures must never propagate -- they are best-effort
    // status signals and the daemon must continue regardless.
  }
}

// Watchdog tuning: systemd sets WATCHDOG_USEC to the watchdog interval in
// microseconds.  We ping at half that interval (keepalive idiom) so jitter
// on the heartbeat loop never silently lets the deadline slip.
// Returns 0 when no watchdog is configured (WATCHDOG_USEC absent or invalid).
function _watchdogIntervalMs() {
  const raw = process.env.WATCHDOG_USEC;
  if (!raw) return 0;
  const usec = parseInt(raw, 10);
  if (!Number.isFinite(usec) || usec <= 0) return 0;
  // Half the configured watchdog period; minimum 5 s so we never spam.
  return Math.max(5000, Math.floor(usec / 2000));
}

let _sdWatchdogTimer = null;
let _sdWatchdogUnhealthyLogged = false;

// Start periodic sd_notify("WATCHDOG=1") pings.  Safe to call multiple times
// (subsequent calls are no-ops until _stopSdWatchdog() is called).
function _startSdWatchdog(statsProvider) {
  if (_sdWatchdogTimer) return;
  const intervalMs = _watchdogIntervalMs();
  if (!intervalMs) return; // no WATCHDOG_USEC configured
  const readStats = typeof statsProvider === 'function' ? statsProvider : getHeartbeatStats;
  _sdWatchdogTimer = setInterval(function () {
    // Gate on heartbeat liveness: a stuck-in-reauth-backoff loop still has
    // _heartbeatRunning=true but no fresh ticks, and we must let systemd
    // restart us in that state rather than satisfying its watchdog.
    try {
      var stats = readStats();
      var heartbeatIntervalMs = stats.intervalMs || _heartbeatIntervalMs;
      var freshnessCap = Math.max(2 * heartbeatIntervalMs, 5 * 60_000);
      var fresh = stats.lastTickAt && (Date.now() - stats.lastTickAt) <= freshnessCap;
      if (stats.running && stats.consecutiveFailures === 0 && fresh) {
        _sdNotify('WATCHDOG=1');
        _sdWatchdogUnhealthyLogged = false;
      } else if (!_sdWatchdogUnhealthyLogged) {
        _sdWatchdogUnhealthyLogged = true;
        try {
          console.warn('[Watchdog] skipping WATCHDOG=1 ping (heartbeat unhealthy: running=' +
            stats.running + ' consecutiveFailures=' + stats.consecutiveFailures +
            ' lastTickAt=' + stats.lastTickAt + ')');
        } catch (_) {}
      }
    } catch (_) {
      // Stats unavailable: stay silent and skip ping rather than risk a
      // false-positive liveness signal.
    }
  }, intervalMs);
  // unref: the watchdog timer must not prevent Node from exiting cleanly
  // when all other work is done.
  if (_sdWatchdogTimer && typeof _sdWatchdogTimer.unref === 'function') {
    _sdWatchdogTimer.unref();
  }
}

function _stopSdWatchdog() {
  if (_sdWatchdogTimer) {
    clearInterval(_sdWatchdogTimer);
    _sdWatchdogTimer = null;
  }
  _sdWatchdogUnhealthyLogged = false;
}

function startSystemdNotifyWatchdog(statsProvider) {
  try { _sdNotify('READY=1'); } catch (_) {}
  try { _startSdWatchdog(statsProvider); } catch (_) {}
}
// `getEvomapDir` is used lazily via _nodeIdDir() further down (#114) so a test
// can redirect ~/.evomap via EVOLVER_HOME without monkey-patching os.homedir.
const { getGepAssetsDir, getEvolverLogPath, getEvomapDir, getEvomapPath } = require('./paths');
const { computeAssetId } = require('./contentHash');
const { captureEnvFingerprint } = require('./envFingerprint');
const { validateGene } = require('./schemas/gene');
const { validateCapsule } = require('./schemas/capsule');
const { redactString } = require('./sanitize');
const {
  MAILBOX_NODE_SECRET_STATE_KEYS,
  readMailboxStateFile,
  writeMergedMailboxStateFile,
} = require('../proxy/mailbox/state');

// Run schema validators on assets before broadcasting them. Warn-only by
// design: the hub re-validates server-side and we'd rather see a malformed
// asset reach the hub (where it gets logged with full context) than have a
// silent local crash that causes the publish loop to fall behind. See
// issue #30 (H1).
function _publishValidateWarn(label, validatorFn, obj) {
  try {
    validatorFn(obj);
  } catch (e) {
    console.warn('[a2aProtocol] ' + label + ' schema validation warning before publish: ' + (e && e.message || e));
  }
}

const PROTOCOL_NAME = 'gep-a2a';
const PROTOCOL_VERSION = '1.0.0';
const VALID_MESSAGE_TYPES = ['hello', 'publish', 'fetch', 'report', 'decision', 'revoke'];

const NODE_ID_RE = /^node_[a-f0-9]{12,32}$/;
function _nodeIdDir() { return getEvomapDir(); }
function _nodeIdFile() { return path.join(_nodeIdDir(), 'node_id'); }
const LOCAL_NODE_ID_FILE = path.resolve(__dirname, '..', '..', '.evomap_node_id');

let _cachedNodeId = null;

function _loadPersistedNodeId() {
  try {
    if (fs.existsSync(_nodeIdFile())) {
      const id = fs.readFileSync(_nodeIdFile(), 'utf8').trim();
      if (id && NODE_ID_RE.test(id)) return id;
    }
  } catch {}
  try {
    if (fs.existsSync(LOCAL_NODE_ID_FILE)) {
      const id = fs.readFileSync(LOCAL_NODE_ID_FILE, 'utf8').trim();
      if (id && NODE_ID_RE.test(id)) return id;
    }
  } catch {}
  return null;
}

function _persistNodeId(id) {
  // NOTE(windows): mode 0o700 / 0o600 are silently ignored on Windows.
  // The node-id directory and file will NOT be access-restricted to the
  // current user. Rely on Windows user-profile isolation (%APPDATA% or
  // %USERPROFILE%\.evomap) as the only available protection mechanism.
  try {
    const dir = _nodeIdDir();
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
    fs.writeFileSync(_nodeIdFile(), id, { encoding: 'utf8', mode: 0o600 });
    return;
  } catch {}
  try {
    fs.writeFileSync(LOCAL_NODE_ID_FILE, id, { encoding: 'utf8', mode: 0o600 });
    return;
  } catch {}
}

function generateMessageId() {
  return 'msg_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex');
}

function getNodeId() {
  if (_cachedNodeId) return _cachedNodeId;

  if (process.env.A2A_NODE_ID) {
    const envId = String(process.env.A2A_NODE_ID).trim();
    if (NODE_ID_RE.test(envId)) {
      _cachedNodeId = envId;
      return _cachedNodeId;
    }
    console.warn('[a2aProtocol] A2A_NODE_ID=' + envId + ' has an unexpected format ' +
      '(expected node_<12-32 hex chars>). Using it as-is, but hub may reject it. ' +
      'Copy the node_id shown on https://evomap.ai after registration.');
    _cachedNodeId = envId;
    return _cachedNodeId;
  }

  const persisted = _loadPersistedNodeId();
  if (persisted) {
    _cachedNodeId = persisted;
    return _cachedNodeId;
  }

  console.warn('[a2aProtocol] A2A_NODE_ID is not set. Generating a fresh node ID. ' +
    'The ID is persisted locally, so it stays stable across runs on this install. ' +
    'Set A2A_NODE_ID after registering at https://evomap.ai to use a stable identity.');

  // Random rather than hash(device+agent+cwd): a container/VM image cloned
  // before any first run would otherwise produce identical IDs across every
  // clone (same hostname, agent name, cwd → same hash → Hub conflict).
  // 12 hex chars (48 bits) matches the existing persisted format; existing
  // installs already have a persisted ID and never re-enter this path.
  const computed = 'node_' + crypto.randomBytes(6).toString('hex');

  _persistNodeId(computed);
  _cachedNodeId = computed;
  return _cachedNodeId;
}

// --- Base message builder ---

function buildMessage(params) {
  if (!params || typeof params !== 'object') {
    throw new Error('buildMessage requires a params object');
  }
  const messageType = params.messageType;
  const payload = params.payload;
  const senderId = params.senderId;
  if (!VALID_MESSAGE_TYPES.includes(messageType)) {
    throw new Error('Invalid message type: ' + messageType + '. Valid: ' + VALID_MESSAGE_TYPES.join(', '));
  }
  return {
    protocol: PROTOCOL_NAME,
    protocol_version: PROTOCOL_VERSION,
    message_type: messageType,
    message_id: generateMessageId(),
    sender_id: senderId || getNodeId(),
    timestamp: new Date().toISOString(),
    payload: payload || {},
  };
}

// --- Typed message builders ---

function buildHello(opts) {
  const o = opts || {};
  var name = (typeof o.name === 'string') ? o.name.trim().slice(0, 32) : undefined;
  return buildMessage({
    messageType: 'hello',
    senderId: o.nodeId,
    payload: {
      capabilities: o.capabilities || {},
      gene_count: typeof o.geneCount === 'number' ? o.geneCount : null,
      capsule_count: typeof o.capsuleCount === 'number' ? o.capsuleCount : null,
      env_fingerprint: captureEnvFingerprint(),
      name: name || undefined,
    },
  });
}

function buildPublish(opts) {
  const o = opts || {};
  const asset = o.asset;
  if (!asset || !asset.type || !asset.id) {
    throw new Error('publish: asset must have type and id');
  }
  // 2026-05-03: mirror the guard in buildPublishBundle. Single-asset publish
  // is another path for LLM-generated Capsules that bypass solidify.js.
  if (asset.type === 'Capsule'
      && (!Array.isArray(asset.execution_trace) || asset.execution_trace.length === 0)) {
    try {
      const { buildCapsuleTraceSteps } = require('./solidify');
      const synthesized = buildCapsuleTraceSteps({
        blast: asset.blast_radius || null,
        validation: o.validation || null,
        canary: o.canary || null,
        outcomeStatus: asset.outcome && asset.outcome.status,
      });
      if (Array.isArray(synthesized) && synthesized.length > 0) {
        asset.execution_trace = synthesized;
      }
    } catch (_) {
      // non-fatal; hub has a backfill path.
    }
  }
  if (asset.type === 'Gene')         _publishValidateWarn('Gene', validateGene, asset);
  else if (asset.type === 'Capsule') _publishValidateWarn('Capsule', validateCapsule, asset);
  const assetIdVal = asset.asset_id || computeAssetId(asset);
  const nodeSecret = getHubNodeSecret();
  if (!nodeSecret) {
    throw new Error('publish: node_secret is required for signing. Run hello first to obtain one.');
  }
  const signature = crypto.createHmac('sha256', nodeSecret).update(assetIdVal).digest('hex');
  return buildMessage({
    messageType: 'publish',
    senderId: o.nodeId,
    payload: {
      asset_type: asset.type,
      asset_id: assetIdVal,
      local_id: asset.id,
      asset: asset,
      signature: signature,
    },
  });
}

// Build a bundle publish message containing Gene + Capsule (+ optional EvolutionEvent).
// Hub requires payload.assets = [Gene, Capsule] since bundle enforcement was added.
function buildPublishBundle(opts) {
  const o = opts || {};
  const gene = o.gene;
  const capsule = o.capsule;
  const event = o.event || null;
  if (!gene || gene.type !== 'Gene' || !gene.id) {
    throw new Error('publishBundle: gene must be a valid Gene with type and id');
  }
  if (!capsule || capsule.type !== 'Capsule' || !capsule.id) {
    throw new Error('publishBundle: capsule must be a valid Capsule with type and id');
  }
  // Deep schema validation (warn-only).
  _publishValidateWarn('Gene', validateGene, gene);
  _publishValidateWarn('Capsule', validateCapsule, capsule);
  if (o.modelName && typeof o.modelName === 'string') {
    gene.model_name = o.modelName;
    capsule.model_name = o.modelName;
  }
  // 2026-05-03: publish-time guard. The LLM prompt template historically
  // produced Capsules with no execution_trace field, causing the hub to flag
  // every Capsule as trace_empty even on agents that had upgraded to a
  // trace-aware SDK. Synthesize an array from whatever the caller happens to
  // have (validation/canary/blast) -- buildCapsuleTraceSteps always returns
  // at least one fallback step so the resulting array is guaranteed non-empty.
  // Runs before computeAssetId so the asset_id reflects the filled-in trace.
  if (!Array.isArray(capsule.execution_trace) || capsule.execution_trace.length === 0) {
    try {
      const { buildCapsuleTraceSteps } = require('./solidify');
      const synthesized = buildCapsuleTraceSteps({
        blast: capsule.blast_radius || null,
        validation: o.validation || null,
        canary: o.canary || null,
        outcomeStatus: capsule.outcome && capsule.outcome.status,
      });
      if (Array.isArray(synthesized) && synthesized.length > 0) {
        capsule.execution_trace = synthesized;
      }
    } catch (_) {
      // non-fatal: the hub has a backfill path as a second line of defense
    }
  }
  gene.asset_id = computeAssetId(gene);
  capsule.asset_id = computeAssetId(capsule);
  const geneAssetId = gene.asset_id;
  const capsuleAssetId = capsule.asset_id;
  const nodeSecret = getHubNodeSecret();
  if (!nodeSecret) {
    throw new Error('publishBundle: node_secret is required for signing. Run hello first to obtain one.');
  }
  const signatureInput = [geneAssetId, capsuleAssetId].sort().join('|');
  const signature = crypto.createHmac('sha256', nodeSecret).update(signatureInput).digest('hex');
  const assets = [gene, capsule];
  if (event && event.type === 'EvolutionEvent') {
    if (o.modelName && typeof o.modelName === 'string') {
      event.model_name = o.modelName;
    }
    event.asset_id = computeAssetId(event);
    assets.push(event);
  }
  const publishPayload = {
    assets: assets,
    signature: signature,
  };
  if (o.chainId && typeof o.chainId === 'string') {
    publishPayload.chain_id = o.chainId;
  }
  return buildMessage({
    messageType: 'publish',
    senderId: o.nodeId,
    payload: publishPayload,
  });
}

function buildFetch(opts) {
  const o = opts || {};
  const fetchPayload = {
    asset_type: o.assetType || null,
    local_id: o.localId || null,
    content_hash: o.contentHash || null,
  };
  if (Array.isArray(o.signals) && o.signals.length > 0) {
    fetchPayload.signals = o.signals;
  }
  if (o.searchOnly === true) {
    fetchPayload.search_only = true;
  }
  if (Array.isArray(o.assetIds) && o.assetIds.length > 0) {
    fetchPayload.asset_ids = o.assetIds;
  }
  return buildMessage({
    messageType: 'fetch',
    senderId: o.nodeId,
    payload: fetchPayload,
  });
}

function buildReport(opts) {
  const o = opts || {};
  return buildMessage({
    messageType: 'report',
    senderId: o.nodeId,
    payload: {
      target_asset_id: o.assetId || null,
      target_local_id: o.localId || null,
      validation_report: o.validationReport || null,
    },
  });
}

function buildDecision(opts) {
  const o = opts || {};
  const validDecisions = ['accept', 'reject', 'quarantine'];
  if (!validDecisions.includes(o.decision)) {
    throw new Error('decision must be one of: ' + validDecisions.join(', '));
  }
  return buildMessage({
    messageType: 'decision',
    senderId: o.nodeId,
    payload: {
      target_asset_id: o.assetId || null,
      target_local_id: o.localId || null,
      decision: o.decision,
      reason: o.reason || null,
    },
  });
}

function buildRevoke(opts) {
  const o = opts || {};
  return buildMessage({
    messageType: 'revoke',
    senderId: o.nodeId,
    payload: {
      target_asset_id: o.assetId || null,
      target_local_id: o.localId || null,
      reason: o.reason || null,
    },
  });
}

// --- Validation ---

function isValidProtocolMessage(msg) {
  if (!msg || typeof msg !== 'object') return false;
  if (msg.protocol !== PROTOCOL_NAME) return false;
  if (!msg.message_type || !VALID_MESSAGE_TYPES.includes(msg.message_type)) return false;
  if (!msg.message_id || typeof msg.message_id !== 'string') return false;
  if (!msg.timestamp || typeof msg.timestamp !== 'string') return false;
  return true;
}

// Try to extract a raw asset from either a protocol message or a plain asset object.
// This enables backward-compatible ingestion of both old-format and new-format payloads.
function unwrapAssetFromMessage(input) {
  if (!input || typeof input !== 'object') return null;
  // If it is a protocol message with a publish payload, extract the asset.
  if (input.protocol === PROTOCOL_NAME && input.message_type === 'publish') {
    const p = input.payload;
    if (p && p.asset && typeof p.asset === 'object') return p.asset;
    return null;
  }
  // If it is a plain asset (Gene/Capsule/EvolutionEvent), return as-is.
  if (input.type === 'Gene' || input.type === 'Capsule' || input.type === 'EvolutionEvent') {
    return input;
  }
  return null;
}

// --- File Transport ---

function ensureDir(dir) {
  try {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  } catch (e) {
    console.warn('[a2aProtocol] ensureDir failed:', dir, e && e.message || e);
  }
}

function defaultA2ADir() {
  return process.env.A2A_DIR || path.join(getGepAssetsDir(), 'a2a');
}

function fileTransportSend(message, opts) {
  const dir = (opts && opts.dir) || defaultA2ADir();
  const subdir = path.join(dir, 'outbox');
  ensureDir(subdir);
  const filePath = path.join(subdir, message.message_type + '.jsonl');
  fs.appendFileSync(filePath, JSON.stringify(message) + '\n', 'utf8');
  return { ok: true, path: filePath };
}

function fileTransportReceive(opts) {
  const dir = (opts && opts.dir) || defaultA2ADir();
  const subdir = path.join(dir, 'inbox');
  if (!fs.existsSync(subdir)) return [];
  const MAX_FILES = 50;
  const MAX_FILE_BYTES = 256 * 1024;
  const files = fs.readdirSync(subdir).filter(function (f) { return f.endsWith('.jsonl'); }).slice(0, MAX_FILES);
  const messages = [];
  for (let fi = 0; fi < files.length; fi++) {
    try {
      const filePath = path.join(subdir, files[fi]);
      const stat = fs.statSync(filePath);
      let raw;
      if (stat.size <= MAX_FILE_BYTES) {
        raw = fs.readFileSync(filePath, 'utf8');
      } else {
        const fd = fs.openSync(filePath, 'r');
        try {
          const buf = Buffer.alloc(MAX_FILE_BYTES);
          fs.readSync(fd, buf, 0, MAX_FILE_BYTES, stat.size - MAX_FILE_BYTES);
          raw = buf.toString('utf8');
          const firstNl = raw.indexOf('\n');
          if (firstNl >= 0) raw = raw.slice(firstNl + 1);
        } finally {
          fs.closeSync(fd);
        }
      }
      const lines = raw.split('\n').map(function (l) { return l.trim(); }).filter(Boolean);
      for (let li = 0; li < lines.length; li++) {
        try {
          const msg = JSON.parse(lines[li]);
          if (msg && msg.protocol === PROTOCOL_NAME) messages.push(msg);
        } catch (e) {
          console.warn('[a2aProtocol] Malformed JSON line in inbox file ' + files[fi] + ' (line ' + (li + 1) + '):', e && e.message || e);
        }
      }
    } catch (e) {
      console.warn('[a2aProtocol] Failed to read inbox file:', files[fi], e && e.message || e);
    }
  }
  return messages;
}

function fileTransportList(opts) {
  const dir = (opts && opts.dir) || defaultA2ADir();
  const subdir = path.join(dir, 'outbox');
  if (!fs.existsSync(subdir)) return [];
  return fs.readdirSync(subdir).filter(function (f) { return f.endsWith('.jsonl'); });
}

// --- HTTP Transport (connects to evomap-hub) ---

// Sanitize untrusted values before they appear in log lines.
function _safeLogVal(v, max) {
  if (v === null || v === undefined) return '?';
  return String(v).replace(/[\x00-\x1f\x7f]/g, '').slice(0, typeof max === 'number' ? max : 80);
}

// Returns true when HUB_DRY_RUN is active — shared by all outbound hub paths.
function _isDryRun() {
  var v = String(process.env.HUB_DRY_RUN || '').toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

// Set to true after the first dry-run warning fires. HUB_DRY_RUN warnings are
// intentionally single-shot per process — repeated calls in the same run (e.g.
// from test suites) should not spam stderr. If the flag needs to be reset
// between test cases, use _resetDryRunWarnedForTesting().
let _dryRunWarned = false;

function httpTransportSend(message, opts) {
  // HUB_DRY_RUN is a process-wide escape hatch for integration tests.
  // It takes precedence over opts.hubUrl — env always wins — so callers with
  // an explicit hubUrl are also short-circuited when the flag is set.
  // NOTE: returns {ok:true, dry_run:true} even when A2A_HUB_URL is unset.
  // Callers must not interpret ok:true as "hub accepted the message" — it only
  // means "send was attempted and did not error". The one-time warn below and
  // the dry_run:true marker in the response are the only signals available.
  if (_isDryRun()) {
    if (!_dryRunWarned) {
      _dryRunWarned = true;
      console.warn('[A2A] HUB_DRY_RUN is set -- outbound hub transport disabled. Do not set this in production.');
    }
    return Promise.resolve({ ok: true, dry_run: true });
  }
  const hubUrl = (opts && opts.hubUrl) || process.env.A2A_HUB_URL;
  if (!hubUrl) return Promise.resolve({ ok: false, error: 'A2A_HUB_URL not set' });
  const timeoutMs = (opts && opts.timeoutMs) || require('../config').HTTP_TRANSPORT_TIMEOUT_MS;
  const endpoint = hubUrl.replace(/\/+$/, '') + '/a2a/' + message.message_type;
  const body = JSON.stringify(message);
  return hubFetch(endpoint, {
    method: 'POST',
    headers: buildNodeScopedHubHeaders(),
    body: body,
    signal: AbortSignal.timeout(timeoutMs),
  })
    .then(function (res) {
      if (!res.ok) return res.text().then(function (t) { return { ok: false, error: 'HTTP ' + res.status + ': ' + t.slice(0, 200) }; });
      return res.json().then(function (data) { return { ok: true, response: data }; });
    })
    .catch(function (err) { return { ok: false, error: err.message }; });
}

function httpTransportReceive(opts) {
  const hubUrl = (opts && opts.hubUrl) || process.env.A2A_HUB_URL;
  if (!hubUrl) return Promise.resolve([]);
  const timeoutMs = (opts && opts.timeoutMs) || require('../config').HTTP_TRANSPORT_TIMEOUT_MS;
  const assetType = (opts && opts.assetType) || null;
  const signals = (opts && Array.isArray(opts.signals)) ? opts.signals : null;
  const fetchMsg = buildFetch({ assetType: assetType, signals: signals });
  const endpoint = hubUrl.replace(/\/+$/, '') + '/a2a/fetch';
  return hubFetch(endpoint, {
    method: 'POST',
    headers: buildNodeScopedHubHeaders(),
    body: JSON.stringify(fetchMsg),
    signal: AbortSignal.timeout(timeoutMs),
  })
    .then(function (res) {
      if (!res.ok) {
        // Drain the response body so undici can return the pool slot. Leaving
        // the body un-consumed on the floor leaks one socket per non-ok
        // /a2a/fetch reply; over a long idle session that exhausts the
        // dispatcher pool and causes later heartbeats to hang.
        try { if (res.body && typeof res.body.cancel === 'function') res.body.cancel().catch(function () {}); } catch (_) {}
        console.warn('[a2aProtocol] httpTransportReceive HTTP ' + res.status);
        return { payload: { results: [] } };
      }
      return res.json();
    })
    .then(function (data) {
      if (data && data.payload && Array.isArray(data.payload.results)) {
        var total = data.payload.results.length;
        var discarded = 0;
        var filtered = data.payload.results.filter(function (asset) {
          if (!asset) return false;
          if (!asset.asset_id) {
            discarded++;
            console.warn('[A2A] asset_id_missing_inbound type=' + _safeLogVal(asset.type, 32) + ' id=' + _safeLogVal(asset.id, 64) + ' -- discarded');
            return false;
          }
          // computeAssetId called directly (not verifyAssetId) so the computed
          // hash is available for the structured warn below without a second call.
          // Only asset_id is excluded (self-referential). The a2a field IS included
          // because solidify sets capsule.a2a before buildPublishBundle, so the
          // stored asset_id was computed with the a2a field present. lowerConfidence
          // annotations (confidence_factor, received_at) are applied client-side
          // after this integrity check, not by the Hub on stored assets.
          var expected = computeAssetId(asset);
          if (asset.asset_id !== expected) {
            discarded++;
            console.warn('[A2A] asset_id_mismatch_inbound type=' + _safeLogVal(asset.type, 32) + ' asset_id_received=' + _safeLogVal(asset.asset_id, 80) + ' asset_id_expected=' + _safeLogVal(expected, 80) + ' id=' + _safeLogVal(asset.id, 64) + ' -- discarded');
            return false;
          }
          return true;
        });
        if (discarded > 0) {
          console.warn('[A2A] integrity_filter_summary discarded=' + discarded + ' total=' + total);
        }
        return filtered;
      }
      return [];
    })
    .catch(function (err) {
      console.warn('[a2aProtocol] httpTransportReceive failed:', err && err.message || err);
      return [];
    });
}

function httpTransportList() {
  return ['http'];
}

// --- Heartbeat ---

let _heartbeatTimer = null;
let _heartbeatStartedAt = null;
let _heartbeatConsecutiveFailures = 0;
let _heartbeatTotalSent = 0;
let _heartbeatTotalFailed = 0;
let _heartbeatFpSent = false;
let _latestAvailableWork = [];
let _latestOverdueTasks = [];
let _latestSkillStoreHint = null;
let _latestNoveltyHint = null;
let _latestCapabilityGaps = [];
let _pendingCommitmentUpdates = [];
let _latestHubEvents = [];
let _latestHeartbeatActions = null;
let _latestSharedKnowledgeDelta = null;
let _sharedKnowledgeVersion = 0;
let _forceUpdatePending = null;
// Heartbeat-driven force_update lifecycle tracking.
// _forceUpdateInFlight: true while executeForceUpdate is running (sync in practice,
//   but we guard anyway in case a later implementation is async).
// _forceUpdateLastAttemptAt: epoch ms of the most recent upgrade attempt.
//   Used to cool down retries when the upgrade fails, so we do not spawn
//   `npx degit` / `npm install -g` on every heartbeat (default interval 30s).
let _forceUpdateInFlight = false;
let _forceUpdateLastAttemptAt = 0;
function _getForceUpdateRetryCooldownMs() {
  var v = Number(process.env.EVOLVER_FORCE_UPDATE_RETRY_COOLDOWN_MS);
  if (Number.isFinite(v) && v >= 0) return v;
  return 15 * 60 * 1000;
}

// ---------------------------------------------------------------------------
// force_update last_update reporting (evomap-hub #1034 / #1039).
//
// After every executeForceUpdate attempt we persist the outcome to
// ${EVOLVER_HOME}/force_update_last.json (atomic write via per-pid tmp
// + rename). The next sendHeartbeat() reads that file and attaches it to
// body.last_update so the hub-side EvolverUpgradeAttempt table gets a row.
// On confirmed 2xx delivery the file is deleted; on non-2xx / network
// error the file is retained so the next heartbeat retries (hub-side
// Redis dedup makes retries safe).
//
// File contents = the exact lastUpdateSchema payload from
// evomap-hub/src/schemas/a2a.js (to_version required <=32, status enum,
// optional from_version, directive_id min:1/max:64, error <=1000,
// finished_at as ms-since-epoch >= 1700000000000).
// ---------------------------------------------------------------------------
// Hub lastUpdateSchema limits (mirrors evomap-hub/src/schemas/a2a.js). Hoisted
// so the parse, read, and persist paths share a single source of truth.
const _LAST_UPDATE_LIMITS = {
  TO_VERSION_MAX: 32,
  FROM_VERSION_MAX: 32,
  DIRECTIVE_ID_MAX: 64,
  ERROR_MAX: 1000,
  FINISHED_AT_MIN: 1_700_000_000_000,
};

// 7-day TTL: a node that exit(78)'d but supervisor never restarted should not
// keep lying to the hub forever.
const _LAST_UPDATE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

// Concrete-semver regex matching src/forceUpdate.js -- the hub also expects
// to_version to be a bare version, no range operators. The strip-then-validate
// pair (see _extractTargetVersion below) mirrors forceUpdate.js exactly,
// so telemetry's parsed to_version can only differ from the upgrader's
// requiredVersion in cases where forceUpdate.js itself would refuse the
// directive -- and in those cases _extractTargetVersion returns ''.
const _SEMVER_NUMERIC_IDENTIFIER = '0|[1-9]\\d*';
const _SEMVER_PRERELEASE_IDENTIFIER = '(?:0|[1-9]\\d*|\\d*[A-Za-z-][0-9A-Za-z-]*)';
const _SEMVER_BUILD_IDENTIFIER = '[0-9A-Za-z-]+';
const _CONCRETE_SEMVER_RE = new RegExp(
  '^(' + _SEMVER_NUMERIC_IDENTIFIER + ')\\.(' + _SEMVER_NUMERIC_IDENTIFIER + ')\\.(' +
    _SEMVER_NUMERIC_IDENTIFIER + ')(?:-(' + _SEMVER_PRERELEASE_IDENTIFIER +
    '(?:\\.' + _SEMVER_PRERELEASE_IDENTIFIER + ')*))?(?:\\+(' +
    _SEMVER_BUILD_IDENTIFIER + '(?:\\.' + _SEMVER_BUILD_IDENTIFIER + ')*))?$'
);

// Rate-limit the noisy warns from persist/read/clear so a permanently-broken
// home dir does not flood stderr on every heartbeat tick.
var _lastUpdateWarnState = { lastWarnAt: 0 };
function _warnLastUpdateRateLimited(msg) {
  var now = Date.now();
  if ((now - _lastUpdateWarnState.lastWarnAt) > 60 * 60 * 1000) {
    _lastUpdateWarnState.lastWarnAt = now;
    console.warn(msg);
  }
}

// Hub 400 circuit breaker. If the hub keeps rejecting heartbeats with 400 and
// last_update was attached, the file is poisoning the heartbeat. Three strikes
// (or one strike that explicitly names last_update) unlink it.
var _lastUpdateConsecutive400 = 0;

// Read the current node_id synchronously without forcing creation of a new ID
// (getNodeId would generate + persist a fresh one in a fault path, which we
// must not do from the heartbeat tick just to pick a state-file suffix).
//
// Defense-in-depth: the 8-char slice MUST be lowercase hex. The legacy
// ~/.evomap/node_id file is user-writable (mode 0o600) and tests have
// observed corrupted content surface in the wild (truncated writes,
// hand-edits, atomic-write races). Without the regex gate, a corrupt file
// like `node_../etc/passwd` would yield a suffix like `../etc/p`, which
// path.join() in _getLastUpdateStatePath() would then traverse outside
// EVOLVER_HOME. Fall through to 'anon' rather than emit a path that
// escapes the directory.
function _shortNodeIdForStatePath() {
  var HEX8 = /^[a-f0-9]{8}$/;
  try {
    if (_cachedNodeId && typeof _cachedNodeId === 'string') {
      var hex = _cachedNodeId.replace(/^node_/, '');
      if (hex.length >= 8) {
        var slice = hex.slice(0, 8);
        if (HEX8.test(slice)) return slice;
      }
    }
  } catch (_) {}
  try {
    var raw = fs.readFileSync(_nodeIdFile(), 'utf8').trim();
    if (raw) {
      var hex2 = raw.replace(/^node_/, '');
      if (hex2.length >= 8) {
        var slice2 = hex2.slice(0, 8);
        if (HEX8.test(slice2)) return slice2;
      }
    }
  } catch (_) {}
  try {
    var raw2 = fs.readFileSync(LOCAL_NODE_ID_FILE, 'utf8').trim();
    if (raw2) {
      var hex3 = raw2.replace(/^node_/, '');
      if (hex3.length >= 8) {
        var slice3 = hex3.slice(0, 8);
        if (HEX8.test(slice3)) return slice3;
      }
    }
  } catch (_) {}
  return 'anon';
}

function _getLastUpdateStatePath() {
  // Per-node suffix: multiple processes sharing EVOLVER_HOME (test runners,
  // dev sandboxes) would otherwise collide on one file.
  return getEvomapPath('force_update_last.' + _shortNodeIdForStatePath() + '.json');
}

const _LAST_UPDATE_STATUS_VALUES = new Set([
  'pending', 'in_progress', 'success', 'failed', 'skipped',
]);

// Parse a usable target version out of forceUpdate.required_version. The hub
// (evomap-hub/src/services/a2aService.js:220) only sends
// `force_update.required_version`, expressed as a semver range like
// ">=1.88.0". to_version on lastUpdateSchema is a bare version string, so the
// constraint operators and an optional leading v MUST be stripped before
// persisting. The strip and validation regexes mirror forceUpdate.js exactly
// -- any input that
// _extractTargetVersion accepts here, executeForceUpdate would also accept,
// and vice versa. Without that alignment, telemetry can report
// to_version="1.88.0" for a directive (e.g. "<2.0.0") that the
// upgrader itself rejects, producing ghost `failed` rows in
// EvolverUpgradeAttempt for upgrades that were never even attempted.
// Returns '' when no parsable version remains.
function _extractTargetVersion(forceUpdate) {
  if (!forceUpdate || typeof forceUpdate !== 'object') return '';
  var raw = forceUpdate.required_version;
  if (typeof raw !== 'string') return '';
  // Bugbot PR#188 #2: do NOT .trim() after the strip. forceUpdate.js does the
  // same strip with no trim, so any trailing whitespace (space, tab, newline)
  // falls into the anchored _CONCRETE_SEMVER_RE check below. The regex's `$`
  // anchor rejects it, matching forceUpdate.js's behavior.
  // A previous .trim() here would let "1.88.0 " pass our check but get
  // rejected by executeForceUpdate, producing a phantom failed-row with a
  // concrete to_version for an upgrade that never started.
  var s = raw.replace(/^[>=^~\s]+/, '');
  s = s.replace(/^v(?=\d)/, '');
  if (!s) return '';
  // Reject (rather than slice) when too long -- slicing could land in the
  // middle of a prerelease/build tag and produce a value the hub rejects.
  if (s.length > _LAST_UPDATE_LIMITS.TO_VERSION_MAX) return '';
  if (!_CONCRETE_SEMVER_RE.test(s)) return '';
  return s;
}

function _persistLastUpdateState(payload) {
  // Defensive: telemetry must never block force_update. All errors are
  // swallowed with a warn.
  try {
    var dir = getEvomapDir();
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    var statePath = _getLastUpdateStatePath();
    // Match the per-pid tmp + rename pattern from
    // src/proxy/mailbox/store.js:_persistState (two evolver processes
    // sharing the same tmp path would otherwise tear writes).
    var tmp = statePath + '.' + process.pid + '.tmp';
    // 0o600: matches the convention used by _persistNodeSecret / _persistNodeId.
    fs.writeFileSync(tmp, JSON.stringify(payload), { encoding: 'utf8', mode: 0o600 });
    if (process.platform === 'win32') {
      // Windows rename(2) does not atomically replace an existing target.
      try { fs.unlinkSync(statePath); } catch (e) {
        if (e && e.code !== 'ENOENT') throw e;
      }
    }
    fs.renameSync(tmp, statePath);
  } catch (e) {
    _warnLastUpdateRateLimited('[ForceUpdate] failed to persist last_update state (non-fatal): ' +
      (e && e.message || e));
  }
}

function _readPendingLastUpdate() {
  var statePath;
  try {
    statePath = _getLastUpdateStatePath();
    if (!fs.existsSync(statePath)) return null;
    var raw = fs.readFileSync(statePath, 'utf8');
    var parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') {
      throw new Error('parsed payload is not an object');
    }
    // TTL gate: if finished_at is a valid ms-since-epoch AND older than 7d,
    // drop the file. (A bogus seconds-instead-of-ms value falls outside the
    // FINISHED_AT_MIN window and is handled by the optional-field stripper
    // below -- do not interpret it as "ancient".) This prevents a node that
    // exit(78)'d but supervisor never restarted from replaying the same row
    // on every restart forever.
    if (typeof parsed.finished_at === 'number'
        && Number.isInteger(parsed.finished_at)
        && parsed.finished_at >= _LAST_UPDATE_LIMITS.FINISHED_AT_MIN
        && (Date.now() - parsed.finished_at) > _LAST_UPDATE_TTL_MS) {
      _warnLastUpdateRateLimited('[ForceUpdate] stale last_update state, dropping (older than 7d)');
      try { fs.unlinkSync(statePath); } catch (_) {}
      return null;
    }
    // Validate the shape we will send. The hub validates with
    // lastUpdateSchema; anything that fails there is silently dropped
    // server-side, so we drop client-side instead of sending garbage.
    // Required fields: invalid -> drop the file (caller treats as "no
    // pending"). Optional fields: invalid -> omit from the returned payload
    // but keep the file so the rest of the report still lands.
    if (typeof parsed.to_version !== 'string' || parsed.to_version.length === 0
        || parsed.to_version.length > _LAST_UPDATE_LIMITS.TO_VERSION_MAX) {
      throw new Error('to_version missing or invalid');
    }
    if (!_LAST_UPDATE_STATUS_VALUES.has(parsed.status)) {
      throw new Error('status missing or not in enum');
    }
    var clean = {
      to_version: parsed.to_version,
      status: parsed.status,
    };
    // from_version: optional string. Trim+slice; omit if not a non-empty
    // string after sanitisation.
    if (parsed.from_version !== undefined) {
      if (typeof parsed.from_version === 'string') {
        var fv = parsed.from_version.trim().slice(0, _LAST_UPDATE_LIMITS.FROM_VERSION_MAX);
        if (fv.length > 0) clean.from_version = fv;
      }
    }
    // directive_id: hub schema is .min(1) so the empty string is rejected.
    if (parsed.directive_id !== undefined) {
      if (typeof parsed.directive_id === 'string') {
        var did = parsed.directive_id.slice(0, _LAST_UPDATE_LIMITS.DIRECTIVE_ID_MAX);
        if (did.length > 0) clean.directive_id = did;
      }
    }
    // error: optional string. Truncate; omit if not a string at all (hub
    // also allows null, but we just drop the field for simplicity).
    if (parsed.error !== undefined && parsed.error !== null) {
      if (typeof parsed.error === 'string') {
        clean.error = parsed.error.slice(0, _LAST_UPDATE_LIMITS.ERROR_MAX);
      }
    }
    // finished_at: optional integer in ms since epoch. A client that wrote
    // seconds (e.g. 1700000000) would silently land in 1970 on the hub side.
    if (parsed.finished_at !== undefined) {
      if (typeof parsed.finished_at === 'number'
          && Number.isInteger(parsed.finished_at)
          && parsed.finished_at >= _LAST_UPDATE_LIMITS.FINISHED_AT_MIN) {
        clean.finished_at = parsed.finished_at;
      }
    }
    return clean;
  } catch (e) {
    _warnLastUpdateRateLimited('[ForceUpdate] dropping corrupt last_update state: ' +
      (e && e.message || e));
    try {
      if (statePath && fs.existsSync(statePath)) fs.unlinkSync(statePath);
    } catch (_) {}
    return null;
  }
}

function _clearLastUpdateState() {
  try {
    var statePath = _getLastUpdateStatePath();
    if (fs.existsSync(statePath)) fs.unlinkSync(statePath);
  } catch (e) {
    _warnLastUpdateRateLimited('[ForceUpdate] failed to clear last_update state (non-fatal): ' +
      (e && e.message || e));
  }
}

// Identity-aware clear. The success/clear branch in sendHeartbeat captures
// _pendingLastUpdate at request-build time; between that moment and the 2xx
// arrival a concurrent _maybeTriggerForceUpdateFromHeartbeat (retry past
// cooldown after a previous failure) may have rewritten the same file with a
// FRESHER outcome. A blanket _clearLastUpdateState() would silently drop that
// second attempt and the hub would never see it (next heartbeat finds no
// file). Solution: re-read the file and only unlink when its identity tuple
// matches what we just sent. If it differs, the next heartbeat will pick up
// the fresher payload.
function _clearLastUpdateStateIfMatches(sent) {
  if (!sent || typeof sent !== 'object') return;
  var statePath = _getLastUpdateStatePath();
  var raw;
  try {
    if (!fs.existsSync(statePath)) return; // already gone, fine
    raw = fs.readFileSync(statePath, 'utf8');
  } catch (e) {
    // Read errored on an existing file -- be conservative and keep it. Next
    // heartbeat's _readPendingLastUpdate will deal with it (parse-fail path
    // unlinks anyway).
    _warnLastUpdateRateLimited('[ForceUpdate] failed to read last_update state for identity check (non-fatal): ' +
      (e && e.message || e));
    return;
  }
  var parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (_) {
    // Corrupt JSON: matches the "drop it" semantics in _readPendingLastUpdate.
    try { fs.unlinkSync(statePath); } catch (_) {}
    return;
  }
  // Mirror the optional-field strip rules in _readPendingLastUpdate so the
  // identity tuple does not diverge between sanitized `sent` and raw on-disk
  // `parsed`. Without this, an on-disk `finished_at` that fails the ms-int
  // gate (e.g. legacy seconds-precision value) lives on `parsed` but is
  // stripped from `sent` → identity never matches → file is never deleted
  // and the same payload re-sends every heartbeat. Bugbot PR#188 #2.
  function _identityFields(p) {
    if (!p || typeof p !== 'object') return { status: undefined, finished_at: undefined, directive_id: null, to_version: undefined };
    var finishedAt;
    if (typeof p.finished_at === 'number'
        && Number.isInteger(p.finished_at)
        && p.finished_at >= _LAST_UPDATE_LIMITS.FINISHED_AT_MIN) {
      finishedAt = p.finished_at;
    }
    var directiveId = null;
    if (typeof p.directive_id === 'string') {
      var did = p.directive_id.slice(0, _LAST_UPDATE_LIMITS.DIRECTIVE_ID_MAX);
      if (did.length > 0) directiveId = did;
    }
    return {
      status: p.status,
      finished_at: finishedAt,
      directive_id: directiveId,
      to_version: p.to_version,
    };
  }
  function _identity(p) { return JSON.stringify(_identityFields(p)); }
  if (_identity(parsed) !== _identity(sent)) {
    _warnLastUpdateRateLimited('[ForceUpdate] last_update state file rotated mid-flight; keeping fresher payload.');
    return;
  }
  try {
    fs.unlinkSync(statePath);
  } catch (e) {
    _warnLastUpdateRateLimited('[ForceUpdate] failed to clear last_update state (non-fatal): ' +
      (e && e.message || e));
  }
}
let _pollInflight = false;
// Round-5: self-driving long-poll. Prior to this branch, _fetchHubEvents
// was triggered only when /a2a/heartbeat responded with
// has_pending_events=true (a2aProtocol.js:1471). The user-visible bug:
// if SSE silently fails (Node 22.x EventSource is experimental + the
// `eventsource` fallback package is not installed -- both are true on
// default installs), the hub has no live consumer for new events, so
// events queue server-side until the NEXT heartbeat tick happens to
// surface has_pending_events. With a default 30s..6m heartbeat
// interval, the user perceives the node as "alive on the hub but
// nothing happens when I click dispatch". A self-driving long-poll
// closes this hole: the client keeps a single long-poll open at all
// times, so hub-side events are delivered within the long-poll round
// trip (<= 55s) regardless of SSE health or heartbeat cadence. See
// claude-heartbeat-resilience-followups.md section 3 for the historical
// "recommended fix" that this implements.
let _selfDrivingPollEnabled = false;
let _selfDrivingPollTimer = null;
let _selfDrivingPollBackoffMs = 1000;
const _SELF_DRIVING_POLL_BASE_MS = 1000;
const _SELF_DRIVING_POLL_MAX_BACKOFF_MS = 60_000;
const _SELF_DRIVING_POLL_QUIET_MS = 5 * 60_000;
// Round-7 (§20.2): client-side defense against hub 429 from
// /a2a/events/poll's 4/60s per-sender bucket (followups §19.3). When
// _fetchHubEvents sees a non-ok response, it carries any retry_after_ms
// signal (body envelope or Retry-After header) out via this module-level
// override. The self-driving poll's success arm reads-and-clears it
// before falling back to its own scheduling logic, so a 429 forces the
// next poll past the hub's window instead of refilling the rate-limit
// bucket every 1s. Default 16s on a bare 429 keeps us under the 4/60s
// ceiling even without an explicit retry signal. Floor 16s, ceiling
// 60s (matches _SELF_DRIVING_POLL_MAX_BACKOFF_MS).
let _pendingSelfDrivingPollDelayMs = 0;
const _SELF_DRIVING_POLL_429_FALLBACK_MS = 16_000;
let _cachedHubNodeSecret = null;
let _cachedHubNodeSecretAt = 0;
let _cachedHubNodeSecretVersion = null;
let _cachedHubNodeSecretVersionAt = 0;
let _suppressEnvNodeSecret = false;
const _SECRET_CACHE_TTL_MS = require('../config').SECRET_CACHE_TTL_MS;
let _heartbeatIntervalMs = 0;
let _heartbeatRunning = false;
// Wall-clock timestamp of the most recent heartbeat tick (entry, not exit).
// Used by pokeHeartbeat() to throttle healthy-node wake-ups so that
// user-activity-driven pokes cannot exceed the hub's 6 heartbeats / 300s
// per-sender rate limit.
let _heartbeatLastTickAt = 0;
// pokeHeartbeat() debounce window for healthy nodes. A failing node
// (consecutiveFailures > 0) bypasses this so recovery is never blocked.
// Mirrors POKE_THROTTLE_MS in src/proxy/lifecycle/manager.js (#544).
const _HEARTBEAT_POKE_THROTTLE_MS = 60 * 1000;

// Carries a "next reschedule must be at least this many ms away" signal
// from inside sendHeartbeat() (rate_limited branch) out to the
// finally-arm reschedule in _heartbeatTick. Without this, _scheduleNextHeartbeat()
// fired from the finally-arm (no arg → default interval) silently overwrites
// any in-body _scheduleNextHeartbeat(backoff) call, and a hub returning a
// large retry_after_ms is effectively ignored. _scheduleNextHeartbeat()
// reads-and-clears this value, so it cannot leak across ticks.
let _pendingRescheduleDelayMs = 0;
// Upper bound on hub-supplied retry_after_ms. A malformed or hostile hub
// response (e.g. retry_after_ms: 86_400_000) must not be able to silence
// the heartbeat for hours. 30 min matches the base reauth backoff -- the
// longest legitimate backoff the client itself ever installs.
const _HEARTBEAT_MAX_RATE_LIMIT_BACKOFF_MS = 30 * 60_000;

// Reauth backoff window (Task #15, port of evolver#544 commit 104cdbd).
// Without this, every 401 from /a2a/heartbeat unconditionally fires
// _sendHelloWithRotate, and with pokeHeartbeat being wired into user-
// activity paths a hub that has genuinely rejected our secret (operator
// "Reset Secret") would see every keystroke trigger another hello+rotate
// attempt -- exhausting the hub's 60/h per-IP hello rate limit in well
// under 30 minutes. The window grows exponentially per consecutive
// failure. Round-9: the BASE was 30min, which on a machine that never
// sleeps turned a transient hub blip into a 30min..4h restart-only
// silence (deepReauthFailure carve-out in pokeHeartbeat + the only
// non-restart clear being a 30-min wall-clock jump that never happens
// awake). BASE is now 2min and the ladder is bounded in practice by the
// re-hello PROBE escape hatch below (_REAUTH_PROBE_INTERVAL_MS), so a
// node re-discovers a hub-side recovery within ~10min without a restart.
// The proxy LifecycleManager (src/proxy/lifecycle/manager.js) still
// carries the old 30min base -- tracked as a parallel follow-up; most
// users hit THIS (non-proxy) path.
const _HEARTBEAT_REAUTH_BACKOFF_BASE_MS = 2 * 60_000;
const _HEARTBEAT_REAUTH_BACKOFF_MAX_MS = 4 * 60 * 60_000;
// Round-9: while a reauth backoff is active, allow ONE low-rate
// unauthenticated re-hello PROBE per this interval, regardless of
// deepReauthFailure. This is the non-sleep escape hatch: pokeHeartbeat
// refuses to clear the backoff for deepReauthFailure (>= 2) and the only
// other auto-clear is a 30-min wall-clock jump, so without a probe a
// never-sleeping node was restart-only. ~6 probes/h max, far under the
// hub's 60/h per-IP hello budget the backoff exists to protect.
const _REAUTH_PROBE_INTERVAL_MS = 10 * 60_000;
// Round-9: a benign 401 (hub has no secret for us yet -- fresh node or
// hb-response-cache race; hub returns node_secret_not_set/required) must
// NOT arm the escalating reauth backoff. On a failed benign re-hello we
// schedule a short retry instead of the 2min..4h ladder. 90s keeps the
// retry cadence (1 heartbeat + 1 hello per tick) safely under BOTH the
// hub's 60/h per-IP hello limit and its 6/300s heartbeat limit even if the
// benign condition persists, so prompt re-registration never tips into
// self-inflicted rate-limiting. (A working hello recovers in ONE tick with
// no wait; this delay only gates the case where the hello ALSO fails.)
const _REAUTH_BENIGN_RETRY_MS = 90 * 1000;
// Wall-clock of the last reauth probe attempt (Round-9 escape hatch).
let _heartbeatLastReauthProbeAt = 0;
// Hard cap on the reauth failure counter. Once it reaches the cap, additional
// failures stop incrementing -- the backoff has already saturated at MAX_MS
// (4h) and further growth only deepens the deepReauthFailure (>= 2) state
// in pokeHeartbeat() from which user activity cannot rescue the loop. Without
// this cap, a flapping hub locks the node into a permanent "user actions do
// nothing" state. log2(4h / 30min) == 3, so the counter reaches max backoff
// at 4; we leave headroom to 6 to keep the cap obviously above the natural
// saturation point.
const _HEARTBEAT_REAUTH_FAILURE_CAP = 6;
// Wall-clock timestamp until which _rotateAndRetryHeartbeat must short-
// circuit. 0 means "not in backoff". Cleared on successful reauth and
// (carefully) by pokeHeartbeat -- see the deep-failure carve-out in
// pokeHeartbeat() for why we cannot blindly wipe it.
let _heartbeatReauthBackoffUntil = 0;
let _heartbeatConsecutiveReauthFailures = 0;

// Round-4 audit: "re-hello cache-poisoning loop" guard. The hub caches the
// /a2a/heartbeat response under c:hb:resp:{nodeId} for 420s (7 min). The
// FIRST non-ok payload (e.g. an unknown_node returned during DB-replication
// lag right after the user's first hello write) gets pinned for the full
// window. While that cache is hot:
//   tick -> heartbeat returns unknown_node -> client calls /a2a/hello ->
//   hello succeeds (no cache there) -> client returns "ok" to the tick loop
//   -> 30s later, next tick -> same cached unknown_node -> hello again -> ...
// At default heartbeat interval the client racks up ~14 hellos in 7 min,
// well over the hub's 60/h per-IP hello rate limit, after which hello fails
// too and the node enters reauth backoff -- locked dead for hours.
//
// Mitigation: count consecutive unknown_node responses where re-hello DID
// succeed. After UNKNOWN_NODE_AFTER_HELLO_THRESHOLD such cycles, install a
// backoff longer than the hub cache TTL so the cache can expire instead of
// being hammered. Reset on first ok heartbeat or on a hub-rejected hello.
let _consecutiveUnknownNodeAfterHello = 0;
const _UNKNOWN_NODE_AFTER_HELLO_THRESHOLD = 2;
const _UNKNOWN_NODE_AFTER_HELLO_BACKOFF_MS = 8 * 60_000;
// Round-5: round-4 set _pendingRescheduleDelayMs when the unknown_node
// loop counter saturated, but that value is read-and-cleared by
// _scheduleNextHeartbeat on the FIRST reschedule and not preserved across
// drift-detector pokes. The drift detector's persistent-failure branch
// (consecutiveFailures > 0 + sinceLastTick > 2*interval) was raised by
// the same unknown_node tick that armed the delay, so the very next
// drift sample 30s later bypassed the 8-min wait via pokeHeartbeat() ->
// setImmediate(_heartbeatTick), hit the same cached unknown_node
// response, incremented the counter again, and the 8-min backoff was
// effectively ignored. Track an absolute deadline so the drift detector
// (and any other poke path) can refuse to bypass the wait until the
// hub-side cache TTL has had a real chance to expire.
let _unknownNodeBackoffUntil = 0;
// Round-5: hello-success margin. After unknown_node -> re-hello succeeds,
// we used to let the default reschedule run at the next heartbeat
// interval (~30s). The hub's response cache for /a2a/heartbeat lives
// 420s, so the next tick almost certainly hits the same cached
// unknown_node and bumps the loop counter. Give DB replication +
// cache expiry at least HEARTBEAT_FIRST_DELAY_MS + a small margin
// before the next attempt so a single transient lag does not snowball
// into the 8-min backoff above.
const _UNKNOWN_NODE_HELLO_RECOVERY_DELAY_MS = 35 * 1000;

// Wall-clock drift detector tunables. See startHeartbeat() for the
// rationale. We sample Date.now() every DRIFT_CHECK_MS; if two samples are
// more than DRIFT_SLEEP_THRESHOLD_MS apart, the process was demonstrably
// suspended (macOS sleep, App Nap, hypervisor pause, debugger break) and
// we fire pokeHeartbeat() so recovery does not have to wait for the next
// natural tick (up to 30 min worst case with exponential backoff).
// Mirrors DRIFT_CHECK_MS / DRIFT_SLEEP_THRESHOLD_MS in
// src/proxy/lifecycle/manager.js (#544).
const DRIFT_CHECK_MS = 30 * 1000;
const DRIFT_SLEEP_THRESHOLD_MS = 90 * 1000;
// Wall-clock jumps above this threshold mean "the device almost certainly
// slept long enough that any hub-side state we cached -- reauth failure
// counter, backoff window, the once-per-process env_fingerprint sent flag --
// is stale". On such a jump we force a fresh reauth attempt + fingerprint
// resend on the next tick. This is the load-bearing fix for the "laptop
// closed overnight, evolver silent forever after wake" failure mode where
// the hub's view of the node changed during sleep but the client kept its
// pre-sleep penalty state.
// Round-9: this used to alias _HEARTBEAT_REAUTH_BACKOFF_BASE_MS. Now that
// the reauth base is 2min, the "long sleep" threshold must stay an
// explicit 30min -- otherwise the drift detector would treat any 2-min
// wall-clock gap as an overnight sleep and wipe reauth/unknown_node/fp
// state on routine timer coalescing.
const DRIFT_LONG_SLEEP_THRESHOLD_MS = 30 * 60_000;
let _heartbeatDriftInterval = null;
let _heartbeatLastDriftCheckAt = 0;
// Round-4: QoS-throttle diagnostic. macOS Sonoma/Sequoia demotes a
// backgrounded process's QoS such that wall-clock advances normally but
// the CPU we are scheduled for collapses (~5% of one core). Comparing the
// cpuUsage delta against the wall-clock delta on each drift sample lets
// us emit an RCA breadcrumb the FIRST time a throttle episode starts,
// instead of waiting for the next user-reported "evolver dead" to
// re-investigate from scratch. Snapshotted at the start of each sample
// and compared on the next.
let _heartbeatLastCpuUsage = null;
let _heartbeatLastDriftWallClock = 0;
let _heartbeatQosThrottleWarnedAt = 0;

// Round-5: shared disk-log writer used by both the heartbeat_ok branch
// (round-4) and the failure / lifecycle paths. Rounds 1-3 had to do
// source-only RCAs because evolver_loop.log stayed at 0 bytes; round-4
// fixed the success path but NOT the failure paths -- so the next
// incident still shows "tail of log = last successful tick, then
// silence", indistinguishable from a process crash. Append a single
// JSON line per event; callers pass {type, ...} and we add ts.
function _appendHeartbeatLog(record) {
  try {
    const logPath = getEvolverLogPath();
    fs.mkdirSync(path.dirname(logPath), { recursive: true });
    const line = JSON.stringify(Object.assign(
      { ts: new Date().toISOString() },
      record || {}
    )) + '\n';
    try {
      fs.appendFileSync(logPath, line, { encoding: 'utf8' });
    } catch (e) {
      if (e && e.code === 'ENOENT') {
        try {
          fs.appendFileSync(logPath, line, { encoding: 'utf8' });
        } catch (_) { /* log destination broken; do not throw out */ }
      }
    }
  } catch (_) { /* never let the log helper escape into the caller */ }
}

function _nodeSecretFile() { return path.join(_nodeIdDir(), 'node_secret'); }
function _nodeSecretVersionFile() { return path.join(_nodeIdDir(), 'node_secret_version'); }
function _nodeSecretSourceFile() { return path.join(_nodeIdDir(), 'node_secret_source'); }
function _nodeSecretEnvSuppressedFile() { return path.join(_nodeIdDir(), 'node_secret_env_suppressed'); }
function _mailboxStateFile() { return getEvomapPath('mailbox', 'state.json'); }

function _parseNodeSecretVersion(value) {
  var n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : null;
}

var _NODE_SECRET_RE = /^[a-f0-9]{64}$/i;
var _NODE_SECRET_SUPPRESSION_RE = /^sha256:[a-f0-9]{64}$/i;

function _isValidNodeSecret(secret) {
  return typeof secret === 'string' && _NODE_SECRET_RE.test(secret);
}

function _fingerprintNodeSecret(secret) {
  if (!_isValidNodeSecret(secret)) return null;
  var normalized = String(secret).trim().toLowerCase();
  return 'sha256:' + crypto.createHash('sha256').update(normalized).digest('hex');
}

function _isTruthyState(value) {
  var v = String(value || '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

function _normalizeNodeSecretEnvSuppressed(value) {
  var raw = String(value || '').trim();
  if (!raw) return null;
  if (_isTruthyState(raw)) return 'true';
  var lower = raw.toLowerCase();
  return _NODE_SECRET_SUPPRESSION_RE.test(lower) ? lower : null;
}

function _normalizeNodeSecretSource(value) {
  var source = String(value || '').trim();
  return source === 'hub_rotate' || source === 'env_seed' ? source : null;
}

function _getEnvNodeSecret() {
  return process.env.A2A_NODE_SECRET || process.env.EVOMAP_NODE_SECRET || null;
}

function _extractNodeSecretVersion(data) {
  return _parseNodeSecretVersion(
    data && data.payload && data.payload.node_secret_version
      ? data.payload.node_secret_version
      : data && data.node_secret_version
  );
}

function _loadPersistedNodeSecret() {
  try {
    const file = _nodeSecretFile();
    if (fs.existsSync(file)) {
      const s = fs.readFileSync(file, 'utf8').trim();
      if (s && _isValidNodeSecret(s)) return s;
    }
  } catch {}
  return null;
}

function _loadMailboxState() {
  const file = _mailboxStateFile();
  const state = readMailboxStateFile(file);
  if (state) return state;
  try {
    if (fs.existsSync(file)) {
      JSON.parse(fs.readFileSync(file, 'utf8'));
    }
  } catch (e) {
    const reason = e && (e.code || e.name) ? (e.code || e.name) : 'error';
    console.warn('[a2aProtocol] Failed to read mailbox node state:', reason);
  }
  return null;
}

function _loadMailboxNodeSecret() {
  const state = _loadMailboxState();
  const secret = state && typeof state.node_secret === 'string'
    ? state.node_secret.trim()
    : null;
  return _isValidNodeSecret(secret) ? secret : null;
}

function _loadMailboxNodeSecretVersion() {
  const state = _loadMailboxState();
  return _parseNodeSecretVersion(state && state.node_secret_version);
}

function _loadMailboxNodeSecretSource() {
  const state = _loadMailboxState();
  return _normalizeNodeSecretSource(state && state.node_secret_source);
}

function _loadMailboxNodeSecretEnvSuppressed() {
  const state = _loadMailboxState();
  return _normalizeNodeSecretEnvSuppressed(state && state.node_secret_env_suppressed);
}

function _nodeSecretTuple(secret, version, source, store) {
  if (!_isValidNodeSecret(secret) || source !== 'hub_rotate') return null;
  return {
    secret: secret,
    version: _parseNodeSecretVersion(version),
    source: source,
    store: store,
  };
}

function _preferNodeSecretTuple(a, b) {
  if (!a) return b;
  if (!b) return a;
  const aVersion = a.version || 0;
  const bVersion = b.version || 0;
  if (aVersion !== bVersion) return aVersion > bVersion ? a : b;
  return a.store === 'mailbox' ? a : b;
}

function _selectHubRotatedNodeSecretTuple(mailboxSecret, mailboxVersion, mailboxSource, persistedSecret, persistedVersion, persistedSource) {
  const mailboxTuple = _nodeSecretTuple(mailboxSecret, mailboxVersion, mailboxSource, 'mailbox');
  const persistedTuple = _nodeSecretTuple(persistedSecret, persistedVersion, persistedSource, 'persisted');
  return _preferNodeSecretTuple(mailboxTuple, persistedTuple);
}

function _syncSelectedHubRotatedNodeSecretTuple(tuple, mailboxSecret, mailboxVersion, mailboxSource, persistedSecret, persistedVersion, persistedSource) {
  if (!tuple || !_isValidNodeSecret(tuple.secret)) return;
  const selectedVersion = tuple.version || null;
  if (
    tuple.store === 'persisted' &&
    (mailboxSecret !== tuple.secret || mailboxVersion !== selectedVersion || mailboxSource !== 'hub_rotate')
  ) {
    _persistMailboxHubNodeSecret(tuple.secret, selectedVersion);
    return;
  }
  if (
    tuple.store === 'mailbox' &&
    (persistedSecret !== tuple.secret || persistedVersion !== selectedVersion || persistedSource !== 'hub_rotate')
  ) {
    _persistNodeSecret(tuple.secret);
    _persistNodeSecretSource('hub_rotate');
    if (selectedVersion) _persistNodeSecretVersion(selectedVersion);
    else _clearNodeSecretVersion();
  }
}

function _writeMailboxState(state, updatedKeys) {
  try {
    const file = _mailboxStateFile();
    writeMergedMailboxStateFile(file, state || {}, updatedKeys);
  } catch (e) {
    const reason = e && (e.code || e.name || e.message) ? (e.code || e.name || e.message) : 'error';
    console.warn('[a2aProtocol] Failed to update mailbox node state:', reason);
  }
}

function _persistMailboxHubNodeSecret(secret, secretVersion) {
  if (!_isValidNodeSecret(secret)) return;
  const state = _loadMailboxState() || {};
  state.node_secret = secret;
  state.node_secret_source = 'hub_rotate';
  const parsedVersion = _parseNodeSecretVersion(secretVersion);
  state.node_secret_version = parsedVersion ? String(parsedVersion) : '';
  const suppression = _normalizeNodeSecretEnvSuppressed(_suppressEnvNodeSecret);
  state.node_secret_env_suppressed = suppression || '';
  _writeMailboxState(state, MAILBOX_NODE_SECRET_STATE_KEYS);
}

function _clearMailboxHubNodeSecret() {
  const state = _loadMailboxState();
  if (!state) return;
  state.node_secret = '';
  state.node_secret_version = '';
  state.node_secret_source = '';
  const suppression = _normalizeNodeSecretEnvSuppressed(_suppressEnvNodeSecret);
  state.node_secret_env_suppressed = suppression || '';
  _writeMailboxState(state, MAILBOX_NODE_SECRET_STATE_KEYS);
}

function _syncMailboxNodeSecretVersionFromHello(secretVersion) {
  const state = _loadMailboxState();
  if (!state) return;
  const secret = state && typeof state.node_secret === 'string'
    ? state.node_secret.trim()
    : null;
  const source = _normalizeNodeSecretSource(state && state.node_secret_source);
  if (!_isValidNodeSecret(secret) || source !== 'hub_rotate') return;
  const parsedVersion = _parseNodeSecretVersion(secretVersion);
  state.node_secret_version = parsedVersion ? String(parsedVersion) : '';
  _writeMailboxState(state, ['node_secret_version']);
}

function _loadPersistedNodeSecretSource() {
  try {
    const file = _nodeSecretSourceFile();
    if (fs.existsSync(file)) {
      return _normalizeNodeSecretSource(fs.readFileSync(file, 'utf8'));
    }
  } catch (e) {
    console.warn('[a2aProtocol] Failed to read node secret source:', e && e.message || e);
  }
  return null;
}

function _loadPersistedNodeSecretEnvSuppressed() {
  try {
    const file = _nodeSecretEnvSuppressedFile();
    if (!fs.existsSync(file)) return null;
    return _normalizeNodeSecretEnvSuppressed(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    console.warn('[a2aProtocol] Failed to read node secret env suppression:', e && e.message || e);
  }
  return null;
}

function _persistNodeSecret(secret) {
  // SECURITY NOTE(windows): mode 0o600 is silently ignored on Windows.
  // The node secret file will NOT be restricted to owner-read-only.
  // On Windows, the file is protected only by the OS user-profile directory
  // permissions (%USERPROFILE%\.evomap). There is no portable equivalent of
  // Unix 0o600 that can be applied via fs.writeFileSync on Windows.
  try {
    const dir = _nodeIdDir();
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
    // Atomic write: a second evolver instance (proxy + ad-hoc CLI, or two
    // daemons started by hand) racing on this path could otherwise leave a
    // half-written file. The loser of the race would then read a truncated
    // secret on next startup and quietly enter 401-loop + reauth backoff.
    // Write to a per-process tmp sibling then renameSync, which is atomic
    // on the same filesystem.
    const target = _nodeSecretFile();
    const tmp = target + '.' + process.pid + '.tmp';
    fs.writeFileSync(tmp, secret, { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(tmp, target);
  } catch (e) {
    console.warn('[a2aProtocol] Failed to persist node secret:', e && e.message || e);
  }
}

function _persistNodeSecretSource(source) {
  const normalized = _normalizeNodeSecretSource(source);
  if (!normalized) return;
  try {
    const dir = _nodeIdDir();
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
    const target = _nodeSecretSourceFile();
    const tmp = target + '.' + process.pid + '.tmp';
    fs.writeFileSync(tmp, normalized, { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(tmp, target);
  } catch (e) {
    console.warn('[a2aProtocol] Failed to persist node secret source:', e && e.message || e);
  }
}

function _persistNodeSecretEnvSuppressed(marker) {
  var normalized = _normalizeNodeSecretEnvSuppressed(marker);
  if (!normalized) return;
  try {
    const dir = _nodeIdDir();
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
    const target = _nodeSecretEnvSuppressedFile();
    const tmp = target + '.' + process.pid + '.tmp';
    fs.writeFileSync(tmp, normalized, { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(tmp, target);
  } catch (e) {
    console.warn('[a2aProtocol] Failed to persist node secret env suppression:', e && e.message || e);
  }
}

function _markCurrentEnvNodeSecretSuppressed() {
  var marker = _fingerprintNodeSecret(_getEnvNodeSecret());
  if (!marker) {
    _suppressEnvNodeSecret = false;
    _clearNodeSecretEnvSuppressed();
    return;
  }
  _suppressEnvNodeSecret = marker;
  _persistNodeSecretEnvSuppressed(marker);
}

function _resolveEnvNodeSecretSuppression(envSecret) {
  var marker = _normalizeNodeSecretEnvSuppressed(_suppressEnvNodeSecret) ||
    _loadPersistedNodeSecretEnvSuppressed() ||
    _loadMailboxNodeSecretEnvSuppressed();
  if (!marker) {
    _suppressEnvNodeSecret = false;
    return { suppressed: false, changed: false };
  }
  _suppressEnvNodeSecret = marker;
  if (marker === 'true') {
    return { suppressed: Boolean(envSecret), changed: false };
  }
  var envFingerprint = _fingerprintNodeSecret(envSecret);
  if (!envFingerprint) {
    return { suppressed: false, changed: false };
  }
  if (envFingerprint === marker) {
    return { suppressed: true, changed: false };
  }
  _suppressEnvNodeSecret = false;
  _clearNodeSecretEnvSuppressed();
  return { suppressed: false, changed: true };
}

function _syncEnvNodeSecretToPersisted(secret) {
  if (!_isValidNodeSecret(String(secret || ''))) return;
  _persistNodeSecret(secret);
  const envVersion = _parseNodeSecretVersion(process.env.A2A_NODE_SECRET_VERSION || process.env.EVOMAP_NODE_SECRET_VERSION);
  if (envVersion) {
    _cachedHubNodeSecretVersion = envVersion;
    _cachedHubNodeSecretVersionAt = Date.now();
    _persistNodeSecretVersion(envVersion);
  } else {
    _clearNodeSecretVersion();
  }
  _persistNodeSecretSource('env_seed');
  _clearNodeSecretEnvSuppressed();
}

function _loadPersistedNodeSecretVersion() {
  try {
    const file = _nodeSecretVersionFile();
    if (fs.existsSync(file)) {
      const version = _parseNodeSecretVersion(fs.readFileSync(file, 'utf8').trim());
      if (version) return version;
    }
  } catch {}
  return null;
}

function _persistNodeSecretVersion(version) {
  const parsed = _parseNodeSecretVersion(version);
  if (!parsed) return;
  try {
    const dir = _nodeIdDir();
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
    const target = _nodeSecretVersionFile();
    const tmp = target + '.' + process.pid + '.tmp';
    fs.writeFileSync(tmp, String(parsed), { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(tmp, target);
  } catch (e) {
    console.warn('[a2aProtocol] Failed to persist node secret version:', e && e.message || e);
  }
}

function _clearNodeSecretVersion() {
  _cachedHubNodeSecretVersion = null;
  _cachedHubNodeSecretVersionAt = 0;
  try {
    if (fs.existsSync(_nodeSecretVersionFile())) fs.unlinkSync(_nodeSecretVersionFile());
  } catch (e) {
    console.warn('[a2aProtocol] Failed to clear node secret version:', e && e.message || e);
  }
}

function _clearNodeSecretSource() {
  try {
    if (fs.existsSync(_nodeSecretSourceFile())) fs.unlinkSync(_nodeSecretSourceFile());
  } catch (e) {
    console.warn('[a2aProtocol] Failed to clear node secret source:', e && e.message || e);
  }
}

function _clearNodeSecretEnvSuppressed() {
  try {
    if (fs.existsSync(_nodeSecretEnvSuppressedFile())) fs.unlinkSync(_nodeSecretEnvSuppressedFile());
  } catch (e) {
    console.warn('[a2aProtocol] Failed to clear node secret env suppression:', e && e.message || e);
  }
}

function _secretDivergenceReason(reason) {
  var r = String(reason || '').toLowerCase();
  if (!r) return '';
  if (r.indexOf('node_secret_invalid') !== -1) return 'node_secret_invalid';
  if (r.indexOf('rotation_requires_current_secret') !== -1) return 'rotation_requires_current_secret';
  if (r.indexOf('invalid_secret') !== -1) return 'invalid_secret';
  return '';
}

function _benignNoSecretHeartbeatAuthError(status, reason) {
  if (status !== 401) return false;
  var r = String(reason || '').toLowerCase();
  return r === 'node_secret_not_set' || r === 'node_secret_required';
}

function _hubErrorReasonFromText(text) {
  try {
    var parsed = JSON.parse(text || '{}');
    var payload = parsed && parsed.payload && typeof parsed.payload === 'object' ? parsed.payload : null;
    return String(
      (payload && (payload.error || payload.reason)) ||
      (parsed && (parsed.error || parsed.reason)) ||
      ''
    ).toLowerCase();
  } catch (_) {
    return '';
  }
}

function _clearDivergedHubNodeSecret(reason) {
  _cachedHubNodeSecret = null;
  _cachedHubNodeSecretAt = 0;
  _cachedHubNodeSecretVersion = null;
  _cachedHubNodeSecretVersionAt = 0;
  _markCurrentEnvNodeSecretSuppressed();
  _clearMailboxHubNodeSecret();
  try {
    if (fs.existsSync(_nodeSecretFile())) fs.unlinkSync(_nodeSecretFile());
  } catch (e) {
    console.warn('[a2aProtocol] Failed to unlink diverged node_secret file: ' + (e && e.message || e));
  }
  _clearNodeSecretVersion();
  _clearNodeSecretSource();
  console.warn('[a2aProtocol] Hub rejected local node secret (reason=' +
    (reason || 'unknown') + '); cleared local secret to allow unauthenticated re-hello on next tick.');
  return { ok: false, error: 'secret_diverged_cleared' };
}

function _syncNodeSecretVersionFromHello(secretVersion) {
  if (secretVersion) {
    _cachedHubNodeSecretVersion = secretVersion;
    _cachedHubNodeSecretVersionAt = Date.now();
    _persistNodeSecretVersion(secretVersion);
    _syncMailboxNodeSecretVersionFromHello(secretVersion);
    return;
  }
  _clearNodeSecretVersion();
  _syncMailboxNodeSecretVersionFromHello(null);
}

function _storeHubRotatedNodeSecret(secret, secretVersion) {
  _cachedHubNodeSecret = secret;
  _cachedHubNodeSecretAt = Date.now();
  _persistNodeSecret(secret);
  _persistNodeSecretSource('hub_rotate');
  if (_getEnvNodeSecret() && _getEnvNodeSecret() !== secret) {
    _markCurrentEnvNodeSecretSuppressed();
  } else {
    _suppressEnvNodeSecret = false;
    _clearNodeSecretEnvSuppressed();
  }
  _syncNodeSecretVersionFromHello(secretVersion);
  _persistMailboxHubNodeSecret(secret, secretVersion);
}

function getHubUrl() {
  // Trim and fall through on empty/whitespace-only. A trailing space in the
  // env value survives `hubUrl.replace(/\/+$/, '')` at every endpoint
  // construction site and yields "https://evomap.ai /a2a/..." which fails
  // hubFetch's URL validation (#580 Bug 1). Trimming once here keeps every
  // consumer (hello / heartbeat / events-poll / fetch / publish) clean.
  const a = (process.env.A2A_HUB_URL || '').trim();
  const b = (process.env.EVOMAP_HUB_URL || '').trim();
  return a || b || '';
}

function buildHubHeaders() {
  const headers = { 'Content-Type': 'application/json' };
  // User-scoped Hub APIs prefer a valid OAuth device token from `evolver login`.
  // Node-scoped A2A APIs must call buildNodeScopedHubHeaders() instead.
  let bearer = null;
  try { bearer = require('./oauthLogin').loadValidAccessToken(); } catch {}
  if (!bearer) bearer = getHubNodeSecret();
  if (bearer) headers['Authorization'] = 'Bearer ' + bearer;
  var secretVersion = getHubNodeSecretVersion();
  if (secretVersion) headers['X-EvoMap-Node-Secret-Version'] = String(secretVersion);
  headers['x-correlation-id'] = crypto.randomUUID();
  return headers;
}

function buildNodeScopedHubHeaders() {
  const headers = { 'Content-Type': 'application/json' };
  const bearer = getHubNodeSecret();
  if (bearer) headers['Authorization'] = 'Bearer ' + bearer;
  const secretVersion = getHubNodeSecretVersion();
  if (secretVersion) headers['X-EvoMap-Node-Secret-Version'] = String(secretVersion);
  headers['x-correlation-id'] = crypto.randomUUID();
  return headers;
}

function sendHelloToHub() {
  if (_isDryRun()) return Promise.resolve({ ok: true, dry_run: true });
  const hubUrl = getHubUrl();
  if (!hubUrl) return Promise.resolve({ ok: false, error: 'no_hub_url' });

  const endpoint = hubUrl.replace(/\/+$/, '') + '/a2a/hello';
  const nodeId = getNodeId();
  const agentName = (process.env.EVOLVER_AGENT_NAME || process.env.EVOLVER_MODEL_NAME || '').trim().slice(0, 32) || undefined;
  const msg = buildHello({ nodeId: nodeId, capabilities: {}, name: agentName });
  msg.sender_id = nodeId;

  return hubFetch(endpoint, {
    method: 'POST',
    headers: buildNodeScopedHubHeaders(),
    body: JSON.stringify(msg),
    signal: AbortSignal.timeout(require('../config').HELLO_TIMEOUT_MS),
  })
    .then(function (res) {
      if (!res.ok) {
        return res.text().then(function (t) {
          console.warn('[Hello] Hub returned ' + res.status + ': ' + sanitizeHubResponseForLog(t));
          return { ok: false, error: 'http_' + res.status };
        });
      }
      return res.json();
    })
    .then(function (data) {
      if (data && data.ok === false) return data;
      const secret = (data && data.payload && data.payload.node_secret)
        || (data && data.node_secret)
        || null;
      const secretVersion = _extractNodeSecretVersion(data);
      if (secret && _isValidNodeSecret(secret)) {
        _storeHubRotatedNodeSecret(secret, secretVersion);
      } else {
        if (!getHubNodeSecret()) {
          _clearNodeSecretVersion();
          console.log('[Hello] No local secret after hello; auto-rotating...');
          return _sendHelloWithRotate();
        }
        _syncNodeSecretVersionFromHello(secretVersion);
      }
      try {
        const { maybePrintClaimNudge } = require('./claimNudge');
        const payload = (data && data.payload) || data || {};
        maybePrintClaimNudge(payload);
      } catch (_) {
        // claim nudge is best-effort; never break hello on print failure
      }
      return { ok: true, response: data };
    })
    .catch(function (err) { return { ok: false, error: err.message }; });
}

function getHubNodeSecret() {
  const rawEnvSecret = _getEnvNodeSecret();
  const suppression = _resolveEnvNodeSecretSuppression(rawEnvSecret);
  const envSecret = suppression.suppressed ? null : rawEnvSecret;
  const mailbox = _loadMailboxNodeSecret();
  const mailboxVersion = _loadMailboxNodeSecretVersion();
  const mailboxSource = mailbox ? _loadMailboxNodeSecretSource() : null;
  const persisted = _loadPersistedNodeSecret();
  const persistedVersion = _loadPersistedNodeSecretVersion();
  const persistedSource = persisted ? _loadPersistedNodeSecretSource() : null;
  const rotatedTuple = _selectHubRotatedNodeSecretTuple(mailbox, mailboxVersion, mailboxSource, persisted, persistedVersion, persistedSource);
  const rotated = rotatedTuple ? rotatedTuple.secret : null;
  if (envSecret && rotated && envSecret !== rotated && !suppression.changed) {
    _syncSelectedHubRotatedNodeSecretTuple(rotatedTuple, mailbox, mailboxVersion, mailboxSource, persisted, persistedVersion, persistedSource);
    _cachedHubNodeSecret = rotated;
    _cachedHubNodeSecretAt = Date.now();
    return rotated;
  }
  if (envSecret && suppression.changed && _isValidNodeSecret(envSecret) && (!persisted || envSecret === persisted)) {
    if (!(persisted && envSecret === persisted && persistedSource === 'hub_rotate')) {
      _syncEnvNodeSecretToPersisted(envSecret);
    }
  }
  if (envSecret && mailbox && envSecret !== mailbox) {
    if (mailboxSource === 'hub_rotate' && !suppression.changed) {
      _cachedHubNodeSecret = mailbox;
      _cachedHubNodeSecretAt = Date.now();
      return mailbox;
    }
    if (_isValidNodeSecret(envSecret)) {
      _syncEnvNodeSecretToPersisted(envSecret);
    }
  }
  if (envSecret && persisted && envSecret !== persisted) {
    if (persistedSource === 'hub_rotate' && !suppression.changed) {
      _cachedHubNodeSecret = persisted;
      _cachedHubNodeSecretAt = Date.now();
      return persisted;
    }
    _syncEnvNodeSecretToPersisted(envSecret);
  }
  if (envSecret) {
    return envSecret;
  }
  const now = Date.now();
  if (rotatedTuple) {
    _syncSelectedHubRotatedNodeSecretTuple(rotatedTuple, mailbox, mailboxVersion, mailboxSource, persisted, persistedVersion, persistedSource);
    _cachedHubNodeSecret = rotated;
    _cachedHubNodeSecretAt = now;
    return rotated;
  }
  if (_cachedHubNodeSecret && (now - _cachedHubNodeSecretAt) < _SECRET_CACHE_TTL_MS) {
    return _cachedHubNodeSecret;
  }
  if (mailbox) {
    _cachedHubNodeSecret = mailbox;
    _cachedHubNodeSecretAt = now;
    return mailbox;
  }
  if (persisted) {
    _cachedHubNodeSecret = persisted;
    _cachedHubNodeSecretAt = now;
    return persisted;
  }
  if (process.env.A2A_HUB_TOKEN) return process.env.A2A_HUB_TOKEN;
  return null;
}

function getHubNodeSecretVersion() {
  const activeSecret = getHubNodeSecret();
  if (!activeSecret) return null;
  const envVersion = _parseNodeSecretVersion(process.env.A2A_NODE_SECRET_VERSION || process.env.EVOMAP_NODE_SECRET_VERSION);
  const rawEnvSecret = _getEnvNodeSecret();
  const suppression = _resolveEnvNodeSecretSuppression(rawEnvSecret);
  const envSecret = suppression.suppressed ? null : rawEnvSecret;
  const mailboxSecret = _loadMailboxNodeSecret();
  const mailboxVersion = _loadMailboxNodeSecretVersion();
  const mailboxSource = _loadMailboxNodeSecretSource();
  const persistedSecret = _loadPersistedNodeSecret();
  const persistedVersion = _loadPersistedNodeSecretVersion();
  const persistedSource = _loadPersistedNodeSecretSource();
  const rotatedTuple = _selectHubRotatedNodeSecretTuple(mailboxSecret, mailboxVersion, mailboxSource, persistedSecret, persistedVersion, persistedSource);
  if (rotatedTuple && rotatedTuple.secret === activeSecret) {
    _syncSelectedHubRotatedNodeSecretTuple(rotatedTuple, mailboxSecret, mailboxVersion, mailboxSource, persistedSecret, persistedVersion, persistedSource);
    if (rotatedTuple.version) {
      _cachedHubNodeSecretVersion = rotatedTuple.version;
      _cachedHubNodeSecretVersionAt = Date.now();
      return rotatedTuple.version;
    }
    return null;
  }
  if (envSecret && suppression.changed && _isValidNodeSecret(envSecret)) {
    if (!(persistedSecret && envSecret === persistedSecret && persistedSource === 'hub_rotate')) {
      _syncEnvNodeSecretToPersisted(envSecret);
    }
  }
  if (persistedSource === 'hub_rotate' && persistedSecret === activeSecret && (!suppression.changed || envSecret === persistedSecret)) {
    if (persistedVersion) {
      _cachedHubNodeSecretVersion = persistedVersion;
      _cachedHubNodeSecretVersionAt = Date.now();
      return persistedVersion;
    }
    return null;
  }
  if (envSecret && envSecret === activeSecret) {
    if (envVersion) return envVersion;
    if (mailboxSecret === envSecret && mailboxVersion) return mailboxVersion;
    if (!persistedSecret || persistedSecret !== envSecret) return null;
  }
  const now = Date.now();
  if (_cachedHubNodeSecretVersion && (now - _cachedHubNodeSecretVersionAt) < _SECRET_CACHE_TTL_MS) {
    return _cachedHubNodeSecretVersion;
  }
  if (!envSecret && !persistedSecret && !mailboxSecret && !_cachedHubNodeSecret) return null;
  if (mailboxSecret === activeSecret && mailboxVersion) {
    _cachedHubNodeSecretVersion = mailboxVersion;
    _cachedHubNodeSecretVersionAt = now;
    return mailboxVersion;
  }
  if (persistedVersion && persistedSecret === activeSecret) {
    _cachedHubNodeSecretVersion = persistedVersion;
    _cachedHubNodeSecretVersionAt = now;
    return persistedVersion;
  }
  return null;
}

let _heartbeatInFlight = false;
// Round-9: monotonic identity for the in-flight tick. Bumped on tick entry
// and on every FORCED clear of the single-flight gate (wake branch,
// hung-tick watchdog, stop/reset) so a superseded tick's late continuation
// can detect it no longer owns the gate and bail instead of double-clearing
// or double-scheduling. See _heartbeatTick().
let _heartbeatTickGeneration = 0;

function mergeAndCap(prev, incoming, cap) {
  var merged = prev.concat(incoming);
  if (merged.length > cap) {
    console.warn('[A2A] accumulation cap reached (' + merged.length + '); dropping ' + (merged.length - cap) + ' oldest entries -- consumer may be stalled');
    return merged.slice(-cap);
  }
  return merged;
}

// Companion to src/proxy/lifecycle/manager.js#startHeartbeatLoop (#544).
// The previous version rescheduled in .then() rather than .finally(): if
// sendHeartbeat() threw synchronously (e.g. getHubUrl()/getNodeId() raising,
// JSON.stringify on a poisoned commitment_updates payload, a require()
// inside the body failing) the .catch never fired, .then never ran, the
// reschedule was skipped and _heartbeatInFlight stayed true forever --
// silently killing the loop for the rest of the process. We now wrap the
// whole tick in try/finally so the reschedule is the load-bearing
// invariant: no failure path inside the try (including the catch arm) can
// drop us out of the loop.
// Lower bound on the next-tick delay. Without this floor, a misconfigured
// HEARTBEAT_INTERVAL_MS=0 (or NaN-coerced-to-0, or hub-supplied
// retry_after_ms=0) would schedule setTimeout(..., 0), turning the
// heartbeat into an event-loop-saturating hot spin that burns CPU and
// trips the hub's 6/300s per-sender rate limit within seconds. The floor
// is well below any legitimate interval (default 6 min, minimum
// reasonable ~5 s) so it only kicks in on misconfiguration.
const _HEARTBEAT_MIN_SCHEDULE_DELAY_MS = 1000;

function _scheduleNextHeartbeat(delayMs) {
  if (!_heartbeatRunning) return;
  if (_heartbeatTimer) clearTimeout(_heartbeatTimer);
  // Treat 0 as an explicit "schedule promptly" caller intent (the
  // hung-tick watchdog uses _scheduleNextHeartbeat(0) to recover from a
  // wedged tick). A plain `delayMs || _heartbeatIntervalMs` coerces 0 to
  // the full default interval (~6min), delaying recovery and bypassing
  // the floor below. Use an explicit numeric/non-negative check so the
  // floor (1000ms) can do its job for the watchdog's force-reschedule.
  const requested = (typeof delayMs === 'number' && delayMs >= 0) ? delayMs : _heartbeatIntervalMs;
  // Honor any pending backoff signal from this tick's body (rate_limited
  // branch in sendHeartbeat sets _pendingRescheduleDelayMs). The larger
  // of the two wins so the finally-arm reschedule cannot stomp the
  // hub-supplied backoff with the default interval. Read-and-clear so
  // the signal cannot leak into the next tick.
  const pending = _pendingRescheduleDelayMs || 0;
  _pendingRescheduleDelayMs = 0;
  let delay = pending > requested ? pending : requested;
  // Floor against misconfiguration (interval=0, NaN-coerced, negative,
  // or hub retry_after_ms=0). setTimeout clamps negative/zero to 1ms
  // which becomes an effectively-immediate hot loop.
  if (!(delay >= _HEARTBEAT_MIN_SCHEDULE_DELAY_MS)) {
    delay = _HEARTBEAT_MIN_SCHEDULE_DELAY_MS;
  }
  _heartbeatTimer = setTimeout(_heartbeatTick, delay);
  if (_heartbeatTimer.unref) _heartbeatTimer.unref();
}

function _heartbeatTick() {
  if (!_heartbeatRunning) return;
  // Single-flight gate. Prevents pokeHeartbeat() (or any other re-entry)
  // from starting a parallel tick while one is mid-await. Two ticks
  // running concurrently would each schedule a setTimeout at the end and
  // the earlier timer reference would be leaked (and still fire later,
  // fanning out into more parallel ticks).
  if (_heartbeatInFlight) return;
  _heartbeatInFlight = true;
  // Round-9: tag this tick with a generation. If a watchdog or the wake
  // branch force-clears the single-flight gate (because this tick wedged
  // through sleep or hung on a NAT-dead socket) and adopts a NEW tick, it
  // bumps _heartbeatTickGeneration. When this now-orphaned tick's
  // continuation finally resolves it must NOT clear the gate the new tick
  // owns, nor schedule a second timer -- that double-schedule was the
  // round-9 single-flight race. It checks its captured generation and
  // bails if a newer tick (or a stop/reset) has superseded it.
  var myGen = ++_heartbeatTickGeneration;
  _heartbeatLastTickAt = Date.now();

  // We must derive `p` defensively: if sendHeartbeat itself throws
  // synchronously (not just rejects), we still need to enter the
  // .finally() path to reschedule. Wrap the call so a sync throw becomes
  // a rejected promise.
  let p;
  try {
    p = sendHeartbeat();
    // sendHeartbeat is documented to return a Promise, but defend against
    // a future refactor that returns a non-thenable.
    if (!p || typeof p.then !== 'function') {
      p = Promise.resolve(p);
    }
  } catch (err) {
    p = Promise.reject(err);
  }

  p.catch(function (err) {
    // Defence in depth. sendHeartbeat() already catches its own errors and
    // resolves with { ok: false }, but a future change that lets one slip
    // through must NOT silently kill the loop. Wrap the logger call too:
    // if the logger transport itself throws, we must not let it escape
    // and skip the reschedule in finally.
    try {
      console.warn('[Heartbeat] Scheduled heartbeat threw unexpectedly:', err && err.message || err);
    } catch (_logErr) { /* logger blew up; loop must still survive */ }
  }).then(function () {
    // Reschedule lives here (the equivalent of finally for then/catch
    // chains -- this .then runs whether the previous catch resolved
    // cleanly or itself rejected, because we did not return from the
    // .catch). This is the load-bearing invariant of issue #544: if this
    // line is ever skipped, the node goes silent until process restart.
    // Round-9: but if a watchdog/wake/stop superseded this tick, the gate
    // and the next timer now belong to a newer tick -- bail so we do not
    // double-clear or double-schedule.
    if (myGen !== _heartbeatTickGeneration) return;
    _heartbeatInFlight = false;
    if (_heartbeatRunning) _scheduleNextHeartbeat();
  }, function () {
    // Backstop: even if the .catch arm above somehow throws (e.g. console
    // transport is broken and re-throws after the try/catch), still
    // reschedule. This is paranoid but cheap.
    if (myGen !== _heartbeatTickGeneration) return;
    _heartbeatInFlight = false;
    if (_heartbeatRunning) _scheduleNextHeartbeat();
  });
}

/**
 * Wake the heartbeat loop immediately. Clears accumulated consecutive
 * failure state so subsequent failures start counting fresh, then fires
 * one tick right away if conditions allow.
 *
 * Mirrors LifecycleManager.pokeHeartbeat() in src/proxy/lifecycle/manager.js
 * for the default (non-proxy) code path. Most users do not set
 * EVOMAP_PROXY=1 and therefore reach this module's heartbeat loop, not
 * the LifecycleManager one -- the public manager.js fix from #544 did
 * not cover them.
 *
 * Throttling rules (matches manager.js):
 *   - Returns false if the loop isn't running.
 *   - Returns true (no new tick) if a tick is already in flight -- that
 *     IS the liveness proof we wanted.
 *   - For a HEALTHY node (no consecutive failures, no active reauth
 *     backoff), the call is debounced to one tick per
 *     _HEARTBEAT_POKE_THROTTLE_MS so user-activity-driven pokes cannot
 *     bypass the hub's 6/300s per-sender heartbeat rate limit.
 *   - A node with a transient failure streak (consecutiveFailures > 0,
 *     OR _heartbeatConsecutiveReauthFailures < 2 with active reauth
 *     backoff) bypasses the throttle so recovery is never blocked.
 *   - A node DEEP in a reauth-failure streak (>= 2 consecutive reauth
 *     failures) still respects the throttle AND keeps its
 *     _heartbeatReauthBackoffUntil intact. See below.
 *
 * Reauth backoff handling (Task #15, port of evolver#544 commit 104cdbd):
 *   pokeHeartbeat is being wired into user-activity hot paths. If the hub
 *   has genuinely invalidated the secret, every poke would otherwise wipe
 *   the 30-min _heartbeatReauthBackoffUntil that _rotateAndRetryHeartbeat
 *   just installed -> next user action would trigger another reauth
 *   attempt -> the hub's per-IP hello rate limit would be exhausted in
 *   well under 30 minutes of typing. We gate the clear on
 *   _heartbeatConsecutiveReauthFailures < 2:
 *     - 1st failure: still let user activity drive a retry. The backoff
 *       was probably set against a transient hub blip and a fresh attempt
 *       is cheap.
 *     - >= 2 failures: the hub is genuinely-rejecting; the backoff is
 *       doing real work and user activity must not wipe it. Deep-failure
 *       nodes also respect the 60s throttle so they cannot spam either.
 *
 * @returns {boolean} true if a tick is in flight or was kicked off.
 */
function pokeHeartbeat() {
  if (!_heartbeatRunning) return false;

  // Deep-failure nodes (>= 2 consecutive reauth failures) keep their
  // backoff intact and respect the throttle. wasFailing semantics here
  // mean "this poke is allowed to bypass the debounce", NOT "we cleared
  // backoff state". The loop-level _heartbeatConsecutiveFailures counter
  // is cleared below ONLY when we are actually going to drive a new tick,
  // not when we early-return because a tick is already in flight: an
  // in-flight tick has not yet produced its result, so the failures it is
  // about to surface must still be visible to the drift detector's
  // persistent-failure branch (which gates on
  // _heartbeatConsecutiveFailures > 0). Clearing here unconditionally
  // would let v2 drift recovery silently miss its window.
  const deepReauthFailure = _heartbeatConsecutiveReauthFailures >= 2;
  const reauthBackoffActive = _heartbeatReauthBackoffUntil > Date.now();
  const wasFailing =
    _heartbeatConsecutiveFailures > 0 || (reauthBackoffActive && !deepReauthFailure);

  if (_heartbeatInFlight) return true;

  // Round-6 (§19.1): respect the unknown_node cache-poisoning deadline.
  // Round-5 installed _unknownNodeBackoffUntil so the drift detector's
  // persistent-failure branch would not bypass the 8-min wait, but
  // pokeHeartbeat() itself was left unchecked. Any external poke during
  // the backoff window (user activity, SIGCONT, SSE-message arrival,
  // ad-hoc supervisor wake) would call setImmediate(_heartbeatTick),
  // the next tick hit the still-hot hub cache, the counter incremented
  // toward the 60/h hello rate limit, and the node landed in the deep
  // 30 min..4 h reauth backoff. The gate was one-sided; this closes it.
  // Round-9 note: we deliberately do NOT add a user-activity probe here.
  // Unlike the reauth deep-lockout (which was permanent until restart and
  // now has an escape hatch in _rotateAndRetryHeartbeat), the unknown_node
  // backoff already SELF-recovers: it is sized (8min) just past the hub's
  // 420s response-cache TTL so a single wait outlasts the poison, and 8min
  // stays under the hub's 15min online threshold so one episode never marks
  // the node offline. A probe could only catch the ~7-8min sliver where the
  // cache expired early, at the cost of weakening the 60/h hub protection
  // this gate exists to provide. The real fix is hub-side skipCacheIf
  // (see claude-heartbeat-resilience-followups.md §23).
  if (_unknownNodeBackoffUntil > Date.now()) return false;

  // Round-7 (§20.4): healthy-node throttle check goes BEFORE any state
  // mutation. The pre-round-7 order cleared _heartbeatReauthBackoffUntil
  // (and _heartbeatConsecutiveFailures) and only then checked the 60s
  // throttle -- so a user-activity poke from a healthy-ish node could
  // wipe an active 30 min reauth backoff without firing any tick. The
  // throttle gate returned false and the next reauth attempt happened
  // earlier than the backoff intended, defeating the rate-limit
  // protection the backoff exists to provide. Move the throttle gate
  // first; only mutate after we are committed to scheduling a tick.
  if (!wasFailing) {
    const sinceLast = Date.now() - (_heartbeatLastTickAt || 0);
    if (_heartbeatLastTickAt && sinceLast < _HEARTBEAT_POKE_THROTTLE_MS) return false;
  }

  // Committed to driving a fresh tick: NOW it is safe to clear the
  // consecutive-failure counter and (for non-deep-failure nodes) the
  // reauth backoff window. The previous order mutated before the in-
  // flight check, which let an in-flight tick wipe the counter without
  // contributing a result and broke the drift detector's persistent-
  // failure branch.
  _heartbeatConsecutiveFailures = 0;
  if (!deepReauthFailure) {
    _heartbeatReauthBackoffUntil = 0;
  }

  if (_heartbeatTimer) {
    clearTimeout(_heartbeatTimer);
    _heartbeatTimer = null;
  }
  // Fire on next tick rather than inline so a synchronous caller of
  // pokeHeartbeat() (e.g. an HTTP middleware on the hot path) is not
  // blocked by the heartbeat body.
  setImmediate(_heartbeatTick);
  return true;
}

// Round-9: +/-20% jitter so a fleet that armed the same backoff at the
// same instant (e.g. a hub blip seen by every node) does not re-probe in
// lockstep and re-create the rate-limit storm the backoff exists to avoid.
function _withReauthJitter(ms) {
  var factor = 0.8 + (Math.random() * 0.4);
  return Math.round(ms * factor);
}

function _refreshHeartbeatSecretVersionForRetry(body) {
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch (_) {
    return body;
  }
  if (!parsed || typeof parsed !== 'object') return body;
  const nodeSecretVersion = getHubNodeSecretVersion();
  if (nodeSecretVersion) {
    parsed.node_secret_version = nodeSecretVersion;
    if (!parsed.meta || typeof parsed.meta !== 'object' || Array.isArray(parsed.meta)) parsed.meta = {};
    parsed.meta.node_secret_version = nodeSecretVersion;
  } else {
    delete parsed.node_secret_version;
    if (parsed.meta && typeof parsed.meta === 'object') delete parsed.meta.node_secret_version;
  }
  return JSON.stringify(parsed);
}

function _rotateAndRetryHeartbeat(endpoint, body, opts) {
  opts = opts || {};
  // benign === a hub 401 (node_secret_not_set / node_secret_required): the
  // hub simply has no secret for us yet (fresh node, or the hb-response
  // cache / first-launch race). This is NOT a genuine rejection and must
  // never arm the escalating reauth backoff -- doing so was the round-9
  // idle-death. A genuine 403 mismatch (operator "Reset Secret") still
  // takes the escalating path below.
  var benign = !!opts.benign;
  var heartbeatDivergenceReason = _secretDivergenceReason(opts.secretDivergenceReason);

  // Hot-loop guard (Task #15, port of evolver#544 commit 104cdbd). When a
  // hub has genuinely rejected our secret, every 401 would otherwise trigger
  // another hello+rotate -- and with pokeHeartbeat wired into user-activity
  // paths, that means every keystroke fires a /a2a/hello. The hub's per-IP
  // 60/h hello rate limit would be exhausted quickly. The backoff window is
  // set on consecutive genuine failure (2min base, x2 per failure, 4h cap)
  // and cleared on success below.
  var isProbe = false;
  if (_heartbeatReauthBackoffUntil > Date.now()) {
    // Round-9 ESCAPE HATCH: even while backed off, allow ONE low-rate
    // re-hello PROBE per _REAUTH_PROBE_INTERVAL_MS, regardless of
    // deepReauthFailure. Without it a node that hit deepReauthFailure (>= 2)
    // on a machine that never sleeps was restart-only: pokeHeartbeat refuses
    // to clear the backoff for deep failures, and the only other auto-clear
    // is a 30-min wall-clock jump that never happens awake. The probe is
    // throttled far under the hub's 60/h per-IP hello budget.
    var nowB = Date.now();
    if ((nowB - (_heartbeatLastReauthProbeAt || 0)) < _REAUTH_PROBE_INTERVAL_MS) {
      var waitSec = Math.ceil((_heartbeatReauthBackoffUntil - nowB) / 1000);
      try {
        console.warn(
          '[Heartbeat] re-auth suppressed: backoff active for ' + waitSec + 's ' +
          '(failure #' + _heartbeatConsecutiveReauthFailures + ')'
        );
      } catch (_) { /* logger broken; backoff still in effect */ }
      // Write a log entry so lifecycle.checkHealth() (gated on log mtime vs
      // MAX_SILENCE_MS = 30 min) never falsely declares the process stagnant
      // during a reauth backoff window (which can be up to 4 hours).
      // Without this write, 30 min of backoff silence → stagnation kill →
      // restart → new reauth cycle: the "idle-death" loop.
      _appendHeartbeatLog({
        type: 'heartbeat_reauth_suppressed',
        waitSec: waitSec,
        consecutiveReauthFailures: _heartbeatConsecutiveReauthFailures,
      });
      return Promise.resolve({ ok: false, error: 'reauth_backoff_active' });
    }
    isProbe = true;
    _heartbeatLastReauthProbeAt = nowB;
    try {
      console.warn('[Heartbeat] re-auth backoff active; probe window elapsed, attempting one re-hello probe');
    } catch (_) { /* logger broken; probe still proceeds */ }
  }

  return _sendHelloWithRotate().then(function (helloResult) {
    if (!helloResult.ok) {
      // Secret-divergence carve-out: the secret was cleared (in-memory +
      // on-disk) inside _sendHelloWithRotate. The next tick will send an
      // unauthenticated hello which the hub treats as a fresh registration
      // and returns a new secret. Arming the reauth backoff here would
      // block that natural recovery, so we skip it and surface the signal
      // so the caller's .then can also avoid resetting
      // _heartbeatConsecutiveFailures.
      if (helloResult.error === 'secret_diverged_cleared') {
        return { ok: false, error: 'secret_diverged_cleared' };
      }
      if (heartbeatDivergenceReason) {
        return _clearDivergedHubNodeSecret(heartbeatDivergenceReason);
      }
      // A failed PROBE (we were already backed off) must NOT extend the
      // window or bump the counter -- that would only push toward MAX_MS
      // faster and defeat the escape hatch. Keep the existing backoff and
      // wait for the next probe window.
      if (isProbe) {
        return { ok: false, error: 'reauth_backoff_active' };
      }
      // Benign no-secret race (hub 401): short retry instead of the
      // escalating ladder, and never touch the reauth counter/backoff.
      if (benign) {
        _pendingRescheduleDelayMs = Math.max(_pendingRescheduleDelayMs || 0, _REAUTH_BENIGN_RETRY_MS);
        try {
          console.warn(
            '[Heartbeat] benign no-secret re-hello failed; short retry in ' +
            Math.round(_REAUTH_BENIGN_RETRY_MS / 1000) + 's (no reauth backoff)'
          );
        } catch (_) { /* logger broken; short retry still scheduled */ }
        _appendHeartbeatLog({ type: 'reauth_benign_retry', rescheduleInMs: _REAUTH_BENIGN_RETRY_MS });
        return { ok: false, error: 'reauth_benign_retry' };
      }
      // Genuine reauth (403) failed: bump the failure counter and arm an
      // exponential, jittered backoff window. Capped to prevent unbounded
      // growth from a flapping hub; the escape-hatch probe above bounds the
      // worst-case re-discovery regardless of how high the ladder climbs.
      _heartbeatConsecutiveReauthFailures = Math.min(
        _heartbeatConsecutiveReauthFailures + 1,
        _HEARTBEAT_REAUTH_FAILURE_CAP
      );
      const backoffMs = _withReauthJitter(Math.min(
        _HEARTBEAT_REAUTH_BACKOFF_BASE_MS * Math.pow(2, _heartbeatConsecutiveReauthFailures - 1),
        _HEARTBEAT_REAUTH_BACKOFF_MAX_MS
      ));
      _heartbeatReauthBackoffUntil = Date.now() + backoffMs;
      try {
        console.error(
          '[Heartbeat] re-auth failed (failure #' + _heartbeatConsecutiveReauthFailures + '), ' +
          'backing off for ' + Math.round(backoffMs / 1000) + 's'
        );
      } catch (_) { /* logger broken; backoff still in effect */ }
      // Round-5: previously the only on-disk evidence of a reauth backoff
      // was the absence of the next heartbeat_ok line. Operators staring
      // at a silent log could not distinguish "process crashed" from
      // "waiting on reauth backoff". Record the deadline so they can.
      _appendHeartbeatLog({
        type: 'reauth_backoff_armed',
        consecutiveReauthFailures: _heartbeatConsecutiveReauthFailures,
        until: new Date(_heartbeatReauthBackoffUntil).toISOString(),
        backoffMs: backoffMs,
      });
      return { ok: false, error: 'reauth_failed: ' + (helloResult.error || 'unknown') };
    }
    const retryBody = _refreshHeartbeatSecretVersionForRetry(body);
    return hubFetch(endpoint, {
      method: 'POST',
      headers: buildNodeScopedHubHeaders(),
      body: retryBody,
      signal: AbortSignal.timeout(require('../config').HEARTBEAT_TIMEOUT_MS),
    }).then(function (retryRes) {
      if (!retryRes.ok) {
        // Hello succeeded but the retried heartbeat still failed.
        // Mirror manager.js: only the hello-arm bumps reauth failures;
        // the heartbeat retry going sideways here is a regular HTTP error
        // and should not arm the reauth backoff.
        return retryRes.text().then(function (t) {
          return { ok: false, error: 'retry_http_' + retryRes.status + ': ' + t };
        });
      }
      // Full success: reset both the failure counter and the backoff window
      // so a future incident starts fresh from the base delay.
      var hadReauthBackoff = _heartbeatReauthBackoffUntil > 0;
      _heartbeatConsecutiveReauthFailures = 0;
      _heartbeatReauthBackoffUntil = 0;
      console.log('[Heartbeat] Re-auth succeeded, heartbeat recovered.');
      // Round-6 (§19.2): the self-driving poll enters 5 min quiet mode
      // while reauth backoff is active; without this re-arm, event
      // delivery is paused for up to 5 min after reauth recovers.
      if (hadReauthBackoff) {
        try { _armSelfDrivingPollFromHeartbeat(); } catch (_) {}
      }
      return retryRes.json();
    });
  }).catch(function (err) {
    return { ok: false, error: 'reauth_error: ' + (err.message || err) };
  });
}

function _sendHelloWithRotate() {
  if (_isDryRun()) return Promise.resolve({ ok: true, dry_run: true });
  var hubUrl = getHubUrl();
  if (!hubUrl) return Promise.resolve({ ok: false, error: 'no_hub_url' });
  var endpoint = hubUrl.replace(/\/+$/, '') + '/a2a/hello';
  var nodeId = getNodeId();
  var agentName = (process.env.EVOLVER_AGENT_NAME || process.env.EVOLVER_MODEL_NAME || '').trim().slice(0, 32) || undefined;
  var msg = buildHello({ nodeId: nodeId, capabilities: {}, name: agentName });
  msg.sender_id = nodeId;
  if (msg.payload) msg.payload.rotate_secret = true;
  else msg.payload = { rotate_secret: true };

  return hubFetch(endpoint, {
    method: 'POST',
    headers: buildNodeScopedHubHeaders(),
    body: JSON.stringify(msg),
    signal: AbortSignal.timeout(require('../config').HELLO_TIMEOUT_MS),
  })
    .then(function (res) {
      // Mirror sendHelloToHub: a hub 5xx with a non-JSON body (e.g. an
      // nginx HTML error page) would otherwise throw a JSON parse error
      // here and mask the real HTTP status. Drain the body via .text() so
      // we don't leak an undrained socket per non-ok response either.
      if (!res.ok) {
        return res.text().then(function (t) {
          console.warn('[a2aProtocol] rotate_secret hello returned ' + res.status + ': ' + sanitizeHubResponseForLog(t, { maxChars: 200 }));
          var reason = _secretDivergenceReason(_hubErrorReasonFromText(t));
          if (reason) return { __secretDiverged: true, reason: reason };
          return { __nonOk: true, status: res.status };
        });
      }
      return res.json();
    })
    .then(function (data) {
      if (data && data.__nonOk) {
        return { ok: false, error: 'http_' + data.status };
      }
      if (data && data.__secretDiverged) {
        return _clearDivergedHubNodeSecret(data.reason);
      }
      var secret = (data && data.payload && data.payload.node_secret) || (data && data.node_secret) || null;
      var secretVersion = _extractNodeSecretVersion(data);
      if (secret && _isValidNodeSecret(secret)) {
        _storeHubRotatedNodeSecret(secret, secretVersion);
        console.log('[a2aProtocol] Secret rotated and stored.');
        return { ok: true, response: data };
      }
      // Secret-divergence recovery. The hub may HTTP-200 with an
      // app-level rejection (status:"rejected", reason:"node_secret_invalid"
      // or "rotation_requires_current_secret") when the locally-cached
      // secret has drifted from the hub's record (e.g. hub-side reset,
      // restored-from-backup laptop, manual unlink). Treating this as a
      // generic "no_secret_in_response" arms the 30min..4h reauth backoff
      // even though a fresh unauthenticated hello on the next tick would
      // recover us. Clear the diverged secret (in-memory + on-disk) so
      // buildNodeScopedHubHeaders() falls back to unauthenticated on the next
      // /a2a/hello, and signal the caller NOT to arm reauth backoff.
      var payloadStatus = data && data.payload && data.payload.status;
      var payloadReason = data && data.payload && data.payload.reason;
      var topStatus = data && data.status;
      var topReason = data && data.reason;
      var rejected = payloadStatus === 'rejected' || topStatus === 'rejected';
      var reason = String(payloadReason || topReason || '').toLowerCase();
      var divergenceReason = rejected ? _secretDivergenceReason(reason) : '';
      var divergence = Boolean(divergenceReason);
      if (divergence) {
        return _clearDivergedHubNodeSecret(divergenceReason);
      }
      console.warn('[a2aProtocol] rotate_secret hello did not return a new secret.');
      return { ok: false, error: 'no_secret_in_response' };
    })
    .catch(function (err) { return { ok: false, error: err.message }; });
}

// Test-only injection point. Set via _setHeartbeatThrowForTesting().
// When non-null, sendHeartbeat() throws this value synchronously at its
// top, simulating the real-world bug class from #544 (getNodeId() raising,
// getHubUrl() raising, queueCommitmentUpdate poisoning JSON.stringify,
// etc.). The flag is consumed on first throw so tests can verify that
// the next scheduled tick still happens.
let _heartbeatSyncThrowForTesting = null;

function sendHeartbeat() {
  if (_heartbeatSyncThrowForTesting) {
    const err = _heartbeatSyncThrowForTesting;
    _heartbeatSyncThrowForTesting = null;
    throw err;
  }
  if (_isDryRun()) return Promise.resolve({ ok: true, dry_run: true });
  const hubUrl = getHubUrl();
  if (!hubUrl) {
    // Write a log entry so lifecycle.checkHealth() (gated on log mtime vs
    // MAX_SILENCE_MS = 30 min) never falsely declares the process stagnant
    // just because no hub URL is configured.
    _appendHeartbeatLog({ type: 'heartbeat_skip', reason: 'no_hub_url' });
    return Promise.resolve({ ok: false, error: 'no_hub_url' });
  }

  const endpoint = hubUrl.replace(/\/+$/, '') + '/a2a/heartbeat';
  const nodeId = getNodeId();
  const bodyObj = {
    node_id: nodeId,
    sender_id: nodeId,
  };

  const meta = {};
  const nodeSecretVersion = getHubNodeSecretVersion();
  if (nodeSecretVersion) {
    bodyObj.node_secret_version = nodeSecretVersion;
    meta.node_secret_version = nodeSecretVersion;
  }

  if (process.env.WORKER_ENABLED === '1') {
    const domains = (process.env.WORKER_DOMAINS || '').split(',').map(function (s) { return s.trim(); }).filter(Boolean);
    bodyObj.worker_enabled = true;
    bodyObj.worker_domains = domains;
    bodyObj.max_load = Math.max(1, Number(process.env.WORKER_MAX_LOAD) || 5);
    meta.worker_enabled = true;
    meta.worker_domains = domains;
    meta.max_load = bodyObj.max_load;
  }

  const modelTier = (process.env.EVOLVER_MODEL_TIER || '').trim();
  if (modelTier) {
    meta.model_tier = modelTier;
  }

  if (_pendingCommitmentUpdates.length > 0) {
    meta.commitment_updates = _pendingCommitmentUpdates.splice(0);
  }

  // env_fingerprint emission: previously set _heartbeatFpSent=true
  // synchronously here (before hubFetch ran), so a request that failed
  // mid-flight (process suspended right after this line; abort timeout;
  // hub dropped the response) left the client believing it had sent the
  // fingerprint while the hub had no record of evolver_version. The only
  // recovery was unknown_node / resend_hello / a >30min wall-clock jump
  // -- a short sleep (90s..30min) pokes the heartbeat but does NOT
  // re-arm fingerprint, so the dashboard could stay "unknown version"
  // until process restart. Track the intent locally and only flip the
  // module-level flag inside the success branch.
  let _fpEmittedThisTick = false;
  if (!_heartbeatFpSent) {
    try {
      const fp = captureEnvFingerprint();
      if (fp && fp.evolver_version) {
        bodyObj.env_fingerprint = fp;
        bodyObj.evolver_version = fp.evolver_version;
        meta.env_fingerprint = fp;
        _fpEmittedThisTick = true;
      }
    } catch (e) {
      console.warn('[a2aProtocol] Failed to capture env fingerprint:', e && e.message || e);
    }
  }

  if (_sharedKnowledgeVersion > 0) {
    meta.shared_knowledge_version = _sharedKnowledgeVersion;
  }

  try {
    const cfg = require('../config');
    if (cfg.antiAbuseTelemetryMode && cfg.antiAbuseTelemetryMode() === 'heartbeat') {
      const { buildHeartbeatAntiAbuseTelemetry } = require('./antiAbuseTelemetry');
      meta.anti_abuse = buildHeartbeatAntiAbuseTelemetry({
        source: 'evolver-client',
        nodeId,
        envFingerprint: meta.env_fingerprint || null,
        taskMeta: meta,
      });
    }
  } catch (e) {
    console.warn('[AntiAbuseTelemetry] failed to build heartbeat summary:', e && e.message || e);
  }

  if (Object.keys(meta).length > 0) {
    bodyObj.meta = meta;
  }

  // Attach pending force_update outcome (evomap-hub #1034 / #1039). The file
  // is written by _maybeTriggerForceUpdateFromHeartbeat after each upgrade
  // attempt. Successful upgrades exit the process; the next heartbeat is a
  // fresh process that reads this file and reports the outcome to the hub.
  // The file is only deleted after a confirmed 2xx response below.
  var _pendingLastUpdate = _readPendingLastUpdate();
  if (_pendingLastUpdate) {
    bodyObj.last_update = _pendingLastUpdate;
  }

  const body = JSON.stringify(bodyObj);

  _heartbeatTotalSent++;

  return hubFetch(endpoint, {
    method: 'POST',
    headers: buildNodeScopedHubHeaders(),
    body: body,
    signal: AbortSignal.timeout(require('../config').HEARTBEAT_TIMEOUT_MS),
  })
    .then(function (res) {
      if (res.status === 403 || res.status === 401) {
        // Round-9: distinguish a benign 401 (hub has no secret for us yet --
        // node_secret_not_set / node_secret_required; fresh node or
        // first-launch / hb-response-cache race) from a genuine 403 secret
        // mismatch (operator "Reset Secret"). The benign case must NOT arm
        // the escalating reauth backoff (that was the round-9 idle-death);
        // the 403 case still does. We READ the body here (which also drains
        // the socket -- replaces the round-8 cancel() so the undici pool
        // does not leak a socket per auth failure) to read the hub's error
        // code, with a status-only fallback if the body is unreadable.
        var status = res.status;
        return res.text().then(function (t) {
          var authErr = _hubErrorReasonFromText(t);
          var benign = _benignNoSecretHeartbeatAuthError(status, authErr);
          var divergenceReason = _secretDivergenceReason(authErr);
          console.warn('[Heartbeat] Auth failed (' + status + (authErr ? ' ' + authErr : '') + '). ' +
            (benign ? 'Benign no-secret race; short re-hello retry.' : 'Rotating secret via re-hello.'));
          return _rotateAndRetryHeartbeat(endpoint, body, {
            benign: benign,
            status: status,
            secretDivergenceReason: divergenceReason,
          });
        }, function () {
          // Body unreadable: fall back to status-only discrimination.
          console.warn('[Heartbeat] Auth failed (' + status + ', body unreadable). Attempting re-hello...');
          return _rotateAndRetryHeartbeat(endpoint, body, { benign: false, status: status });
        });
      }
      if (!res.ok) {
        // Bugbot PR#188 #3: parse 426 body for a force_update directive.
        // Hub emits `426 Upgrade Required` with JSON body
        // `{ error:'evolver_min_version_required', force_update:{...} }`
        // (see hub `src/routes/a2a/_middleware.js requireForceUpdateVersion`)
        // when the node falls below the hard floor. Pre-fix, this branch
        // collapsed every non-2xx into `http_<status>: <body>` — canonical
        // (non-proxy) nodes that hit the floor never attempted an upgrade,
        // exactly the failure mode this PR set out to close for proxy.
        // Mirror the proxy `LifecycleManager` (manager.js:786-815): parse
        // the body, fire `_maybeTriggerForceUpdateFromHeartbeat` so the
        // microtask runs executeForceUpdate + reportForceUpdateOutcome,
        // and let the next heartbeat carry the attempt as `body.last_update`.
        // Still return an error so the caller's failure counter ticks and
        // the heartbeat loop backs off (the upgrade itself runs in a
        // detached microtask and exit(78)s on success).
        if (res.status === 426) {
          return res.text().then(function (t) {
            var parsed = null;
            try { parsed = JSON.parse(t); } catch (_) { /* body not JSON */ }
            var fu = parsed && parsed.force_update;
            if (fu && typeof fu === 'object') {
              console.warn('[Heartbeat] HTTP 426 with force_update directive (required=' +
                (fu.required_version || '?') + ') — triggering executeForceUpdate');
              try {
                _maybeTriggerForceUpdateFromHeartbeat(fu);
              } catch (e) {
                console.warn('[Heartbeat] 426 force_update trigger threw (non-fatal): ' +
                  (e && e.message || e));
              }
            } else {
              console.warn('[Heartbeat] HTTP 426 without parseable force_update payload: ' + t);
            }
            return { ok: false, error: 'http_426: ' + t };
          });
        }
        return res.text().then(function (t) {
          return { ok: false, error: 'http_' + res.status + ': ' + t };
        });
      }
      return res.json();
    })
    .then(function (data) {
      if (data && (data.error === 'rate_limited' || data.status === 'rate_limited')) {
        const retryMs = Number(data.retry_after_ms) || 0;
        const policy = data.policy || {};
        const windowMs = Number(policy.window_ms) || 0;
        const rawBackoff = retryMs > 0 ? retryMs + 5000 : (windowMs > 0 ? windowMs + 5000 : _heartbeatIntervalMs);
        // Clamp the hub-supplied wait to a safe ceiling. Without the clamp a
        // single hub bug or hostile response carrying retry_after_ms
        // == 86_400_000 would silence the heartbeat for 24h.
        const backoff = Math.min(rawBackoff, _HEARTBEAT_MAX_RATE_LIMIT_BACKOFF_MS);
        if (backoff > _heartbeatIntervalMs) {
          console.warn('[Heartbeat] Rate limited by hub. Next attempt in ' + Math.round(backoff / 1000) + 's. ' +
            'Consider increasing HEARTBEAT_INTERVAL_MS to >= ' + (windowMs || backoff) + 'ms.');
          // Set the pending-reschedule signal instead of calling
          // _scheduleNextHeartbeat() directly. The finally-arm in
          // _heartbeatTick will read this and ensure the next tick is
          // scheduled with max(default, backoff); a direct call here would
          // be silently overwritten by the finally-arm's no-arg
          // _scheduleNextHeartbeat() ~microseconds later.
          _pendingRescheduleDelayMs = backoff;
        }
        // Count rate_limited as a soft failure so the drift detector's
        // persistent-failure branch (consecutiveFailures > 0 && sinceLastTick
        // > 2*interval) can still drive recovery if the hub stays angry. Without
        // this the counter resets to 0 below and drift detection is blind to
        // a hub that is continuously rate-limiting us.
        _heartbeatConsecutiveFailures = Math.min(_heartbeatConsecutiveFailures + 1, 1000);
        return { ok: false, error: 'rate_limited', retryMs: backoff };
      }
      if (data && data.status === 'unknown_node') {
        console.warn('[Heartbeat] Node not registered on hub. Sending hello to re-register...');
        // Bugbot PR#188 #4: trust the ack contract on unknown_node too.
        // The hub route writes last_update_ack BEFORE handleHeartbeat
        // returns status='unknown_node' (replica lag can return
        // unknown_node while persist already succeeded). Without this
        // clear here, the canonical path retains the file and re-sends
        // next tick where hub-side dedup ack clears it anyway --
        // an extra heartbeat of wasted bytes. proxy/lifecycle/manager.js
        // already trusts ack on this path; this brings canonical parity.
        if (_pendingLastUpdate) {
          var ackUnk = data && data.last_update_ack;
          if (ackUnk && typeof ackUnk === 'object') {
            // Mirror the canonical-path warn semantics (see ack-clear block
            // ~L2497) so reviewers reading hub-rejected force_updates see
            // the same signal regardless of which branch handled the ack.
            if (ackUnk.reason === 'failed') {
              console.warn('[ForceUpdate] hub last_update_ack=failed (unknown_node path); ' +
                'keeping state file for retry on next heartbeat.');
            } else if (ackUnk.reason === 'invalid') {
              console.warn('[ForceUpdate] hub last_update_ack=invalid (unknown_node path); ' +
                'clearing state file (retry will not help).');
            }
            if (ackUnk.ok === true
                || ackUnk.reason === 'duplicate'
                || ackUnk.reason === 'invalid') {
              _clearLastUpdateStateIfMatches(_pendingLastUpdate);
            }
          }
        }
        // Round-6 (§19.8): if the 8-min backoff window expired naturally
        // (deadline in the past, counter still at saturation), reset the
        // counter so the next unknown_node response starts fresh from
        // the 35s hello-recovery margin instead of immediately re-arming
        // the full 8-min backoff. A node that flaps unknown_node <-> ok
        // above the threshold otherwise never gets the margin re-armed
        // and bounces between cache-poison backoffs every cycle.
        if (
          _consecutiveUnknownNodeAfterHello >= _UNKNOWN_NODE_AFTER_HELLO_THRESHOLD
          && _unknownNodeBackoffUntil > 0
          && _unknownNodeBackoffUntil <= Date.now()
        ) {
          _consecutiveUnknownNodeAfterHello = 0;
          _unknownNodeBackoffUntil = 0;
        }
        return sendHelloToHub().then(function (helloResult) {
          if (helloResult.ok) {
            // Cache-poisoning loop guard (round-4): a hub-side response cache
            // pins the unknown_node payload for up to 7 min even after our
            // hello rebuilt the node row. Calling hello again on every tick
            // burns through the 60/h per-IP hello rate limit and locks the
            // node out entirely. Track the run and back off past the cache
            // TTL once we see it.
            _consecutiveUnknownNodeAfterHello++;
            if (_consecutiveUnknownNodeAfterHello >= _UNKNOWN_NODE_AFTER_HELLO_THRESHOLD) {
              console.warn(
                '[Heartbeat] ' + _consecutiveUnknownNodeAfterHello + ' consecutive unknown_node ' +
                'responses despite successful re-hellos -- suspected hub-side response cache ' +
                'poisoning. Backing off ' + Math.round(_UNKNOWN_NODE_AFTER_HELLO_BACKOFF_MS / 1000) +
                's to let the cache expire.'
              );
              _pendingRescheduleDelayMs = _UNKNOWN_NODE_AFTER_HELLO_BACKOFF_MS;
              // Round-5: also install an ABSOLUTE deadline. The drift
              // detector's persistent-failure branch otherwise bypasses the
              // 8-min wait every 30s via pokeHeartbeat() -> setImmediate
              // (round-4 reproducer surfaced by the round-5 audit), since
              // _pendingRescheduleDelayMs is consumed by the very first
              // reschedule after this branch. With the deadline, poke
              // callers can refuse to drive a new tick until the cache TTL
              // has actually had a chance to expire.
              _unknownNodeBackoffUntil = Date.now() + _UNKNOWN_NODE_AFTER_HELLO_BACKOFF_MS;
              _appendHeartbeatLog({
                type: 'unknown_node_backoff_armed',
                consecutive: _consecutiveUnknownNodeAfterHello,
                until: new Date(_unknownNodeBackoffUntil).toISOString(),
                backoffMs: _UNKNOWN_NODE_AFTER_HELLO_BACKOFF_MS,
              });
              // Count as a soft failure so the drift detector's persistent-
              // failure branch can drive recovery if even the backoff does
              // not break us out (e.g. hub bug pins the cache forever).
              _heartbeatConsecutiveFailures = Math.min(_heartbeatConsecutiveFailures + 1, 1000);
            } else {
              console.log('[Heartbeat] Re-registered with hub successfully.');
              _heartbeatConsecutiveFailures = 0;
              // Round-5: give the DB replication that just acknowledged
              // our hello write a fighting chance to reach the heartbeat
              // read replica before the next tick fires. Without this,
              // the next scheduled tick (~30s away at default interval)
              // hits the still-cached unknown_node response and the loop
              // counter climbs to the threshold above, snapping the node
              // into the 8-min backoff for nothing more than first-launch
              // replication lag. Use max() so a larger pre-existing
              // rate_limited/long-poll backoff is never shortened by us.
              _pendingRescheduleDelayMs = Math.max(
                _pendingRescheduleDelayMs || 0,
                _UNKNOWN_NODE_HELLO_RECOVERY_DELAY_MS
              );
              _appendHeartbeatLog({
                type: 'unknown_node_recovery',
                consecutive: _consecutiveUnknownNodeAfterHello,
                rescheduleInMs: _pendingRescheduleDelayMs,
              });
            }
            // Hub just accepted us as a fresh registration, so any
            // pre-existing reauth penalty (counter + backoff window)
            // is for a state that no longer exists. Clear it so the
            // first 401 after this point starts the backoff from base
            // again rather than from the half-saturated cap. Without
            // this, a hub-side row rebuild leaves the client stuck in
            // deepReauthFailure for up to 4h even though re-hello just
            // succeeded.
            var hadDeepReauthBackoff = _heartbeatReauthBackoffUntil > 0;
            _heartbeatConsecutiveReauthFailures = 0;
            _heartbeatReauthBackoffUntil = 0;
            if (hadDeepReauthBackoff) {
              // Round-6 (§19.2): pull the self-driving poll out of the
              // 5 min reauth-backoff quiet mode now that the hub has
              // accepted us.
              try { _armSelfDrivingPollFromHeartbeat(); } catch (_) {}
            }
            // The hub-side node card was recreated; the once-per-process
            // _heartbeatFpSent guard means the hub still has no env_fingerprint
            // / evolver_version for this row. Re-arm so the next tick
            // resends it -- otherwise the dashboard renders "unknown
            // version" indefinitely and users perceive the node as dead.
            _heartbeatFpSent = false;
          } else {
            console.warn('[Heartbeat] Re-registration failed: ' + (helloResult.error || 'unknown'));
            // Round-8 (§21.1): the round-7 fix was structurally broken in
            // two ways:
            //   (a) it returned {ok:false, error:'hello_failed_after_unknown_node'}
            //       from the OUTER .then(data) callback, but the soft-error
            //       allow-list that would have kept _heartbeatConsecutiveFailures
            //       climbing lives further down in that same callback,
            //       AFTER the early return. So the counter never incremented,
            //       and the drift detector's persistent-failure branch
            //       (gated on counter > 0) could not drive recovery.
            //   (b) it cleared _unknownNodeBackoffUntil = 0, removing the
            //       only gate pokeHeartbeat() consults. Any user-activity
            //       poke during the 5-min wait then bypassed the
            //       reschedule and re-fired into the still-hot cache /
            //       still-rate-limited /a2a/hello, burning the hub's 60/h
            //       per-IP budget that the 5-min wait existed to protect.
            // Round-8 fixes:
            //   (1) increment the failure counter HERE (the outer allow-
            //       list is unreachable from this code path).
            //   (2) re-purpose _unknownNodeBackoffUntil as a 5-min deadline
            //       so pokeHeartbeat()'s round-6 gate at :1090 protects
            //       this window the same way it protects the 8-min cache
            //       backoff window. Both states mean "do not call the hub
            //       for X minutes"; one field is enough.
            //   (3) keep _consecutiveUnknownNodeAfterHello as-is (do NOT
            //       reset to 0) so a recovery tick that immediately hits
            //       the cache again can re-arm the full 8-min backoff
            //       without first having to walk the counter back up.
            _pendingRescheduleDelayMs = Math.max(
              _pendingRescheduleDelayMs || 0,
              5 * 60_000
            );
            _unknownNodeBackoffUntil = Math.max(
              _unknownNodeBackoffUntil,
              Date.now() + 5 * 60_000
            );
            _heartbeatConsecutiveFailures = Math.min(
              _heartbeatConsecutiveFailures + 1,
              1000
            );
            _appendHeartbeatLog({
              type: 'hello_failed_after_unknown_node',
              helloError: helloResult.error || 'unknown',
              rescheduleInMs: _pendingRescheduleDelayMs,
              backoffUntil: new Date(_unknownNodeBackoffUntil).toISOString(),
              consecutiveFailures: _heartbeatConsecutiveFailures,
            });
            return {
              ok: false,
              response: data,
              reregistered: false,
              error: 'hello_failed_after_unknown_node',
            };
          }
          return { ok: helloResult.ok, response: data, reregistered: helloResult.ok };
        });
      }
      if (data && data.resend_hello) {
        console.log('[Heartbeat] Hub requests re-hello (' + (data.resend_reason || 'unspecified') + '). Sending hello...');
        _heartbeatFpSent = false;
        // Round-4: previously a bare `sendHelloToHub().then(...).catch(...)`.
        // If sendHelloToHub() throws SYNCHRONOUSLY (getHubUrl() unreadable on
        // post-wake env reload, buildNodeScopedHubHeaders() crypto.randomUUID failing on
        // a still-asleep entropy pool, JSON.stringify on a circular meta
        // object, hubFetch require throwing on a stale module cache), the
        // exception escapes the .catch() entirely and bubbles up the
        // sendHeartbeat() promise chain. The outer `.catch(err)` at the tail
        // sees it as a heartbeat failure -- not fatal -- but the in-tick
        // promise chain's `.then` after this line is also skipped, so
        // available_work / overdue tasks / shared knowledge updates from a
        // valid `data` payload are dropped. Worse: in a setup where the hub
        // sets resend_hello on every response (legitimate request the client
        // cannot satisfy), every tick throws here, every tick fails to
        // process the rest of the payload, and the "process alive but
        // functionally inert" pattern recurs. Wrap in try/catch so a sync
        // throw never breaks the rest of the tick.
        try {
          var helloPromise = sendHelloToHub();
          if (helloPromise && typeof helloPromise.then === 'function') {
            helloPromise.then(function (r) {
              if (r && r.ok) console.log('[Heartbeat] Re-hello sent successfully.');
              else console.warn('[Heartbeat] Re-hello failed: ' + ((r && r.error) || 'unknown'));
            }).catch(function () {});
          }
        } catch (syncErr) {
          console.warn('[Heartbeat] Re-hello threw synchronously: ' + (syncErr && syncErr.message || syncErr));
        }
      }
      // Healthy ok response: clear the unknown_node loop counter. Any
      // subsequent unknown_node after this point is a fresh occurrence.
      // Round-5: also drop the backoff deadline so any future cache-
      // poisoning episode starts from a clean counter rather than
      // inheriting a (now-stale) deadline from a previous run.
      if (data && data.status !== 'unknown_node' && !data.resend_hello) {
        var hadUnknownNodeBackoff = _unknownNodeBackoffUntil > 0;
        _consecutiveUnknownNodeAfterHello = 0;
        _unknownNodeBackoffUntil = 0;
        // Round-6 (§19.2): wake the self-driving poll out of quiet mode
        // immediately. While the unknown_node backoff was hot the poll
        // self-rescheduled at _SELF_DRIVING_POLL_QUIET_MS (5 min), so
        // without this re-arm there is a >= 5 min hole between heartbeat
        // recovery and the first event delivery, even though the hub now
        // has fresh state for us.
        if (hadUnknownNodeBackoff) {
          try { _armSelfDrivingPollFromHeartbeat(); } catch (_) {}
        }
      }
      if (Array.isArray(data.available_work)) {
        _latestAvailableWork = data.available_work;
      }
      if (Array.isArray(data.overdue_tasks) && data.overdue_tasks.length > 0) {
        _latestOverdueTasks = data.overdue_tasks;
        console.warn('[Commitment] ' + data.overdue_tasks.length + ' overdue task(s) detected via heartbeat.');
      }
      if (data.skill_store) {
        _latestSkillStoreHint = data.skill_store;
        if (data.skill_store.eligible && data.skill_store.published_skills === 0) {
          console.log('[Skill Store] ' + data.skill_store.hint);
        }
      }
      if (data.novelty && typeof data.novelty === 'object') {
        _latestNoveltyHint = data.novelty;
      }
      if (Array.isArray(data.capability_gaps) && data.capability_gaps.length > 0) {
        _latestCapabilityGaps = data.capability_gaps;
      }
      if (data.circle_experience && typeof data.circle_experience === 'object') {
        console.log('[EvolutionCircle] Active circle: ' + (data.circle_experience.circle_id || '?') + ' (' + (data.circle_experience.member_count || 0) + ' members)');
      }
      if (data.accountability && typeof data.accountability === 'object') {
        var ep = data.accountability.error_patterns;
        if (ep && typeof ep === 'object') {
          var topPatterns = Array.isArray(ep.top_patterns) ? ep.top_patterns : [];
          if (topPatterns.length > 0) {
            var patternSummary = topPatterns
              .map(function (p) { return (p.fingerprint || '?').slice(0, 12) + ' (' + (p.count || 0) + 'x, ' + (p.escalation || 'info') + ')'; })
              .join('; ');
            console.warn('[ErrorPatterns] Recurring rejection patterns detected: ' + patternSummary);
            if (ep.recommendation) {
              console.warn('[ErrorPatterns] Recommendation: ' + ep.recommendation);
            }
          }
        }
      }
      if (data.heartbeat_actions && typeof data.heartbeat_actions === 'object') {
        var newActions = Array.isArray(data.heartbeat_actions.actions) ? data.heartbeat_actions.actions : [];
        if (_latestHeartbeatActions && Array.isArray(_latestHeartbeatActions.actions)) {
          _latestHeartbeatActions.actions = mergeAndCap(_latestHeartbeatActions.actions, newActions, 100);
        } else {
          _latestHeartbeatActions = { actions: newActions.slice(-100) };
        }
        if (data.heartbeat_actions.metrics_snapshot) {
          _latestHeartbeatActions.metrics_snapshot = data.heartbeat_actions.metrics_snapshot;
        }
        var actionTypes = newActions.length > 0
          ? newActions.map(function (a) { return a.type; }).join(', ')
          : 'none';
        console.log('[HeartbeatAction] Received actions: ' + actionTypes);
      }
      if (data.shared_knowledge_delta && typeof data.shared_knowledge_delta === 'object') {
        var newEntries = Array.isArray(data.shared_knowledge_delta.entries) ? data.shared_knowledge_delta.entries : [];
        if (_latestSharedKnowledgeDelta && Array.isArray(_latestSharedKnowledgeDelta.entries)) {
          _latestSharedKnowledgeDelta.entries = mergeAndCap(_latestSharedKnowledgeDelta.entries, newEntries, 100);
        } else {
          _latestSharedKnowledgeDelta = { entries: newEntries.slice(-100) };
        }
        if (Number.isFinite(Number(data.shared_knowledge_delta.version))) {
          _sharedKnowledgeVersion = data.shared_knowledge_delta.version;
        }
        var deltaCount = newEntries.length;
        if (deltaCount > 0) {
          console.log('[SharedKnowledge] Received ' + deltaCount + ' delta entries (version: ' + _sharedKnowledgeVersion + ')');
        }
      }
      if (data.force_update && typeof data.force_update === 'object') {
        _forceUpdatePending = data.force_update;
        console.log('[ForceUpdate] Hub requires update to ' +
          (data.force_update.required_version || '?') +
          ' -- reason: ' + (data.force_update.reason || 'unspecified'));
        // Heartbeat-thread trigger: many workers (merchantAgent, buyer-only,
        // proxy lifecycle) never enter the evolve run() loop that historically
        // consumed _forceUpdatePending. Without this block, Hub can send
        // force_update forever and the node will keep heartbeating on the old
        // version. We therefore drive executeForceUpdate directly from here,
        // gated by a single in-flight lock and a cooldown on failures so we
        // do not hammer npm/degit every heartbeat tick.
        _maybeTriggerForceUpdateFromHeartbeat(data.force_update);
      }
      if (data.has_pending_events) {
        _fetchHubEvents().catch(function (err) {
          console.warn('[Events] Poll failed:', err && err.message || err);
        });
      }
      // Reauth failures can flow into this success-side callback as
      // { ok:false, ... } because auth-recovery branches return structured
      // errors instead of throwing. Do not wrap those as heartbeat_ok: keep the
      // failure counter climbing so drift recovery remains armed. Plain HTTP
      // failures must continue through the legacy envelope / last_update logic
      // below.
      // Round-8 (§21.1): removed the `hello_failed_after_unknown_node`
      // entry that round-7 added here. The unknown_node branch at :1422
      // returns early from THIS outer .then(data), so this allow-list is
      // unreachable for that error key; the failure-counter increment now
      // happens inline inside the unknown_node hello-fail branch instead.
      if (data && data.ok === false && (
        data.error === 'reauth_backoff_active' ||
        data.error === 'secret_diverged_cleared' ||
        data.error === 'reauth_benign_retry'
      )) {
        _heartbeatConsecutiveFailures = Math.min(_heartbeatConsecutiveFailures + 1, 1000);
        return data;
      }
      _heartbeatConsecutiveFailures = 0;
      if ((Array.isArray(data.pending_atp_tasks) && data.pending_atp_tasks.length > 0)
          || (Array.isArray(data.pending_deliveries) && data.pending_deliveries.length > 0)) {
        // Heartbeat-thread ATP trigger: the evolve run() loop is responsible
        // for ATP pickup and autoDeliver polling, but many merchant nodes
        // run in heartbeat-only mode (worker subprocess, proxy lifecycle,
        // Cursor-native wrapper without a run() loop). For those, we react
        // directly from the heartbeat callback so submitDelivery lands
        // without the run() loop. Pure HTTP, no spawn, no LLM.
        try {
          var hbSig = require('../atp/heartbeatSignalsHandler');
          hbSig.handleHeartbeatSignals({
            pending_atp_tasks: data.pending_atp_tasks,
            pending_deliveries: data.pending_deliveries,
          }).catch(function (err) {
            console.warn('[ATP-HB] handler rejected:', err && err.message || err);
          });
        } catch (e) {
          console.warn('[ATP-HB] handler unavailable:', e && e.message || e);
        }
      }
      // Round-4: previously this block only called utimesSync(), so
      // evolver_loop.log stayed at 0 bytes for the entire process lifetime
      // even after thousands of successful ticks. Round-5 refactored the
      // inline append into _appendHeartbeatLog so the failure / lifecycle
      // paths can share the same writer and emit comparable records.
      _appendHeartbeatLog({
        type: 'heartbeat_ok',
        tick: _heartbeatTotalSent,
        fpSent: _fpEmittedThisTick || false,
        pendingEvents: !!(data && data.has_pending_events),
      });
      // Hub accepted the heartbeat (no auth retry, no http error, no
      // rate_limited, no unknown_node). NOW it's safe to commit the
      // "fingerprint has been delivered" flag for the rest of the
      // process lifetime. Setting this synchronously before the network
      // call (the previous behavior) lost the fingerprint on any
      // mid-flight failure -- short sleeps don't re-arm it, so the
      // hub-side node card stayed "unknown version" until restart.
      if (_fpEmittedThisTick) {
        _heartbeatFpSent = true;
      }
      // last_update report (evomap-hub #1034 / #1039) was attached to this
      // body and we need to decide whether the hub actually persisted it
      // before unlinking the local state file. Drop the file only when the
      // hub explicitly acked persistence; otherwise keep it so the next
      // heartbeat retries. Deliberately NOT done in a finally: a non-2xx /
      // network failure must KEEP the file.
      //
      // PR #188 follow-up (HIGH H1-client): the original gate
      //   hubAccepted = !(data && data.ok === false)
      // was a bare HTTP-2xx + envelope check, but the hub side fires
      // persistLastUpdate as a void-promise *after* the 2xx response has
      // already gone on the wire (evomap-hub src/routes/a2a/protocol.js).
      // So DB write failures, schema rejections, expired-dedup-then-refire,
      // and the bypass-returns-false path all silently lose the row while
      // the client cheerfully deleted the only evidence. The hub now writes
      // a `last_update_ack: { ok, reason? }` field at the TOP LEVEL of the
      // heartbeat response, set only when the request carried last_update.
      // Contract (coordinated wire change):
      //   ack.ok === true           -> row persisted; clear file.
      //   ack.reason === 'duplicate'-> dedup hit (already persisted); clear.
      //   ack.reason === 'invalid'  -> hub rejected payload shape; retry
      //                                would just re-fail. Clear + warn.
      //   ack.reason === 'failed'   -> hub tried but write failed; KEEP file
      //                                so the next tick retries; warn.
      //   no ack field present      -> old hub (pre-rollout). Fall back to
      //                                the original bare-2xx semantics for
      //                                backward compat -- this preserves
      //                                today's behavior on hubs that have
      //                                not yet deployed the ack writer.
      // Non-2xx HTTP responses materialise here as
      // `data = { ok:false, error:'http_<status>: ...' }` and trip neither
      // the new-hub nor the old-hub clear (data.ok === false on the
      // fallback path, no ack on the new-hub path because the hub did not
      // get to write one).
      var hubAccepted = !(data && data.ok === false);
      // Bugbot PR#188 #6: hubAcceptedLastUpdate was tracked but never read.
      // The clear is gated by `shouldClear` below; no caller consumes the
      // separate flag. Removed.
      if (_pendingLastUpdate) {
        var ack = data && data.last_update_ack;
        var hasAck = ack && typeof ack === 'object';
        var shouldClear;
        if (hasAck) {
          // New-hub branch: trust the ack contract.
          shouldClear = ack.ok === true
            || ack.reason === 'duplicate'
            || ack.reason === 'invalid';
          if (ack.reason === 'failed') {
            console.warn('[ForceUpdate] hub last_update_ack=failed; ' +
              'keeping state file for retry on next heartbeat.');
          } else if (ack.reason === 'invalid') {
            console.warn('[ForceUpdate] hub last_update_ack=invalid; ' +
              'clearing state file (retry will not help).');
          }
        } else {
          // Old-hub backward-compat branch: bare 2xx envelope.
          shouldClear = hubAccepted;
        }
        if (shouldClear) {
          _clearLastUpdateStateIfMatches(_pendingLastUpdate);
        }
      }
      // Hub 400 circuit breaker: if last_update was attached this tick and
      // the hub rejected the body with 400 AND the rejection is about the
      // last_update field, the state file is poisoning every heartbeat.
      // Clear it conservatively -- either when the error string names
      // last_update (case-insensitive) or after 3 consecutive last_update-
      // related 400s in this state. Reset the counter on anything other
      // than a last_update-related 400 with a pending payload.
      //
      // PR #188 follow-up: previously the breaker triggered on ANY http_400
      // (fingerprint/node_id/etc.), so an unrelated 400 could silently
      // unlink a legitimate upgrade telemetry file after 3 strikes. Now we
      // require the error body to mention `last_update` (the hub validateBody
      // envelope serialises field paths into the body text, so a zod failure
      // on `last_update.*` reliably contains the substring). Unrelated 400s
      // are left alone -- they are the responsibility of the code that owns
      // the offending field, not this circuit breaker.
      var isHttp400 = !!(data && data.ok === false
        && typeof data.error === 'string' && data.error.indexOf('http_400') === 0);
      // Tolerant match: case-insensitive, accepts `last_update`, `last-update`,
      // and dot-paths like `last_update.finished_at`.
      var isLastUpdateRelated = isHttp400
        && /last[_-]?update/i.test(String((data && data.error) || ''));
      if (isLastUpdateRelated && _pendingLastUpdate) {
        var errStr = String(data.error || '');
        var mentionsLastUpdate = /last[_-]?update/i.test(errStr);
        _lastUpdateConsecutive400++;
        if (mentionsLastUpdate || _lastUpdateConsecutive400 >= 3) {
          // Bypass _warnLastUpdateRateLimited: the breaker-fire moment is a
          // critical signal that must not be suppressible by an unrelated
          // earlier ForceUpdate warn in the same 1h rate-limit window.
          console.warn('[ForceUpdate] hub 400 with last_update attached (' +
            (mentionsLastUpdate ? 'error names last_update' : '3 consecutive 400s') +
            '); clearing poisoning state file.');
          _clearLastUpdateStateIfMatches(_pendingLastUpdate);
          _lastUpdateConsecutive400 = 0;
        }
      } else if (hubAccepted || (data && data.ok === false && !isLastUpdateRelated)) {
        // Non-last_update 400s, 5xx, and 2xx all reset the counter. They
        // are NOT evidence that the state file is the poison.
        _lastUpdateConsecutive400 = 0;
      }
      return { ok: true, response: data };
    })
    .catch(function (err) {
      _heartbeatConsecutiveFailures++;
      _heartbeatTotalFailed++;
      if (_heartbeatConsecutiveFailures === 3) {
        console.warn('[Heartbeat] 3 consecutive failures. Network issue? Last error: ' + err.message);
      } else if (_heartbeatConsecutiveFailures === 10) {
        console.warn('[Heartbeat] 10 consecutive failures. Hub may be unreachable. (' + err.message + ')');
      } else if (_heartbeatConsecutiveFailures % 50 === 0) {
        console.warn('[Heartbeat] ' + _heartbeatConsecutiveFailures + ' consecutive failures. (' + err.message + ')');
      }
      // Round-5: record failure on disk so the next "evolver dead after
      // idle" incident shows the actual error trail past the final
      // heartbeat_ok rather than abruptly going silent (which previously
      // looked indistinguishable from a process crash).
      _appendHeartbeatLog({
        type: 'heartbeat_fail',
        tick: _heartbeatTotalSent,
        consecutiveFailures: _heartbeatConsecutiveFailures,
        error: err && err.message || String(err),
      });
      // Linux network-disruption fast-recovery: when the kernel reports a
      // network-level error (ECONNRESET, ENETDOWN, ENETUNREACH, EHOSTUNREACH,
      // ENOTCONN, UND_ERR_SOCKET) it means a NetworkManager reconnect, VPN
      // re-establishment, or WiFi hand-off has invalidated the TCP socket.
      // hubFetch already called drainPool() so the next request gets a
      // fresh socket.  On top of that, poke the heartbeat loop so it retries
      // immediately (within the normal pokeHeartbeat throttle rules) rather
      // than waiting up to _heartbeatIntervalMs (~6 min default) for the
      // next scheduled tick.  Without this poke the drift-detector's
      // persistent-failure branch (fires only when sinceLastTick >
      // 2*interval) is the earliest auto-recovery at ~12 min, which is well
      // above the hub's 15-min online threshold.
      //
      // Safety: pokeHeartbeat() respects the single-flight gate, the
      // unknown_node backoff deadline, and the healthy-node 60s throttle,
      // so this cannot produce a hot-spin or bypass any intentional backoff.
      try {
        var hfMod = require('./hubFetch');
        if (
          typeof hfMod._isNetworkDisruptionError === 'function' &&
          hfMod._isNetworkDisruptionError(err)
        ) {
          console.warn('[Heartbeat] Network-level error on heartbeat (' +
            (err.code || (err.cause && err.cause.code) || err.message) +
            '); pool drained, poking for fast recovery');
          _appendHeartbeatLog({
            type: 'heartbeat_network_disruption',
            code: err.code || (err.cause && err.cause.code) || null,
            consecutiveFailures: _heartbeatConsecutiveFailures,
          });
          // Schedule a poke on next tick so the .finally reschedule in
          // _heartbeatTick runs first (preventing a double-schedule race).
          setImmediate(function () {
            try { pokeHeartbeat(); } catch (_) {}
          });
        }
      } catch (_) { /* never block the error return on recovery side-effects */ }
      return { ok: false, error: err.message };
    });
}

function getLatestAvailableWork() {
  return _latestAvailableWork;
}

function consumeAvailableWork() {
  const work = _latestAvailableWork;
  _latestAvailableWork = [];
  return work;
}

function getOverdueTasks() {
  return _latestOverdueTasks;
}

function getSkillStoreHint() {
  return _latestSkillStoreHint;
}

function consumeOverdueTasks() {
  const tasks = _latestOverdueTasks;
  _latestOverdueTasks = [];
  return tasks;
}

function getNoveltyHint() {
  return _latestNoveltyHint;
}

function getCapabilityGaps() {
  return _latestCapabilityGaps;
}

/**
 * Returns and clears pending heartbeat actions from Hub.
 * Actions include reflect, consolidate, pivot_check.
 */
function consumeHeartbeatActions() {
  var actions = _latestHeartbeatActions;
  _latestHeartbeatActions = null;
  return actions;
}

function getHeartbeatActions() {
  return _latestHeartbeatActions;
}

function consumeSharedKnowledgeDelta() {
  var delta = _latestSharedKnowledgeDelta;
  _latestSharedKnowledgeDelta = null;
  return delta;
}

function getSharedKnowledgeVersion() {
  return _sharedKnowledgeVersion;
}

function consumeForceUpdate() {
  var pending = _forceUpdatePending;
  _forceUpdatePending = null;
  return pending;
}

// Heartbeat-driven force_update trigger. Called inline when the heartbeat
// response carries a `force_update` directive. This exists because most
// worker deployments (merchantAgent, proxy lifecycle, buyer-only mode) never
// run the evolve run() loop, so the pending directive was never consumed and
// those nodes stayed on stale versions indefinitely -- which is exactly what
// blocked ATP settlement (v1.74.0 autoDeliver) from rolling out.
function _maybeTriggerForceUpdateFromHeartbeat(forceUpdate) {
  if (!forceUpdate || typeof forceUpdate !== 'object') return;
  if (_forceUpdateInFlight) return;
  var nowMs = Date.now();
  if (_forceUpdateLastAttemptAt && (nowMs - _forceUpdateLastAttemptAt) < _getForceUpdateRetryCooldownMs()) {
    // A recent attempt already ran and either succeeded (in which case the
    // process exited and we won't get here) or failed. Back off to avoid
    // spamming the upgrade channels every heartbeat interval.
    return;
  }
  _forceUpdateInFlight = true;
  _forceUpdateLastAttemptAt = nowMs;
  // Claim the pending directive immediately so any concurrent evolve run()
  // loop via consumeForceUpdate does not re-trigger executeForceUpdate.
  _forceUpdatePending = null;

  // Capture from_version BEFORE executeForceUpdate runs. Successful upgrades
  // call process.exit(78); the post-restart heartbeat reads the state file
  // from a fresh process where require('../../package.json').version is the
  // NEW version, so we must snapshot the currently-running version now.
  var fromVersion = '';
  try {
    fromVersion = String((require('../../package.json') || {}).version || '');
  } catch (_) {}

  // Kick off in a microtask so the heartbeat promise chain can still complete
  // (log touch, return {ok:true}) before the long-running upgrade takes over
  // the process.
  Promise.resolve().then(function () {
    var updated = false;
    var noop = false;
    var busy = false;
    var thrownErr = null;
    // Structured failure object ({ ok:false, code, detail }) when the upgrader
    // RETURNED a failure; forwarded to reportForceUpdateOutcome so the hub gets
    // the precise branch code instead of "executeForceUpdate returned false".
    var failureResult = null;
    try {
      var mod = require('../forceUpdate');
      var result = mod.executeForceUpdate(forceUpdate);
      // Sentinel === comparison: executeForceUpdate returns the
      // FORCE_UPDATE_NOOP symbol when the install is already at the required
      // version. We must NOT treat that as a "success" — doing so would
      // (a) write a phantom {status:"success", from_version==to_version} row
      // to EvolverUpgradeAttempt, and (b) trigger an exit(78) restart with
      // nothing to restart for. The hub schema accepts status="skipped".
      noop = (result === mod.FORCE_UPDATE_NOOP);
      // FORCE_UPDATE_BUSY: a concurrent caller is already running the upgrade.
      // Defensive only — _forceUpdateInFlight (the instance-level cooldown
      // flag) already gates this path before we get here, so BUSY should be
      // unreachable in practice. If it does fire (e.g. an evolve tick beat
      // us to executeForceUpdate via the module mutex), the other caller
      // owns the telemetry: we MUST NOT write a state file or exit(78).
      busy = (result === mod.FORCE_UPDATE_BUSY);
      updated = (result === true);
      // Inline the failure-shape check rather than calling mod.isForceUpdateFailure:
      // keeps this robust against partial test mocks of forceUpdate that stub
      // executeForceUpdate but omit the helper (a missing-function throw here
      // would otherwise demote a real success to "failed").
      failureResult = (result && typeof result === 'object' && result.ok === false) ? result : null;
    } catch (e) {
      thrownErr = e;
      console.warn('[ForceUpdate] heartbeat-trigger failed (non-fatal): ' + (e && e.message || e));
      updated = false;
    } finally {
      _forceUpdateInFlight = false;
    }
    if (busy) {
      _forceUpdateLastAttemptAt = 0;
      console.log('[ForceUpdate] heartbeat-trigger observed BUSY (concurrent invocation). Skipping telemetry; in-flight caller owns the outcome.');
      return;
    }
    // Delegate persist to the shared helper so the heartbeat-thread trigger
    // and the public reportForceUpdateOutcome stay in lockstep on payload
    // assembly + validation.
    // Bugbot PR#188 #7: wrap in try/catch to match proxy (manager.js:308)
    // and enrich (enrich.js:304). reportForceUpdateOutcome is throw-safe
    // today, but the outer try/finally above (L2726-2750) has already
    // closed by this microtask line; an uncaught throw here would
    // surface as an unhandled promise rejection.
    try {
      reportForceUpdateOutcome(forceUpdate, {
        updated: updated,
        noop: noop,
        error: thrownErr,
        failure: failureResult,
        fromVersion: fromVersion,
      });
    } catch (e) {
      console.warn('[ForceUpdate] heartbeat-trigger reportForceUpdateOutcome failed (non-fatal): ' +
        (e && e.message || e));
    }
    if (updated) {
      console.log('[ForceUpdate] Update complete (heartbeat-trigger). Exiting for restart...');
      try { process.exit(78); } catch (_) {}
    } else if (noop) {
      _forceUpdateLastAttemptAt = 0;
      // Already at required version — nothing changed on disk, no restart needed.
      console.log('[ForceUpdate] No-op (heartbeat-trigger): already at required version. Skipping restart.');
    } else {
      console.warn('[ForceUpdate] heartbeat-trigger failed. Will retry after cooldown (' +
        Math.round(_getForceUpdateRetryCooldownMs() / 60000) + 'min).');
    }
  });
}

// Public: assemble + persist the last_update payload for a force_update
// attempt. Callers outside the heartbeat loop (enrich.js, lifecycle/manager.js)
// drive this directly when they execute their own force_update -- the next
// heartbeat picks it up via the state file and reports to the hub.
// Side-effects only; returns nothing.
function reportForceUpdateOutcome(forceUpdate, opts) {
  var options = opts || {};
  var noop = !!options.noop;
  // noop wins over updated if both somehow get set (defensive): a no-op is
  // never a "real" success and must never persist as status="success".
  var updated = !noop && !!options.updated;
  var thrownErr = options.error;
  // Structured failure from executeForceUpdate ({ ok:false, code, detail }).
  // Present when the upgrader RETURNED a failure (the common case — degit
  // missing, tag-404, version mismatch, copy EPERM). thrownErr, by contrast,
  // is only set when executeForceUpdate THREW (rare — it catches its own
  // Channel 1 errors internally). We prefer `failure` over `thrownErr` when
  // building the error string so the hub gets the precise branch code instead
  // of the legacy "executeForceUpdate returned false". See
  // src/forceUpdate.js FORCE_UPDATE_FAIL_CODES.
  var failure = options.failure;
  var fromVersion = options.fromVersion;
  if (typeof fromVersion !== 'string' || fromVersion.length === 0) {
    try {
      fromVersion = String((require('../../package.json') || {}).version || '');
    } catch (_) { fromVersion = ''; }
  }
  var toVersion = '';
  try {
    toVersion = _extractTargetVersion(forceUpdate);
  } catch (_) {}
  if (!toVersion) {
    // Deliberately NOT rate-limited: diagnostic of a malformed hub payload
    // and fires at most once per cooldown anyway.
    console.warn('[ForceUpdate] no parsable target version, skipping outcome report');
    return;
  }
  var directiveId;
  try {
    if (forceUpdate && typeof forceUpdate.directive_id === 'string') {
      var d = forceUpdate.directive_id.slice(0, _LAST_UPDATE_LIMITS.DIRECTIVE_ID_MAX);
      if (d.length > 0) directiveId = d;
    }
  } catch (_) {}
  // Status selection:
  //   noop    -> "skipped" (hub schema enum value; no from_version: the binary
  //              didn't change so from_version == to_version would be noise
  //              that confuses operators reading EvolverUpgradeAttempt)
  //   updated -> "success"
  //   else    -> "failed"
  var status;
  if (noop) status = 'skipped';
  else if (updated) status = 'success';
  else status = 'failed';
  var payload = {
    to_version: toVersion,
    status: status,
    finished_at: Date.now(),
  };
  // Omit from_version for no-ops on purpose; for success/failure we keep it
  // so the hub can render the actual transition.
  if (!noop && fromVersion) {
    payload.from_version = fromVersion.slice(0, _LAST_UPDATE_LIMITS.FROM_VERSION_MAX);
  }
  if (directiveId) payload.directive_id = directiveId;
  if (!updated && !noop) {
    var errMsg;
    // Precedence: structured failure (code[: detail]) > thrown error
    // (unexpected_error: …) > legacy fallback. Every branch now yields a
    // "code: …" shape so operators can `GROUP BY split_part(error, ':', 1)`
    // in EvolverUpgradeAttempt without a hub schema change. The bare
    // "executeForceUpdate returned false" remains only as an unreachable
    // belt-and-suspenders default (every return path in forceUpdate.js now
    // carries a code).
    if (failure && failure.ok === false && typeof failure.code === 'string' && failure.code) {
      errMsg = failure.detail ? (failure.code + ': ' + failure.detail) : failure.code;
    } else if (thrownErr && thrownErr.message) errMsg = 'unexpected_error: ' + String(thrownErr.message);
    else if (typeof thrownErr === 'string') errMsg = 'unexpected_error: ' + thrownErr;
    else if (thrownErr) errMsg = 'unexpected_error: ' + String(thrownErr);
    else errMsg = 'executeForceUpdate returned false';
    // Bugbot PR#188 #5: npm/degit failure messages routinely carry env-derived
    // paths and (rarely) tokens leaked from `.npmrc` / registry URLs. Run a
    // second redaction pass over the full errMsg here, BEFORE the ERROR_MAX
    // truncation below, so a sensitive value near the tail cannot slip through
    // that .slice. This is a backstop over the whole message; the degit stderr
    // tail in particular is already redacted + control-char-stripped at its own
    // .slice(-300) inside forceUpdate.js's _classifyChannel1Error, so a leaked
    // value's prefix anchor is preserved before truncation either way. Uses the
    // same allowlisted redactor as every other GEP-bound payload
    // (src/gep/sanitize.js).
    errMsg = redactString(errMsg);
    payload.error = errMsg.length > _LAST_UPDATE_LIMITS.ERROR_MAX
      ? errMsg.slice(0, _LAST_UPDATE_LIMITS.ERROR_MAX)
      : errMsg;
  }
  // [#188 review-followup] A NOOP ("skipped") must not clobber an as-yet
  // undelivered terminal outcome already on disk. The hub heartbeat-response
  // cache is NOT keyed on the node's reported version, so an already-upgraded
  // node can still receive a stale `force_update`, reach this NOOP path, and
  // would otherwise overwrite a `success`/`failed` row the hub hasn't acked yet
  // (last_update_ack != ok) — silently losing the real telemetry this feature
  // exists to capture. `skipped` is the least informative status, so never let
  // it replace a pending non-skipped one. (Reading also drops a corrupt/expired
  // file, in which case there is nothing to preserve and we fall through.)
  // Upstream coupling: hub PR EvoMap/evomap-hub#1103 follow-up folds the
  // payload-derived directive_id into hbCacheKey, eliminating the stale-cache
  // precondition; this client guard remains a belt-and-suspenders defense.
  if (noop) {
    var pendingForNoop = null;
    try { pendingForNoop = _readPendingLastUpdate(); } catch (_) {}
    if (pendingForNoop && pendingForNoop.status && pendingForNoop.status !== 'skipped') {
      console.log('[ForceUpdate] NOOP: preserving undelivered "' +
        pendingForNoop.status + '" last_update; not overwriting with "skipped".');
      return;
    }
  }
  _persistLastUpdateState(payload);
}

// Public thin wrappers so external modules (enrich.js,
// proxy/lifecycle/manager.js) do not need to depend on the underscored
// internals.
function readPendingLastUpdate() {
  return _readPendingLastUpdate();
}
function clearLastUpdateOnAck(sent) {
  return _clearLastUpdateStateIfMatches(sent);
}

function getForceUpdate() {
  return _forceUpdatePending;
}

/**
 * Fetch pending high-priority events from the hub via long-poll.
 * Called automatically when heartbeat returns has_pending_events: true.
 * Results are stored in _latestHubEvents and can be consumed via consumeHubEvents().
 */
function _fetchHubEvents() {
  if (_isDryRun()) return Promise.resolve([]);
  if (_pollInflight) return Promise.resolve([]);
  const hubUrl = getHubUrl();
  if (!hubUrl) return Promise.resolve([]);

  // Build the request OUTSIDE the inflight gate. A synchronous throw in
  // getNodeId(), buildNodeScopedHubHeaders(), JSON.stringify, AbortSignal.timeout, or
  // hubFetch itself (e.g. config.js's resolveHubUrl throwing because the
  // module cache was poisoned during wake, _validateHubUrl rejecting a
  // briefly-empty env var) must NOT leave _pollInflight=true forever:
  // once that flag latches, every subsequent heartbeat that sees
  // has_pending_events early-returns at the top of this function and the
  // node never processes another hub event for the process's lifetime --
  // hub considers it alive (heartbeat still goes through) but functionally
  // dead. The fix: only flip _pollInflight=true after we have a thenable
  // we can attach .finally() to, so the cleaner is guaranteed to run.
  let pending;
  try {
    const nodeId = getNodeId();
    const endpoint = hubUrl.replace(/\/+$/, '') + '/a2a/events/poll';
    const body = JSON.stringify({
      protocol: 'gep-a2a',
      protocol_version: PROTOCOL_VERSION,
      message_type: 'events_poll',
      message_id: 'poll_' + Date.now(),
      timestamp: new Date().toISOString(),
      sender_id: nodeId,
      payload: {},
    });
    pending = hubFetch(endpoint, {
      method: 'POST',
      headers: buildNodeScopedHubHeaders(),
      body: body,
      signal: AbortSignal.timeout(require('../config').EVENT_POLL_TIMEOUT_MS),
    });
    if (!pending || typeof pending.then !== 'function') {
      // Future refactor / mocked fetch returns a non-thenable: still must
      // not leave _pollInflight stuck. Coerce so the .finally below fires.
      pending = Promise.resolve(pending);
    }
  } catch (err) {
    console.warn('[Events] Poll setup threw synchronously:', err && err.message || err);
    return Promise.resolve([]);
  }
  _pollInflight = true;

  return pending
    .then(function (res) {
      // Round-7 (§20.2 + §20.6): non-ok responses must drain the body so
      // the long-poll dispatcher pool is not leaked one socket per
      // failure, AND must carry the hub's retry signal out so the
      // self-driving poll runner does not refill the 4/60s rate bucket
      // every 1s. Without this, a 429 reads as `events = []` (no
      // `events` field in the rate-limited envelope), the success arm
      // sets _selfDrivingPollBackoffMs = 1000, the next poll fires 1s
      // later and 429s again -- the entire 60s window stays burned.
      if (!res.ok) {
        try { if (res.body && typeof res.body.cancel === 'function') res.body.cancel().catch(function () {}); } catch (_) {}
        if (res.status === 429) {
          // Best-effort retry signal: prefer Retry-After header (seconds),
          // fall back to a conservative 16s floor which keeps us under
          // 4 requests per rolling 60s even if the hub does not send one.
          var retryMs = 0;
          try {
            var hdr = (res.headers && typeof res.headers.get === 'function') ? res.headers.get('retry-after') : null;
            if (hdr) {
              var n = parseInt(hdr, 10);
              if (Number.isFinite(n) && n > 0) retryMs = n * 1000;
            }
          } catch (_) {}
          if (!(retryMs > 0)) retryMs = _SELF_DRIVING_POLL_429_FALLBACK_MS;
          if (retryMs > _SELF_DRIVING_POLL_MAX_BACKOFF_MS) retryMs = _SELF_DRIVING_POLL_MAX_BACKOFF_MS;
          _pendingSelfDrivingPollDelayMs = Math.max(_pendingSelfDrivingPollDelayMs, retryMs);
          try {
            _appendHeartbeatLog({
              type: 'events_poll_rate_limited',
              retryAfterMs: retryMs,
            });
          } catch (_) {}
        }
        var err = new Error('hub_events_poll_http_' + res.status);
        err.status = res.status;
        throw err;
      }
      return res.json();
    })
    .then(function (data) {
      const events = (data && Array.isArray(data.events))
        ? data.events
        : (data && data.payload && Array.isArray(data.payload.events))
          ? data.payload.events
          : [];
      if (events.length > 0) {
        _latestHubEvents = _latestHubEvents.concat(events);
        var MAX_BUFFERED_EVENTS = 200;
        if (_latestHubEvents.length > MAX_BUFFERED_EVENTS) {
          var dropped = _latestHubEvents.length - MAX_BUFFERED_EVENTS;
          _latestHubEvents = _latestHubEvents.slice(-MAX_BUFFERED_EVENTS);
          console.warn('[Events] Buffer overflow: dropped ' + dropped + ' oldest event(s).');
        }
        console.log('[Events] Received ' + events.length + ' pending event(s): ' +
          events.map(function (e) { return e.type; }).join(', '));
      }
      return events;
    })
    .catch(function (err) {
      console.warn('[Events] Poll error:', err && err.message || err);
      return [];
    })
    .finally(function () {
      _pollInflight = false;
    });
}

// Round-5: self-driving long-poll runner. Kept INTENTIONALLY separate
// from the heartbeat-triggered poll path so the existing
// has_pending_events optimization still works for SSE-healthy nodes.
// _pollInflight serves as the single-flight gate either way -- a
// concurrent poll attempt from this runner or from heartbeat is a no-op
// while another is in flight. Cadence: 1s after success (give the event
// loop room and avoid thundering-herd on hub event arrival), exponential
// backoff up to 60s on error (DNS down, hub down, TLS flaky -- not our
// problem to fix in tight loops). Disabled entirely when SSE is OFF via
// EVOLVER_SSE_DISABLED is NOT a reason to also disable poll: poll is
// the ONLY delivery path when SSE is off. Disabled when:
//   - heartbeat stopped (startHeartbeat() not yet called, or stopHeartbeat() ran)
//   - EVOLVER_DISABLE_SELF_DRIVING_POLL=1 (escape hatch for self-hosted hubs
//     that cannot tolerate the load)
//   - unknown_node backoff active (re-polling under a poisoned cache wastes
//     hub CPU and our IP rate-limit budget; the heartbeat path will arm
//     us via _armSelfDrivingPollFromHeartbeat once the cache clears)
function _isSelfDrivingPollDisabled() {
  var v = String(process.env.EVOLVER_DISABLE_SELF_DRIVING_POLL || '').trim();
  return v === '1' || v.toLowerCase() === 'true';
}

// Round-6 (§19.5): wake recovery wired so it runs from BOTH the SIGCONT
// handler (hypervisor/docker resume) AND the drift detector's long-sleep
// branch (the only path that fires on bare-metal macOS wake -- followups
// §18.2). Heartbeat-internal recovery (drainPool, poke, SSE restart) is
// owned here; process-level hooks (sleepMs interrupt, validator poke) are
// registered by index.js to avoid circular requires.
const _wakeRecoveryHooks = [];
function registerWakeHook(fn) {
  if (typeof fn !== 'function') return;
  _wakeRecoveryHooks.push(fn);
}

// Debounce gate for _runWakeRecovery covering two distinct burst sources:
//
// 1. docker pause/unpause: fires both the SIGCONT handler (synchronously on
//    unpause) and the drift detector's gap branch (within the next 30s
//    setInterval tick) for the same wake event. Without a guard both paths
//    call stopEventStream()+startEventStream(), tearing down the SSE
//    connection the first recovery already established and forcing an
//    unnecessary 5s reconnect.
//
// 2. Linux debugger attach/detach: a ptrace(PTRACE_ATTACH) / ptrace(PTRACE_DETACH)
//    cycle sends SIGSTOP+SIGCONT, and some debuggers (gdb, lldb on Linux,
//    strace) issue multiple SIGCONT signals per attach/detach sequence within
//    the same second. Each unguarded call would recreate undici agents (the
//    old ones drain asynchronously but accumulate), tear down and reopen SSE,
//    and reschedule the self-driving poll -- compounding into agent-object
//    leaks and SSE connection storms. A 1000ms window collapses an entire
//    attach/detach burst into a single recovery while remaining negligible
//    relative to the 5s SSE reconnect base backoff.
//
// Exposed as a let so tests can reset it between runs via _testing.
let _lastWakeRecoveryAt = 0;
const _WAKE_RECOVERY_DEDUP_MS = 1000;

function _runWakeRecovery() {
  var now = Date.now();
  if (now - _lastWakeRecoveryAt < _WAKE_RECOVERY_DEDUP_MS) return;
  _lastWakeRecoveryAt = now;
  // Drain the undici pool first so the heartbeat poke below gets fresh
  // sockets instead of reusing ones the NAT dropped during sleep.
  try {
    var hf = require('./hubFetch');
    if (typeof hf.drainPool === 'function') hf.drainPool();
  } catch (_) {}
  try { pokeHeartbeat(); } catch (_) {}
  try { stopEventStream(); } catch (_) {}
  try { startEventStream(); } catch (_) {}
  // Round-6 (§19.2): the self-driving poll may be in 5 min quiet mode
  // (unknown_node or reauth backoff active before sleep). The hub side
  // has likely changed during a multi-hour sleep, so pull the poll back
  // to the base cadence -- the next poll will gate on the post-wake
  // state again if the backoff is still legitimately active.
  try { _armSelfDrivingPollFromHeartbeat(); } catch (_) {}
  // Process-level hooks registered by index.js / supervisors.
  for (var i = 0; i < _wakeRecoveryHooks.length; i++) {
    try { _wakeRecoveryHooks[i](); } catch (_) {}
  }
}

function _runSelfDrivingPoll() {
  if (!_selfDrivingPollEnabled) return;
  if (_isDryRun()) return;
  // Skip while unknown_node backoff is hot -- the hub does not know us
  // yet, so polling will either be ignored or count against rate limits
  // for no payoff. The heartbeat tick that clears the backoff will arm
  // us again via _scheduleNextSelfDrivingPoll.
  if (_unknownNodeBackoffUntil > Date.now()) {
    _scheduleNextSelfDrivingPoll(_SELF_DRIVING_POLL_QUIET_MS);
    return;
  }
  // Skip while reauth backoff is hot for the same reason.
  if (_heartbeatReauthBackoffUntil > Date.now()) {
    _scheduleNextSelfDrivingPoll(_SELF_DRIVING_POLL_QUIET_MS);
    return;
  }
  _fetchHubEvents().then(function (events) {
    // Round-7 (§20.2): if _fetchHubEvents observed a 429 it set the
    // pending-delay override. Honor it before defaulting to the base
    // cadence; otherwise the retry-after carried out from the hub is
    // silently dropped and the next poll refills the rate bucket.
    if (_pendingSelfDrivingPollDelayMs > 0) {
      var overrideDelay = _pendingSelfDrivingPollDelayMs;
      _pendingSelfDrivingPollDelayMs = 0;
      // Keep _selfDrivingPollBackoffMs tracking the worst case so a
      // subsequent error path's *2 calculation grows from the correct
      // floor rather than racing back down to BASE_MS.
      _selfDrivingPollBackoffMs = Math.max(_selfDrivingPollBackoffMs, overrideDelay);
      _scheduleNextSelfDrivingPoll(overrideDelay);
      return;
    }
    // Success path: reset backoff so the next iteration runs at the
    // base cadence. If a real event arrived, run again with no delay so
    // the consumer sees stacked events as quickly as the hub emits them.
    _selfDrivingPollBackoffMs = _SELF_DRIVING_POLL_BASE_MS;
    var nextDelay = (events && events.length > 0) ? 0 : _SELF_DRIVING_POLL_BASE_MS;
    _scheduleNextSelfDrivingPoll(nextDelay);
  }).catch(function (err) {
    // Network/transport errors get exponential backoff so we do not
    // spam a downed hub.
    _selfDrivingPollBackoffMs = Math.min(
      Math.max(_selfDrivingPollBackoffMs * 2, _SELF_DRIVING_POLL_BASE_MS),
      _SELF_DRIVING_POLL_MAX_BACKOFF_MS
    );
    try {
      _appendHeartbeatLog({
        type: 'self_driving_poll_error',
        error: (err && err.message) || String(err),
        nextDelayMs: _selfDrivingPollBackoffMs,
      });
    } catch (_) {}
    _scheduleNextSelfDrivingPoll(_selfDrivingPollBackoffMs);
  });
}

function _scheduleNextSelfDrivingPoll(delayMs) {
  if (!_selfDrivingPollEnabled) return;
  if (_selfDrivingPollTimer) {
    clearTimeout(_selfDrivingPollTimer);
    _selfDrivingPollTimer = null;
  }
  var d = Math.max(0, delayMs | 0);
  _selfDrivingPollTimer = setTimeout(function () {
    _selfDrivingPollTimer = null;
    _runSelfDrivingPoll();
  }, d);
  if (_selfDrivingPollTimer && _selfDrivingPollTimer.unref) {
    _selfDrivingPollTimer.unref();
  }
}

function startSelfDrivingPoll() {
  if (_selfDrivingPollEnabled) return;
  if (_isSelfDrivingPollDisabled()) {
    try {
      console.log('[Events] Self-driving poll disabled via EVOLVER_DISABLE_SELF_DRIVING_POLL=1');
    } catch (_) {}
    return;
  }
  _selfDrivingPollEnabled = true;
  _selfDrivingPollBackoffMs = _SELF_DRIVING_POLL_BASE_MS;
  // Wait a short window before the first poll so hello / first heartbeat
  // can complete (the hub validates our nodeId on the poll endpoint and
  // would otherwise return 401 until /a2a/hello has run).
  _scheduleNextSelfDrivingPoll(2000);
}

function stopSelfDrivingPoll() {
  _selfDrivingPollEnabled = false;
  if (_selfDrivingPollTimer) {
    clearTimeout(_selfDrivingPollTimer);
    _selfDrivingPollTimer = null;
  }
}

// Called from the heartbeat tick when we exit unknown_node / reauth
// backoff so the runner picks up quickly instead of waiting on its
// quiet-mode schedule.
function _armSelfDrivingPollFromHeartbeat() {
  if (!_selfDrivingPollEnabled) return;
  // Round-8 (§21.2): the round-5..6 implementation had
  // `if (_pollInflight || _selfDrivingPollTimer) return;` here, which
  // defeated the whole purpose of this hook. All callers fire exactly
  // when transitioning OUT of an unknown_node / reauth backoff window,
  // which is precisely when the existing timer was set to
  // _SELF_DRIVING_POLL_QUIET_MS (5 min). The `|| _selfDrivingPollTimer`
  // early-return then made the re-arm a no-op and the poll stayed
  // asleep for the full 5 min after the gate cleared -- a 5-min event
  // delivery hole on top of the recovery the heartbeat had just done.
  // Keep only the _pollInflight gate (genuine single-flight protection)
  // and let _scheduleNextSelfDrivingPoll's clearTimeout replace the
  // stale quiet-mode timer with a fresh BASE_MS one.
  if (_pollInflight) return;
  _scheduleNextSelfDrivingPoll(_SELF_DRIVING_POLL_BASE_MS);
}

/**
 * Returns all buffered hub events (does not clear the buffer).
 */
function getHubEvents() {
  return _latestHubEvents;
}

/**
 * Returns and clears all buffered hub events.
 */
function consumeHubEvents() {
  const events = _latestHubEvents;
  _latestHubEvents = [];
  return events;
}

/**
 * Queue a commitment deadline update to be sent with the next heartbeat.
 * @param {string} taskId
 * @param {string} deadlineIso - ISO-8601 deadline
 * @param {boolean} [isAssignment] - true if this is a WorkAssignment
 */
function queueCommitmentUpdate(taskId, deadlineIso, isAssignment) {
  if (!taskId || !deadlineIso) return;
  _pendingCommitmentUpdates.push({
    task_id: taskId,
    deadline: deadlineIso,
    assignment: !!isAssignment,
  });
}

function startHeartbeat(intervalMs) {
  if (_heartbeatRunning) return;
  _heartbeatIntervalMs = intervalMs || require('../config').HEARTBEAT_INTERVAL_MS;
  _heartbeatStartedAt = Date.now();
  _heartbeatRunning = true;

  // Linux/systemd: signal READY=1 as soon as the heartbeat loop is armed.
  // The daemon is functionally up at this point -- hello may still be in
  // flight, but the heartbeat loop is scheduled and the process will not
  // exit voluntarily.  Sending READY=1 before hello completes lets systemd
  // move dependent units forward without waiting for the full hub round-trip
  // (which can be slow on cold boot when DNS / hub are not yet reachable).
  // Also start the watchdog timer so WatchdogSec= is satisfied even during
  // extended hub outages.
  startSystemdNotifyWatchdog();

  sendHelloToHub().then(function (r) {
    if (r.ok) console.log('[Heartbeat] Registered with hub. Node: ' + getNodeId());
    else console.warn('[Heartbeat] Hello failed (will retry via heartbeat): ' + (r.error || 'unknown'));
  }).catch(function (err) {
    console.warn('[Heartbeat] Hello during startup failed:', err && err.message || err);
  }).then(function () {
    if (!_heartbeatRunning) return;
    // First heartbeat after hello completes. Use the first-delay config (default
    // 30s) capped by the regular interval: min(first_delay, interval). With
    // Math.max the first delay was always equal to interval (6 min default),
    // completely defeating HEARTBEAT_FIRST_DELAY_MS -- the first heartbeat was
    // sent 6 min after hello instead of 30s, making the node appear inactive to
    // the hub for the first 6 min of every session.
    _scheduleNextHeartbeat(Math.min(require('../config').HEARTBEAT_FIRST_DELAY_MS, _heartbeatIntervalMs));
    // Round-5: start the self-driving long-poll alongside the heartbeat
    // loop so event delivery does not depend on heartbeat cadence or
    // SSE health. See _runSelfDrivingPoll for the cache-poisoning-aware
    // gating.
    try { startSelfDrivingPoll(); } catch (_) {}
  });

  // Wall-clock drift detector. setTimeout / setInterval fire on libuv's
  // monotonic clock, which freezes while the host is suspended -- so a
  // laptop closed for 2 hours and reopened would not trigger any heartbeat
  // tick until the next scheduled time, which under backoff can be up to
  // 30 minutes away. By sampling Date.now() (wall clock) we can detect the
  // jump and immediately poke the heartbeat to refresh liveness.
  // Mirrors LifecycleManager.startHeartbeatLoop in src/proxy/lifecycle/manager.js (#544).
  _heartbeatLastDriftCheckAt = Date.now();
  _heartbeatDriftInterval = setInterval(function () {
    // Wrap the whole body in try/catch so a thrown pokeHeartbeat (e.g. a
    // logger transport blowing up downstream) can never kill the detector
    // itself -- a dead detector is the bug we are protecting against.
    try {
      if (!_heartbeatRunning) return;
      var now = Date.now();
      var gap = now - _heartbeatLastDriftCheckAt;
      _heartbeatLastDriftCheckAt = now;
      // Round-4: QoS / cgroup-throttle diagnostic. On macOS, background QoS
      // demotion does NOT cause a wall-clock jump (the gap branch below stays
      // silent), but the process is scheduled for almost no CPU (~5% of one
      // core under App Nap). On Linux, a cgroup CPU quota (Docker --cpus=0.1,
      // systemd CPUQuota=10%) has the same observable fingerprint: wall-clock
      // advances normally (libuv timer polls are not charged against the
      // quota), but process.cpuUsage() barely advances because the kernel
      // throttle-sleeps the process after it exhausts the quota slice.
      // Comparing cpuUsage delta vs wall-clock delta detects both cases.
      // NOTE: unlike macOS App Nap, Linux cgroup throttling does NOT delay
      // setTimeout callbacks -- libuv epoll_wait is not CPU-quota-charged, so
      // the heartbeat interval is not stretched and offline risk is low.
      // Emit at most once per 5 min to avoid log spam during sustained throttle.
      try {
        if (_heartbeatLastCpuUsage && _heartbeatLastDriftWallClock > 0) {
          var cpuDelta = process.cpuUsage(_heartbeatLastCpuUsage);
          var cpuMs = (cpuDelta.user + cpuDelta.system) / 1000;
          var wallMs = now - _heartbeatLastDriftWallClock;
          // Only consider intervals close to the expected DRIFT_CHECK_MS;
          // a wake event already triggers the gap branch and we don't
          // want to double-warn there.
          if (wallMs > 20_000 && wallMs < 60_000 && cpuMs < 50 &&
              (now - _heartbeatQosThrottleWarnedAt) > 5 * 60_000) {
            _heartbeatQosThrottleWarnedAt = now;
            try {
              // Build a platform-specific RCA hint so operators see an
              // actionable message rather than a macOS-only suggestion on Linux.
              var _throttleHint;
              if (process.platform === 'darwin') {
                _throttleHint = 'macOS App Nap / QoS demotion may be throttling this process; ' +
                  'set EVOLVER_DISABLE_PRIORITY_BOOST=0 (default) or run with caffeinate.';
              } else if (process.platform === 'linux') {
                // Attempt to read cgroup v2 cpu.stat for authoritative throttle
                // evidence. /proc/self/cgroup line format:
                //   0::/system.slice/evolver.service   (v2 unified hierarchy)
                // cpu.stat contains throttled_usec which, if non-zero, confirms
                // kernel-level CPU quota enforcement rather than voluntary idle.
                var _cgroupThrottleDetail = '';
                try {
                  var _cgroupPath = fs.readFileSync('/proc/self/cgroup', 'utf8').trim();
                  // Find the cgroup v2 unified hierarchy entry (starts with "0::")
                  var _cgroupV2Line = _cgroupPath.split('\n').filter(function (l) {
                    return l.startsWith('0::');
                  })[0];
                  if (_cgroupV2Line) {
                    var _cgroupRelPath = _cgroupV2Line.slice(3).trim(); // strip "0::"
                    var _cpuStatPath = '/sys/fs/cgroup' + _cgroupRelPath + '/cpu.stat';
                    var _cpuStat = fs.readFileSync(_cpuStatPath, 'utf8');
                    var _throttledMatch = _cpuStat.match(/^throttled_usec\s+(\d+)/m);
                    if (_throttledMatch && parseInt(_throttledMatch[1], 10) > 0) {
                      _cgroupThrottleDetail = ' cgroup cpu.stat throttled_usec=' +
                        _throttledMatch[1] + ' confirms CPU quota enforcement.';
                    } else if (_throttledMatch) {
                      _cgroupThrottleDetail = ' cgroup cpu.stat throttled_usec=0 (quota not exhausted; may be cpuset or scheduling contention).';
                    }
                  }
                } catch (_cgroupErr) {
                  // cgroup v2 not mounted, v1-only hierarchy, or permission
                  // denied -- fall through without the extra detail.
                }
                _throttleHint = 'Linux cgroup CPU quota or cpuset may be throttling this process.' +
                  _cgroupThrottleDetail + ' ' +
                  'Check: docker inspect --format "{{.HostConfig.NanoCpus}}" <container> ' +
                  'or systemctl show evolver | grep CPUQuota. ' +
                  'Note: unlike macOS App Nap, cgroup throttle does NOT delay setTimeout, ' +
                  'so heartbeat intervals are not stretched -- offline risk is low.';
              } else {
                _throttleHint = 'Process may be CPU-throttled by the OS scheduler.';
              }
              console.warn(
                '[Heartbeat] suspected CPU throttle: wall-clock advanced ' +
                Math.round(wallMs / 1000) + 's but CPU only ' + Math.round(cpuMs) +
                'ms (ratio ' + (cpuMs / wallMs).toFixed(4) + '). ' +
                _throttleHint
              );
            } catch (_) {}
          }
        }
      } catch (_) { /* cpuUsage not available on this platform */ }
      try { _heartbeatLastCpuUsage = process.cpuUsage(); } catch (_) {}
      _heartbeatLastDriftWallClock = now;
      if (gap > DRIFT_SLEEP_THRESHOLD_MS) {
        try {
          console.warn(
            '[Heartbeat] wall-clock jump detected (+' + Math.round(gap / 1000) + 's); ' +
            'likely sleep/wake or process suspension, poking heartbeat'
          );
        } catch (_) { /* logger broken; detector must still poke */ }
        // Long-sleep recovery: if the gap is large enough that hub-side
        // state we cached is almost certainly stale, force a clean retry
        // path on wake instead of carrying the pre-sleep penalty through.
        // pokeHeartbeat() only clears the reauth backoff when
        // _heartbeatConsecutiveReauthFailures < 2 -- but a laptop closed
        // overnight could easily have hit deepReauthFailure during the
        // last awake window via natural ticks. Without this branch the
        // node stays silent for up to 4h after wake even though the
        // underlying hub state has long since changed.
        if (gap > DRIFT_LONG_SLEEP_THRESHOLD_MS) {
          _heartbeatConsecutiveReauthFailures = 0;
          _heartbeatReauthBackoffUntil = 0;
          // Round-6 (§19.7): clear the unknown_node backoff deadline
          // too. A laptop closed for several hours may carry a
          // pre-sleep _unknownNodeBackoffUntil that survived only
          // because the resumed wall-clock has not yet advanced past
          // it (NTP step-backward correction on wake can produce this
          // exact pattern). Without the explicit clear, the gate added
          // in §19.1 to pokeHeartbeat plus the drift detector's
          // persistent-failure gate both refuse to drive the next tick
          // until the stale deadline expires on resumed wall-clock --
          // up to 8 min of post-wake silence for no good reason.
          _unknownNodeBackoffUntil = 0;
          _consecutiveUnknownNodeAfterHello = 0;
          // Also re-arm fingerprint resend. Hub-side rolling restarts
          // or migrations during the sleep window may have dropped the
          // node card's env_fingerprint / evolver_version; the
          // once-per-process flag would otherwise pin those fields to
          // empty until the next process restart.
          _heartbeatFpSent = false;
          // Reset SSE exponential backoff. Pre-sleep flaps may have
          // saturated _sseReconnectMs at 120s; on a fresh wake we want
          // the first reconnect attempt within seconds, not minutes.
          try { _resetSseReconnectBackoff(); } catch (_) {}
        }
        // Round-7 (§20.1): if a heartbeat tick was awaiting sendHeartbeat()
        // at the moment of suspend (undici socket bound to a 5-tuple the
        // NAT silently dropped during sleep, AbortSignal frozen on the
        // monotonic clock), _heartbeatInFlight is still true on wake.
        // pokeHeartbeat() inside _runWakeRecovery() would early-return
        // "true" at the single-flight gate without scheduling anything,
        // and the hung-tick watchdog below cannot fire either because
        // we are about to zero _heartbeatLastTickAt (its truthy guard).
        // The result: the entire wake-recovery rite runs, but the
        // heartbeat loop sits silent forever; getHeartbeatStats() reports
        // running:true with lastTickAt stuck near the pre-sleep value
        // (then forced to 0 by the next line) -- exactly the user-
        // reported "alive but lastTickAt frozen" symptom. Clear the gate
        // here so the wake poke can actually drive a fresh tick.
        // Round-9: bump the tick generation so the pre-sleep wedged tick's
        // late continuation (if its socket ever unblocks) cannot re-clear
        // the gate or schedule a duplicate timer behind the wake tick.
        _heartbeatTickGeneration++;
        _heartbeatInFlight = false;
        // Force the wake poke past pokeHeartbeat's "healthy + recent
        // tick" debounce: post-sleep _heartbeatLastTickAt is meaningless
        // (monotonic timer froze through sleep). Without this the
        // healthy-node throttle can suppress the wake poke entirely and
        // we sit silent until the next natural setTimeout fire -- on
        // the resumed monotonic clock, up to a full interval away.
        _heartbeatLastTickAt = 0;
        // Round-6 (§19.5): full wake recovery -- drainPool + pokeHeartbeat
        // + restart SSE + interrupt sleepMs + poke validator. Replaces a
        // bare pokeHeartbeat() that left undici sockets bound to
        // NAT-evicted 5-tuples, validator dormant, and the outer evolve
        // loop's sleepMs sitting out the rest of its pre-suspend window.
        _runWakeRecovery();
        // Round-8 (§21.10): re-stamp _heartbeatLastTickAt so the hung-
        // tick watchdog at :2444 has a usable baseline. Pre-round-8 the
        // wake branch zeroed lastTickAt at :2379 (to defeat pokeHeartbeat
        // throttle, which is correct) but never restored a non-zero
        // value -- the watchdog's truthy guard
        // `_heartbeatInFlight && _heartbeatLastTickAt && ...` then
        // refused to fire on the very next wedged tick because
        // lastTickAt was still 0. If the setImmediate(_heartbeatTick)
        // queued by pokeHeartbeat inside _runWakeRecovery is dropped
        // (event-loop starvation, gc pause, post-wake task storm),
        // we'd sit silent forever with the watchdog blind. Stamping
        // here gives the watchdog a measurable baseline; the next real
        // tick that actually runs will overwrite this stamp at its
        // own entry. Belt-and-suspenders schedule too in case
        // pokeHeartbeat's setImmediate path is dropped -- the
        // single-flight gate prevents duplicate ticks.
        _heartbeatLastTickAt = now;
        try { _scheduleNextHeartbeat(2_000); } catch (_) {}
        // Fall through to the hung-tick watchdog below. A tick wedged
        // through sleep (single-flight gate stuck on _heartbeatInFlight)
        // would otherwise wait until the NEXT drift sample 30s later
        // before the watchdog evaluates -- and during that window
        // pokeHeartbeat() returns true ("in-flight is liveness proof")
        // without scheduling anything. The wedged-through-sleep tick is
        // exactly the path the watchdog exists to clear.
      }
      // Race recovery (Task #14, port of evolver#544 commit 464c009): on
      // macOS wake the setInterval (this detector) and the setTimeout
      // (heartbeat tick) fire near-simultaneously. If the tick enters first,
      // _heartbeatInFlight=true and a wall-clock-gap-driven poke would no-op
      // via the single-flight gate. That post-wake tick almost always fails
      // (WiFi/DNS not up yet), bumping _heartbeatConsecutiveFailures to 1.
      // The default-mode loop has no exponential backoff, so the next
      // scheduled tick is still _heartbeatIntervalMs (~6 min default) away.
      // By the next drift sample 30s later, gap < 90s and no poke fires --
      // the user is stuck silent for up to 6 min even though the network
      // came back almost immediately.
      //
      // Mitigation (Approach B from the public-repo review): if we already
      // have a recent failure AND it's been longer than 2*interval since
      // the last tick, poke again. pokeHeartbeat's throttle / single-flight
      // gate still protects healthy nodes (this branch never runs when
      // _heartbeatConsecutiveFailures === 0).
      var sinceLastTick = now - (_heartbeatLastTickAt || now);
      // Round-5: respect the unknown_node backoff deadline. The drift
      // detector previously bypassed it on every 30s sample because the
      // unknown_node branch raises _heartbeatConsecutiveFailures (to keep
      // long-term recovery alive in case the cache TTL is mis-configured)
      // and the persistent-failure check below treats any consecutive
      // failure as license to poke. Pre-round-5 this drove the same
      // cached unknown_node every 30s, snowballing the counter until the
      // hub IP rate limit kicked in. The deadline gives the cache a real
      // chance to expire instead of being hammered.
      var unknownNodeBackoffActive = _unknownNodeBackoffUntil > now;
      if (
        _heartbeatConsecutiveFailures > 0
        && _heartbeatLastTickAt
        && sinceLastTick > 2 * _heartbeatIntervalMs
        && !unknownNodeBackoffActive
      ) {
        try {
          console.warn(
            '[Heartbeat] persistent failure (' + _heartbeatConsecutiveFailures + ') and no tick for ' +
            Math.round(sinceLastTick / 1000) + 's; poking heartbeat'
          );
        } catch (_) { /* logger broken; detector must still poke */ }
        pokeHeartbeat();
      }
      // Hung-tick watchdog. _heartbeatLastTickAt is stamped at tick ENTRY,
      // so a tick that hangs forever (await on a fetch that never settles,
      // promise chain that drops on the floor, etc.) leaves
      // _heartbeatInFlight=true and a stale _heartbeatLastTickAt that
      // looks healthy to the persistent-failure branch above. If we've
      // been "in flight" for more than 3 intervals (and at least 5 min),
      // assume the tick is wedged: clear the single-flight gate and
      // force-reschedule so the loop can recover.
      if (
        _heartbeatInFlight
        && _heartbeatLastTickAt
        && (now - _heartbeatLastTickAt) > Math.max(3 * _heartbeatIntervalMs, 5 * 60_000)
      ) {
        try {
          console.warn(
            '[Heartbeat] tick stuck in flight for ' +
            Math.round((now - _heartbeatLastTickAt) / 1000) +
            's; forcing reschedule'
          );
        } catch (_) { /* logger broken; watchdog must still reschedule */ }
        // Round-9: supersede the wedged tick so its late continuation
        // cannot double-clear the gate / double-schedule behind the
        // tick this watchdog is about to start.
        _heartbeatTickGeneration++;
        _heartbeatInFlight = false;
        _scheduleNextHeartbeat(0);
      }
    } catch (_) { /* never let the detector escape */ }
  }, DRIFT_CHECK_MS);
  // Don't keep the event loop alive on behalf of the detector alone --
  // matches the unref() used on the heartbeat timer above.
  if (_heartbeatDriftInterval && _heartbeatDriftInterval.unref) _heartbeatDriftInterval.unref();
}

function stopHeartbeat() {
  _heartbeatRunning = false;
  if (_heartbeatTimer) {
    clearTimeout(_heartbeatTimer);
    _heartbeatTimer = null;
  }
  if (_heartbeatDriftInterval) {
    clearInterval(_heartbeatDriftInterval);
    _heartbeatDriftInterval = null;
  }
  // Stop the systemd watchdog timer so it doesn't fire after the loop ends.
  _stopSdWatchdog();
  _heartbeatLastDriftCheckAt = 0;
  // Reset poke-throttle bookkeeping so a stop/start cycle (e.g. tests or a
  // future supervisor) doesn't carry stale "last tick" timestamps into
  // the next lifetime, which would suppress the first poke.
  _heartbeatLastTickAt = 0;
  // Reset reauth-backoff bookkeeping so a stopped-and-restarted loop does
  // not inherit a stale backoff window from a previous lifetime.
  _heartbeatReauthBackoffUntil = 0;
  _heartbeatConsecutiveReauthFailures = 0;
  _heartbeatLastReauthProbeAt = 0;
  // Reset rate_limited backoff signal. Without this, a stop() called
  // mid-rate-limit (admin restart, supervisor flap) lets the stale
  // pending value silently inflate the FIRST reschedule of the next
  // lifetime via the max(pending, requested) rule in
  // _scheduleNextHeartbeat. Tests are also affected -- a previous test
  // that exercised the rate_limited branch could leak the delay into a
  // sibling test even after _resetHeartbeatStateForTesting (now also
  // fixed below).
  _pendingRescheduleDelayMs = 0;
  // Reset in-flight gate so a wedged tick from the prior lifetime can
  // never block the next startHeartbeat() from driving a fresh tick.
  // Round-9: bump the generation too so a prior-lifetime tick that resolves
  // after restart cannot clear the new lifetime's gate or reschedule.
  _heartbeatTickGeneration++;
  _heartbeatInFlight = false;
  // Round-4: unknown_node loop counter is per-lifetime; clearing it here
  // matches the rest of the per-lifetime state and prevents a previous
  // cache-poisoning episode from inflating the next lifetime's first
  // unknown_node response into an immediate backoff.
  _consecutiveUnknownNodeAfterHello = 0;
  // Round-5: clear unknown_node backoff deadline and self-driving poll.
  _unknownNodeBackoffUntil = 0;
  // Round-8 (§21.9): round-7 added _pendingSelfDrivingPollDelayMs as a
  // module-global retry-after override but forgot to clear it here.
  // A stop() called mid-429 -- or a test that exercised the 429 path
  // -- would otherwise leak a >=16s delay into the next startHeartbeat
  // lifetime (or the next test). Symmetric to the
  // _pendingRescheduleDelayMs clear above.
  _pendingSelfDrivingPollDelayMs = 0;
  try { stopSelfDrivingPoll(); } catch (_) {}
}

function getHeartbeatStats() {
  return {
    running: _heartbeatRunning,
    intervalMs: _heartbeatIntervalMs,
    uptimeMs: _heartbeatStartedAt ? Date.now() - _heartbeatStartedAt : 0,
    totalSent: _heartbeatTotalSent,
    totalFailed: _heartbeatTotalFailed,
    consecutiveFailures: _heartbeatConsecutiveFailures,
    // Round-4: surface penalty-state fields so ops tooling and the
    // `evolver doctor` CLI can distinguish "running but in backoff" from
    // "running and healthy". Without these, getHeartbeatStats() showed
    // `running: true, lastTickAt: <recent>` even when the loop was silent
    // for 30 min waiting on a reauth backoff, matching the user-perceived
    // "node looks dead" symptom without giving ops a way to confirm it.
    consecutiveReauthFailures: _heartbeatConsecutiveReauthFailures,
    reauthBackoffUntil: _heartbeatReauthBackoffUntil,
    consecutiveUnknownNodeAfterHello: _consecutiveUnknownNodeAfterHello,
    // Round-5: expose the absolute deadline for the unknown_node
    // cache-poisoning backoff and the self-driving poll state so ops
    // tooling can show "waiting on hub cache" vs "running but no
    // events" without re-reading the source.
    unknownNodeBackoffUntil: _unknownNodeBackoffUntil,
    selfDrivingPollEnabled: _selfDrivingPollEnabled,
    selfDrivingPollBackoffMs: _selfDrivingPollBackoffMs,
    lastTickAt: _heartbeatLastTickAt,
  };
}

// --- Transport registry ---

const transports = {
  file: {
    send: fileTransportSend,
    receive: fileTransportReceive,
    list: fileTransportList,
  },
  http: {
    send: httpTransportSend,
    receive: httpTransportReceive,
    list: httpTransportList,
  },
};

function getTransport(name) {
  const n = String(name || process.env.A2A_TRANSPORT || 'file').toLowerCase();
  const t = transports[n];
  if (!t) throw new Error('Unknown A2A transport: ' + n + '. Available: ' + Object.keys(transports).join(', '));
  return t;
}

function registerTransport(name, impl) {
  if (!name || typeof name !== 'string') throw new Error('transport name required');
  if (!impl || typeof impl.send !== 'function' || typeof impl.receive !== 'function') {
    throw new Error('transport must implement send() and receive()');
  }
  transports[name] = impl;
}

// --- Hub Infrastructure Helpers ---
// These wrap the agent infrastructure endpoints added to evomap-hub,
// enabling evolver instances to self-provision, transfer credits,
// manage identity, and query audit logs programmatically.

function _hubPost(pathSuffix, body, timeoutMs) {
  if (_isDryRun()) return Promise.resolve({ ok: true, dry_run: true });
  var hubUrl = getHubUrl();
  if (!hubUrl) return Promise.resolve({ ok: false, error: 'no_hub_url' });
  var endpoint = hubUrl.replace(/\/+$/, '') + pathSuffix;
  var timeout = timeoutMs || require('../config').HTTP_TRANSPORT_TIMEOUT_MS;
  return hubFetch(endpoint, {
    method: 'POST',
    headers: buildNodeScopedHubHeaders(),
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeout),
  })
    .then(function (res) {
      if (!res.ok) return res.text().then(function (t) { return { ok: false, status: res.status, error: t.slice(0, 400) }; });
      return res.json().then(function (data) { return { ok: true, data: data }; });
    })
    .catch(function (err) { return { ok: false, error: err.message }; });
}

function _hubGet(pathSuffix, timeoutMs) {
  if (_isDryRun()) return Promise.resolve({ ok: true, dry_run: true });
  var hubUrl = getHubUrl();
  if (!hubUrl) return Promise.resolve({ ok: false, error: 'no_hub_url' });
  var endpoint = hubUrl.replace(/\/+$/, '') + pathSuffix;
  var timeout = timeoutMs || require('../config').HTTP_TRANSPORT_TIMEOUT_MS;
  return hubFetch(endpoint, {
    method: 'GET',
    headers: buildNodeScopedHubHeaders(),
    signal: AbortSignal.timeout(timeout),
  })
    .then(function (res) {
      if (!res.ok) return res.text().then(function (t) { return { ok: false, status: res.status, error: t.slice(0, 400) }; });
      return res.json().then(function (data) { return { ok: true, data: data }; });
    })
    .catch(function (err) { return { ok: false, error: err.message }; });
}

/**
 * Self-provision a machine account on the hub.
 * POST /a2a/provision
 */
function hubSelfProvision(opts) {
  var nodeId = (opts && opts.nodeId) || getNodeId();
  return _hubPost('/a2a/provision', {
    node_id: nodeId,
    sender_id: nodeId,
    label: (opts && opts.label) || undefined,
    description: (opts && opts.description) || undefined,
  });
}

/**
 * Programmatically top up credits on the hub.
 * POST /a2a/credit/topup
 */
function hubCreditTopUp(amount, opts) {
  var nodeId = (opts && opts.nodeId) || getNodeId();
  var safeAmount = Math.max(0, Number(amount) || 0);
  return _hubPost('/a2a/credit/topup', {
    node_id: nodeId,
    sender_id: nodeId,
    amount: safeAmount,
    idempotency_key: (opts && opts.idempotencyKey) || undefined,
  });
}

/**
 * Transfer credits to another agent on the hub.
 * POST /a2a/credit/transfer
 */
function hubCreditTransfer(toNodeId, amount, opts) {
  var fromNodeId = (opts && opts.fromNodeId) || getNodeId();
  var safeAmount = Math.max(0, Number(amount) || 0);
  return _hubPost('/a2a/credit/transfer', {
    from_node_id: fromNodeId,
    sender_id: fromNodeId,
    to_node_id: toNodeId,
    amount: safeAmount,
    reason: (opts && opts.reason) || 'agent_transfer',
    reference_id: (opts && opts.referenceId) || undefined,
    meta: (opts && opts.meta) || undefined,
  });
}

/**
 * Create a recipe (DNA blueprint) on the hub from owned Gene/Capsule assets.
 * Recipes are created as drafts; publishing is a separate, explicit step
 * (hubPublishRecipe) so autonomous flows never push to the live marketplace
 * without an intentional publish.
 * POST /a2a/recipe
 *
 * @param {{ title: string, steps: Array<{asset_id: string, asset_type: string, position?: number}>,
 *   description?: string, pricePerExecution?: number, currency?: string, maxConcurrent?: number,
 *   nodeId?: string }} params
 */
function hubCreateRecipe(params) {
  params = params || {};
  var nodeId = params.nodeId || getNodeId();
  return _hubPost('/a2a/recipe', {
    node_id: nodeId,
    sender_id: nodeId,
    title: params.title,
    steps: params.steps,
    description: params.description || undefined,
    price_per_execution: params.pricePerExecution || undefined,
    currency: params.currency || undefined,
    max_concurrent: params.maxConcurrent || undefined,
  });
}

/**
 * Publish a draft recipe to the live marketplace. Explicit, separate from
 * creation by design.
 * POST /a2a/recipe/:id/publish
 */
function hubPublishRecipe(recipeId, opts) {
  var nodeId = (opts && opts.nodeId) || getNodeId();
  return _hubPost('/a2a/recipe/' + encodeURIComponent(recipeId) + '/publish', {
    node_id: nodeId,
    sender_id: nodeId,
  });
}

/**
 * Fetch a recipe by id (public, no node secret required).
 * GET /a2a/recipe/:id
 */
function hubGetRecipe(recipeId) {
  return _hubGet('/a2a/recipe/' + encodeURIComponent(recipeId));
}

/**
 * Express (run) a recipe into an organism. Charged per execution.
 * POST /a2a/recipe/:id/express
 */
function hubExpressRecipe(recipeId, inputPayload, opts) {
  var nodeId = (opts && opts.nodeId) || getNodeId();
  return _hubPost('/a2a/recipe/' + encodeURIComponent(recipeId) + '/express', {
    node_id: nodeId,
    sender_id: nodeId,
    input_payload: inputPayload || {},
  });
}

/**
 * Get transfer fee estimate.
 * GET /a2a/credit/transfer/estimate?amount=N
 */
function hubTransferEstimate(amount) {
  return _hubGet('/a2a/credit/transfer/estimate?amount=' + (Number(amount) || 0));
}

/**
 * Get own transfer history.
 * GET /a2a/credit/transfer/history?node_id=...
 */
function hubTransferHistory(opts) {
  var nodeId = (opts && opts.nodeId) || getNodeId();
  var limit = (opts && opts.limit) || 20;
  var offset = (opts && opts.offset) || 0;
  var dir = (opts && opts.direction) || '';
  var qs = 'node_id=' + encodeURIComponent(nodeId) + '&limit=' + limit + '&offset=' + offset;
  if (dir) qs += '&direction=' + encodeURIComponent(dir);
  return _hubGet('/a2a/credit/transfer/history?' + qs);
}

/**
 * Get portable identity profile of any node.
 * GET /a2a/identity/:nodeId
 */
function hubGetIdentity(nodeId) {
  var nid = nodeId || getNodeId();
  return _hubGet('/a2a/identity/' + encodeURIComponent(nid));
}

/**
 * Get a verifiable reputation attestation.
 * GET /a2a/identity/:nodeId/attestation
 */
function hubGetAttestation(nodeId) {
  var nid = nodeId || getNodeId();
  return _hubGet('/a2a/identity/' + encodeURIComponent(nid) + '/attestation');
}

/**
 * Verify a reputation attestation.
 * POST /a2a/identity/verify
 */
function hubVerifyAttestation(attestation) {
  return _hubPost('/a2a/identity/verify', attestation);
}

/**
 * Set a DID document for the current node.
 * POST /a2a/identity/did
 */
function hubSetDid(didDocument, didMethod) {
  var nodeId = getNodeId();
  return _hubPost('/a2a/identity/did', {
    node_id: nodeId,
    sender_id: nodeId,
    did_document: didDocument,
    did_method: didMethod || 'did:evomap',
  });
}

/**
 * Get own audit logs.
 * GET /a2a/audit/:nodeId
 */
function hubGetAuditLogs(opts) {
  var nodeId = (opts && opts.nodeId) || getNodeId();
  var limit = (opts && opts.limit) || 50;
  var offset = (opts && opts.offset) || 0;
  var qs = '?node_id=' + encodeURIComponent(nodeId) + '&limit=' + limit + '&offset=' + offset;
  if (opts && opts.action) qs += '&action=' + encodeURIComponent(opts.action);
  if (opts && opts.since) qs += '&since=' + encodeURIComponent(opts.since);
  if (opts && opts.until) qs += '&until=' + encodeURIComponent(opts.until);
  return _hubGet('/a2a/audit/' + encodeURIComponent(nodeId) + qs);
}

/**
 * Get a generated work report.
 * GET /a2a/audit/:nodeId/report
 */
function hubGetWorkReport(opts) {
  var nodeId = (opts && opts.nodeId) || getNodeId();
  var days = (opts && opts.days) || 7;
  return _hubGet('/a2a/audit/' + encodeURIComponent(nodeId) + '/report?node_id=' + encodeURIComponent(nodeId) + '&days=' + days);
}

function _buildEventStreamHeaders() {
  var headers = {};
  var secret = getHubNodeSecret();
  if (secret) {
    headers['Authorization'] = 'Bearer ' + secret;
  }
  var secretVersion = getHubNodeSecretVersion();
  if (secretVersion) {
    headers['X-EvoMap-Node-Secret-Version'] = String(secretVersion);
  }
  return headers;
}

function _emitFetchSseFrame(es, frame) {
  if (!frame) return;
  var lines = String(frame).replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
  var data = [];
  var eventName = '';
  var lastEventId = '';
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (!line || line.charAt(0) === ':') continue;
    var idx = line.indexOf(':');
    var field = idx === -1 ? line : line.slice(0, idx);
    var value = idx === -1 ? '' : line.slice(idx + 1);
    if (value.charAt(0) === ' ') value = value.slice(1);
    if (field === 'data') data.push(value);
    else if (field === 'event') eventName = value;
    else if (field === 'id') lastEventId = value;
  }
  if (data.length === 0) return;
  var ev = {
    data: data.join('\n'),
    type: eventName || 'message',
    lastEventId: lastEventId,
  };
  if (typeof es.onmessage === 'function') {
    es.onmessage(ev);
  }
}

function _openFetchEventStream(endpoint, headers, durationMs) {
  var controller = new AbortController();
  var closed = false;
  var es = {
    onmessage: null,
    onerror: null,
    close: function () {
      closed = true;
      try { controller.abort(); } catch (_) {}
    },
  };
  var timeoutMs = Math.max(1, Number(durationMs) || 300000) + 15000;
  var timer = setTimeout(function () {
    try { controller.abort(); } catch (_) {}
  }, timeoutMs);
  if (timer && timer.unref) timer.unref();

  hubFetch(endpoint, {
    method: 'GET',
    headers: headers,
    signal: controller.signal,
  }).then(async function (res) {
    if (!res.ok) {
      // Drain the body so undici returns the _eventStreamAgent socket to the
      // pool. Leaving a non-ok SSE-open reply un-consumed leaks one socket
      // per failed open; over repeated reconnect attempts that exhausts the
      // dispatcher pool (same leak class fixed in httpTransportReceive).
      try { if (res.body && typeof res.body.cancel === 'function') res.body.cancel().catch(function () {}); } catch (_) {}
      throw new Error('event_stream_http_' + res.status);
    }
    if (!res.body || typeof res.body.getReader !== 'function') {
      try { if (res.body && typeof res.body.cancel === 'function') res.body.cancel().catch(function () {}); } catch (_) {}
      throw new Error('event_stream_body_unavailable');
    }
    var reader = res.body.getReader();
    var decoder = new TextDecoder();
    var buffer = '';
    try {
      while (!closed) {
        var part = await reader.read();
        if (part.done) break;
        buffer += decoder.decode(part.value || Buffer.alloc(0), { stream: true });
        var normalized = buffer.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
        var sep;
        while ((sep = normalized.indexOf('\n\n')) !== -1) {
          var frame = normalized.slice(0, sep);
          normalized = normalized.slice(sep + 2);
          _emitFetchSseFrame(es, frame);
        }
        buffer = normalized;
      }
      buffer += decoder.decode();
      if (buffer.trim()) _emitFetchSseFrame(es, buffer);
    } finally {
      try { if (reader && typeof reader.releaseLock === 'function') reader.releaseLock(); } catch (_) {}
    }
    if (!closed && typeof es.onerror === 'function') {
      es.onerror(new Error('event_stream_closed'));
    }
  }).catch(function (err) {
    if (!closed && typeof es.onerror === 'function') {
      es.onerror(err);
    }
  }).finally(function () {
    try { clearTimeout(timer); } catch (_) {}
  });

  return es;
}

/**
 * Open a Server-Sent Events stream for real-time hub notifications.
 * Returns an object with { ok, eventSource, close() } on success.
 * The caller should attach event listeners to eventSource.
 * GET /a2a/events/stream?node_id=...
 */
function hubOpenEventStream(opts) {
  if (_isDryRun()) return { ok: false, dry_run: true, eventSource: null, close: function() {} };
  var hubUrl = getHubUrl();
  if (!hubUrl) return { ok: false, error: 'no_hub_url' };

  var nodeId = (opts && opts.nodeId) || getNodeId();
  var durationMs = (opts && opts.durationMs) || 300000;
  var qs = 'node_id=' + encodeURIComponent(nodeId) + '&duration_ms=' + encodeURIComponent(durationMs);
  var endpoint = hubUrl.replace(/\/+$/, '') + '/a2a/events/stream?' + qs;

  var forceFetchFallback = opts && opts.forceFetchFallback === true;
  var EventSource = forceFetchFallback ? null : globalThis.EventSource;
  if (!EventSource && !forceFetchFallback) {
    try {
      var _mod = require('eventsource');
      EventSource = (typeof _mod === 'function') ? _mod : (_mod.EventSource || _mod.default);
    } catch (e) {}
  }

  try {
    var headers = _buildEventStreamHeaders();
    if (typeof EventSource === 'function') {
      var esOpts = {};
      if (Object.keys(headers).length) {
        esOpts.headers = headers;
      }
      var es = new EventSource(endpoint, esOpts);
      return {
        ok: true,
        eventSource: es,
        close: function () { es.close(); },
      };
    }

    var fetchEs = _openFetchEventStream(endpoint, headers, durationMs);
    return {
      ok: true,
      eventSource: fetchEs,
      close: function () { fetchEs.close(); },
    };
  } catch (err) {
    return { ok: false, error: 'eventsource_init_failed: ' + (err.message || err) };
  }
}

// ---------------------------------------------------------------------------
// Managed SSE stream -- starts/stops alongside the heartbeat loop.
// Events are buffered into _latestHubEvents for consumption by evolve.js.
// Falls back gracefully to poll-based events if SSE is unavailable.
// ---------------------------------------------------------------------------

var _activeStream = null;
var _activeStreamOpenedAt = 0;
var _sseReconnectTimer = null;
var _sseReconnectMs = 5000;
var _sseMaxReconnectMs = 120000;
var _SSE_RECONNECT_BASE_MS = 5000;
var _SSE_STABLE_RESET_MS = 30000;

// Reset SSE reconnect backoff to the base interval. Called from the drift
// detector's long-sleep branch: pre-sleep flaps may have doubled
// _sseReconnectMs all the way to the 120s ceiling, and on a fresh wake we
// want the first reconnect attempt within seconds. Exposed via _testing
// for unit coverage but also used internally from the long-sleep branch.
function _resetSseReconnectBackoff() {
  _sseReconnectMs = _SSE_RECONNECT_BASE_MS;
}

function _wasActiveStreamStable() {
  return _activeStreamOpenedAt > 0 && (Date.now() - _activeStreamOpenedAt) >= _SSE_STABLE_RESET_MS;
}

function _scheduleSseReconnect() {
  if (_sseReconnectTimer) {
    clearTimeout(_sseReconnectTimer);
  }
  _sseReconnectTimer = setTimeout(function () {
    _sseReconnectTimer = null;
    startEventStream();
  }, _sseReconnectMs);
  if (_sseReconnectTimer && _sseReconnectTimer.unref) _sseReconnectTimer.unref();
  _sseReconnectMs = Math.min(_sseReconnectMs * 2, _sseMaxReconnectMs);
}

function startEventStream() {
  if (_activeStream) return;
  if (process.env.EVOLVER_SSE_DISABLED === '1') return;

  var result = hubOpenEventStream({ durationMs: 600000 });
  if (!result.ok) {
    // Previous behavior was to log once and silently give up. That left
    // SSE permanently dead on transient open failures: hub URL briefly
    // unreadable on wake, secret not yet persisted from a concurrent
    // hello, hub TLS handshake failing because resumed v6 route is
    // black-holed. The only recovery was SIGCONT-driven restart, which
    // requires the OS to actually send SIGCONT and the user to wait. We
    // now schedule the same exponential reconnect we use for onerror so
    // a soft-open failure resolves automatically. The early no-op gate
    // for EVOLVER_SSE_DISABLED above is unchanged: explicit opt-out
    // still means "stay off".
    console.log('[SSE] Event stream unavailable: ' + (result.error || 'unknown') + ' (will retry in ' + Math.round(_sseReconnectMs / 1000) + 's)');
    // Round-5: SSE silently failing is the most common reason events
    // never reach the node (Node 22.x EventSource is experimental, the
    // `eventsource` fallback module is not in node_modules on default
    // installs, hubs behind some TLS-terminating proxies drop SSE
    // upgrades). Record the failure so the next "I never saw the event"
    // RCA can confirm SSE was the missing link. The self-driving
    // long-poll added in this round means events still flow even when
    // this branch repeats forever.
    _appendHeartbeatLog({
      type: 'sse_open_failed',
      error: result.error || 'unknown',
      reconnectInMs: _sseReconnectMs,
    });
    _scheduleSseReconnect();
    return;
  }

  _activeStream = result;
  _activeStreamOpenedAt = Date.now();
  console.log('[SSE] Event stream connected');
  _appendHeartbeatLog({ type: 'sse_connected' });

  result.eventSource.onmessage = function (ev) {
    try {
      var parsed = JSON.parse(ev.data);
      if (parsed && parsed.type) {
        _latestHubEvents.push(parsed);
        // Enforce the same 200-event ring-buffer cap the poll path uses
        // (search _MAX_BUFFERED_EVENTS). Without this, an SSE storm
        // (mass-broadcast event, hub bug, attacker flooding) gradually
        // bloats memory until process restart -- noticeable on long-uptime
        // daemons.
        var MAX_BUFFERED_EVENTS = 200;
        if (_latestHubEvents.length > MAX_BUFFERED_EVENTS) {
          var dropped = _latestHubEvents.length - MAX_BUFFERED_EVENTS;
          _latestHubEvents = _latestHubEvents.slice(-MAX_BUFFERED_EVENTS);
          try {
            console.warn('[SSE] Buffer overflow: dropped ' + dropped + ' oldest event(s).');
          } catch (_) {}
        }
      }
    } catch (e) {}
  };

  result.eventSource.onerror = function () {
    if (_wasActiveStreamStable()) _resetSseReconnectBackoff();
    console.warn('[SSE] Stream error, will reconnect in ' + Math.round(_sseReconnectMs / 1000) + 's');
    _appendHeartbeatLog({
      type: 'sse_error',
      reconnectInMs: _sseReconnectMs,
    });
    stopEventStream();
    _scheduleSseReconnect();
  };
}

function stopEventStream() {
  if (_activeStream) {
    try { _activeStream.close(); } catch (e) {}
    _activeStream = null;
  }
  _activeStreamOpenedAt = 0;
  if (_sseReconnectTimer) {
    clearTimeout(_sseReconnectTimer);
    _sseReconnectTimer = null;
  }
  // Backoff reset intentionally NOT done here: onerror's teardown path runs
  // through this function, so resetting would defeat exponential escalation
  // on persistent SSE failures. Explicit reset sites are stable stream errors
  // and _resetSseReconnectBackoff() in wake recovery.
}

function isEventStreamActive() {
  return _activeStream !== null;
}

module.exports = {
  PROTOCOL_NAME,
  PROTOCOL_VERSION,
  VALID_MESSAGE_TYPES,
  getNodeId,
  buildMessage,
  buildHello,
  buildPublish,
  buildPublishBundle,
  buildFetch,
  buildReport,
  buildDecision,
  buildRevoke,
  isValidProtocolMessage,
  unwrapAssetFromMessage,
  getTransport,
  registerTransport,
  fileTransportSend,
  fileTransportReceive,
  fileTransportList,
  httpTransportSend,
  httpTransportReceive,
  httpTransportList,
  sendHeartbeat,
  sendHelloToHub,
  rotateNodeSecret: _sendHelloWithRotate,
  getHubNodeSecretVersion,
  startHeartbeat,
  startSystemdNotifyWatchdog,
  stopHeartbeat,
  pokeHeartbeat,
  getHeartbeatStats,
  // Round-6 (§19.5): wake recovery API. Owners of process-level wake
  // side-effects (sleepMs interrupter, validator daemon, future sub-
  // process hooks) register a function via registerWakeHook; both
  // SIGCONT and the drift detector's long-sleep branch drive
  // _runWakeRecovery to run them in addition to the heartbeat-internal
  // recovery.
  registerWakeHook,
  _runWakeRecovery,
  // Linux systemd sd_notify helper. Exported so index.js can send
  // RELOADING=1 / READY=1 around SIGHUP reload handling without
  // duplicating the socket logic. No-op on non-Linux or when
  // NOTIFY_SOCKET is not set.
  _sdNotify,
  getLatestAvailableWork,
  consumeAvailableWork,
  getOverdueTasks,
  consumeOverdueTasks,
  getSkillStoreHint,
  queueCommitmentUpdate,
  getHubUrl,
  getHubNodeSecret,
  buildHubHeaders,
  buildNodeScopedHubHeaders,
  getNoveltyHint,
  getCapabilityGaps,
  mergeAndCap,
  consumeHeartbeatActions,
  getHeartbeatActions,
  consumeSharedKnowledgeDelta,
  getSharedKnowledgeVersion,
  consumeForceUpdate,
  // last_update reporting (evomap-hub #1034 / #1039). Public API consumed
  // by enrich.js / proxy/lifecycle/manager.js for callers that drive their
  // own force_update outside the heartbeat-thread trigger.
  reportForceUpdateOutcome,
  readPendingLastUpdate,
  clearLastUpdateOnAck,
  // Test hooks are intentionally namespaced under `_testing` so production
  // callers cannot trivially inject faults via auto-completion of the
  // public exports. Specifically, _setHeartbeatThrowForTesting is a fault
  // injector that can permanently kill the heartbeat loop -- exposing it
  // at module.exports root meant any consumer of the published dist could
  // call it accidentally (or maliciously). Hiding behind one extra hop
  // makes that fingerprint visible in code review and prevents IDE-driven
  // discovery.
  _testing: {
    // Reset heartbeat-driven force_update state. Used by
    // forceUpdateHeartbeat.test.js to avoid cooldown leakage between
    // sibling tests.
    _resetForceUpdateStateForTesting: function () {
      _forceUpdateInFlight = false;
      _forceUpdateLastAttemptAt = 0;
      _forceUpdatePending = null;
    },
    // Clear any pending force_update last_update state file. Used by
    // forceUpdateLastUpdateReport.test.js to keep cases independent. Also
    // resets the module-level 400 circuit-breaker counter so the consecutive
    // 400 logic does not leak across cases (a single shared counter at
    // file scope persists for the whole test process lifetime).
    _resetLastUpdateStateForTesting: function () {
      _clearLastUpdateState();
      _lastUpdateConsecutive400 = 0;
    },
    _persistLastUpdateStateForTesting: _persistLastUpdateState,
    _readPendingLastUpdateForTesting: _readPendingLastUpdate,
    _getLastUpdateStatePathForTesting: _getLastUpdateStatePath,
    _extractTargetVersionForTesting: _extractTargetVersion,
    // Expose the suffix helper so the regex-guard regression test can
    // exercise corrupt-file inputs without round-tripping through the
    // full heartbeat path. Read-only -- safe to expose.
    _shortNodeIdForStatePathForTesting: _shortNodeIdForStatePath,
    // Reset the in-process node-id cache so tests can simulate "fresh
    // boot" (no _cachedNodeId, no legacy file) and observe the
    // LifecycleManager's mint-and-persist path end-to-end. Without this
    // helper a previous test's getNodeId() call leaks _cachedNodeId
    // through the require-cache and the proxy fix appears to be a no-op.
    _resetCachedNodeIdForTesting: function () {
      _cachedNodeId = null;
    },
    _resetDryRunWarnedForTesting: function () {
      _dryRunWarned = false;
    },
    _resetHubNodeSecretStateForTesting: function () {
      _cachedHubNodeSecret = null;
      _cachedHubNodeSecretAt = 0;
      _cachedHubNodeSecretVersion = null;
      _cachedHubNodeSecretVersionAt = 0;
      _suppressEnvNodeSecret = false;
    },
    // Schedule a one-shot synchronous throw inside the next sendHeartbeat()
    // call. Used by a2aProtocolHeartbeatLoop.test.js to verify the loop
    // survives the bug class fixed in #544 (sync throw before the await --
    // old code's .catch never fired). Pass null to clear without triggering.
    _setHeartbeatThrowForTesting: function (err) {
      _heartbeatSyncThrowForTesting = err;
    },
    // Reset full heartbeat scheduler state to allow start/stop cycles
    // inside a single test process without leaking timers, flags or
    // failure counters between tests.
    _resetHeartbeatStateForTesting: function () {
      _heartbeatRunning = false;
      if (_heartbeatTimer) {
        clearTimeout(_heartbeatTimer);
        _heartbeatTimer = null;
      }
      if (_heartbeatDriftInterval) {
        clearInterval(_heartbeatDriftInterval);
        _heartbeatDriftInterval = null;
      }
      _heartbeatLastDriftCheckAt = 0;
      _heartbeatTickGeneration++;
      _heartbeatInFlight = false;
      _heartbeatLastTickAt = 0;
      _heartbeatConsecutiveFailures = 0;
      _heartbeatTotalSent = 0;
      _heartbeatTotalFailed = 0;
      _heartbeatStartedAt = null;
      _heartbeatIntervalMs = 0;
      _heartbeatSyncThrowForTesting = null;
      _heartbeatReauthBackoffUntil = 0;
      _heartbeatConsecutiveReauthFailures = 0;
      _heartbeatLastReauthProbeAt = 0;
      // Cross-test isolation: rate_limited branch sets
      // _pendingRescheduleDelayMs to drive the finally-arm reschedule.
      // A test that exercises rate_limited and then stops without
      // letting _scheduleNextHeartbeat consume the value will leak it
      // into the next test, where max(stale, requested) silently
      // inflates the schedule. Clear here for parity with stopHeartbeat().
      _pendingRescheduleDelayMs = 0;
      // Reset env_fingerprint emission flag so the next test starts from
      // the same "not yet sent" state as a fresh process.
      _heartbeatFpSent = false;
      // Round-4: unknown_node loop counter. Same isolation rationale as
      // _pendingRescheduleDelayMs above.
      _consecutiveUnknownNodeAfterHello = 0;
      // Round-5: unknown_node backoff deadline + self-driving poll state.
      _unknownNodeBackoffUntil = 0;
      try { stopSelfDrivingPoll(); } catch (_) {}
      _selfDrivingPollBackoffMs = _SELF_DRIVING_POLL_BASE_MS;
      // Round-8 (§21.9): round-7 left _pendingSelfDrivingPollDelayMs
      // out of every cleanup path. Without this clear, a test that
      // exercises the 429 branch leaks a >=16s self-driving poll
      // delay into every subsequent test in the same process.
      _pendingSelfDrivingPollDelayMs = 0;
      // Task-10: clear wake-recovery dedup timestamp so a test that
      // exercises _runWakeRecovery does not suppress the next call.
      _lastWakeRecoveryAt = 0;
      _activeStreamOpenedAt = 0;
    },
    // Synchronously enter the heartbeat scheduler with custom state so
    // tests do not have to wait HEARTBEAT_FIRST_DELAY_MS (30s) for the
    // first tick. Sets _heartbeatRunning=true, _heartbeatIntervalMs to
    // intervalMs, then drives one tick. The .finally inside _heartbeatTick
    // will reschedule using _heartbeatIntervalMs -- pass a short value (or
    // call stopHeartbeat() in the test's after()) so the next reschedule
    // is small and unref'd.
    _driveHeartbeatTickForTesting: function (intervalMs) {
      _heartbeatRunning = true;
      _heartbeatIntervalMs = intervalMs || 60_000;
      _heartbeatTick();
    },
    // Introspect single-flight + scheduler state.
    _getHeartbeatInternalsForTesting: function () {
      return {
        running: _heartbeatRunning,
        inFlight: _heartbeatInFlight,
        lastTickAt: _heartbeatLastTickAt,
        hasTimer: _heartbeatTimer !== null,
        hasDriftInterval: _heartbeatDriftInterval !== null,
        lastDriftCheckAt: _heartbeatLastDriftCheckAt,
        consecutiveFailures: _heartbeatConsecutiveFailures,
        totalSent: _heartbeatTotalSent,
        totalFailed: _heartbeatTotalFailed,
        reauthBackoffUntil: _heartbeatReauthBackoffUntil,
        consecutiveReauthFailures: _heartbeatConsecutiveReauthFailures,
        lastReauthProbeAt: _heartbeatLastReauthProbeAt,
        tickGeneration: _heartbeatTickGeneration,
        intervalMs: _heartbeatIntervalMs,
        // Expose the carry-out signal so tests of the rate_limited
        // backoff handoff can prove read-and-clear semantics.
        pendingRescheduleDelayMs: _pendingRescheduleDelayMs,
        // Expose env_fingerprint emission state for the recovery test
        // that proves a failed first heartbeat re-arms FP on the next tick.
        fpSent: _heartbeatFpSent,
        // SSE backoff is module-level; expose for the long-sleep reset test.
        sseReconnectMs: _sseReconnectMs,
        // Round-4: unknown_node cache-poisoning loop counter. Tests prove
        // the counter increments under cached unknown_node responses and
        // resets on the first ok response.
        consecutiveUnknownNodeAfterHello: _consecutiveUnknownNodeAfterHello,
        // Round-5: unknown_node absolute backoff deadline + self-driving
        // poll state for the regression tests below.
        unknownNodeBackoffUntil: _unknownNodeBackoffUntil,
        selfDrivingPollEnabled: _selfDrivingPollEnabled,
        hasSelfDrivingPollTimer: _selfDrivingPollTimer !== null,
        selfDrivingPollBackoffMs: _selfDrivingPollBackoffMs,
        // Round-8 (§21.9): expose the round-7 retry-after override so
        // tests can prove stopHeartbeat / _resetHeartbeatStateForTesting
        // clear it (pre-fix it leaked across lifetimes).
        pendingSelfDrivingPollDelayMs: _pendingSelfDrivingPollDelayMs,
      };
    },
    // SSE backoff reset hook for tests. Production code reaches it via
    // the drift detector's long-sleep branch (DRIFT_LONG_SLEEP_THRESHOLD_MS).
    _resetSseReconnectBackoffForTesting: _resetSseReconnectBackoff,
    // Carry-out backoff signal mutator. Used to assert that stopHeartbeat
    // and _resetHeartbeatStateForTesting clear the signal so it cannot
    // leak across lifetimes / tests.
    _setPendingRescheduleDelayMsForTesting: function (ms) {
      _pendingRescheduleDelayMs = ms;
    },
    // Round-8 (§21.9) test seam: lets the cross-lifetime leak test seed
    // the 429 retry-after override without actually exercising
    // _fetchHubEvents (which would need a hub stub at the right URL).
    _setPendingSelfDrivingPollDelayMsForTesting: function (ms) {
      _pendingSelfDrivingPollDelayMs = ms;
    },
    // Direct exercise of _scheduleNextHeartbeat so the lower-bound floor
    // can be regression-tested without timing-dependent setup.
    _scheduleNextHeartbeatForTesting: _scheduleNextHeartbeat,
    _heartbeatMinScheduleDelayMsForTesting: _HEARTBEAT_MIN_SCHEDULE_DELAY_MS,
    // Pin the drift detector's last-sample wall-clock timestamp to a
    // known value so a test can synthesize a controlled "wall-clock jump"
    // via Date.now stubbing.
    _forceDriftLastCheckAtForTesting: function (ts) {
      _heartbeatLastDriftCheckAt = ts;
    },
    // Pin loop bookkeeping for tests of the v2 drift branch and the reauth
    // backoff guards. All fields are optional; omitted fields are left
    // unchanged so tests can layer setup steps.
    _setHeartbeatStateForTesting: function (state) {
      if (!state || typeof state !== 'object') return;
      if (typeof state.running === 'boolean') _heartbeatRunning = state.running;
      if (typeof state.intervalMs === 'number') _heartbeatIntervalMs = state.intervalMs;
      if (typeof state.lastTickAt === 'number') _heartbeatLastTickAt = state.lastTickAt;
      if (typeof state.consecutiveFailures === 'number') _heartbeatConsecutiveFailures = state.consecutiveFailures;
      if (typeof state.reauthBackoffUntil === 'number') _heartbeatReauthBackoffUntil = state.reauthBackoffUntil;
      if (typeof state.consecutiveReauthFailures === 'number') _heartbeatConsecutiveReauthFailures = state.consecutiveReauthFailures;
      if (typeof state.lastDriftCheckAt === 'number') _heartbeatLastDriftCheckAt = state.lastDriftCheckAt;
      if (typeof state.inFlight === 'boolean') _heartbeatInFlight = state.inFlight;
      // Round-9: pin the reauth probe-throttle clock so tests can prove
      // both the escape-hatch probe (lastReauthProbeAt far in the past)
      // and the throttle (lastReauthProbeAt == now).
      if (typeof state.lastReauthProbeAt === 'number') _heartbeatLastReauthProbeAt = state.lastReauthProbeAt;
      // Round-5: tests for the drift-respects-backoff guard need to pin
      // the unknown_node deadline directly.
      if (typeof state.unknownNodeBackoffUntil === 'number') {
        _unknownNodeBackoffUntil = state.unknownNodeBackoffUntil;
      }
    },
    // Round-9: mimic the watchdog/wake-branch "supersede the wedged tick"
    // step (generation bump) so a test can prove an orphaned in-flight
    // tick's late continuation no longer clobbers the gate or reschedules.
    _bumpTickGenerationForTesting: function () {
      _heartbeatTickGeneration++;
    },
    // Round-5: expose self-driving poll start/stop/run for tests.
    _startSelfDrivingPollForTesting: startSelfDrivingPoll,
    _stopSelfDrivingPollForTesting: stopSelfDrivingPoll,
    _runSelfDrivingPollForTesting: _runSelfDrivingPoll,
  },
  _isDryRun,
  getForceUpdate,
  getHubEvents,
  consumeHubEvents,
  hubSelfProvision,
  hubCreditTopUp,
  hubCreditTransfer,
  hubCreateRecipe,
  hubPublishRecipe,
  hubGetRecipe,
  hubExpressRecipe,
  hubTransferEstimate,
  hubTransferHistory,
  hubGetIdentity,
  hubGetAttestation,
  hubVerifyAttestation,
  hubSetDid,
  hubGetAuditLogs,
  hubGetWorkReport,
  hubOpenEventStream,
  startEventStream,
  stopEventStream,
  isEventStreamActive,
};

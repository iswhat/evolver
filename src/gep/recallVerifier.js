'use strict';

// ---------------------------------------------------------------------------
// recallVerifier — confirm that assets we publish to Hub can actually be
// recalled later. After a successful publish (capsule bundle, anti-pattern,
// or skill bundle), enqueue the asset_id; a background worker uses Hub's
// Phase 2 deterministic lookup to verify the asset round-trips, with
// exponential backoff to absorb Hub indexing latency. Outcomes land as
// MemoryGraphEvents of kind 'recall_verify' so a report script can compute
// per-asset-type success rates and gate releases.
//
// Scope: only assets with a content-hash asset_id are verified. MemoryGraph
// events themselves go through a different transport (POST /a2a/memory/event,
// not the asset store) and produce no asset_id, so they cannot be subject to
// roundtrip verification. This naturally terminates any recursion of
// recall_verify events that would otherwise mirror to Hub.
//
// Graceful degradation: if fetchAssetById fails for any reason (network,
// auth, schema), the worker emits 'verification_skipped' rather than
// throwing. Verification must NEVER block the daemon cycle.
// ---------------------------------------------------------------------------

const { envInt, envFloat } = require('../config');
const { fetchAssetById } = require('./hubSearch');
const { computeAssetId } = require('./contentHash');
const { writeMemoryGraphEvent } = require('./memoryGraph');

// --- Module state (per-process lifetime, bounded) ---

let _queue = [];
const _inflightAssetIds = new Set();
let _workerStarted = false;
let _workerTimer = null;
let _lastReport = { ok: 0, missing: 0, mismatch: 0, skipped: 0 };

// Backoff schedule between attempts. attempt 1 fires INITIAL_WAIT_MS after
// publish; if it returns missing, retries fire after these intervals.
const BACKOFF_MS = [5000, 15000, 60000];

// --- Env getters (read at call time, never module-load) ---

function _isFeatureEnabled() {
  // Default OFF: Hub /a2a/fetch contract is strict (unknown asset_id → empty
  // results, 0 cost) so client-side round-trip verification is redundant as a
  // default safety net. Operators who want end-to-end SLA observability can
  // opt in with EVOLVE_RECALL_VERIFY=1; events still emit locally and (once
  // Hub-side schema lands, see EvoMap/evomap-hub#670) optionally to Hub.
  return String(process.env.EVOLVE_RECALL_VERIFY || '0') === '1';
}

function _getSampleRate() {
  // Clamp to [0, 1] to match the startup banner in index.js. A negative
  // env value would otherwise make the gate `Math.random() >= rate`
  // always true → every verify silently skipped, while the banner
  // (which does its own range clamp) still shows 1.0. Operators need
  // the implementation and the banner to agree. (Bugbot review on PR #53.)
  const raw = envFloat('EVOLVE_RECALL_VERIFY_SAMPLE_RATE', 1.0);
  if (!Number.isFinite(raw) || raw < 0 || raw > 1) return 1.0;
  return raw;
}

function _getQueueMax() {
  return envInt('EVOLVE_RECALL_VERIFY_QUEUE_MAX', 256);
}

function _getPollMs() {
  return envInt('EVOLVE_RECALL_VERIFY_POLL_MS', 5000);
}

function _getInitialWaitMs() {
  return envInt('EVOLVE_RECALL_VERIFY_INITIAL_WAIT_MS', 5000);
}

function _getMaxAttempts() {
  return envInt('EVOLVE_RECALL_VERIFY_ATTEMPTS', 3);
}

function _getFetchTimeoutMs() {
  return envInt('EVOLVE_RECALL_VERIFY_FETCH_TIMEOUT_MS', 8000);
}

// --- Event emission ---

function _emitEvent(entry, outcome, reason, extras) {
  const ts = Date.now();
  const verification = {
    outcome,
    reason: reason || null,
    attempts: extras && Number.isFinite(extras.attempts) ? extras.attempts : (entry.attempts || 0),
    latency_ms: extras && Number.isFinite(extras.latency_ms) ? extras.latency_ms : 0,
    age_at_verify_ms: entry.publishedAt ? (ts - entry.publishedAt) : 0,
    recalled_hash: extras && extras.recalled_hash ? extras.recalled_hash : null,
  };
  const ev = {
    type: 'MemoryGraphEvent',
    kind: 'recall_verify',
    id: 'mge_' + ts + '_' + Math.random().toString(36).slice(2, 10),
    ts,
    asset: {
      type: entry.type || 'Unknown',
      id: entry.asset_id || null,
    },
    verification,
    signal: { signals: Array.isArray(entry.signals) ? entry.signals.slice(0, 8) : [] },
  };
  try {
    writeMemoryGraphEvent(ev);
  } catch (writeErr) {
    if (process.env.EVOLVE_RECALL_VERIFY_DEBUG === '1') {
      console.warn('[RecallVerify] writeMemoryGraphEvent failed: ' + (writeErr && writeErr.message || writeErr));
    }
  }
  if (outcome === 'roundtrip_ok') _lastReport.ok++;
  else if (outcome === 'roundtrip_missing') _lastReport.missing++;
  else if (outcome === 'roundtrip_mismatch') _lastReport.mismatch++;
  else _lastReport.skipped++;
}

// --- Public API ---

function enqueuePublishedAsset(input) {
  const entry = {
    asset_id: input && input.asset_id ? String(input.asset_id) : null,
    type: input && input.type ? String(input.type) : 'Unknown',
    signals: Array.isArray(input && input.signals) ? input.signals : [],
    publishedAt: input && Number.isFinite(input.publishedAt) ? input.publishedAt : Date.now(),
    attempts: 0,
    nextEligibleAt: 0,
  };

  if (!_isFeatureEnabled()) {
    _emitEvent(entry, 'verification_skipped', 'feature_disabled');
    return { enqueued: false, reason: 'feature_disabled' };
  }

  if (!entry.asset_id) {
    _emitEvent(entry, 'verification_skipped', 'missing_asset_id');
    return { enqueued: false, reason: 'missing_asset_id' };
  }

  const sampleRate = _getSampleRate();
  if (sampleRate < 1.0 && Math.random() >= sampleRate) {
    _emitEvent(entry, 'verification_skipped', 'sample_rate');
    return { enqueued: false, reason: 'sample_rate' };
  }

  entry.nextEligibleAt = entry.publishedAt + _getInitialWaitMs();

  const queueMax = _getQueueMax();
  while (_queue.length >= queueMax) {
    const dropped = _queue.shift();
    _emitEvent(dropped, 'verification_skipped', 'queue_full');
  }

  _queue.push(entry);
  return { enqueued: true };
}

// Single-asset verification. Returns one of the four outcomes.
// outcome ∈ { roundtrip_ok | roundtrip_missing | roundtrip_mismatch | verification_skipped }
async function verifyOnce(assetId, assetType) {
  const t0 = Date.now();
  if (!assetId) {
    return { outcome: 'verification_skipped', reason: 'missing_asset_id', latency_ms: 0, recalled_hash: null };
  }
  let result;
  try {
    result = await fetchAssetById(assetId, { timeoutMs: _getFetchTimeoutMs(), bypassCache: true });
  } catch (err) {
    return {
      outcome: 'verification_skipped',
      reason: 'hub_unreachable',
      latency_ms: Date.now() - t0,
      recalled_hash: null,
      error: err && err.message || String(err),
    };
  }

  const latency = Date.now() - t0;

  if (!result || !result.ok) {
    return {
      outcome: 'verification_skipped',
      reason: 'hub_unreachable',
      latency_ms: latency,
      recalled_hash: null,
      error: (result && result.error) || 'fetch_not_ok',
    };
  }

  if (!result.asset) {
    return { outcome: 'roundtrip_missing', reason: null, latency_ms: latency, recalled_hash: null };
  }

  const recalled = result.asset;
  if (recalled.asset_id !== assetId) {
    return { outcome: 'roundtrip_missing', reason: 'wrong_asset', latency_ms: latency, recalled_hash: recalled.asset_id || null };
  }

  // Recompute the asset_id from the recalled body. If it doesn't match what
  // the recalled asset claims its asset_id is, the Hub re-encoded or
  // corrupted the asset between publish and fetch.
  let recomputed;
  try {
    recomputed = computeAssetId(recalled);
  } catch (hashErr) {
    return {
      outcome: 'verification_skipped',
      reason: 'hash_recompute_failed',
      latency_ms: latency,
      recalled_hash: null,
      error: hashErr && hashErr.message || String(hashErr),
    };
  }

  if (recomputed !== recalled.asset_id) {
    return { outcome: 'roundtrip_mismatch', reason: 'hash_drift', latency_ms: latency, recalled_hash: recomputed };
  }

  return { outcome: 'roundtrip_ok', reason: null, latency_ms: latency, recalled_hash: recomputed };
}

// Drain the queue once. Public + idempotent so tests can drive it
// synchronously without waiting on setInterval.
async function _runWorkerOnce() {
  if (_queue.length === 0) return { processed: 0 };
  const now = Date.now();
  const maxAttempts = _getMaxAttempts();
  const ready = [];
  for (let i = 0; i < _queue.length; i++) {
    const entry = _queue[i];
    if (entry.nextEligibleAt <= now && !_inflightAssetIds.has(entry.asset_id)) {
      ready.push(entry);
    }
  }
  if (ready.length === 0) return { processed: 0 };

  let processed = 0;
  for (const entry of ready) {
    _inflightAssetIds.add(entry.asset_id);
    try {
      entry.attempts += 1;
      const verifyResult = await verifyOnce(entry.asset_id, entry.type);

      const isRetryable = (verifyResult.outcome === 'roundtrip_missing' ||
                          (verifyResult.outcome === 'verification_skipped' && verifyResult.reason === 'hub_unreachable'));
      const hasAttemptsLeft = entry.attempts < maxAttempts;

      if (isRetryable && hasAttemptsLeft) {
        const backoffIdx = Math.min(entry.attempts - 1, BACKOFF_MS.length - 1);
        entry.nextEligibleAt = Date.now() + BACKOFF_MS[backoffIdx];
      } else {
        _emitEvent(entry, verifyResult.outcome, verifyResult.reason, {
          attempts: entry.attempts,
          latency_ms: verifyResult.latency_ms,
          recalled_hash: verifyResult.recalled_hash,
        });
        const idx = _queue.indexOf(entry);
        if (idx !== -1) _queue.splice(idx, 1);
      }
      processed += 1;
    } finally {
      // Always release inflight (including on retry) — next poll re-adds.
      _inflightAssetIds.delete(entry.asset_id);
    }
  }
  return { processed };
}

function startWorker() {
  if (_workerStarted) return;
  _workerStarted = true;
  const pollMs = _getPollMs();
  _workerTimer = setInterval(function () {
    _runWorkerOnce().catch(function (err) {
      if (process.env.EVOLVE_RECALL_VERIFY_DEBUG === '1') {
        console.warn('[RecallVerify] worker tick failed: ' + (err && err.message || err));
      }
    });
  }, pollMs);
  if (_workerTimer && typeof _workerTimer.unref === 'function') {
    _workerTimer.unref();
  }
}

function stopWorker() {
  if (_workerTimer) {
    clearInterval(_workerTimer);
    _workerTimer = null;
  }
  _workerStarted = false;
}

function getLastReport() {
  return Object.assign({}, _lastReport);
}

function _resetForTesting() {
  stopWorker();
  _queue = [];
  _inflightAssetIds.clear();
  _lastReport = { ok: 0, missing: 0, mismatch: 0, skipped: 0 };
}

function _getQueueLengthForTesting() {
  return _queue.length;
}

module.exports = {
  enqueuePublishedAsset,
  verifyOnce,
  startWorker,
  stopWorker,
  getLastReport,
  _runWorkerOnce,
  _resetForTesting,
  _getQueueLengthForTesting,
};

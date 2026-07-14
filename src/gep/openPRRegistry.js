'use strict';

// ---------------------------------------------------------------------------
// openPRRegistry — fetch and cache the current repo's open PR list, and decide
// whether a daemon-driven cycle's planned changes overlap with any of them.
//
// Why this exists: evolver --loop has been observed to independently
// re-implement work that's already in flight on an open PR (PR #38's a2a
// integrity check, PR #43's rollback safety, both rebuilt from scratch by
// the daemon). This dirties the working tree and triggers downstream
// rollback risk (see feedback_evolver_solidify_rollback). The fix: at
// solidify time, before the cycle commits, check whether the changed files
// substantially overlap with an open PR — if yes, rollback this cycle.
//
// The module is graceful: if `gh` is missing, unauthenticated, or the API
// errors, getOpenPRs returns [] and findOverlap returns { overlap: false }.
// EVOLVE_OPEN_PR_DEDUP=0 short-circuits the whole feature.
// ---------------------------------------------------------------------------

// Note: do not destructure execSync at module load — tests stub
// child_process.execSync at call time via the live module reference.
const { envInt } = require('../config');

const MAX_EXEC_BUFFER = 10 * 1024 * 1024;
const GH_TIMEOUT_MS = 5000;

let _cache = null;
let _cacheAt = 0;
let _inflight = null;
let _ghMissingWarned = false;

function _now() { return Date.now(); }

function _isFeatureEnabled() {
  return String(process.env.EVOLVE_OPEN_PR_DEDUP || '1') !== '0';
}

function _getTtlMs() {
  return envInt('EVOLVE_OPEN_PR_TTL_MS', 60000);
}

// Run `gh pr list ...` and parse JSON. Returns [] on any failure.
function _fetchOpenPRsSync() {
  try {
    const raw = require('child_process').execSync('gh pr list --state=open --json number,title,headRefName,files --limit 50', {
      encoding: 'utf8',
      timeout: GH_TIMEOUT_MS,
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: MAX_EXEC_BUFFER,
    });
    const arr = JSON.parse(raw || '[]');
    if (!Array.isArray(arr)) return [];
    return arr.map(function (pr) {
      return {
        number: pr.number,
        title: String(pr.title || ''),
        headRefName: String(pr.headRefName || ''),
        files: Array.isArray(pr.files) ? pr.files.map(function (f) { return String(f.path || ''); }).filter(Boolean) : [],
      };
    });
  } catch (e) {
    var msg = e && e.message ? String(e.message) : '';
    if (/not found|ENOENT|command not found/i.test(msg)) {
      if (!_ghMissingWarned) {
        _ghMissingWarned = true;
        console.warn('[OpenPR] gh CLI not available — open-PR dedup disabled for this process. Install gh or set EVOLVE_OPEN_PR_DEDUP=0 to silence.');
      }
    } else {
      console.warn('[OpenPR] gh pr list failed (non-fatal): ' + msg.slice(0, 200));
    }
    return [];
  }
}

// Public: get the current open-PR list, cached for EVOLVE_OPEN_PR_TTL_MS.
// Concurrent callers within the same TTL window share the same fetch.
function getOpenPRs(opts) {
  if (!_isFeatureEnabled()) return [];
  var ttlMs = (opts && Number.isFinite(opts.ttlMs)) ? opts.ttlMs : _getTtlMs();
  var age = _now() - _cacheAt;
  if (_cache && age < ttlMs) return _cache;
  // Single-flight: if a fetch is already in progress, return the prior cache
  // (or []) rather than spawning a second gh call.
  if (_inflight) return _cache || [];
  _inflight = true;
  try {
    var fresh = _fetchOpenPRsSync();
    _cache = fresh;
    _cacheAt = _now();
    return fresh;
  } finally {
    _inflight = false;
  }
}

// Compute overlap between this cycle's changed files and each open PR's files.
// Returns the strongest overlap by ratio. Ratio = |intersection| / |changedFiles|.
//
// Why we use changedFiles as the denominator (not the PR's files): we're asking
// "is this cycle re-doing work that the PR is already doing?" — the right
// question is "what fraction of MY changes are also in their PR?". If the daemon
// changes 4 files and 3 are also in PR #38's 11-file diff, that's 0.75 overlap
// from the daemon's POV (re-doing most of its own work) even though it's only
// 0.27 from the PR's POV.
function findOverlap(opts) {
  if (!_isFeatureEnabled()) return { overlap: false, reason: 'feature_disabled' };
  var changedFiles = (opts && Array.isArray(opts.changedFiles)) ? opts.changedFiles : [];
  if (changedFiles.length === 0) return { overlap: false, reason: 'no_changed_files' };
  var prs = (opts && Array.isArray(opts.prs)) ? opts.prs : getOpenPRs();
  if (prs.length === 0) return { overlap: false, reason: 'no_open_prs' };

  var changedSet = new Set(changedFiles.map(String));
  var best = null;
  for (var i = 0; i < prs.length; i++) {
    var pr = prs[i];
    if (!pr || !Array.isArray(pr.files) || pr.files.length === 0) continue;
    var prSet = new Set(pr.files.map(String));
    var shared = [];
    changedSet.forEach(function (f) { if (prSet.has(f)) shared.push(f); });
    if (shared.length === 0) continue;
    var ratio = shared.length / changedFiles.length;
    if (!best || ratio > best.overlapRatio) {
      best = {
        overlap: true,
        prNumber: pr.number,
        prTitle: pr.title,
        headRefName: pr.headRefName,
        overlapRatio: ratio,
        sharedFiles: shared,
      };
    }
  }
  return best || { overlap: false, reason: 'no_intersection' };
}

// Token-overlap version for the select-stage hint (no file paths available).
// Compares a Gene's signals_match against a PR's title + headRefName tokens.
// Returns the top-N matches with ratio >= threshold (default 0.5).
function findSignalHints(opts) {
  if (!_isFeatureEnabled()) return [];
  var signals = (opts && Array.isArray(opts.signals)) ? opts.signals : [];
  if (signals.length === 0) return [];
  var prs = (opts && Array.isArray(opts.prs)) ? opts.prs : getOpenPRs();
  if (prs.length === 0) return [];
  var threshold = (opts && Number.isFinite(opts.threshold)) ? opts.threshold : 0.5;

  function tokenize(s) {
    return String(s || '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, ' ')
      .split(/\s+/)
      .filter(function (t) { return t.length >= 3; });
  }
  var sigTokens = new Set();
  for (var i = 0; i < signals.length; i++) {
    tokenize(signals[i]).forEach(function (t) { sigTokens.add(t); });
  }
  if (sigTokens.size === 0) return [];

  var hits = [];
  for (var j = 0; j < prs.length; j++) {
    var pr = prs[j];
    if (!pr) continue;
    var prTokens = new Set();
    tokenize(pr.title).forEach(function (t) { prTokens.add(t); });
    tokenize(pr.headRefName).forEach(function (t) { prTokens.add(t); });
    if (prTokens.size === 0) continue;
    var common = 0;
    sigTokens.forEach(function (t) { if (prTokens.has(t)) common++; });
    var ratio = common / sigTokens.size;
    if (ratio >= threshold) {
      // Guard against pr.files being missing/null — getOpenPRs always
      // populates it, but tests and external callers may pass partial
      // PR objects. Without this guard pr.files.slice would throw a
      // TypeError, the try/catch in select.js would swallow it, and we
      // would silently lose ALL hits for that invocation rather than
      // just the malformed PR. (Bugbot review on PR #50.)
      var fileSample = Array.isArray(pr.files) ? pr.files.slice(0, 5) : [];
      hits.push({
        number: pr.number,
        title: pr.title,
        headRefName: pr.headRefName,
        files: fileSample,
        tokenOverlap: ratio,
      });
    }
  }
  hits.sort(function (a, b) { return b.tokenOverlap - a.tokenOverlap; });
  return hits.slice(0, 3);
}

// Internal: reset cache for tests.
function _resetForTesting() {
  _cache = null;
  _cacheAt = 0;
  _inflight = null;
  _ghMissingWarned = false;
}

module.exports = {
  getOpenPRs,
  findOverlap,
  findSignalHints,
  _resetForTesting,
};

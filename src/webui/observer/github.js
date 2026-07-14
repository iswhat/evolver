'use strict';

// ---------------------------------------------------------------------------
// observer/github — read-only GitHub PR status for the Web UI hovercard.
//
// Mirrors the Claude Code "hover a #123 → floating PR status card" behaviour:
// the client linkifies PR references and, on hover, asks this observer for the
// live status of one PR (state, title, author, +additions/-deletions, changed
// files, timestamps). It also feeds a dedicated "Pull Requests" panel with the
// repo's open PRs.
//
// Data source precedence (per the approved plan):
//   1. `gh pr view N --json ...`  — argv form, NO shell (mirrors selfPR.runGh),
//      reuses the operator's existing `gh` auth.
//   2. GitHub REST `/repos/{slug}/pulls/{n}` — fallback when `gh` is missing,
//      unauthenticated, times out, or errors. Token optional (public repos
//      read without one), resolved like issueReporter.getGithubToken().
//
// The module is graceful by construction: EVERY failure path returns
// `{ number, available: false, reason }` rather than throwing, so a flaky
// network or a non-GitHub checkout can never break the dashboard. A short
// negative cache stops hover-jitter from amplifying failed lookups into a
// request storm. EVOLVER_WEBUI_GITHUB=0 short-circuits the whole feature.
// ---------------------------------------------------------------------------

// Note: do not destructure execFileSync / fetch at module load — tests stub
// them at call time via the live references (child_process.execFileSync and
// global.fetch), matching the openPRRegistry / issueReporter test style.
const { envInt } = require('../../config');
const { getRepoRoot } = require('../../gep/paths');

const MAX_EXEC_BUFFER = 10 * 1024 * 1024;
const GH_TIMEOUT_MS = 5000;
const API_TIMEOUT_MS = 10000;
const NEG_CACHE_TTL_MS = 10000; // failed lookups: cache briefly to damp hover jitter
const MAX_CACHE_ENTRIES = 200; // bound memory; LRU-evict oldest beyond this

// gh's --json field list. Kept identical to the REST fields we normalise from
// so both sources produce the same shape.
const GH_PR_FIELDS = 'number,title,state,isDraft,author,additions,deletions,changedFiles,createdAt,updatedAt,mergedAt,closedAt,url';

const _prCache = new Map(); // number -> { data, at }
const _inflight = new Map(); // number -> Promise<data>
let _ghMissingWarned = false;

function _now() { return Date.now(); }

function _isFeatureEnabled() {
  return String(process.env.EVOLVER_WEBUI_GITHUB || '1') !== '0';
}

function _getTtlMs() {
  return envInt('EVOLVER_WEBUI_GITHUB_TTL_MS', 60000);
}

function _getGithubToken() {
  return process.env.GITHUB_TOKEN || process.env.GH_TOKEN || process.env.GITHUB_PAT || '';
}

// A PR number is untrusted route input. Accept only a positive *safe* integer;
// never let anything else reach `gh` or the REST URL. The safe-integer bound
// applies to both branches so a huge numeric input (e.g. Number('9'.repeat(23))
// === 1e23, whose String() is the non-numeric '1e+23') is rejected cleanly
// rather than handed to `gh pr view 1e+23`.
function _normalizeNumber(input) {
  if (typeof input === 'number') {
    return Number.isSafeInteger(input) && input > 0 ? input : null;
  }
  const s = String(input == null ? '' : input).trim();
  if (!/^\d+$/.test(s)) return null;
  const n = Number(s);
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}

// --- Repo slug resolution ---------------------------------------------------
// Precedence: EVOLVER_GITHUB_REPO → `git remote get-url origin` → SELF_PR_REPO.
let _slugCache; // undefined = unresolved; string|null once resolved

function _parseSlugFromRemote(url) {
  const m = String(url || '').trim().match(/github\.com[:/]([^/]+)\/([^/\s]+?)(?:\.git)?$/i);
  return m ? m[1] + '/' + m[2] : null;
}

function _resolveRepoSlug() {
  if (_slugCache !== undefined) return _slugCache;
  const envSlug = String(process.env.EVOLVER_GITHUB_REPO || '').trim();
  if (envSlug) { _slugCache = envSlug; return _slugCache; }
  try {
    const out = require('child_process').execFileSync('git', ['remote', 'get-url', 'origin'], {
      cwd: getRepoRoot(),
      encoding: 'utf8',
      timeout: GH_TIMEOUT_MS,
      stdio: ['ignore', 'pipe', 'ignore'],
      maxBuffer: MAX_EXEC_BUFFER,
    });
    const parsed = _parseSlugFromRemote(out);
    if (parsed) { _slugCache = parsed; return _slugCache; }
  } catch (_) { /* fall through to config default */ }
  try {
    _slugCache = require('../../config').SELF_PR_REPO || null;
  } catch (_) {
    _slugCache = null;
  }
  return _slugCache;
}

// --- Normalisation ----------------------------------------------------------
// gh: state ∈ {OPEN, CLOSED, MERGED} + isDraft. REST: state ∈ {open, closed} +
// merged_at + draft. Collapse both to merged|open|closed|draft.
function _normalizeState(rawState, isDraft, mergedAt) {
  if (mergedAt) return 'merged';
  const s = String(rawState || '').toLowerCase();
  if (s === 'merged') return 'merged';
  if (s === 'closed') return 'closed';
  if (isDraft) return 'draft';
  return s === 'open' ? 'open' : (s || 'open');
}

function _normalizeGh(raw) {
  const author = raw.author && typeof raw.author === 'object'
    ? String(raw.author.login || raw.author.name || '')
    : '';
  return {
    number: raw.number,
    title: String(raw.title || ''),
    state: _normalizeState(raw.state, raw.isDraft, raw.mergedAt),
    author,
    additions: Number(raw.additions) || 0,
    deletions: Number(raw.deletions) || 0,
    changedFiles: Number(raw.changedFiles) || 0,
    createdAt: raw.createdAt || null,
    updatedAt: raw.updatedAt || null,
    mergedAt: raw.mergedAt || null,
    closedAt: raw.closedAt || null,
    url: String(raw.url || ''),
    source: 'gh',
    available: true,
  };
}

function _normalizeApi(raw) {
  const author = raw.user && typeof raw.user === 'object' ? String(raw.user.login || '') : '';
  return {
    number: raw.number,
    title: String(raw.title || ''),
    state: _normalizeState(raw.state, raw.draft, raw.merged_at),
    author,
    additions: Number(raw.additions) || 0,
    deletions: Number(raw.deletions) || 0,
    changedFiles: Number(raw.changed_files) || 0,
    createdAt: raw.created_at || null,
    updatedAt: raw.updated_at || null,
    mergedAt: raw.merged_at || null,
    closedAt: raw.closed_at || null,
    url: String(raw.html_url || ''),
    source: 'api',
    available: true,
  };
}

// --- Fetch paths ------------------------------------------------------------
// Returns a normalized PR object, or null if this source could not answer
// (so the caller can try the next source).
function _fetchViaGh(n) {
  let raw;
  try {
    raw = require('child_process').execFileSync(
      'gh',
      ['pr', 'view', String(n), '--json', GH_PR_FIELDS],
      {
        cwd: getRepoRoot(),
        encoding: 'utf8',
        timeout: GH_TIMEOUT_MS,
        stdio: ['ignore', 'pipe', 'pipe'],
        maxBuffer: MAX_EXEC_BUFFER,
      },
    );
  } catch (e) {
    const msg = e && e.message ? String(e.message) : '';
    // Distinguish "gh binary is absent" (spawn failure) from "gh ran but
    // couldn't answer" (unknown/private PR → non-zero exit). Only the former
    // should latch the fall-back-to-REST warning. Match the spawn-failure
    // signals (`e.code === 'ENOENT'`, or "command not found" from a shell
    // wrapper) — NOT a bare "not found", which also appears in gh's own
    // "no pull requests found" message for a real but missing PR.
    const ghMissing = (e && e.code === 'ENOENT') || /\bENOENT\b|command not found/i.test(msg);
    if (ghMissing && !_ghMissingWarned) {
      _ghMissingWarned = true;
      console.warn('[WebUI/GitHub] gh CLI not available — falling back to REST API. Install gh or set a GITHUB_TOKEN.');
    }
    // Non-zero exit (unknown PR, auth) also lands here: signal "gh can't answer"
    // so the caller falls through to the REST path.
    return null;
  }
  let parsed;
  try {
    parsed = JSON.parse(raw || '{}');
  } catch (_) {
    return null;
  }
  if (!parsed || typeof parsed !== 'object' || parsed.number == null) return null;
  return _normalizeGh(parsed);
}

async function _fetchViaApi(n) {
  const slug = _resolveRepoSlug();
  if (!slug) return { number: n, available: false, reason: 'no_repo_slug' };
  const token = _getGithubToken();
  const headers = {
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'evolver-webui',
  };
  if (token) headers['Authorization'] = 'Bearer ' + token;
  const url = 'https://api.github.com/repos/' + slug + '/pulls/' + n;
  let res;
  try {
    res = await fetch(url, { method: 'GET', headers, signal: AbortSignal.timeout(API_TIMEOUT_MS) });
  } catch (_) {
    return { number: n, available: false, reason: 'network_error' };
  }
  if (res.status === 404) return { number: n, available: false, reason: 'not_found' };
  if (res.status === 403 || res.status === 429) return { number: n, available: false, reason: 'rate_limited' };
  if (!res.ok) return { number: n, available: false, reason: 'http_' + res.status };
  let data;
  try {
    data = await res.json();
  } catch (_) {
    return { number: n, available: false, reason: 'bad_json' };
  }
  if (!data || data.number == null) return { number: n, available: false, reason: 'bad_json' };
  return _normalizeApi(data);
}

// --- Cache helpers ----------------------------------------------------------
function _cacheGet(n) {
  const hit = _prCache.get(n);
  if (!hit) return null;
  const ttl = hit.data && hit.data.available ? _getTtlMs() : NEG_CACHE_TTL_MS;
  if (_now() - hit.at >= ttl) {
    _prCache.delete(n);
    return null;
  }
  // LRU touch: re-insert so recently-read entries survive eviction.
  _prCache.delete(n);
  _prCache.set(n, hit);
  return hit.data;
}

function _cacheSet(n, data) {
  _prCache.set(n, { data, at: _now() });
  while (_prCache.size > MAX_CACHE_ENTRIES) {
    const oldest = _prCache.keys().next().value;
    _prCache.delete(oldest);
  }
}

// --- Public API -------------------------------------------------------------

// Get one PR's normalized status. Never throws. Shape on success:
//   { number, title, state, author, additions, deletions, changedFiles,
//     createdAt, updatedAt, mergedAt, closedAt, url, source, available:true }
// On any failure (or feature disabled): { number, available:false, reason }.
async function getPrStatus(input) {
  const n = _normalizeNumber(input);
  if (n == null) return { number: null, available: false, reason: 'invalid_number' };
  if (!_isFeatureEnabled()) return { number: n, available: false, reason: 'feature_disabled' };

  const cached = _cacheGet(n);
  if (cached) return cached;

  // Single-flight: concurrent hovers on the same #N share one lookup.
  const pending = _inflight.get(n);
  if (pending) return pending;

  const promise = (async () => {
    let data = _fetchViaGh(n);
    if (!data) data = await _fetchViaApi(n);
    if (!data) data = { number: n, available: false, reason: 'unavailable' };
    _cacheSet(n, data);
    return data;
  })().finally(() => { _inflight.delete(n); });

  _inflight.set(n, promise);
  return promise;
}

// Open PRs for the dedicated panel. Reuses the existing open-PR registry so we
// don't spawn a second gh path. Returns [] on any failure.
//
// Note: openPRRegistry.getOpenPRs() is independently gated by
// EVOLVE_OPEN_PR_DEDUP — if an operator has the hovercard on
// (EVOLVER_WEBUI_GITHUB=1) but that dedup flag off (EVOLVE_OPEN_PR_DEDUP=0),
// this returns [] and the panel shows its "no open PRs (or gh unavailable)"
// empty state. That's intentional: we don't override another module's feature
// flag from here. Hovering any #N reference still fetches live status via the
// independent getPrStatus() path, so the core capability is unaffected.
function getOpenPrs() {
  if (!_isFeatureEnabled()) return [];
  try {
    const { getOpenPRs } = require('../../gep/openPRRegistry');
    const prs = getOpenPRs() || [];
    return prs.map((pr) => ({
      number: pr.number,
      title: String(pr.title || ''),
      headRefName: String(pr.headRefName || ''),
      fileCount: Array.isArray(pr.files) ? pr.files.length : 0,
    }));
  } catch (_) {
    return [];
  }
}

// Repo slug + PR URL base, so the client can build hrefs and linkify #N.
function getRepoInfo() {
  const slug = _isFeatureEnabled() ? _resolveRepoSlug() : null;
  return {
    slug: slug || null,
    prUrlBase: slug ? 'https://github.com/' + slug + '/pull' : null,
    available: !!slug,
  };
}

// Internal: reset caches for tests.
function _resetForTesting() {
  _prCache.clear();
  _inflight.clear();
  _slugCache = undefined;
  _ghMissingWarned = false;
}

module.exports = {
  getPrStatus,
  getOpenPrs,
  getRepoInfo,
  _resetForTesting,
  _normalizeNumber,
  _parseSlugFromRemote,
  _normalizeState,
};

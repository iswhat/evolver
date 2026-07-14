'use strict';

// Conversation Capability Sniffer
// --------------------------------
// evolver autonomously surfaces evolution opportunities from CODE (errsig /
// recurring_error), from MISSING features (capability_gap), and at idle time
// from external knowledge (explore.js: TODO scan, arxiv). The one blind spot:
// a human-verified, deterministic capability demonstrated *in the conversation*
// (e.g. "I just published a Feishu doc via lark-cli and validated it") never
// surfaces, because signal extraction maps free text onto the closed
// OPPORTUNITY_SIGNALS vocabulary and there is no extractor that reads the
// transcript for "the user just proved a reusable capability worth keeping".
//
// This module is that extractor. It mirrors explore.js: env gating + cooldown,
// a scan that produces results, dedup state on disk, and convertToSignals().
// Like the rest of evolver it does NOT call an LLM directly (evolver builds
// prompts and lets the bridged executor — the Hand — do the reasoning). The
// scan here is a lightweight RULE-BASED pre-filter; when it fires it injects a
// candidate signal so the selector/distiller can pick the work up on the
// executor side.
//
// Default posture is SHADOW (observe-only): it logs what it *would* surface
// without injecting, so the behaviour can be validated before it influences
// real cycles. Set EVOLVER_CONV_SNIFF_ENABLED=enforce to inject for real.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { getEvolutionDir } = require('./paths');

// off | shadow | enforce. Default 'shadow' so a fresh install observes before
// it acts. 'off' disables entirely; 'enforce' injects candidate signals.
const MODE = (() => {
  const raw = String(process.env.EVOLVER_CONV_SNIFF_ENABLED || 'shadow').toLowerCase().trim();
  if (raw === 'off' || raw === 'false' || raw === '0') return 'off';
  if (raw === 'enforce' || raw === 'on' || raw === 'true' || raw === '1') return 'enforce';
  return 'shadow';
})();

const COOLDOWN_MS = parseInt(process.env.EVOLVER_CONV_SNIFF_COOLDOWN_MS || '1800000', 10) || 1800000;
const MAX_CANDIDATES = 5;
const SNIPPET_MAX = 240;

// Signals injected (enforce mode). The umbrella signal lets a dedicated gene
// (or the distiller) match "there is a conversation-surfaced capability".
const UMBRELLA_SIGNAL = 'conv_capability_candidate';

// Evidence that a reusable capability was just *successfully exercised* in the
// transcript. We require (a) a success/completion marker AND (b) a reusable
// action verb, so idle chatter or failed attempts do not trigger.
const SUCCESS_MARKERS = [
  'success', 'succeeded', 'verified', 'validated', 'works', 'working',
  'published', 'created', 'completed', 'passed', 'done',
  '成功', '已发布', '已验证', '验证通过', '搞定', '跑通', '通过了',
];

// Reusable, deterministic actions worth keeping as a capability. Each entry is
// [regex, capability-slug]. Kept deliberately conservative.
const CAPABILITY_PATTERNS = [
  [/\blark-cli\b|飞书文档|feishu doc|lark doc/i, 'publish-feishu-doc'],
  [/\bgh (pr|issue|release)\b|github api|open(ed)? a pr\b/i, 'github-automation'],
  [/\bcurl\b.+\b(api|endpoint)\b|\bfetch\(.+\bapi\b/i, 'api-call'],
  [/\bdocker (build|run|compose)\b/i, 'docker-workflow'],
  [/\bkubectl\b|helm (install|upgrade)\b/i, 'k8s-operation'],
  [/\bprisma (migrate|db push)\b|\bpsql\b|pg_dump/i, 'db-operation'],
  [/\bnpm publish\b|\bnpx skills\b/i, 'package-publish'],
];

function _statePath() { return path.join(getEvolutionDir(), 'conv_sniff_state.json'); }
function _logPath() { return path.join(getEvolutionDir(), 'conv_sniff_log.jsonl'); }

function readState() {
  try { return JSON.parse(fs.readFileSync(_statePath(), 'utf8')); }
  catch (_) { return { seen: {}, last_sniff_ts: 0 }; }
}

function writeState(state) {
  try {
    const dir = getEvolutionDir();
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const tmp = _statePath() + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(state, null, 2) + '\n', 'utf8');
    fs.renameSync(tmp, _statePath());
  } catch (_) {}
}

function _appendLog(obj) {
  try {
    const dir = getEvolutionDir();
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.appendFileSync(_logPath(), JSON.stringify(obj) + '\n', 'utf8');
  } catch (_) {}
}

function _shortHash(s) {
  return crypto.createHash('sha256').update(String(s || '')).digest('hex').slice(0, 16);
}

function getMode() { return MODE; }

function shouldSniff(state) {
  if (MODE === 'off') return false;
  const st = state || readState();
  const last = st.last_sniff_ts || 0;
  // Date.now is fine here — this runs in the live process, not the workflow VM.
  if (Date.now() - last < COOLDOWN_MS) return false;
  return true;
}

// Proximity window (chars): a success marker must appear within this distance
// of the capability match for the pair to count. A global "success anywhere +
// capability anywhere" co-occurrence is NOT enough — that lets an unrelated
// "tests passed" pair with a *failed* lark-cli/kubectl mention and surface a
// false candidate (Bugbot #175, High). Require LOCAL co-occurrence instead.
const PROXIMITY_WINDOW = 200;

// Negators that flip a success marker ("not verified", "未发布", "failed to
// publish"). If one appears within NEGATION_LOOKBACK chars before the marker,
// the marker does not count as success (Bugbot #175 round 2, Medium).
const NEGATORS = ['not ', "n't ", 'no ', 'never ', 'fail', 'unable', "wasn't", "isn't", "didn't",
  '没', '未', '不', '失败', '无法'];
const NEGATION_LOOKBACK = 20;

function _markerIsNegated(lowerText, markerStart) {
  const from = Math.max(0, markerStart - NEGATION_LOOKBACK);
  const before = lowerText.slice(from, markerStart);
  return NEGATORS.some((n) => before.includes(n));
}

function _hasSuccessNear(text, lowerText, matchIndex, matchLen) {
  const from = Math.max(0, matchIndex - PROXIMITY_WINDOW);
  const to = Math.min(lowerText.length, matchIndex + matchLen + PROXIMITY_WINDOW);
  for (const m of SUCCESS_MARKERS) {
    const needle = m.toLowerCase();
    // walk every occurrence of this marker inside the window; accept only a
    // non-negated one.
    let rel = windowIndexOf(lowerText, needle, from, to);
    while (rel !== -1) {
      if (!_markerIsNegated(lowerText, rel)) return true;
      rel = windowIndexOf(lowerText, needle, rel + 1, to);
    }
  }
  return false;
}

// indexOf for `needle` constrained to [from, to); returns absolute index in
// lowerText or -1. Keeps negation checks anchored to the full text so the
// lookback can see chars just before the window edge.
function windowIndexOf(lowerText, needle, from, to) {
  const idx = lowerText.indexOf(needle, from);
  if (idx === -1 || idx >= to) return -1;
  return idx;
}

// Scan ONE segment for candidates (success marker within PROXIMITY_WINDOW of a
// capability match, non-negated). Returns [{capability, matched, snippet, hash}].
function _scanSegment(text, sink, seenSlugs) {
  if (!text || !text.trim()) return;
  const lower = text.toLowerCase();
  for (const [re, slug] of CAPABILITY_PATTERNS) {
    if (seenSlugs.has(slug)) continue;
    const gre = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
    let m;
    let accepted = null;
    while ((m = gre.exec(text)) !== null) {
      if (m[0].length === 0) { gre.lastIndex++; continue; } // guard zero-width
      if (_hasSuccessNear(text, lower, m.index, m[0].length)) { accepted = m; break; }
    }
    if (!accepted) continue;
    seenSlugs.add(slug);
    const idx = Math.max(0, accepted.index - 80);
    const snippet = text.slice(idx, idx + SNIPPET_MAX).replace(/\s+/g, ' ').trim();
    sink.push({
      capability: slug,
      matched: accepted[0].slice(0, 60),
      snippet,
      hash: _shortHash(slug + '|' + snippet),
    });
  }
}

// Pure scan. Accepts a single string OR an array of segments (e.g. master log
// and today log). Each segment is scanned INDEPENDENTLY so a success marker in
// one segment can never falsely sit "near" a capability match in another
// (Bugbot #175 round 2: joined logs caused false cross-boundary proximity).
// A candidate requires a non-negated success marker within PROXIMITY_WINDOW of
// the capability match, scanning all occurrences so a later successful use wins
// over an earlier failed mention.
function scanCorpus(corpus) {
  const segments = Array.isArray(corpus) ? corpus : [corpus];
  const candidates = [];
  const seenSlugs = new Set();
  for (const seg of segments) {
    if (candidates.length >= MAX_CANDIDATES) break;
    _scanSegment(String(seg || ''), candidates, seenSlugs);
  }
  return candidates.slice(0, MAX_CANDIDATES);
}

function convertToSignals(candidates) {
  const signals = [];
  const seen = new Set();
  for (const c of candidates) {
    const sig = 'conv_capability:' + c.capability;
    if (!seen.has(sig)) { seen.add(sig); signals.push(sig); }
  }
  if (signals.length > 0) signals.unshift(UMBRELLA_SIGNAL);
  return signals;
}

// Main entry, mirrors explore.tryExplore(): gate -> scan -> dedup -> (shadow|enforce).
// Returns { mode, candidates, signals } — signals is [] in shadow/off so the
// caller can inject unconditionally without leaking shadow candidates.
function trySniff(corpus, state) {
  const st = state || readState();
  if (!shouldSniff(st)) return { mode: MODE, candidates: [], signals: [] };

  const all = scanCorpus(corpus);

  // dedup against already-processed candidate hashes
  const seenMap = st.seen || {};
  const fresh = all.filter((c) => !seenMap[c.hash]);

  // Only start the cooldown when we actually surfaced something new. An empty
  // sniff (no candidates, or all already-seen) must NOT arm the cooldown —
  // otherwise a barren cycle blocks detection until the window elapses even
  // when the transcript gains real evidence moments later (Bugbot #175, Med).
  if (fresh.length === 0) return { mode: MODE, candidates: [], signals: [] };

  st.last_sniff_ts = Date.now();
  for (const c of fresh) seenMap[c.hash] = { capability: c.capability, at: new Date().toISOString() };
  st.seen = seenMap;
  writeState(st);

  const signals = convertToSignals(fresh);

  // Always log what was surfaced (both shadow and enforce) for auditing.
  _appendLog({
    at: new Date().toISOString(),
    mode: MODE,
    candidates: fresh.map((c) => ({ capability: c.capability, matched: c.matched, hash: c.hash })),
    signals,
  });

  if (MODE === 'shadow') {
    console.log('[ConvSniff:shadow] Would surface ' + fresh.length + ' capability candidate(s): ' +
      fresh.map((c) => c.capability).join(', ') + ' (signals NOT injected; set EVOLVER_CONV_SNIFF_ENABLED=enforce to act).');
    return { mode: MODE, candidates: fresh, signals: [] };
  }

  console.log('[ConvSniff] Surfaced ' + fresh.length + ' capability candidate(s); injecting ' +
    signals.length + ' signal(s): ' + signals.join(', '));
  return { mode: MODE, candidates: fresh, signals };
}

module.exports = {
  getMode,
  shouldSniff,
  scanCorpus,
  convertToSignals,
  trySniff,
  readState,
  writeState,
  UMBRELLA_SIGNAL,
};

// recallInject.js
// Harness-agnostic core for "runtime asset injection" (P4-c): when a general
// agent is about to work on a task, find GEP assets (Hub genes + local genes)
// that match the task and surface a distilled hint the agent can use.
//
// This module is PURE: no stdin/stdout, no process.exit. It is driven by the
// per-harness hook entrypoint (src/adapters/scripts/evolver-task-recall.js) and
// is unit-testable in isolation. The entrypoint owns the fail-open latch +
// watchdog + stdout shape; this module owns the matching/gating/logging.
//
// HARD INVARIANTS (do not regress — these are the P4-c scope contract):
//   1. SEARCH-ONLY. We call fetchSemanticResults (a free GET
//      /a2a/assets/semantic-search) and NEVER hubSearch()/fetchAssetById() —
//      Phase-2 fetch SPENDS CREDITS (hubSearch.js:379 logs "Fetch cost"). The
//      recall path must never spend a credit, in any mode. No money surface.
//   2. LLM-FREE / NO CHILD PROCESS. We extract signals with ONLY the pure
//      extractors _extractRegex + _extractKeywordScore. We must NOT call
//      extractSignals() — it calls _extractLLM(), a SYNC execFileSync('curl',
//      ['-m','10',...]) that (a) blocks the event loop for up to 10s so the
//      entrypoint watchdog can't fire, and (b) ships a raw-prompt corpus to the
//      Hub. Both are forbidden here.
//   3. SHADOW-FIRST. In 'shadow' we compute + log what WOULD inject but return
//      inject:false (the entrypoint injects nothing). In 'off' the entrypoint
//      never calls us. Only 'enforce' returns inject:true.
//   4. HIGH-CONFIDENCE ONLY. Hub rows must clear the similarity HIGH band
//      (>= EVOLVER_RECALL_MIN_SIM, default 0.75). Local genes must have >=1
//      real signal-pattern hit (not bag-of-words noise).
//   5. NO Hub used_asset_ids / reuse-credit reporting. Attribution is a LOCAL
//      JSONL artifact only (assetCallLog). Promoting it to Hub credit needs a
//      stronger usage signal AND team sign-off (it changes money).

const path = require('path');

// ---------------------------------------------------------------------------
// Mode parsing: EVOLVER_RECALL_MODE ∈ off (default) | shadow | enforce.
// Anything unknown/absent -> off (safest). Mirrors the conv-distill/P3 cadence
// of a single 3-state env var.
// ---------------------------------------------------------------------------
function getMode() {
  const v = String(process.env.EVOLVER_RECALL_MODE || '').toLowerCase().trim();
  return v === 'shadow' || v === 'enforce' ? v : 'off';
}

// Similarity HIGH band. Ported as an in-repo literal from
// gep-mcp-server/src/searchEnrich.js (SIMILARITY_BAND_HIGH = 0.75) — that file
// is a separate ESM repo and must NOT be imported. Operator-tunable.
function getMinSim() {
  const n = Number(process.env.EVOLVER_RECALL_MIN_SIM);
  return Number.isFinite(n) && n > 0 && n <= 1 ? n : 0.75;
}

// Max assets injected per turn. Default 1 (top hit only) to minimise context
// pollution; the entrypoint blocks every prompt, so we stay terse.
function getMaxInject() {
  const n = parseInt(process.env.EVOLVER_RECALL_MAX, 10);
  return Number.isFinite(n) && n > 0 && n <= 10 ? n : 1;
}

// Hard ceiling on injected text length (defense against a giant nl_summary
// bloating the agent's context window).
const INJECT_CHAR_CEILING = 800;
const SUMMARY_CLIP = 200;

// ---------------------------------------------------------------------------
// LLM-free signal extraction. Uses ONLY the pure extractors. We deliberately
// do NOT call signals.extractSignals (curl/event-loop-block, see invariant 2)
// and do NOT call _mergeSignals (it console.log()s to STDOUT — which would
// corrupt the hook's single-JSON stdout contract; we inline a Set-merge).
// ---------------------------------------------------------------------------
function extractSignalsPure(prompt) {
  const corpus = String(prompt || '');
  const lower = corpus.toLowerCase();
  const errorHit = /\b(error|exception|fail(?:ed|ure)?)\b|错误|异常|报错|失败/i.test(lower);

  let regexSignals = [];
  let scoreSignals = [];
  try {
    const sig = require('./signals');
    regexSignals = sig._extractRegex(corpus, lower, errorHit) || [];
    scoreSignals = sig._extractKeywordScore(lower) || [];
  } catch (_) {
    // signals.js unreachable — degrade to no signals (local/Hub then no-op).
    return [];
  }

  // Inline Set-merge (do NOT use sig._mergeSignals — it writes to stdout).
  const merged = new Set();
  for (const s of regexSignals) merged.add(s);
  for (const s of scoreSignals) merged.add(s);
  // 'stable_success_plateau' is the extractor's "nothing interesting" default;
  // it carries no task content, so drop it to avoid a noise query.
  merged.delete('stable_success_plateau');
  return Array.from(merged);
}

// The closed-vocabulary extractors above only fire on the evolver's own corpus
// shapes (errors, specific feature-request phrasings). A normal task prompt
// ("add retry with backoff to the http client") yields NO closed-vocab signal,
// so on its own the recall hook would almost never fire for real coding work.
// Embedding-based semantic search wants the actual task WORDS, so we also add a
// token projection of the prompt. tokenize() drops stop-words and short tokens;
// buildSemanticQuery (inside fetchSemanticResults) caps the outgoing query to
// 12 terms, so this stays a bounded token-projection — never the verbatim
// prompt. Capped here too as defense-in-depth.
const MAX_QUERY_TOKENS = 12;
function buildSignalList(prompt) {
  const coreSignals = extractSignalsPure(prompt);
  let tokens = [];
  try {
    const { tokenize } = require('./selector');
    // De-dup while preserving order, then cap.
    const seen = new Set();
    for (const t of tokenize(prompt)) {
      if (!seen.has(t)) { seen.add(t); tokens.push(t); }
      if (tokens.length >= MAX_QUERY_TOKENS) break;
    }
  } catch (_) { tokens = []; }

  const merged = new Set();
  for (const s of coreSignals) merged.add(s);
  for (const t of tokens) merged.add(t);
  return Array.from(merged);
}

// ---------------------------------------------------------------------------
// Hub search — SEARCH-ONLY, credit-free. Returns the rows that clear the HIGH
// similarity band, best-effort self-suppressed, never spending a credit.
// ---------------------------------------------------------------------------
async function searchHub(signalList, timeoutMs) {
  let hs, a2a;
  try {
    hs = require('./hubSearch');
    a2a = require('./a2aProtocol');
  } catch (_) {
    return [];
  }
  // Honor the HUBSEARCH_SEMANTIC kill-switch the same way hubSearch() does:
  // an operator who set it to false/0 to stop semantic Hub traffic must not
  // have this hook keep issuing semantic GETs on every prompt (Bugbot #183
  // medium). When disabled -> no Hub call, local genes only.
  try { if (typeof hs.isSemanticEnabled === 'function' && !hs.isSemanticEnabled()) return []; } catch (_) {}
  // Resolve the Hub URL via a2aProtocol.getHubUrl(), the canonical resolver
  // that honors BOTH A2A_HUB_URL and the legacy EVOMAP_HUB_URL fallback.
  // hubSearch.getHubUrl() reads only A2A_HUB_URL, so a node configured with the
  // legacy var alone would silently skip recall while every other Hub feature
  // (auth, heartbeat, memory) still worked (Bugbot #183 medium). Strip trailing
  // slashes to match hubSearch's own normalization. Fall back to hs.getHubUrl()
  // only if a2a is unavailable.
  let hubUrl = '';
  try {
    hubUrl = (typeof a2a.getHubUrl === 'function' ? a2a.getHubUrl() : hs.getHubUrl()) || '';
    hubUrl = hubUrl.replace(/\/+$/, '');
  } catch (_) { hubUrl = ''; }
  // Air-gapped / no Hub configured -> zero egress, local genes only.
  if (!hubUrl) return [];

  let headers = {};
  try { headers = a2a.buildHubHeaders(); } catch (_) { headers = {}; }

  let rows = [];
  try {
    // fetchSemanticResults already owns an AbortController bound to timeoutMs
    // and returns [] on timeout/error/non-200 (hubSearch.js:160). It hits
    // GET /a2a/assets/semantic-search?...&type=Gene -> genes only, no fetch,
    // no credit. The query is a token-trimmed projection of the signals
    // (buildSemanticQuery), NOT the verbatim prompt.
    rows = await hs.fetchSemanticResults(hubUrl, headers, signalList, timeoutMs);
  } catch (_) {
    return [];
  }
  if (!Array.isArray(rows)) return [];

  const minSim = getMinSim();
  let selfId = '';
  try { selfId = a2a.getNodeId() || ''; } catch (_) { selfId = ''; }

  const out = [];
  for (const r of rows) {
    if (!r || typeof r !== 'object') continue;
    const sim = Number(r._semantic_similarity);
    if (!Number.isFinite(sim) || sim < minSim) continue; // drop drag-net matches
    // Best-effort self-suppression: only when source_node_id is present (the
    // semantic endpoint often omits it — do NOT treat absence as a hard gate).
    if (selfId && r.source_node_id && r.source_node_id === selfId) continue;
    out.push({
      asset_id: r.asset_id || r.assetId || '',
      source_node_id: r.source_node_id || '',
      chain_id: r.chain_id || '',
      similarity: sim,
      title: r.short_title || r.nl_title || r.name || '',
      summary: r.nl_summary || r.summary || '',
      origin: 'hub',
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Local genes — match against on-disk genes with a real signal-pattern hit.
// We use the EXPORTED scorers (scoreGene is NOT exported, and selectGene uses
// Math.random + env I/O so it's unsuitable). Require >=1 pattern hit so we
// inject only genes whose signals_match actually fire for this task, not
// bag-of-words near-misses.
// ---------------------------------------------------------------------------
function matchLocalGenes(signalList) {
  let genes = [];
  let sel;
  try {
    genes = require('./assetStore').loadGenes() || [];
    sel = require('./selector');
  } catch (_) {
    return [];
  }
  if (!Array.isArray(genes) || genes.length === 0 || !sel) return [];

  const out = [];
  for (const gene of genes) {
    if (!gene || gene.type !== 'Gene') continue;
    const patterns = Array.isArray(gene.signals_match) ? gene.signals_match : [];
    let hits = 0;
    for (const p of patterns) {
      try { if (sel.matchPatternToSignals(p, signalList)) hits++; } catch (_) { /* skip */ }
    }
    if (hits < 1) continue; // require a real pattern hit, not noise
    let sem = 0;
    try { sem = sel.scoreGeneSemantic(gene, signalList) || 0; } catch (_) { sem = 0; }
    // Many genes (incl. genesis genes) carry no `summary`. Fall back to a terse
    // projection of the strategy/avoid text or the matched signal patterns so
    // the injected line is actionable rather than a dangling "...: " (caught by
    // real-gene E2E where synthetic fixtures had summaries).
    let summary = (gene.summary || '').toString().trim();
    if (!summary && gene.strategy && typeof gene.strategy === 'object') {
      const pieces = [];
      if (Array.isArray(gene.strategy.steps)) pieces.push(gene.strategy.steps.slice(0, 3).join('; '));
      if (typeof gene.strategy.approach === 'string') pieces.push(gene.strategy.approach);
      summary = pieces.filter(Boolean).join(' — ').trim();
    }
    if (!summary) {
      const pats = patterns
        .map(p => String(p).split('|')[0]) // first alias of each multi-lang pattern
        .filter(p => p && !p.startsWith('/'))
        .slice(0, 4);
      if (pats.length) summary = 'matches: ' + pats.join(', ');
    }
    out.push({
      asset_id: gene.asset_id || '',
      source_node_id: gene.source_node_id || gene.author_node_id || '',
      chain_id: gene.chain_id || '',
      // Map local score into a 0..1-ish band for ranking next to Hub similarity.
      // hits dominate; semantic cosine breaks ties.
      similarity: Math.min(1, 0.75 + 0.05 * hits + 0.1 * sem),
      title: gene.id || gene.short_title || '',
      summary,
      origin: 'local',
      _hits: hits,
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Build the injected text. Distilled hint, NOT raw JSON. Each line uses
// nl_summary/title (always present in list/search responses) — never
// payload.strategy (often empty for distilled/sybil assets). Hard char ceiling.
// ---------------------------------------------------------------------------
// A candidate is "hollow" when it has neither a title nor a summary: there is
// nothing actionable to render (a dangling "Gene "": " helps no one). Hollow
// candidates are excluded from BOTH the injected text and the attribution log,
// so the log can never claim an asset was injected that never appeared in the
// hook context (Bugbot #183 low: log/inject must agree by construction).
function isRenderable(d) {
  const title = (d && d.title ? String(d.title) : '').trim();
  const summary = (d && d.summary ? String(d.summary) : '').trim();
  return !!(title || summary);
}

function buildInjectText(decided) {
  const renderable = (decided || []).filter(isRenderable);
  if (!renderable.length) return '';
  const lines = ['[Evolver — relevant prior capability]'];
  let anyPublished = false;
  for (const d of renderable) {
    const title = (d.title || '').toString().slice(0, 80);
    const summary = (d.summary || '').toString().replace(/\s+/g, ' ').trim().slice(0, SUMMARY_CLIP);
    const sim = d.similarity != null ? d.similarity.toFixed(2) : '?';
    const idTag = d.asset_id ? `asset ${d.asset_id}` : 'local, unpublished';
    if (d.asset_id) anyPublished = true;
    lines.push(`- ${title ? `Gene "${title}"` : 'Gene'} (${idTag}, sim ${sim})${summary ? ': ' + summary : ''}`);
  }
  lines.push('A prior distilled approach may fit this task. Adapt it; verify before applying.');
  if (anyPublished) lines.push('To reuse a published asset: `gep_reuse <asset_id>` (or `gep_recall`).');
  const text = lines.join('\n');
  return text.length > INJECT_CHAR_CEILING ? text.slice(0, INJECT_CHAR_CEILING) : text;
}

// ---------------------------------------------------------------------------
// Local reuse logging. Records WHICH assets were (would be) injected, keyed by
// a stable run_id derived from the session, so a later Stop hook can correlate
// "asset injected -> session outcome" LOCALLY. This is correlational/local
// only — it is NOT Hub credit and must not be promoted to one without sign-off.
// ---------------------------------------------------------------------------
function logInjections(decided, mode, runId, signalList) {
  let logAssetCall;
  try { ({ logAssetCall } = require('./assetCallLog')); } catch (_) { return; }
  const action = mode === 'enforce' ? 'asset_inject' : 'asset_inject_shadow';
  for (const d of decided) {
    try {
      logAssetCall({
        run_id: runId,
        action,
        asset_id: d.asset_id || undefined,
        asset_type: 'Gene',
        source_node_id: d.source_node_id || undefined,
        chain_id: d.chain_id || undefined,
        score: d.similarity,
        signals: signalList.slice(0, 8),
        reason: d.origin === 'hub' ? 'hub_semantic_high_band' : 'local_gene_pattern_hit',
        extra: { via: 'task_recall', attribution: 'correlational_local', origin: d.origin },
      });
    } catch (_) { /* logging is best-effort; never block injection */ }
  }
}

// ---------------------------------------------------------------------------
// Entry point of the core. Returns:
//   { inject: bool, text: string|null, decided: [], dropped: number, signals: [] }
// inject is true ONLY in enforce mode with >=1 decided asset. In shadow we log
// but return inject:false. Throwing is acceptable — the hook entrypoint wraps
// this in try/.catch -> finish({}) (fail-open).
// ---------------------------------------------------------------------------
async function recallForTask(opts) {
  const o = opts || {};
  const mode = o.mode || getMode();
  if (mode === 'off') return { inject: false, text: null, decided: [], dropped: 0, signals: [] };

  const signalList = buildSignalList(o.prompt);
  if (!signalList.length) return { inject: false, text: null, decided: [], dropped: 0, signals: [] };

  // Do LOCAL gene work (synchronous disk I/O via loadGenes + ranking) BEFORE
  // the Hub await, so it runs while the full budget is available — never after
  // the Hub search has consumed most of the watchdog window (Bugbot #183
  // medium: post-await local work could overrun the watchdog and spuriously
  // skip injection). After the Hub await, only in-memory merge/text/log remain.
  const localRows = matchLocalGenes(signalList);

  // Bound the Hub call by the time REMAINING until the entrypoint's absolute
  // deadline (passed as deadlineMs, ms-since-epoch), minus a safety margin for
  // the in-memory post-processing + finish(). If too little remains, skip the
  // Hub call (local genes still apply). Falls back to the static timeoutMs when
  // no deadline is supplied (e.g. unit tests / non-hook callers).
  const POST_AWAIT_SAFETY_MS = 150;
  let hubBudget = Number.isFinite(o.timeoutMs) && o.timeoutMs > 0 ? o.timeoutMs : 2000;
  if (Number.isFinite(o.deadlineMs)) {
    const remaining = o.deadlineMs - Date.now() - POST_AWAIT_SAFETY_MS;
    hubBudget = Math.min(hubBudget, remaining);
  }

  // Hub (search-only, credit-free), only if there's a usable budget left.
  const hubRows = hubBudget >= 300 ? await searchHub(signalList, hubBudget) : [];

  const seen = new Set();
  const candidates = [];
  let dropped = 0;
  for (const r of [...hubRows, ...localRows]) {
    const key = r.asset_id || `${r.origin}:${r.title}`;
    if (key && seen.has(key)) { dropped++; continue; } // de-dup local vs hub
    if (key) seen.add(key);
    candidates.push(r);
  }
  candidates.sort((a, b) => (b.similarity || 0) - (a.similarity || 0));

  const topN = candidates.slice(0, getMaxInject());
  dropped += Math.max(0, candidates.length - topN.length);

  // Filter out hollow candidates ONCE, so the injected text and the attribution
  // log operate on the exact same set — the log can never claim an asset was
  // injected that wasn't rendered into the hook context (Bugbot #183 low).
  const decided = topN.filter(isRenderable);
  dropped += topN.length - decided.length;
  if (!decided.length) return { inject: false, text: null, decided: [], dropped, signals: signalList };

  const text = buildInjectText(decided);
  if (!text) return { inject: false, text: null, decided: [], dropped, signals: signalList };

  const runId = o.runId || ('recall:' + (o.sessionId || 'unknown'));
  logInjections(decided, mode, runId, signalList);

  // SHADOW returns the computed text (for tests/inspection) but inject:false —
  // the entrypoint only injects when inject is true (enforce).
  return {
    inject: mode === 'enforce',
    text,
    decided,
    dropped,
    signals: signalList,
  };
}

module.exports = {
  recallForTask,
  // exported for unit tests:
  getMode,
  getMinSim,
  getMaxInject,
  extractSignalsPure,
  buildSignalList,
  buildInjectText,
  _internals: { searchHub, matchLocalGenes, logInjections },
};

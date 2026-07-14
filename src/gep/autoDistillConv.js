'use strict';

// P2 — Conversation capability -> distilled gene (discover -> distill).
//
// The conversation sniffer (#175) discovers a human-verified reusable capability
// from the transcript (slug + ~240-char snippet). P3 (#181) distills genes from
// SUCCESS CAPSULES. P2 bridges them: it takes a sniffed capability candidate and
// synthesizes a candidate gene by running a CONVERSATION brief through the same
// light read-only `claude` (P3's claude-distill recipe) + the same quality gate
// (validate / Jaccard / normalize / run-green) that P3 uses.
//
// SHADOW-ONLY v1 (deliberate — see the P2 spec §5/§8): a slug + 240-char snippet
// is too thin to safely auto-upsert. The quality gate is structural + tautological
// (normalizeValidation injects `node --version`, which passes regardless of the
// gene's strategy), so it filters MALFORMED genes, not WRONG ones. For P3 that's
// fine (strategy grounded in >=10 real capsules); for P2's one-snippet material it
// is NOT — nothing downstream distinguishes a correct procedure from a confident
// hallucination. So v1 logs a candidate gene for HUMAN REVIEW and NEVER upserts.
// `enforce` is intentionally absent (downgraded to shadow with a loud log); a real
// enforce path needs grounding the snippet can't provide (execution capsule / human
// approval) and is deferred.
//
// State (P2-OWNED, never the shared cross-distiller scalars — lesson L1 from P3's
// 8 rounds): distiller_state.json -> conv_distill.{ by_hash, by_slug }.
// Reuses ad._p3Decide (pure, data-source-agnostic) for the per-(hash,mode) cadence.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

const sd = require('./skillDistiller');
const ad = require('./autoDistillLlm');
const pc = require('./policyCheck');
const eb = require('./execBridge');
const assetStore = require('./assetStore');
const { getRepoRoot, getEvolutionDir } = require('./paths');

function _envInt(name, def) { const n = parseInt(process.env[name] || '', 10); return Number.isFinite(n) && n > 0 ? n : def; }
const SLUG_COOLDOWN_MS = () => _envInt('CONV_SLUG_COOLDOWN_MS', 21600000); // 6h per-slug spawn budget
const HASH_CAP = () => _envInt('EVOLVER_CONV_DISTILL_HASH_CAP', 32);
const QUEUE_MAX = () => _envInt('EVOLVER_CONV_QUEUE_MAX', 64);

function _log(entry) {
  try {
    fs.appendFileSync(sd.distillerLogPath(), JSON.stringify(Object.assign({ at: new Date().toISOString(), component: 'auto-distill-conv' }, entry)) + '\n', 'utf8');
  } catch (_) {}
}

// ---- P2-OWNED state over distiller_state.json -> conv_distill (NOT p3_llm; L1) ----
function _readConv() {
  try {
    const st = sd.readDistillerState() || {};
    const c = st.conv_distill || {};
    return { by_hash: c.by_hash || {}, by_slug: c.by_slug || {} };
  } catch (_) { return { by_hash: {}, by_slug: {} }; }
}
function _convGet(H) { return _readConv().by_hash[H] || null; }
function _convSlugGet(slug) { return _readConv().by_slug[slug] || null; }

function _convCap(byHash) {
  const keys = Object.keys(byHash);
  const cap = HASH_CAP();
  if (keys.length <= cap) return byHash;
  const age = (k) => { const r = byHash[k]; return Math.max(Date.parse(r.shadowed_at || 0) || 0, Date.parse(r.last_attempt_at || 0) || 0); };
  const nonTerminal = keys.filter((k) => !byHash[k].shadowed_at).sort((a, b) => age(a) - age(b));
  const terminal = keys.filter((k) => byHash[k].shadowed_at).sort((a, b) => age(a) - age(b));
  let n = keys.length;
  for (const k of nonTerminal.concat(terminal)) { if (n <= cap) break; delete byHash[k]; n--; }
  return byHash;
}

// Patch conv_distill.by_hash[H]. Returns ok boolean (caller fails closed).
function _convPatch(H, patch) {
  try {
    const st = sd.readDistillerState() || {};
    if (!st.conv_distill || typeof st.conv_distill !== 'object') st.conv_distill = { version: 1, by_hash: {}, by_slug: {} };
    if (!st.conv_distill.by_hash) st.conv_distill.by_hash = {};
    const cur = st.conv_distill.by_hash[H] || { shadowed_at: null, enforced_at: null, failed_attempts: 0, last_attempt_at: null };
    for (const k of Object.keys(patch)) {
      if (k === 'failed_attempts_inc') { if (patch[k]) cur.failed_attempts = (Number(cur.failed_attempts) || 0) + 1; continue; }
      cur[k] = patch[k];
    }
    st.conv_distill.by_hash[H] = cur;
    _convCap(st.conv_distill.by_hash);
    sd.writeDistillerState(st);
    return true;
  } catch (_) { return false; }
}
function _convSlugPatch(slug, patch) {
  try {
    const st = sd.readDistillerState() || {};
    if (!st.conv_distill || typeof st.conv_distill !== 'object') st.conv_distill = { version: 1, by_hash: {}, by_slug: {} };
    if (!st.conv_distill.by_slug) st.conv_distill.by_slug = {};
    st.conv_distill.by_slug[slug] = Object.assign({}, st.conv_distill.by_slug[slug], patch);
    sd.writeDistillerState(st);
    return true;
  } catch (_) { return false; }
}

// ---- queue (P2-owned transport; NOT the shared distill_request.json) ----
function _convQueuePath() { return path.join(getEvolutionDir(), 'conv_capability_queue.jsonl'); }
function _readQueue() {
  try {
    const raw = fs.readFileSync(_convQueuePath(), 'utf8');
    const rows = raw.split('\n').map((l) => l.trim()).filter(Boolean).map((l) => { try { return JSON.parse(l); } catch (_) { return null; } }).filter(Boolean);
    return rows.slice(-QUEUE_MAX());
  } catch (_) { return []; }
}
// Append sniffer candidate(s). Best-effort; called from signals.js at sniff time.
function enqueueCandidate(candidates) {
  const arr = Array.isArray(candidates) ? candidates : [candidates];
  try {
    const dir = getEvolutionDir();
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    for (const c of arr) {
      if (!c || !c.hash) continue;
      fs.appendFileSync(_convQueuePath(), JSON.stringify({ capability: c.capability, matched: c.matched, snippet: c.snippet, hash: c.hash, enqueued_at: new Date().toISOString() }) + '\n', 'utf8');
    }
    return true;
  } catch (_) { return false; }
}

// ---------------------------------------------------------------------------
// autoDistillConversation — pick one queued candidate, synthesize a gene via
// the conversation brief + P3 quality gate, log it for human review. SHADOW ONLY.
// ---------------------------------------------------------------------------
async function autoDistillConversation(opts = {}) {
  const now = opts.now ? opts.now() : Date.now();
  let mode = String(opts.mode || process.env.EVOLVER_CONV_DISTILL_ENABLED || 'off').toLowerCase().trim();
  if (mode === 'off') return { ok: false, reason: 'disabled' };
  if (mode === 'enforce') {
    // v1: enforce (auto-upsert) is NOT implemented — conversation-snippet material
    // is too thin to safely write to genes.json. Downgrade to shadow, loudly.
    _log({ status: 'enforce_not_implemented_v1', note: 'conv-snippet too thin to auto-upsert; running shadow' });
    mode = 'shadow';
  }
  if (mode !== 'shadow') return { ok: false, reason: 'disabled' };

  const queue = _readQueue();
  if (queue.length === 0) return { ok: false, reason: 'queue_empty', mode };

  // Pick one candidate the cadence machine says is fresh. by_hash is the authority.
  let cand = null;
  for (const entry of queue) {
    if (!entry || !entry.hash) continue;
    const dec = ad._p3Decide(mode, _convGet(entry.hash), now); // reused pure cadence fn
    if (dec !== 'spawn') continue;
    const slugRec = _convSlugGet(entry.capability);
    if (slugRec && slugRec.last_attempt_at && (now - Date.parse(slugRec.last_attempt_at)) < SLUG_COOLDOWN_MS()) continue;
    cand = entry; break;
  }
  if (!cand) return { ok: false, reason: 'nothing_ready', mode };

  // Arm BEFORE spawn (crash-idempotency).
  _convPatch(cand.hash, { last_attempt_at: new Date(now).toISOString() });
  _convSlugPatch(cand.capability, { last_attempt_at: new Date(now).toISOString() });

  const existing = (assetStore.loadGenes && assetStore.loadGenes()) || [];
  const prompt = sd.buildConversationDistillPrompt(cand, existing);

  const spawnFn = opts.spawnFn || spawn;
  // claude requires --session-id to be a valid UUID (caught by E2E). cand.hash
  // is a 16-hex sniffer hash, NOT a UUID — use a fresh UUID like P3 does.
  const built = eb.RECIPES['claude-distill'].buildArgs({ sessionId: crypto.randomUUID() });
  const r = await eb.runChild(spawnFn, built.bin, built.args, {
    env: Object.assign({}, process.env, built.env),
    stdinText: prompt,
    timeoutMs: _envInt('EVOLVE_DISTILL_TIMEOUT_MS', 180000),
    label: 'conv-distill', bufferMode: 'tail', cwd: getRepoRoot(),
  });

  if (r.spawnError) { _log({ status: 'claude_spawn_error', reason: r.spawnError }); return { ok: false, reason: 'claude_spawn_error', mode }; }
  if (r.timedOut) { _log({ status: 'claude_timeout' }); return { ok: false, reason: 'claude_timeout', mode }; }
  if (r.code !== 0) { _log({ status: 'claude_nonzero_exit', code: r.code }); return { ok: false, reason: 'claude_nonzero_exit', mode }; }

  const envelope = eb.tryParseClaudeResult(r.stdout);
  if (!envelope || envelope.is_error) { _convPatch(cand.hash, { failed_attempts_inc: true }); _log({ status: 'claude_is_error', hash: cand.hash }); return { ok: false, reason: 'claude_is_error', mode }; }
  const rawGene = sd.extractJsonFromLlmResponse(envelope.result);
  if (!rawGene) { _convPatch(cand.hash, { failed_attempts_inc: true }); _log({ status: 'no_gene_in_response', hash: cand.hash }); return { ok: false, reason: 'no_gene_in_response', mode }; }

  // QUALITY GATE — reused from P3. Structural + run-green only (see module header).
  const v = sd.validateSynthesizedGene(rawGene, existing);
  if (!v.valid) { _convPatch(cand.hash, { failed_attempts_inc: true }); _log({ status: 'validation_failed', errors: v.errors }); return { ok: false, reason: 'validation_failed', mode }; }
  let gene = v.gene;
  gene._distilled_meta = { via: 'conv-distill', source_capability: cand.capability, source_hash: cand.hash, observed_at: cand.enqueued_at || null };

  const dupId = ad.jaccardDuplicate(gene, existing, parseFloat(process.env.EVOLVER_CONV_DISTILL_DUP_JACCARD || '0.8'));
  if (dupId) { _convPatch(cand.hash, { failed_attempts_inc: true }); _log({ status: 'near_duplicate', duplicate_of: dupId, gene_id: gene.id }); return { ok: false, reason: 'near_duplicate', mode }; }

  gene = ad.normalizeValidation(gene).gene;
  const vg = pc.runValidations(gene, { repoRoot: getRepoRoot(), timeoutMs: _envInt('EVOLVE_DISTILL_VALIDATION_TIMEOUT_MS', 20000) });
  if (!vg.ok) { _convPatch(cand.hash, { failed_attempts_inc: true }); _log({ status: 'light_validation_failed', validation: gene.validation }); return { ok: false, reason: 'light_validation_failed', mode }; }

  // SHADOW TERMINAL — surface the FULL candidate gene for human review. NEVER upsert.
  _log({ status: 'conv_distill_shadow_candidate', mode: 'shadow', source_capability: cand.capability, source_hash: cand.hash, gene });
  const ok = _convPatch(cand.hash, { shadowed_at: new Date(now).toISOString() });
  if (!ok) console.warn('[P2] conv-distill shadow state write FAILED — may re-surface candidate ' + gene.id + ' next cycle.');
  return { ok, mode: 'shadow', gene_id: gene.id, reason: 'shadowed', candidate: gene };
}

module.exports = {
  autoDistillConversation, enqueueCandidate,
  _convGet, _convPatch, _convSlugGet, _convQueuePath, _readQueue, // for tests
};

'use strict';

// P3 — Autonomous LLM-quality gene distillation.
//
// Closes the last gap in the flywheel: the forward distiller (skillDistiller)
// can PREPARE a distillation prompt and COMPLETE a gene from an LLM response,
// but the LLM step required a human ("run your LLM, then `distill
// --response-file`"). This module runs that LLM step AUTONOMOUSLY by reusing
// the P1 execBridge machinery to spawn a LIGHT, read-only headless `claude`
// (the 'claude-distill' recipe) that reads the prompt on stdin and emits a Gene
// JSON — then feeds it back through validation + a REAL quality gate.
//
// The quality gate is load-bearing (neither completeDistillation nor createGene
// runs the gene's own validation): we (a) structural-validate + canonicalize
// via validateSynthesizedGene, (b) reject near-duplicates (Jaccard on
// signals_match — validateSynthesizedGene only catches exact set-equality),
// (c) NORMALIZE validation to light commands + VERIFY-GREEN by actually running
// it (the same runner solidify uses), and only THEN upsert the exact object we
// proved green. Shadow-first: EVOLVER_AUTO_DISTILL_LLM=off|shadow|enforce.
//
// Design + adversarial reviews: P3 build spec (this session). Reuses, never
// re-implements, execBridge (runChild/resolveBin/RECIPES/tryParseClaudeResult).

const crypto = require('crypto');
const fs = require('fs');

const execBridge = require('./execBridge');
const sd = require('./skillDistiller');
const pc = require('./policyCheck');
const assetStore = require('./assetStore');
const { getRepoRoot } = require('./paths');

// Heavy validation commands that PASS the policyCheck filter (verified) but are
// too slow / environment-fragile to run at solidify time (P1 E2E lesson: the
// test suite is ~77s and fails under symlinked node_modules). Must be stripped.
const HEAVY_DENYLIST = /(validate-suite|--test\b|test\/[^ ]*\.test\.js|\bjest\b|\bmocha\b)/;

function _envInt(name, def) { const n = parseInt(process.env[name] || '', 10); return Number.isFinite(n) && n > 0 ? n : def; }
function _mode(explicit) {
  const m = String(explicit || process.env.EVOLVER_AUTO_DISTILL_LLM || 'off').toLowerCase().trim();
  return (m === 'shadow' || m === 'enforce') ? m : 'off';
}

// --- §4b step 1+2+3: filter policy-blocked + heavy commands; inject light default if empty ---
function normalizeValidation(gene) {
  const orig = Array.isArray(gene.validation) ? gene.validation.slice() : [];
  const dropped = [];
  const kept = orig.filter((cmd) => {
    const c = String(cmd || '');
    if (!pc.isValidationCommandAllowed(c)) { dropped.push(c); return false; }
    if (HEAVY_DENYLIST.test(c)) { dropped.push(c); return false; }
    return true;
  });
  let injected = false;
  if (kept.length === 0) { kept.push('node --version'); injected = true; }
  const out = Object.assign({}, gene, { validation: kept });
  return { gene: out, injected, dropped };
}

// --- §5 M1: near-duplicate gate. validateSynthesizedGene only rejects EXACT
// set-equality of signals_match; this catches near-dups by Jaccard overlap. ---
function jaccardDuplicate(gene, existingGenes, threshold) {
  const t = Number.isFinite(threshold) ? threshold : 0.8;
  const a = new Set((gene.signals_match || []).map((s) => String(s).toLowerCase()));
  if (a.size === 0) return null;
  for (const eg of existingGenes || []) {
    if (!eg || eg.id === gene.id) continue; // same id is an update, not a dup
    const b = new Set((eg.signals_match || []).map((s) => String(s).toLowerCase()));
    if (b.size === 0) continue;
    let inter = 0;
    a.forEach((x) => { if (b.has(x)) inter++; });
    const union = a.size + b.size - inter;
    const j = union > 0 ? inter / union : 0;
    if (j >= t) return eg.id;
  }
  return null;
}

function _log(entry) {
  try {
    const p = sd.distillerLogPath();
    require('./skillDistiller'); // ensure module path resolved
    fs.appendFileSync(p, JSON.stringify(Object.assign({ at: new Date().toISOString(), component: 'auto-distill-llm' }, entry)) + '\n', 'utf8');
  } catch (_) {}
}

function _cleanupRequest(dr) {
  try { const rp = sd.distillRequestPath(); if (fs.existsSync(rp)) fs.unlinkSync(rp); } catch (_) {}
  try { if (dr && dr.promptPath && fs.existsSync(dr.promptPath)) fs.unlinkSync(dr.promptPath); } catch (_) {}
}

// Patch the shared distiller scalars (used by the human/forward throttle).
// distillation_count_inc:true bumps the counter. Returns ok boolean.
function _writeState(patch) {
  try {
    const st = sd.readDistillerState() || {};
    for (const k of Object.keys(patch)) {
      if (k === 'distillation_count_inc') { if (patch[k]) st.distillation_count = (Number(st.distillation_count) || 0) + 1; continue; }
      st[k] = patch[k];
    }
    sd.writeDistillerState(st);
    return true;
  } catch (_) { return false; }
}

// ===========================================================================
// P3-OWNED CADENCE/IDEMPOTENCY STATE MACHINE  (distiller_state.json -> p3_llm.by_hash)
// ---------------------------------------------------------------------------
// The 7 prior Bugbot rounds proved that overloading the two shared scalars
// (last_distillation_at = cross-distiller 24h throttle; last_data_hash =
// prepareDistillation idempotency) to ALSO mean "P3 already processed this data
// in this mode" creates contradictions (shadow-throttle vs shadow->enforce;
// failure-throttle vs changed-data-retry). The fix: ONE P3-owned key keyed by
// (dataHash) recording per-mode outcomes, as the SOLE authority for P3 cadence.
// P3 never reads last_distillation_at / shouldDistill() for its own cadence (C7).
// ===========================================================================
const OWNER = 'p3-auto';
const P3_COOLDOWN_MS = () => _envInt('EVOLVER_AUTO_DISTILL_LLM_COOLDOWN_MS', 1800000); // 30 min, P3-owned (not the shared 24h)
const MAX_FAILED_ATTEMPTS = () => _envInt('EVOLVER_AUTO_DISTILL_LLM_MAX_ATTEMPTS', 3);
const HASH_CAP = () => _envInt('EVOLVER_AUTO_DISTILL_LLM_HASH_CAP', 32);

function _p3Get(H) {
  try { return ((sd.readDistillerState() || {}).p3_llm || {}).by_hash && (sd.readDistillerState().p3_llm.by_hash[H]) || null; }
  catch (_) { return null; }
}

function _p3Cap(byHash) {
  const keys = Object.keys(byHash);
  const cap = HASH_CAP();
  if (keys.length <= cap) return byHash;
  // evict non-terminal (no enforced_at) oldest-first; only evict enforced when no non-terminal remain
  const age = (k) => {
    const r = byHash[k];
    return Math.max(Date.parse(r.shadowed_at || 0) || 0, Date.parse(r.enforced_at || 0) || 0, Date.parse(r.last_attempt_at || 0) || 0);
  };
  const nonTerminal = keys.filter((k) => !byHash[k].enforced_at).sort((a, b) => age(a) - age(b));
  const terminal = keys.filter((k) => byHash[k].enforced_at).sort((a, b) => age(a) - age(b));
  const order = nonTerminal.concat(terminal); // evict non-terminal first
  let n = keys.length;
  for (const k of order) { if (n <= cap) break; delete byHash[k]; n--; }
  return byHash;
}

// Read-modify-write a by_hash[H] record. Returns ok boolean (caller fails closed).
function _p3Patch(H, patch) {
  try {
    const st = sd.readDistillerState() || {};
    if (!st.p3_llm || typeof st.p3_llm !== 'object') st.p3_llm = { version: 1, by_hash: {} };
    if (!st.p3_llm.by_hash || typeof st.p3_llm.by_hash !== 'object') st.p3_llm.by_hash = {};
    const cur = st.p3_llm.by_hash[H] || { shadowed_at: null, enforced_at: null, enforced_gene_id: null, failed_attempts: 0, last_attempt_at: null };
    for (const k of Object.keys(patch)) {
      if (k === 'failed_attempts_inc') { if (patch[k]) cur.failed_attempts = (Number(cur.failed_attempts) || 0) + 1; continue; }
      cur[k] = patch[k];
    }
    st.p3_llm.by_hash[H] = cur;
    _p3Cap(st.p3_llm.by_hash);
    sd.writeDistillerState(st);
    return true;
  } catch (_) { return false; }
}

// The whole cadence machine: pure decision from (mode, rec, now). -> 'spawn' | <skip reason>
function _p3Decide(mode, rec, now) {
  if (rec && rec.enforced_at) return 'enforced_idempotent_skip';                 // C8
  if (mode === 'shadow') {
    if (rec && rec.shadowed_at) return 'shadow_idempotent_skip';                 // C1
  } else { // enforce
    if (rec && rec.shadowed_at) return 'spawn';                                  // C2/C3: enforce after shadow on same H
  }
  if (rec && (Number(rec.failed_attempts) || 0) >= MAX_FAILED_ATTEMPTS()) return 'failed_exhausted'; // C4
  if (rec && (Number(rec.failed_attempts) || 0) >= 1 && rec.last_attempt_at &&
      (now - Date.parse(rec.last_attempt_at)) < P3_COOLDOWN_MS()) return 'p3_cooldown'; // C4 backoff
  return 'spawn'; // fresh, or cooled retry (changed data is a new H -> fresh -> C5)
}

// Classify the shared request file: 'yield' (foreign/fresh -> honor C6) |
// 'reclaim' (P3-own same-hash stale -> take over) | 'none'.
function _classifyInflightRequest(H, now) {
  const rp = sd.distillRequestPath();
  if (!fs.existsSync(rp)) return { kind: 'none' };
  let req; try { req = JSON.parse(fs.readFileSync(rp, 'utf8')); } catch (_) { return { kind: 'none' }; }
  const ageMs = now - new Date((req && req.created_at) || 0).getTime();
  const freshMs = _envInt('EVOLVE_DISTILL_REQUEST_FRESH_MS', _envInt('EVOLVE_DISTILL_TIMEOUT_MS', 180000));
  const isFresh = Number.isFinite(ageMs) && ageMs >= 0 && ageMs < freshMs;
  if (req && req.owner === OWNER && req.data_hash === H) return { kind: 'reclaim', ageMs }; // P3's own abandoned request for THIS data
  if (isFresh) return { kind: 'yield', ageMs };                                  // foreign (manual) or P3-other-hash, still fresh -> C6
  return { kind: 'none' };                                                       // stale foreign -> fair game
}

// P3 readiness = success thresholds ONLY (the throttle-free half of shouldDistill),
// never the shared 24h last_distillation_at scalar (C7). Reuses collected data.
function _p3DataReady(data) {
  if (String(process.env.SKILL_DISTILLER || 'true').toLowerCase() === 'false') return false;
  if (!data || !Array.isArray(data.successCapsules)) return false;
  if (data.successCapsules.length < sd.DISTILLER_MIN_CAPSULES) return false;
  return true;
}

// ---------------------------------------------------------------------------
// autoDistillLlm — the autonomous flow. spawnFn + now are the test seams.
// ---------------------------------------------------------------------------
async function autoDistillLlm(opts = {}) {
  const now = opts.now ? opts.now() : Date.now();
  const mode = _mode(opts.mode);
  if (mode === 'off') return { ok: false, reason: 'disabled', mode };

  // (A) READINESS — success thresholds only (NOT shouldDistill's 24h throttle).
  const data = sd.collectDistillationData();
  if (!_p3DataReady(data)) {
    if (!data || (data.successCapsules || []).length < sd.DISTILLER_MIN_CAPSULES) return { ok: false, reason: 'insufficient_data', mode };
    return { ok: false, reason: 'not_ready', mode };
  }
  const H = data.dataHash;
  const inputCapsuleCount = data.successCapsules.length;

  // (D) P3 PER-(HASH,MODE) GATE — the whole cadence machine.
  const decision = _p3Decide(mode, _p3Get(H), now);
  if (decision !== 'spawn') { _log({ status: decision, data_hash: H, mode }); return { ok: false, reason: decision, mode }; }

  // (B) IN-FLIGHT REQUEST — after the P3 gate said spawn. Yield to foreign/fresh
  // (C6); reclaim P3's own stale same-hash request; else proceed.
  const inflight = _classifyInflightRequest(H, now);
  if (inflight.kind === 'yield') { _log({ status: 'yield_inflight_request', age_ms: inflight.ageMs }); return { ok: false, reason: 'inflight_request', mode }; }
  if (inflight.kind === 'reclaim') { _log({ status: 'reclaim_own_request', data_hash: H }); _cleanupRequest({}); }

  // (E) PREPARE — bypass the shared last_data_hash skip (P3's gate is the authority);
  // stamp owner so a future cycle can attribute/reclaim this request.
  const dr = sd.prepareDistillation({ ignoreHashSkip: true, owner: OWNER });
  if (!dr.ok) return { ok: false, reason: dr.reason, mode };

  // Arm the cooldown up-front so even a hard crash mid-run throttles the next cycle.
  if (!_p3Patch(H, { last_attempt_at: new Date(now).toISOString() })) {
    _cleanupRequest(dr); _log({ status: 'state_write_failed', data_hash: H });
    return { ok: false, reason: 'state_write_failed', mode };
  }

  let promptText;
  try { promptText = fs.readFileSync(dr.promptPath, 'utf8'); }
  catch (e) { _log({ status: 'prompt_read_error', reason: e.message }); _cleanupRequest(dr); return { ok: false, reason: 'prompt_read_error', mode }; }

  // (2) RUN CLAUDE — light read-only recipe; hard timeout + group-kill via runChild.
  const spawnFn = opts.spawnFn || require('child_process').spawn;
  const built = execBridge.RECIPES['claude-distill'].buildArgs({ sessionId: crypto.randomUUID() });
  const r = await execBridge.runChild(spawnFn, built.bin, built.args, {
    env: Object.assign({}, process.env, built.env),
    stdinText: promptText,
    timeoutMs: _envInt('EVOLVE_DISTILL_TIMEOUT_MS', 180000),
    label: 'Distill', bufferMode: 'tail', cwd: getRepoRoot(),
  });

  // TRANSIENT failures — clean P3's own request (so step B doesn't see it next
  // cycle) and rely on the up-front last_attempt_at cooldown. Do NOT bump
  // failed_attempts (transient != deterministic).
  if (r.spawnError) { _cleanupRequest(dr); _log({ status: 'claude_spawn_error', reason: r.spawnError }); return { ok: false, reason: 'claude_spawn_error', mode }; }
  if (r.timedOut) { _cleanupRequest(dr); _log({ status: 'claude_timeout' }); return { ok: false, reason: 'claude_timeout', mode }; }
  if (r.code !== 0) { _cleanupRequest(dr); _log({ status: 'claude_nonzero_exit', code: r.code }); return { ok: false, reason: 'claude_nonzero_exit', mode }; }

  // (3) PARSE — envelope then Gene. DETERMINISTIC failures bump failed_attempts.
  const envelope = execBridge.tryParseClaudeResult(r.stdout);
  if (!envelope || envelope.is_error) { _p3Patch(H, { failed_attempts_inc: true }); _cleanupRequest(dr); _log({ status: 'claude_is_error', data_hash: H }); return { ok: false, reason: 'claude_is_error', mode }; }
  const rawGene = sd.extractJsonFromLlmResponse(envelope.result);
  if (!rawGene) { _p3Patch(H, { failed_attempts_inc: true }); _cleanupRequest(dr); _log({ status: 'no_gene_in_response', data_hash: H }); return { ok: false, reason: 'no_gene_in_response', mode }; }

  // (4) STRUCTURAL VALIDATION + canonicalization (createGene runs inside).
  const existing = (assetStore.loadGenes && assetStore.loadGenes()) || [];
  const v = sd.validateSynthesizedGene(rawGene, existing);
  if (!v.valid) { _p3Patch(H, { failed_attempts_inc: true }); _cleanupRequest(dr); _log({ status: 'validation_failed', errors: v.errors }); return { ok: false, reason: 'validation_failed', mode }; }
  let gene = v.gene;

  // (5) NEAR-DUPLICATE GATE.
  const dupId = jaccardDuplicate(gene, existing, parseFloat(process.env.EVOLVER_AUTO_DISTILL_LLM_DUP_JACCARD || '0.8'));
  if (dupId) { _p3Patch(H, { failed_attempts_inc: true }); _cleanupRequest(dr); _log({ status: 'near_duplicate', duplicate_of: dupId, gene_id: gene.id }); return { ok: false, reason: 'near_duplicate', mode }; }

  // (6) LIGHT-VALIDATION NORMALIZE + RUN-GREEN — the load-bearing gate.
  gene = normalizeValidation(gene).gene;
  const vg = pc.runValidations(gene, { repoRoot: getRepoRoot(), timeoutMs: _envInt('EVOLVE_DISTILL_VALIDATION_TIMEOUT_MS', 20000) });
  if (!vg.ok) { _p3Patch(H, { failed_attempts_inc: true }); _cleanupRequest(dr); _log({ status: 'light_validation_failed', validation: gene.validation }); return { ok: false, reason: 'light_validation_failed', mode }; }
  // INVARIANT: `gene` is the EXACT object proven green; we upsert THIS object.

  // (7) MODE BRANCH.
  if (mode === 'shadow') {
    // Record shadow in the P3 authority (NOT the shared throttle). by_hash now
    // makes shouldDistill irrelevant to P3 cadence, so shadow neither re-spawns
    // (C1: shadow_idempotent_skip next time) nor blocks enforce (C2: enforce
    // branch of _p3Decide returns spawn when shadowed_at is set).
    const ok = _p3Patch(H, { shadowed_at: new Date(now).toISOString() });
    if (!ok) { _log({ status: 'shadow_state_write_failed', gene_id: gene.id, data_hash: H }); console.warn('[Distiller-LLM] WARNING: shadow by_hash write FAILED — may re-spawn next cycle.'); }
    _log({ status: 'shadow_candidate', gene_id: gene.id, data_hash: H, validation_passed: true, validation: gene.validation });
    _cleanupRequest(dr);
    return { ok: false, reason: 'shadow_logged', candidate: gene, mode };
  }

  // enforce: upsert the SAME validated object.
  gene._distilled_meta = { distilled_at: new Date(now).toISOString(), source_capsule_count: inputCapsuleCount, data_hash: H, via: 'auto-distill-llm' };
  assetStore.upsertGene(gene); // recomputes canonical asset_id
  // by_hash.enforced_at is the IDEMPOTENCY AUTHORITY — write it first.
  const authOk = _p3Patch(H, { enforced_at: new Date(now).toISOString(), enforced_gene_id: gene.id });
  if (!authOk) { _log({ status: 'enforce_state_write_failed', gene_id: gene.id, data_hash: H }); console.warn('[Distiller-LLM] WARNING: gene ' + gene.id + ' upserted but by_hash write FAILED — Jaccard/exact-dup gates guard re-upsert.'); }
  // Courtesy shared-scalar write so the human/forward 24h throttle + idempotency
  // stay eventually-consistent with P3 (P3 never READS these for its own cadence).
  _writeState({ last_distillation_at: new Date(now).toISOString(), last_data_hash: H, last_gene_id: gene.id, distillation_count_inc: true });
  _log({ status: 'success', gene_id: gene.id, validation_passed: true, validation: gene.validation });
  _cleanupRequest(dr);

  // publish only on explicit opt-in (never auto-publish an LLM gene to Hub by default).
  if (String(process.env.EVOLVER_AUTO_DISTILL_LLM_PUBLISH || '') === 'true') {
    try { require('./skillPublisher').publishSkillToHub(gene); } catch (_) {}
  }
  return { ok: true, gene, mode };
}

module.exports = {
  autoDistillLlm, normalizeValidation, jaccardDuplicate, HEAVY_DENYLIST,
  _p3Decide, _classifyInflightRequest, _p3Get, _p3Patch, // exported for unit tests
};

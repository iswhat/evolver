'use strict';

// P1 auto-exec bridge — closes the Brain->Hand loop on Claude Code (and, dormant,
// OpenClaw). evolver's daemon prints a sessions_spawn(...) call to stdout but
// never spawns the executor; the only thing that did was the OpenClaw-only
// feishu wrapper. This module is the harness-agnostic, tested generalization:
// run the Brain (`node index.js run` with EVOLVE_BRIDGE=true), scrape its
// stdout for the FIRST sessions_spawn(...) (via bridge.parseFirstSpawnCall),
// then spawn the Hand (a headless `claude -p` run) to apply the patch + run
// solidify, gated by a status file. Shadow-first: only runs via the opt-in
// `exec` CLI when EVOLVE_EXEC_BRIDGE=true.
//
// Design + adversarial reviews: P1 build spec (this session). Reference loop
// (read-only, NOT edited): feishu-evolver-wrapper-private/index.js.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync, execFileSync } = require('child_process');

const { getRepoRoot, getEvolutionDir } = require('./paths');

// --- B2 defense: vendor a parser fallback so a stale worktree (missing the
// P0-a export on bridge.js) can never crash the bridge at runtime. ---
const _bridge = require('./bridge');
const parseFirstSpawnCall =
  typeof _bridge.parseFirstSpawnCall === 'function'
    ? _bridge.parseFirstSpawnCall
    : _localParseFirstSpawnCall;

const _SPAWN_MARKER = 'sessions_spawn(';
function _localExtractFirstSpawnPayload(text) {
  const s = String(text || '');
  const idx = s.indexOf(_SPAWN_MARKER);
  if (idx === -1) return null;
  let braceStart = -1;
  for (let i = idx + _SPAWN_MARKER.length; i < s.length; i++) {
    if (s[i] === '{') { braceStart = i; break; }
    if (!/\s/.test(s[i])) break;
  }
  if (braceStart === -1) return null;
  let depth = 0, inString = false, escape = false;
  for (let i = braceStart; i < s.length; i++) {
    const ch = s[i];
    if (inString) {
      if (escape) escape = false;
      else if (ch === '\\') escape = true;
      else if (ch === '"') inString = false;
    } else if (ch === '"') inString = true;
    else if (ch === '{') depth++;
    else if (ch === '}') { depth--; if (depth === 0) return s.slice(braceStart, i + 1); }
  }
  return null;
}
function _localParseFirstSpawnCall(text) {
  const raw = _localExtractFirstSpawnPayload(text);
  if (raw === null) return null;
  try { const o = JSON.parse(raw); return o && typeof o === 'object' ? o : null; }
  catch (_) { return null; }
}

// --- env-driven knobs (defaults baked here) ---
const HAND_TIMEOUT_MS  = () => parseInt(process.env.EVOLVE_HAND_TIMEOUT_MS  || '900000', 10) || 900000;
const BRAIN_TIMEOUT_MS = () => parseInt(process.env.EVOLVE_BRAIN_TIMEOUT_MS || '900000', 10) || 900000;
const KILL_GRACE_MS    = () => parseInt(process.env.EVOLVE_HAND_KILL_GRACE_MS || '10000', 10) || 10000;
const IDLE_SLEEP_MS    = () => parseInt(process.env.EVOLVE_IDLE_SLEEP_MS || '120000', 10) || 120000;
const MAX_BUF_BYTES    = () => parseInt(process.env.EVOLVE_HAND_MAX_BUF_BYTES || '262144', 10) || 262144;

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
function tail(s, n) { const str = String(s || ''); return str.length <= n ? str : str.slice(-n); }

// #179 r4: the Brain is the EVOLVER package's own index.js (this module is
// src/gep/execBridge.js -> ../../index.js), NOT getRepoRoot()/index.js. In an
// npm-install layout getRepoRoot() is the user's project (the tree to evolve),
// which has no evolver index.js. Resolve evolver's own entrypoint from __dirname.
const EVOLVER_OWN_INDEX = path.resolve(__dirname, '..', '..', 'index.js');

// ---------------------------------------------------------------------------
// resolveBin — per-harness binary resolver (generalizes feishu resolveOpenclawPath)
// order: env override -> `which` -> candidate files -> bare cmd (bare NOT cached, m10)
// ---------------------------------------------------------------------------
const _binCache = {};
const _BIN_SPECS = {
  'claude-code': { env: 'CLAUDE_BIN', cmd: 'claude',
    candidates: ['claude', '~/.npm-global/bin/claude', '/usr/local/bin/claude', '/usr/bin/claude'] },
  'openclaw': { env: 'OPENCLAW_BIN', cmd: 'openclaw',
    candidates: ['openclaw', '~/.npm-global/bin/openclaw', '/usr/local/bin/openclaw', '/usr/bin/openclaw'] },
  // P4-b: codex-cli (npm-global) + opencode (bun). Cross-home candidates so a
  // PATH-stripped cron/daemon still resolves them; `which` wins first when PATH is set.
  'codex': { env: 'CODEX_BIN', cmd: 'codex',
    candidates: ['codex', '~/.npm-global/bin/codex', '~/.bun/bin/codex', '/usr/local/bin/codex', '/usr/bin/codex'] },
  'opencode': { env: 'OPENCODE_BIN', cmd: 'opencode',
    candidates: ['opencode', '~/.bun/bin/opencode', '~/.npm-global/bin/opencode', '/usr/local/bin/opencode', '/usr/bin/opencode'] },
};
function _expandHome(p) { return p.startsWith('~/') ? path.join(process.env.HOME || '', p.slice(2)) : p; }

// ---------------------------------------------------------------------------
// _resolveNpmCmdShim — CVE-2024-27980 safe path for Windows npm shims.
//
// Starting with Node 18.20.2 / 20.12.2 / 21.7.3 / 22+, child_process.spawn()
// refuses to launch a .cmd or .bat without `shell: true` (throws EINVAL).
// This package's engines require Node >= 22.12, so any Windows code path
// that hands a .cmd target to spawn() without `shell: true` is dead. The
// fix the auto-exec recipes need is "spawn the underlying JS entry through
// `node` directly" — shell-free, zero injection surface, and zero
// argument-quoting concerns (vs the cmd.exe /d /s /c wrapper alternative
// which requires hand-rolled cmd-style quoting). This is the direction
// autogame-17 recommended in the #196 review:
// https://github.com/EvoMap/evolver-private-dev/pull/196#pullrequestreview-4438622343
//
// npm-cli generates Windows shims with a well-known format whose last
// non-empty line ends with:
//   ... "%_prog%"  "%dp0%\<relative-entry>" %*
// where %dp0% is the .cmd's own directory. Pulling the relative entry out
// gives us the underlying JS file we can hand to node.exe directly.
//
// Returns { bin, args } when the shim was recognized and rewritten; null
// when the bin is not a .cmd, is on a non-Windows host, or the file does
// not match the npm-cli format (custom shim, hand-rolled wrapper, etc.).
// Callers must fall through to the original bin + args on null.
function _resolveNpmCmdShim(bin, args) {
  if (process.platform !== 'win32') return null;
  if (!bin || !/\.cmd$/i.test(bin)) return null;

  // We need the absolute path of the .cmd file to read its content. spawn()
  // would otherwise PATH-resolve a bare name itself; here we have to do it.
  let absPath = bin;
  if (!path.isAbsolute(bin)) {
    try {
      const out = execFileSync('where', [bin], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        windowsHide: true,
      }).trim();
      absPath = out.split(/\r?\n/)[0].trim();
    } catch (_) {
      return null;
    }
    if (!absPath) return null;
  }

  let content;
  try { content = fs.readFileSync(absPath, 'utf8'); }
  catch (_) { return null; }

  // The "%_prog%" line is the actual exec. Some shim variants use single
  // quotes around the path or omit them entirely on the entry; the npm-cli
  // default (the one we care about) double-quotes both, so anchor on that.
  const m = content.match(/"%dp0%[\\/](.+?)"\s*%\*/);
  if (!m) return null;
  const entry = path.resolve(path.dirname(absPath), m[1]);

  // npm shims may omit the .js extension (Node resolves it). Accept the
  // path as-is OR with .js / .mjs appended, then hand the unresolved form
  // back to Node so its own require/resolve handles the lookup.
  if (!fs.existsSync(entry) &&
      !fs.existsSync(entry + '.js') &&
      !fs.existsSync(entry + '.mjs')) {
    return null;
  }

  return { bin: process.execPath, args: [entry, ...(args || [])] };
}

function resolveBin(harness) {
  const spec = _BIN_SPECS[harness];
  if (!spec) throw new Error(`execBridge: no bin spec for harness '${harness}'`);
  if (process.env[spec.env]) return process.env[spec.env];          // env always wins, never cached stale
  if (_binCache[harness]) return _binCache[harness];
  try { execSync(`which ${spec.cmd}`, { stdio: 'ignore' }); _binCache[harness] = spec.cmd; return spec.cmd; }
  catch (_) { /* fall through */ }
  for (const c of spec.candidates) {
    const abs = _expandHome(c);
    if (abs !== spec.cmd) { try { if (fs.existsSync(abs)) { _binCache[harness] = abs; return abs; } } catch (_) {} }
  }
  return spec.cmd; // bare cmd, NOT cached (m10) — let a later PATH change be picked up
}

// ---------------------------------------------------------------------------
// writeScopedSettings — bridge-owned, validated. NEVER the user's repo .claude/settings.json.
// --print silently ignores an invalid settings file, so we JSON.parse it back.
// ---------------------------------------------------------------------------
function writeScopedSettings() {
  const dir = getEvolutionDir();
  try { if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true }); } catch (_) {}
  const p = path.join(dir, 'hand_claude_settings.json');
  const settings = {
    permissions: {
      allow: [
        'Edit', 'Write', 'Read', 'Glob', 'Grep',
        'Bash(node index.js solidify)',
        'Bash(git status*)', 'Bash(git diff*)', 'Bash(git add*)', 'Bash(git rev-parse*)', 'Bash(git ls-files*)',
      ],
      deny: [
        'Bash(git push*)', 'Bash(rm -rf *)', 'Bash(curl *)', 'Bash(wget *)', 'Bash(sudo *)',
        'WebFetch', 'WebSearch',
      ],
    },
  };
  fs.writeFileSync(p, JSON.stringify(settings, null, 2) + '\n', 'utf8');
  // footgun guard (gate 1.4): a settings file that fails to parse is silently
  // ignored by --print, which under acceptEdits could over-permit. Fail loud.
  try { JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch (e) { throw new Error(`execBridge: wrote invalid scoped settings at ${p}: ${e.message}`); }
  return p;
}

// ---------------------------------------------------------------------------
// appendStatusFileContract — Risk #6: the GEP task only weakly mentions solidify,
// but the gate keys on [SOLIDIFY] SUCCESS/FAILED + a status JSON. Append a
// contract verbatim-aligned with evaluateStatusGate so a real success can't
// fall through to failure.
// ---------------------------------------------------------------------------
function appendStatusFileContract(taskText, statusFile, cycleTag) {
  return String(taskText || '') +
    '\n\n━━━━━━━━━━━━━━━━━━━━━━\n' +
    'MANDATORY POST-SOLIDIFY STEP (exec-bridge authority — cannot be skipped)\n' +
    '━━━━━━━━━━━━━━━━━━━━━━\n\n' +
    'After applying your changes you MUST run:\n' +
    '    node index.js solidify\n' +
    'It must print `[SOLIDIFY] SUCCESS` on completion (or `[SOLIDIFY] FAILED` on failure).\n\n' +
    `Then write this status file (cycle ${cycleTag}) at EXACTLY this path:\n` +
    `    ${statusFile}\n` +
    'with this JSON shape:\n' +
    '    {"result":"success|failure","en":"Status: [INTENT] <what you did, English, 1-2 sentences>","zh":"状态: [意图] <中文，1-2句>"}\n\n' +
    'Rules: INTENT ∈ {INNOVATION, REPAIR, OPTIMIZE}. "en"/"zh" must describe the ACTUAL work (no generic "done"). ' +
    'Both the [SOLIDIFY] marker AND this status file are required for the cycle to count as success.\n';
}

// ---------------------------------------------------------------------------
// runChild — spawn with HARD timeout + group-kill (B1) + buffer cap (M4) +
// label prefix (M6) + M3 clean-exit-not-timeout. Always resolves (never hangs).
// ---------------------------------------------------------------------------
function runChild(spawnFn, bin, args, { env, stdinText, timeoutMs, label, bufferMode, cwd } = {}) {
  return new Promise((resolve) => {
    let child;
    // CVE-2024-27980: Node >= 18.20.2 refuses to spawn .cmd / .bat without
    // shell:true. When the target is a recognized npm-cli Windows shim we
    // rewrite (bin, args) into (node.exe, [<entry.js>, ...args]) and bypass
    // the .cmd shell entirely. Pass-through for everything else: POSIX
    // hosts, .exe binaries, and unrecognized custom shims (caller may need
    // to install via an installer that produces .exe, or set the *_BIN env
    // override to an absolute non-.cmd path).
    const shim = _resolveNpmCmdShim(bin, args);
    const spawnBin = shim ? shim.bin : bin;
    const spawnArgs = shim ? shim.args : args;
    try {
      child = spawnFn(spawnBin, spawnArgs, {
        env,
        cwd: cwd || undefined, // #179 r4: run children in the evolution repo, not the launcher's cwd
        detached: true, // B1: own process group so we can kill the whole subtree
        stdio: [stdinText != null ? 'pipe' : 'ignore', 'pipe', 'pipe'],
      });
    } catch (e) {
      resolve({ code: null, stdout: '', stderr: '', timedOut: false, spawnError: e.message, truncated: false });
      return;
    }

    let out = '', err = '', truncated = false;
    let timedOut = false, spawnError = null, settled = false;
    let hardTimer = null, killTimer = null, backstop = null;
    const cap = MAX_BUF_BYTES();
    const pfx = label ? `[${label}] ` : '';
    // bufferMode picks which end of an over-cap stream to KEEP:
    //   'head' — the Brain emits sessions_spawn(...) FIRST, so keep the head or a
    //            huge full-prompt log after it would evict the line we must scrape
    //            (Bugbot #179 r2: no_spawn despite a good Brain run).
    //   'tail' — the Hand's claude result JSON + [SOLIDIFY] markers are at the END.
    const mode = bufferMode === 'head' ? 'head' : 'tail';

    // M4: bound the retained buffer at `cap` even when a single chunk is huge —
    // concat then hard-slice every append so one large write can't blow past it.
    const append = (buf, chunk) => {
      const combined = buf + chunk;
      if (combined.length <= cap) return combined;
      truncated = true;
      return mode === 'head' ? combined.slice(0, cap) : combined.slice(-cap);
    };

    const finish = (code) => {
      if (settled) return; settled = true;
      if (code === 0) timedOut = false; // M3: clean exit within grace is NOT a timeout
      clearTimeout(hardTimer); clearTimeout(killTimer); clearTimeout(backstop);
      resolve({ code, stdout: out, stderr: err, timedOut, spawnError, truncated });
    };

    child.on('error', (e) => { spawnError = e.message; finish(null); });
    // #179 r6 (security MEDIUM): live-mirroring raw child output to the parent's
    // stdout/stderr aids debugging but can surface tool output / secrets in logs.
    // Mirror by default (operator-facing progress), but allow muting via
    // EVOLVE_HAND_QUIET=true; the captured buffer is unaffected either way.
    const mirror = String(process.env.EVOLVE_HAND_QUIET || '').toLowerCase() !== 'true';
    if (child.stdout) child.stdout.on('data', (d) => { out = append(out, d.toString()); if (mirror) process.stdout.write(pfx + d); });
    if (child.stderr) child.stderr.on('data', (d) => { err = append(err, d.toString()); if (mirror) process.stderr.write(pfx + d); });
    child.on('close', (code) => finish(code));

    hardTimer = setTimeout(() => {
      timedOut = true;
      const pid = child.pid;
      try { process.kill(-pid, 'SIGTERM'); } catch (_) { try { child.kill('SIGTERM'); } catch (_) {} }
      killTimer = setTimeout(() => {
        try { process.kill(-pid, 'SIGKILL'); } catch (_) { try { child.kill('SIGKILL'); } catch (_) {} }
      }, KILL_GRACE_MS());
      // backstop: even an unkillable child can't wedge the loop — detach pipes,
      // unref, and resolve so the parent event loop drains.
      backstop = setTimeout(() => {
        try { if (child.stdout) child.stdout.destroy(); if (child.stderr) child.stderr.destroy(); child.unref(); } catch (_) {}
        finish(null);
      }, KILL_GRACE_MS() + 5000);
    }, timeoutMs);

    if (stdinText != null) writeStdin(child, stdinText);
  });
}

// m7: EPIPE-guarded one-shot stdin write+end (child gets EOF to start its turn).
function writeStdin(child, text) {
  if (!child.stdin) return;
  child.stdin.on('error', () => {}); // swallow EPIPE if child already exited
  try { child.stdin.write(String(text), 'utf8'); child.stdin.end(); }
  catch (_) { /* child gone; the timeout/close path handles it */ }
}

// ---------------------------------------------------------------------------
// tryParseClaudeResult — M5: claude -p --output-format json emits ONE result
// doc. Strip our [Hand] prefix, take the last non-empty line, JSON.parse it.
// Do NOT substring-match (model's free-text result may contain "type":"result").
// ---------------------------------------------------------------------------
function tryParseClaudeResult(stdout) {
  const lines = String(stdout || '')
    .split('\n')
    .map((l) => l.replace(/^\[Hand\]\s?/, '').trim())
    .filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i--) {
    if (!lines[i].startsWith('{')) continue;
    try {
      const o = JSON.parse(lines[i]);
      if (o && o.type === 'result') return o;
    } catch (_) { /* keep scanning upward */ }
  }
  return null;
}

// ---------------------------------------------------------------------------
// evaluateStatusGate — minimal v1 gate. Fallback A/B behind EVOLVE_EXEC_FALLBACKS.
// ---------------------------------------------------------------------------
function evaluateStatusGate({ r, statusFile, cycleStartMs, attemptStartMs, solidifyProof }) {
  const combined = `${r.stdout}\n${r.stderr}`;
  if (r.spawnError) return { ok: false, kind: 'spawn_error', reason: `spawn error: ${r.spawnError}` };

  // claude JSON classification first (deterministic)
  const jr = tryParseClaudeResult(r.stdout);
  if (jr) {
    // #179 r4: persist only the fixed enum subtype, never jr.result (free model
    // text — may contain secrets/tool output that lands in the lessons log).
    if (jr.is_error) return { ok: false, kind: 'nonzero', reason: `claude is_error: ${String(jr.subtype || 'unknown').slice(0, 80)}` };
    if (Array.isArray(jr.permission_denials) && jr.permission_denials.length > 0) {
      // surface only the denied tool NAMES, never tool_input (the command may
      // embed secrets). Names are a bounded, non-sensitive enum.
      const names = jr.permission_denials.map((d) => (d && d.tool_name) || '?').slice(0, 10);
      return { ok: false, kind: 'permission_denied', reason: `tool perms denied: ${names.join(',')}` };
    }
  }

  const hasSolidifyFail = combined.includes('[SOLIDIFY] FAILED'); // honored for ALL harnesses (cheap, can only fail)
  // P4-b: how to obtain POSITIVE proof that solidify succeeded.
  //   'stdout' (default — claude-code): the [SOLIDIFY] SUCCESS marker rides the
  //     claude --output-format json transcript reliably. Unchanged behavior.
  //   'state'  (codex/opencode): those harnesses frame/swallow the child's
  //     stdout, so trust the evolver-written evolution_solidify_state.json
  //     instead (written by solidify.js, freshness+skip_reason gated). Stricter,
  //     not weaker. Per-attempt freshness uses attemptStartMs (cycleStartMs fallback).
  const sinceMs = Number.isFinite(attemptStartMs) ? attemptStartMs : cycleStartMs;
  const hasSolidifyOk = (solidifyProof === 'state')
    ? solidifyStateSucceededSince(sinceMs)
    : combined.includes('[SOLIDIFY] SUCCESS');
  const statusResult = readStatusResult(statusFile); // null | 'success' | 'failure' | 'invalid'

  // success check BEFORE honoring timeout (M3: clean exit within SIGTERM grace).
  // Bugbot #179 r3: require POSITIVE proof of solidify, not just absence of
  // FAILED. A Hand that skips `node index.js solidify`, or writes
  // result:"failure", must NOT close the cycle as success. So: exit 0 AND no
  // FAILED marker AND positive solidify proof (marker OR state per solidifyProof)
  // AND a status file whose parsed result is exactly "success".
  if (r.code === 0 && !hasSolidifyFail && hasSolidifyOk && statusResult === 'success') {
    return { ok: true, kind: 'success', reason: '' };
  }

  if (r.timedOut) return { ok: false, kind: 'timeout', reason: `hand timed out after ${HAND_TIMEOUT_MS()}ms` };

  if (String(process.env.EVOLVE_EXEC_FALLBACKS || '') === 'true') {
    // Fallback A: stdout success markers -> auto-write status (v1.1 — port from feishu).
    // P4-b (Bugbot #184): this path trusts stdout/stderr markers, which is exactly
    // what solidifyProof:'state' exists to DISTRUST (codex frames its transcript to
    // stderr; opencode reframes tool output into events). So skip Fallback A entirely
    // for 'state' harnesses — they fall through to Fallback B (the state-file proof,
    // which rejects skip_reason). claude-code ('stdout') keeps Fallback A unchanged.
    const hasEvent = combined.includes('"type": "EvolutionEvent"') || combined.includes('"type":"EvolutionEvent"');
    const hasCapsule = combined.includes('"type": "Capsule"') || combined.includes('"type":"Capsule"');
    if (solidifyProof !== 'state' && r.code === 0 && !hasSolidifyFail && (combined.includes('[SOLIDIFY] SUCCESS') || (hasEvent && hasCapsule))) {
      try {
        fs.writeFileSync(statusFile, JSON.stringify({
          result: 'success',
          en: 'Status: [AUTO-DETECTED] Hand completed work (status auto-generated by exec-bridge).',
          zh: '状态: [自动检测] Hand 完成工作（状态由 exec-bridge 自动生成）。',
        }, null, 2));
        return { ok: true, kind: 'success_fallback_a', reason: '' };
      } catch (_) { /* fall through */ }
    }
    // Fallback B: solidify_state confirms a success AFTER THIS ATTEMPT started.
    // Bugbot #179 r3: must gate on the per-ATTEMPT start, not the per-cycle start.
    // P4-b (Bugbot #184): reuse solidifyStateSucceededSince so Fallback B applies
    // the SAME success criteria as the primary 'state' proof — in particular it
    // must also REJECT a fresh status:'success' that carries skip_reason (e.g. a
    // PR-overlap rollback). Inlining the check here previously let such a rollback
    // close the cycle as success_fallback_b even though the primary gate rejects it.
    if (solidifyStateSucceededSince(sinceMs)) {
      return { ok: true, kind: 'success_fallback_b', reason: '' };
    }
  }

  // classify the failure precisely (#267): distinguish no-solidify-marker,
  // explicit result:"failure", and missing/invalid status from a plain nonzero.
  let kind;
  if (hasSolidifyFail) kind = 'solidify_failed';
  else if (!hasSolidifyOk) kind = 'no_solidify_marker';
  else if (statusResult === null) kind = 'no_status';
  else if (statusResult === 'failure') kind = 'status_failure';
  else if (statusResult === 'invalid') kind = 'status_invalid';
  else kind = 'nonzero';
  // #299: do NOT persist raw model/tool stdout (may contain secrets). Keep only
  // a classified, bounded reason — no transcript tail.
  return { ok: false, kind, reason: `code=${r.code} solidify_ok=${hasSolidifyOk} status_result=${statusResult}` };
}

// Parse the Hand-written status file: -> 'success' | 'failure' | 'invalid' | null(absent).
// #267: a positive `result:"success"` is required for the success gate.
function readStatusResult(statusFile) {
  if (!statusFile || !fs.existsSync(statusFile)) return null;
  try {
    const o = JSON.parse(fs.readFileSync(statusFile, 'utf8'));
    if (o && o.result === 'success') return 'success';
    if (o && o.result === 'failure') return 'failure';
    return 'invalid';
  } catch (_) { return 'invalid'; }
}

// P4-b: harness-AGNOSTIC positive proof that `node index.js solidify` ran and
// SUCCEEDED in THIS attempt — used for harnesses (codex/opencode) whose
// stdout/stderr may not relay the `[SOLIDIFY] SUCCESS` marker verbatim (codex
// frames its transcript to stderr; opencode reframes tool output into events).
// This is STRICTER than the stdout substring, not weaker: the state file is
// written by solidify.js itself (not the model, so it can't be faked by an
// echoed line), it is freshness-gated per-attempt, and it rejects any
// skip_reason. solidify.js writes state.last_solidify UNCONDITIONALLY on both
// success and failure (solidify.js:~1169), so freshness alone is insufficient —
// we require outcome.status==='success' AND no skip_reason AND at>=sinceMs.
// A PR-overlap rollback serializes outcome.status:'success' + skip_reason:
// 'open_pr_overlap' (solidify.js:~942) — that is NOT a real solidify success.
function solidifyStateSucceededSince(sinceMs) {
  try {
    if (!Number.isFinite(sinceMs)) return false;
    const stPath = path.join(getEvolutionDir(), 'evolution_solidify_state.json');
    if (!fs.existsSync(stPath)) return false;
    const st = JSON.parse(fs.readFileSync(stPath, 'utf8'));
    const ls = st && st.last_solidify;
    if (!ls || !ls.outcome) return false;
    if (ls.outcome.status !== 'success') return false;
    if (ls.outcome.skip_reason) return false; // PR-overlap rollback etc. is NOT a real success
    const at = Date.parse(ls.at || 0);
    return Number.isFinite(at) && at >= sinceMs;
  } catch (_) { return false; }
}

// thin lesson bank (full bank deferred to v1.1)
function appendFailureLesson(cycleTag, tag, reason) {
  try {
    const dir = getEvolutionDir();
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.appendFileSync(path.join(dir, 'exec_bridge_lessons.jsonl'),
      JSON.stringify({ at: new Date().toISOString(), cycle: cycleTag, tag, reason: String(reason || '').slice(0, 500) }) + '\n', 'utf8');
  } catch (_) {}
}

// ---------------------------------------------------------------------------
// Recipes — per-harness Hand invocation.
// ---------------------------------------------------------------------------
const RECIPES = {
  'claude-code': {
    deliversTaskVia: 'stdin',
    buildArgs({ sessionId, statusFile, cycleTag, settingsPath }) {
      const allow = [
        'Edit', 'Write', 'Read', 'Glob', 'Grep',
        'Bash(node index.js solidify)',
        'Bash(git status*)', 'Bash(git diff*)', 'Bash(git add*)', 'Bash(git rev-parse*)', 'Bash(git ls-files*)',
      ];
      const args = [
        '-p', '--output-format', 'json',
        '--permission-mode', 'acceptEdits',
        '--settings', settingsPath,
        '--allowedTools', ...allow, // redundant defense vs silently-ignored settings (gate 1.4)
        '--model', process.env.EVOLVE_HAND_MODEL || 'sonnet',
        '--session-id', sessionId,
        '--add-dir', getRepoRoot(),
        '--max-turns', String(process.env.EVOLVE_HAND_MAX_TURNS || 60),
        ...(String(process.env.EVOLVE_HAND_DANGEROUS || '') === 'true' ? ['--dangerously-skip-permissions'] : []),
      ];
      return { bin: resolveBin('claude-code'), args,
        env: { EVOLVE_CYCLE_TAG: String(cycleTag), EVOLVE_STATUS_FILE: statusFile } };
    },
  },
  // v1.1 — contract written, dormant (feishu already closes the openclaw loop).
  'openclaw': {
    deliversTaskVia: 'argv',
    buildArgs({ sessionId, statusFile, cycleTag, taskText }) {
      return {
        bin: resolveBin('openclaw'),
        args: ['agent', '--agent', 'main', '--session-id', sessionId, '-m', taskText, '--timeout', '600'],
        env: { EVOLVE_CYCLE_TAG: String(cycleTag), EVOLVE_STATUS_FILE: statusFile },
      };
    },
  },
  // P4-b — codex-cli 0.131.0 headless `codex exec`. SHADOW/experimental until the
  // live smoke test (scripts/smoke-exec-hand.sh) passes on a working-provider box.
  // Verified on-box 2026-06-03 (flags/sandbox/framing; the live agentic turn was
  // NOT verifiable here — provider auth 401):
  //  * deliversTaskVia:'stdin' — `codex exec` with no PROMPT reads stdin; the
  //    bridge pipes taskText (stdio[0]='pipe'). Avoids the argv leading-dash footgun.
  //  * solidifyProof:'state' — codex frames its transcript to STDERR (stdout=0 bytes)
  //    and may not relay the child `node index.js solidify` stdout, so the gate uses
  //    evolution_solidify_state.json (written by solidify.js) as positive proof.
  //  * -s workspace-write: writes confined to [workdir,/tmp,$TMPDIR], NETWORK OFF —
  //    the claude-acceptEdits analog (NOT --dangerously-bypass). Coarser than claude's
  //    per-command allow/deny (codex may run arbitrary shell INSIDE the sandbox), but
  //    network-off + cwd=git-repo make in-workspace damage recoverable.
  //  * -c approval_policy=never: non-interactive auto-approve INSIDE the sandbox.
  //  * -C REPO_ROOT: working + sandbox root.
  //  * --add-dir getEvolutionDir(): UNCONDITIONAL — MEMORY_DIR/EVOLUTION_DIR/
  //    OPENCLAW_WORKSPACE/EVOLVER_SESSION_SCOPE (paths.js) can relocate the status +
  //    state files OUTSIDE REPO_ROOT, which workspace-write would otherwise block.
  //  * --skip-git-repo-check + --ephemeral (no session persistence in ~/.codex).
  //  * NO --session-id (codex has none; resume is a subcommand) — passed id ignored.
  //  * EVOLVE_HAND_DANGEROUS=true escalates to danger-full-access (parity escape hatch).
  //  * -m only when EVOLVE_HAND_MODEL is set (codex wants a bare model name; claude's
  //    'sonnet' default would be wrong to forward).
  'codex': {
    deliversTaskVia: 'stdin',
    solidifyProof: 'state',
    buildArgs({ statusFile, cycleTag }) {
      const sandbox = String(process.env.EVOLVE_HAND_DANGEROUS || '') === 'true'
        ? 'danger-full-access' : 'workspace-write';
      const args = [
        'exec',
        '-s', sandbox,
        '-c', 'approval_policy=never',
        '-C', getRepoRoot(),
        '--add-dir', getEvolutionDir(),
        '--skip-git-repo-check',
        '--ephemeral',
        ...(process.env.EVOLVE_HAND_MODEL ? ['-m', process.env.EVOLVE_HAND_MODEL] : []),
        // task delivered on stdin (deliversTaskVia:'stdin'); no PROMPT argv.
      ];
      return { bin: resolveBin('codex'), args,
        env: { EVOLVE_CYCLE_TAG: String(cycleTag), EVOLVE_STATUS_FILE: statusFile } };
    },
  },
  // P4-b — opencode 1.14.41 headless `opencode run [message..]`. SHADOW/experimental
  // (same live-turn caveat as codex; opencode hung at the model call on-box).
  //  * deliversTaskVia:'argv' — `opencode run` reads the message from the ARGV
  //    positional (NOT stdin). Verified multiline-safe (ARG_MAX 3.2MB, shell-free
  //    array spawn). The message MUST be the LAST arg (variadic [message..]); a `--`
  //    terminator guards a '-'-leading taskText.
  //  * solidifyProof:'state' — same rationale; opencode reframes tool output into
  //    events that bufferMode:'tail' could evict.
  //  * PERMISSIONS ASYMMETRY (honest): opencode has NO fine-grained scoping or
  //    sandbox — only the blunt --dangerously-skip-permissions (can run unrestricted
  //    shell: push/curl/rm anywhere). Mandatory for headless function (else it hangs
  //    on the first edit approval), so it is gated by a SECOND explicit env
  //    EVOLVE_OPENCODE_DANGEROUS=true, refused FAIL-FAST before the loop in
  //    runExecBridge (NOT thrown from buildArgs, which stays pure). Weakest-isolation
  //    harness — documented, opt-in twice.
  //  * --dir REPO_ROOT. No --format json (default relays to stdout = operator mirror;
  //    json buries output in non-tail events). -m only when EVOLVE_HAND_MODEL set
  //    (opencode wants provider/model).
  'opencode': {
    deliversTaskVia: 'argv',
    solidifyProof: 'state',
    buildArgs({ statusFile, cycleTag, taskText }) {
      const args = [
        'run',
        '--dangerously-skip-permissions', // blunt; gated by EVOLVE_OPENCODE_DANGEROUS (checked pre-loop)
        '--dir', getRepoRoot(),
        ...(process.env.EVOLVE_HAND_MODEL ? ['-m', process.env.EVOLVE_HAND_MODEL] : []),
        '--',           // terminate flags so a '-'-leading taskText is the message, not a flag
        taskText,       // positional message — MUST be last (variadic [message..])
      ];
      return { bin: resolveBin('opencode'), args,
        env: { EVOLVE_CYCLE_TAG: String(cycleTag), EVOLVE_STATUS_FILE: statusFile } };
    },
  },
  // P3: a LIGHT read-only claude for DISTILLATION — it reads a distill prompt on
  // stdin and outputs a Gene JSON; it must NOT edit files or run tools. Hence
  // --permission-mode plan (read-only posture), no --add-dir / --settings /
  // --allowedTools (an empty --allowedTools would swallow the next arg), low
  // --max-turns. Distinct from the 'claude-code' Hand recipe (which edits + solidifies).
  'claude-distill': {
    deliversTaskVia: 'stdin',
    buildArgs({ sessionId }) {
      const args = [
        '-p', '--output-format', 'json',
        '--permission-mode', 'plan',
        '--model', process.env.EVOLVE_DISTILL_MODEL || 'sonnet',
        '--session-id', sessionId,
        '--max-turns', String(parseInt(process.env.EVOLVE_DISTILL_MAX_TURNS || '3', 10) || 3),
      ];
      return { bin: resolveBin('claude-code'), args, env: {} };
    },
  },
};

// ---------------------------------------------------------------------------
// runExecBridge — the loop. Brain -> scrape -> Hand (retry w/ hard timeout) -> gate.
// ---------------------------------------------------------------------------
async function runExecBridge(opts = {}) {
  const harness = opts.harness || 'claude-code';
  const recipe = RECIPES[harness];
  if (!recipe) throw new Error(`execBridge: no recipe for harness '${harness}'`);
  // P4-b: opencode has NO sandbox / fine-grained permissions — only the blunt
  // --dangerously-skip-permissions (the Hand can run unrestricted shell). Refuse
  // FAIL-FAST here (before any Brain run) unless the operator explicitly accepts
  // that trade-off via a SECOND env. Done at the loop head — not in buildArgs
  // (which must stay pure) — so a wasted Brain cycle never precedes the refusal.
  if (harness === 'opencode'
      && String(process.env.EVOLVE_OPENCODE_DANGEROUS || '').toLowerCase() !== 'true') {
    throw new Error(
      'execBridge: opencode Hand requires EVOLVE_OPENCODE_DANGEROUS=true. opencode has no ' +
      'fine-grained permission scoping (only the blunt --dangerously-skip-permissions, no ' +
      'sandbox like codex -s workspace-write or claude --settings). Set it explicitly to accept ' +
      'that the opencode Hand can run unrestricted shell, or use claude-code/codex.');
  }
  const spawnFn = opts.spawnFn || require('child_process').spawn;
  const maxCycles = opts.once ? 1 : (Number(opts.maxCycles) || 0); // 0 = unbounded
  const REPO_ROOT = getRepoRoot();
  const MAX_RETRIES = parseInt(process.env.EVOLVE_HAND_MAX_RETRIES || '3', 10) || 3;
  const BACKOFF_MS = (parseInt(process.env.EVOLVE_HAND_RETRY_BACKOFF_SECONDS || '15', 10) || 15) * 1000;
  const settingsPath = (harness === 'claude-code') ? writeScopedSettings() : null;

  let cycleCount = 0, lastOutcome = 'none';
  while (maxCycles === 0 || cycleCount < maxCycles) {
    cycleCount++;
    const cycleStartMs = Date.now();
    const cycleTag = String(cycleCount).padStart(4, '0');
    const statusBase = path.join(getEvolutionDir(), `status_${cycleTag}`);

    // BRAIN — force bridge print mode, scrape stdout (dispatch.js untouched).
    const brain = await runChild(spawnFn, 'node', [EVOLVER_OWN_INDEX, 'run'], {
      env: { ...process.env, EVOLVE_BRIDGE: 'true' }, stdinText: null, cwd: REPO_ROOT, // evolve the target tree, run evolver's own index.js
      timeoutMs: BRAIN_TIMEOUT_MS(), label: 'Brain', bufferMode: 'head', // keep the sessions_spawn line at the head
    });
    if (brain.timedOut) { lastOutcome = 'brain_timeout'; appendFailureLesson(cycleTag, 'brain_timeout', brain.spawnError || ''); if (opts.once) break; await sleep(IDLE_SLEEP_MS()); continue; }
    if (brain.code !== 0) { lastOutcome = 'brain_failed'; appendFailureLesson(cycleTag, 'brain_failed', brain.spawnError || `code=${brain.code}`); if (opts.once) break; await sleep(IDLE_SLEEP_MS()); continue; }

    const spawnObj = parseFirstSpawnCall(brain.stdout);
    if (!spawnObj || !spawnObj.task) { lastOutcome = 'no_spawn'; if (opts.once) break; await sleep(IDLE_SLEEP_MS()); continue; }

    const baseTask = spawnObj.task;
    let handOk = false;
    let cycleOutcome = 'hand_failed'; // #179 r5: each cycle owns its outcome; the LAST cycle wins
    for (let attempt = 1; attempt <= MAX_RETRIES && !handOk; attempt++) {
      const attemptStartMs = Date.now(); // #179 r3: Fallback B must gate per-attempt, not per-cycle
      const statusFile = `${statusBase}_${attempt}.json`; // m8: per-attempt file
      try { if (fs.existsSync(statusFile)) fs.unlinkSync(statusFile); } catch (_) {}
      const hint = attempt > 1
        ? `\n\nRETRY ${attempt}/${MAX_RETRIES}: previous attempt failed. Keep changes small/reversible; you MUST run \`node index.js solidify\` AND write the status JSON.\n`
        : '';
      const taskText = appendStatusFileContract(baseTask + hint, statusFile, cycleTag);
      try { fs.writeFileSync(`${statusBase}_${attempt}_task.txt`, taskText); } catch (_) {}

      const sessionId = (harness === 'claude-code') ? crypto.randomUUID() : `evolver_hand_${cycleTag}_${Date.now()}_${attempt}`;
      const built = recipe.buildArgs({ sessionId, statusFile, cycleTag, settingsPath, taskText });

      const r = await runChild(spawnFn, built.bin, built.args, {
        env: { ...process.env, ...built.env },
        stdinText: recipe.deliversTaskVia === 'stdin' ? taskText : null, cwd: REPO_ROOT, // Hand's solidify+git must run in the evolution repo
        timeoutMs: HAND_TIMEOUT_MS(), label: 'Hand', bufferMode: 'tail', // keep claude's result JSON at the tail
      });

      const gate = evaluateStatusGate({ r, statusFile, cycleStartMs, attemptStartMs, solidifyProof: recipe.solidifyProof || 'stdout' });
      if (gate.ok) { handOk = true; cycleOutcome = 'success'; break; }
      appendFailureLesson(cycleTag, `hand_attempt_${attempt}_${gate.kind}`, gate.reason);
      if (attempt < MAX_RETRIES) await sleep(BACKOFF_MS * attempt);
    }
    // #179 r5: assign unconditionally so a LATER cycle's failure is not masked by
    // an EARLIER cycle's success. The latest cycle's outcome is the run outcome.
    lastOutcome = cycleOutcome;
    if (opts.once) break;
  }
  return { cycles: cycleCount, lastOutcome };
}

module.exports = {
  runExecBridge, resolveBin, evaluateStatusGate, writeScopedSettings,
  appendStatusFileContract, tryParseClaudeResult, runChild, RECIPES,
  // Test-only surface for the CVE-2024-27980 Windows npm-shim resolver.
  // Exposes the helper so tests can verify the parser handles real shim
  // formats (claude-code, codex, opencode, openclaw, sdk packages) and
  // gracefully returns null for non-shim targets, custom shims, missing
  // entries, and non-Windows hosts.
  __test: {
    resolveNpmCmdShim: _resolveNpmCmdShim,
  },
};

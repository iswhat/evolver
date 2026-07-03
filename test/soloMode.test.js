const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');

const repoRoot = path.resolve(__dirname, '..');
let tmpDir;

function ensureGitRepo(dir) {
  execFileSync('git', ['init', '-q'], { cwd: dir, stdio: 'ignore' });
  execFileSync('git', ['config', 'user.email', 'test@example.com'], { cwd: dir, stdio: 'ignore' });
  execFileSync('git', ['config', 'user.name', 'test'], { cwd: dir, stdio: 'ignore' });
  execFileSync('git', ['config', 'commit.gpgsign', 'false'], { cwd: dir, stdio: 'ignore' });
  execFileSync('git', ['commit', '--allow-empty', '-m', 'init', '-q'], { cwd: dir, stdio: 'ignore' });
}

// Env for a short, isolated solo child run: dead hub, tmp repo as target,
// suicide off, max 1 cycle so the process exits fast, tiny sleeps.
function soloChildEnv(extra = {}) {
  return {
    ...process.env,
    A2A_HUB_URL: '',
    EVOMAP_HUB_URL: '',
    EVOLVER_REPO_ROOT: tmpDir,
    EVOLVER_LOCK_DIR: tmpDir,
    EVOLVER_SETTINGS_DIR: path.join(tmpDir, '.evolver-settings'),
    EVOMAP_PROXY: '0',
    EVOMAP_PROXY_AUTO_INJECT: 'off',
    CLAUDE_SETTINGS_FILE: path.join(tmpDir, '.claude', 'settings.json'),
    EVOLVER_CAFFEINATE: '0',
    EVOLVER_SUICIDE: 'false',
    EVOLVER_CYCLE_TIMEOUT_ENABLED: 'false',
    EVOLVER_MIN_SLEEP_MS: '1',
    EVOLVER_MAX_SLEEP_MS: '1',
    EVOLVE_PENDING_SLEEP_MS: '1',
    EVOLVER_MAX_CYCLES_PER_PROCESS: '1',
    ...extra,
  };
}

function runSoloOnce(extraEnv = {}, extraArgs = []) {
  const result = spawnSync(
    process.execPath,
    [path.join(repoRoot, 'index.js'), '--solo', ...extraArgs],
    { cwd: tmpDir, encoding: 'utf8', timeout: 8000, env: soloChildEnv(extraEnv) }
  );
  return {
    combined: (result.stdout || '') + (result.stderr || ''),
    status: result.status,
  };
}

describe('solo mode (--solo)', () => {
  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'solo-mode-'));
    ensureGitRepo(tmpDir);
  });
  afterEach(() => { try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {} });

  it('--solo routes into loop mode and prints the solo banner', () => {
    const { combined } = runSoloOnce();
    assert.match(combined, /\[Solo\] Mad Dog · 受约束的野性模式已启动/);
    assert.match(combined, /断网 · 禁ATP/);
    assert.match(combined, /仅本地 git 可追溯/);
  });

  it('--solo hard-cuts the network even when the user sets a hub URL', () => {
    // Solo OVERRIDES a user-provided hub URL — the "no escape valve" rule.
    const { combined } = runSoloOnce({ A2A_HUB_URL: 'http://dead.invalid' });
    assert.match(combined, /\[Solo\] 断网模式/);
    assert.doesNotMatch(combined, /startHeartbeat|\[SSE\]|\[Proxy\] Started/);
  });

  it('--solo cuts the validator daemon (network + staked credits) even when enabled', () => {
    // User forces the validator on; solo must still refuse to start it.
    const { combined } = runSoloOnce({ EVOLVER_VALIDATOR_ENABLED: 'true' });
    assert.doesNotMatch(combined, /\[ValidatorDaemon\] started|Validator mode is ENABLED/);
  });

  it('--solo hard-cuts ATP even when the user sets it on', () => {
    // User forces autobuy on; solo overrides to off at the source, so neither
    // the startup path nor the in-cycle path (guards.js) starts ATP.
    const { combined } = runSoloOnce({ EVOLVER_ATP: 'on', EVOLVER_ATP_AUTOBUY: 'on' });
    assert.match(combined, /\[Solo\] 禁 ATP/);
    assert.doesNotMatch(combined, /\[ATP-AutoBuyer\] Started|\[ATP-AutoDeliver\] Started|ATP auto-spend is ON/);
  });

  it('does not leak uncaught errors under --solo', () => {
    const { combined } = runSoloOnce();
    assert.ok(
      !combined.includes('SyntaxError') && !combined.includes('ReferenceError') && !combined.includes('is not defined'),
      'solo run must not leak uncaught errors: ' + combined.slice(0, 400)
    );
  });
});

// Self-PR: auto-contribute high-confidence self-mutations back to the public repo.
// When evolver optimizes its own code and the change passes all gates (score, streak,
// blast radius, leak scan, non-obfuscated files only), this module creates a PR on
// the configured public GitHub repo via the `gh` CLI.
//
// Safety: env-gated (EVOLVER_SELF_PR=true), 24h cooldown, diff dedup,
// never auto-merges, only `optimize` + `low` risk mutations qualify.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
// 10 MB — prevents RangeError on large child process output (e.g. git log/diff
// on large repos). See GHSA reports / issue #451.
const MAX_EXEC_BUFFER = 10 * 1024 * 1024;

// SECURITY (Semgrep #285 detect-child-process): every git/gh invocation here
// goes through argv-form execFileSync (no shell), NEVER string concatenation.
// PR titles/branches/file paths can carry mutation rationale that is
// model-generated or hub-fetched (untrusted), and a `git commit -m "..."`
// shell string would let `$(...)` / backticks in that text execute. Passing
// each value as a discrete argv element removes the shell entirely, so no
// metacharacter can break out. Injectable for tests via __test.setExecFile.
let _execFileImpl = execFileSync;

// Run `git <args...>` with no shell. Returns { ok, out } / { ok:false, err }
// mirroring runGh so callers stay uniform.
function runGit(args, opts) {
  const o = opts || {};
  try {
    const out = _execFileImpl('git', args, {
      cwd: o.cwd,
      timeout: o.timeoutMs || 10000,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
      maxBuffer: MAX_EXEC_BUFFER,
      env: o.env || process.env,
    });
    return { ok: true, out: String(out || '').trim() };
  } catch (e) {
    return { ok: false, out: '', err: String(e && e.stderr ? e.stderr : e.message || e).slice(0, 500) };
  }
}

const { getEvolutionDir, getRepoRoot, getEvolverInstallRoot } = require('./paths');
const { fullLeakCheck, redactString } = require('./sanitize');
const {
  SELF_PR_MIN_SCORE,
  SELF_PR_MIN_STREAK,
  SELF_PR_MAX_FILES,
  SELF_PR_MAX_LINES,
  SELF_PR_COOLDOWN_MS,
  SELF_PR_REPO,
  SELF_PR_TIMEOUT_MS,
} = require('../config');

const STATE_FILE = 'self_pr_state.json';

// Files obfuscated in public.manifest.json -- PRs touching these would land
// raw source on the public repo where the file ships obfuscated, leaking
// implementation detail. Source of truth: public.manifest.json `obfuscate`
// array, loaded lazily on first use.
//
// public.manifest.json is itself excluded from the npm package (it's a
// build-time artifact for the obfuscation pipeline), so on npm installs the
// file is absent. That is expected — self-PR is dev-only (gated by
// EVOLVER_SELF_PR=true) and a missing manifest correctly produces the
// fail-safe behavior (reject all files). We therefore stay silent on load
// failure here and only surface a warning when maybeCreatePR is actually
// invoked but the manifest cannot be read.
//
// Failed loads are retried after MANIFEST_RETRY_TTL_MS (default 5 min) so a
// transient FS error during process start (build script still writing the
// file, NFS hiccup, permission flap) does not freeze the cache at null for
// the entire daemon lifetime, silently disabling self-PR for days or weeks
// with no recovery. A successful load remains sticky because the manifest is
// effectively read-only at runtime.
let _obfuscatedFilesCache;     // undefined = not loaded; Set | null after first attempt
let _manifestLoadError = null;
let _manifestLoadFailedAt = 0; // ms timestamp of the last failed load attempt
let _warnedAboutMissingManifest = false;
let _manifestRetryTtlMs = 5 * 60 * 1000;

function loadObfuscatedFromManifest() {
  // Hit on a successful previous load — manifest does not change at runtime.
  if (_obfuscatedFilesCache instanceof Set) return _obfuscatedFilesCache;
  // Within the retry window after a failure: skip the FS hit, return cached
  // null so callers stay in the fail-safe branch without hammering the disk.
  if (_obfuscatedFilesCache === null &&
      (Date.now() - _manifestLoadFailedAt) < _manifestRetryTtlMs) {
    return null;
  }
  // First-ever attempt OR retry window elapsed since the last failure.
  try {
    const manifestPath = path.join(getEvolverInstallRoot(), 'public.manifest.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    if (!Array.isArray(manifest.obfuscate)) {
      throw new Error('public.manifest.json missing `obfuscate` array');
    }
    // Reject glob patterns: build_public.js may expand them, but Set.has(rel)
    // would silently miss matches and reintroduce the drift this PR fixed.
    for (const f of manifest.obfuscate) {
      if (typeof f !== 'string' || /[*?[\]]/.test(f)) {
        throw new Error('public.manifest.json `obfuscate` must contain literal paths, got: ' + JSON.stringify(f));
      }
    }
    _obfuscatedFilesCache = new Set(manifest.obfuscate.map((f) => f.replace(/\\/g, '/').replace(/^\.\/+/, '')));
    _manifestLoadError = null;
    _manifestLoadFailedAt = 0;
    // Allow a future failure (after this success) to surface its warning
    // once, instead of staying silent because an earlier failure already
    // warned in this process.
    _warnedAboutMissingManifest = false;
  } catch (e) {
    _manifestLoadError = e.message;
    _obfuscatedFilesCache = null;
    _manifestLoadFailedAt = Date.now();
  }
  return _obfuscatedFilesCache;
}

// Test-only: reset the lazy cache so a test can exercise the load path
// (e.g. cover the fail-safe branch after a missing manifest is restored).
function _resetObfuscatedCache() {
  _obfuscatedFilesCache = undefined;
  _manifestLoadError = null;
  _manifestLoadFailedAt = 0;
  _warnedAboutMissingManifest = false;
  _manifestRetryTtlMs = 5 * 60 * 1000;
}

// Test-only: shrink (or grow) the retry TTL so a test can exercise the
// retry-after-transient-failure path without sleeping for real time.
function _setManifestRetryTtlForTests(ms) {
  _manifestRetryTtlMs = Number(ms) || 0;
}

// Files that are included in the public manifest (superset patterns).
const PUBLIC_INCLUDE_PREFIXES = ['src/', 'scripts/'];
const PUBLIC_INCLUDE_EXACT = new Set(['index.js', 'package.json']);
const PUBLIC_EXCLUDE_PREFIXES = ['docs/', 'memory/', 'dist-public/'];

function normalizeRel(filePath) {
  return String(filePath || '').replace(/\\/g, '/').replace(/^\.\/+/, '');
}

function isPublicNonObfuscated(filePath) {
  const rel = normalizeRel(filePath);
  if (!rel) return false;
  const obfuscated = loadObfuscatedFromManifest();
  if (obfuscated === null) return false; // fail-safe when manifest is unreadable
  if (obfuscated.has(rel)) return false;
  for (const excl of PUBLIC_EXCLUDE_PREFIXES) {
    if (rel.startsWith(excl)) return false;
  }
  if (PUBLIC_INCLUDE_EXACT.has(rel)) return true;
  for (const incl of PUBLIC_INCLUDE_PREFIXES) {
    if (rel.startsWith(incl)) return true;
  }
  return false;
}

function getStatePath() {
  return path.join(getEvolutionDir(), STATE_FILE);
}

function readState() {
  try {
    const p = getStatePath();
    if (fs.existsSync(p)) {
      return JSON.parse(fs.readFileSync(p, 'utf8'));
    }
  } catch (_) {}
  return { lastPRAt: null, recentDiffHashes: [] };
}

function writeState(state) {
  try {
    const dir = getEvolutionDir();
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(getStatePath(), JSON.stringify(state, null, 2) + '\n');
  } catch (e) {
    if (process.env.DEBUG || process.env.EVOLVER_DEBUG) {
      try { process.stderr.write('selfPR.writeState failed: ' + String(e && e.message || e) + '\n'); } catch (_) {}
    }
  }
}

function isInCooldown() {
  const state = readState();
  if (!state.lastPRAt) return false;
  const elapsed = Date.now() - new Date(state.lastPRAt).getTime();
  return elapsed < SELF_PR_COOLDOWN_MS;
}

function computeDiffHash(changedFiles, repoRoot) {
  const diffParts = [];
  for (const f of changedFiles) {
    const abs = path.join(repoRoot, f);
    try {
      if (fs.existsSync(abs)) {
        diffParts.push(f + ':' + fs.readFileSync(abs, 'utf8'));
      }
    } catch (_) {}
  }
  return crypto.createHash('sha256').update(diffParts.join('\n---\n')).digest('hex').slice(0, 16);
}

function isDuplicateDiff(diffHash) {
  const state = readState();
  const recent = Array.isArray(state.recentDiffHashes) ? state.recentDiffHashes : [];
  return recent.includes(diffHash);
}

function recordPR(diffHash) {
  const state = readState();
  let recent = Array.isArray(state.recentDiffHashes) ? state.recentDiffHashes : [];
  recent.push(diffHash);
  if (recent.length > 20) recent = recent.slice(-20);
  writeState({
    lastPRAt: new Date().toISOString(),
    recentDiffHashes: recent,
  });
}

function buildPRBody({ capsule, mutation, gene, blastRadius }) {
  const score = capsule && capsule.outcome ? capsule.outcome.score : 0;
  const streak = capsule ? capsule.success_streak : 0;
  const capsuleId = capsule ? capsule.id : 'unknown';
  const geneId = gene ? gene.id : 'unknown';
  const signals = capsule && Array.isArray(capsule.trigger)
    ? capsule.trigger.slice(0, 5).join(', ')
    : '';
  const category = mutation ? mutation.category : 'unknown';
  const risk = mutation ? mutation.risk : 'unknown';
  const rationale = mutation && mutation.rationale
    ? redactString(String(mutation.rationale).slice(0, 500))
    : '';
  const files = blastRadius && Array.isArray(blastRadius.all_changed_files)
    ? blastRadius.all_changed_files.map(normalizeRel)
    : [];
  const filesStr = files.map(function (f) { return '- `' + f + '`'; }).join('\n');

  return [
    '## Mutation Summary',
    '',
    '- **Category:** ' + category,
    '- **Risk:** ' + risk,
    '- **PRM Score:** ' + (typeof score === 'number' ? score.toFixed(3) : String(score)),
    '- **Success Streak:** ' + streak,
    '- **Gene:** `' + geneId + '`',
    '- **Signals:** ' + (signals || 'none'),
    '- **Capsule:** `' + capsuleId + '`',
    '',
    '## Rationale',
    '',
    rationale || '_No rationale provided._',
    '',
    '## Changed Files',
    '',
    filesStr || '_None._',
    '',
    '## Blast Radius',
    '',
    '- Files: ' + (blastRadius ? blastRadius.files : 0),
    '- Lines: ' + (blastRadius ? blastRadius.lines : 0),
    '',
    '---',
    '',
    '_This PR was auto-generated by evolver self-evolution (GEP)._',
    '_Capsule: ' + capsuleId + ' | Gene: ' + geneId + '_',
  ].join('\n');
}

function buildPRTitle(mutation) {
  const rationale = mutation && mutation.rationale
    ? String(mutation.rationale).replace(/[\r\n]+/g, ' ').trim().slice(0, 80)
    : 'self-optimization';
  return '[Auto-Mutation] ' + rationale;
}

// Run `gh <args...>` with no shell. `args` is an ARGV ARRAY, not a string, so
// repo names / branch / title / file paths are discrete arguments the shell
// never sees.
function runGh(args, opts) {
  const timeoutMs = (opts && opts.timeoutMs) || SELF_PR_TIMEOUT_MS;
  const cwd = (opts && opts.cwd) || getRepoRoot();
  try {
    const result = _execFileImpl('gh', args, {
      cwd: cwd,
      timeout: timeoutMs,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
      env: Object.assign({}, process.env), maxBuffer: MAX_EXEC_BUFFER
    });
    return { ok: true, out: String(result || '').trim() };
  } catch (e) {
    return { ok: false, out: '', err: String(e && e.stderr ? e.stderr : e.message || e).slice(0, 500) };
  }
}

function getGitDiff(changedFiles, repoRoot) {
  const parts = [];
  for (const f of changedFiles) {
    const before = parts.length;
    // `f` is a discrete argv element after `--`, so a path with quotes or
    // shell metacharacters cannot break out of the command.
    const head = runGit(['diff', 'HEAD', '--', f], { cwd: repoRoot });
    if (head.ok && head.out) parts.push(head.out);
    if (parts.length === before) {
      const noHead = runGit(['diff', '--', f], { cwd: repoRoot });
      if (noHead.ok && noHead.out) parts.push(noHead.out);
    }
  }
  return parts.join('\n');
}

async function maybeCreatePR({ capsule, event, mutation, gene, blastRadius }) {
  if (String(process.env.EVOLVER_SELF_PR || '').toLowerCase() !== 'true') return null;

  // User has explicitly opted into self-PR. Ensure we have the obfuscate
  // list so we don't accidentally leak obfuscated source via a "non-obf" PR.
  if (loadObfuscatedFromManifest() === null) {
    if (!_warnedAboutMissingManifest) {
      console.warn('[SelfPR] public.manifest.json not found at ' + getEvolverInstallRoot() + ' — rejecting all self-PRs (manifest is required to identify obfuscated files). Error: ' + _manifestLoadError);
      _warnedAboutMissingManifest = true;
    }
    return null;
  }

  const score = capsule && capsule.outcome ? (capsule.outcome.score || 0) : 0;
  const streak = capsule ? (capsule.success_streak || 0) : 0;

  if (score < SELF_PR_MIN_SCORE) return null;
  if (streak < SELF_PR_MIN_STREAK) return null;

  if (!mutation || mutation.category !== 'optimize') return null;
  if (!mutation || mutation.risk !== 'low') return null;

  const filesChanged = blastRadius ? (blastRadius.files || 0) : 0;
  const linesChanged = blastRadius ? (blastRadius.lines || 0) : 0;
  if (filesChanged > SELF_PR_MAX_FILES || filesChanged === 0) return null;
  if (linesChanged > SELF_PR_MAX_LINES || linesChanged === 0) return null;

  const changedFiles = (blastRadius && Array.isArray(blastRadius.all_changed_files)
    ? blastRadius.all_changed_files
    : []).map(normalizeRel).filter(Boolean);

  if (changedFiles.length === 0) return null;
  if (!changedFiles.every(isPublicNonObfuscated)) return null;

  if (isInCooldown()) {
    console.log('[SelfPR] Skipping: cooldown active.');
    return { attempted: false, reason: 'cooldown' };
  }

  const repoRoot = getRepoRoot();
  const diffHash = computeDiffHash(changedFiles, repoRoot);
  if (isDuplicateDiff(diffHash)) {
    console.log('[SelfPR] Skipping: duplicate diff ' + diffHash);
    return { attempted: false, reason: 'duplicate_diff' };
  }

  const diffContent = getGitDiff(changedFiles, repoRoot);
  if (!diffContent) {
    console.log('[SelfPR] Skipping: no diff content.');
    return { attempted: false, reason: 'no_diff' };
  }
  const leakResult = fullLeakCheck(diffContent);
  if (leakResult.found) {
    const leakSummary = leakResult.leaks.map(function (l) { return l.type; }).join(', ');
    console.warn('[SelfPR] Skipping: leak detected in diff (' + leakSummary + ')');
    return { attempted: false, reason: 'leak_detected', leaks: leakResult.leaks.length };
  }

  const repo = SELF_PR_REPO;
  const capsuleIdShort = capsule && capsule.id ? String(capsule.id).slice(0, 8) : crypto.randomBytes(4).toString('hex');
  const branch = 'evolver-bot/mutation-' + capsuleIdShort;
  const title = buildPRTitle(mutation);
  const body = buildPRBody({ capsule, mutation, gene, blastRadius });

  try {
    console.log('[SelfPR] Creating PR on ' + repo + ' branch ' + branch + '...');

    const forkCheck = runGh(['repo', 'view', repo, '--json', 'name'], { timeoutMs: 15000 });
    if (!forkCheck.ok) {
      console.warn('[SelfPR] Cannot access repo ' + repo + ': ' + (forkCheck.err || 'unknown'));
      return { attempted: false, reason: 'repo_access_failed' };
    }

    const tmpDir = path.join(getEvolutionDir(), 'self_pr_workdir');
    if (fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
    fs.mkdirSync(tmpDir, { recursive: true });

    const cloneResult = runGh(
      ['repo', 'clone', repo, tmpDir, '--', '--depth', '1'],
      { timeoutMs: 60000 }
    );
    if (!cloneResult.ok) {
      console.warn('[SelfPR] Clone failed: ' + (cloneResult.err || 'unknown'));
      return { attempted: false, reason: 'clone_failed' };
    }

    const checkoutResult = runGit(['checkout', '-b', branch], { cwd: tmpDir });
    if (!checkoutResult.ok) {
      console.warn('[SelfPR] Branch creation failed: ' + (checkoutResult.err || 'unknown'));
      return { attempted: false, reason: 'branch_failed' };
    }

    for (const relFile of changedFiles) {
      const srcFile = path.join(repoRoot, relFile);
      const destFile = path.join(tmpDir, relFile);
      const destDir = path.dirname(destFile);
      if (!fs.existsSync(destDir)) fs.mkdirSync(destDir, { recursive: true });
      if (fs.existsSync(srcFile)) {
        fs.copyFileSync(srcFile, destFile);
      }
    }

    const addResult = runGit(['add', '-A'], { cwd: tmpDir });
    if (!addResult.ok) {
      console.warn('[SelfPR] Commit failed: ' + (addResult.err || 'git add failed'));
      return { attempted: false, reason: 'commit_failed' };
    }
    const statusResult = runGit(['status', '--porcelain'], { cwd: tmpDir });
    if (!statusResult.ok) {
      console.warn('[SelfPR] Commit failed: ' + (statusResult.err || 'git status failed'));
      return { attempted: false, reason: 'commit_failed' };
    }
    if (!statusResult.out) {
      console.log('[SelfPR] No changes to commit in public repo clone.');
      return { attempted: false, reason: 'no_public_diff' };
    }
    // title is passed as a discrete argv element, so its content (mutation
    // rationale, possibly model-generated) is never shell-interpreted; no
    // manual quote-escaping needed and `$(...)`/backticks stay literal.
    const commitResult = runGit(['commit', '-m', title], {
      cwd: tmpDir,
      env: Object.assign({}, process.env, {
        GIT_AUTHOR_NAME: 'evolver-bot', GIT_AUTHOR_EMAIL: 'evolver-bot@evomap.ai',
        GIT_COMMITTER_NAME: 'evolver-bot', GIT_COMMITTER_EMAIL: 'evolver-bot@evomap.ai',
      }),
    });
    if (!commitResult.ok) {
      console.warn('[SelfPR] Commit failed: ' + (commitResult.err || 'git commit failed'));
      return { attempted: false, reason: 'commit_failed' };
    }

    const pushResult = runGit(['push', 'origin', branch], { cwd: tmpDir, timeoutMs: 30000 });
    if (!pushResult.ok) {
      console.warn('[SelfPR] Push failed: ' + (pushResult.err || 'git push failed'));
      return { attempted: false, reason: 'push_failed' };
    }

    const bodyFile = path.join(tmpDir, '.pr_body.md');
    fs.writeFileSync(bodyFile, body);

    const prResult = runGh(
      ['pr', 'create', '--repo', repo, '--head', branch,
        '--title', title, '--body-file', bodyFile, '--label', 'auto-mutation'],
      { cwd: tmpDir, timeoutMs: 30000 }
    );

    if (fs.existsSync(tmpDir)) {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {}
    }

    if (!prResult.ok) {
      console.warn('[SelfPR] PR creation failed: ' + (prResult.err || 'unknown'));
      return { attempted: true, reason: 'pr_create_failed', error: prResult.err };
    }

    const prUrl = prResult.out || '';
    console.log('[SelfPR] PR created: ' + prUrl);
    recordPR(diffHash);
    return { attempted: true, ok: true, pr_url: prUrl, branch: branch, diff_hash: diffHash };
  } catch (e) {
    console.warn('[SelfPR] Unexpected error (non-fatal): ' + (e && e.message ? e.message : e));
    return { attempted: false, reason: 'unexpected_error', error: String(e && e.message || e).slice(0, 200) };
  }
}

module.exports = {
  maybeCreatePR,
  isPublicNonObfuscated,
  isInCooldown,
  isDuplicateDiff,
  computeDiffHash,
  buildPRTitle,
  buildPRBody,
  readState,
  writeState,
  recordPR,
  // For testing
  _loadObfuscatedFromManifest: loadObfuscatedFromManifest,
  _resetObfuscatedCache,
  _setManifestRetryTtlForTests,
  // Argv-form exec surface (Semgrep #285): lets tests capture the exact
  // (file, args) handed to execFileSync and assert no shell string is ever
  // built, so a metacharacter-laden title/branch/path cannot inject.
  __test: {
    setExecFile(fn) { _execFileImpl = fn || execFileSync; },
    runGit,
    runGh,
  },
};

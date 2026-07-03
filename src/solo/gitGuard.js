// Solo-mode git safety net (--solo). The wild Mad Dog loop self-modifies its
// target project every cycle with no undo; solo trades the human-review gate
// for a mechanical one: snapshot the target repo before each cycle, and on a
// failed cycle hard-reset back to that snapshot so a broken self-edit cannot
// accumulate. This is the "改坏能回退" leg of the four solo backstops.
//
// Scope: this guards the TARGET project repo (getRepoRoot() — the project the
// user is standing in, or EVOLVER_REPO_ROOT), NOT evolver's own source. A
// Mad Dog cycle mutates the target codebase, so that is what we roll back.
//
// All git calls go through execFileSync (never a shell) so a repo path or
// branch name can't be interpreted as a command. Pure, dependency-free, and
// intentionally small so test/solo/gitGuard.test.js can exercise it against a
// throwaway repo.
const { execFileSync } = require('child_process');

function git(repoDir, args, opts) {
  return execFileSync('git', ['-C', repoDir, ...args], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    ...(opts || {}),
  });
}

// True if the repo has any staged/unstaged/untracked changes.
function hasUncommittedChanges(repoDir) {
  try {
    const out = git(repoDir, ['status', '--porcelain']);
    return out.trim().length > 0;
  } catch (_) {
    // Not a git repo / git missing: treat as "can't tell" → no clean baseline.
    return false;
  }
}

// Capture a rollback point for the current cycle. Returns the HEAD sha, or null
// if the repo can't be snapshotted (not a git repo, detached with no commits,
// git unavailable). A null snapshot disables rollback for that cycle rather
// than throwing — solo must not crash because the target isn't a git repo.
function snapshot(repoDir) {
  try {
    const sha = git(repoDir, ['rev-parse', 'HEAD']).trim();
    return sha || null;
  } catch (_) {
    return null;
  }
}

// Roll the target repo back to a snapshot sha: discard tracked-file edits
// (reset --hard) AND remove any new files the cycle created (clean -fd), so the
// working tree matches the pre-cycle state. No-op when sha is null/empty.
// Returns true on success, false if the rollback itself failed (surfaced by the
// caller so a wedged repo doesn't masquerade as a clean recovery).
function rollbackTo(repoDir, sha) {
  if (!sha) return false;
  try {
    git(repoDir, ['reset', '--hard', sha]);
    git(repoDir, ['clean', '-fd']);
    return true;
  } catch (_) {
    return false;
  }
}

module.exports = { snapshot, rollbackTo, hasUncommittedChanges };

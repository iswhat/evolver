const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { getEvolverInstallRoot } = require('./gep/paths');

const MAX_EXEC_BUFFER = 10 * 1024 * 1024;

// Sentinel returned by executeForceUpdate when the no-op short-circuit fires
// (current installed version already matches required_version). Distinct from
// `true` so callers can suppress phantom "success" telemetry and avoid the
// gratuitous process.exit(78) restart that follows a real upgrade. Callers
// MUST detect this with === identity comparison; do not use truthy/falsy
// checks (the sentinel IS truthy).
const FORCE_UPDATE_NOOP = Symbol('FORCE_UPDATE_NOOP');

// Sentinel returned by executeForceUpdate when a concurrent invocation is
// already running in this process. The two callers (enrich.js's evolve tick
// and a2aProtocol's heartbeat-thread trigger) can both observe a pending
// force_update directive in the same scheduler tick. Without a shared
// in-process mutex, both would call executeForceUpdate and both would fire
// reportForceUpdateOutcome, causing two atomic-rename writes to the same
// state file -- last writer wins, the first attempt's telemetry is lost.
//
// Callers MUST detect this with === identity comparison and treat it as a
// no-op (do NOT write a state file, do NOT trigger process.exit(78), do NOT
// emit failure telemetry). The in-flight invocation owns the outcome and will
// fire its own reportForceUpdateOutcome. See test/forceUpdateConcurrencyGuard.test.js.
const FORCE_UPDATE_BUSY = Symbol('FORCE_UPDATE_BUSY');

// Module-level mutex: shared by every caller that requires('../forceUpdate'),
// so the heartbeat-thread trigger in a2aProtocol.js and the evolve-tick path
// in enrich/pipeline cannot run executeForceUpdate concurrently. This is a
// process-local guard only; it does not protect against two separate node
// processes upgrading the same install root simultaneously (out of scope --
// distinct processes have distinct install layouts in practice).
let _inFlight = false;

// Force Update: triggered by Hub when version is critically outdated.
// Extracted from src/evolve.js so both the evolve main loop and heartbeat
// thread can trigger it independently (heartbeat-only workers need this
// because they never reach the evolve run() loop that consumes the pending
// force_update directive).
//
// CRITICAL (issue #51): this function MUST operate on the evolver INSTALL
// directory, NOT getRepoRoot(). getRepoRoot() preferentially returns the
// user's surrounding project (process.cwd()'s nearest .git ancestor).
// Using it here would delete the user's project files and copy the
// evolver package on top of them. Always use getEvolverInstallRoot(),
// which resolves to the package containing this file regardless of
// install layout (global npm / local node_modules / dev clone).
function executeForceUpdate(forceUpdate) {
  // Concurrency guard: if a prior invocation is still in flight, refuse and
  // return the BUSY sentinel. The in-flight caller owns the outcome (state
  // file write, process.exit(78) on success); a second concurrent attempt
  // would (a) race the atomic-rename state-file writes and clobber the first
  // attempt's telemetry row, and (b) potentially double-exit. See
  // FORCE_UPDATE_BUSY docstring above for context.
  if (_inFlight) {
    console.log('[ForceUpdate] BUSY: another invocation already in flight, skipping');
    return FORCE_UPDATE_BUSY;
  }
  _inFlight = true;
  try {
    return _executeForceUpdateInner(forceUpdate);
  } finally {
    // Always release the mutex, even on throw. Callers may rely on retrying
    // after a failure (e.g. heartbeat cooldown), so the flag MUST NOT remain
    // set after the function returns/throws. Note: on a successful upgrade,
    // _executeForceUpdateInner returns true and the caller invokes
    // process.exit(78); the finally still runs before exit -- which is fine,
    // there is nothing else to coordinate with at that point.
    _inFlight = false;
  }
}

function _executeForceUpdateInner(forceUpdate) {
  const INSTALL_ROOT = getEvolverInstallRoot();

  // Defense in depth: if a future refactor breaks path resolution and
  // INSTALL_ROOT no longer points at the evolver package (no package.json
  // / wrong package name), refuse the update rather than risk
  // overwriting an unrelated directory. This is the last guard between
  // the deletion loop and the user's data.
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(INSTALL_ROOT, 'package.json'), 'utf8'));
    if (!pkg || (pkg.name !== '@evomap/evolver' && pkg.name !== 'evolver')) {
      console.warn('[ForceUpdate] Refusing — ' + INSTALL_ROOT +
        '/package.json has name="' + (pkg && pkg.name) +
        '", expected "@evomap/evolver". Aborting to avoid data loss.');
      return false;
    }
  } catch (e) {
    console.warn('[ForceUpdate] Refusing — cannot read ' + INSTALL_ROOT +
      '/package.json: ' + (e && e.message || e));
    return false;
  }

  const requiredVersion = String(forceUpdate.required_version || '').replace(/^[>=^~\s]+/, '');
  if (!/^\d+\.\d+\.\d+(-[\w.]+)?(\+[\w.]+)?$/.test(requiredVersion)) {
    console.warn('[ForceUpdate] Refusing — required_version "' + requiredVersion + '" is not a concrete semver (ranges not accepted).');
    return false;
  }

  function getCurrentVersion() {
    try {
      var pkg = JSON.parse(fs.readFileSync(path.join(INSTALL_ROOT, 'package.json'), 'utf8'));
      return pkg.version || '0.0.0';
    } catch (_) { return '0.0.0'; }
  }

  // Idempotency short-circuit: the hub keeps re-issuing the same force_update
  // directive until the node reports success. After a successful upgrade +
  // restart (process.exit(78)), the next heartbeat may still carry the same
  // directive. Without this early return, a transient Channel 1 failure (npx
  // unavailable, network blip, EBUSY) would cause executeForceUpdate to
  // return false and overwrite the previous successful run's state file with
  // a bogus "failed" — even though we are already at the target version.
  //
  // Compare the ACTUAL current running version (which reflects the new
  // version post-restart) against the parsed requiredVersion. Only reached
  // after the strip+validate above, so a garbage / unparseable
  // required_version will NOT short-circuit — it falls into the validation
  // failure branch above and returns false safely.
  var currentVersion = getCurrentVersion();
  if (currentVersion === requiredVersion) {
    console.log('[ForceUpdate] already at required version, no-op (current=' +
      currentVersion + ', required=' + requiredVersion + ')');
    // Return the dedicated sentinel rather than `true`. Callers use this to
    // (a) emit status="skipped" telemetry instead of a phantom "success"
    // row in EvolverUpgradeAttempt with from_version == to_version, and
    // (b) skip the process.exit(78) restart — there is nothing to restart
    // for when the binary didn't change.
    return FORCE_UPDATE_NOOP;
  }

  console.log('[ForceUpdate] Starting update (target: ' + requiredVersion +
    ', install root: ' + INSTALL_ROOT + ')');

  // Use os.tmpdir() for staging — INSTALL_ROOT's parent (e.g.
  // /usr/lib/node_modules/@evomap when globally installed) is often not
  // writable, unlike the previous user-project parent.
  // mkdtempSync produces a random suffix, preventing predictable-path pre-population.
  const TMP_TARGET = fs.mkdtempSync(path.join(os.tmpdir(), '.evolver-update-tmp-'));

  // Channel 1: GitHub Release (via degit pinned to exact version tag)
  try {
    console.log('[ForceUpdate] Channel 1: GitHub Release download (v' + requiredVersion + ')...');
    var npxBin = process.platform === 'win32' ? 'npx.cmd' : 'npx';
    // Pin to exact git tag so we download a specific published release, not
    // whatever is currently at HEAD (which could be a different, unreviewed commit).
    // --force: mkdtempSync pre-creates TMP_TARGET; some degit versions refuse a pre-existing dest.
    execFileSync(npxBin, ['-y', 'degit', '--force', 'EvoMap/evolver#v' + requiredVersion, TMP_TARGET], {
      encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 60000, windowsHide: true, maxBuffer: MAX_EXEC_BUFFER,
    });
    var tmpPkg = JSON.parse(fs.readFileSync(path.join(TMP_TARGET, 'package.json'), 'utf8'));
    // Require exact version match — a ">=" check would allow a compromised hub to
    // request version "0.0.1" and install any version including unreleased HEAD code.
    if (tmpPkg.version && tmpPkg.version === requiredVersion) {
      var entries = fs.readdirSync(INSTALL_ROOT, { withFileTypes: true });
      for (var ei = 0; ei < entries.length; ei++) {
        var eName = entries[ei].name;
        if (eName === 'node_modules' || eName === 'memory' || eName === '.git' || eName === 'MEMORY.md'
            || eName === '.env' || eName === '.env.local' || eName === 'USER.md' || eName === '.evolver') continue;
        try { fs.rmSync(path.join(INSTALL_ROOT, eName), { recursive: true, force: true }); } catch (_) {}
      }
      var newEntries = fs.readdirSync(TMP_TARGET, { withFileTypes: true });
      for (var ni = 0; ni < newEntries.length; ni++) {
        var src = path.join(TMP_TARGET, newEntries[ni].name);
        var dst = path.join(INSTALL_ROOT, newEntries[ni].name);
        // On Windows, files held open by antivirus or the OS itself raise EPERM/EBUSY.
        // Retry up to 3 times with a short delay before propagating the error.
        var copyErr = null;
        for (var attempt = 0; attempt < 3; attempt++) {
          try {
            fs.cpSync(src, dst, { recursive: true });
            copyErr = null;
            break;
          } catch (cpErr) {
            copyErr = cpErr;
            var code = cpErr && cpErr.code;
            if (code !== 'EPERM' && code !== 'EBUSY' && code !== 'EACCES') break;
            // Brief busy-wait — execFileSync has already blocked the event loop,
            // so a synchronous spin is acceptable here.
            var until = Date.now() + 200;
            while (Date.now() < until) { /* spin */ }
          }
        }
        if (copyErr) {
          console.warn('[ForceUpdate] cpSync failed for ' + newEntries[ni].name + ': ' + (copyErr.message || copyErr));
          throw copyErr;
        }
      }
      try { fs.rmSync(TMP_TARGET, { recursive: true, force: true }); } catch (_) {}
      console.log('[ForceUpdate] GitHub Release update successful: ' + tmpPkg.version);
      return true;
    }
    try { fs.rmSync(TMP_TARGET, { recursive: true, force: true }); } catch (_) {}
  } catch (e) {
    console.warn('[ForceUpdate] GitHub Release failed:', e && e.message || e);
    try { fs.rmSync(TMP_TARGET, { recursive: true, force: true }); } catch (_) {}
    // Fall through to Channel 2 (manual download URL hint) instead of
    // returning. A Channel 1 error (degit missing, network down, tag not
    // found) still leaves the user a path forward via the release_url.
  }

  // Channel 2: GitHub release (manual download URL only)
  try {
    var releaseUrl = forceUpdate.release_url;
    if (releaseUrl) {
      console.log('[ForceUpdate] Channel 2: GitHub release -- manual download required');
      console.log('[ForceUpdate] Visit: ' + releaseUrl);
    }
  } catch (_) {}

  console.warn('[ForceUpdate] All automatic channels exhausted. Current version: ' + getCurrentVersion());
  return false;
}

// Test-only hook: re-implements the EXACT same operator-strip + semver
// validation as the inline check at executeForceUpdate's L99-100. Exists
// so test/forceUpdateLastUpdateReport.test.js can build a parity sweep
// proving that _extractTargetVersion's (a2aProtocol.js) verdict matches
// forceUpdate.js's verdict byte-for-byte on any input -- the comment at
// a2aProtocol.js:823-833 claims this invariant but a hand-maintained
// regex copy can silently drift. Anything that changes this function
// MUST also update _extractTargetVersion (and vice versa) or the
// parity test breaks.
function _isAcceptedRequiredVersionForTesting(raw) {
  if (typeof raw !== 'string') return false;
  var stripped = String(raw).replace(/^[>=^~\s]+/, '');
  return /^\d+\.\d+\.\d+(-[\w.]+)?(\+[\w.]+)?$/.test(stripped);
}

module.exports = {
  executeForceUpdate,
  FORCE_UPDATE_NOOP,
  FORCE_UPDATE_BUSY,
  // Test-only hook: reset the in-flight mutex so unit tests do not leak state
  // across cases. Production callers must NOT touch this -- the mutex is the
  // load-bearing invariant that prevents concurrent state-file writes.
  _resetInFlightForTesting: function () { _inFlight = false; },
  _isAcceptedRequiredVersionForTesting: _isAcceptedRequiredVersionForTesting,
};

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { captureEnvFingerprint, envFingerprintKey } = require('./envFingerprint');

const SCHEMA_VERSION = 'anti_abuse.v1';
const REDACTION_VERSION = 'anti_abuse_redaction.v1';
const DEFAULT_TTL_DAYS = 90;
const MAX_HASH_FILE_BYTES = 10 * 1024 * 1024;

function nowIso(now) {
  if (now instanceof Date) return now.toISOString();
  if (typeof now === 'string' && now) return now;
  return new Date().toISOString();
}

function boolFromEnv(value) {
  const v = String(value || '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

function hmacPseudonym(value, opts) {
  const raw = value == null ? '' : String(value);
  const salt = opts && opts.salt ? String(opts.salt) : '';
  const purpose = opts && opts.purpose ? String(opts.purpose) : 'anti_abuse';
  if (!raw || !salt) return null;
  return crypto.createHmac('sha256', salt).update(purpose).update('\0').update(raw).digest('hex').slice(0, 32);
}

function sha256File(filePath) {
  let stat;
  try {
    stat = fs.statSync(filePath);
  } catch (_) {
    return null;
  }
  if (!stat.isFile() || stat.size > MAX_HASH_FILE_BYTES) return null;
  const hash = crypto.createHash('sha256');
  hash.update(fs.readFileSync(filePath));
  return hash.digest('hex');
}

function safeJsonFile(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (_) {
    return null;
  }
}

function filePermissionClass(filePath) {
  let stat;
  try {
    stat = fs.statSync(filePath);
  } catch (_) {
    return 'missing';
  }
  if (!stat.isFile()) return 'not_file';
  const mode = stat.mode & 0o777;
  if ((mode & 0o077) === 0) return 'owner_only';
  if ((mode & 0o007) !== 0) return 'world_accessible';
  return 'group_accessible';
}

// The integrity envelope fingerprints the INSTALLED @evomap/evolver package
// — its package.json, CLI entry, and lockfiles — not the user's project.
// __dirname tracks this file inside the install (<pkg>/src/gep/), so two
// levels up is the package root in every install mode (dev clone, npm
// global, npx cache). Hashing getRepoRoot() (the user's project) here would
// make hub-side integrity checks compare workspace files against
// evolver_version, mismatching on every npm/global install.
function getEvolverPackageRoot() {
  return path.resolve(__dirname, '..', '..');
}

// Containment gate for EVERY file the integrity envelope reads: resolve the
// candidate through symlinks and require it to stay inside the package root.
// Default-on heartbeat collection must not grow an out-of-tree file-read
// side effect — not via a tampered bin.evolver, and not via a symlinked
// package.json / lockfile either (each read is up to MAX_HASH_FILE_BYTES).
// Returns the real path when contained, else null (missing files land here
// too, matching sha256File's old null-on-ENOENT behavior).
function containedRealPath(root, candidate) {
  try {
    const realRoot = fs.realpathSync(root);
    const real = fs.realpathSync(candidate);
    return real.startsWith(realRoot + path.sep) ? real : null;
  } catch (_) {
    return null;
  }
}

function collectIntegrityHashes(packageRoot) {
  const root = packageRoot || getEvolverPackageRoot();
  const pkgPath = containedRealPath(root, path.join(root, 'package.json'));
  const pkg = (pkgPath && safeJsonFile(pkgPath)) || {};
  const bin = pkg && pkg.bin && typeof pkg.bin.evolver === 'string' ? pkg.bin.evolver : null;
  const binPath = bin ? containedRealPath(root, path.resolve(root, bin)) : null;
  const lockfiles = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lockb'];
  const lockfile_hashes = {};
  for (const name of lockfiles) {
    const p = containedRealPath(root, path.join(root, name));
    const digest = p ? sha256File(p) : null;
    if (digest) lockfile_hashes[name] = digest;
  }
  return {
    package_json_hash: pkgPath ? sha256File(pkgPath) : null,
    cli_entry_hash: binPath ? sha256File(binPath) : null,
    lockfile_hashes,
  };
}

function settingsPermissionClass(env) {
  const e = env || process.env;
  const settingsDir = e.EVOLVER_SETTINGS_DIR || path.join(os.homedir(), '.evolver');
  return filePermissionClass(path.join(settingsDir, 'settings.json'));
}

function normalizeTaskMetrics(taskMeta) {
  const meta = taskMeta && typeof taskMeta === 'object' ? taskMeta : {};
  const metrics = meta.task_metrics && typeof meta.task_metrics === 'object' ? meta.task_metrics : null;
  if (!metrics) return null;
  return {
    pending: Number.isFinite(Number(metrics.pending)) ? Number(metrics.pending) : null,
    claimed: Number.isFinite(Number(metrics.claimed)) ? Number(metrics.claimed) : null,
    completed: Number.isFinite(Number(metrics.completed)) ? Number(metrics.completed) : null,
    failed: Number.isFinite(Number(metrics.failed)) ? Number(metrics.failed) : null,
    avg_completion_ms: Number.isFinite(Number(metrics.avg_completion_ms)) ? Number(metrics.avg_completion_ms) : null,
  };
}

function ttlDays(env) {
  const raw = Number(env && env.EVOLVER_ANTI_ABUSE_TTL_DAYS);
  return Number.isFinite(raw) && raw > 0 ? Math.floor(raw) : DEFAULT_TTL_DAYS;
}

function unavailable(field, reason, expectedSource) {
  return {
    field,
    reason,
    expected_source: expectedSource || 'hub_server',
  };
}

function buildHeartbeatAntiAbuseTelemetry(opts) {
  const options = opts || {};
  const env = options.env || process.env;
  const fp = options.envFingerprint || captureEnvFingerprint();
  const salt = options.salt != null ? options.salt : env.EVOLVER_ANTI_ABUSE_SALT;
  const saltId = options.saltId || env.EVOLVER_ANTI_ABUSE_SALT_ID || (salt ? 'env' : null);
  const packageRoot = options.packageRoot || getEvolverPackageRoot();
  const devicePseudonym = hmacPseudonym(fp && fp.device_id, { salt, purpose: 'device' });
  const workspacePseudonym = hmacPseudonym(process.cwd(), { salt, purpose: 'workspace' });
  const missing = [];
  if (!devicePseudonym) missing.push(unavailable('device_pseudonym', 'anti_abuse_salt_missing', 'signed_policy_or_env'));
  if (!workspacePseudonym) missing.push(unavailable('workspace_pseudonym', 'anti_abuse_salt_missing', 'signed_policy_or_env'));
  missing.push(
    unavailable('client_ip', 'server_observed_required', 'hub_edge'),
    unavailable('asn', 'server_observed_required', 'hub_edge'),
    unavailable('proxy_vpn_tor_datacenter_class', 'server_observed_required', 'hub_edge'),
    unavailable('account_security', 'account_service_required', 'hub_account'),
    unavailable('payout_method_token', 'payments_service_required', 'hub_payments'),
    unavailable('risk_action_case', 'risk_engine_required', 'hub_risk')
  );

  return {
    schema_version: SCHEMA_VERSION,
    event_type: 'node.heartbeat',
    purpose: 'anti_abuse',
    pii_class: 'medium',
    consent_level: 'default',
    retention_ttl_days: ttlDays(env),
    policy_version: env.EVOLVER_ANTI_ABUSE_POLICY_VERSION || 'local-default',
    redaction_version: REDACTION_VERSION,
    source: options.source || 'evolver-client',
    generated_at: nowIso(options.now),
    source_confidence: {
      node_identity: 'client_attested',
      device_integrity: 'client_attested',
      task_metrics: 'client_attested',
      network_source: 'server_observed_required',
      account_security: 'server_observed_required',
      payout: 'server_observed_required',
      risk_decision: 'server_observed_required',
    },
    identity: {
      node_id: options.nodeId || null,
      account_id: null,
      org_id: null,
    },
    device: {
      device_pseudonym: devicePseudonym,
      workspace_pseudonym: workspacePseudonym,
      pseudonym_salt_id: saltId,
      env_fingerprint_key: envFingerprintKey(fp),
      platform: fp.platform || null,
      arch: fp.arch || null,
      os_release: fp.os_release || null,
      node_version: fp.node_version || null,
      evolver_version: fp.evolver_version || null,
      client: fp.client || null,
      client_version: fp.client_version || null,
      model: fp.model || null,
      region: fp.region || null,
      container: !!fp.container,
    },
    integrity: collectIntegrityHashes(packageRoot),
    local_security_boundary: {
      proxy_bind_address_class: 'loopback',
      // Env sniffing is only a fallback for the client heartbeat: the proxy
      // lifecycle heartbeat runs INSIDE the proxy process (which usually has
      // neither env var set) and passes its ground truth explicitly.
      proxy_port_configured: options.proxyPortConfigured != null
        ? !!options.proxyPortConfigured
        : (boolFromEnv(env.EVOMAP_PROXY) || !!env.EVOMAP_PROXY_PORT),
      settings_permission_class: settingsPermissionClass(env),
    },
    task_timing: normalizeTaskMetrics(options.taskMeta),
    unavailable_fields: missing,
  };
}

module.exports = {
  SCHEMA_VERSION,
  REDACTION_VERSION,
  buildHeartbeatAntiAbuseTelemetry,
  collectIntegrityHashes,
  hmacPseudonym,
};

// Environment fingerprint capture for GEP assets.
// Records the runtime environment so that cross-environment diffusion
// success rates (GDI) can be measured scientifically.

const os = require('os');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { getRepoRoot } = require('./paths');
const { getDeviceId, isContainer } = require('./deviceId');

// Resolve the underlying LLM model name powering this evolver node.
//
// Until now the only source was the explicit EVOLVER_MODEL_NAME env var, so
// nodes that never set it published assets with no model at all -- the Hub
// could not tell which model produced a Gene/Capsule, breaking the by-model
// leaderboard and depriving anti-sybil clustering of a strong signal.
//
// We now fall back to the model env vars the common host CLIs expose
// (Claude Code / Codex / Cursor / generic OpenAI-compatible runners). When
// nothing is discoverable we return the literal 'unknown' rather than null so
// that downstream aggregation always has a stable, groupable value and can
// distinguish "ran but model undetectable" from "field absent (old client)".
function detectModelName() {
  const candidates = [
    process.env.EVOLVER_MODEL_NAME,
    process.env.ANTHROPIC_MODEL,
    process.env.CLAUDE_MODEL,
    process.env.CLAUDE_CODE_MODEL,
    process.env.OPENAI_MODEL,
    process.env.CODEX_MODEL,
    process.env.CURSOR_MODEL,
  ];
  for (const c of candidates) {
    const v = (c || '').trim();
    if (v) return v.slice(0, 100);
  }
  return 'unknown';
}

// Capture a structured environment fingerprint.
// This is embedded into Capsules, EvolutionEvents, and ValidationReports.
function captureEnvFingerprint() {
  const repoRoot = getRepoRoot();
  let pkgVersion = null;
  let pkgName = null;

  // Read evolver's own package.json via __dirname so that npm-installed
  // deployments report the correct evolver version. getRepoRoot() walks
  // up to the nearest .git directory, which resolves to the HOST project
  // when evolver is an npm dependency -- producing a wrong name/version.
  const ownPkgPath = path.resolve(__dirname, '..', '..', 'package.json');
  try {
    const raw = fs.readFileSync(ownPkgPath, 'utf8');
    const pkg = JSON.parse(raw);
    pkgVersion = pkg && pkg.version ? String(pkg.version) : null;
    pkgName = pkg && pkg.name ? String(pkg.name) : null;
  } catch (e) {}

  if (!pkgVersion) {
    try {
      const raw = fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8');
      const pkg = JSON.parse(raw);
      pkgVersion = pkg && pkg.version ? String(pkg.version) : null;
      pkgName = pkg && pkg.name ? String(pkg.name) : null;
    } catch (e) {}
  }

  const region = (process.env.EVOLVER_REGION || '').trim().toLowerCase().slice(0, 5) || undefined;

  return {
    device_id: getDeviceId(),
    node_version: process.version,
    platform: process.platform,
    arch: process.arch,
    os_release: os.release(),
    hostname: crypto.createHash('sha256').update(os.hostname()).digest('hex').slice(0, 12),
    evolver_version: pkgVersion,
    client: pkgName || 'evolver',
    client_version: pkgVersion,
    // Underlying LLM model. NOT folded into envFingerprintKey() below: a node
    // can swap models without changing its environment class, so the grouping
    // key must stay model-independent. The model travels as its own field.
    model: detectModelName(),
    region: region,
    cwd: crypto.createHash('sha256').update(process.cwd()).digest('hex').slice(0, 12),
    container: isContainer(),
    captured_at: new Date().toISOString(),
  };
}

// Compute a short fingerprint key for comparison and grouping.
// Two nodes with the same key are considered "same environment class".
function envFingerprintKey(fp) {
  if (!fp || typeof fp !== 'object') return 'unknown';
  const parts = [
    fp.device_id || '',
    fp.node_version || '',
    fp.platform || '',
    fp.arch || '',
    fp.hostname || '',
    fp.client || fp.evolver_version || '',
    fp.client_version || fp.evolver_version || '',
  ].join('|');
  return crypto.createHash('sha256').update(parts, 'utf8').digest('hex').slice(0, 16);
}

// Check if two fingerprints are from the same environment class.
function isSameEnvClass(fpA, fpB) {
  return envFingerprintKey(fpA) === envFingerprintKey(fpB);
}

module.exports = {
  captureEnvFingerprint,
  envFingerprintKey,
  isSameEnvClass,
  detectModelName,
};

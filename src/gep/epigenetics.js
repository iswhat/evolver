'use strict';

const cfg = require('../config');

function resolveEnvContext(envFingerprint) {
  const platform = envFingerprint && envFingerprint.platform ? String(envFingerprint.platform) : '';
  const arch = envFingerprint && envFingerprint.arch ? String(envFingerprint.arch) : '';
  const nodeVersion = envFingerprint && envFingerprint.node_version ? String(envFingerprint.node_version) : '';
  return [platform, arch, nodeVersion].filter(Boolean).join('/') || 'unknown';
}

function getEpigeneticBoost(gene, envFingerprint) {
  if (!gene || !Array.isArray(gene.epigenetic_marks)) return 0;
  const envContext = resolveEnvContext(envFingerprint);
  const mark = gene.epigenetic_marks.find(function (m) { return m && m.context === envContext; });
  return mark ? Number(mark.boost) || 0 : 0;
}

function isEpigeneticallySuppressed(gene, envFingerprint) {
  if (!gene || !Array.isArray(gene.epigenetic_marks) || gene.epigenetic_marks.length === 0) {
    return false;
  }
  const envContext = resolveEnvContext(envFingerprint);
  const mark = gene.epigenetic_marks.find(function (m) { return m && m.context === envContext; });
  if (!mark) return false;
  const boost = Number(mark.boost);
  if (!Number.isFinite(boost)) return false;
  return boost <= cfg.GENE_EPIGENETIC_HARD_BOOST;
}

module.exports = { resolveEnvContext, getEpigeneticBoost, isEpigeneticallySuppressed };

'use strict';

const crypto = require('crypto');

const DEFAULT_TRACE_CONFIG_SIGNING_PUBLIC_KEY = [
  '-----BEGIN PUBLIC KEY-----',
  'MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA7kJvWUP3HC4FJPQtkh74',
  'y75h9Rzc2NSZC9e4fiIWdax4iv+yWeMeIHGNsMr7YI8Ws7ck1BimJWt026gwRW8I',
  'c2A7h97oZQ0Z0zFcjEZ8FpYFSu++Yz/dGrARAV7uCQg289jvo89F5fWNdX2k+lTH',
  'hBoBm0G71vkiAYlbQEjq1xm1WzYf8CVXmbr+J1z+ydQf9jczcFL79u3eQZhIPs3R',
  '8Sr83YrXWyCVOBIPTW4EbyR1RrHNs9pyrcHo7tyKdpKYreM/0de5A5Ya1VFaakVd',
  'RsE3UModswJeMzyHOj7wZ+OZVb466Bttr0wDHhg93sWg5h5m0YqNfEcdqFXKlxy3',
  'RCAu+hINcwt27CcIEU82jhDusiKEfM/EHS/uN3GTuvNaUFpmIOPNFYINKdjdiMJK',
  '50lyW9E3SN+Q3HT6flseEAI+hMvFx6wxGqzf64jWbuUlatl8M9v3NNZAOgG4SnTt',
  'PiOh2Uxc0qFAKPpcz8gaGYm0yMuFGsr5zb0IMDSBr++PAgMBAAE=',
  '-----END PUBLIC KEY-----',
].join('\n');

function canonicalTraceConfigPayload(payload = {}) {
  const clean = {};
  for (const key of Object.keys(payload).sort()) {
    if (key === 'signature' || key === 'trace_config_signature' || key === 'signature_algorithm') continue;
    if (key === 'hub_public_key') continue;
    const value = payload[key];
    if (value !== undefined) clean[key] = value;
  }
  return JSON.stringify(clean);
}

function verifyTraceConfigSignature(payload = {}, env = process.env) {
  const publicKey = String(
    env.EVOMAP_TRACE_CONFIG_SIGNING_PUBLIC_KEY
    || env.EVOMAP_PROXY_TRACE_CONFIG_SIGNING_PUBLIC_KEY
    || DEFAULT_TRACE_CONFIG_SIGNING_PUBLIC_KEY
  ).trim();
  const signature = String(payload.signature || payload.trace_config_signature || '').trim();
  if (!publicKey || !signature) return false;
  try {
    return crypto.verify(
      'sha256',
      Buffer.from(canonicalTraceConfigPayload(payload), 'utf8'),
      publicKey,
      Buffer.from(signature, 'base64')
    );
  } catch {
    return false;
  }
}

class TraceControl {
  constructor({ store, logger } = {}) {
    this.store = store;
    this.logger = logger || console;
  }

  process(message) {
    const payload = message && message.payload ? message.payload : message;
    const enabled = payload && (
      payload.enabled ??
      payload.trace_collection_enabled ??
      payload.proxy_trace_collection_enabled
    );
    if (typeof enabled !== 'boolean') {
      this.logger.warn?.('[trace-control] ignoring config without boolean enabled');
      return { ack: true, applied: false };
    }
    let profileEnabled = payload.profile_analysis_enabled ?? payload.trace_profile_analysis_enabled;
    const signed = verifyTraceConfigSignature(payload);
    const unsafeEnable = enabled === true;
    const unsafeProfile = profileEnabled === true;
    const hasRuntimeHubKey = typeof payload.hub_public_key === 'string' && payload.hub_public_key.trim();
    if (!signed && unsafeEnable) {
      this.logger.warn?.('[trace-control] rejected unsigned trace config that could enable collection/profile analysis');
      return { ack: true, applied: false };
    }
    if (!signed && unsafeProfile) {
      this.logger.warn?.('[trace-control] ignored unsigned profile analysis enable while applying trace disable');
      profileEnabled = false;
    }
    this.store.setState('trace_collection_enabled', enabled ? 'true' : 'false');
    if (typeof profileEnabled === 'boolean') {
      this.store.setState('trace_profile_analysis_enabled', profileEnabled ? 'true' : 'false');
    }
    // trace_hub_public_key is part of the SIGNED canonical payload (unlike the legacy runtime hub_public_key,
    // which stays excluded + ignored). Persist it only from a verified-signed config, so the hub can distribute
    // its trace-encryption public key centrally without a per-node env, while a forged/unsigned config still
    // cannot inject a key. extractor.readTraceProfileConfig reads this as a fallback to the pinned env var.
    const signedHubKey = typeof payload.trace_hub_public_key === 'string' && payload.trace_hub_public_key.trim();
    if (signed && signedHubKey && payload.trace_hub_public_key.includes('PUBLIC KEY')) {
      this.store.setState('trace_hub_public_key', payload.trace_hub_public_key.trim());
    } else if (!signed && signedHubKey) {
      this.logger.warn?.('[trace-control] ignored trace_hub_public_key from an unsigned config');
    }
    if (hasRuntimeHubKey) {
      this.logger.warn?.('[trace-control] ignored runtime hub_public_key; use pinned EVOMAP_PROXY_TRACE_HUB_PUBLIC_KEY or signed trace_hub_public_key');
    }
    this.store.setState('trace_collection_updated_at', new Date().toISOString());
    this.logger.log?.('[trace-control] trace collection ' + (enabled ? 'enabled' : 'disabled'));
    return { ack: true, applied: true };
  }

  pollAndApply() {
    const messages = [
      ...this.store.poll({ type: 'trace_collection_config', limit: 50 }),
      ...this.store.poll({ type: 'proxy_trace_config', limit: 50 }),
    ];
    let applied = 0;
    for (const msg of messages) {
      const result = this.process(msg);
      const ack = result === true || (result && result.ack === true);
      const didApply = result === true || (result && result.applied === true);
      if (ack) {
        this.store.ack(msg.id);
      }
      if (didApply) {
        applied++;
      }
    }
    return applied;
  }
}

module.exports = { TraceControl, canonicalTraceConfigPayload, verifyTraceConfigSignature, DEFAULT_TRACE_CONFIG_SIGNING_PUBLIC_KEY };

'use strict';

// Per-run token-usage rollup over the proxy trace log.
//
// The local proxy (src/proxy) meters real Anthropic input/output tokens for
// every Hand /v1/messages call into proxy-traces.jsonl. This reads that log
// back -- decrypting encrypted rows with the local EvoMap node secret -- and
// sums the real tokens spent within a time window, giving solidify the
// MEASURED cost of a derive loop.
//
// Best-effort by design: returns measured:false (and never throws) when the
// proxy was inactive, the node secret is missing, no rows fall in the window,
// or the in-window rows carried no usage (e.g. streamed-but-unobserved calls).
// Callers fall back to a grounded estimate in that case.

const fs = require('fs');
const {
  resolveTraceFile,
  resolveEvomapNodeSecret,
  decryptTraceEnvelope,
} = require('./extractor');

const EMPTY = Object.freeze({
  input_tokens: 0,
  output_tokens: 0,
  total_tokens: 0,
  calls: 0,
  measured: false,
});

function _rowTimestampMs(row) {
  const iso = row && (row.timestamp || row.createdAtIso);
  if (iso) {
    const ms = Date.parse(iso);
    if (Number.isFinite(ms)) return ms;
  }
  // createdAt is unix seconds in the Prism trace shape.
  if (row && Number.isFinite(Number(row.createdAt))) return Number(row.createdAt) * 1000;
  return null;
}

/**
 * Sum the real token usage the proxy recorded within a run's time window.
 *
 * @param {object} opts
 * @param {string} opts.sinceIso - REQUIRED lower bound (e.g. last_run.created_at).
 *   Without a window we cannot attribute traces to this run, so we report
 *   unmeasured rather than summing unrelated calls.
 * @param {string} [opts.untilIso] - upper bound; defaults to now.
 * @returns {{input_tokens:number,output_tokens:number,total_tokens:number,calls:number,measured:boolean}}
 */
function sumRunUsage(opts = {}) {
  const sinceMs = opts && opts.sinceIso != null ? Date.parse(opts.sinceIso) : NaN;
  if (!Number.isFinite(sinceMs)) return { ...EMPTY };
  const untilMs = opts && opts.untilIso != null && Number.isFinite(Date.parse(opts.untilIso))
    ? Date.parse(opts.untilIso)
    : Date.now();

  let raw;
  try {
    const file = resolveTraceFile();
    if (!fs.existsSync(file)) return { ...EMPTY };
    raw = fs.readFileSync(file, 'utf8');
  } catch (_) {
    return { ...EMPTY };
  }

  let secret = null;
  try { secret = resolveEvomapNodeSecret(); } catch (_) { secret = null; }

  let input = 0;
  let output = 0;
  let calls = 0;
  for (const line of raw.split('\n')) {
    const s = line.trim();
    if (!s) continue;
    let row;
    try { row = JSON.parse(s); } catch (_) { continue; }
    if (row && row.encrypted) {
      if (!secret) continue; // cannot decrypt -> treat as unobserved
      try { row = decryptTraceEnvelope(row, secret); } catch (_) { continue; }
    }
    if (!row || typeof row !== 'object') continue;
    const ms = _rowTimestampMs(row);
    if (ms == null || ms < sinceMs || ms > untilMs) continue;
    const i = Number(row.input_tokens);
    const o = Number(row.output_tokens);
    const hasI = Number.isFinite(i) && i > 0;
    const hasO = Number.isFinite(o) && o > 0;
    if (hasI) input += i;
    if (hasO) output += o;
    if (hasI || hasO) calls += 1;
  }

  if (calls === 0) return { ...EMPTY };
  return {
    input_tokens: input,
    output_tokens: output,
    total_tokens: input + output,
    calls,
    measured: true,
  };
}

module.exports = { sumRunUsage };

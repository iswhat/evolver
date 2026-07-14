// hubFetch -- single chokepoint for every Hub-facing HTTP call.
//
// Two protections, both bypassable only via EVOMAP_HUB_ALLOW_INSECURE=1:
//
//   1. URL schema check.  Rejects anything that does not parse as https://.
//      This catches every misconfigured / attacker-supplied env var even
//      when the caller bypassed resolveHubUrl() and read process.env
//      directly (httpTransportSend / getHubUrl() / per-call opts.hubUrl /
//      proxy this.hubUrl all reach here).
//
//   2. TLS verification.  Built-in fetch validates certificates by default,
//      but NODE_TLS_REJECT_UNAUTHORIZED=0 disables that globally.  Passing
//      an explicit undici.Agent with connect.rejectUnauthorized:true as
//      the dispatcher makes Hub traffic immune to that env var.
//
// Escape hatch: EVOMAP_HUB_ALLOW_INSECURE=1 disables BOTH protections (used
// for local dev / mock hubs on http:// or with self-signed certs).  Any
// value other than exactly "1" is treated as absent.

// Use BOTH Agent and fetch from the same undici package.  Node's global
// fetch is built on an internal undici, and an Agent created from the
// installed `undici` package is not interface-compatible with it — mixing
// them yields `UND_ERR_INVALID_ARG: invalid onRequestStart method` at
// request time.  Pulling fetch from the same package keeps them in sync.
const https = require('https');
const { TextDecoder } = require('util');
const { Agent, fetch: undiciFetch, buildConnector } = require('undici');
const { redactString } = require('./sanitize');

const HUB_ERROR_TEXT_MAX_BYTES = 8 * 1024;
const HUB_JSON_TEXT_MAX_BYTES = 4 * 1024 * 1024;
const HUB_LOG_TEXT_MAX_CHARS = 1024;
const HUB_UNREACHABLE_BACKOFF_BASE_MS = 60_000;
const HUB_UNREACHABLE_BACKOFF_MAX_MS = 10 * 60_000;
const HUB_LOG_REDACTED = '[REDACTED]';
const HUB_LOG_SENSITIVE_KEY_RE = /(?:secret|token|api[_-]?key|authorization|password|env|credential)/i;

class HubUnreachableError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'HubUnreachableError';
    this.code = 'HUB_UNREACHABLE';
    this.statusCode = details.statusCode || null;
    this.contentType = details.contentType || '';
    this.bodySnippet = details.bodySnippet || '';
    this.context = details.context || '';
  }
}

// Cap idle keep-alive well below consumer-router NAT eviction (typically
// 60-300s). undici's default keepAliveTimeout is 600s, which means after an
// idle period the next request reuses a socket the NAT has already silently
// dropped and only fails after AbortSignal timeout — a major contributor to
// post-idle heartbeat death. headers/bodyTimeout are bounded so a wedged
// socket cannot stall the heartbeat indefinitely.
// Connect options shared between agents.
//   - rejectUnauthorized: TLS verification, immune to NODE_TLS_REJECT_UNAUTHORIZED=0.
//   - timeout: TCP+TLS handshake deadline.
//   - Hub traffic defaults to IPv4-first: try an IPv4 socket first, then fall
//     back to dual-stack Happy Eyeballs if IPv4 cannot connect. Real-world
//     VPN/TUN setups often route IPv4 through the intended exit while leaving
//     IPv6 on the local ISP path; Cloudflare country rules then see a CN IPv6
//     and block otherwise valid Hub calls. Set EVOMAP_HUB_IP_FAMILY=auto to
//     restore dual-stack Happy Eyeballs as the primary path, or ipv4-only to
//     disable fallback for controlled networks.
function _resolveHubIpFamily() {
  const raw = String(process.env.EVOMAP_HUB_IP_FAMILY || 'ipv4first').trim().toLowerCase();
  if (raw === 'ipv4' || raw === 'v4' || raw === '4' || raw === 'ipv4first' || raw === 'ipv4-first') return 'ipv4first';
  if (raw === 'ipv4only' || raw === 'ipv4-only') return 'ipv4only';
  if (raw === 'auto' || raw === 'dualstack' || raw === 'dual-stack') return 'auto';
  throw new Error('[hubFetch] EVOMAP_HUB_IP_FAMILY must be "ipv4", "ipv4-only", or "auto" — got ' + JSON.stringify(process.env.EVOMAP_HUB_IP_FAMILY));
}

const _hubIpFamily = _resolveHubIpFamily();
const _CONNECT_TIMEOUT_MS = 10_000;
const _IPV4FIRST_PRIMARY_CONNECT_TIMEOUT_MS = 2_500;
const _baseConnectOpts = {
  rejectUnauthorized: true,
  timeout: _CONNECT_TIMEOUT_MS,
};
const _ipv4OnlyConnectOpts = {
  ..._baseConnectOpts,
  family: 4,
  autoSelectFamily: false,
};
// In ipv4first mode the IPv4-only connector is a probe, not the whole
// heartbeat budget. Keep it short so fallback Happy Eyeballs still has
// time to connect before the 10s application-layer deadline fires.
const _ipv4FirstPrimaryConnectOpts = {
  ..._ipv4OnlyConnectOpts,
  timeout: _IPV4FIRST_PRIMARY_CONNECT_TIMEOUT_MS,
};
const _autoConnectOpts = {
  ..._baseConnectOpts,
  autoSelectFamily: true,
  autoSelectFamilyAttemptTimeout: 250,
};
const _connectOpts = _hubIpFamily === 'auto'
  ? _autoConnectOpts
  : (_hubIpFamily === 'ipv4only' ? _ipv4OnlyConnectOpts : _ipv4FirstPrimaryConnectOpts);

const _IPV4_FALLBACK_CODES = new Set([
  'EADDRNOTAVAIL',
  'EAI_AGAIN',
  'ECONNREFUSED',
  'ETIMEDOUT',
  'ENETUNREACH',
  'EHOSTUNREACH',
  'ENOTFOUND',
  'UND_ERR_CONNECT_TIMEOUT',
]);

function _shouldFallbackFromIpv4(err) {
  if (_hubIpFamily !== 'ipv4first') return false;
  const code = err && (err.code || (err.cause && err.cause.code));
  return _IPV4_FALLBACK_CODES.has(code);
}

// Round-8 (§21.6): wrap undici's built-in connector so we can enable
// OS-level TCP keepalive on the underlying socket. macOS default
// TCP_KEEPIDLE is 7200s -- way too long for our 10s heartbeat
// AbortSignal to ever benefit from kernel-level dead-socket detection.
// undici's keepAliveTimeout (10s above) trims sockets that have been
// idle in our pool, but a socket that is freshly idle (1-9s) and gets
// silently NAT-evicted during the macOS sleep window is reused on
// wake, the next request hangs until the AbortSignal trips, and the
// dispatcher pool fills with "destroying" sockets that pin capacity.
// With setKeepAlive(true, 15_000) the kernel fires TCP keepalive
// probes after 15s of socket idle, sees the silent drop within a few
// probe intervals, and surfaces ECONNRESET to the next read -- so
// reuse of a dead socket fails fast instead of hanging until app-
// layer timeout. rejectUnauthorized, connect.timeout, and the selected
// IP-family policy all still apply because we delegate to buildConnector(opts).
const _primaryConnect = buildConnector(_connectOpts);
const _fallbackConnect = _hubIpFamily === 'ipv4first' ? buildConnector(_autoConnectOpts) : null;
function _connectWithKeepAlive(opts, cb) {
  function done(err, socket) {
    if (err) return cb(err, socket);
    try {
      if (socket && typeof socket.setKeepAlive === 'function') {
        socket.setKeepAlive(true, 15_000);
      }
    } catch (_) { /* never block connect on a setKeepAlive failure */ }
    cb(null, socket);
  }

  return _primaryConnect(opts, function (err, socket) {
    if (err && _fallbackConnect && _shouldFallbackFromIpv4(err)) {
      return _fallbackConnect(opts, done);
    }
    return done(err, socket);
  });
}
// Marker so the #160 TLS-pinning contract (dispatcher.options.connect
// .rejectUnauthorized === true) remains introspectable now that
// `connect` is a function wrapping buildConnector(_connectOpts) instead
// of a plain options object. The actual TLS pinning is enforced by
// _connectOpts above; this property only mirrors that intent for tests
// and readers.
_connectWithKeepAlive.rejectUnauthorized = true;

function _makeStrictAgent() {
  return new Agent({
    connect: _connectWithKeepAlive,
    keepAliveTimeout: 10_000,
    keepAliveMaxTimeout: 60_000,
    headersTimeout: 30_000,
    bodyTimeout: 30_000,
    pipelining: 1,
  });
}

function _makeLongPollAgent() {
  return new Agent({
    connect: _connectWithKeepAlive,
    keepAliveTimeout: 10_000,
    keepAliveMaxTimeout: 60_000,
    headersTimeout: 65_000,
    bodyTimeout: 65_000,
    pipelining: 1,
  });
}

function _makeEventStreamAgent() {
  return new Agent({
    connect: _connectWithKeepAlive,
    keepAliveTimeout: 10_000,
    keepAliveMaxTimeout: 60_000,
    headersTimeout: 30_000,
    bodyTimeout: 0,
    pipelining: 1,
  });
}

function _makeMailboxAgent() {
  return new Agent({
    connect: _connectWithKeepAlive,
    keepAliveTimeout: 10_000,
    keepAliveMaxTimeout: 60_000,
    // Sits just above the highest mailbox AbortSignal (inbound=35s) so the
    // app-layer signal is the authority on cancellation, while still
    // bounding wedged-socket lifetime well below "forever".
    headersTimeout: 45_000,
    bodyTimeout: 45_000,
    pipelining: 1,
  });
}

function _getHubFetchConfigForTest() {
  return {
    hubIpFamily: _hubIpFamily,
    connectTimeoutMs: _CONNECT_TIMEOUT_MS,
    ipv4FirstPrimaryConnectTimeoutMs: _IPV4FIRST_PRIMARY_CONNECT_TIMEOUT_MS,
    connectOpts: { ..._connectOpts },
    primaryConnectOpts: { ..._connectOpts },
    fallbackConnectOpts: _fallbackConnect ? { ..._autoConnectOpts } : null,
  };
}

// Default agent for short hub calls (heartbeat, hello, transport, publish).
// Header/body timeouts (30s) are bounded so a wedged socket cannot stall
// the heartbeat loop (HEARTBEAT_TIMEOUT_MS=10s leaves a 3x margin).
// keepAliveTimeout is well below consumer-router NAT eviction (typically
// 60-300s) so the next call after an idle period gets a fresh socket
// rather than reusing one the NAT has silently dropped.
// Backward-compatible Node native `https.Agent` export for callers that still
// build their own `https.request(...)` transport. New Hub clients should route
// through hubFetch so TLS and IP-family policy stay centralized.
const _strictHttpsAgent = new https.Agent({ rejectUnauthorized: true });

// Long-poll agent for /a2a/events/poll. The application-layer
// AbortSignal.timeout for that path is 60s (EVENT_POLL_TIMEOUT_MS), but
// _strictAgent's headersTimeout=30s would otherwise fire first and abort
// every long poll at 30s -- the hub gets no chance to deliver an event
// that arrives in the 30-55s window. Headers/body timeouts here sit just
// above the app-layer 60s ceiling so the AbortSignal is the visible
// timeout signal.
// Event-stream agent for /a2a/events/stream. SSE may sit idle for minutes
// between messages, so bodyTimeout is disabled and lifecycle is owned by
// the caller's AbortController / close() path.
// Mailbox agent for /a2a/mailbox/inbound (35s AbortSignal) and
// /a2a/mailbox/outbound (30s AbortSignal). _strictAgent's 30s
// headers/bodyTimeout would fire AT OR BEFORE those app signals,
// silently capping inbound at 30s (regression vs main where _strictAgent
// had undici defaults ~300s) and racing with outbound's identical 30s
// signal. The 45s ceiling here keeps the app-layer AbortSignal as the
// authority while still bounding a wedged socket.
let _strictAgent = _makeStrictAgent();
let _longPollAgent = _makeLongPollAgent();
let _eventStreamAgent = _makeEventStreamAgent();
let _mailboxAgent = _makeMailboxAgent();

// Drain and rebuild both undici agents. Called from the index.js SIGCONT
// handler on macOS resume: undici's keepAliveTimeout is measured from
// "socket goes idle" on libuv's monotonic clock, which freezes through
// sleep. The next post-wake request can therefore reuse a socket the
// NAT silently dropped during the suspend window and only fail after the
// 30s headersTimeout -- well above HEARTBEAT_TIMEOUT_MS (10s). The
// AbortSignal trips first but the socket may linger in the pool's
// "destroying" state, pinning capacity. Closing both agents forces all
// idle sockets shut and frees the per-host autoSelectFamily cache so a
// stale "v6 wins" decision from before sleep does not stick when v6 is
// now black-holed. In-flight requests still finish on their existing
// socket (close() does not abort them). Cheap to call -- safe to invoke
// even if nothing changed.
function drainPool() {
  const old = [_strictAgent, _longPollAgent, _eventStreamAgent, _mailboxAgent];
  _strictAgent = _makeStrictAgent();
  _longPollAgent = _makeLongPollAgent();
  _eventStreamAgent = _makeEventStreamAgent();
  _mailboxAgent = _makeMailboxAgent();
  for (const agent of old) {
    try {
      // Agent.close() returns a Promise that resolves when all in-flight
      // requests finish. We do not await it -- the new agents already
      // serve fresh calls, and the old ones drain naturally.
      const p = agent.close();
      if (p && typeof p.catch === 'function') p.catch(() => {});
    } catch (_) {}
  }
}

function _pickDispatcher(url) {
  // Four dispatcher pools, picked by exact path match:
  //   - /a2a/events/poll             -> _longPollAgent (65s timeouts)
  //   - /a2a/events/stream           -> _eventStreamAgent (stream body timeout disabled)
  //   - /a2a/mailbox/{inbound,outbound} -> _mailboxAgent (45s timeouts)
  //   - everything else              -> _strictAgent (30s timeouts)
  //
  // The split exists because each path has a different app-layer
  // AbortSignal ceiling: event poll = 60s, event stream = minutes,
  // mailbox inbound = 35s, mailbox outbound = 30s (racy against strict's
  // 30s), heartbeat / hello / transport = <= 10s. The strict agent's 30s
  // headers/bodyTimeout would otherwise fire BEFORE the longer app signals,
  // silently capping those paths and making AbortSignal cosmetic. Mailbox /
  // event dispatchers keep the app-layer signal as the visible timeout
  // while still bounding wedged-socket lifetime.
  //
  // Match on path (not host) to avoid coupling to a specific hub URL.
  //
  // Round-6 (§19.8): previously the matcher accepted both
  // `pathname === '/a2a/events/poll'` AND `pathname.endsWith('/a2a/events/poll')`.
  // The endsWith branch was a needless widening that also caught
  // unrelated paths such as `/admin/a2a/events/poll`, `/v2/a2a/events/poll`,
  // or any future hub path that happens to end with the same suffix --
  // those would silently inherit the 65s long-poll timeout when they
  // should fail fast on the 30s strict timeout. Use exact match only.
  // For hub deployments mounted under a base path (rare; not in the
  // current hub repo), set EVOLVER_LONG_POLL_PATH to override.
  const longPollPath = process.env.EVOLVER_LONG_POLL_PATH || '/a2a/events/poll';
  const eventStreamPath = process.env.EVOLVER_EVENT_STREAM_PATH || '/a2a/events/stream';
  try {
    const u = new URL(url);
    if (u.pathname === longPollPath) {
      return _longPollAgent;
    }
    if (u.pathname === eventStreamPath) {
      return _eventStreamAgent;
    }
    if (u.pathname === '/a2a/mailbox/inbound' || u.pathname === '/a2a/mailbox/outbound') {
      return _mailboxAgent;
    }
  } catch {
    // fall through to strict
  }
  return _strictAgent;
}

// Test seam: lets unit tests swap in a mock fetch without forking the call
// path.  Production code must NEVER reassign this from outside the module.
let _fetchImpl = undiciFetch;
function _setFetchImplForTest(fn) { _fetchImpl = fn || undiciFetch; }

// Error codes that indicate a network-layer disruption rather than an
// application-layer error.  On Linux, a NetworkManager reconnect, VPN
// re-establishment, or WiFi hand-off invalidates the 5-tuples of all
// existing TCP connections in the undici pool.  The kernel surfaces the
// break as one of these codes on the next read/write; undici wraps them
// in Error objects but preserves the original .code property.
//
// When we see one of these we call drainPool() so the *next* request
// gets a freshly connected socket instead of reusing a dead one, then
// re-throw so the caller's existing error path still fires normally.
// ECONNRESET -- TCP RST received (NM reconnect, VPN teardown)
// ENETDOWN    -- network interface went offline
// ENETUNREACH -- no route to host (transient during re-IP)
// EHOSTUNREACH-- host unreachable (routing table flush)
// ENOTCONN    -- socket not connected (rare but seen on interface bounce)
// UND_ERR_SOCKET -- undici's own wrapper for abrupt socket closure
const _NETWORK_DISRUPTION_CODES = new Set([
  'ECONNRESET',
  'ECONNREFUSED',
  'ENETDOWN',
  'ENETUNREACH',
  'EHOSTUNREACH',
  'EAI_AGAIN',
  'ENOTFOUND',
  'ENOTCONN',
  'ETIMEDOUT',
  'ABORT_ERR',
  'UND_ERR_SOCKET',
  'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_HEADERS_TIMEOUT',
  'UND_ERR_BODY_TIMEOUT',
]);

function _isNetworkDisruptionError(err) {
  if (!err) return false;
  // undici may carry the original code either on err.code or on err.cause.code
  if (_NETWORK_DISRUPTION_CODES.has(err.code)) return true;
  if (err.cause && _NETWORK_DISRUPTION_CODES.has(err.cause.code)) return true;
  return false;
}

function isHubUnreachableError(err) {
  if (!err) return false;
  if (err instanceof HubUnreachableError || err.code === 'HUB_UNREACHABLE') return true;
  if (_isNetworkDisruptionError(err)) return true;
  if (err.name === 'AbortError' || err.name === 'TimeoutError') return true;
  if (err.cause && (err.cause.name === 'AbortError' || err.cause.name === 'TimeoutError')) return true;
  return false;
}

function hubUnreachableBackoffMs(failureCount) {
  const n = Math.max(1, Number(failureCount) || 1);
  return Math.min(
    HUB_UNREACHABLE_BACKOFF_BASE_MS * Math.pow(2, n - 1),
    HUB_UNREACHABLE_BACKOFF_MAX_MS
  );
}

function hubResponseContentType(res) {
  const headers = res && res.headers;
  if (!headers) return '';
  let value = '';
  try {
    if (typeof headers.get === 'function') {
      value = headers.get('content-type') || headers.get('Content-Type') || '';
    } else if (typeof headers === 'object') {
      value = headers['content-type'] || headers['Content-Type'] || '';
    }
  } catch (_) {
    value = '';
  }
  return String(value || '').toLowerCase();
}

function isHubApiResponse(res) {
  const contentType = hubResponseContentType(res);
  if (!contentType) return true;
  return contentType.includes('json');
}

function isHubUnreachableResponse(res) {
  if (!res) return false;
  const status = Number(res.status || 0);
  const contentType = hubResponseContentType(res);
  if (!contentType) return false;
  if (isHubApiResponse(res)) return false;
  if (status >= 200 && status < 300) return true;
  return status === 401 || status === 403 || status === 408 || status === 429 || status >= 500;
}

async function drainHubResponse(res) {
  try {
    if (res && res.body && typeof res.body.cancel === 'function') {
      await res.body.cancel().catch(() => {});
    }
  } catch (_) {
    // Best-effort cleanup only; never turn body cleanup into a caller error.
  }
}

function _truncateUtf8(text, maxBytes) {
  const buf = Buffer.from(String(text || ''), 'utf8');
  if (buf.length <= maxBytes) return String(text || '');
  return buf.subarray(0, maxBytes).toString('utf8') + '\n...[truncated]';
}

function _truncateLogText(text, maxChars) {
  const s = String(text || '');
  if (s.length <= maxChars) return s;
  return s.slice(0, maxChars) + '\n...[truncated]';
}

function _sanitizeJsonForHubLog(value) {
  if (Array.isArray(value)) {
    return value.map(function (item) { return _sanitizeJsonForHubLog(item); });
  }
  if (!value || typeof value !== 'object') return value;

  const clean = {};
  for (const [key, child] of Object.entries(value)) {
    if (HUB_LOG_SENSITIVE_KEY_RE.test(key)) {
      clean[key] = HUB_LOG_REDACTED;
    } else {
      clean[key] = _sanitizeJsonForHubLog(child);
    }
  }
  return clean;
}

function sanitizeHubResponseForLog(text, options = {}) {
  let safeText = String(text || '');
  const n = Number(options.maxChars);
  const maxChars = Number.isFinite(n) && n >= 0 ? n : HUB_LOG_TEXT_MAX_CHARS;

  try {
    safeText = JSON.stringify(_sanitizeJsonForHubLog(JSON.parse(safeText)));
  } catch (_) {
    // Non-JSON hub responses still pass through redactString below.
  }

  safeText = redactString(safeText);
  return _truncateLogText(safeText, maxChars);
}

async function readHubResponseText(res, options = {}) {
  if (!res) return '';
  const maxBytes = Math.max(0, Number(options.maxBytes) || HUB_ERROR_TEXT_MAX_BYTES);

  if (res.body && typeof res.body.getReader === 'function') {
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    const chunks = [];
    let total = 0;
    let truncated = false;
    try {
      while (true) {
        const part = await reader.read();
        if (part.done) break;
        const value = part.value instanceof Uint8Array
          ? part.value
          : Buffer.from(part.value || '');
        const remaining = maxBytes - total;
        if (remaining > 0) {
          const slice = value.subarray(0, remaining);
          chunks.push(slice);
          total += slice.byteLength;
        }
        // Only truncate when a chunk genuinely OVERFLOWS the remaining
        // capacity. A chunk that fills the buffer exactly (byteLength ===
        // remaining, total === maxBytes) must NOT be flagged truncated: the
        // stream may end cleanly on the next read. Flagging it appended
        // `...[truncated]` to a complete body, which broke JSON.parse for a
        // response sitting exactly on the 4MB cap. When remaining hits 0, any
        // subsequent non-empty chunk (byteLength > 0 > remaining 0) trips this.
        if (value.byteLength > remaining) {
          truncated = true;
          try { await reader.cancel(); } catch (_) {}
          break;
        }
      }
    } catch (err) {
      try { await reader.cancel(); } catch (_) {}
      throw err;
    } finally {
      try { reader.releaseLock(); } catch (_) {}
    }
    const text = decoder.decode(Buffer.concat(chunks, total));
    return truncated ? text + '\n...[truncated]' : text;
  }

  if (typeof res.text === 'function') {
    try {
      return _truncateUtf8(await res.text(), maxBytes);
    } catch (err) {
      await drainHubResponse(res);
      throw err;
    }
  }

  await drainHubResponse(res);
  return '';
}

async function readHubResponseJson(res, options = {}) {
  const text = await readHubResponseText(res, {
    maxBytes: options.maxBytes || HUB_JSON_TEXT_MAX_BYTES,
  });
  return JSON.parse(text);
}

async function throwIfHubUnreachableResponse(res, context = 'hub') {
  if (!isHubUnreachableResponse(res)) return;
  const contentType = hubResponseContentType(res);
  let bodyText = '';
  try {
    bodyText = await readHubResponseText(res, { maxBytes: HUB_ERROR_TEXT_MAX_BYTES });
  } catch (err) {
    bodyText = `[body read failed: ${err && err.message || err}]`;
  }
  const bodySnippet = _truncateUtf8(String(bodyText || '').replace(/\s+/g, ' ').trim(), 512);
  const statusCode = Number(res.status || 0) || null;
  const label = contentType || 'unknown content-type';
  throw new HubUnreachableError(
    `${context} returned a non-API Hub response (${statusCode || 'unknown status'}, ${label})`,
    { statusCode, contentType, bodySnippet, context }
  );
}

function _validateHubUrl(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(
      '[hubFetch] Hub URL is not a valid URL: ' + JSON.stringify(url) + '. ' +
      'Set EVOMAP_HUB_ALLOW_INSECURE=1 to bypass (local dev / mock hub only).'
    );
  }
  if (parsed.protocol !== 'https:') {
    throw new Error(
      '[hubFetch] Hub URL must use https:// — got ' + JSON.stringify(url) + '. ' +
      'Set EVOMAP_HUB_ALLOW_INSECURE=1 to bypass (local dev / mock hub only).'
    );
  }
}

// Public scheme-only guard for callers that already manage their own HTTP
// transport (Node's `http`/`https` modules, the platform `fetch`, etc.) and
// just want to honour the same "https-only unless EVOMAP_HUB_ALLOW_INSECURE=1"
// posture hubFetch enforces. Throws synchronously on bad input — match
// _validateHubUrl's throw semantics so call sites can wrap in try/catch.
//
// Use this instead of bare URL/fetch when you cannot route through hubFetch
// (e.g. the existing src/atp/atpExecute.js and src/atp/hubClient.js paths
// that use http.request / native fetch directly).
function enforceHubScheme(url) {
  if (process.env.EVOMAP_HUB_ALLOW_INSECURE === '1') return;
  _validateHubUrl(url);
}

// async so synchronous validation throws become Promise rejections — every
// caller already awaits / .then()s the result, and this makes the function
// behave uniformly for `assert.rejects(...)` in tests.
async function hubFetch(url, options) {
  if (process.env.EVOMAP_HUB_ALLOW_INSECURE === '1') {
    // Insecure mode is documented as "local dev / mock hub on http:// or
    // self-signed cert". In that mode use the platform fetch — Node's
    // built-in global.fetch is identical engine to undici, but keeping it
    // as the platform lookup lets tests that stub `global.fetch = mockImpl`
    // intercept the call without forking through _setFetchImplForTest. If
    // a test has explicitly installed the seam, honor that — the explicit
    // override wins over the implicit global lookup.
    const insecureFetch = (_fetchImpl !== undiciFetch) ? _fetchImpl : global.fetch;
    return insecureFetch(url, options);
  }
  _validateHubUrl(url);
  // Object.assign last-wins is intentional: a caller-supplied dispatcher
  // would defeat the TLS guard, so we always force ours.  No current caller
  // passes one; revisit if that changes.
  const dispatcher = _pickDispatcher(url);
  try {
    return await _fetchImpl(url, Object.assign({}, options, { dispatcher }));
  } catch (err) {
    // On Linux a NetworkManager reconnect, VPN re-establishment, or WiFi
    // hand-off silently invalidates all existing TCP sockets in the undici
    // pool.  The kernel surfaces the break as a network-disruption error
    // code on the next read/write.  Without drainPool() the next request
    // reuses another dead socket from the same pool and suffers the same
    // error again.  Draining here lets the *next* call open a fresh
    // connection immediately without waiting for the heartbeat's normal
    // interval or the drift-detector's 2*interval poke window.
    //
    // We call drainPool() synchronously before re-throwing so the caller's
    // existing error path (heartbeat .catch, poll .catch, etc.) fires as
    // normal -- this is purely a pool-hygiene side-effect, not a retry.
    if (isHubUnreachableError(err)) {
      try {
        drainPool();
      } catch (_) { /* never block the throw on a pool-drain failure */ }
    }
    throw err;
  }
}

module.exports = {
  hubFetch,
  drainPool,
  HubUnreachableError,
  drainHubResponse,
  hubResponseContentType,
  hubUnreachableBackoffMs,
  isHubApiResponse,
  isHubUnreachableError,
  isHubUnreachableResponse,
  readHubResponseJson,
  readHubResponseText,
  sanitizeHubResponseForLog,
  throwIfHubUnreachableResponse,
  _isNetworkDisruptionError,
  _validateHubUrl,
  enforceHubScheme,
  // For callers that must build their own HTTP transport. The Node
  // native case (`https.request(...)`) needs an Agent pinned to
  // rejectUnauthorized:true so a global `NODE_TLS_REJECT_UNAUTHORIZED=0`
  // cannot weaken the Hub channel; pass `strictHttpsAgent` as
  // `options.agent`. Skip when `EVOMAP_HUB_ALLOW_INSECURE=1`, matching
  // hubFetch's own escape-hatch behaviour.
  //
  // For fetch-based callers do NOT pair a hand-rolled Agent with
  // `global.fetch`: `global.fetch` is backed by Node's *internal*
  // undici, and an Agent from the installed `undici` package crashes
  // it with `UND_ERR_INVALID_ARG: invalid onRequestStart method`
  // (see the warning at the top of this file). Route through
  // `hubFetch()` itself instead — it already applies the dispatcher
  // from the right undici copy.
  strictHttpsAgent: _strictHttpsAgent,
  _getHubFetchConfigForTest,
  _setFetchImplForTest,
};

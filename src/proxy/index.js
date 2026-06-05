'use strict';

const { getEvomapPath } = require('../gep/paths');
const { MailboxStore } = require('./mailbox/store');
const { ProxyHttpServer } = require('./server/http');
const { buildRoutes } = require('./server/routes');
const { buildMessagesHandler, canonicalizeForBedrock } = require('./router/messages_route');
const { SyncEngine } = require('./sync/engine');
const { LifecycleManager } = require('./lifecycle/manager');
const { TaskMonitor } = require('./task/monitor');
const { SkillUpdater } = require('./extensions/skillUpdater');
const { DmHandler } = require('./extensions/dmHandler');
const { SessionHandler } = require('./extensions/sessionHandler');

// Lazy via paths.getEvomapPath() — honors EVOLVER_HOME (#114).
function _defaultDataDir() { return getEvomapPath('mailbox'); }

// The hub serves asset signal-search as `GET /a2a/assets/search` with query
// params (signals, status, limit, fields, domain); `signals`/`fields` are
// comma-separated lists. The proxy's public contract stays `POST /asset/search`
// with a JSON body, so we translate that body into the hub's query string here.
// Historically assetSearch forwarded as `POST /a2a/assets/search`, which the
// current hub rejects with `route_not_found` (it only matches the GET form).
function buildAssetSearchQuery(body = {}) {
  const query = {};
  const csv = (v) => (Array.isArray(v) ? v.join(',') : v);
  if (body.signals != null) query.signals = csv(body.signals);
  if (body.fields != null) query.fields = csv(body.fields);
  if (body.status != null) query.status = body.status;
  if (body.domain != null) query.domain = body.domain;
  if (body.limit != null) query.limit = body.limit;
  return query;
}

class EvoMapProxy {
  constructor(opts = {}) {
    this.hubUrl = (opts.hubUrl || process.env.A2A_HUB_URL || '').replace(/\/+$/, '');
    this.dataDir = opts.dataDir || opts.dbPath || _defaultDataDir();
    this.port = opts.port;
    this.logger = opts.logger || console;
    this._skillPath = opts.skillPath || null;
    this._anthropicBaseUrl = (opts.anthropicBaseUrl || process.env.EVOMAP_ANTHROPIC_BASE_URL || 'https://api.anthropic.com').replace(/\/+$/, '');

    this.store = null;
    this.server = null;
    this.sync = null;
    this.lifecycle = null;
    this.taskMonitor = null;
    this.skillUpdater = null;
    this.dmHandler = null;
    this.sessionHandler = null;
    this._started = false;
  }

  async start() {
    if (this._started) throw new Error('Proxy already started');

    this.store = new MailboxStore(this.dataDir);

    this.lifecycle = new LifecycleManager({
      hubUrl: this.hubUrl,
      store: this.store,
      logger: this.logger,
      getTaskMeta: () => this.taskMonitor ? this.taskMonitor.getHeartbeatMeta() : {},
    });

    this.taskMonitor = new TaskMonitor({
      store: this.store,
      logger: this.logger,
    });

    this.skillUpdater = new SkillUpdater({
      store: this.store,
      skillPath: this._skillPath,
      logger: this.logger,
    });

    this.dmHandler = new DmHandler({
      store: this.store,
      logger: this.logger,
    });

    this.sessionHandler = new SessionHandler({
      store: this.store,
      logger: this.logger,
    });

    const getHeaders = () => this.lifecycle._buildHeaders();
    const taskMonitor = this.taskMonitor;

    this.sync = new SyncEngine({
      store: this.store,
      hubUrl: this.hubUrl,
      getHeaders,
      logger: this.logger,
      onAuthError: () => this.lifecycle.reAuthenticate(),
      onInboundReceived: () => {
        try { this.skillUpdater?.pollAndApply(); } catch (e) {
          this.logger?.warn?.('[proxy] skillUpdater.pollAndApply failed:', e.message);
        }
      },
    });

    const proxyHandlers = {
      assetFetch: (body) => this._proxyHttp('/a2a/fetch', body),
      // GET (not POST): hub route is `GET /a2a/assets/search?signals=...`.
      assetSearch: (body) => this._proxyHttp('/a2a/assets/search', null, {
        method: 'GET',
        query: buildAssetSearchQuery(body),
      }),
      assetValidate: (body) => this._proxyHttp('/a2a/validate', body),
      // ATP passthrough (#460 Bug 2): merchant/consumer flows that used to call
      // hub directly via src/atp/hubClient.js must route through the proxy when
      // EVOMAP_PROXY=1 so proxy sees the transaction (for audit + offline queue).
      atpPost: (endpoint, body) => this._proxyHttp(endpoint, body),
      atpGet: (endpoint, query) => this._proxyHttp(endpoint, null, { method: 'GET', query }),
    };

    const messagesHandler = buildMessagesHandler({
      // Provider dispatch: EVOMAP_UPSTREAM read per-request (matches the
      // hot-swap policy used for ANTHROPIC_API_KEY at line 266 below).
      // Default 'anthropic' keeps the existing path byte-for-byte; 'bedrock'
      // forwards via AWS Bedrock InvokeModel/InvokeModelWithResponseStream
      // and re-emits standard SSE so the client contract is unchanged.
      anthropicProxy: (reqPath, body, opts) => {
        // Mode is decided once per request in messages_route.js (the same
        // place the auth gate reads it), then passed in via opts.upstreamMode.
        // This makes the gate decision and the routing decision share one
        // env read, so a hot-swap of EVOMAP_UPSTREAM mid-request can't make
        // them disagree (e.g. gate skipped but request still hits Anthropic).
        const mode = opts?.upstreamMode || 'anthropic';
        return mode === 'bedrock'
          ? this._proxyBedrock(reqPath, body, opts)
          : this._proxyAnthropic(reqPath, body, opts);
      },
      logger: this.logger,
    });

    const routes = buildRoutes(this.store, proxyHandlers, this.taskMonitor, {
      dmHandler: this.dmHandler,
      skillUpdater: this.skillUpdater,
      sessionHandler: this.sessionHandler,
      getHubMailboxStatus: () => this._getHubMailboxStatus(),
      messagesHandler,
    });

    const OUTBOUND_ROUTES = [
      'POST /mailbox/send',
      'POST /asset/submit',
      'POST /task/claim',
      'POST /task/complete',
      'POST /task/subscribe',
      'POST /task/unsubscribe',
      'POST /dm/send',
      'POST /session/create',
      'POST /session/join',
      'POST /session/leave',
      'POST /session/message',
      'POST /session/delegate',
      'POST /session/submit',
    ];
    for (const key of OUTBOUND_ROUTES) {
      const original = routes[key];
      if (!original) continue;
      routes[key] = async (ctx) => {
        const result = await original(ctx);
        this.sync.notifyNewOutbound();
        return result;
      };
    }

    this.server = new ProxyHttpServer(routes, {
      port: this.port,
      logger: this.logger,
    });

    const serverInfo = await this.server.start();

    if (this.hubUrl) {
      await this.lifecycle.hello();
      this.lifecycle.startHeartbeatLoop();
      this.sync.start();
    } else {
      this.logger.warn('[proxy] No A2A_HUB_URL set, running in offline/local mode');
    }

    this._started = true;

    return {
      url: serverInfo.url,
      port: serverInfo.port,
      nodeId: this.lifecycle.nodeId,
    };
  }

  async stop() {
    if (!this._started) return;
    // Tear down in deliberate reverse-of-start order, but don't let one
    // failing step abort the rest: a thrown sync.stop() must not leave the
    // HTTP server and store leaked. Each step is isolated; failures are
    // warned and collected so shutdown always completes.
    const steps = [
      ['sync', () => this.sync?.stop()],
      ['heartbeat', () => this.lifecycle?.stopHeartbeatLoop()],
      ['server', () => this.server?.stop()],
      ['store', () => this.store?.close()],
    ];
    const errors = [];
    for (const [name, fn] of steps) {
      try {
        await fn();
      } catch (err) {
        errors.push(err);
        this.logger.warn('[proxy] error stopping ' + name + ': ' + (err && err.message ? err.message : err));
      }
    }
    this._started = false;
    if (errors.length) {
      this.logger.log('[proxy] stopped with ' + errors.length + ' teardown error(s)');
    } else {
      this.logger.log('[proxy] stopped');
    }
  }

  get mailbox() {
    return this.store;
  }

  async _proxyHttp(path, body, opts = {}) {
    if (!this.hubUrl) throw Object.assign(new Error('Hub not configured'), { statusCode: 503 });

    const method = (opts.method || 'POST').toUpperCase();
    const query = opts.query && typeof opts.query === 'object' ? opts.query : null;
    const timeoutMs = opts.timeoutMs || 30_000;

    let fullPath = path;
    if (query) {
      const qs = new URLSearchParams();
      for (const [k, v] of Object.entries(query)) {
        if (v !== undefined && v !== null) qs.set(k, String(v));
      }
      const qsString = qs.toString();
      if (qsString) fullPath += (path.includes('?') ? '&' : '?') + qsString;
    }

    const endpoint = `${this.hubUrl}${fullPath}`;
    const init = {
      method,
      headers: this.lifecycle._buildHeaders(),
      signal: AbortSignal.timeout(timeoutMs),
    };
    if (method !== 'GET' && method !== 'HEAD') {
      init.body = JSON.stringify(body || {});
    }

    const res = await fetch(endpoint, init);

    if (res.status === 403 || res.status === 401) {
      const recovered = await this.lifecycle.reAuthenticate();
      if (recovered) {
        const retryInit = {
          method,
          headers: this.lifecycle._buildHeaders(),
          signal: AbortSignal.timeout(timeoutMs),
        };
        if (method !== 'GET' && method !== 'HEAD') {
          retryInit.body = JSON.stringify(body || {});
        }
        const retry = await fetch(endpoint, retryInit);
        if (!retry.ok) {
          const text = await retry.text().catch(() => '');
          throw Object.assign(new Error(`Hub ${retry.status}: ${text}`), { statusCode: retry.status });
        }
        return retry.json();
      }
      const text = await res.text().catch(() => '');
      throw Object.assign(new Error(`Hub ${res.status} (re-auth failed): ${text}`), { statusCode: res.status });
    }

    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw Object.assign(new Error(`Hub ${res.status}: ${text}`), { statusCode: res.status });
    }

    return res.json();
  }

  // Phase C slice 4 + token mediation: relay to api.anthropic.com. The
  // route layer applies router rewrite and decides stream vs. JSON; this
  // method forwards the request and exposes the response shape.
  //
  // Allowed forward headers (lowercased): x-api-key, anthropic-version,
  // and anything matching anthropic-* (anthropic-beta, etc.). Everything
  // else (host, authorization, cookie, content-length, ...) is dropped
  // so the inbound proxy-auth header never leaks upstream.
  //
  // Token mediation: the proxy server's `Authorization: Bearer <token>`
  // header is consumed by ProxyHttpServer for self-auth and stripped
  // here, so clients (e.g. Claude Code) can authenticate to the proxy
  // with `ANTHROPIC_AUTH_TOKEN=<proxy_token>` without losing the ability
  // to reach Anthropic upstream. When the client did not pass x-api-key,
  // the proxy substitutes its own ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN
  // env var on the upstream request. Env is read per-request so creds
  // can be hot-swapped without restart, matching the EVOMAP_MODEL_*
  // policy in README.
  async _proxyAnthropic(reqPath, body, opts = {}) {
    const baseUrl = (opts.baseUrl || this._anthropicBaseUrl || '').replace(/\/+$/, '');
    const inbound = opts.inboundHeaders || {};
    const timeoutMs = opts.timeoutMs || 60_000;

    const fwd = { 'content-type': 'application/json' };
    for (const [k, v] of Object.entries(inbound)) {
      if (v === undefined || v === null) continue;
      const lk = k.toLowerCase();
      if (lk === 'x-api-key' || lk === 'anthropic-version' || lk.startsWith('anthropic-')) {
        fwd[lk] = Array.isArray(v) ? v.join(', ') : String(v);
      }
    }

    if (!fwd['x-api-key']) {
      if (process.env.ANTHROPIC_API_KEY) {
        fwd['x-api-key'] = process.env.ANTHROPIC_API_KEY;
      } else if (process.env.ANTHROPIC_AUTH_TOKEN) {
        fwd['authorization'] = `Bearer ${process.env.ANTHROPIC_AUTH_TOKEN}`;
      }
    }

    const endpoint = `${baseUrl}${reqPath}`;
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: fwd,
      body: JSON.stringify(body || {}),
      signal: AbortSignal.timeout(timeoutMs),
    });

    const headers = Object.fromEntries(res.headers.entries());
    const contentType = (headers['content-type'] || '').toLowerCase();
    const isStream = contentType.includes('text/event-stream');

    return {
      status: res.status,
      headers,
      stream: isStream ? res.body : null,
      json: isStream ? null : () => res.json(),
      text: () => res.text(),
    };
  }

  // Bedrock upstream mode: same return contract as _proxyAnthropic so
  // messages_route.js and ProxyHttpServer._streamResponse don't change.
  // Body transformation: model -> URL path; inject anthropic_version;
  // strip top-level model so Bedrock InvokeModel doesn't 400. SDK owns
  // SigV4 signing (creds via AWS_* env or opts.bedrockCredentials for
  // tests) and AWS event-stream binary decoding; we only re-emit each
  // chunk as standard SSE so clients remain Anthropic-compatible.
  async _proxyBedrock(reqPath, body, opts = {}) {
    if (!this._bedrockSdk) {
      this._bedrockSdk = require('@aws-sdk/client-bedrock-runtime');
    }
    const {
      BedrockRuntimeClient,
      InvokeModelCommand,
      InvokeModelWithResponseStreamCommand,
    } = this._bedrockSdk;

    // Defense-in-depth: when router is disabled (EVOMAP_ROUTER_ENABLED!=1)
    // the router handler skips the body-rewrite step, so a short inbound ID
    // would otherwise reach Bedrock InvokeModel and trigger ValidationException.
    // Re-canonicalize here; idempotent for already-canonical IDs from the
    // router-enabled path.
    const rawModel = body && typeof body.model === 'string' ? body.model : null;
    const modelId = rawModel ? canonicalizeForBedrock(rawModel) : null;
    if (!modelId) {
      const errBody = JSON.stringify({
        type: 'error',
        error: { type: 'invalid_request_error', message: 'body.model required for Bedrock upstream' },
      });
      return {
        status: 400,
        headers: { 'content-type': 'application/json' },
        stream: null,
        json: () => JSON.parse(errBody),
        text: () => errBody,
      };
    }

    const upstreamBody = { ...body };
    delete upstreamBody.model;
    if (!upstreamBody.anthropic_version) {
      upstreamBody.anthropic_version = 'bedrock-2023-05-31';
    }
    const wantsStream = upstreamBody.stream === true;
    // Bedrock infers stream-vs-not from the command, not the body field.
    delete upstreamBody.stream;

    // Claude Code v2.1.150+ sends `thinking: { type: 'adaptive' }` plus
    // `output_config.effort` for Opus 4.7+. Keep that shape for 4.7 models:
    // folding it to `enabled` makes the current 4.7 endpoint reject compaction
    // with: "thinking.type.enabled is not supported for this model".
    //
    // Older Bedrock-deployed 4.5/4.1 generation models only accept
    // 'enabled' | 'disabled'. Fold 'adaptive' for those older models:
    //
    // Two hard constraints collide:
    //   - Anthropic: budget_tokens >= 1024 when thinking is enabled
    //   - Bedrock:   budget_tokens <  max_tokens (strictly)
    //
    // For max_tokens <= 1024 there's no valid budget at all (1024 floor
    // would fail Bedrock's strict-less-than check), so we have to drop
    // thinking entirely on those calls — fold to 'disabled'. For larger
    // max_tokens we default to max_tokens/2 (the model picks budget in
    // adaptive mode, but Bedrock 'enabled' requires the field).
    const modelSupportsAdaptiveThinking = /claude-(opus|sonnet|haiku)-4-7\b/.test(modelId);
    if (
      !modelSupportsAdaptiveThinking
      && upstreamBody.thinking
      && upstreamBody.thinking.type === 'adaptive'
    ) {
      const maxTokens = typeof upstreamBody.max_tokens === 'number' ? upstreamBody.max_tokens : 8192;
      const haveBudget = typeof upstreamBody.thinking.budget_tokens === 'number';
      if (!haveBudget && maxTokens <= 1024) {
        upstreamBody.thinking = { type: 'disabled' };
      } else {
        upstreamBody.thinking = {
          ...upstreamBody.thinking,
          type: 'enabled',
          budget_tokens: haveBudget ? upstreamBody.thinking.budget_tokens : Math.max(1024, Math.floor(maxTokens / 2)),
        };
      }
    }

    // Claude Code v2.1.150+ adds top-level fields. Keep output_config for
    // 4.7 adaptive thinking, where it controls effort; older Bedrock schemas
    // reject it as an extra input.
    //
    //   - output_config: { effort }      (when effortLevel is set)
    //   - context_management: { ... }    (auto context window management)
    // Bedrock's strict schema means any unknown top-level field 400s the
    // whole call, so strip the known CC additions before forwarding. New CC
    // fields will surface as 400s and need to be added here.
    for (const k of ['context_management']) {
      if (k in upstreamBody) delete upstreamBody[k];
    }
    if (!modelSupportsAdaptiveThinking && 'output_config' in upstreamBody) {
      delete upstreamBody.output_config;
    }

    // Cache the BedrockRuntimeClient across requests so its connection
    // pool, DNS cache, and credential-chain resolution amortize. Reusing
    // a single client matches what _proxyAnthropic does with the global
    // fetch + Agent. Cache key includes the SDK module identity so test
    // SDK injection (proxy._bedrockSdk = mock) invalidates correctly.
    const clientArgs = {
      region: opts.bedrockRegion || process.env.AWS_REGION || 'us-east-1',
      ...(opts.bedrockEndpoint || process.env.EVOMAP_BEDROCK_ENDPOINT
        ? { endpoint: opts.bedrockEndpoint || process.env.EVOMAP_BEDROCK_ENDPOINT }
        : {}),
      ...(opts.bedrockCredentials ? { credentials: opts.bedrockCredentials } : {}),
    };
    const cacheKey = JSON.stringify(clientArgs);
    if (
      !this._bedrockClient
      || this._bedrockClientKey !== cacheKey
      || this._bedrockClientSdk !== this._bedrockSdk
    ) {
      this._bedrockClient = new BedrockRuntimeClient(clientArgs);
      this._bedrockClientKey = cacheKey;
      this._bedrockClientSdk = this._bedrockSdk;
    }
    const client = this._bedrockClient;

    // Match _proxyAnthropic's per-request timeout boundary so a hung
    // upstream can't pin a Bedrock connection forever. AWS SDK v3
    // commands accept abortSignal in the second arg.
    const timeoutMs = opts.timeoutMs || 60_000;
    const abortController = new AbortController();
    const abortTimer = setTimeout(() => abortController.abort(), timeoutMs);

    try {
      if (wantsStream) {
        const out = await client.send(new InvokeModelWithResponseStreamCommand({
          modelId,
          contentType: 'application/json',
          accept: 'application/json',
          body: JSON.stringify(upstreamBody),
        }), { abortSignal: abortController.signal });
        // The timeout that bounds the initial send must not apply to the
        // streaming body — chunks arrive over many seconds. Clear it now;
        // the readable-stream's cancel() handler is what closes the
        // upstream when the client disconnects mid-stream.
        clearTimeout(abortTimer);
        const stream = new ReadableStream({
          async start(controller) {
            const enc = new TextEncoder();
            try {
              for await (const event of out.body) {
                if (event.chunk?.bytes) {
                  const json = Buffer.from(event.chunk.bytes).toString('utf8');
                  controller.enqueue(enc.encode(`data: ${json}\n\n`));
                  continue;
                }
                // Bedrock InvokeModelWithResponseStream may emit any of these
                // exception envelopes mid-stream; missing one silently drops
                // it and closes the stream without an error frame, so the
                // client sees a truncated-but-clean response.
                const ex = event.internalServerException
                  || event.modelStreamErrorException
                  || event.throttlingException
                  || event.validationException
                  || event.modelTimeoutException
                  || event.serviceUnavailableException;
                if (ex) {
                  const errFrame = JSON.stringify({
                    type: 'error',
                    error: { type: ex.name || 'upstream_error', message: ex.message || String(ex) },
                  });
                  controller.enqueue(enc.encode(`event: error\ndata: ${errFrame}\n\n`));
                }
              }
              controller.close();
            } catch (err) {
              controller.error(err);
            }
          },
          // ProxyHttpServer._streamResponse calls reader.cancel() when the
          // downstream HTTP client disconnects. Without this, the AWS
          // event-stream AsyncIterable keeps pulling frames into a
          // discarded ReadableStream, leaking the underlying HTTP/2
          // stream + socket out of the SDK's pool.
          cancel() {
            try {
              if (typeof out.body?.return === 'function') {
                out.body.return();
              }
            } catch { /* AsyncIterable already closed */ }
          },
        });
        return {
          status: 200,
          headers: { 'content-type': 'text/event-stream' },
          stream,
          json: null,
          text: null,
        };
      }

      const out = await client.send(new InvokeModelCommand({
        modelId,
        contentType: 'application/json',
        accept: 'application/json',
        body: JSON.stringify(upstreamBody),
      }), { abortSignal: abortController.signal });
      clearTimeout(abortTimer);
      const text = Buffer.from(out.body).toString('utf8');
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        stream: null,
        json: () => JSON.parse(text),
        text: () => text,
      };
    } catch (err) {
      clearTimeout(abortTimer);
      const status = err.$metadata?.httpStatusCode || 500;
      const errBody = JSON.stringify({
        type: 'error',
        error: { type: err.name || 'upstream_error', message: err.message || String(err) },
      });
      return {
        status,
        headers: { 'content-type': 'application/json' },
        stream: null,
        json: () => JSON.parse(errBody),
        text: () => errBody,
      };
    }
  }

  async _getHubMailboxStatus() {
    if (!this.hubUrl) return { error: 'Hub not configured' };
    const nodeId = this.lifecycle.nodeId;
    if (!nodeId) return { error: 'No node_id yet' };
    const endpoint = `${this.hubUrl}/a2a/mailbox/status?node_id=${encodeURIComponent(nodeId)}`;
    try {
      const res = await fetch(endpoint, {
        method: 'GET',
        headers: this.lifecycle._buildHeaders(),
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) {
        // Drain body so undici can recycle the socket back to the pool.
        // Without this, repeated non-ok responses leak pool slots and
        // eventually starve the dispatcher.
        try { res.body?.cancel?.().catch(() => {}); } catch {}
        return { error: `Hub ${res.status}` };
      }
      return res.json();
    } catch (err) {
      return { error: err.message };
    }
  }
}

async function startProxy(opts = {}) {
  const proxy = new EvoMapProxy(opts);
  const info = await proxy.start();
  return { proxy, ...info };
}

module.exports = { EvoMapProxy, startProxy };

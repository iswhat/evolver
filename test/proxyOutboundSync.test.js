'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { MailboxStore } = require('../src/proxy/mailbox/store');
const { OutboundSync } = require('../src/proxy/sync/outbound');
const hubFetchMod = require('../src/gep/hubFetch');

function tmpDataDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'proxy-outbound-sync-'));
}

function readMessagesJsonl(dataDir) {
  return fs.readFileSync(path.join(dataDir, 'messages.jsonl'), 'utf8');
}

function jsonResponse(body, status = 200) {
  return {
    status,
    ok: status >= 200 && status < 300,
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}

function encryptedTrace(ciphertext) {
  return {
    encrypted: true,
    algorithm: 'aes-256-gcm',
    payload_schema: 'prism_trace_row',
    iv: 'aXYxMjM0NTY3ODkw',
    tag: 'dGFnMTIzNDU2Nzg5MA==',
    ciphertext,
  };
}

describe('proxy trace outbound sync', () => {
  let savedOutboundMaxBytes;

  beforeEach(() => {
    savedOutboundMaxBytes = process.env.EVOMAP_OUTBOUND_SYNC_MAX_BODY_BYTES;
    delete process.env.EVOMAP_OUTBOUND_SYNC_MAX_BODY_BYTES;
  });

  afterEach(() => {
    hubFetchMod._setFetchImplForTest(null);
    if (savedOutboundMaxBytes === undefined) delete process.env.EVOMAP_OUTBOUND_SYNC_MAX_BODY_BYTES;
    else process.env.EVOMAP_OUTBOUND_SYNC_MAX_BODY_BYTES = savedOutboundMaxBytes;
  });

  it('uploads pending proxy_trace messages to the Hub mailbox endpoint', async () => {
    const dataDir = tmpDataDir();
    const store = new MailboxStore(dataDir);
    const requests = [];
    store.setState('node_id', 'node_test_trace_upload');
    const created = store.send({
      type: 'proxy_trace',
      priority: 'low',
      payload: {
        schema: 'prism_trace_row.v1',
        encrypted: true,
        trace: encryptedTrace('Y2lwaGVydGV4dC1mb3ItdGVzdA=='),
      },
    });

    hubFetchMod._setFetchImplForTest(async (url, opts) => {
      requests.push({
        url,
        method: opts.method,
        headers: opts.headers,
        body: JSON.parse(opts.body),
      });
      return jsonResponse({
        results: [{ id: created.message_id, status: 'accepted' }],
      });
    });

    try {
      const sync = new OutboundSync({
        store,
        hubUrl: 'https://hub.example.test',
        getHeaders: () => ({ Authorization: 'Bearer test' }),
        logger: { error: () => {}, warn: () => {}, log: () => {} },
      });

      const result = await sync.flush();

      assert.equal(result.sent, 1);
      assert.equal(result.synced, 1);
      assert.equal(requests.length, 1);
      const outboundUrl = new URL(requests[0].url);
      assert.equal(outboundUrl.origin + outboundUrl.pathname, 'https://hub.example.test/a2a/mailbox/outbound');
      assert.equal(outboundUrl.searchParams.get('sender_id'), 'node_test_trace_upload');
      assert.equal(requests[0].method, 'POST');
      assert.equal(requests[0].body.sender_id, 'node_test_trace_upload');
      assert.equal(requests[0].body.messages.length, 1);
      assert.equal(requests[0].body.messages[0].id, created.message_id);
      assert.equal(requests[0].body.messages[0].type, 'proxy_trace');
      assert.equal(requests[0].body.messages[0].priority, 'low');
      assert.equal(requests[0].body.messages[0].payload.schema, 'prism_trace_row.v1');
      assert.equal(requests[0].body.messages[0].payload.encrypted, true);
      assert.equal(requests[0].body.messages[0].payload.trace.encrypted, true);
      assert.equal(store.getById(created.message_id).status, 'synced');
      assert.equal(store.countPending({ direction: 'outbound' }), 0);
      assert.match(store.getState('last_sync_at'), /^\d{4}-\d{2}-\d{2}T/);
    } finally {
      store.close();
      try { fs.rmSync(dataDir, { recursive: true }); } catch {}
    }
  });

  it('drops pending proxy_trace messages when trace upload is disabled before flush', async () => {
    const dataDir = tmpDataDir();
    const store = new MailboxStore(dataDir);
    const requests = [];
    store.setState('node_id', 'node_test_trace_disabled');
    store.setState('trace_collection_enabled', false);
    const trace = store.send({
      type: 'proxy_trace',
      priority: 'low',
      payload: {
        schema: 'prism_trace_row.v1',
        encrypted: true,
        trace: encryptedTrace('ZHJvcC1tZQ=='),
      },
    });
    const asset = store.send({
      type: 'asset_submit',
      priority: 'normal',
      payload: { type: 'Gene', summary: 'still send non-trace' },
    });

    hubFetchMod._setFetchImplForTest(async (url, opts) => {
      requests.push({
        url,
        body: JSON.parse(opts.body),
      });
      return jsonResponse({
        results: [{ id: asset.message_id, status: 'accepted' }],
      });
    });

    try {
      const sync = new OutboundSync({
        store,
        hubUrl: 'https://hub.example.test',
        getHeaders: () => ({ Authorization: 'Bearer test' }),
        logger: { error: () => {}, warn: () => {}, log: () => {} },
      });

      const result = await sync.flush();

      assert.equal(result.sent, 1);
      assert.equal(result.synced, 1);
      assert.equal(result.dropped, 1);
      assert.equal(requests.length, 1);
      assert.equal(requests[0].body.messages.length, 1);
      assert.equal(requests[0].body.messages[0].id, asset.message_id);
      assert.equal(requests[0].body.messages[0].type, 'asset_submit');
      assert.equal(store.getById(trace.message_id).status, 'rejected');
      assert.equal(store.getById(trace.message_id).error, 'proxy trace upload disabled');
      assert.equal(store.getById(asset.message_id).status, 'synced');
    } finally {
      store.close();
      try { fs.rmSync(dataDir, { recursive: true }); } catch {}
    }
  });

  it('rejects unsafe pending proxy_trace payloads before outbound upload', async () => {
    const dataDir = tmpDataDir();
    const store = new MailboxStore(dataDir);
    store.setState('node_id', 'node_test_trace_payload_reject');
    const trace = store.send({
      type: 'proxy_trace',
      priority: 'low',
      payload: {
        schema: 'prism_trace_row.v1',
        encrypted: true,
        trace: {
          ...encryptedTrace('ZmFrZS1lbmNyeXB0ZWQ='),
          requestBody: 'plaintext should not leave pending mailbox',
        },
      },
    });

    hubFetchMod._setFetchImplForTest(async () => {
      throw new Error('unsafe proxy_trace should not be sent');
    });

    try {
      const sync = new OutboundSync({
        store,
        hubUrl: 'https://hub.example.test',
        getHeaders: () => ({ Authorization: 'Bearer test' }),
        logger: { error: () => {}, warn: () => {}, log: () => {} },
      });

      const result = await sync.flush();

      assert.equal(result.sent, 0);
      assert.equal(result.dropped, 1);
      assert.equal(store.getById(trace.message_id).status, 'rejected');
      assert.equal(store.getById(trace.message_id).error, 'proxy trace payload rejected');
    } finally {
      store.close();
      try { fs.rmSync(dataDir, { recursive: true }); } catch {}
    }
  });

  it('rejects secret_version-only encrypted proxy_trace payloads before outbound upload by default', async () => {
    const dataDir = tmpDataDir();
    const store = new MailboxStore(dataDir);
    store.setState('node_id', 'node_test_trace_secret_version_reject');
    const trace = store.send({
      type: 'proxy_trace',
      priority: 'low',
      payload: {
        schema: 'prism_trace_row.v1',
        encrypted: true,
        node_secret_version: 7,
        trace: {
          ...encryptedTrace('ZmFrZS1lbmNyeXB0ZWQ='),
          secret_version: 7,
        },
      },
    });

    hubFetchMod._setFetchImplForTest(async () => {
      throw new Error('secret_version-only proxy_trace should not be sent');
    });

    try {
      const sync = new OutboundSync({
        store,
        hubUrl: 'https://hub.example.test',
        getHeaders: () => ({ Authorization: 'Bearer test' }),
        logger: { error: () => {}, warn: () => {}, log: () => {} },
      });

      const result = await sync.flush();

      assert.equal(result.sent, 0);
      assert.equal(result.dropped, 1);
      assert.equal(store.getById(trace.message_id).status, 'rejected');
      assert.equal(store.getById(trace.message_id).error, 'proxy trace payload rejected');
    } finally {
      store.close();
      try { fs.rmSync(dataDir, { recursive: true }); } catch {}
    }
  });

  it('rejects encrypted proxy_trace payloads with plaintext outside the envelope', async () => {
    const dataDir = tmpDataDir();
    const store = new MailboxStore(dataDir);
    store.setState('node_id', 'node_test_trace_wrapper_reject');
    const topLevel = store.send({
      type: 'proxy_trace',
      priority: 'low',
      payload: {
        schema: 'prism_trace_row.v1',
        encrypted: true,
        trace: encryptedTrace('dG9wLWxldmVs'),
        requestBody: 'top-level plaintext should not leave pending mailbox',
      },
    });
    const nested = store.send({
      type: 'proxy_trace',
      priority: 'low',
      payload: {
        schema: 'prism_trace_row.v1',
        encrypted: true,
        trace: {
          ...encryptedTrace('bmVzdGVk'),
          hub_key_envelope: {
            requestBody: 'nested plaintext should not leave pending mailbox',
          },
        },
      },
    });

    hubFetchMod._setFetchImplForTest(async () => {
      throw new Error('unsafe proxy_trace should not be sent');
    });

    try {
      const sync = new OutboundSync({
        store,
        hubUrl: 'https://hub.example.test',
        getHeaders: () => ({ Authorization: 'Bearer test' }),
        logger: { error: () => {}, warn: () => {}, log: () => {} },
      });

      const result = await sync.flush();

      assert.equal(result.sent, 0);
      assert.equal(result.dropped, 2);
      assert.equal(store.getById(topLevel.message_id).status, 'rejected');
      assert.equal(store.getById(nested.message_id).status, 'rejected');
      assert.equal(store.getById(topLevel.message_id).error, 'proxy trace payload rejected');
      assert.equal(store.getById(nested.message_id).error, 'proxy trace payload rejected');
    } finally {
      store.close();
      try { fs.rmSync(dataDir, { recursive: true }); } catch {}
    }
  });

  it('splits outbound flush batches by serialized request body size before calling Hub', async () => {
    const dataDir = tmpDataDir();
    const store = new MailboxStore(dataDir);
    const requests = [];
    store.setState('node_id', 'node_test_body_budget');
    process.env.EVOMAP_OUTBOUND_SYNC_MAX_BODY_BYTES = '900';
    const first = store.send({
      type: 'asset_submit',
      priority: 'normal',
      payload: { summary: 'a'.repeat(200) },
    });
    const second = store.send({
      type: 'asset_submit',
      priority: 'normal',
      payload: { summary: 'b'.repeat(200) },
    });
    store.send({
      type: 'asset_submit',
      priority: 'normal',
      payload: { summary: 'c'.repeat(200) },
    });

    hubFetchMod._setFetchImplForTest(async (url, opts) => {
      const body = JSON.parse(opts.body);
      requests.push(body);
      return jsonResponse({
        results: body.messages.map((m) => ({ id: m.id, status: 'accepted' })),
      });
    });

    try {
      const sync = new OutboundSync({
        store,
        hubUrl: 'https://hub.example.test',
        getHeaders: () => ({ Authorization: 'Bearer test' }),
        logger: { error: () => {}, warn: () => {}, log: () => {} },
      });

      const result = await sync.flush();

      assert.equal(result.sent, 2);
      assert.equal(result.synced, 2);
      assert.equal(requests.length, 1);
      assert.deepEqual(requests[0].messages.map((m) => m.id), [first.message_id, second.message_id]);
      assert.equal(store.countPending({ direction: 'outbound' }), 1);
    } finally {
      store.close();
      try { fs.rmSync(dataDir, { recursive: true }); } catch {}
    }
  });

  it('rejects a single outbound message that cannot fit under the body budget', async () => {
    const dataDir = tmpDataDir();
    const store = new MailboxStore(dataDir);
    store.setState('node_id', 'node_test_single_too_large');
    process.env.EVOMAP_OUTBOUND_SYNC_MAX_BODY_BYTES = '512';
    const created = store.send({
      type: 'asset_submit',
      priority: 'normal',
      payload: { summary: 'x'.repeat(2000) },
    });

    hubFetchMod._setFetchImplForTest(async () => {
      throw new Error('oversized single message should not be sent');
    });

    try {
      const sync = new OutboundSync({
        store,
        hubUrl: 'https://hub.example.test',
        getHeaders: () => ({ Authorization: 'Bearer test' }),
        logger: { error: () => {}, warn: () => {}, log: () => {} },
      });

      const result = await sync.flush();

      assert.equal(result.sent, 0);
      assert.equal(result.dropped, 1);
      assert.equal(store.getById(created.message_id).status, 'rejected');
      assert.match(store.getById(created.message_id).error, /exceeds max body bytes/);
    } finally {
      store.close();
      try { fs.rmSync(dataDir, { recursive: true }); } catch {}
    }
  });

  it('quarantines a single message when Hub still returns 413', async () => {
    const dataDir = tmpDataDir();
    const store = new MailboxStore(dataDir);
    const fakeToken = 'fake-token-413-abcdefghijklmnopqrstuvwxyz';
    store.setState('node_id', 'node_test_hub_413_single');
    const created = store.send({
      type: 'asset_submit',
      priority: 'normal',
      payload: { summary: 'hub says too large' },
    });

    hubFetchMod._setFetchImplForTest(async () => jsonResponse({
      error: 'entity too large',
      token: fakeToken,
      authorization: `Bearer ${fakeToken}`,
    }, 413));

    try {
      const sync = new OutboundSync({
        store,
        hubUrl: 'https://hub.example.test',
        getHeaders: () => ({ Authorization: 'Bearer test' }),
        logger: { error: () => {}, warn: () => {}, log: () => {} },
      });

      const result = await sync.flush();

      assert.equal(result.payloadTooLarge, true);
      assert.equal(result.error, 'hub_payload_too_large');
      assert.equal(result.dropped, 1);
      assert.equal(store.getById(created.message_id).status, 'rejected');
      assert.match(store.getById(created.message_id).error, /Hub 413 outbound payload too large/);
      assert.doesNotMatch(store.getById(created.message_id).error, new RegExp(fakeToken));
      assert.doesNotMatch(readMessagesJsonl(dataDir), new RegExp(fakeToken));
      assert.doesNotMatch(result.error, new RegExp(fakeToken));
      assert.equal(store.countPending({ direction: 'outbound' }), 0);
    } finally {
      store.close();
      try { fs.rmSync(dataDir, { recursive: true }); } catch {}
    }
  });

  it('sanitizes Hub non-2xx response text before retry persistence and logs', async () => {
    const dataDir = tmpDataDir();
    const store = new MailboxStore(dataDir);
    const errors = [];
    const fakeToken = 'fake-token-retry-abcdefghijklmnopqrstuvwxyz';
    store.setState('node_id', 'node_test_hub_retry_sanitize');
    const created = store.send({
      type: 'asset_submit',
      priority: 'normal',
      payload: { summary: 'retry without leaking hub response body token' },
    });

    hubFetchMod._setFetchImplForTest(async () => jsonResponse({
      error: 'temporary hub failure',
      token: fakeToken,
      authorization: `Bearer ${fakeToken}`,
    }, 500));

    try {
      const sync = new OutboundSync({
        store,
        hubUrl: 'https://hub.example.test',
        getHeaders: () => ({ Authorization: 'Bearer test' }),
        logger: { error: (msg) => errors.push(String(msg)), warn: () => {}, log: () => {} },
      });

      const result = await sync.flush();
      const persisted = store.getById(created.message_id);
      const messagesJsonl = readMessagesJsonl(dataDir);
      const loggerOutput = errors.join('\n');

      assert.equal(result.sent, 0);
      assert.equal(persisted.status, 'pending');
      assert.equal(persisted.retry_count, 1);
      assert.match(persisted.error, /Hub returned 500/);
      assert.match(loggerOutput, /Hub returned 500/);
      assert.doesNotMatch(persisted.error, new RegExp(fakeToken));
      assert.doesNotMatch(messagesJsonl, new RegExp(fakeToken));
      assert.doesNotMatch(loggerOutput, new RegExp(fakeToken));
      assert.doesNotMatch(result.error, new RegExp(fakeToken));
    } finally {
      store.close();
      try { fs.rmSync(dataDir, { recursive: true }); } catch {}
    }
  });

  it('defers retryable per-message Hub failures without burning retry count', async () => {
    const dataDir = tmpDataDir();
    const store = new MailboxStore(dataDir);
    const requests = [];
    store.setState('node_id', 'node_test_retryable_result');
    const created = store.send({
      type: 'proxy_trace',
      priority: 'low',
      payload: {
        schema: 'prism_trace_row.v1',
        encrypted: true,
        trace: encryptedTrace('cmV0cnlhYmxl'),
      },
    });

    hubFetchMod._setFetchImplForTest(async (url, opts) => {
      requests.push({ url, body: JSON.parse(opts.body) });
      return jsonResponse({
        results: [{
          id: created.message_id,
          status: 'failed',
          reason: 'hub overloaded',
          retryable: true,
          retry_after_ms: 30_000,
          terminal: false,
        }],
      });
    });

    try {
      const sync = new OutboundSync({
        store,
        hubUrl: 'https://hub.example.test',
        getHeaders: () => ({ Authorization: 'Bearer test' }),
        logger: { error: () => {}, warn: () => {}, log: () => {} },
      });

      const first = await sync.flush();
      const deferred = store.getById(created.message_id);
      const second = await sync.flush();

      assert.equal(first.sent, 1);
      assert.equal(first.deferred, 1);
      assert.equal(deferred.status, 'pending');
      assert.equal(deferred.retry_count, 0);
      assert.match(deferred.error, /hub overloaded/);
      assert.ok(deferred.next_retry_at > Date.now());
      assert.equal(second.sent, 0);
      assert.equal(requests.length, 1, 'deferred message should not be resent before next_retry_at');
    } finally {
      store.close();
      try { fs.rmSync(dataDir, { recursive: true }); } catch {}
    }
  });

  it('treats terminal per-message Hub failures as final', async () => {
    const dataDir = tmpDataDir();
    const store = new MailboxStore(dataDir);
    store.setState('node_id', 'node_test_terminal_result');
    const created = store.send({
      type: 'proxy_trace',
      priority: 'low',
      payload: {
        schema: 'prism_trace_row.v1',
        encrypted: true,
        trace: encryptedTrace('dGVybWluYWw='),
      },
    });

    hubFetchMod._setFetchImplForTest(async () => jsonResponse({
      results: [{
        id: created.message_id,
        status: 'failed',
        reason: 'invalid_proxy_trace_payload_schema',
        terminal: true,
      }],
    }));

    try {
      const sync = new OutboundSync({
        store,
        hubUrl: 'https://hub.example.test',
        getHeaders: () => ({ Authorization: 'Bearer test' }),
        logger: { error: () => {}, warn: () => {}, log: () => {} },
      });

      const result = await sync.flush();
      const terminal = store.getById(created.message_id);

      assert.equal(result.sent, 1);
      assert.equal(result.synced, 1);
      assert.equal(terminal.status, 'failed');
      assert.equal(terminal.retry_count, 0);
      assert.match(terminal.error, /invalid_proxy_trace_payload_schema/);
      assert.equal(store.countPending({ direction: 'outbound' }), 0);
    } finally {
      store.close();
      try { fs.rmSync(dataDir, { recursive: true }); } catch {}
    }
  });

  // Bugbot PR #301 (High): a terminal:true hint must win even when the same
  // result also carries retryAfterMs / retryable:true. Before the fix the
  // defer branch fired first on the retry hint and parked a final message for
  // retry, so it stayed pending and was resent.
  it('treats terminal as final even when the result also carries retry hints', async () => {
    const dataDir = tmpDataDir();
    const store = new MailboxStore(dataDir);
    const requests = [];
    store.setState('node_id', 'node_test_terminal_with_retry_hint');
    const created = store.send({
      type: 'proxy_trace',
      priority: 'low',
      payload: {
        schema: 'prism_trace_row.v1',
        encrypted: true,
        trace: encryptedTrace('dGVybWluYWwtcmV0cnk='),
      },
    });

    hubFetchMod._setFetchImplForTest(async (url, opts) => {
      requests.push({ url, body: JSON.parse(opts.body) });
      return jsonResponse({
        results: [{
          id: created.message_id,
          status: 'failed',
          reason: 'invalid_proxy_trace_payload_schema',
          // Contradictory but possible: terminal plus retry hints. Terminal wins.
          terminal: true,
          retryable: true,
          retry_after_ms: 30_000,
        }],
      });
    });

    try {
      const sync = new OutboundSync({
        store,
        hubUrl: 'https://hub.example.test',
        getHeaders: () => ({ Authorization: 'Bearer test' }),
        logger: { error: () => {}, warn: () => {}, log: () => {} },
      });

      const first = await sync.flush();
      const row = store.getById(created.message_id);
      const second = await sync.flush();

      assert.equal(first.synced, 1, 'terminal result must be finalized, not deferred');
      assert.notEqual(first.deferred, 1, 'terminal result must NOT count as deferred');
      assert.equal(row.status, 'failed', 'terminal message must end as failed');
      assert.equal(row.retry_count, 0);
      assert.ok(!row.next_retry_at, 'terminal message must not be parked for retry');
      assert.equal(store.countPending({ direction: 'outbound' }), 0);
      assert.equal(second.sent, 0, 'nothing left to resend');
      assert.equal(requests.length, 1, 'terminal message must never be resent');
    } finally {
      store.close();
      try { fs.rmSync(dataDir, { recursive: true }); } catch {}
    }
  });

  // Bugbot PR #301 (Low): a terminal rejection with no error/reason must keep
  // a meaningful label ('rejected by hub'), not the retry-exhaustion 'max
  // retries' fallback (it never retried).
  it('labels a terminal rejection without error/reason as rejected by hub, not max retries', async () => {
    const dataDir = tmpDataDir();
    const store = new MailboxStore(dataDir);
    store.setState('node_id', 'node_test_terminal_no_reason');
    const created = store.send({
      type: 'proxy_trace',
      priority: 'low',
      payload: {
        schema: 'prism_trace_row.v1',
        encrypted: true,
        trace: encryptedTrace('dGVybWluYWwtbm8tcmVhc29u'),
      },
    });

    hubFetchMod._setFetchImplForTest(async () => jsonResponse({
      results: [{ id: created.message_id, status: 'failed', terminal: true }],
    }));

    try {
      const sync = new OutboundSync({
        store,
        hubUrl: 'https://hub.example.test',
        getHeaders: () => ({ Authorization: 'Bearer test' }),
        logger: { error: () => {}, warn: () => {}, log: () => {} },
      });

      await sync.flush();
      const row = store.getById(created.message_id);
      assert.equal(row.status, 'failed');
      assert.match(row.error, /rejected by hub/);
      assert.doesNotMatch(row.error, /max retries/, 'terminal rejection must not be labeled retry-exhausted');
    } finally {
      store.close();
      try { fs.rmSync(dataDir, { recursive: true }); } catch {}
    }
  });

  it('backs down the outbound batch budget when Hub returns 413 for multiple messages', async () => {
    const dataDir = tmpDataDir();
    const store = new MailboxStore(dataDir);
    let calls = 0;
    store.setState('node_id', 'node_test_hub_413_batch');
    store.send({ type: 'asset_submit', payload: { summary: 'a'.repeat(1000) } });
    store.send({ type: 'asset_submit', payload: { summary: 'b'.repeat(1000) } });

    hubFetchMod._setFetchImplForTest(async () => {
      calls++;
      return jsonResponse({ error: 'entity too large' }, 413);
    });

    try {
      const sync = new OutboundSync({
        store,
        hubUrl: 'https://hub.example.test',
        getHeaders: () => ({ Authorization: 'Bearer test' }),
        logger: { error: () => {}, warn: () => {}, log: () => {} },
      });

      const result = await sync.flush();

      assert.equal(result.payloadTooLarge, true);
      assert.equal(result.error, 'hub_payload_too_large');
      assert.equal(calls, 1);
      assert.equal(store.countPending({ direction: 'outbound' }), 2);
      assert.ok(Number(store.getState('outbound_sync_max_body_bytes')) > 0);
    } finally {
      store.close();
      try { fs.rmSync(dataDir, { recursive: true }); } catch {}
    }
  });

});

'use strict';

// In bedrock upstream mode, canonicalize the inbound model ID at the
// proxy boundary so the rest of the pipeline (router decision, no-downgrade
// guard, outbound rewrite, retry body) operates on the same Bedrock-OK
// form. Two consequences fall out for free, both validated below:
//   - alias-only normalizations collapse chosenModel === originalModel,
//     so a transient 5xx skips the wasteful retry that would re-issue the
//     same model anyway
//   - cross-family retries carry the canonical original (not the inbound
//     short ID) so Bedrock accepts them
//
// Triggered by 2026-05-25/26 telemetry: 75 upstream_5xx_retry events,
// 37 of which retried with a short ID Bedrock rejects, turning a transient
// upstream blip into a 100% client-visible ValidationException 400.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { request } = require('undici');

const {
  buildMessagesHandler,
  canonicalizeForBedrock,
  DEFAULT_TIER_MODELS,
  KNOWN_BEDROCK_ALIASES,
  supportsAdaptiveThinking,
} = require('../src/proxy/router/messages_route');

function makeStubProxy(handler) {
  const calls = [];
  const fn = async (reqPath, body, opts) => {
    calls.push({ reqPath, body: JSON.parse(JSON.stringify(body || {})), opts });
    return handler ? handler(calls.length, body) : {
      status: 200,
      headers: { 'content-type': 'application/json' },
      stream: null,
      json: async () => ({ id: 'msg', model: body && body.model, content: [] }),
      text: async () => '',
    };
  };
  return { fn, calls };
}

function makeLogger() {
  const lines = [];
  return {
    log: (s) => lines.push({ stream: 'log', s }),
    warn: (s) => lines.push({ stream: 'warn', s }),
    error: () => {},
    lines,
  };
}

describe('canonicalizeForBedrock', () => {
  it('maps known short IDs to ARN-shaped Bedrock aliases', () => {
    assert.equal(canonicalizeForBedrock('claude-opus-4-7'),
      'global.anthropic.claude-opus-4-7');
    assert.equal(canonicalizeForBedrock('claude-haiku-4-5'),
      'global.anthropic.claude-haiku-4-5-20251001-v1:0');
    assert.equal(canonicalizeForBedrock('claude-sonnet-4-6'),
      'global.anthropic.claude-sonnet-4-6');
  });

  it('passes long IDs through unchanged when they match a known alias', () => {
    for (const v of Object.values(KNOWN_BEDROCK_ALIASES)) {
      assert.equal(canonicalizeForBedrock(v), v);
    }
  });

  it('keeps shipped default tier models on Bedrock-resolvable aliases', () => {
    assert.deepEqual(Object.values(DEFAULT_TIER_MODELS), [
      'global.anthropic.claude-opus-4-7',
      'global.anthropic.claude-opus-4-7',
      'global.anthropic.claude-opus-4-7',
    ]);
    for (const model of Object.values(DEFAULT_TIER_MODELS)) {
      assert.ok(Object.values(KNOWN_BEDROCK_ALIASES).includes(model),
        'default tier model must be a known Bedrock alias: ' + model);
    }
  });

  it('passes through unknown / non-Claude IDs untouched', () => {
    assert.equal(canonicalizeForBedrock('gpt-4'), 'gpt-4');
    assert.equal(canonicalizeForBedrock('mistral-large-2'), 'mistral-large-2');
    // Claude family with unmapped minor: pass-through (Bedrock owns rejection)
    assert.equal(canonicalizeForBedrock('claude-opus-9-9'), 'claude-opus-9-9');
    assert.equal(canonicalizeForBedrock(null), null);
    assert.equal(canonicalizeForBedrock(undefined), undefined);
  });

  it('canonicalizes us.* dated Bedrock IDs to the global.* equivalent', () => {
    // parseClaudeId extracts {opus, 4, 7} from us.anthropic.claude-opus-4-7-...
    // and we map back to the global alias if known. The previous setup left
    // us.* IDs alone and any client sending them got pinned to that profile.
    assert.equal(
      canonicalizeForBedrock('us.anthropic.claude-haiku-4-5-20251001-v1:0'),
      'global.anthropic.claude-haiku-4-5-20251001-v1:0',
    );
  });

  // Tripwire: when Anthropic ships sonnet-4-7 on Bedrock InvokeModel, this
  // test fails until the operator adds the entry to KNOWN_BEDROCK_ALIASES.
  // The probe fetches the AWS Bedrock "Supported foundation models" doc —
  // which AWS maintains in lockstep with InvokeModel availability — and
  // checks for the canonical alias. A real Bedrock InvokeModel probe would
  // require AWS credentials + an enabled model + region, which is out of
  // scope for a unit test; the docs page is the lightweight ground-truth
  // source we tie the assertion to.
  //
  // Two failure modes this test guards against:
  //   1. Operator adds a fake alias (typo or guessed ID) before Bedrock
  //      actually accepts it — the probe would say "not shipped", the
  //      assertion expects passthrough, the canonicalizer's returned
  //      fake ID trips the test.
  //   2. Operator adds the right alias in the wrong format (dated suffix
  //      when bare is canonical, or `us.*` when `global.*` is) — the
  //      probe asserts the exact string, so a wrong format fails.
  //
  // On failure the message tells the operator exactly what to do: verify
  // the alias on the AWS doc page, then add it to KNOWN_BEDROCK_ALIASES
  // in the same format the probe found.
  // AWS_BEDROCK_PROBE=0 opts the tripwire out of the live network probe
  // (useful for fast local iteration or CI environments without outbound
  // access to docs.aws.amazon.com). When disabled, the test assumes
  // sonnet-4-7 has NOT shipped and asserts passthrough — same behavior
  // as the network-unavailable fall-through path.
  it("canonicalizeForBedrock('claude-sonnet-4-7') trips when AWS Bedrock docs list the alias (ground-truth for InvokeModel availability)", async (t) => {
    const PROBE_DISABLED = process.env.AWS_BEDROCK_PROBE === '0';
    const SONNET_4_7_BEDROCK_ID = 'global.anthropic.claude-sonnet-4-7';
    const AWS_BEDROCK_DOCS_URL =
      'https://docs.aws.amazon.com/bedrock/latest/userguide/models-supported.html';

    let aliasShipped = false;
    let probeNote = '';
    if (PROBE_DISABLED) {
      probeNote = 'AWS_BEDROCK_PROBE=0: probe skipped; assuming not shipped';
    } else try {
      const { statusCode, body } = await request(AWS_BEDROCK_DOCS_URL, {
        headersTimeout: 5000,
        bodyTimeout: 5000,
      });
      if (statusCode === 200) {
        const html = await body.text();
        aliasShipped = html.includes(SONNET_4_7_BEDROCK_ID);
        probeNote = `AWS doc probe (${AWS_BEDROCK_DOCS_URL}): ` +
          `${aliasShipped ? 'FOUND' : 'NOT FOUND'} \`${SONNET_4_7_BEDROCK_ID}\``;
      } else {
        probeNote = `AWS doc probe returned HTTP ${statusCode}; assuming not shipped`;
      }
    } catch (err) {
      probeNote = `AWS doc probe unavailable (${err && err.message}); assuming not shipped`;
    }
    t.diagnostic(probeNote);

    const actual = canonicalizeForBedrock('claude-sonnet-4-7');

    if (aliasShipped) {
      assert.equal(
        actual,
        SONNET_4_7_BEDROCK_ID,
        `Anthropic has shipped \`${SONNET_4_7_BEDROCK_ID}\` on Bedrock InvokeModel ` +
          `(verified at ${AWS_BEDROCK_DOCS_URL}), but canonicalizeForBedrock ` +
          `does not return it. Add 'sonnet/4/7': '${SONNET_4_7_BEDROCK_ID}' to ` +
          `KNOWN_BEDROCK_ALIASES in src/proxy/router/messages_route.js (verify ` +
          `bare-vs-dated format from the AWS doc before pasting).`,
      );
    } else {
      assert.equal(
        actual,
        'claude-sonnet-4-7',
        `Anthropic has NOT shipped sonnet-4-7 on Bedrock InvokeModel yet ` +
          `(verified at ${AWS_BEDROCK_DOCS_URL}). canonicalizeForBedrock ` +
          `must passthrough. When the probe shows it shipped, update ` +
          `KNOWN_BEDROCK_ALIASES.`,
      );
    }
  });
});

describe('supportsAdaptiveThinking', () => {
  it('treats Claude 4.7+ as adaptive-thinking capable', () => {
    assert.equal(supportsAdaptiveThinking('global.anthropic.claude-opus-4-7'), true);
    assert.equal(supportsAdaptiveThinking('global.anthropic.claude-opus-4-8'), true);
    assert.equal(supportsAdaptiveThinking('global.anthropic.claude-sonnet-4-10'), true);
    assert.equal(supportsAdaptiveThinking('global.anthropic.claude-opus-5-1'), true);
  });

  it('keeps older or opaque models on legacy Bedrock thinking conversion', () => {
    assert.equal(supportsAdaptiveThinking('global.anthropic.claude-haiku-4-5-20251001-v1:0'), false);
    assert.equal(supportsAdaptiveThinking('global.anthropic.claude-opus-4-1-20250805-v1:0'), false);
    assert.equal(supportsAdaptiveThinking('mistral-large-2'), false);
    assert.equal(supportsAdaptiveThinking(null), false);
  });
});

describe('buildMessagesHandler — bedrock canonicalization', () => {
  it('canonicalizes inbound short ID before forwarding to Bedrock upstream', async () => {
    const prevUpstream = process.env.EVOMAP_UPSTREAM;
    const prevCheap = process.env.EVOMAP_MODEL_CHEAP;
    const prevExpensive = process.env.EVOMAP_MODEL_EXPENSIVE;
    process.env.EVOMAP_UPSTREAM = 'bedrock';
    process.env.EVOMAP_MODEL_CHEAP = 'global.anthropic.claude-opus-4-7';
    process.env.EVOMAP_MODEL_EXPENSIVE = 'global.anthropic.claude-opus-4-7';
    try {
      const { fn, calls } = makeStubProxy();
      const logger = makeLogger();
      const handler = buildMessagesHandler({
        anthropicProxy: fn, logger, routerEnabled: true,
      });
      await handler({
        body: {
          model: 'claude-opus-4-7',
          messages: [{ role: 'user', content: 'what is npm?' }],
        },
        headers: {},
      });
      assert.equal(calls.length, 1);
      assert.equal(calls[0].body.model, 'global.anthropic.claude-opus-4-7',
        'outbound body must carry canonical Bedrock alias, not the inbound short ID');

      const decision = JSON.parse(logger.lines.find((l) => l.stream === 'log').s);
      assert.equal(decision.original_model, 'global.anthropic.claude-opus-4-7',
        'log records canonical original_model in bedrock mode');
      assert.equal(decision.chosen_model, 'global.anthropic.claude-opus-4-7');
    } finally {
      if (prevUpstream === undefined) delete process.env.EVOMAP_UPSTREAM;
      else process.env.EVOMAP_UPSTREAM = prevUpstream;
      if (prevCheap === undefined) delete process.env.EVOMAP_MODEL_CHEAP;
      else process.env.EVOMAP_MODEL_CHEAP = prevCheap;
      if (prevExpensive === undefined) delete process.env.EVOMAP_MODEL_EXPENSIVE;
      else process.env.EVOMAP_MODEL_EXPENSIVE = prevExpensive;
    }
  });

  it('leaves inbound short ID unchanged in anthropic upstream mode', async () => {
    // No EVOMAP_UPSTREAM set -> default 'anthropic' -> short IDs passthrough.
    const { fn, calls } = makeStubProxy();
    const handler = buildMessagesHandler({
      anthropicProxy: fn, logger: makeLogger(), routerEnabled: false,
    });
    await handler({
      body: { model: 'claude-opus-4-7', messages: [] },
      headers: { 'x-api-key': 'sk-test' },
    });
    assert.equal(calls[0].body.model, 'claude-opus-4-7',
      'anthropic-mode must not canonicalize — api.anthropic.com accepts short IDs');
  });

  it('does NOT trigger 5xx retry when first call hits 500 but chosen ≡ original (alias-only)', async () => {
    // Daemon config: all tiers -> opus-4-7. Client sends short claude-opus-4-7.
    // After canonicalization, originalModel === chosenModel === long opus.
    // First Bedrock call returns transient 500; retry would re-send the same
    // model (already canonical) so the old retry path was wasteful AND would
    // re-issue with originalModel that, before C, was still the short ID.
    // Now retry condition is false because chosenModel === originalModel.
    const prevUpstream = process.env.EVOMAP_UPSTREAM;
    const prevCheap = process.env.EVOMAP_MODEL_CHEAP;
    const prevExpensive = process.env.EVOMAP_MODEL_EXPENSIVE;
    process.env.EVOMAP_UPSTREAM = 'bedrock';
    process.env.EVOMAP_MODEL_CHEAP = 'global.anthropic.claude-opus-4-7';
    process.env.EVOMAP_MODEL_EXPENSIVE = 'global.anthropic.claude-opus-4-7';
    try {
      const { fn, calls } = makeStubProxy(() => ({
        status: 500,
        headers: { 'content-type': 'application/json' },
        stream: null,
        json: async () => ({ error: 'transient' }),
        text: async () => '{"error":"transient"}',
      }));
      const logger = makeLogger();
      const handler = buildMessagesHandler({
        anthropicProxy: fn, logger, routerEnabled: true,
      });
      await handler({
        body: { model: 'claude-opus-4-7', messages: [{ role: 'user', content: 'plan it' }] },
        headers: {},
      });
      assert.equal(calls.length, 1, 'must NOT retry — chosen and original collapse to the same canonical ID');
      const retryFallbacks = logger.lines
        .filter((l) => l.stream === 'warn')
        .map((l) => JSON.parse(l.s))
        .filter((e) => e.reason === 'upstream_5xx_retry');
      assert.equal(retryFallbacks.length, 0, 'no upstream_5xx_retry log for alias-only normalization');
    } finally {
      if (prevUpstream === undefined) delete process.env.EVOMAP_UPSTREAM;
      else process.env.EVOMAP_UPSTREAM = prevUpstream;
      if (prevCheap === undefined) delete process.env.EVOMAP_MODEL_CHEAP;
      else process.env.EVOMAP_MODEL_CHEAP = prevCheap;
      if (prevExpensive === undefined) delete process.env.EVOMAP_MODEL_EXPENSIVE;
      else process.env.EVOMAP_MODEL_EXPENSIVE = prevExpensive;
    }
  });

  it('retries with the canonical Bedrock-OK ID when cross-family 5xx triggers fallback', async () => {
    // Inbound short claude-opus-4-7 -> tier=cheap -> haiku (different family).
    // First call (haiku) gets 500; retry must use the CANONICAL opus long ID,
    // never the inbound short ID — Bedrock rejects short IDs with 400.
    const prevUpstream = process.env.EVOMAP_UPSTREAM;
    const prevCheap = process.env.EVOMAP_MODEL_CHEAP;
    const prevExpensive = process.env.EVOMAP_MODEL_EXPENSIVE;
    process.env.EVOMAP_UPSTREAM = 'bedrock';
    process.env.EVOMAP_MODEL_CHEAP = 'global.anthropic.claude-haiku-4-5-20251001-v1:0';
    process.env.EVOMAP_MODEL_EXPENSIVE = 'global.anthropic.claude-opus-4-7';
    try {
      const { fn, calls } = makeStubProxy((nthCall) => {
        if (nthCall === 1) {
          return {
            status: 500,
            headers: { 'content-type': 'application/json' },
            stream: null,
            json: async () => ({ error: 'overloaded' }),
            text: async () => '{"error":"overloaded"}',
          };
        }
        // retry succeeds
        return {
          status: 200,
          headers: { 'content-type': 'application/json' },
          stream: null,
          json: async () => ({ id: 'msg_retry', model: 'opus' }),
          text: async () => '',
        };
      });
      const logger = makeLogger();
      const handler = buildMessagesHandler({
        anthropicProxy: fn, logger, routerEnabled: true,
      });
      await handler({
        body: { model: 'claude-opus-4-7', messages: [{ role: 'user', content: 'what is npm?' }] },
        headers: {},
      });
      assert.equal(calls.length, 2);
      assert.equal(calls[0].body.model, 'global.anthropic.claude-haiku-4-5-20251001-v1:0',
        'first call uses cheap tier (cross-family rewrite)');
      assert.equal(calls[1].body.model, 'global.anthropic.claude-opus-4-7',
        'retry uses CANONICAL opus, never the inbound short ID — Bedrock would 400 the short form');
    } finally {
      if (prevUpstream === undefined) delete process.env.EVOMAP_UPSTREAM;
      else process.env.EVOMAP_UPSTREAM = prevUpstream;
      if (prevCheap === undefined) delete process.env.EVOMAP_MODEL_CHEAP;
      else process.env.EVOMAP_MODEL_CHEAP = prevCheap;
      if (prevExpensive === undefined) delete process.env.EVOMAP_MODEL_EXPENSIVE;
      else process.env.EVOMAP_MODEL_EXPENSIVE = prevExpensive;
    }
  });
});

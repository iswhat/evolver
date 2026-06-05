'use strict';

// P4-a Slice A — evolver reuse-attribution report (default off, shadow-only).
// Verifies: the flag parsing, the attribution block built from the dispatch
// run-state, the money/identity-safety invariants (no client source_node_id,
// absent when generated, absent when off), and the local-only reuse rollup.

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ENV = ['EVOLUTION_DIR', 'MEMORY_DIR', 'EVOLVER_REPO_ROOT', 'EVOLVER_REUSE_ATTRIBUTION', 'MEMORY_GRAPH_SYNC_HUB', 'A2A_HUB_URL'];

function fresh(p) { const r = require.resolve(p); delete require.cache[r]; return require(r); }
function reloadAll() {
  // config + paths are read by memoryGraph; reload so env changes take effect.
  for (const m of ['../src/config', '../src/gep/paths', '../src/gep/assetCallLog', '../src/gep/assetStore', '../src/gep/memoryGraph']) {
    try { delete require.cache[require.resolve(m)]; } catch (_) {}
  }
}

describe('P4-a Slice A — reuse attribution', () => {
  let tmp, saved;
  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'reuse-attr-test-'));
    saved = {};
    for (const k of ENV) { saved[k] = process.env[k]; delete process.env[k]; }
    process.env.EVOLUTION_DIR = tmp;
    reloadAll();
  });
  afterEach(() => {
    for (const k of ENV) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
    fs.rmSync(tmp, { recursive: true, force: true });
    reloadAll();
  });

  // Pipeline order: recordAttempt (last_action) -> dispatch (last_run) ->
  // recordOutcome. So a CURRENT-cycle last_run.created_at is >= last_action's.
  const ACT_AT = '2026-06-03T10:00:00.000Z';
  const RUN_AT_FRESH = '2026-06-03T10:00:05.000Z'; // after the attempt (same cycle)
  const RUN_AT_STALE = '2026-06-03T09:59:00.000Z'; // before the attempt (prior cycle)

  // write evolution_solidify_state.json the way dispatch.js does (state.last_run.*)
  // Defaults created_at to a fresh (same-cycle) timestamp unless the caller sets one.
  function writeRunState(lastRun) {
    const lr = Object.assign({ created_at: RUN_AT_FRESH }, lastRun);
    fs.writeFileSync(path.join(tmp, 'evolution_solidify_state.json'), JSON.stringify({ last_run: lr }));
  }
  // write memory_graph_state.json so recordOutcomeFromState has a last_action
  function writeLastAction() {
    fs.writeFileSync(path.join(tmp, 'memory_graph_state.json'), JSON.stringify({
      last_action: { action_id: 'act_test', signal_key: 'k', signals: ['log_error'], had_error: true, outcome_recorded: false, created_at: ACT_AT },
    }));
  }

  describe('config flag', () => {
    it('defaults to off; only shadow is accepted', () => {
      const cfg = fresh('../src/config');
      assert.equal(cfg.reuseAttributionMode(), 'off');
      process.env.EVOLVER_REUSE_ATTRIBUTION = 'SHADOW';
      assert.equal(cfg.reuseAttributionMode(), 'shadow');
      process.env.EVOLVER_REUSE_ATTRIBUTION = 'enforce'; // no client enforce -> off
      assert.equal(cfg.reuseAttributionMode(), 'off');
      process.env.EVOLVER_REUSE_ATTRIBUTION = 'garbage';
      assert.equal(cfg.reuseAttributionMode(), 'off');
    });
  });

  describe('outcome event gets reuse_attribution only in shadow + on real reuse', () => {
    it('off mode: no reuse_attribution even when a reuse happened', () => {
      // default off
      writeRunState({ source_type: 'reused', reused_asset_id: 'sha256:abc', reused_chain_id: 'chain1', reused_source_node: 'node_pub' });
      writeLastAction();
      const mg = fresh('../src/gep/memoryGraph');
      const ev = mg.recordOutcomeFromState({ signals: [], observations: null });
      assert.ok(ev, 'outcome event produced');
      assert.equal(ev.reuse_attribution, undefined, 'no attribution when off');
    });

    it('shadow + reused: attaches block with runtime asset_id, NO client source_node_id', () => {
      process.env.EVOLVER_REUSE_ATTRIBUTION = 'shadow';
      writeRunState({ source_type: 'reused', reused_asset_id: 'sha256:abc', reused_chain_id: 'chain1', reused_source_node: 'node_pub_DO_NOT_TRUST' });
      writeLastAction();
      const mg = fresh('../src/gep/memoryGraph');
      const ev = mg.recordOutcomeFromState({ signals: [], observations: null });
      assert.ok(ev.reuse_attribution, 'attribution attached in shadow');
      assert.equal(ev.reuse_attribution.reused_asset_id, 'sha256:abc');
      assert.equal(ev.reuse_attribution.reused_chain_id, 'chain1');
      assert.equal(ev.reuse_attribution.source_type, 'reused');
      assert.equal(ev.reuse_attribution.schema, 'reuse_attr/1.0');
      // CRITICAL anti-sybil: never carry the client's claim of who to pay
      assert.ok(!('source_node_id' in ev.reuse_attribution), 'must NOT carry client source_node_id');
      assert.ok(!JSON.stringify(ev.reuse_attribution).includes('node_pub_DO_NOT_TRUST'), 'reuser must not name the payee');
    });

    it('shadow + generated (nothing reused): no block', () => {
      process.env.EVOLVER_REUSE_ATTRIBUTION = 'shadow';
      writeRunState({ source_type: 'generated', reused_asset_id: null });
      writeLastAction();
      const mg = fresh('../src/gep/memoryGraph');
      const ev = mg.recordOutcomeFromState({ signals: [], observations: null });
      assert.equal(ev.reuse_attribution, undefined, 'generated => no attribution');
    });

    it('shadow + reference: attaches block', () => {
      process.env.EVOLVER_REUSE_ATTRIBUTION = 'shadow';
      writeRunState({ source_type: 'reference', reused_asset_id: 'sha256:ref1', reused_chain_id: null });
      writeLastAction();
      const mg = fresh('../src/gep/memoryGraph');
      const ev = mg.recordOutcomeFromState({ signals: [], observations: null });
      assert.ok(ev.reuse_attribution);
      assert.equal(ev.reuse_attribution.source_type, 'reference');
      assert.equal(ev.reuse_attribution.reused_chain_id, null);
    });

    it('shadow + STALE last_run (prior cycle, created_at < last_action): no block (Bugbot #186)', () => {
      // dispatch never ran this cycle -> last_run is from an earlier cycle and
      // must NOT mislink another cycle's reuse to this outcome.
      process.env.EVOLVER_REUSE_ATTRIBUTION = 'shadow';
      writeRunState({ source_type: 'reused', reused_asset_id: 'sha256:STALE', created_at: RUN_AT_STALE });
      writeLastAction();
      const mg = fresh('../src/gep/memoryGraph');
      const ev = mg.recordOutcomeFromState({ signals: [], observations: null });
      assert.equal(ev.reuse_attribution, undefined, 'stale last_run must not attach');
      assert.ok(!JSON.stringify(ev).includes('STALE'), 'no stale asset id leaks into the outcome');
    });

    it('shadow + last_run with no created_at: no block (cannot correlate cycle)', () => {
      process.env.EVOLVER_REUSE_ATTRIBUTION = 'shadow';
      // bypass the helper default to simulate a legacy state w/o created_at
      fs.writeFileSync(path.join(tmp, 'evolution_solidify_state.json'),
        JSON.stringify({ last_run: { source_type: 'reused', reused_asset_id: 'sha256:nocreat' } }));
      writeLastAction();
      const mg = fresh('../src/gep/memoryGraph');
      const ev = mg.recordOutcomeFromState({ signals: [], observations: null });
      assert.equal(ev.reuse_attribution, undefined, 'uncorrelatable last_run must not attach');
    });

    it('shadow but no run-state file: no block, no crash', () => {
      process.env.EVOLVER_REUSE_ATTRIBUTION = 'shadow';
      writeLastAction(); // no evolution_solidify_state.json
      const mg = fresh('../src/gep/memoryGraph');
      const ev = mg.recordOutcomeFromState({ signals: [], observations: null });
      assert.ok(ev, 'still produces the outcome event');
      assert.equal(ev.reuse_attribution, undefined);
    });
  });

  describe('reuseAttributionSummary (local-only rollup)', () => {
    it('aggregates reuse/reference per asset from the local log', () => {
      const acl = fresh('../src/gep/assetCallLog');
      acl.logAssetCall({ run_id: 'r1', action: 'asset_reuse', asset_id: 'A', source_node_id: 'nodeA', chain_id: 'c1' });
      acl.logAssetCall({ run_id: 'r2', action: 'asset_reuse', asset_id: 'A' });
      acl.logAssetCall({ run_id: 'r3', action: 'asset_reference', asset_id: 'B', source_node_id: 'nodeB' });
      acl.logAssetCall({ run_id: 'r4', action: 'hub_search_hit', asset_id: 'C' }); // ignored
      const s = acl.reuseAttributionSummary();
      assert.equal(s.total_reuse, 2);
      assert.equal(s.total_reference, 1);
      const a = s.by_asset.find(x => x.asset_id === 'A');
      assert.equal(a.reuse, 2); assert.equal(a.reference, 0); assert.equal(a.source_node_id, 'nodeA');
      const b = s.by_asset.find(x => x.asset_id === 'B');
      assert.equal(b.reference, 1);
      assert.ok(!s.by_asset.find(x => x.asset_id === 'C'), 'non-reuse actions excluded');
      // sorted by total desc -> A first
      assert.equal(s.by_asset[0].asset_id, 'A');
    });
    it('empty log -> zeroes, no throw', () => {
      const acl = fresh('../src/gep/assetCallLog');
      const s = acl.reuseAttributionSummary();
      assert.equal(s.total_reuse, 0); assert.equal(s.total_reference, 0); assert.deepEqual(s.by_asset, []);
    });
  });
});

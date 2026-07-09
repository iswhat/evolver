'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { MailboxStore } = require('../src/proxy/mailbox/store');
const { SkillUpdater } = require('../src/proxy/extensions/skillUpdater');
const { DmHandler } = require('../src/proxy/extensions/dmHandler');
const {
  SessionHandler,
  normalizeCreatePayload,
  normalizeMessagePayload,
  normalizeDelegatePayload,
  normalizeSubmitPayload,
} = require('../src/proxy/extensions/sessionHandler');

function tmpDataDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'extensions-test-'));
}

describe('SkillUpdater', () => {
  let store, dataDir, skillDir;

  before(() => {
    dataDir = tmpDataDir();
    skillDir = tmpDataDir();
    store = new MailboxStore(dataDir);
  });

  after(() => {
    store.close();
    try { fs.rmSync(dataDir, { recursive: true }); } catch {}
    try { fs.rmSync(skillDir, { recursive: true }); } catch {}
  });

  it('updates skill.md from inbound message', () => {
    const skillPath = path.join(skillDir, 'SKILL.md');
    const updater = new SkillUpdater({
      store,
      skillPath,
      logger: { log: () => {}, warn: () => {}, error: () => {} },
    });

    const result = updater.processSkillUpdate({
      payload: { content: '# Updated Skill\nNew content here.', version: '1.1.0' },
    });
    assert.equal(result, true);
    assert.equal(fs.readFileSync(skillPath, 'utf8'), '# Updated Skill\nNew content here.');
    assert.equal(store.getState('skill_version'), '1.1.0');
  });

  it('creates backup before overwriting', () => {
    const skillPath = path.join(skillDir, 'SKILL2.md');
    fs.writeFileSync(skillPath, 'original content', 'utf8');

    const updater = new SkillUpdater({
      store,
      skillPath,
      logger: { log: () => {}, warn: () => {}, error: () => {} },
    });

    updater.processSkillUpdate({
      payload: { content: 'updated content', version: '2.0' },
    });
    assert.equal(fs.readFileSync(skillPath, 'utf8'), 'updated content');
    assert.equal(fs.readFileSync(skillPath + '.bak', 'utf8'), 'original content');
  });

  it('returns false without skill path', () => {
    const updater = new SkillUpdater({
      store,
      logger: { log: () => {}, warn: () => {}, error: () => {} },
    });
    assert.equal(updater.processSkillUpdate({ payload: { content: 'x' } }), false);
  });

  it('returns false without content', () => {
    const updater = new SkillUpdater({
      store,
      skillPath: path.join(skillDir, 'noop.md'),
      logger: { log: () => {}, warn: () => {}, error: () => {} },
    });
    assert.equal(updater.processSkillUpdate({ payload: {} }), false);
  });

  it('pollAndApply processes pending skill_update messages', () => {
    const dir2 = tmpDataDir();
    const s2 = new MailboxStore(dir2);
    const sp = path.join(skillDir, 'polled.md');

    s2.writeInbound({
      type: 'skill_update',
      payload: { content: '# Polled skill', version: '3.0' },
    });

    const updater = new SkillUpdater({
      store: s2,
      skillPath: sp,
      logger: { log: () => {}, warn: () => {}, error: () => {} },
    });

    const applied = updater.pollAndApply();
    assert.equal(applied, 1);
    assert.equal(fs.readFileSync(sp, 'utf8'), '# Polled skill');
    s2.close();
    try { fs.rmSync(dir2, { recursive: true }); } catch {}
  });
});

describe('DmHandler', () => {
  let store, handler, dataDir;

  before(() => {
    dataDir = tmpDataDir();
    store = new MailboxStore(dataDir);
    handler = new DmHandler({ store });
  });

  after(() => {
    store.close();
    try { fs.rmSync(dataDir, { recursive: true }); } catch {}
  });

  it('sends a DM and creates outbound message', () => {
    const result = handler.send({
      recipientNodeId: 'node_abc',
      content: 'Hello there',
    });
    assert.ok(result.message_id);
    assert.equal(result.status, 'pending');

    const msg = store.getById(result.message_id);
    assert.equal(msg.type, 'dm');
    assert.equal(msg.direction, 'outbound');
    assert.equal(msg.payload.recipient_node_id, 'node_abc');
    assert.equal(msg.payload.content, 'Hello there');
  });

  it('throws on missing recipientNodeId', () => {
    assert.throws(() => handler.send({ content: 'x' }), /recipientNodeId/);
  });

  it('throws on missing content', () => {
    assert.throws(() => handler.send({ recipientNodeId: 'n' }), /content/);
  });

  it('polls inbound DMs', () => {
    store.writeInbound({ type: 'dm', payload: { content: 'incoming dm' } });
    const msgs = handler.poll();
    assert.ok(msgs.length >= 1);
    assert.equal(msgs[0].type, 'dm');
  });

  it('acks DM messages', () => {
    const id = store.writeInbound({ type: 'dm', payload: { content: 'to ack' } });
    const count = handler.ack(id);
    assert.equal(count, 1);
    const msg = store.getById(id);
    assert.equal(msg.status, 'delivered');
  });

  it('lists DM history', () => {
    const msgs = handler.list();
    assert.ok(Array.isArray(msgs));
  });
});

describe('SessionHandler', () => {
  let store, handler, dataDir;

  before(() => {
    dataDir = tmpDataDir();
    store = new MailboxStore(dataDir);
    handler = new SessionHandler({ store });
  });

  after(() => {
    store.close();
    try { fs.rmSync(dataDir, { recursive: true }); } catch {}
  });

  it('creates a session and stores outbound message', () => {
    const result = handler.createSession({
      title: 'Test Session',
      description: 'A test collaboration session',
      inviteNodeIds: ['node_a', 'node_b'],
    });
    assert.ok(result.message_id);
    assert.equal(result.status, 'pending');

    const msg = store.getById(result.message_id);
    assert.equal(msg.type, 'session_create');
    assert.equal(msg.direction, 'outbound');
    assert.equal(msg.payload.title, 'Test Session');
    assert.deepEqual(msg.payload.invite_node_ids, ['node_a', 'node_b']);
  });

  it('throws on missing title', () => {
    assert.throws(() => handler.createSession({}), /title/);
  });

  it('joins a session', () => {
    const result = handler.joinSession({ sessionId: 'sess_123' });
    assert.ok(result.message_id);
    const msg = store.getById(result.message_id);
    assert.equal(msg.type, 'session_join');
    assert.equal(msg.payload.session_id, 'sess_123');
  });

  it('throws on join without sessionId', () => {
    assert.throws(() => handler.joinSession({}), /sessionId/);
  });

  it('leaves a session', () => {
    const result = handler.leaveSession({ sessionId: 'sess_456' });
    assert.ok(result.message_id);
    const msg = store.getById(result.message_id);
    assert.equal(msg.type, 'session_leave');
  });

  it('sends a message to a session', () => {
    const result = handler.sendMessage({
      sessionId: 'sess_789',
      toNodeId: 'node_c',
      msgType: 'context_update',
      payload: { key: 'value' },
    });
    assert.ok(result.message_id);
    const msg = store.getById(result.message_id);
    assert.equal(msg.type, 'session_message');
    assert.equal(msg.payload.session_id, 'sess_789');
    assert.equal(msg.payload.to_node_id, 'node_c');
  });

  it('throws on send message with oversized payload', () => {
    const bigPayload = { data: 'x'.repeat(17000) };
    assert.throws(() => handler.sendMessage({
      sessionId: 'sess_big',
      payload: bigPayload,
    }), /too large/);
  });

  it('delegates a subtask', () => {
    const result = handler.delegateSubtask({
      sessionId: 'sess_del',
      toNodeId: 'node_worker',
      title: 'Implement feature X',
      role: 'builder',
    });
    assert.ok(result.message_id);
    const msg = store.getById(result.message_id);
    assert.equal(msg.type, 'session_delegate');
    assert.equal(msg.payload.role, 'builder');
    assert.equal(msg.payload.title, 'Implement feature X');
  });

  it('normalizes invalid role to builder', () => {
    const result = handler.delegateSubtask({
      sessionId: 'sess_role',
      title: 'Fix bug',
      role: 'invalid_role',
    });
    const msg = store.getById(result.message_id);
    assert.equal(msg.payload.role, 'builder');
  });

  it('submits a result', () => {
    const result = handler.submitResult({
      sessionId: 'sess_sub',
      taskId: 'task_1',
      resultAssetId: 'asset_1',
      summary: 'Completed the implementation',
    });
    assert.ok(result.message_id);
    const msg = store.getById(result.message_id);
    assert.equal(msg.type, 'session_submit');
    assert.equal(msg.payload.task_id, 'task_1');
  });

  it('polls session invites', () => {
    store.writeInbound({ type: 'collaboration_invite', payload: { session_id: 's1' } });
    const msgs = handler.pollInvites();
    assert.ok(msgs.length >= 1);
  });

  it('lists active sessions', () => {
    const sessions = handler.listActiveSessions();
    assert.ok(Array.isArray(sessions));
    assert.ok(sessions.length > 0);
  });
});

describe('Session payload normalizers', () => {
  describe('normalizeCreatePayload', () => {
    it('throws on missing title', () => {
      assert.throws(() => normalizeCreatePayload({}), /title/);
      assert.throws(() => normalizeCreatePayload({ description: 'x' }), /title/);
    });

    it('clamps max_participants to [2, 20]', () => {
      assert.equal(normalizeCreatePayload({ title: 't', max_participants: 1 }).max_participants, 2);
      assert.equal(normalizeCreatePayload({ title: 't', max_participants: 100 }).max_participants, 20);
      assert.equal(normalizeCreatePayload({ title: 't', max_participants: 5 }).max_participants, 5);
    });

    it('defaults max_participants to 5 when missing or non-numeric', () => {
      assert.equal(normalizeCreatePayload({ title: 't' }).max_participants, 5);
      assert.equal(normalizeCreatePayload({ title: 't', max_participants: 'abc' }).max_participants, 5);
      assert.equal(normalizeCreatePayload({ title: 't', max_participants: null }).max_participants, 5);
      assert.equal(normalizeCreatePayload({ title: 't', max_participants: '' }).max_participants, 5);
    });

    it('slices invite_node_ids to first 10', () => {
      const ids = Array.from({ length: 15 }, (_, i) => 'n' + i);
      const r = normalizeCreatePayload({ title: 't', invite_node_ids: ids });
      assert.equal(r.invite_node_ids.length, 10);
      assert.deepEqual(r.invite_node_ids, ids.slice(0, 10));
    });

    it('defaults invite_node_ids to [] when not an array', () => {
      assert.deepEqual(normalizeCreatePayload({ title: 't' }).invite_node_ids, []);
      assert.deepEqual(normalizeCreatePayload({ title: 't', invite_node_ids: 'bad' }).invite_node_ids, []);
    });

    it('defaults description to empty string', () => {
      assert.equal(normalizeCreatePayload({ title: 't' }).description, '');
    });
  });

  describe('normalizeMessagePayload', () => {
    it('throws on missing session_id', () => {
      assert.throws(() => normalizeMessagePayload({}), /session_id/);
    });

    it('throws when payload exceeds 16KB serialized', () => {
      const big = { data: 'x'.repeat(20000) };
      assert.throws(() => normalizeMessagePayload({ session_id: 's', payload: big }), /too large/);
    });

    it('defaults payload to {} when not an object', () => {
      assert.deepEqual(normalizeMessagePayload({ session_id: 's' }).payload, {});
      assert.deepEqual(normalizeMessagePayload({ session_id: 's', payload: 'bad' }).payload, {});
    });

    it('defaults msg_type to context_update and to_node_id to null', () => {
      const r = normalizeMessagePayload({ session_id: 's' });
      assert.equal(r.msg_type, 'context_update');
      assert.equal(r.to_node_id, null);
    });
  });

  describe('normalizeDelegatePayload', () => {
    it('throws on missing session_id or title', () => {
      assert.throws(() => normalizeDelegatePayload({}), /session_id/);
      assert.throws(() => normalizeDelegatePayload({ session_id: 's' }), /title/);
    });

    it('whitelists role to builder/planner/reviewer', () => {
      assert.equal(normalizeDelegatePayload({ session_id: 's', title: 't', role: 'builder' }).role, 'builder');
      assert.equal(normalizeDelegatePayload({ session_id: 's', title: 't', role: 'planner' }).role, 'planner');
      assert.equal(normalizeDelegatePayload({ session_id: 's', title: 't', role: 'reviewer' }).role, 'reviewer');
    });

    it('falls back to builder for invalid or missing role', () => {
      assert.equal(normalizeDelegatePayload({ session_id: 's', title: 't', role: 'invalid' }).role, 'builder');
      assert.equal(normalizeDelegatePayload({ session_id: 's', title: 't' }).role, 'builder');
    });
  });

  describe('normalizeSubmitPayload', () => {
    it('throws on missing session_id or task_id', () => {
      assert.throws(() => normalizeSubmitPayload({}), /session_id/);
      assert.throws(() => normalizeSubmitPayload({ session_id: 's' }), /task_id/);
    });

    it('truncates summary to 200 chars', () => {
      const r = normalizeSubmitPayload({ session_id: 's', task_id: 't', summary: 'x'.repeat(300) });
      assert.equal(r.summary.length, 200);
    });

    it('defaults summary to empty string when not a string', () => {
      assert.equal(normalizeSubmitPayload({ session_id: 's', task_id: 't' }).summary, '');
      assert.equal(normalizeSubmitPayload({ session_id: 's', task_id: 't', summary: 123 }).summary, '');
    });

    it('defaults result_asset_id to null', () => {
      assert.equal(normalizeSubmitPayload({ session_id: 's', task_id: 't' }).result_asset_id, null);
    });
  });
});

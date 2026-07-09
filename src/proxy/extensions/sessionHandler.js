'use strict';

// SessionHandler -- enables agents to proactively create, join, and manage
// collaboration sessions via the Hub. Extends Evolver's proxy with full
// peer-to-peer swarm collaboration capability (session lifecycle + subtask
// delegation), shifting from passive Hub-orchestrated mode to agent-initiated
// mesh collaboration.

// Session payload limits. Centralized so the route fallback and the
// SessionHandler extension share one source of truth -- otherwise the
// fallback path (when the extension is not registered) silently skips these
// clamps/truncations and the wire contract diverges.
const MAX_PARTICIPANTS = 20;
const MIN_PARTICIPANTS = 2;
const DEFAULT_PARTICIPANTS = 5;
const MAX_INVITEES = 10;
const MAX_PAYLOAD_BYTES = 16000;
const MAX_SUMMARY_CHARS = 200;
const VALID_ROLES = ['builder', 'planner', 'reviewer'];
const DEFAULT_ROLE = 'builder';

// Pure normalizers. Throw Error('...') on validation failure; the route
// layer wraps the throw in a 400. Each accepts the wire shape (snake_case
// keys) and returns the normalized payload (also snake_case). The handler
// methods map their camelCase public API to snake_case before calling.

// Normalize a /session/create body. Throws if `title` is missing.
// `max_participants` is clamped to [MIN, MAX] (default DEFAULT).
// `invite_node_ids` is sliced to the first MAX_INVITEES entries.
function normalizeCreatePayload(body = {}) {
  if (!body.title) throw new Error('title is required');
  // Treat undefined/null/'' as missing (use default). Otherwise parse the
  // value and clamp. `|| DEFAULT_PARTICIPANTS` would treat 0 as missing and
  // silently change a legitimate 0 input into the default 5; the handler
  // had this bug pre-refactor and the test suite caught it.
  const raw = body.max_participants;
  let num = Number(raw);
  if (raw === undefined || raw === null || raw === '' || !Number.isFinite(num)) {
    num = DEFAULT_PARTICIPANTS;
  }
  return {
    title: body.title,
    description: body.description || '',
    invite_node_ids: Array.isArray(body.invite_node_ids) ? body.invite_node_ids.slice(0, MAX_INVITEES) : [],
    max_participants: Math.max(MIN_PARTICIPANTS, Math.min(MAX_PARTICIPANTS, num)),
  };
}

// Normalize a /session/message body. Throws if `session_id` is missing or
// the serialized `payload` exceeds MAX_PAYLOAD_BYTES.
function normalizeMessagePayload(body = {}) {
  if (!body.session_id) throw new Error('session_id is required');
  const safePayload = body.payload && typeof body.payload === 'object' ? body.payload : {};
  const serialized = JSON.stringify(safePayload);
  if (serialized.length > MAX_PAYLOAD_BYTES) throw new Error('payload too large (max 16KB)');
  return {
    session_id: body.session_id,
    to_node_id: body.to_node_id || null,
    msg_type: body.msg_type || 'context_update',
    payload: safePayload,
  };
}

// Normalize a /session/delegate body. Throws if `session_id` or `title` is
// missing. `role` is whitelisted (unknown values fall back to DEFAULT_ROLE).
function normalizeDelegatePayload(body = {}) {
  if (!body.session_id) throw new Error('session_id is required');
  if (!body.title) throw new Error('title is required');
  return {
    session_id: body.session_id,
    to_node_id: body.to_node_id || null,
    title: body.title,
    description: body.description || '',
    role: VALID_ROLES.includes(body.role) ? body.role : DEFAULT_ROLE,
  };
}

// Normalize a /session/submit body. Throws if `session_id` or `task_id` is
// missing. `summary` is truncated to MAX_SUMMARY_CHARS.
function normalizeSubmitPayload(body = {}) {
  if (!body.session_id) throw new Error('session_id is required');
  if (!body.task_id) throw new Error('task_id is required');
  const safeSummary = typeof body.summary === 'string' ? body.summary.slice(0, MAX_SUMMARY_CHARS) : '';
  return {
    session_id: body.session_id,
    task_id: body.task_id,
    result_asset_id: body.result_asset_id || null,
    summary: safeSummary,
  };
}

class SessionHandler {
  constructor({ store, logger } = {}) {
    this.store = store;
    this.logger = logger || console;
  }

  createSession(input = {}) {
    const payload = normalizeCreatePayload({
      title: input.title,
      description: input.description,
      invite_node_ids: input.inviteNodeIds,
      max_participants: input.maxParticipants,
    });
    return this.store.send({
      type: 'session_create',
      payload: { ...payload, created_at: new Date().toISOString() },
      priority: 'high',
    });
  }

  joinSession({ sessionId } = {}) {
    if (!sessionId) throw new Error('sessionId is required');

    return this.store.send({
      type: 'session_join',
      payload: {
        session_id: sessionId,
        joined_at: new Date().toISOString(),
      },
      priority: 'normal',
    });
  }

  leaveSession({ sessionId } = {}) {
    if (!sessionId) throw new Error('sessionId is required');

    return this.store.send({
      type: 'session_leave',
      payload: {
        session_id: sessionId,
        left_at: new Date().toISOString(),
      },
      priority: 'normal',
    });
  }

  sendMessage(input = {}) {
    const payload = normalizeMessagePayload({
      session_id: input.sessionId,
      to_node_id: input.toNodeId,
      msg_type: input.msgType,
      payload: input.payload,
    });
    return this.store.send({
      type: 'session_message',
      payload: { ...payload, sent_at: new Date().toISOString() },
      priority: 'normal',
    });
  }

  delegateSubtask(input = {}) {
    const payload = normalizeDelegatePayload({
      session_id: input.sessionId,
      to_node_id: input.toNodeId,
      title: input.title,
      description: input.description,
      role: input.role,
    });
    return this.store.send({
      type: 'session_delegate',
      payload: { ...payload, delegated_at: new Date().toISOString() },
      priority: 'high',
    });
  }

  submitResult(input = {}) {
    const payload = normalizeSubmitPayload({
      session_id: input.sessionId,
      task_id: input.taskId,
      result_asset_id: input.resultAssetId,
      summary: input.summary,
    });
    return this.store.send({
      type: 'session_submit',
      payload: { ...payload, submitted_at: new Date().toISOString() },
      priority: 'high',
    });
  }

  pollInvites({ limit } = {}) {
    return this.store.poll({
      type: 'collaboration_invite',
      limit: limit || 10,
    });
  }

  pollSessionEvents({ limit } = {}) {
    return this.store.poll({
      type: 'session_event',
      limit: limit || 20,
    });
  }

  listActiveSessions() {
    const sessionMsgs = this.store.list({
      type: 'session_create',
      direction: 'outbound',
      limit: 50,
    });
    return sessionMsgs;
  }
}

module.exports = {
  SessionHandler,
  normalizeCreatePayload,
  normalizeMessagePayload,
  normalizeDelegatePayload,
  normalizeSubmitPayload,
};

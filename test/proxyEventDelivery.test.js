'use strict';

const assert = require('node:assert/strict');
const { execFileSync, spawn } = require('node:child_process');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');

function sendJson(res, body) {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

function waitFor(predicate, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    function check() {
      if (predicate()) {
        resolve();
        return;
      }
      if (Date.now() >= deadline) {
        reject(new Error('timed out waiting for proxy event delivery'));
        return;
      }
      setTimeout(check, 25);
    }
    check();
  });
}

function waitForExit(child, timeoutMs) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, timeoutMs);
    child.once('exit', () => {
      clearTimeout(timer);
      resolve();
    });
  });
}

test('official proxy daemon uses healthy SSE without persistent poll or a second a2a heartbeat', {
  timeout: 20_000,
}, async (t) => {
  const repoRoot = path.resolve(__dirname, '..');
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'evolver-proxy-delivery-'));
  const projectDir = path.join(sandbox, 'project');
  const homeDir = path.join(sandbox, 'home');
  const evolverHome = path.join(homeDir, '.evomap');
  const settingsDir = path.join(homeDir, '.config', 'evomap');
  fs.mkdirSync(projectDir, { recursive: true });
  fs.mkdirSync(homeDir, { recursive: true });
  fs.writeFileSync(path.join(projectDir, 'README.md'), '# proxy event delivery fixture\n');
  execFileSync('git', ['init', '-q'], { cwd: projectDir });
  execFileSync('git', ['add', 'README.md'], { cwd: projectDir });
  execFileSync('git', [
    '-c', 'user.name=Evolver Test',
    '-c', 'user.email=evolver-test@example.invalid',
    'commit', '-qm', 'test fixture',
  ], { cwd: projectDir });

  const testSecret = '7'.repeat(64);
  const counts = { hello: 0, heartbeat: 0, stream: 0, poll: 0, mailbox: 0 };
  const authSeen = { stream: false, poll: false };
  const openStreams = new Set();
  let child = null;
  let stdout = '';
  let stderr = '';

  const hub = http.createServer((req, res) => {
    const pathname = new URL(req.url, 'http://127.0.0.1').pathname;
    if (pathname === '/a2a/events/stream') {
      counts.stream += 1;
      authSeen.stream = req.headers.authorization === 'Bearer ' + testSecret;
      openStreams.add(res);
      res.on('close', () => openStreams.delete(res));
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
      });
      res.write('event: task_available\n');
      res.write('data: {"type":"task_available","payload":{"source":"proxy-sse"}}\n\n');
      return;
    }

    req.resume();
    if (pathname === '/a2a/hello') {
      counts.hello += 1;
      sendJson(res, {
        ok: true,
        payload: { node_secret: testSecret, node_secret_version: 1 },
      });
      return;
    }
    if (pathname === '/a2a/heartbeat') {
      counts.heartbeat += 1;
      sendJson(res, { ok: true });
      return;
    }
    if (pathname === '/a2a/events/poll') {
      counts.poll += 1;
      authSeen.poll = req.headers.authorization === 'Bearer ' + testSecret;
      sendJson(res, {
        events: [{
          id: 'proxy-poll-event',
          type: 'dialog_message',
          payload: { source: 'proxy-poll' },
        }],
        next_poll_after_ms: 15_000,
      });
      return;
    }
    if (pathname === '/a2a/mailbox/inbound') {
      counts.mailbox += 1;
      sendJson(res, { messages: [] });
      return;
    }
    sendJson(res, { ok: true });
  });

  try {
    await new Promise((resolve) => hub.listen(0, '127.0.0.1', resolve));
    const hubUrl = 'http://127.0.0.1:' + hub.address().port;
    child = spawn(process.execPath, [path.join(repoRoot, 'index.js'), '--loop'], {
      cwd: projectDir,
      env: {
        PATH: process.env.PATH || '',
        NODE_PATH: process.env.NODE_PATH || '',
        HOME: homeDir,
        EVOLVER_HOME: evolverHome,
        EVOLVER_SETTINGS_DIR: settingsDir,
        // The packaged Linux service does not set A2A_HUB_URL. Exercise the
        // same fallback: EvoMapProxy resolves this default and passes its
        // resolved URL into the narrower a2a event-delivery owner.
        EVOLVER_DEFAULT_HUB_URL: hubUrl,
        EVOMAP_HUB_ALLOW_INSECURE: '1',
        EVOMAP_PROXY: '1',
        EVOMAP_PROXY_AUTO_INJECT: 'off',
        EVOLVE_BRIDGE: 'false',
        EVOLVER_VALIDATOR_ENABLED: 'false',
        EVOLVER_ATP: 'off',
        EVOLVER_ATP_AUTOBUY: 'off',
        EVOLVER_ATP_AUTODELIVER: 'off',
        EVOLVE_RECALL_VERIFY: '0',
        MEMORY_GRAPH_SYNC_HUB: '0',
        EVOLVER_DISABLE_PRIORITY_BOOST: '1',
        EVOLVER_DISABLE_OOM_ADJUST: '1',
        EVOLVER_MIN_SLEEP_MS: '5000',
        EVOLVER_MAX_SLEEP_MS: '5000',
        NODE_ENV: 'test',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });

    await waitFor(() => counts.stream > 0 && /\[SSE\] Event stream connected/.test(stdout), 10_000);
    const pollsAtSseConnect = counts.poll;
    await new Promise((resolve) => setTimeout(resolve, 2500));

    assert.equal(counts.hello, 1, 'proxy mode must not start the a2a hello/heartbeat loop');
    assert.ok(counts.heartbeat >= 1, 'the proxy lifecycle heartbeat should remain active');
    assert.equal(authSeen.stream, true, 'SSE should use the proxy-rotated node secret');
    assert.equal(counts.poll, pollsAtSseConnect, 'healthy SSE must suppress additional persistent long-poll requests');
    assert.equal(authSeen.poll, pollsAtSseConnect > 0, 'only startup fallback poll may authenticate before SSE is healthy');
    assert.doesNotMatch(stdout, /\[Heartbeat\] Registered with hub/);
    assert.equal(stdout.includes(testSecret), false, 'test secret must not be logged to stdout');
    assert.equal(stderr.includes(testSecret), false, 'test secret must not be logged to stderr');
    t.diagnostic(
      'mock Hub requests: hello=' + counts.hello +
      ', heartbeat=' + counts.heartbeat +
      ', stream=' + counts.stream +
      ', poll=' + counts.poll +
      ', mailbox=' + counts.mailbox
    );
  } finally {
    if (child && child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM');
      await waitForExit(child, 3000);
      if (child.exitCode === null && child.signalCode === null) {
        child.kill('SIGKILL');
        await waitForExit(child, 1000);
      }
    }
    for (const stream of openStreams) stream.destroy();
    await new Promise((resolve) => hub.close(resolve));
    fs.rmSync(sandbox, { recursive: true, force: true });
  }
});

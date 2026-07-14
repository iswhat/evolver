'use strict';

// observer/github tests — the Web UI PR-status data layer.
//
// Mirrors the openPRRegistry / issueReporter test style: stub
// child_process.execFileSync (the `gh` path) and global.fetch (the REST
// fallback) via their live references; no real `gh` or network is invoked.
// EVOLVER_GITHUB_REPO is pinned so slug resolution is deterministic and never
// shells out to `git remote`.

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

const MODULE_PATH = require.resolve('../src/webui/observer/github');

function loadFresh() {
  delete require.cache[MODULE_PATH];
  return require('../src/webui/observer/github');
}

function withExecFileMock(impl, fn) {
  const cp = require('child_process');
  const original = cp.execFileSync;
  cp.execFileSync = impl;
  return Promise.resolve(fn()).finally(() => { cp.execFileSync = original; });
}

function withFetchMock(impl, fn) {
  const original = global.fetch;
  global.fetch = impl;
  return Promise.resolve(fn()).finally(() => { global.fetch = original; });
}

function jsonResponse(body, status) {
  return {
    ok: status == null || (status >= 200 && status < 300),
    status: status || 200,
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}

function ghMissingError() {
  const e = new Error('spawn gh ENOENT');
  e.code = 'ENOENT';
  return e;
}

const GH_PR_319 = {
  number: 319,
  title: 'refactor(proxy): centralize session payload validation',
  state: 'MERGED',
  isDraft: false,
  author: { login: 'autogame-17', name: '' },
  additions: 457,
  deletions: 117,
  changedFiles: 7,
  createdAt: '2026-07-09T14:44:56Z',
  updatedAt: '2026-07-09T14:53:44Z',
  mergedAt: '2026-07-09T14:53:44Z',
  closedAt: '2026-07-09T14:53:44Z',
  url: 'https://github.com/EvoMap/evolver-private-dev/pull/319',
};

describe('observer/github — getPrStatus (gh path)', () => {
  let saved;
  beforeEach(() => {
    saved = { flag: process.env.EVOLVER_WEBUI_GITHUB, repo: process.env.EVOLVER_GITHUB_REPO };
    delete process.env.EVOLVER_WEBUI_GITHUB;
    process.env.EVOLVER_GITHUB_REPO = 'EvoMap/evolver-private-dev';
  });
  afterEach(() => {
    if (saved.flag === undefined) delete process.env.EVOLVER_WEBUI_GITHUB; else process.env.EVOLVER_WEBUI_GITHUB = saved.flag;
    if (saved.repo === undefined) delete process.env.EVOLVER_GITHUB_REPO; else process.env.EVOLVER_GITHUB_REPO = saved.repo;
  });

  it('normalizes gh pr view JSON into the unified shape', async () => {
    const gh = loadFresh();
    gh._resetForTesting();
    let calledArgs = null;
    await withExecFileMock((file, args) => {
      calledArgs = { file, args };
      return JSON.stringify(GH_PR_319);
    }, async () => {
      const pr = await gh.getPrStatus(319);
      assert.equal(pr.available, true);
      assert.equal(pr.source, 'gh');
      assert.equal(pr.number, 319);
      assert.equal(pr.state, 'merged');
      assert.equal(pr.author, 'autogame-17');
      assert.equal(pr.additions, 457);
      assert.equal(pr.deletions, 117);
      assert.equal(pr.changedFiles, 7);
      assert.equal(pr.url, GH_PR_319.url);
    });
    // Shell-safety: argv form, PR number is a discrete arg, never a shell string.
    assert.equal(calledArgs.file, 'gh');
    assert.deepEqual(calledArgs.args.slice(0, 3), ['pr', 'view', '319']);
  });

  it('caches within TTL (second call does not re-invoke gh)', async () => {
    const gh = loadFresh();
    gh._resetForTesting();
    let calls = 0;
    await withExecFileMock(() => { calls++; return JSON.stringify(GH_PR_319); }, async () => {
      await gh.getPrStatus(319);
      await gh.getPrStatus(319);
    });
    assert.equal(calls, 1);
  });

  it('rejects a non-integer number without invoking gh', async () => {
    const gh = loadFresh();
    gh._resetForTesting();
    let calls = 0;
    await withExecFileMock(() => { calls++; return '{}'; }, async () => {
      const bad = await gh.getPrStatus('3; rm -rf /');
      assert.equal(bad.available, false);
      assert.equal(bad.reason, 'invalid_number');
    });
    assert.equal(calls, 0);
  });

  it('short-circuits to feature_disabled when EVOLVER_WEBUI_GITHUB=0', async () => {
    process.env.EVOLVER_WEBUI_GITHUB = '0';
    const gh = loadFresh();
    gh._resetForTesting();
    let calls = 0;
    await withExecFileMock(() => { calls++; return '{}'; }, async () => {
      const res = await gh.getPrStatus(319);
      assert.equal(res.available, false);
      assert.equal(res.reason, 'feature_disabled');
    });
    assert.equal(calls, 0);
  });
});

describe('observer/github — REST fallback', () => {
  let saved;
  beforeEach(() => {
    saved = { flag: process.env.EVOLVER_WEBUI_GITHUB, repo: process.env.EVOLVER_GITHUB_REPO, tok: process.env.GITHUB_TOKEN, tok2: process.env.GH_TOKEN, tok3: process.env.GITHUB_PAT };
    delete process.env.EVOLVER_WEBUI_GITHUB;
    delete process.env.GITHUB_TOKEN; delete process.env.GH_TOKEN; delete process.env.GITHUB_PAT;
    process.env.EVOLVER_GITHUB_REPO = 'EvoMap/evolver-private-dev';
  });
  afterEach(() => {
    if (saved.flag === undefined) delete process.env.EVOLVER_WEBUI_GITHUB; else process.env.EVOLVER_WEBUI_GITHUB = saved.flag;
    if (saved.repo === undefined) delete process.env.EVOLVER_GITHUB_REPO; else process.env.EVOLVER_GITHUB_REPO = saved.repo;
    for (const [k, v] of [['GITHUB_TOKEN', saved.tok], ['GH_TOKEN', saved.tok2], ['GITHUB_PAT', saved.tok3]]) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
  });

  it('falls back to REST when gh is missing, normalizing the API shape', async () => {
    const gh = loadFresh();
    gh._resetForTesting();
    let fetchedUrl = null;
    await withExecFileMock(() => { throw ghMissingError(); }, async () => {
      await withFetchMock(async (url) => {
        fetchedUrl = String(url);
        return jsonResponse({
          number: 596,
          title: 'public sibling PR',
          state: 'open',
          draft: false,
          merged_at: null,
          user: { login: 'octocat' },
          additions: 10,
          deletions: 2,
          changed_files: 3,
          created_at: '2026-07-01T00:00:00Z',
          updated_at: '2026-07-02T00:00:00Z',
          closed_at: null,
          html_url: 'https://github.com/EvoMap/evolver/pull/596',
        });
      }, async () => {
        const pr = await gh.getPrStatus(596);
        assert.equal(pr.available, true);
        assert.equal(pr.source, 'api');
        assert.equal(pr.state, 'open');
        assert.equal(pr.author, 'octocat');
        assert.equal(pr.changedFiles, 3);
        assert.equal(pr.url, 'https://github.com/EvoMap/evolver/pull/596');
      });
    });
    assert.ok(fetchedUrl.includes('/repos/EvoMap/evolver-private-dev/pulls/596'), 'hits the pulls endpoint: ' + fetchedUrl);
  });

  it('degrades (available:false) on REST 404 without throwing', async () => {
    const gh = loadFresh();
    gh._resetForTesting();
    await withExecFileMock(() => { throw ghMissingError(); }, async () => {
      await withFetchMock(async () => jsonResponse({ message: 'Not Found' }, 404), async () => {
        const pr = await gh.getPrStatus(999999);
        assert.equal(pr.available, false);
        assert.equal(pr.reason, 'not_found');
      });
    });
  });

  it('degrades (rate_limited) on REST 403', async () => {
    const gh = loadFresh();
    gh._resetForTesting();
    await withExecFileMock(() => { throw ghMissingError(); }, async () => {
      await withFetchMock(async () => jsonResponse({ message: 'rate limit' }, 403), async () => {
        const pr = await gh.getPrStatus(5);
        assert.equal(pr.available, false);
        assert.equal(pr.reason, 'rate_limited');
      });
    });
  });

  it('degrades (network_error) when fetch throws', async () => {
    const gh = loadFresh();
    gh._resetForTesting();
    await withExecFileMock(() => { throw ghMissingError(); }, async () => {
      await withFetchMock(async () => { throw new Error('ECONNRESET'); }, async () => {
        const pr = await gh.getPrStatus(5);
        assert.equal(pr.available, false);
        assert.equal(pr.reason, 'network_error');
      });
    });
  });

  it('treats a gh non-zero "not found" exit as PR-not-answerable, not gh-missing (falls through to REST)', async () => {
    // A real but unknown/private PR makes gh exit non-zero with a message
    // containing "not found". That must NOT be mistaken for a missing gh
    // binary; it should simply fall through to the REST path.
    const gh = loadFresh();
    gh._resetForTesting();
    const notFound = new Error('GraphQL: Could not resolve to a PullRequest with the number of 42. no pull requests found');
    // No .code === 'ENOENT' — this is a normal non-zero exit, not a spawn failure.
    let fetched = 0;
    await withExecFileMock(() => { throw notFound; }, async () => {
      await withFetchMock(async () => { fetched++; return jsonResponse({ message: 'Not Found' }, 404); }, async () => {
        const pr = await gh.getPrStatus(42);
        assert.equal(pr.available, false);
        assert.equal(pr.reason, 'not_found');
      });
    });
    assert.equal(fetched, 1, 'gh non-zero exit must fall through to the REST path');
  });
});

describe('observer/github — pure helpers', () => {
  it('_normalizeNumber accepts positive ints only', () => {
    const gh = loadFresh();
    assert.equal(gh._normalizeNumber('319'), 319);
    assert.equal(gh._normalizeNumber(319), 319);
    assert.equal(gh._normalizeNumber('0'), null);
    assert.equal(gh._normalizeNumber('-1'), null);
    assert.equal(gh._normalizeNumber('3a'), null);
    assert.equal(gh._normalizeNumber('3.5'), null);
    assert.equal(gh._normalizeNumber(''), null);
    assert.equal(gh._normalizeNumber(null), null);
    // Beyond-safe-integer input must be rejected on BOTH branches — a numeric
    // 1e23 (whose String() is the non-numeric '1e+23') must never reach gh.
    assert.equal(gh._normalizeNumber(Number('9'.repeat(23))), null, 'huge number-typed input rejected');
    assert.equal(gh._normalizeNumber('9'.repeat(23)), null, 'huge string input rejected');
    assert.equal(gh._normalizeNumber(Number.MAX_SAFE_INTEGER), Number.MAX_SAFE_INTEGER);
    assert.equal(gh._normalizeNumber(Number.MAX_SAFE_INTEGER + 1), null);
  });

  it('_normalizeState collapses gh + REST states to merged|open|closed|draft', () => {
    const gh = loadFresh();
    assert.equal(gh._normalizeState('MERGED', false, '2026-07-09'), 'merged');
    assert.equal(gh._normalizeState('open', false, '2026-07-09'), 'merged', 'merged_at wins');
    assert.equal(gh._normalizeState('OPEN', true, null), 'draft');
    assert.equal(gh._normalizeState('CLOSED', false, null), 'closed');
    assert.equal(gh._normalizeState('open', false, null), 'open');
  });

  it('_parseSlugFromRemote handles https and ssh remotes', () => {
    const gh = loadFresh();
    assert.equal(gh._parseSlugFromRemote('https://github.com/EvoMap/evolver-private-dev.git'), 'EvoMap/evolver-private-dev');
    assert.equal(gh._parseSlugFromRemote('git@github.com:EvoMap/evolver.git'), 'EvoMap/evolver');
    assert.equal(gh._parseSlugFromRemote('https://gitlab.com/x/y.git'), null);
  });

  it('getRepoInfo builds a PR url base from the env slug', () => {
    const savedRepo = process.env.EVOLVER_GITHUB_REPO;
    const savedFlag = process.env.EVOLVER_WEBUI_GITHUB;
    process.env.EVOLVER_GITHUB_REPO = 'EvoMap/evolver-private-dev';
    delete process.env.EVOLVER_WEBUI_GITHUB;
    try {
      const gh = loadFresh();
      gh._resetForTesting();
      const info = gh.getRepoInfo();
      assert.equal(info.available, true);
      assert.equal(info.slug, 'EvoMap/evolver-private-dev');
      assert.equal(info.prUrlBase, 'https://github.com/EvoMap/evolver-private-dev/pull');
    } finally {
      if (savedRepo === undefined) delete process.env.EVOLVER_GITHUB_REPO; else process.env.EVOLVER_GITHUB_REPO = savedRepo;
      if (savedFlag === undefined) delete process.env.EVOLVER_WEBUI_GITHUB; else process.env.EVOLVER_WEBUI_GITHUB = savedFlag;
    }
  });
});

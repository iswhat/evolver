'use strict';

// ---- GitHub PR hovercard + Pull Requests panel ----
// Replicates Claude Code's "hover a #123 → floating PR status card" behaviour.
// linkifyPRRefs() turns escaped #N text into <a class="pr-ref">; a single
// document-level delegated hover then fetches /webui/github/pr/N and renders a
// floating card (state badge, title, author, +add/-del, N files, relative
// time). A dedicated Pull Requests tab lists the repo's open PRs, each row
// itself hoverable.
exports.githubJs = `
// Repo info (prUrlBase) for building hrefs. Prefetched at init; linkify falls
// back to '#' until it resolves (the hovercard fetch works regardless).
let GITHUB_REPO_INFO = { prUrlBase: null, slug: null, available: false };
const PR_CARD_CACHE = {}; // number -> normalized PR data (client-side memo)

function prUrlFor(n) {
  return GITHUB_REPO_INFO.prUrlBase ? (GITHUB_REPO_INFO.prUrlBase + '/' + n) : '#';
}

// Turn '#123' references inside ALREADY-ESCAPED text into anchor chips.
// Input MUST be esc()'d first: we only ever linkify plain text, never raw
// HTML, so we can't corrupt existing markup or attributes. The prefix class
// [^\\w\\/&] refuses matches after a word char (abc#1), a slash (URL paths)
// or an ampersand (numeric entities like &#39;), so only free-standing #N
// becomes a link. The number is [1-9]\\d* — a real PR number is never 0 or
// zero-padded, so '#0' / '#007' are left as plain text rather than dead chips.
function linkifyPRRefs(escapedText) {
  if (escapedText == null) return '';
  const s = String(escapedText);
  if (s.indexOf('#') === -1) return s;
  return s.replace(/(^|[^\\w\\/&])#([1-9]\\d*)\\b/g, function (m, pre, num) {
    return pre + '<a class="pr-ref" data-pr="' + num + '" href="' + prUrlFor(num) +
      '" target="_blank" rel="noopener noreferrer">#' + num + '</a>';
  });
}

// Compact relative time — mirrors the '14m ago' line in the reference card.
function relativeTime(iso) {
  if (!iso) return '';
  const then = new Date(iso).getTime();
  if (isNaN(then)) return '';
  let secs = Math.floor((Date.now() - then) / 1000);
  const future = secs < 0;
  secs = Math.abs(secs);
  let out;
  if (secs < 45) out = 'just now';
  else if (secs < 5400) { const m = Math.max(1, Math.round(secs / 60)); out = m + 'm'; }
  else if (secs < 86400) { out = Math.round(secs / 3600) + 'h'; }
  else if (secs < 2592000) { out = Math.round(secs / 86400) + 'd'; }
  else if (secs < 31536000) { out = Math.round(secs / 2592000) + 'mo'; }
  else { out = Math.round(secs / 31536000) + 'y'; }
  if (out === 'just now') return out;
  return future ? ('in ' + out) : (out + ' ago');
}

function prStateLabel(state) {
  const key = 'pr.state.' + state;
  const label = t(key);
  return label === key ? state : label;
}

// --- Floating hovercard (single instance) ---
let _prCardEl = null;
let _prShowTimer = null;
let _prHideTimer = null;
let _prActiveNum = null;

function ensurePrCard() {
  if (_prCardEl) return _prCardEl;
  _prCardEl = document.createElement('div');
  _prCardEl.id = 'pr-hovercard';
  _prCardEl.className = 'pr-hovercard';
  _prCardEl.style.display = 'none';
  // Keep the card open while the pointer is on it (enterable), so users can
  // click the GitHub link inside.
  _prCardEl.addEventListener('mouseenter', function () { clearTimeout(_prHideTimer); });
  _prCardEl.addEventListener('mouseleave', hidePrCard);
  document.body.appendChild(_prCardEl);
  return _prCardEl;
}

function prCardLoadingHtml(n) {
  return '<div class="pr-card-head"><span class="pr-badge loading">·</span>' +
    '<span class="pr-card-ref">#' + esc(n) + '</span></div>' +
    '<div class="pr-card-title muted">' + esc(t('pr.loading')) + '</div>';
}

function prCardUnavailableHtml(n, data) {
  const reason = data && data.reason ? data.reason : 'unavailable';
  return '<div class="pr-card-head"><span class="pr-badge unknown">?</span>' +
    '<a class="pr-card-ref" href="' + prUrlFor(n) + '" target="_blank" rel="noopener noreferrer">#' + esc(n) + '</a></div>' +
    '<div class="pr-card-title muted">' + esc(t('pr.unavailable')) + '</div>' +
    '<div class="pr-card-meta muted small">' + esc(reason) + '</div>';
}

function prCardSuccessHtml(d) {
  const state = d.state || 'open';
  const badge = '<span class="pr-badge ' + esc(state) + '">' + esc(prStateLabel(state)) + '</span>';
  const when = d.mergedAt || d.closedAt || d.updatedAt || d.createdAt;
  const rel = relativeTime(when);
  const author = d.author ? ('<span class="pr-card-author">' + esc(d.author) + '</span>') : '';
  const diff = '<span class="pr-diff"><span class="pr-add">+' + esc(d.additions || 0) + '</span> ' +
    '<span class="pr-del">\\u2212' + esc(d.deletions || 0) + '</span></span>';
  const files = '<span class="pr-files">' + esc(d.changedFiles || 0) + ' ' + esc(t('pr.files')) + '</span>';
  return '<div class="pr-card-head">' + badge +
    '<a class="pr-card-ref" href="' + esc(d.url || prUrlFor(d.number)) + '" target="_blank" rel="noopener noreferrer">#' + esc(d.number) + '</a>' +
    (rel ? '<span class="pr-card-time muted">' + esc(rel) + '</span>' : '') +
    '</div>' +
    '<div class="pr-card-title">' + esc(d.title || '') + '</div>' +
    '<div class="pr-card-meta">' + author + diff + files + '</div>';
}

function renderPrCard(n, data) {
  const el = ensurePrCard();
  if (!data) el.innerHTML = prCardLoadingHtml(n);
  else if (!data.available) el.innerHTML = prCardUnavailableHtml(n, data);
  else el.innerHTML = prCardSuccessHtml(data);
}

// Position the card above the anchor (as in the reference), flipping below
// when it would overflow the top of the viewport. Uses fixed positioning so
// getBoundingClientRect (viewport-relative) maps directly.
function positionPrCard(anchor) {
  const el = _prCardEl;
  if (!el || !anchor) return;
  const r = anchor.getBoundingClientRect();
  el.style.display = 'block';
  const cw = el.offsetWidth;
  const ch = el.offsetHeight;
  let left = r.left;
  if (left + cw > window.innerWidth - 8) left = Math.max(8, window.innerWidth - cw - 8);
  let top = r.top - ch - 8;
  if (top < 8) top = r.bottom + 8; // flip below when no room above
  el.style.left = Math.round(left) + 'px';
  el.style.top = Math.round(top) + 'px';
}

async function showPrCard(anchor) {
  const n = anchor.getAttribute('data-pr');
  if (!n) return;
  _prActiveNum = n;
  renderPrCard(n, PR_CARD_CACHE[n] || null); // instant paint: cache or loading
  positionPrCard(anchor);
  if (PR_CARD_CACHE[n]) return;
  try {
    const data = await api('/webui/github/pr/' + encodeURIComponent(n));
    PR_CARD_CACHE[n] = data;
    if (_prActiveNum === n) { renderPrCard(n, data); positionPrCard(anchor); }
  } catch (err) {
    if (_prActiveNum === n) {
      renderPrCard(n, { number: n, available: false, reason: (err && err.message) || 'error' });
      positionPrCard(anchor);
    }
  }
}

function hidePrCard() {
  clearTimeout(_prHideTimer);
  _prHideTimer = setTimeout(function () {
    if (_prCardEl) _prCardEl.style.display = 'none';
    _prActiveNum = null;
  }, 180);
}

function initPrHovercards() {
  ensurePrCard();
  // Event delegation: one pair of listeners covers every current and future
  // .pr-ref, no matter which tab rendered it.
  document.addEventListener('mouseover', function (e) {
    const ref = e.target && e.target.closest ? e.target.closest('.pr-ref') : null;
    if (!ref) return;
    clearTimeout(_prHideTimer);
    clearTimeout(_prShowTimer);
    _prShowTimer = setTimeout(function () { showPrCard(ref); }, 250); // debounce hover
  });
  document.addEventListener('mouseout', function (e) {
    const ref = e.target && e.target.closest ? e.target.closest('.pr-ref') : null;
    if (!ref) return;
    clearTimeout(_prShowTimer);
    hidePrCard();
  });
}

async function initGithub() {
  initPrHovercards();
  try {
    const info = await api('/webui/github/repo');
    if (info) GITHUB_REPO_INFO = info;
  } catch (_) { /* linkify falls back to '#'; hovercard still works */ }
}

// --- Pull Requests panel ---
async function loadPullRequests() {
  const host = $('pull-requests');
  if (!host) return;
  // Localized placeholder while the (cold gh pr list) fetch resolves — avoids
  // sitting on the static English "Loading..." from the server-rendered shell.
  host.innerHTML = '<p class="muted">' + esc(t('common.loading')) + '</p>';
  let res;
  try {
    res = await api('/webui/github/prs');
  } catch (err) {
    host.innerHTML = '<p class="status-failed">' + esc(t('pr.loadFailed')) + esc(err.message || '') + '</p>';
    return;
  }
  renderPullRequests(res && res.data ? res.data : []);
}

function renderPullRequests(prs) {
  const host = $('pull-requests');
  if (!host) return;
  if (!prs.length) {
    // No open PRs (or gh unavailable): guide the user to hover any #N instead.
    host.innerHTML = '<p class="muted">' + esc(t('pr.empty')) + '</p>';
    return;
  }
  host.innerHTML = '<ul class="pr-list">' + prs.map(function (pr) {
    const ref = '<a class="pr-ref" data-pr="' + esc(pr.number) + '" href="' + prUrlFor(pr.number) +
      '" target="_blank" rel="noopener noreferrer">#' + esc(pr.number) + '</a>';
    const branch = pr.headRefName ? ('<span class="pill">' + esc(pr.headRefName) + '</span>') : '';
    const files = '<span class="muted small">' + esc(pr.fileCount || 0) + ' ' + esc(t('pr.files')) + '</span>';
    return '<li class="pr-row">' + ref + ' <span class="pr-row-title">' + esc(pr.title || '') + '</span> ' + branch + ' ' + files + '</li>';
  }).join('') + '</ul>';
}
`;

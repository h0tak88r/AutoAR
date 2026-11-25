const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const repoRoot = path.resolve(__dirname, '../..');

// Findings (merged with AI Triage): every string on this page came from a
// scanned target or from the model reading it. These tests feed hostile
// payloads and assert they stay inert text, and that data-* attributes (which
// drive CSS colour) only ever carry whitelisted values.

const EVIL = '<img src=x onerror=alert(1)>';
const HOSTILE = {
  id: 7,
  title: `${EVIL} Evil <b>bold</b>`,
  host: 'x.example',
  matched_at: 'https://x.example/"><script>alert(2)</script>',
  module: '"><svg onload=alert(3)>',
  template_id: EVIL,
  cve: EVIL,
  severity: '"><svg onload=alert(4)>',
  status: 'validated" onmouseover="alert(5)',
  program: EVIL,
  platform: EVIL,
  scan_id: 's1',
  report_md: '[x](javascript:alert(6))\n![b](https://evil.example/b.png)\n<script>alert(7)</script>',
  notes: EVIL,
  evidence: '{"k":"<img src=x onerror=alert(8)>"}',
  first_seen: 1700000000,
  last_seen: 1700000100,
  ai: {
    verdict: 'true_positive" onmouseover="alert(9)', confidence: 9999, severity: 'unknown', reason: EVIL,
    status: 'done', reportable: true, scope: 'in"><b>', scope_program: '<iframe src=//evil.example></iframe>',
    human_verdict: '', notify_note: EVIL, report_md: EVIL, provider: EVIL, model: EVIL,
  },
};

function makeEl(id) {
  return {
    id, innerHTML: '', textContent: '', value: '', hidden: false, dataset: {}, style: {},
    classList: { toggle() {}, add() {}, remove() {} },
    addEventListener() {}, querySelectorAll: () => [], querySelector: () => ({ focus() {}, textContent: '' }),
    remove() {}, appendChild() {}, focus() {}, setAttribute(k, v) { this[`attr:${k}`] = String(v); },
  };
}

function load(items, opts = {}) {
  const els = {};
  for (const id of ['fx-root', 'fx-results', 'fx-kpis', 'fx-status', 'fx-lastrun', 'fx-pager', 'fx-pager-top', 'fx-scan-chip', 'fx-search', 'fx-status-filter', 'fx-severity-filter', 'fx-module-filter', 'fx-program-filter', 'fx-program-list', 'fx-platform-filter', 'fx-report-filter', 'fx-closed-toggle', 'fx-remind-toggle']) {
    els[id] = makeEl(id);
  }
  const created = [];
  const calls = { fetch: [], post: [], nav: [], toast: [], agent: [], patch: [], prompt: [] };
  const context = {
    console, Date, URLSearchParams, Promise, setTimeout: () => 0, clearTimeout() {},
    confirm: () => opts.confirm !== false,
    prompt: () => { throw new Error('native prompt() is suppressed in the app browser pane — use window.uiPrompt'); },
    location: { search: opts.search || '' },
    document: {
      getElementById: (id) => els[id] || null,
      createElement: () => { const e = makeEl(''); created.push(e); return e; },
      addEventListener() {}, removeEventListener() {}, activeElement: null, contains: () => false, body: { appendChild() {} },
    },
    window: {},
  };
  context.window = {
    state: { _me: { role: opts.role || 'admin' }, view: 'findings' },
    esc: (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])),
    apiFetch: async (p) => {
      calls.fetch.push(p);
      if (p.startsWith('/api/triage/status')) return { ai_available: true, provider: 'deepseek', model: 'deepseek-flash', auto: true, notify: true, used_today: 3, daily_limit: 200, pending: [], running: null, recent: [] };
      if (/^\/api\/findings\/\d+/.test(p)) return { finding: items[0] };
      return { findings: items, total: opts.total ?? items.length, facets: opts.facets || { total: items.length, ai: { reportable: 4, needs_manual_review: 2, unreviewed: 9 }, status: { validated: 1, drafted: 2, submitted: 3 } } };
    },
    apiPost: async (p, body) => { calls.post.push([p, body]); return { ai: true, finding: items[0] }; },
    apiPatch: async (p, body) => { calls.patch.push([p, body]); if (opts.patchError) throw new Error(opts.patchError); return {}; },
    uiConfirm: async () => opts.confirm !== false,
    uiPrompt: async (msg, o) => { calls.prompt.push([msg, o]); return opts.promptAnswer === undefined ? null : opts.promptAnswer; },
    navigateTo: (v) => calls.nav.push(v),
    showToast: (...a) => calls.toast.push(a),
    copyToClipboard: async () => {},
    openAgentWith: (t) => calls.agent.push(t),
  };
  vm.createContext(context);
  const rel = 'internal/api/ui/pages/findings.js';
  vm.runInContext(fs.readFileSync(path.join(repoRoot, rel), 'utf8'), context, { filename: rel });
  return { win: context.window, els, created, calls };
}

function assertInert(html) {
  assert.doesNotMatch(html, /<(img|svg|iframe|script|object|embed|link)\b/i, 'injected element');
  for (const tag of html.match(/<[a-z][^>]*>/gi) || []) {
    const bare = tag.replace(/"[^"]*"/g, '""');
    assert.doesNotMatch(bare, /\son[a-z]+\s*=/i, `event-handler attribute in: ${tag}`);
    assert.doesNotMatch(bare, /javascript:/i, `javascript: URL in: ${tag}`);
  }
}
const attrValues = (html, attr) => [...html.matchAll(new RegExp(`\\s${attr}="([^"]*)"`, 'g'))].map((m) => m[1]);

test('table renders hostile finding fields as inert, visible text', async () => {
  const { win, els } = load([HOSTILE]);
  await win.loadFindingsPage();
  const html = els['fx-results'].innerHTML;
  assert.ok(html.includes('tri-row'), 'row rendered');
  assertInert(html);
  assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'), 'payload text stays visible, escaped');
});

test('data-* attributes only carry whitelisted values', async () => {
  const { win, els } = load([HOSTILE]);
  await win.loadFindingsPage();
  const html = els['fx-results'].innerHTML;
  const ok = (attr, allowed) => { for (const v of attrValues(html, attr)) assert.ok(allowed.includes(v), `${attr}="${v}"`); };
  ok('data-v', ['', 'true_positive', 'likely', 'needs_manual_review', 'false_positive', 'error']);
  ok('data-src', ['none', 'status', 'ai', 'human']);
  ok('data-agree', ['0']);
  ok('data-sev', ['', 'critical', 'high', 'medium', 'low', 'info']);
  ok('data-s', ['', 'in', 'out', 'paused', 'related', 'guess']);
  ok('data-st', ['discovered', 'validated', 'drafted', 'approved', 'submitted', 'resolved', 'dup', 'rejected', 'wontfix']);
  ok('data-mod', ['nuclei', 'zerodays', 'misconfig', 'dns-takeover', 'exposure', 'dalfox', 'sqlmap', 'depconf', 'buckets', 'firebase', 'mcp-server', 'backup', 'aem', 'manual', 'other']);
});

test('confidence is clamped to 0-100 before it reaches a style attribute', async () => {
  const { win, els } = load([{ ...HOSTILE, ai: { ...HOSTILE.ai, verdict: 'likely', confidence: 9999 } }]);
  await win.loadFindingsPage();
  const html = els['fx-results'].innerHTML;
  assert.ok(html.includes('--w:100%'));
  assert.doesNotMatch(html, /--w:9999/);
});

test('drawer shows evidence, AI reason and report as plain text', async () => {
  const { win, created } = load([HOSTILE]);
  await win.FindingsPage.openDetail(7);
  const overlay = created.find((e) => e.innerHTML.includes('tri-drawer'));
  assert.ok(overlay, 'drawer built');
  assertInert(overlay.innerHTML);
  assert.ok(overlay.innerHTML.includes('role="dialog"') && overlay.innerHTML.includes('aria-modal="true"'));
  assert.ok(overlay.innerHTML.includes('![b](https://evil.example/b.png)'), 'markdown stays literal');
  assert.ok(overlay.innerHTML.includes('data-act="report"'), 'report can be edited');
});

test('a finding with no report offers Draft report; the AI draft is offered when present', async () => {
  const noReport = { ...HOSTILE, report_md: '', ai: { ...HOSTILE.ai, report_md: '' } };
  let { win, created } = load([noReport]);
  await win.FindingsPage.openDetail(7);
  let html = created.find((e) => e.innerHTML.includes('tri-drawer')).innerHTML;
  assert.match(html, /No report yet\..*Draft report/s);
  ({ win, created } = load([{ ...HOSTILE, report_md: '', ai: { ...HOSTILE.ai, report_md: '## AI draft' } }]));
  await win.FindingsPage.openDetail(7);
  html = created.find((e) => e.innerHTML.includes('tri-drawer')).innerHTML;
  assert.ok(html.includes("AI review's draft") && html.includes('Use & edit'));
});

test('KPIs and segment counts come from the facets', async () => {
  const { win, els } = load([]);
  await win.loadFindingsPage();
  const k = els['fx-kpis'].innerHTML;
  assert.ok(k.includes('Ready to file') && k.includes('>4<'), 'the reportable queue is called Ready to file');
  assert.ok(k.includes('Needs review') && k.includes('>2<'));
  assert.ok(k.includes('Not reviewed') && k.includes('>9<'));
  assert.ok(k.includes('Submitted') && k.includes('>3<'), 'the submitted facet, not an aggregate that the filter cannot show');
  assert.ok(!k.includes('Reportable'), 'no second name for the same queue');
  assert.ok(els['fx-status'].innerHTML.includes('AI budget <b>3</b> / 200'));
});

test('AI review is offered on unreviewed rows only, and only to admins', async () => {
  const unreviewed = { ...HOSTILE, id: 8, ai: null };
  let { win, els } = load([HOSTILE, unreviewed]);
  await win.loadFindingsPage();
  assert.equal((els['fx-results'].innerHTML.match(/data-fx-review=/g) || []).length, 1);
  ({ win, els } = load([unreviewed], { role: 'member' }));
  await win.loadFindingsPage();
  assert.doesNotMatch(els['fx-results'].innerHTML, /data-fx-review=|data-fx-check=/);
});

test('filters become query parameters', async () => {
  const { win, calls } = load([]);
  Object.assign(win.FindingsPage.state, { ai: 'reportable', status: 'validated', severity: 'high', module: 'zerodays', q: 'jira', scanId: 's9' });
  await win.loadFindingsPage();
  const url = calls.fetch.find((p) => p.startsWith('/api/findings?'));
  for (const part of ['ai=reportable', 'status=validated', 'severity=high', 'module=zerodays', 'q=jira', 'scan_id=s9', 'facets=1']) {
    assert.ok(url.includes(part), `${part} in ${url}`);
  }
});

test('Send to Findings (scan page) queues an import with AI review, then shows that scan', async () => {
  const { win, calls } = load([]);
  await win.triageScan('scan-123');
  assert.deepEqual(JSON.parse(JSON.stringify(calls.post)), [['/api/findings/import-scan', { scan_id: 'scan-123', include_info: false, ai: true }]]);
  assert.deepEqual(calls.nav, ['findings']);
  assert.equal(win.FindingsPage.state.scanId, 'scan-123');
});

test('declining the confirm imports nothing', async () => {
  const { win, calls } = load([], { confirm: false });
  await win.triageScan('scan-123');
  assert.equal(calls.post.length, 0);
});

test('an empty scan view explains why and offers the info-level import', async () => {
  const { win, els } = load([]);
  win.FindingsPage.state.scanId = 's9';
  await win.loadFindingsPage();
  const html = els['fx-results'].innerHTML;
  assert.match(html, /No findings from this scan/);
  assert.ok(html.includes('data-fx-import-info'));
});

test('auto-review is a toggle button for admins', async () => {
  const { win, els } = load([]);
  await win.loadFindingsPage();
  const st = els['fx-status'].innerHTML;
  assert.match(st, /<button type="button" class="tri-chip fx-toggle" data-state="ok" data-fx-auto="1" aria-pressed="true"/);
  assert.match(st, /Auto-review <b>on<\/b>/);
});

test('agent validation chips are whitelisted and hostile text stays inert', async () => {
  const items = [
    { ...HOSTILE, id: 21, validation: { status: 'done', verdict: 'true_positive" onmouseover="alert(1)', confidence: 999, summary: EVIL } },
    { ...HOSTILE, id: 22, validation: { status: 'done', verdict: 'likely', confidence: 70, summary: EVIL } },
    { ...HOSTILE, id: 23, validation: { status: 'running' } },
    { ...HOSTILE, id: 24, validation: { status: 'error', error: EVIL } },
  ];
  const { win, els } = load(items);
  await win.loadFindingsPage();
  const html = els['fx-results'].innerHTML;
  assertInert(html);
  for (const v of attrValues(html, 'data-av')) assert.ok(['', 'true_positive', 'likely', 'needs_manual_review', 'false_positive', 'error', 'busy'].includes(v), `data-av="${v}"`);
  assert.match(html, /agent likely · 70%/);
  assert.match(html, /agent \? · 100%/, 'unknown verdict shows ?, confidence clamped');
  assert.match(html, /agent validating…/);
});

test('the agent badge never re-says the verdict pill or the reportable queue', async () => {
  const f = { ...HOSTILE, id: 40, status: 'discovered', ai: { verdict: 'true_positive', confidence: 88, status: 'done', reportable: true },
    validation: { status: 'done', verdict: 'true_positive', confidence: 91, reportable: true, steps: 4 } };
  const { win, els } = load([f]);
  await win.loadFindingsPage();
  const html = els['fx-results'].innerHTML;
  assert.match(html, /agent confirmed · 91%/, 'the agent uses its own word');
  assert.ok(!/Agent TP/.test(html), 'no TP shorthand that mirrors the pill');
  assert.ok(!/reportable/i.test(html), 'reportable is the KPI/filter queue, not a row pill');
});

test('the agent badge flags disagreement with the verdict', async () => {
  const f = { ...HOSTILE, id: 41, status: 'discovered', ai: { verdict: 'true_positive', confidence: 88, status: 'done' },
    validation: { status: 'done', verdict: 'false_positive', confidence: 92, reportable: false, steps: 3 } };
  const { win, els } = load([f]);
  await win.loadFindingsPage();
  const html = els['fx-results'].innerHTML;
  assert.match(html, /data-agree="0"[^>]*>⚠ agent ruled out · 92%/, 'disagreement is called out');
});

test('the drawer shows the agent evidence as text and offers validation', async () => {
  const f = { ...HOSTILE, validation: { status: 'done', verdict: 'true_positive', confidence: 90, reportable: true, steps: 5,
    session_id: 'validate-f7-1', summary: EVIL, evidence: `curl -i …\n${EVIL}`, reproduction: EVIL, next_steps: EVIL } };
  const { win, created } = load([f]);
  await win.FindingsPage.openDetail(7);
  const overlay = created.find((e) => e.innerHTML.includes('tri-drawer'));
  assertInert(overlay.innerHTML);
  assert.ok(overlay.innerHTML.includes('Agent validation'));
  assert.match(overlay.innerHTML, /agent confirmed · 90%/, 'the agent keeps its own vocabulary');
  assert.match(overlay.innerHTML, /Worth filing — the agent would report this\./, 'the filing decision is a sentence, not a second pill');
  assert.ok(!/>reportable</.test(overlay.innerHTML), 'no reportable pill next to a true positive pill');
  assert.ok(overlay.innerHTML.includes('data-act="validate"') && overlay.innerHTML.includes('Re-validate'));
  assert.ok(overlay.innerHTML.includes('validate-f7-1'));
});

test('the verdict pill follows the workflow status before the AI, and says where it came from', async () => {
  const base = { ...HOSTILE, title: 'x', module: 'nuclei', severity: 'high', status: 'discovered' };
  const items = [
    { ...base, id: 31, status: 'submitted', ai: null },
    { ...base, id: 32, status: 'approved', ai: { verdict: 'needs_manual_review', confidence: 50, status: 'done' } },
    { ...base, id: 33, status: 'rejected', ai: null },
    { ...base, id: 34, status: 'discovered', ai: { verdict: 'likely', confidence: 70, status: 'done' } },
    { ...base, id: 35, status: 'discovered', ai: { verdict: 'likely', confidence: 70, status: 'done', human_verdict: 'true_positive' } },
  ];
  const { win, els } = load(items);
  await win.loadFindingsPage();
  const html = els['fx-results'].innerHTML;
  const pills = [...html.matchAll(/<span class="tri-pill" data-v="([^"]*)" data-src="([^"]*)"[^>]*>(.*?)<\/span>/g)]
    .map((m) => `${m[1]}|${m[2]}|${m[3].replace(/<[^>]+>/g, '')}`);
  assert.deepEqual(pills.slice(0, 5), [
    'true_positive|status|True positive (from workflow status)',
    'true_positive|status|True positive (from workflow status)',
    'false_positive|status|False positive (from workflow status)',
    'likely|ai|Likely',
    'true_positive|human|True positive · you',
  ]);
  assert.ok(!html.includes('True positive · you (from workflow status)'), 'a status-derived verdict never claims to be your label');
  assert.equal((html.match(/<span class="fx-sr"> \(from workflow status\)<\/span>/g) || []).length, 3, 'the source is announced, not only drawn');
});

test('program chip says how the program was found, and only a catalog match reads as scope', async () => {
  const base = { status: 'discovered', severity: 'high', module: 'nuclei', title: 't', host: 'h.example.com' };
  const items = [
    { ...base, id: 1, platform: 'h1', program: 'alibaba', program_match: 'related', host: '888kiss.aliexpress.com' },
    { ...base, id: 2, platform: 'bc', program: 'originenergy', program_match: 'guess' },
    { ...base, id: 3, platform: 'h1', program: 'acme', program_match: 'in' },
    { ...base, id: 4, platform: 'h1', program: 'acme', program_match: 'out' },
    { ...base, id: 5, platform: 'ywh', program: 'mine', program_match: '' },
    { ...base, id: 6, platform: 'h1', program: 'x', program_match: 'in" onmouseover="alert(1)' },
    { ...base, id: 7 },
    // An AI scope verdict wins over the catalog match.
    { ...base, id: 8, platform: 'h1', program: 'acme', program_match: 'guess', ai: { scope: 'in', scope_program: 'h1 acme', verdict: 'likely', status: 'done' } },
  ];
  const { win, els } = load(items);
  await win.loadFindingsPage();
  const html = els['fx-results'].innerHTML;
  assertInert(html);
  const chips = [...html.matchAll(/<span class="tri-scope" data-s="([^"]*)" title="([^"]*)"><span>([^<]*)<\/span>/g)].map((m) => ({ s: m[1], title: m[2], text: m[3] }));
  const byText = (t) => chips.find((c) => c.text === t);
  assert.equal(byText('h1 alibaba · root').s, 'related');
  assert.match(byText('h1 alibaba · root').title, /root domain, not this host/);
  assert.equal(byText('bc originenergy?').s, 'guess');
  assert.match(byText('bc originenergy?').title, /named like its root domain/);
  assert.ok(chips.some((c) => c.text === 'h1 acme' && c.s === 'in'));
  assert.ok(chips.some((c) => c.text === 'Out of scope · h1 acme' && c.s === 'out'));
  assert.ok(chips.some((c) => c.text === 'ywh mine' && c.s === ''), 'a hand-set program stays neutral');
  assert.ok(chips.some((c) => c.text === 'h1 x' && c.s === ''), 'unknown match values fall back to neutral');
  assert.ok(chips.some((c) => c.text === 'Scope unverified'));
  assert.ok(!chips.some((c) => (c.s === 'related' || c.s === 'guess') && /in scope/i.test(c.text)));
});

test('the program chip links to the program page; only http(s) URLs become links', async () => {
  const base = { status: 'discovered', severity: 'high', module: 'nuclei', title: 't' };
  const items = [
    { ...base, id: 1, platform: 'h1', program: 'sea', program_match: 'related', program_url: 'https://hackerone.com/sea', program_accounts: ['0x88', 'Samii'] },
    { ...base, id: 2, platform: 'h1', program: 'x', program_url: 'javascript:alert(1)' },
    { ...base, id: 3, platform: 'it', program: 'y' },
    { ...base, id: 4, platform: 'bc', program: 'z', program_url: 'https://bugcrowd.com/engagements/z', program_accounts: ['a', 'b', 'c', 'd', 'e'] },
  ];
  const { win, els } = load(items);
  await win.loadFindingsPage();
  const html = els['fx-results'].innerHTML;
  assertInert(html);
  assert.match(html, /<span class="tri-scope" data-s="related" title="[^"]*Open https:\/\/hackerone.com\/sea"><a class="fx-proglink" href="https:\/\/hackerone.com\/sea" target="_blank" rel="noopener noreferrer">h1 sea · root<\/a><\/span><span class="fx-acct" title="Accounts that can see this program: 0x88, Samii">👤 0x88, Samii<\/span>/);
  assert.match(html, /<span class="tri-scope" data-s="" title="h1 x"><span>h1 x<\/span><\/span>/);
  assert.match(html, /<span class="tri-scope" data-s="" title="it y"><span>it y<\/span><\/span>/);
  // Only the first 3 labels are shown, with a +N overflow.
  assert.match(html, /👤 a, b, c \+2<\/span>/);
  // A program with no account list shows no accounts line.
  assert.ok(!/h1 x<\/span><\/span><span class="fx-acct"/.test(html));
  assert.ok(!html.includes('javascript:'));
});

test('submitFinding: previews, confirms, files via API, reports the URL', async () => {
  const { win, calls } = load([{ id: 7, title: 't', status: 'drafted' }]);
  await win.loadFindingsPage();
  win.apiFetch = async (p) => { calls.fetch.push(p); return { finding_id: 7, platform: 'h1', program: 'alibaba', via: 'api', account: 'Samii', title: 'Exposed .env', body: '## r', can_submit: true }; };
  win.apiPost = async (p, b) => { calls.post.push([p, b]); return { submitted: true, url: 'https://hackerone.com/reports/42', status: 'submitted' }; };
  let confirmMsg = '';
  win.uiConfirm = async (m) => { confirmMsg = m; return true; };
  const ok = await win.FindingsPage.submitFinding(7);
  assert.equal(ok, true);
  assert.match(confirmMsg, /File this report to H1/);
  assert.match(confirmMsg, /Account: Samii/);
  assert.match(confirmMsg, /can.t be undone/);
  const sent = calls.post.pop();
  assert.equal(sent[0], '/api/findings/7/submit');
  assert.equal(sent[1].account_label, 'Samii');
});

test('submitFinding: cancelling the confirm files nothing', async () => {
  const { win, calls } = load([{ id: 7, title: 't', status: 'drafted' }]);
  await win.loadFindingsPage();
  win.apiFetch = async () => ({ platform: 'h1', program: 'a', via: 'api', account: 'x', title: 't', body: 'b', can_submit: true });
  win.uiConfirm = async () => false;
  assert.equal(await win.FindingsPage.submitFinding(7), false);
  assert.equal(calls.post.length, 0);
});

test('submitFinding: a blocker (no report) never POSTs', async () => {
  const { win, calls } = load([{ id: 7, title: 't', status: 'discovered' }]);
  await win.loadFindingsPage();
  win.apiFetch = async () => ({ platform: 'h1', program: 'a', blocker: 'no report yet — draft the report first' });
  win.uiConfirm = async () => true;
  assert.equal(await win.FindingsPage.submitFinding(7), false);
  assert.equal(calls.post.length, 0);
});

test('submitFinding: a manual platform copies the report and does not POST', async () => {
  const { win, calls } = load([{ id: 8, title: 't', status: 'drafted' }]);
  await win.loadFindingsPage();
  let copied = '', opened = '';
  win.apiFetch = async () => ({ platform: 'bc', program: 'epam', via: 'manual', body: 'REPORT BODY', url: 'https://bugcrowd.com/engagements/epam-mbb-og' });
  win.copyToClipboard = async (t) => { copied = t; };
  win.open = (u) => { opened = u; };
  win.uiConfirm = async () => true;
  assert.equal(await win.FindingsPage.submitFinding(8), false);
  assert.equal(copied, 'REPORT BODY');
  assert.equal(opened, 'https://bugcrowd.com/engagements/epam-mbb-og');
  assert.equal(calls.post.length, 0);
});

test('submitFinding: picks an account when several can see the program', async () => {
  const { win, calls } = load([{ id: 9, title: 't', status: 'drafted' }], { promptAnswer: 'Samii' });
  await win.loadFindingsPage();
  win.apiFetch = async () => ({ platform: 'h1', program: 'a', via: 'api', account: '', account_options: ['0x88', 'Samii'], title: 't', body: 'b', can_submit: false });
  win.apiPost = async (p, b) => { calls.post.push([p, b]); return { submitted: true, url: 'u' }; };
  win.uiConfirm = async () => true;
  assert.equal(await win.FindingsPage.submitFinding(9), true);
  const sent = calls.post.pop();
  assert.equal(sent[0], '/api/findings/9/submit');
  assert.equal(sent[1].account_label, 'Samii');
});

test('reminders: a set reminder shows a badge, due shows due, and the control + filter work', async () => {
  const now = Math.floor(Date.now() / 1000);
  const items = [
    { id: 1, title: 'soon', status: 'drafted', remind_at: now + 30 * 86400 },
    { id: 2, title: 'overdue', status: 'drafted', remind_at: now - 3600 },
    { id: 3, title: 'none', status: 'drafted' },
  ];
  const { win, els, calls } = load(items);
  await win.loadFindingsPage();
  const html = els['fx-results'].innerHTML;
  assertInert(html);
  assert.match(html, /class="fx-remind" title="Reminder:[^"]*">⏰ 30d<\/span>/);
  assert.match(html, /class="fx-remind due" title="Reminder:[^"]*">⏰ due<\/span>/);
  // Exactly two reminder badges (ids 1 and 2; id 3 has none).
  assert.equal((html.match(/class="fx-remind/g) || []).length, 2);
  // The control POSTs the chosen days; clearing posts 0.
  win.apiPost = async (p, b) => { calls.post.push([p, b]); return { remind_at: now + 60 * 86400 }; };
  assert.equal(await win.FindingsPage.remind(1, 60), true);
  let sent = calls.post.pop();
  assert.equal(sent[0], '/api/findings/1/remind');
  assert.equal(sent[1].days, 60);
  assert.equal(await win.FindingsPage.remind(1, 0), true);
  assert.equal(calls.post.pop()[1].days, 0);
  // The "due" filter adds remind=due to the query.
  win.FindingsPage.state.remind = 'due';
  await win.loadFindingsPage();
  const last = calls.fetch.filter((p) => p.startsWith('/api/findings?')).pop();
  assert.ok(last.includes('remind=due'), last);
});

test('pager: numbered pages, page size, and the offset sent to the API', async () => {
  const items = Array.from({ length: 50 }, (_, i) => ({ id: i + 1, title: 't' + i, status: 'discovered', severity: 'low', module: 'nuclei' }));
  const { win, els, calls } = load(items, { total: 1234 });
  await win.loadFindingsPage();
  const top = els['fx-pager-top'].innerHTML;
  assert.equal(top, els['fx-pager'].innerHTML, 'the same pager sits above and below the table');
  assert.match(top, /1–50 of 1234/);
  assert.match(top, /data-fx-goto="1" aria-current="page" disabled>1</);
  assert.match(top, /data-fx-goto="25"[^>]*>25</, 'last page is offered');
  assert.match(top, /<option value="50" selected>50<\/option>/);
  assert.ok(calls.fetch.some((p) => p.includes('limit=50') && p.includes('offset=0')));
  await win.FindingsPage.goToPage(4);
  assert.ok(calls.fetch.some((p) => p.includes('offset=150')), calls.fetch.join(' '));
  await win.FindingsPage.goToPage(99);
  assert.ok(calls.fetch.some((p) => p.includes('offset=1200')), 'clamped to the last page');
});

test('program / platform / report-link filters come from the facets and reach the API', async () => {
  const facets = { total: 9, ai: {}, status: {}, platforms: { h1: 7, bc: 2 }, no_program: 4, reported: 3,
    programs: [{ platform: 'h1', program: 'alibaba', count: 6 }, { platform: 'bc', program: EVIL, count: 1 }] };
  const { win, els, calls } = load([{ id: 1, title: 't', status: 'discovered' }], { facets });
  await win.loadFindingsPage();
  const prog = els['fx-program-list'].innerHTML;
  assertInert(prog);
  assert.match(prog, /<option value="No program" label="4 findings"><\/option>/);
  assert.match(prog, /<option value="h1 alibaba" label="6 findings"><\/option>/);
  assert.match(els['fx-platform-filter'].innerHTML, /<option value="h1">HackerOne \(7\)<\/option>/);
  assert.match(els['fx-report-filter'].innerHTML, /Has report link \(3\)/);
  Object.assign(win.FindingsPage.state, { platform: 'h1', program: 'alibaba', report: '1' });
  await win.loadFindingsPage();
  const last = calls.fetch.filter((p) => p.startsWith('/api/findings?')).pop();
  assert.ok(last.includes('program=alibaba') && last.includes('platform=h1') && last.includes('report=1'), last);
});

test('the program filter is a search box: whole names apply as you type, Enter takes a unique partial match', async () => {
  const facets = { total: 12, ai: {}, status: {}, platforms: { h1: 9, ywh: 2, bc: 1 }, no_program: 4,
    programs: [{ platform: 'h1', program: 'alibaba', count: 6 }, { platform: 'ywh', program: 'alibaba', count: 2 },
      { platform: 'h1', program: 'sea', count: 3 }, { platform: 'bc', program: EVIL, count: 1 }] };
  const { win, els, calls } = load([{ id: 1, title: 't', status: 'discovered' }], { facets });
  await win.loadFindingsPage();
  const st = win.FindingsPage.state;
  const input = els['fx-program-filter'];
  const apply = (v, final) => { input.value = v; return win.FindingsPage.applyProgramSearch(input, final); };
  assertInert(els['fx-program-list'].innerHTML);
  assert.equal(input.value, '');
  // Part of a name: nothing while typing; Enter needs a single match.
  assert.equal(apply('ali', false), false);
  assert.equal(apply('ali', true), false);
  assert.equal(input['attr:aria-invalid'], 'true');
  assert.match(input.title, /2 programs match/);
  assert.equal(st.program, '');
  // A whole name (any case) applies while typing, with its platform.
  assert.equal(apply('H1 Alibaba', false), true);
  assert.deepEqual([st.platform, st.program, input.value, input['attr:aria-invalid']], ['h1', 'alibaba', 'h1 alibaba', 'false']);
  assert.equal(apply('se', true), true);
  assert.deepEqual([st.platform, st.program, input.value], ['h1', 'sea', 'h1 sea']);
  await win.loadFindingsPage();
  const last = calls.fetch.filter((p) => p.startsWith('/api/findings?')).pop();
  assert.ok(last.includes('program=sea') && last.includes('platform=h1'), last);
  assert.equal(input.value, 'h1 sea', 'the box shows the active program after a reload');
  // No match keeps the current filter.
  assert.equal(apply('zzz', true), false);
  assert.match(input.title, /No program matches/);
  assert.equal(st.program, 'sea');
  assert.equal(apply('no program', false), true);
  assert.deepEqual([st.platform, st.program], ['', '__none__']);
  // Clearing the box shows every program and drops the platform it picked.
  apply('h1 sea', false);
  assert.equal(apply('', false), true);
  assert.deepEqual([st.platform, st.program], ['', '']);
  // A platform picked by hand stays when the program is cleared.
  Object.assign(st, { platform: 'ywh', platformFromProgram: false });
  assert.equal(apply('', false), false);
  assert.equal(st.platform, 'ywh');
});

test('report links: http(s) is a link, anything else is text; adding one uses the in-page dialog', async () => {
  const items = [
    { id: 1, title: 'a', status: 'submitted', report_ref: 'https://hackerone.com/reports/2401337' },
    { id: 2, title: 'b', status: 'submitted', report_ref: 'javascript:alert(1)' },
    { id: 3, title: 'c', status: 'submitted', report_ref: 'H1#99' },
    { id: 4, title: 'd', status: 'discovered' },
  ];
  const { win, els, calls } = load(items, { promptAnswer: ' https://bugcrowd.com/submissions/x ' });
  await win.loadFindingsPage();
  const html = els['fx-results'].innerHTML;
  assertInert(html);
  assert.match(html, /<a class="fx-reflink" href="https:\/\/hackerone.com\/reports\/2401337" target="_blank" rel="noopener noreferrer"/);
  assert.match(html, /<span class="fx-reflink" title="Report">javascript:alert\(1\)<\/span>/);
  assert.match(html, /<span class="fx-reflink" title="Report">H1#99<\/span>/);
  assert.match(html, /data-fx-reflink="4"[^>]*>Add link</);
  assert.match(html, /data-fx-reflink="1"[^>]*>Edit link</);
  assert.equal(await win.FindingsPage.editReportLink(4, ''), 'https://bugcrowd.com/submissions/x');
  assert.equal(JSON.stringify(calls.patch.pop()), JSON.stringify(['/api/findings/4', { report_ref: 'https://bugcrowd.com/submissions/x' }]));
  // Marking Submitted asks for the link in the page (native prompt() throws here).
  assert.equal(await win.FindingsPage.setStatus(4, 'submitted'), true);
  assert.equal(JSON.stringify(calls.patch.pop()), JSON.stringify(['/api/findings/4', { status: 'submitted', report_ref: 'https://bugcrowd.com/submissions/x' }]));
  assert.ok(calls.prompt.length >= 2);
});

test('cancelling the report-link dialog changes nothing', async () => {
  const { win, calls } = load([{ id: 4, title: 'd', status: 'discovered' }]);
  await win.loadFindingsPage();
  assert.equal(await win.FindingsPage.editReportLink(4, ''), null);
  assert.equal(await win.FindingsPage.setStatus(4, 'submitted'), false);
  assert.equal(calls.patch.length, 0);
});

test('closed findings are hidden by default; the toggle shows how many and brings them back', async () => {
  const facets = { total: 4, ai: {}, status: {}, closed: 2110 };
  let { win, els, calls } = load([{ id: 1, title: 't', status: 'discovered' }], { facets });
  await win.loadFindingsPage();
  const first = calls.fetch.filter((p) => p.startsWith('/api/findings?')).pop();
  assert.ok(first.includes('closed=0'), first);
  const tog = els['fx-closed-toggle'];
  assert.equal(tog.hidden, false);
  assert.match(tog.innerHTML, /Show closed <b>2,110<\/b>/);
  win.FindingsPage.state.showClosed = true;
  await win.loadFindingsPage();
  const second = calls.fetch.filter((p) => p.startsWith('/api/findings?')).pop();
  assert.ok(!second.includes('closed='), second);
  assert.match(tog.innerHTML, /Hide closed/);
  // Filtering by a closed status shows them whatever the toggle says.
  Object.assign(win.FindingsPage.state, { showClosed: false, status: 'rejected' });
  await win.loadFindingsPage();
  assert.equal(tog.disabled, true);
  ({ win, els } = load([{ id: 1, title: 't', status: 'discovered' }], { facets: { total: 1, ai: {}, status: {}, closed: 0 } }));
  await win.loadFindingsPage();
  assert.equal(els['fx-closed-toggle'].hidden, true, 'nothing closed: no toggle');
});

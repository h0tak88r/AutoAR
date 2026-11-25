const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const repoRoot = path.resolve(__dirname, '../..');
const EVIL = '<img src=x onerror=alert(1)>';

function load(data, role = 'admin') {
  const el = { innerHTML: '' };
  const posts = [];
  const context = {
    console, Date, Map, Math, Number, String,
    document: { getElementById: (id) => (id === 'programs-autopilot' ? el : null), addEventListener() {} },
    window: {},
  };
  context.window = {
    state: { _me: { role } },
    esc: (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])),
    apiFetch: async () => data,
    apiPost: async (p, b) => { posts.push([p, b]); return {}; },
    showToast() {},
  };
  vm.createContext(context);
  const rel = 'internal/api/ui/pages/scope-autopilot.js';
  vm.runInContext(fs.readFileSync(path.join(repoRoot, rel), 'utf8'), context, { filename: rel });
  return { win: context.window, el, posts };
}

function assertInert(html) {
  assert.doesNotMatch(html, /<(img|svg|iframe|script)\b/i, 'injected element');
  for (const tag of html.match(/<[a-z][^>]*>/gi) || []) {
    assert.doesNotMatch(tag.replace(/"[^"]*"/g, '""'), /\son[a-z]+\s*=/i, tag);
  }
}

const DATA = {
  ai: true, launched_today: 3, programs_tracked: 812,
  config: { enabled: true, platforms: ['h1', 'bc', 'ywh'], daily_max: 12, max_assets_per_update: 3 },
  runs: [
    { id: 3, event_id: 'e1', program_name: EVIL, platform: 'h1', offers_bounty: true, asset: `pay.${EVIL}.com`, scan_type: 'nuclei_target:cves', status: 'reviewed" onmouseover="x', planned_by: 'ai', findings: 2, insight: `Grafana ${EVIL}`, reason: EVIL },
    { id: 2, event_id: 'e1', program_name: EVIL, platform: 'h1', offers_bounty: true, asset: 'pay.acme.com', scan_type: 'subdomain_run', status: 'reviewed', planned_by: 'ai', findings: 2, insight: `Grafana ${EVIL}` },
    { id: 1, event_id: 'e0', program_name: 'Acme', platform: 'bc', asset: 'com.acme.app', status: 'skipped', reason: 'mobile app — not scanned automatically', planned_by: 'rules' },
  ],
};

test('the panel groups runs per asset and keeps hostile text inert', async () => {
  const { win, el } = load(DATA);
  await win.loadScopeAutopilot();
  const html = el.innerHTML;
  assertInert(html);
  assert.match(html, /HackerOne · bounty/);
  assert.match(html, /3\/12 scans today/);
  assert.equal((html.match(/class="ap-scans"/g) || []).length, 2, 'two events (one per asset)');
  for (const v of [...html.matchAll(/data-ap="([^"]*)"/g)].map((m) => m[1])) {
    assert.ok(['', 'planned', 'launched', 'finished', 'reviewed', 'failed', 'skipped'].includes(v), `data-ap="${v}"`);
  }
  assert.match(html, /data-ap-toggle="1" aria-pressed="true"/);
});

test('members see the state but no toggle', async () => {
  const { win, el } = load(DATA, 'member');
  await win.loadScopeAutopilot();
  assert.doesNotMatch(el.innerHTML, /data-ap-toggle/);
});

test('an empty history explains what will appear', async () => {
  const { win, el } = load({ ...DATA, runs: [] });
  await win.loadScopeAutopilot();
  assert.match(el.innerHTML, /No new assets since the autopilot started/);
});

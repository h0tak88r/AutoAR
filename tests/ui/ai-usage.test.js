const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const repoRoot = path.resolve(__dirname, '../..');

function load() {
  const els = {};
  for (const id of ['ai-usage-card', 'ai-usage-body', 'ai-usage-meta']) {
    els[id] = { id, innerHTML: '', textContent: '', hidden: true, clientWidth: 900, querySelector: () => null, querySelectorAll: () => [] };
  }
  const context = {
    console, Date, Math, Number, String, Set,
    document: { getElementById: (id) => els[id] || null },
    window: {
      addEventListener() {},
      state: { _me: { role: 'admin' } },
      esc: (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])),
    },
  };
  vm.createContext(context);
  const rel = 'internal/api/ui/pages/ai-usage.js';
  vm.runInContext(fs.readFileSync(path.join(repoRoot, rel), 'utf8'), context, { filename: rel });
  return { win: context.window, els };
}

const day = (d, calls, cost) => ({ day: d, calls, errors: 0, prompt_tokens: calls * 1000, cache_hit_tokens: calls * 400, completion_tokens: calls * 200, cost_usd: cost, unpriced_calls: 0 });
const BASE = {
  provider: { id: 'deepseek', name: 'DeepSeek (official)', model: 'deepseek-flash', configured: true },
  totals: {
    today: { calls: 3, errors: 0, prompt_tokens: 3000, cache_hit_tokens: 1200, completion_tokens: 600, cost_usd: 0.0021, unpriced_calls: 0 },
    '7d': {}, '30d': { calls: 40, errors: 2, prompt_tokens: 40000, cache_hit_tokens: 20000, completion_tokens: 8000, cost_usd: 0.0315, unpriced_calls: 0 },
    all: { calls: 40, errors: 2, prompt_tokens: 40000, cache_hit_tokens: 20000, completion_tokens: 8000, cost_usd: 0.0315, unpriced_calls: 0 },
  },
  daily: [day('2026-10-16', 37, 0.0294), day('2026-10-17', 3, 0.0021)],
  by_feature: [{ key: 'triage', calls: 30, errors: 2, prompt_tokens: 30000, cache_hit_tokens: 15000, completion_tokens: 6000, cost_usd: 0.025 }],
  tracking_since: 1792195200,
  pricing: { source: 'x', checked: '2026-10-17', peak_now: false, now: { cache_hit: 0.003, cache_miss: 0.15, output: 0.6 } },
  balance: { available: true, infos: [{ currency: 'USD', total: '9.87', granted: '0.00', topped_up: '9.87' }] },
};

test('money keeps small amounts visible instead of rounding to $0.00', () => {
  const { win } = load();
  const u = win.AIUsagePage.usd;
  assert.equal(u(0), '$0.00');
  assert.equal(u(0.0021), '$0.0021');
  assert.equal(u(0.315), '$0.315');
  assert.equal(u(12.5), '$12.50');
  assert.equal(win.AIUsagePage.compact(1530000), '1.5M');
});

test('renders tiles, balance, chart and feature breakdown', () => {
  const { win, els } = load();
  win.AIUsagePage.render(BASE);
  const html = els['ai-usage-body'].innerHTML;
  assert.ok(html.includes('$0.0021'), 'today');
  assert.ok(html.includes('$0.0315'), '30 days');
  assert.ok(html.includes('$9.87'), 'live balance');
  assert.ok(html.includes('AI Triage') && html.includes('(2 failed)'));
  assert.equal((html.match(/class="au-col"/g) || []).length, 2, 'one hover column per day');
  assert.ok(html.includes('<details class="au-details"><summary>Daily table'), 'table view exists');
  assert.match(els['ai-usage-meta'].textContent, /off-peak now: \$0\.15 in \/ \$0\.6 out per 1M/);
});

test('hostile provider/balance/error strings stay inert', () => {
  const { win, els } = load();
  const evil = '<img src=x onerror=alert(1)>';
  win.AIUsagePage.render({
    ...BASE,
    provider: { id: 'deepseek', name: evil, model: evil },
    balance: { available: false, infos: [{ currency: evil, total: evil, granted: evil, topped_up: evil }] },
    by_feature: [{ key: evil, calls: 1 }],
  });
  const html = els['ai-usage-body'].innerHTML;
  assert.doesNotMatch(html, /<img/i);
  assert.ok(html.includes('Too low for API calls'), 'unavailable balance is flagged');
  assert.equal(els['ai-usage-meta'].innerHTML, '', 'meta is set via textContent, never innerHTML');

  win.AIUsagePage.render({ ...BASE, balance: null, balance_error: evil });
  assert.doesNotMatch(els['ai-usage-body'].innerHTML, /<img/i);
});

test('unpriced calls are called out, not silently dropped', () => {
  const { win, els } = load();
  win.AIUsagePage.render({ ...BASE, totals: { ...BASE.totals, '30d': { ...BASE.totals['30d'], unpriced_calls: 4 } } });
  assert.match(els['ai-usage-body'].innerHTML, /4 calls have no list price/);
});

test('members never see the card', async () => {
  const { win, els } = load();
  win.state._me = { role: 'member' };
  win.apiFetch = async () => { throw new Error('must not be called'); };
  await win.loadAIUsage();
  assert.equal(els['ai-usage-card'].hidden, true);
});

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const repoRoot = path.resolve(__dirname, '../..');

// Scan titles/descriptions come from operators AND from the MCP agent (which
// may echo target content), so every place that renders them must escape.
function load() {
  const context = {
    console, Date, Math, Number, String, JSON, Set, Object, Array,
    document: { getElementById: () => null, addEventListener() {} },
    window: {},
  };
  context.window = {
    state: { scans: { active_scans: [], recent_scans: [] }, scanListUI: {}, error: {} },
    esc: (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])),
    scanTypeLabel: (t) => ({ nuclei: 'Nuclei', domain_run: 'Full Domain' }[t] || t),
    fmtDate: () => 'date',
    statusBadge: (st) => `<span class="badge">${st}</span>`,
    addEventListener() {},
  };
  vm.createContext(context);
  for (const rel of ['internal/api/ui/pages/scan-meta.js', 'internal/api/ui/pages/scans-page.js']) {
    vm.runInContext(fs.readFileSync(path.join(repoRoot, rel), 'utf8'), context, { filename: rel });
  }
  return context.window;
}

const EVIL = '<img src=x onerror=alert(1)>';

test('title falls back to "<Type> · <target>" and names the global target', () => {
  const w = load();
  assert.equal(w.scanTitle({ scan_type: 'nuclei', target: 'global-subdomains' }), 'Nuclei · all subdomains');
  assert.equal(w.scanTitle({ scan_type: 'domain_run', target: 'example.com' }), 'Full Domain · example.com');
  assert.equal(w.scanTitle({ scan_type: 'nuclei', target: 'global-subdomains', name: '  Smarty sweep ' }), 'Smarty sweep');
  assert.equal(w.scanDescription({ description: ' why \n' }), 'why');
});

test('active scan card shows title, target and description as inert text', () => {
  const w = load();
  const html = w.ScansPage.scanItemHtml({
    scan_id: 's1', scan_type: 'nuclei', target: EVIL, status: 'running', name: EVIL, description: EVIL,
    started_at: new Date().toISOString(), created_by: EVIL,
  });
  assert.doesNotMatch(html, /<img/i);
  assert.ok(html.includes('class="scan-title">&lt;img'), 'title rendered escaped');
  assert.ok(html.includes('class="scan-desc"'), 'description shown');
  assert.ok(html.includes('data-scan-action="edit"'), 'running scans can be renamed from the card');
});

test('auto-titled card drops the duplicate type chip; custom titles keep it', () => {
  const w = load();
  const auto = w.ScansPage.scanItemHtml({ scan_id: 's', scan_type: 'nuclei', target: 'global-subdomains', status: 'running' });
  assert.ok(!auto.includes('scan-type-chip'), 'title already says Nuclei');
  const named = w.ScansPage.scanItemHtml({ scan_id: 's', scan_type: 'nuclei', target: 'global-subdomains', status: 'running', name: 'Smarty' });
  assert.ok(named.includes('scan-type-chip'));
});

test('recent scans row shows title over target and escapes everything', () => {
  const w = load();
  const html = w.ScansPage.scanRowHtml({
    scan_id: 's2', scan_type: 'nuclei', target: 'global-subdomains', status: 'completed', name: EVIL, description: EVIL,
    started_at: new Date().toISOString(),
  });
  assert.doesNotMatch(html, /<img/i);
  assert.ok(html.includes('class="scan-row-title">&lt;img'));
  assert.ok(html.includes('class="scan-row-target">global-subdomains'));
});

test('type labels carry no leading space (emoji-strip leftover)', () => {
  const w = load();
  for (const t of ['nuclei', 'domain_run', 'recon', 'ports']) {
    const label = w.ScansPage.scanTypeLabel(t);
    assert.equal(label, label.trim(), `"${label}" for ${t}`);
  }
});

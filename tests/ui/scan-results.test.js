const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const repoRoot = path.resolve(__dirname, '../..');

function loadBrowserScripts() {
  const context = {
    console,
    Blob,
    URL,
    setTimeout,
    clearTimeout,
    window: {},
    document: {
      getElementById: () => null,
      querySelectorAll: () => [],
      createElement: () => ({ style: {}, appendChild() {}, click() {}, remove() {} }),
      body: { appendChild() {} },
    },
  };

  context.window = {
    state: { scanDetailUI: {} },
    esc: (value) => String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;'),
    escAttr: (value) => String(value ?? ''),
    apiFetch: async () => ({}),
    apiPost: async () => ({}),
    navigateTo: () => {},
    showToast: () => {},
    fmtSize: (n) => `${n || 0} B`,
    copyToClipboard: async () => {},
    previewDataToFlatRows: () => [],
    categorizeScanArtifactFile: () => 'output',
    getUnifiedTableColumns: () => [],
    renderRowForUnifiedTab: () => '',
    renderDefaultRow: () => '',
    renderResultTable: (items, resultType) => `<table data-type="${resultType}">${items.length}</table>`,
  };

  vm.createContext(context);
  for (const rel of [
    'internal/api/ui/pages/scan-common.js',
    'internal/api/ui/pages/scan-results-core.js',
    'internal/api/ui/pages/scan-detail.js',
  ]) {
    const code = fs.readFileSync(path.join(repoRoot, rel), 'utf8');
    vm.runInContext(code, context, { filename: rel });
  }
  return context.window;
}

test('manifest card renders API module and started_at fields', () => {
  const window = loadBrowserScripts();
  const html = window.ScanDetailPage.renderScanManifestCard({
    modules: [
      {
        module: 'nuclei',
        status: 'completed',
        started_at: '2026-05-03T08:00:00Z',
        duration_ms: 1500,
        output_files: ['nuclei-results.json'],
      },
    ],
  }, { status: 'completed' });

  assert.match(html, /nuclei/);
  assert.match(html, /completed/);
  assert.match(html, /1 file/);
  assert.doesNotMatch(html, /undefined/);
});

test('manifest labels completed phase with no files as empty, not broken', () => {
  const window = loadBrowserScripts();

  assert.equal(
    window.ScanDetailPage.manifestArtifactLabel({ status: 'completed', output_files: [] }),
    '0 files (empty)',
  );
  assert.equal(
    window.ScanDetailPage.manifestArtifactLabel({ status: 'failed', output_files: [] }),
    '0 files (failed)',
  );
  assert.equal(
    window.ScanDetailPage.manifestArtifactLabel({ status: 'pending', output_files: [] }),
    'not run',
  );
});

test('result parser shows empty-file state separately from fetch errors', async () => {
  const window = loadBrowserScripts();
  const container = { innerHTML: '' };

  window.apiFetch = async () => ({ format: 'json-array', items: [] });
  await window.ScanResultsCorePage.parseAndRenderResults('scan-1', { file_name: 'nuclei-results.json', module: 'nuclei' }, container);
  assert.match(container.innerHTML, /No parseable results/);

  window.apiFetch = async () => {
    throw new Error('network down');
  };
  await window.ScanResultsCorePage.parseAndRenderResults('scan-1', { file_name: 'nuclei-results.json', module: 'nuclei' }, container);
  assert.match(container.innerHTML, /Error loading results/);
  assert.match(container.innerHTML, /network down/);
});

test('module detection covers subdomain workflow artifacts', () => {
  const window = loadBrowserScripts();
  const detectModuleFromFileName = window.ScanCommonPage.detectModuleFromFileName;

  assert.equal(detectModuleFromFileName('live-subs.txt'), 'httpx');
  assert.equal(detectModuleFromFileName('nuclei-results.json'), 'nuclei');
  assert.equal(detectModuleFromFileName('gf-xss.txt'), 'gf-patterns');
  assert.equal(detectModuleFromFileName('s3-buckets.txt'), 's3-scan');
  assert.equal(detectModuleFromFileName('tech-detect.json'), 'tech-detect');
  assert.equal(detectModuleFromFileName('wp-confusion-vulnerabilities.json'), 'wordpress-confusion');
  assert.equal(detectModuleFromFileName('depconfusion-vulnerabilities.json'), 'dependency-confusion');
});

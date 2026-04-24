/**
 * AutoAR Dashboard — app.js
 * Vanilla JS SPA: router, data fetching, component rendering
 * Bundle: v4.0 — dashboard UI; scan merge, R2, monitors, auth
 */

// ── Constants ─────────────────────────────────────────────────────────────────

const API = '';          // same origin
const POLL_INTERVAL = 15000; // idle refresh
const POLL_FAST_SCANS = 3500; // Scans view while workers are active
const POLL_FAST_ANY = 7000;   // any view while ≥1 active scan
const BASE = '/ui';

// Scan detail real-time refresh state (declared early so openScanResultsPage can use them)
let _scanDetailRefreshTimer = null;
let _scanDetailRefreshId = null;
let _scanDetailKnownFiles = new Set();
let _assetsCache = null;


/** Maps launcher <select> values → POST /scan/:path body shape (must match api.go handlers). */
const LAUNCH_SCAN_TYPES = {
  domain_scan: { path: 'domain_run', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  subdomain_scan: { path: 'subdomain_run', modes: ['subdomain', 'subdomain_list'], placeholders: { subdomain: 'api.example.com', subdomain_list: 'one subdomain per line' } },
  lite: { path: 'lite', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  recon: { path: 'recon', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  subdomains: { path: 'subdomains', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  livehosts: { path: 'livehosts', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  urls: { path: 'urls', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  cnames: { path: 'cnames', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  js: { path: 'js', modes: ['domain', 'subdomain', 'domain_list', 'subdomain_list'], placeholders: { domain: 'example.com', subdomain: 'api.example.com', domain_list: 'one domain per line', subdomain_list: 'one subdomain per line' } },
  reflection: { path: 'reflection', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  nuclei: { path: 'nuclei', modes: ['domain', 'subdomain', 'url', 'domain_list', 'subdomain_list', 'url_list'], placeholders: { domain: 'example.com', subdomain: 'api.example.com', url: 'https://target.tld/', domain_list: 'one domain per line', subdomain_list: 'one subdomain per line', url_list: 'one URL per line' } },
  tech: { path: 'tech', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  ports: { path: 'ports', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  gf: { path: 'gf', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  backup: { path: 'backup', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  misconfig: { path: 'misconfig', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  dns: { path: 'dns', modes: ['domain', 'domain_list'], extra: { dns_type: 'takeover' }, placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  dns_dangling: { path: 'dns', modes: ['domain', 'domain_list'], extra: { dns_type: 'dangling-ip' }, placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  dns_takeover: { path: 'dns-takeover', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  dns_cf1016: { path: 'dns-cf1016', modes: ['domain', 'subdomain', 'domain_list', 'subdomain_list'], placeholders: { domain: 'example.com', subdomain: 'api.example.com', domain_list: 'one domain per line', subdomain_list: 'one subdomain per line' } },
  s3: { path: 's3', modes: ['bucket', 'bucket_list'], placeholders: { bucket: 'bucket-name', bucket_list: 'one bucket per line' } },
  github: { path: 'github', modes: ['repo', 'repo_list'], placeholders: { repo: 'owner/repository', repo_list: 'one owner/repo per line' } },
  github_org: { path: 'github_org', modes: ['repo', 'repo_list'], placeholders: { repo: 'org-name', repo_list: 'one org per line' } },
  zerodays: { path: 'zerodays', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  ffuf: { path: 'ffuf', modes: ['target', 'target_list'], placeholders: { target: 'https://example.com/FUZZ', target_list: 'one FUZZ URL per line' } },
  jwt: { path: 'jwt', modes: ['token'], placeholders: { token: 'JWT token' } },
  apkx: { path: 'apkx', modes: ['file_path', 'package_id', 'upload'], placeholders: { file_path: '/absolute/path/to/app.apk', package_id: 'com.example.app', upload: 'Click to upload APK/IPA' } },
};

const LAUNCH_MODE_LABELS = {
  domain: 'Domain',
  subdomain: 'Subdomain',
  url: 'URL',
  target: 'Target URL',
  repo: 'Repository / Org',
  bucket: 'Bucket',
  token: 'Token',
  file_path: 'File path',
  domain_list: 'Domain list',
  subdomain_list: 'Subdomain list',
  url_list: 'URL list',
  target_list: 'Target list',
  repo_list: 'Repo/Org list',
  bucket_list: 'Bucket list',
  package_id: 'Package ID',
  upload: 'Direct Upload',
};

const SCAN_FLAG_DEFS = {
  domain_scan: [{ key: 'skip_ffuf', label: 'Skip FFuf', type: 'bool', advanced: false }],
  lite: [
    { key: 'skip_js', label: 'Skip JS phase', type: 'bool', advanced: false },
    { key: 'phase_timeout', label: 'Phase timeout (sec)', type: 'number', min: 60, advanced: false },
    { key: 'timeout_livehosts', label: 'Livehosts timeout (sec)', type: 'number', min: 0, advanced: true },
    { key: 'timeout_reflection', label: 'Reflection timeout (sec)', type: 'number', min: 0, advanced: true },
    { key: 'timeout_js', label: 'JS timeout (sec)', type: 'number', min: 0, advanced: true },
    { key: 'timeout_nuclei', label: 'Nuclei timeout (sec)', type: 'number', min: 0, advanced: true },
  ],
  nuclei: [
    { key: 'mode', label: 'Mode', type: 'select', options: ['full', 'cves', 'panels', 'default-logins', 'vulnerabilities'], advanced: false },
  ],
  dns: [
    { key: 'dns_type', label: 'DNS type', type: 'select', options: ['takeover', 'dangling-ip'], advanced: false },
  ],
  dns_dangling: [
    { key: 'dns_type', label: 'DNS type', type: 'select', options: ['dangling-ip', 'takeover'], advanced: false },
  ],
  ffuf: [
    { key: 'threads', label: 'Threads', type: 'number', min: 1, advanced: false },
    { key: 'recursion', label: 'Enable recursion', type: 'bool', advanced: false },
    { key: 'recursion_depth', label: 'Recursion depth', type: 'number', min: 1, advanced: true },
    { key: 'bypass_403', label: 'Bypass 403 checks', type: 'bool', advanced: true },
    { key: 'extensions', label: 'Extensions (csv)', type: 'text', advanced: true },
    { key: 'wordlist', label: 'Wordlist path', type: 'text', advanced: true },
  ],
  zerodays: [
    { key: 'threads', label: 'Threads', type: 'number', min: 1, advanced: false },
    { key: 'dos_test', label: 'Enable DoS test', type: 'bool', advanced: true },
    { key: 'enable_source_exposure', label: 'Enable source exposure', type: 'bool', advanced: true },
    { key: 'silent', label: 'Silent mode', type: 'bool', advanced: true },
    { key: 'cves', label: 'CVEs (csv)', type: 'text', advanced: true },
    { key: 'mongodb_host', label: 'MongoDB host', type: 'text', advanced: true },
    { key: 'mongodb_port', label: 'MongoDB port', type: 'number', min: 1, advanced: true },
  ],
  jwt: [
    { key: 'skip_crack', label: 'Skip crack', type: 'bool', advanced: false },
    { key: 'skip_payloads', label: 'Skip payloads', type: 'bool', advanced: false },
    { key: 'wordlist_path', label: 'Wordlist path', type: 'text', advanced: true },
    { key: 'max_crack_attempts', label: 'Max crack attempts', type: 'number', min: 1, advanced: true },
  ],
  backup: [{ key: 'threads', label: 'Threads', type: 'number', min: 1, advanced: false }],
  misconfig: [
    { key: 'service_id', label: 'Service filter', type: 'text', advanced: false },
    { key: 'delay', label: 'Delay ms', type: 'number', min: 0, advanced: true },
    { key: 'permutations', label: 'Enable permutations', type: 'bool', advanced: true },
  ],
  apkx: [
    { key: 'mitm', label: 'MITM Analysis', type: 'bool', advanced: false },
    { key: 'platform', label: 'Platform', type: 'select', options: ['android', 'ios'], advanced: false },
  ],
};

// ── Utilities ─────────────────────────────────────────────────────────────────

async function copyToClipboard(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch (e) { }
  }

  // Fallback
  const textArea = document.createElement('textarea');
  textArea.value = text;
  // Position out of view
  textArea.style.position = 'fixed';
  textArea.style.top = '0';
  textArea.style.left = '0';
  textArea.style.opacity = '0';
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();
  try {
    const successful = document.execCommand('copy');
    if (!successful) throw new Error('execCommand returned false');
  } finally {
    document.body.removeChild(textArea);
  }
}

// ── State ─────────────────────────────────────────────────────────────────────

const state = {
  view: 'overview',
  config: null,
  stats: null,
  domains: [],
  scans: { active_scans: [], recent_scans: [] },
  monitorTargets: [],
  subMonitorTargets: [],
  monitorChanges: [],
  r2: { prefix: '', dirs: [], files: [] },
  selectedDomain: null,
  subdomains: [],
  loading: {},   // keyed by resource name
  error: {},
  scanType: 'lite',
  scanTarget: '',
  pollTimer: null,
  /** UUID scan id when view === 'scan-detail' */
  scanDetailId: null,
  /** Pagination + selection for /scans/:id page */
  scanDetailUI: { filesPage: 1, filesPerPage: 200, previewPage: 1, previewPerPage: 100, selectedFileName: null },
  /** Filters for the main /scans page */
  scanListUI: { search: '', statusFilter: 'all', typeFilter: 'all' },
  _sbClient: null,
  _authAccessToken: null,
  _sbAuthListener: false,
  _dashboardStarted: false,
  _shellWired: false,
  _r2BrowserWired: false,
  _metricsTimer: null,
  reportTemplateOriginalName: '',
};

// ── Router ────────────────────────────────────────────────────────────────────

const VIEWS = ['overview', 'scans', 'domains', 'subdomains', 'targets', 'keyhacks', 'monitor', 'r2', 'settings', 'report-templates'];

function pathScanId() {
  const m = String(location.pathname || '').match(/^\/scans\/([^/]+)\/?$/);
  return m ? decodeURIComponent(m[1]) : null;
}

function navigateTo(view) {
  const prev = state.view;
  state.view = view;
  if (view !== 'scan-detail') {
    state.scanDetailId = null;
    document.getElementById('view-scan-detail')?.classList.remove('active');
    if (prev === 'scan-detail' && /^\/scans\//.test(location.pathname)) {
      try { history.pushState({}, '', '/ui'); } catch (e) { /* ignore */ }
    }
  }
  VIEWS.forEach(v => {
    const el = document.getElementById(`view-${v}`);
    const nav = document.getElementById(`nav-${v}`);
    if (el) el.classList.toggle('active', v === view);
    if (nav) nav.classList.toggle('active', v === view);
  });
  document.getElementById('topbar-title').textContent = viewTitle(view);
  state.selectedDomain = null;
  refreshCurrentView();
  startPolling();
}

/** Deep-linked scan results page (/scans/:id). */
async function openScanResultsPage(scanId, opts = {}) {
  const { replace = false, noHistory = false } = opts;
  if (state.scanDetailId !== scanId) {
    state.scanDetailUI = { filesPage: 1, filesPerPage: 200, previewPage: 1, previewPerPage: 100, selectedFileName: null };
    // Reset real-time refresh state for the new scan
    clearScanDetailRefreshTimer();
    _scanDetailKnownFiles = new Set();
    _scanDetailRefreshId = scanId;
  }
  state.scanDetailId = scanId;
  state.view = 'scan-detail';
  VIEWS.forEach(v => {
    document.getElementById(`view-${v}`)?.classList.remove('active');
    document.getElementById(`nav-${v}`)?.classList.remove('active');
  });
  document.getElementById('view-scan-detail')?.classList.add('active');
  document.getElementById('topbar-title').textContent = 'Scan results';
  if (!noHistory) {
    const path = `/scans/${encodeURIComponent(scanId)}`;
    if (location.pathname !== path) {
      if (replace) history.replaceState({ scanId }, '', path);
      else history.pushState({ scanId }, '', path);
    }
  }
  await renderScanDetailView(scanId);
  startPolling();
}


function viewTitle(v) {
  return {
    overview: 'Overview', scans: 'Scans', domains: 'Domains', subdomains: 'Subdomains',
    targets: 'Bug Bounty Targets',
    keyhacks: 'Keyhacks',
    monitor: 'Monitor', r2: 'R2 Storage', settings: 'Settings',
    'report-templates': 'Report Templates'
  }[v] || v;
}

// ── API Helpers (Local JWT auth) ─────────────────────────────────────────────

const LOCAL_TOKEN_KEY = 'autoar_local_token';

function localTokenGet() {
  try { return localStorage.getItem(LOCAL_TOKEN_KEY) || null; } catch { return null; }
}
function localTokenSet(tok) {
  try { localStorage.setItem(LOCAL_TOKEN_KEY, tok); } catch { /* ignore */ }
}
function localTokenClear() {
  try { localStorage.removeItem(LOCAL_TOKEN_KEY); } catch { /* ignore */ }
}

async function buildAuthHeaders(extra = {}) {
  const h = { ...extra };
  if (state.config?.auth_enabled) {
    const tok = state._authAccessToken || localTokenGet();
    if (tok) h.Authorization = `Bearer ${tok}`;
  }
  return h;
}

function handleAuthError() {
  localTokenClear();
  state._authAccessToken = null;
  state._dashboardStarted = false;
  showAuthGate();
}

async function apiFetch(path) {
  const headers = await buildAuthHeaders();
  const res = await fetch(`${API}${path}`, { headers });
  if (res.status === 401 && state.config?.auth_enabled) {
    handleAuthError();
    throw new Error('Session expired — sign in again');
  }
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function apiPost(path, body, customHeaders = {}) {
  const headers = await buildAuthHeaders({ 'Content-Type': 'application/json', ...customHeaders });
  const res = await fetch(`${API}${path}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
  if (res.status === 401 && state.config?.auth_enabled) {
    handleAuthError();
    throw new Error('Session expired — sign in again');
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
    throw new Error(err.error || `HTTP ${res.status}`);
  }
  return res.json();
}

async function apiDelete(path) {
  const headers = await buildAuthHeaders();
  const res = await fetch(`${API}${path}`, { method: 'DELETE', headers });
  if (res.status === 401 && state.config?.auth_enabled) {
    handleAuthError();
    throw new Error('Session expired — sign in again');
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
    throw new Error(err.error || `HTTP ${res.status}`);
  }
  return res.json();
}

function showAuthGate(hintMsg) {
  const gate = document.getElementById('auth-gate');
  const shell = document.getElementById('app-shell');
  const hint = document.getElementById('auth-config-hint');
  if (hint && hintMsg) {
    hint.style.display = 'block';
    hint.textContent = hintMsg;
  }
  if (gate) gate.style.display = 'flex';
  if (shell) shell.style.display = 'none';
}

function hideAuthGate() {
  const gate = document.getElementById('auth-gate');
  const shell = document.getElementById('app-shell');
  if (gate) gate.style.display = 'none';
  if (shell) shell.style.display = '';
}

async function cancelScan(scanID) {
  if (!confirm('Stop this scan? The worker process will be killed.')) return;
  try {
    await apiPost(`/api/scans/${encodeURIComponent(scanID)}/cancel`, {});
    showToast('success', 'Scan stopped', '');
    loadStats();
    loadScans();
  } catch (e) {
    showToast('error', 'Could not stop scan', e.message);
  }
}

async function deleteScan(scanID, target = '') {
  const label = target ? ` for ${target}` : '';
  if (!confirm(`Delete this scan record${label} and remove its R2 indexed artifacts?`)) return;
  try {
    await apiDelete(`/api/scans/${encodeURIComponent(scanID)}`);
    showToast('success', 'Scan deleted', '');
    loadStats();
    loadScans();
  } catch (e) {
    showToast('error', 'Delete failed', e.message);
  }
}

async function rescanScan(scanID) {
  try {
    const result = await apiPost(`/api/scans/${encodeURIComponent(scanID)}/rescan`, {});
    showToast('success', '🔁 Rescan started', `New scan queued (ID: ${result.new_scan_id || ''})`);
    loadScans();
    if (result.new_scan_id) {
      setTimeout(() => goToScanResultsPage(result.new_scan_id), 900);
    }
  } catch (e) {
    showToast('error', 'Rescan failed', e.message);
  }
}

function toggleSelectAllRecentScans(master) {
  const on = master.checked;
  document.querySelectorAll('#recent-scans-table .scan-row-select').forEach(cb => { cb.checked = on; });
}

async function deleteSelectedScans() {
  const cbs = Array.from(document.querySelectorAll('#recent-scans-table .scan-row-select:checked'));
  const ids = cbs.map(cb => cb.getAttribute('data-scan-id')).filter(Boolean);
  if (!ids.length) {
    showToast('error', 'No scans selected', 'Check the rows you want to remove.');
    return;
  }
  if (!confirm(`Delete ${ids.length} scan record(s) and remove their indexed R2 artifacts?`)) return;
  try {
    const res = await apiPost('/api/scans/bulk-delete', { scan_ids: ids });
    let msg = `Removed ${res.deleted} scan(s).`;
    if (res.skipped_active) msg += ` ${res.skipped_active} skipped (still active).`;
    if (res.failed) msg += ` ${res.failed} failed.`;
    showToast(res.ok && !res.failed ? 'success' : 'error', res.ok ? 'Bulk delete done' : 'Some deletes failed', msg);
    loadStats();
    loadScans();
  } catch (e) {
    showToast('error', 'Bulk delete failed', e.message);
  }
}

async function clearAllScans() {
  if (!confirm('Delete all scan history? Active scans stay; finished scans are removed with their indexed R2 objects.')) return;
  try {
    const res = await apiPost('/api/scans/clear-all', {});
    let msg = `Removed ${res.deleted} scan(s).`;
    if (res.skipped_active) msg += ` ${res.skipped_active} active scan(s) were skipped.`;
    if (res.failed) msg += ` ${res.failed} failed.`;
    showToast(res.ok && !res.failed ? 'success' : 'error', 'Clear all', msg);
    loadStats();
    loadScans();
  } catch (e) {
    showToast('error', 'Clear all failed', e.message);
  }
}

async function deleteDomainRecord(domain) {
  if (!domain) return;
  if (!confirm(`Remove "${domain}" from the database? This deletes subdomains, related scans (and their R2 artifacts), monitor history for this root, and the subdomain monitor target if present.`)) return;
  try {
    await apiDelete(`/api/domains/${encodeURIComponent(domain)}`);
    showToast('success', 'Domain removed', domain);
    state.selectedDomain = null;
    const fb = document.getElementById('filter-bar-domains');
    if (fb) fb.style.display = '';
    loadStats();
    loadDomains();
    loadScans();
  } catch (e) {
    showToast('error', 'Could not delete domain', e.message);
  }
}

async function pauseScan(scanID) {
  try {
    await apiPost(`/api/scans/${encodeURIComponent(scanID)}/pause`, {});
    showToast('success', 'Scan paused', '');
    loadStats();
    loadScans();
  } catch (e) {
    showToast('error', 'Pause failed', e.message);
  }
}

async function resumeScan(scanID) {
  try {
    await apiPost(`/api/scans/${encodeURIComponent(scanID)}/resume`, {});
    showToast('success', 'Scan resumed', '');
    loadStats();
    loadScans();
  } catch (e) {
    showToast('error', 'Resume failed', e.message);
  }
}

async function loadResource(key, path, stateKey) {
  state.loading[key] = true;
  try {
    const data = await apiFetch(path);
    state[stateKey] = data;
    state.error[key] = null;
  } catch (e) {
    state.error[key] = e.message;
  } finally {
    state.loading[key] = false;
  }
}

// ── Data Loading ──────────────────────────────────────────────────────────────

async function loadConfig() {
  try {
    const res = await fetch(`${API}/api/config`);
    if (!res.ok) return;
    state.config = await res.json();
    renderSettings();
    updateStatusDot();
  } catch (e) { /* silent */ }
}

function wireAuthForm() {
  const form = document.getElementById('auth-form');
  if (!form || form.dataset.wired) return;
  form.dataset.wired = '1';
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const errEl = document.getElementById('auth-error');
    const submit = document.getElementById('auth-submit');
    if (errEl) errEl.textContent = '';
    const username = (document.getElementById('auth-username') || {}).value || '';
    const password = (document.getElementById('auth-password') || {}).value || '';
    if (submit) submit.disabled = true;
    try {
      const res = await fetch(`${API}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (!res.ok) {
        if (errEl) errEl.textContent = data.error || 'Login failed';
        return;
      }
      state._authAccessToken = data.token;
      localTokenSet(data.token);
      await startDashboard();
    } catch (err) {
      if (errEl) errEl.textContent = err.message || 'Network error';
    } finally {
      if (submit) submit.disabled = false;
    }
  });
}

function wireShellOnce() {
  if (state._shellWired) return;
  state._shellWired = true;

  VIEWS.forEach(v => {
    const el = document.getElementById(`nav-${v}`);
    if (el) el.addEventListener('click', () => navigateTo(v));
  });

  const refreshBtn = document.getElementById('refresh-btn');
  if (refreshBtn) refreshBtn.addEventListener('click', manualRefresh);

  const dsearch = document.getElementById('domain-search');
  if (dsearch) dsearch.addEventListener('input', renderDomainGrid);

  const ssearch = document.getElementById('subdomains-search');
  if (ssearch) {
    let subSearchDebounce;
    ssearch.addEventListener('input', (e) => {
      clearTimeout(subSearchDebounce);
      subSearchDebounce = setTimeout(() => loadSubdomains(1, e.target.value.trim()), 300);
    });
  }
  const copyAllSubsBtn = document.getElementById('copy-all-subs-btn');
  if (copyAllSubsBtn) copyAllSubsBtn.addEventListener('click', () => copyAllSubdomainsMatching());

  const launchBtn = document.getElementById('launch-btn');
  if (launchBtn) launchBtn.addEventListener('click', triggerScan);
  const launchType = document.getElementById('launch-type');
  const launchTargetMode = document.getElementById('launch-target-mode');
  if (launchType) {
    launchType.addEventListener('change', () => syncLaunchPlaceholder(true));
  }
  if (launchTargetMode) launchTargetMode.addEventListener('change', () => syncLaunchPlaceholder(false));
  const launchTarget = document.getElementById('launch-target');
  const launchTargetList = document.getElementById('launch-target-list');
  if (launchTarget) launchTarget.addEventListener('input', updateLaunchPreview);
  if (launchTargetList) launchTargetList.addEventListener('input', updateLaunchPreview);
  document.addEventListener('input', (e) => {
    if (e.target && e.target.matches('[data-flag-key]')) updateLaunchPreview();
  });
  document.addEventListener('change', (e) => {
    if (e.target && e.target.matches('[data-flag-key]')) updateLaunchPreview();
  });
  syncLaunchPlaceholder(true);

  const urlStrat = document.getElementById('monitor-url-strategy');
  if (urlStrat) urlStrat.addEventListener('change', syncMonitorUrlPatternVisibility);
  syncMonitorUrlPatternVisibility();

  const urlInput = document.getElementById('monitor-url-input');
  if (urlInput) {
    urlInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        quickAddUrlMonitor();
      }
    });
  }
  const subInput = document.getElementById('monitor-sub-domain-input');
  if (subInput) {
    subInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        quickAddSubdomainMonitor();
      }
    });
  }
  const khSearch = document.getElementById('keyhacks-search');
  if (khSearch) {
    let khDebounce;
    khSearch.addEventListener('input', (e) => {
      clearTimeout(khDebounce);
      khDebounce = setTimeout(() => loadKeyhacks(e.target.value.trim()), 300);
    });
  }


  const rtSearch = document.getElementById('report-templates-search');
  if (rtSearch) {
    let rtDebounce;
    rtSearch.addEventListener('input', (e) => {
      clearTimeout(rtDebounce);
      rtDebounce = setTimeout(() => renderReportTemplates(e.target.value.trim()), 300);
    });
  }

  wireR2BrowserOnce();
}

async function startDashboard() {
  if (state._dashboardStarted) return;
  hideAuthGate();

  const so = document.getElementById('sign-out-btn');
  if (so) {
    so.style.display = state.config?.auth_enabled ? 'block' : 'none';
    so.onclick = () => {
      localTokenClear();
      state._authAccessToken = null;
      state._dashboardStarted = false;
      showAuthGate();
      wireAuthForm();
    };
  }

  wireShellOnce();
  const backBtn = document.getElementById('scan-detail-back');
  if (backBtn && !backBtn.dataset.wired) {
    backBtn.dataset.wired = '1';
    backBtn.addEventListener('click', () => navigateTo('scans'));
  }
  if (!window.__autoarPopstate) {
    window.__autoarPopstate = true;
    window.addEventListener('popstate', () => {
      const sid = pathScanId();
      if (sid) {
        openScanResultsPage(sid, { noHistory: true });
      } else {
        state.scanDetailId = null;
        state.view = 'overview';
        document.getElementById('view-scan-detail')?.classList.remove('active');
        VIEWS.forEach(v => {
          document.getElementById(`view-${v}`)?.classList.toggle('active', v === 'overview');
          document.getElementById(`nav-${v}`)?.classList.toggle('active', v === 'overview');
        });
        document.getElementById('topbar-title').textContent = 'Overview';
        refreshCurrentView();
        startPolling();
      }
    });
  }
  startMetricsPolling();
  await loadStats();
  const deepScan = pathScanId();
  if (deepScan) {
    await openScanResultsPage(deepScan, { replace: true });
  } else {
    navigateTo('overview');
  }
  state._dashboardStarted = true;
}

async function loadStats() {
  await loadResource('stats', '/api/dashboard/stats', 'stats');
  renderStats();
  renderRecentChanges();
  // Update active scans badge
  const badge = document.getElementById('scans-badge');
  if (badge && state.stats) {
    badge.textContent = state.stats.active_scans;
    badge.classList.toggle('pulse', state.stats.active_scans > 0);
  }
}

async function loadDomains() {
  await loadResource('domains', '/api/domains', 'domains');
  if (state.view === 'domains' && !state.selectedDomain) renderDomainGrid();
  if (state.view === 'overview') renderStats();
}

async function loadSubdomains(page = 1, search = '') {
  const reqId = Date.now();
  state._subdomainsReqId = reqId;
  state.subdomainsPage = page;

  const searchInput = document.getElementById('subdomains-search');
  const actualSearch = searchInput && document.activeElement === searchInput ? searchInput.value : search;
  state.subdomainsSearch = actualSearch;

  const st = document.getElementById('subdomains-status-filter')?.value || '0';
  const tc = document.getElementById('subdomains-tech-filter')?.value || '';
  const cn = document.getElementById('subdomains-cname-filter')?.value || '';

  state.subdStatus = st;
  state.subdTech = tc;
  state.subdCname = cn;
  state.subdomainsLimit = 30;
  state.loading.subdomains = true;
  state.error.subdomains = null;
  if (state.view === 'subdomains') {
    const container = document.getElementById('subdomains-container');
    if (container) container.innerHTML = emptyState('⏳', 'Loading subdomains…', 'Fetching paginated rows from database.');
  }

  if (!state.domains || !state.domains.length) {
    await loadResource('domains', '/api/domains', 'domains');
  }

  try {
    const q = encodeURIComponent(state.subdomainsSearch);
    const qs = `page=${page}&limit=${state.subdomainsLimit}&search=${q}&status=${state.subdStatus}&tech=${encodeURIComponent(state.subdTech)}&cname=${encodeURIComponent(state.subdCname)}`;
    const data = await apiFetch(`/api/subdomains?${qs}`);
    if (state._subdomainsReqId !== reqId) return;
    state.allSubdomains = data.subdomains || [];
    state.allSubdomainsTotal = data.total || 0;

    const badge = document.getElementById('subdomains-badge');
    if (badge) {
      badge.textContent = state.allSubdomainsTotal;
      badge.style.display = state.allSubdomainsTotal ? '' : 'none';
    }
  } catch (e) {
    if (state._subdomainsReqId !== reqId) return;
    state.allSubdomains = [];
    state.allSubdomainsTotal = 0;
    state.error.subdomains = e?.message || String(e);
    showToast('error', 'Subdomains load failed', state.error.subdomains);
  } finally {
    if (state._subdomainsReqId === reqId) state.loading.subdomains = false;
  }
  if (state.view === 'subdomains') renderSubdomainsPage();
}

/** Copy every subdomain string matching the current search (paginates at API max page size). */
async function copyAllSubdomainsMatching() {
  try {
    const q = encodeURIComponent(state.subdomainsSearch || '');
    const pageSize = 500;
    let page = 1;
    const all = [];
    for (; ;) {
      const data = await apiFetch(`/api/subdomains?page=${page}&limit=${pageSize}&search=${q}`);
      const batch = data.subdomains || [];
      all.push(...batch);
      const total = data.total || 0;
      if (!batch.length || all.length >= total) break;
      page += 1;
      if (page > 2000) break;
    }
    if (!all.length) {
      showToast('error', 'Nothing to copy', 'No subdomains match the current search.');
      return;
    }
    await copyToClipboard(all.map(s => s.subdomain).join('\n'));
    showToast('success', 'Copied!', `${all.length} subdomains copied to clipboard`);
  } catch (e) {
    showToast('error', 'Copy failed', e.message || String(e));
  }
}

async function loadScans() {
  await loadResource('scans', '/api/scans', 'scans');
  if (state.view === 'scans') renderScans();
  renderOverviewActiveScans();
}

async function loadMonitor() {
  const [targets, subTargets, changes] = await Promise.allSettled([
    apiFetch('/api/monitor/targets'),
    apiFetch('/api/monitor/subdomain-targets'),
    apiFetch('/api/monitor/changes'),
  ]);
  state.monitorTargets = targets.status === 'fulfilled' ? (targets.value.targets || []) : [];
  state.subMonitorTargets = subTargets.status === 'fulfilled' ? (subTargets.value.targets || []) : [];
  state.monitorChanges = changes.status === 'fulfilled' ? (changes.value.changes || []) : [];
  if (state.view === 'monitor') renderMonitor();
}

async function loadR2(prefix = '') {
  state.r2.prefix = prefix;
  const el = document.getElementById('r2-loading');
  if (el) el.style.display = 'block';
  try {
    const data = await apiFetch(`/api/r2/files?prefix=${encodeURIComponent(prefix)}`);
    state.r2 = { prefix, dirs: data.dirs || [], files: data.files || [] };
    if (state.view === 'r2') renderR2();
  } catch (e) {
    showToast('error', 'R2 Error', e.message);
  } finally {
    if (el) el.style.display = 'none';
  }
}

function wireR2BrowserOnce() {
  if (state._r2BrowserWired) return;
  state._r2BrowserWired = true;

  const delSel = document.getElementById('r2-delete-selected');
  if (delSel && !delSel.dataset.wired) {
    delSel.dataset.wired = '1';
    delSel.addEventListener('click', (e) => {
      e.stopPropagation();
      r2DeleteSelected();
    });
  }

  let menu = document.getElementById('r2-ctx-menu');
  if (!menu) {
    menu = document.createElement('div');
    menu.id = 'r2-ctx-menu';
    menu.className = 'r2-ctx-menu';
    menu.setAttribute('role', 'menu');
    menu.innerHTML = '<button type="button" class="r2-ctx-item" data-action="delete">Delete…</button>';
    menu.style.display = 'none';
    document.body.appendChild(menu);
  }

  let r2CtxTarget = null;

  document.addEventListener('click', (e) => {
    if (menu.contains(e.target)) return;
    menu.style.display = 'none';
    r2CtxTarget = null;
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') menu.style.display = 'none';
  });

  document.addEventListener('contextmenu', (e) => {
    const row = e.target.closest('.r2-file-row[data-r2-prefix], .r2-file-row[data-r2-key], .r2-tree-item[data-r2-prefix]');
    if (!row || !document.getElementById('view-r2')?.contains(row)) return;
    e.preventDefault();
    r2CtxTarget = row;
    menu.style.display = 'block';
    menu.style.left = `${e.clientX}px`;
    menu.style.top = `${e.clientY}px`;
    requestAnimationFrame(() => {
      const r = menu.getBoundingClientRect();
      let left = e.clientX;
      let top = e.clientY;
      if (r.right > window.innerWidth) left = Math.max(8, window.innerWidth - r.width - 8);
      if (r.bottom > window.innerHeight) top = Math.max(8, window.innerHeight - r.height - 8);
      menu.style.left = `${left}px`;
      menu.style.top = `${top}px`;
    });
  });

  menu.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-action="delete"]');
    if (!btn || !r2CtxTarget) return;
    e.stopPropagation();
    menu.style.display = 'none';
    const t = r2CtxTarget;
    r2CtxTarget = null;
    const p = t.getAttribute('data-r2-prefix');
    const k = t.getAttribute('data-r2-key');
    if (p) r2DeletePrefixInteractive(p);
    else if (k) r2DeleteKeyInteractive(k);
  });

  const filesList = document.getElementById('r2-files-list');
  if (filesList && !filesList.dataset.changeWired) {
    filesList.dataset.changeWired = '1';
    filesList.addEventListener('change', (e) => {
      if (e.target && e.target.classList.contains('r2-row-cb')) r2UpdateDeleteSelectedVisibility();
    });
  }
}

function r2UpdateDeleteSelectedVisibility() {
  const btn = document.getElementById('r2-delete-selected');
  if (!btn) return;
  const n = document.querySelectorAll('#r2-files-list .r2-row-cb:checked').length;
  btn.style.display = n > 0 ? 'inline-block' : 'none';
  btn.textContent = n > 0 ? `🗑 Delete selected (${n})` : '🗑 Delete selected';
}

async function r2DeletePrefixInteractive(prefix) {
  if (!prefix) return;
  if (!confirm(`Delete this folder and everything under it?\n\n${prefix}\n\nThis cannot be undone.`)) return;
  try {
    const res = await apiPost('/api/r2/delete', { prefix });
    const n = res.deleted != null ? res.deleted : '?';
    showToast('success', 'R2', `Deleted (${n} object${n === 1 ? '' : 's'})`);
    await loadR2(state.r2.prefix);
  } catch (e) {
    showToast('error', 'R2', e.message);
  }
}

async function r2DeleteKeyInteractive(key) {
  if (!key) return;
  if (!confirm(`Delete this file?\n\n${key}\n\nThis cannot be undone.`)) return;
  try {
    await apiPost('/api/r2/delete', { key });
    showToast('success', 'R2', 'File deleted');
    await loadR2(state.r2.prefix);
  } catch (e) {
    showToast('error', 'R2', e.message);
  }
}

async function r2DeleteSelected() {
  const boxes = [...document.querySelectorAll('#r2-files-list .r2-row-cb:checked')];
  if (!boxes.length) return;
  const prefixes = [];
  const keys = [];
  for (const cb of boxes) {
    if (cb.dataset.r2Prefix) prefixes.push(cb.dataset.r2Prefix);
    if (cb.dataset.r2Key) keys.push(cb.dataset.r2Key);
  }
  const total = prefixes.length + keys.length;
  if (!total) return;
  if (!confirm(`Delete ${prefixes.length} folder tree(s) and ${keys.length} file(s)? This cannot be undone.`)) return;
  try {
    for (const p of prefixes) {
      await apiPost('/api/r2/delete', { prefix: p });
    }
    for (const k of keys) {
      await apiPost('/api/r2/delete', { key: k });
    }
    showToast('success', 'R2', `Deleted ${total} item(s)`);
    await loadR2(state.r2.prefix);
  } catch (e) {
    showToast('error', 'R2', e.message);
  }
}

/** Strip protocol/path for R2 prefixes (results/, new-results/, lite/). */
function targetToHostname(target) {
  if (target == null || target === '') return '';
  const t = String(target).trim();
  try {
    if (t.includes('://')) {
      const u = new URL(t);
      return (u.hostname || '').replace(/^www\./i, '') || u.hostname;
    }
  } catch (e) { /* use heuristic below */ }
  const noProto = t.replace(/^https?:\/\//i, '');
  const host = noProto.split('/')[0] || '';
  return host.replace(/^www\./i, '') || noProto;
}

function uniquePrefixList(prefixes) {
  const out = [];
  const seen = new Set();
  for (const p of prefixes) {
    if (!p || seen.has(p)) continue;
    seen.add(p);
    out.push(p);
  }
  return out;
}

/**
 * R2 key prefixes to search per scan type (mirrors local new-results/ layout + UploadResultsDirectory results/).
 */
function r2PrefixesForScan(target, scanType) {
  const t = (target || '').trim();
  const st = (scanType || '').toLowerCase();
  const host = targetToHostname(t) || t;

  const domainTriad = (h) => [
    `new-results/${h}/`,
    `results/${h}/`,
    `lite/${h}/`,
  ];

  if (st.startsWith('nuclei')) {
    const hosts = new Set();
    if (host) hosts.add(host);
    if (/^https?:\/\//i.test(t)) {
      const uh = targetToHostname(t);
      if (uh) hosts.add(uh);
    }
    const prefixes = [];
    for (const h of hosts) {
      prefixes.push(...domainTriad(h));
    }
    const h0 = [...hosts][0];
    if (h0) {
      prefixes.push(`new-results/misconfig/${h0}/`, `misconfig/${h0}/`);
    }
    if (!prefixes.length && (host || t)) {
      return uniquePrefixList(domainTriad(host || t));
    }
    return uniquePrefixList(prefixes);
  }

  if (st === 'misconfig') {
    return uniquePrefixList([
      `new-results/misconfig/${host}/`,
      `misconfig/${host}/`,
      ...domainTriad(host),
    ]);
  }

  if (st === 'dns-takeover' || st === 'dns' || st.startsWith('dns-')) {
    return uniquePrefixList([
      `new-results/${host}/vulnerabilities/dns-takeover/`,
      `results/${host}/vulnerabilities/dns-takeover/`,
      ...domainTriad(host),
    ]);
  }

  if (st === 's3') {
    const b = t || host;
    return uniquePrefixList([
      `new-results/s3/${b}/`,
      `s3/${b}/`,
      `results/s3/${b}/`,
    ]);
  }

  if (st === 'github') {
    const slug = t;
    return uniquePrefixList([
      `new-results/github/repos/${slug}/`,
      `github/repos/${slug}/`,
      ...domainTriad(host),
    ]);
  }

  if (st === 'github_org') {
    return uniquePrefixList([
      `new-results/github/orgs/${t}/`,
      `github/orgs/${t}/`,
    ]);
  }

  if (st === 'ffuf') {
    return uniquePrefixList([
      `new-results/ffuf/`,
      `ffuf/`,
      ...domainTriad(host),
    ]);
  }

  if (st === 'jwt') {
    return uniquePrefixList([
      `new-results/jwt-scan/`,
      `jwt-scan/`,
    ]);
  }

  if (st === 'apkx') {
    return uniquePrefixList([
      `new-results/apkx/`,
      `apkx/`,
      `results/apkx/`,
    ]);
  }

  if (st === 'zerodays') {
    return uniquePrefixList([
      ...domainTriad(host),
      `new-results/zerodays/`,
      `zerodays/`,
    ]);
  }

  return uniquePrefixList([
    ...domainTriad(host),
    `new-results/misconfig/${host}/`,
    `misconfig/${host}/`,
  ]);
}

/** Jump to R2 view and open the first prefix that has objects for this scan type + target. */
async function browseR2ForScan(target, scanType) {
  const candidates = r2PrefixesForScan(target, scanType);
  if (!candidates.length) {
    showToast('error', 'R2', 'No R2 search paths for this scan.');
    return;
  }
  let chosen = candidates[0];
  for (const prefix of candidates) {
    try {
      const data = await apiFetch(`/api/r2/files?prefix=${encodeURIComponent(prefix)}&recursive=0`);
      const has = (data.files && data.files.length) || (data.dirs && data.dirs.length);
      if (has) {
        chosen = prefix;
        break;
      }
    } catch (e) { /* try next */ }
  }
  state.r2.prefix = chosen;
  navigateTo('r2');
  showToast('info', 'R2', `Opened ${chosen}`);
}

async function loadDomainSubdomains(domain) {
  state.selectedDomain = domain;
  state.loading.subdomains = true;
  try {
    const data = await apiFetch(`/api/domains/${encodeURIComponent(domain)}/subdomains`);
    state.subdomains = data.subdomains || [];
    renderSubdomainView(domain);
  } catch (e) {
    showToast('error', 'Failed to load subdomains', e.message);
  } finally {
    state.loading.subdomains = false;
  }
}

// ── Polling ───────────────────────────────────────────────────────────────────

function startPolling() {
  if (state.pollTimer) {
    clearTimeout(state.pollTimer);
    state.pollTimer = null;
  }
  const tick = async () => {
    try {
      await loadStats();
      await loadScans();
      if (state.view === 'monitor') await loadMonitor();

      // If on scan detail, only trigger refresh if the scan being viewed is actually active
      if (state.view === 'scan-detail' && state.scanDetailId) {
        const activeIds = (state.scans?.active_scans || []).map(s => String(s.id || s.Id || ''));
        if (activeIds.includes(String(state.scanDetailId))) {
          refreshScanDetailIfRunning(state.scanDetailId);
        }
      }
    } catch (e) { /* ignore */ }

    const n = state.stats?.active_scans ?? 0;
    const onScans = state.view === 'scans';

    // Only fast-poll if on Scans list or viewing a scan that is actually running
    let isViewingActiveScan = false;
    if (state.view === 'scan-detail' && state.scanDetailId) {
      const activeIds = (state.scans?.active_scans || []).map(s => String(s.id || s.Id || ''));
      if (activeIds.includes(String(state.scanDetailId))) isViewingActiveScan = true;
    }

    let ms = POLL_INTERVAL;
    if ((onScans || isViewingActiveScan) && n > 0) ms = POLL_FAST_SCANS;
    else if (n > 0) ms = POLL_FAST_ANY;

    state.pollTimer = setTimeout(tick, ms);
  };
  state.pollTimer = setTimeout(tick, 600);
}

function refreshCurrentView() {
  switch (state.view) {
    case 'overview': loadStats(); loadDomains(); loadScans(); break;
    case 'scans': loadScans(); break;
    case 'domains': loadDomains(); break;
    case 'subdomains': loadSubdomains(); break;
    case 'targets': loadTargetsPlatforms(); break;
    case 'monitor': loadMonitor(); break;
    case 'keyhacks': loadKeyhacks(); break;
    case 'report-templates': renderReportTemplates(); break;
    case 'r2': loadR2(state.r2.prefix); break;
    case 'settings': loadConfig(); break;
    case 'scan-detail':
      if (state.scanDetailId) {
        state.scanDetailUI.filesPage = 1;
        renderScanDetailView(state.scanDetailId);
      }
      break;
  }
}

/** Pagination: previous page of files */
function prevFilesPage(scanId) {
  if (state.scanDetailUI.filesPage > 1) {
    state.scanDetailUI.filesPage--;
    renderScanDetailView(scanId);
  }
}

/** Pagination: next page of files */
function nextFilesPage(scanId, total) {
  if (state.scanDetailUI.filesPage * state.scanDetailUI.filesPerPage < total) {
    state.scanDetailUI.filesPage++;
    renderScanDetailView(scanId);
  }
}

// ── Renderers ─────────────────────────────────────────────────────────────────

function renderStats() {
  const s = state.stats;
  if (!s) return;
  const set = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  };
  set('stat-domains', s.domains ?? 0);
  set('stat-subdomains', s.subdomains ?? 0);
  set('stat-live', s.live_subdomains ?? 0);
  set('stat-monitors', s.monitor_targets ?? 0);
  set('stat-active', s.active_scans ?? 0);
  set('stat-completed', s.completed_scans ?? 0);
}

function renderOverviewActiveScans() {
  const card = document.getElementById('overview-running-scans');
  const body = document.getElementById('overview-active-scans-body');
  if (!card || !body) return;
  const active = state.scans?.active_scans || [];
  if (!active.length) {
    card.style.display = 'none';
    return;
  }
  card.style.display = 'block';
  body.innerHTML = active.map(s => scanItemHtml(s)).join('');
}

// ── System Metrics ────────────────────────────────────────────────────────────

function startMetricsPolling() {
  if (state._metricsTimer) clearInterval(state._metricsTimer);
  const poll = async () => {
    try {
      const data = await apiFetch('/api/system/metrics');
      updateMetricsUI(data);
    } catch (e) { console.warn('[metrics] poll failed', e); }
  };
  poll();
  state._metricsTimer = setInterval(poll, 10000);
}

function updateMetricsUI(data) {
  const cpu = Math.round(data.cpu_percent || 0);
  const ram = Math.round(data.memory_percent || 0);
  
  const cpuEl = document.getElementById('metric-cpu');
  const cpuFill = document.getElementById('metric-cpu-fill');
  const ramEl = document.getElementById('metric-ram');
  const ramFill = document.getElementById('metric-ram-fill');
  
  if (cpuEl) cpuEl.textContent = `${cpu}%`;
  if (cpuFill) cpuFill.style.width = `${cpu}%`;
  if (ramEl) ramEl.textContent = `${ram}%`;
  if (ramFill) ramFill.style.width = `${ram}%`;
}

function renderRecentChanges() {
  const el = document.getElementById('recent-changes-feed');
  if (!el) return;
  const changes = state.stats?.recent_changes || [];
  if (!changes.length) {
    el.innerHTML = emptyState('📭', 'No recent changes', 'Monitor targets have not detected any changes yet.');
    return;
  }
  el.innerHTML = changes.map(c => changeItemHtml(c)).join('');
}

function renderScans() {
  const container = document.getElementById('scans-container');
  if (!container) return;
  const scanErr = state.error.scans;
  const { active_scans = [], recent_scans = [] } = state.scans;
  const sUI = state.scanListUI;

  const filterFn = (s) => {
    const target = (s.target || s.Target || '').toLowerCase();
    const type = (s.scan_type || s.ScanType || '').toLowerCase();
    const status = (s.status || s.Status || '').toLowerCase();

    const matchesSearch = !sUI.search || target.includes(sUI.search.toLowerCase());
    const matchesType = sUI.typeFilter === 'all' || type === sUI.typeFilter.toLowerCase();
    let matchesStatus = sUI.statusFilter === 'all' || status === sUI.statusFilter.toLowerCase();
    if (sUI.statusFilter === 'stopped' && (status === 'cancelled' || status === 'stopped')) {
      matchesStatus = true;
    }

    return matchesSearch && matchesType && matchesStatus;
  };

  const filteredActive = active_scans.filter(filterFn);
  const filteredRecent = recent_scans.filter(filterFn);

  let html = '';
  if (scanErr) {
    html += `<div class="card" style="margin-bottom:16px;border:1px solid var(--accent-red);background:rgba(239,68,68,0.08)">
      <div class="card-body" style="padding:14px 16px;font-size:13px;color:var(--accent-red)">Could not load scans: ${esc(scanErr)}</div>
    </div>`;
  }

  // Filter Bar
  html += `<div class="card" style="margin-bottom:20px; border:1px solid var(--border); background:rgba(13,17,23,0.4)">
    <div class="card-body" style="padding:16px">
      <div style="display:flex;gap:16px;flex-wrap:wrap;align-items:center">
        <div style="flex:1;min-width:280px;position:relative">
          <input type="text" id="scan-search-input" class="search-input" placeholder="🔍 Search targets or scan types..." value="${esc(sUI.search)}" style="width:100%; padding-left:36px; background:var(--bg-secondary)">
          <span style="position:absolute; left:12px; top:50%; transform:translateY(-50%); color:var(--text-muted); pointer-events:none"></span>
        </div>
        <div style="min-width:180px">
          <select id="scan-type-filter" class="input" style="width:100%; background:var(--bg-secondary)">
            <option value="all">All Scan Types</option>
            <optgroup label="Workflows">
              <option value="recon" ${sUI.typeFilter === 'recon' ? 'selected' : ''}>Recon</option>
              <option value="lite" ${sUI.typeFilter === 'lite' ? 'selected' : ''}>Lite Workflow</option>
              <option value="domain_run" ${sUI.typeFilter === 'domain_run' ? 'selected' : ''}>Full Domain</option>
              <option value="subdomain_run" ${sUI.typeFilter === 'subdomain_run' ? 'selected' : ''}>Subdomain Run</option>
            </optgroup>
            <optgroup label="Modules">
              <option value="nuclei" ${sUI.typeFilter === 'nuclei' ? 'selected' : ''}>Nuclei</option>
              <option value="subdomains" ${sUI.typeFilter === 'subdomains' ? 'selected' : ''}>Subdomains</option>
              <option value="livehosts" ${sUI.typeFilter === 'livehosts' ? 'selected' : ''}>Live Hosts</option>
              <option value="tech" ${sUI.typeFilter === 'tech' ? 'selected' : ''}>Tech Detect</option>
              <option value="ffuf" ${sUI.typeFilter === 'ffuf' ? 'selected' : ''}>FFuf Fuzz</option>
              <option value="js" ${sUI.typeFilter === 'js' ? 'selected' : ''}>JS Scan</option>
              <option value="dns" ${sUI.typeFilter === 'dns' ? 'selected' : ''}>DNS Takeover</option>
            </optgroup>
          </select>
        </div>
        <div style="min-width:180px">
          <select id="scan-status-filter" class="input" style="width:100%; background:var(--bg-secondary)">
            <option value="all" ${sUI.statusFilter === 'all' ? 'selected' : ''}>Any Status</option>
            <option value="completed" ${sUI.statusFilter === 'completed' ? 'selected' : ''}>Completed</option>
            <option value="failed" ${sUI.statusFilter === 'failed' ? 'selected' : ''}>Failed</option>
            <option value="running" ${sUI.statusFilter === 'running' ? 'selected' : ''}>Running</option>
            <option value="stopped" ${sUI.statusFilter === 'stopped' ? 'selected' : ''}>Stopped / Cancelled</option>
          </select>
        </div>
      </div>
    </div>
  </div>`;

  if (filteredActive.length) {
    html += `<div class="card" style="margin-bottom:20px">
      <div class="card-header">
        <div class="card-title">⚡ Active Scans <span class="badge badge-running">${filteredActive.length}</span></div>
      </div>
      <div class="card-body">
        ${filteredActive.map(s => scanItemHtml(s)).join('')}
      </div>
    </div>`;
  }

  html += `<div class="card">
    <div class="card-header" style="display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:12px">
      <div class="card-title">🕐 Recent Scans ${filteredRecent.length !== recent_scans.length ? `<span style="font-size:12px;color:var(--text-muted);font-weight:400;margin-left:8px">(${filteredRecent.length} filtered)</span>` : ''}</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
        <button type="button" class="btn btn-ghost" style="font-size:12px;padding:6px 12px" onclick="deleteSelectedScans()">Delete selected</button>
        <button type="button" class="btn btn-ghost" style="font-size:12px;padding:6px 12px;color:var(--accent-red);border-color:rgba(248,113,113,.35)" onclick="clearAllScans()">Clear all</button>
      </div>
    </div>
    <div class="card-body">`;

  if (!filteredRecent.length && !filteredActive.length) {
    if (sUI.search || sUI.typeFilter !== 'all' || sUI.statusFilter !== 'all') {
      html += emptyState('🔍', 'No matches found', 'Adjust your filters or search term to see more scans.');
    } else {
      html += scanErr
        ? emptyState('⚠️', 'Scans unavailable', 'Fix the error above or check that the API is reachable.')
        : emptyState('📋', 'No scans yet', 'Start a scan from the Overview tab or via the CLI.');
    }
  } else if (!filteredRecent.length && recent_scans.length > 0) {
    html += `<div style="padding:20px;text-align:center;color:var(--text-muted);font-size:13px">No completed scans match the current filter</div>`;
  } else if (filteredRecent.length > 0) {
    html += `<table class="data-table" id="recent-scans-table">
      <thead><tr>
        <th style="width:36px" onclick="event.stopPropagation()"><input type="checkbox" title="Select all" aria-label="Select all" onclick="event.stopPropagation();toggleSelectAllRecentScans(this)" /></th>
        <th>Target</th><th>Type</th><th>Status</th><th>Phase</th><th>Started</th><th>Elapsed</th><th>Results</th>
      </tr></thead>
      <tbody>${filteredRecent.map(s => scanRowHtml(s)).join('')}</tbody>
    </table>`;
  }
  html += `</div></div>`;
  container.innerHTML = html;

  const searchIn = container.querySelector('#scan-search-input');
  if (searchIn) {
    searchIn.oninput = (e) => {
      const pos = e.target.selectionStart;
      state.scanListUI.search = e.target.value;
      renderScans();
      // Keep focus and cursor position
      const inp = document.getElementById('scan-search-input');
      if (inp) {
        inp.focus();
        inp.setSelectionRange(pos, pos);
      }
    };
  }
  const typeSel = container.querySelector('#scan-type-filter');
  if (typeSel) {
    typeSel.onchange = (e) => {
      state.scanListUI.typeFilter = e.target.value;
      renderScans();
    };
  }
  const statusSel = container.querySelector('#scan-status-filter');
  if (statusSel) {
    statusSel.onchange = (e) => {
      state.scanListUI.statusFilter = e.target.value;
      renderScans();
    };
  }
}


/**
 * Return a human-friendly badge label + optional icon for a raw scan_type string.
 * Falls back to capitalising the raw value if no mapping exists.
 */
function scanTypeLabel(rawType) {
  const t = String(rawType || '').toLowerCase().trim();
  const map = {
    'recon': '🔭 Recon Discovery',
    'domain_run': '🌍 Full Domain',
    'subdomain_run': '🔬 Subdomain',
    'lite': '⚡ Lite Workflow',
    'fastlook': '👁 Fast Look',
    'subdomains': '🔍 Subdomains',
    'livehosts': '🌐 Live Hosts',
    'cnames': '🔗 CNAMEs',
    'urls': '🔗 URLs',
    'js': '📜 JS Scan',
    'jsscan': '📜 JS Scan',
    'reflection': '⚡  Reflection',
    'gf': '🎯 GF Patterns',
    'nuclei': '☢️ Nuclei',
    'nuclei-full': '☢️ Nuclei Full',
    'nuclei-cves': '☢️ Nuclei CVEs',
    'nuclei-panels': '☢️ Nuclei Panels',
    'nuclei-vulnerabilities': '☢️ Nuclei Vulns',
    'nuclei-default-logins': '☢️ Nuclei Logins',
    'ports': '🔌 Ports',
    'tech': '🔬 Tech Detect',
    'dns': '🔀 DNS Takeover',
    'dns-takeover': '🔀 DNS Takeover',
    'dns-dangling-ip': '🔀 Dangling IP',
    'dns_cf1016': '☁️ CF1016 Dangling',
    'dns-cf1016': '☁️ CF1016 Dangling',
    'backup': '💾 Backup Files',
    'misconfig': '⚙️ Misconfig',
    's3': '🪣 S3 Scan',
    'github': '🐙 GitHub',
    'github_org': '🐙 GitHub Org',
    'github_scan': '🐙 GitHub',
    'ffuf': '🎲 FFuf Fuzz',
    'zerodays': '🚨 Zero-Days',
    'apkx': '📱 APK Scan',
    'jwt': '🔑 JWT Scan',
    'aem': '🏗 AEM Scan',
    'aem_scan': '🏗 AEM Scan',
    'cleanup': '🧹 Cleanup',
    'depconfusion': '📦 Dep Confusion',
    'wp_confusion': '📦 WP Confusion',
  };
  if (map[t]) return map[t];
  // Fallback: capitalise words, replace _ with space
  return t.replace(/_/g, ' ').replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) || rawType;
}

function scanItemHtml(s) {
  const target = s.target || s.Target || '';
  const scanType = s.scan_type || s.ScanType || '';
  const statusRaw = (s.status || s.Status || 'running').toLowerCase();
  const currentPhase = s.current_phase || s.CurrentPhase || 0;
  const totalPhases = s.total_phases || s.TotalPhases || 0;
  const startedAt = s.started_at || s.StartedAt || '';
  const phaseName = s.phase_name || s.PhaseName || '';
  const phaseStartTime = s.phase_start_time || s.PhaseStartTime || '';
  const completedPhases = s.completed_phases || s.CompletedPhases || [];
  const failedPhases = s.failed_phases || s.FailedPhases || [];
  const filesUploaded = s.files_uploaded || s.FilesUploaded || 0;
  const errorCount = s.error_count || s.ErrorCount || 0;
  const lastUpdate = s.last_update || s.LastUpdate || '';
  const scanID = s.scan_id || s.ScanID || '';

  const pct = totalPhases > 0 ? Math.round((currentPhase / totalPhases) * 100) : 0;
  const elapsed = elapsedStr(startedAt);
  const isActive = ['running', 'starting', 'paused', 'cancelling'].includes(statusRaw);
  const showProgress = ['running', 'starting'].includes(statusRaw);
  const noPhaseYet = showProgress && currentPhase === 0 && !phaseName;

  // Status badge
  let badge = '';
  if (statusRaw === 'paused') badge = '<span class="badge badge-starting">⏸ paused</span>';
  else if (statusRaw === 'cancelling') badge = '<span class="badge badge-starting">⋯ stopping</span>';
  else if (isActive) badge = '<span class="badge badge-running" style="animation:pulse 1.4s ease-in-out infinite">● live</span>';

  // Action buttons
  const actions = isActive ? `
    <div class="scan-actions" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center" onclick="event.stopPropagation()">
      ${statusRaw !== 'paused' && statusRaw !== 'cancelling'
      ? `<button type="button" class="btn btn-ghost" style="font-size:11px;padding:4px 10px" onclick="pauseScan('${esc(scanID)}')">⏸ Pause</button>` : ''}
      ${statusRaw === 'paused'
      ? `<button type="button" class="btn btn-ghost" style="font-size:11px;padding:4px 10px" onclick="resumeScan('${esc(scanID)}')">▶ Resume</button>` : ''}
      <button type="button" class="btn btn-ghost scan-btn-stop" style="font-size:11px;padding:4px 10px" onclick="cancelScan('${esc(scanID)}')">■ Stop</button>
      <button type="button" class="btn btn-ghost" style="font-size:11px;padding:4px 10px" onclick="goToScanResultsPage('${esc(scanID)}');event.stopPropagation()">→ View</button>
    </div>` : '';

  // Phase elapsed
  const phaseElapsed = phaseStartTime ? elapsedStr(phaseStartTime) : '';

  // Build completed phases list for timeline
  const phaseSteps = completedPhases.length || phaseName
    ? [
      ...completedPhases.map(p => ({ name: p, state: failedPhases.includes(p) ? 'failed' : 'done' })),
      ...(phaseName ? [{ name: phaseName, state: 'active' }] : []),
    ]
    : [];

  const phaseTimeline = phaseSteps.length ? `
    <div style="display:flex;flex-direction:column;gap:4px;margin-top:10px;margin-bottom:6px;padding:10px 12px;background:rgba(0,0,0,.2);border-radius:8px;border:1px solid rgba(255,255,255,.05)">
      ${phaseSteps.map((step, i) => {
    const isLast = i === phaseSteps.length - 1;
    const icon = step.state === 'done' ? '<span style="color:#10b981;font-size:11px">✓</span>'
      : step.state === 'failed' ? '<span style="color:#ef4444;font-size:11px">✗</span>'
        : '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--accent-cyan);box-shadow:0 0 6px var(--accent-cyan);animation:pulse 1s ease-in-out infinite;vertical-align:middle"></span>';
    const color = step.state === 'done' ? 'var(--text-muted)'
      : step.state === 'failed' ? '#ef4444'
        : 'var(--text-primary)';
    const weight = isLast ? '600' : '400';
    const timer = (isLast && phaseElapsed) ? `<span style="font-size:10px;color:var(--text-muted);margin-left:6px">${phaseElapsed}</span>` : '';
    return `<div style="display:flex;align-items:center;gap:8px;font-size:11px;color:${color};font-weight:${weight}">
          <div style="width:16px;text-align:center;flex-shrink:0">${icon}</div>
          <span style="flex:1">${esc(step.name)}</span>${timer}
        </div>`;
  }).join('')}
    </div>` : '';

  // Progress bar
  let progressBlock = '';
  if (showProgress) {
    if (noPhaseYet) {
      progressBlock = `
        <div class="progress-bar indeterminate" style="margin-top:10px"><div class="progress-fill" style="width:40%"></div></div>
        <div style="font-size:11px;color:var(--text-muted);margin-top:5px">Starting up…</div>`;
    } else {
      const barColor = errorCount > 0 ? '#f59e0b' : 'var(--accent-cyan)';
      progressBlock = `
        <div style="margin-top:10px;background:rgba(255,255,255,.06);border-radius:6px;height:6px;overflow:hidden">
          <div style="height:100%;width:${pct}%;background:linear-gradient(90deg,${barColor},${barColor}cc);border-radius:6px;transition:width .4s ease"></div>
        </div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-top:5px">
          <span style="font-size:11px;color:var(--text-muted)">Phase ${currentPhase}${totalPhases > 0 ? '/' + totalPhases : ''} · ${pct}%</span>
          <div style="display:flex;gap:10px;align-items:center">
            ${filesUploaded > 0 ? `<span style="font-size:10px;color:var(--text-muted)">📁 ${filesUploaded} files</span>` : ''}
            ${errorCount > 0 ? `<span style="font-size:10px;color:#f59e0b">⚠ ${errorCount} error${errorCount !== 1 ? 's' : ''}</span>` : ''}
            ${lastUpdate ? `<span style="font-size:10px;color:var(--text-muted)" title="${esc(lastUpdate)}">updated ${elapsedStr(lastUpdate)} ago</span>` : ''}
          </div>
        </div>`;
    }
  }

  return `<div class="scan-item clickable-row" onclick='goToScanResultsPage(${JSON.stringify(scanID)})' style="padding:14px 16px;border-radius:10px;border:1px solid ${statusRaw === 'paused' ? 'rgba(251,191,36,.25)' : 'rgba(6,182,212,.2)'};background:${statusRaw === 'paused' ? 'rgba(251,191,36,.04)' : 'rgba(6,182,212,.04)'};margin-bottom:12px">
    <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;min-width:0">
        <div style="min-width:0">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
            <span class="scan-target" style="font-size:14px;font-weight:700;color:var(--text-primary)">${esc(target)}</span>
            <span style="font-size:11px;background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.1);border-radius:4px;padding:1px 7px;color:var(--text-secondary)" title="${esc(scanType)}">${esc(scanTypeLabel(scanType))}</span>
            ${badge}
          </div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:2px">Started ${elapsed} ago</div>
        </div>
      </div>
      ${actions}
    </div>
    ${phaseTimeline}
    ${progressBlock}
  </div>`;
}

function scanRowHtml(s) {
  const target = s.target || s.Target || '';
  const scanType = s.scan_type || s.ScanType || '';
  const status = s.status || s.Status || '';
  const statusLc = status.toLowerCase();
  const currentPhase = s.current_phase || s.CurrentPhase || 0;
  const totalPhases = s.total_phases || s.TotalPhases || 0;
  const phaseName = s.phase_name || s.PhaseName || '';
  const startedAt = s.started_at || s.StartedAt || '';
  const completedAt = s.completed_at || s.CompletedAt || '';
  const pct = totalPhases > 0 ? Math.round((currentPhase / totalPhases) * 100) : 0;
  const resultURL = s.result_url || s.ResultURL || '';
  const done = ['completed', 'done'].includes(statusLc);

  const compPhases = s.completed_phases || s.CompletedPhases || [];
  const failPhases = s.failed_phases || s.FailedPhases || [];

  // Clean up phase names: strip "[Stage N]" prefix for display
  const cleanName = n => n.replace(/^\[Stage \d+\]\s*/i, '').replace(/^\[.*?\]\s*/, '');

  let phaseCol = '';
  if (done) {
    const skipped = Math.max(0, totalPhases - (compPhases.length + failPhases.length));

    // Build rich tooltip sections
    const compList = compPhases.length ? compPhases.map(p => `✓ ${cleanName(p)}`).join('\n') : 'None';
    const failList = failPhases.length ? failPhases.map(p => `✗ ${cleanName(p)}`).join('\n') : 'None';
    const skipCount = skipped > 0 ? `${skipped} stage(s) did not run (timeout/skipped/unlaunched)` : 'All stages accounted for';

    const tooltipText = `Completed (${compPhases.length}):\n${compList}\n\nFailed (${failPhases.length}):\n${failList}\n\nSkipped: ${skipCount}`;
    if (pct < 100 && skipped > 0) {
      const failPart = failPhases.length ? ` · ${failPhases.length} failed` : '';
      phaseCol = `<span style="font-size:11px;color:var(--text-muted);border-bottom:1px dashed var(--text-muted);cursor:help" title="${esc(tooltipText)}">Ended at ${pct}% · ${compPhases.length} done${failPart} · ${skipped} skipped</span>`;
    } else {
      const failPart = failPhases.length ? ` · <span style="color:#ef4444">${failPhases.length} failed</span>` : '';
      phaseCol = `<span style="font-size:11px;color:var(--accent-emerald);font-weight:600;border-bottom:1px dashed var(--accent-emerald);cursor:help" title="${esc(tooltipText)}">Done · ${compPhases.length} stages${failPart}</span>`;
    }
  } else {
    phaseCol = `<span style="font-size:11px;color:var(--text-muted)">${pct}%${phaseName ? ` — ${esc(phaseName)}` : ''}</span>`;
  }

  const badge = statusBadge(status);
  const elapsed = completedAt
    ? elapsedBetween(startedAt, completedAt)
    : elapsedStr(startedAt);
  const scanID = s.scan_id || s.ScanID || '';
  const resultsCell = resultURL
    ? `<a href="${esc(resultURL)}" target="_blank" onclick="event.stopPropagation()" class="scan-result-link">Download</a>`
    : `<button type="button" class="scan-control-btn-r2" onclick='event.stopPropagation();browseR2ForScan(${JSON.stringify(target)}, ${JSON.stringify(scanType)})'>Browse R2</button>`;
  const running = ['running', 'starting', 'paused'].includes(statusLc);
  const rescanBtn = !running
    ? `<button type="button" class="scan-control-btn-r2" style="margin-left:6px;border-color:rgba(52,211,153,.35);color:var(--accent-emerald)" onclick='event.stopPropagation();rescanScan(${JSON.stringify(scanID)})' title="Re-run with same command">🔁 Rescan</button>`
    : '';
  const deleteBtn = `<button type="button" class="scan-control-btn-r2" style="margin-left:6px;border-color:rgba(248,113,113,.35);color:var(--accent-red)" onclick='event.stopPropagation();deleteScan(${JSON.stringify(scanID)}, ${JSON.stringify(target)})'>Delete</button>`;
  const rowSelect = `<input type="checkbox" class="scan-row-select" data-scan-id="${esc(scanID)}" onclick="event.stopPropagation()" aria-label="Select scan" />`;
  return `<tr class="clickable-row" onclick='goToScanResultsPage(${JSON.stringify(scanID)})'>
    <td onclick="event.stopPropagation()">${rowSelect}</td>
    <td><span style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan)">${esc(target)}</span></td>
    <td><span class="scan-type" title="${esc(scanType)}">${esc(scanTypeLabel(scanType))}</span></td>
    <td>${badge}</td>
    <td>${phaseCol}</td>
    <td style="font-size:11px;color:var(--text-muted)">${fmtDate(startedAt)}</td>
    <td style="font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--text-muted)">${elapsed}</td>
    <td onclick="event.stopPropagation()">${resultsCell}${rescanBtn}${deleteBtn}</td>
  </tr>`;
}

// ── Scan results page (/scans/:id) ─────────────────────────────────────────────

/** Determine file type category from filename for icon display */
function getFileTypeFromName(fileName) {
  const name = fileName.toLowerCase();
  if (name.endsWith('.json')) return 'json';
  if (name.endsWith('.csv')) return 'csv';
  if (name.endsWith('.log')) return 'log';
  if (name.endsWith('.txt')) return 'text';
  return 'text';
}

/** Get icon emoji for file type */
function getFileTypeIcon(fileType) {
  switch (fileType) {
    case 'json': return '🟣';
    case 'csv': return '📊';
    case 'log': return '📋';
    case 'text': return '📄';
    default: return '📄';
  }
}

/** Toggle collapsible sections */
function toggleCollapsible(header) {
  const content = header.nextElementSibling;
  const isExpanded = content.classList.contains('expanded');

  // Toggle current
  content.classList.toggle('expanded');
  header.classList.toggle('active');
}

/** Switch between scan detail tabs */
function switchScanDetailTab(tabName) {
  const tabsRoot = document.getElementById('scan-detail-tabs');
  if (!tabsRoot) return;

  // Support both legacy .tab-btn and new .tab-pill buttons.
  tabsRoot.querySelectorAll('.tab-btn, .tab-pill').forEach((btn) => {
    btn.classList.remove('active');
    if (btn.getAttribute('data-tab') === tabName) btn.classList.add('active');
  });

  // Update tab panels
  document.querySelectorAll('[id^="tab-panel-"]').forEach(panel => {
    panel.classList.remove('active');
  });
  const panel = document.getElementById(`tab-panel-${tabName}`);
  if (panel) panel.classList.add('active');
}

/** Format JSON with syntax highlighting */
function formatJSONWithHighlighting(jsonObj) {
  const jsonStr = JSON.stringify(jsonObj, null, 2);
  return syntaxHighlightJSON(jsonStr);
}

/** Apply syntax highlighting to JSON string */
function syntaxHighlightJSON(json) {
  if (!json) return '';

  // Escape HTML first
  let escaped = esc(json);

  // Apply syntax highlighting using regex
  return escaped
    // Keys
    .replace(/&quot;([^&]+?)&quot;(\s*:\s*)/g, '<span class="json-key">"$1"</span>$2')
    // String values
    .replace(/:\s*&quot;([^&]*?)&quot;/g, ': <span class="json-string">"$1"</span>')
    // Numbers
    .replace(/\b(\d+\.?\d*)\b/g, '<span class="json-number">$1</span>')
    // Booleans
    .replace(/\b(true|false)\b/g, '<span class="json-boolean">$1</span>')
    // Null
    .replace(/\bnull\b/g, '<span class="json-null">null</span>')
    // Brackets
    .replace(/([{}[\]])/g, '<span class="json-bracket">$1</span>');
}

/** Plain-text line when a finished scan has no indexed artifacts (aligned with Discord phaseNoResultsMessage). */
function scanNoArtifactsMessage(scanType, target) {
  const t = (target && String(target).trim()) || 'this target';
  const st = String(scanType || '').toLowerCase().trim();
  switch (st) {
    case 'ports':
      return `[ ⚪ ] Port Scan — No open ports found (excluding 80, 443, 8080, 8443) for ${t}`;
    case 'aem':
    case 'aem_scan':
      return `[ ⚪ ] AEM Scan — No AEM instances discovered for ${t}`;
    case 'tech':
      return `[ ⚪ ] Tech Detection — No live hosts found for ${t}`;
    case 'backup':
      return `[ ⚪ ] Backup Scan — No backup files found for ${t}`;
    case 'misconfig':
      return `[ ⚪ ] Misconfig Scan — No misconfigurations found for ${t}`;
    case 'subdomains':
      return `[ ⚪ ] Subdomains — No subdomains found for ${t}`;
    case 'livehosts':
      return `[ ⚪ ] Live hosts — No live hosts found for ${t}`;
    case 'urls':
      return `[ ⚪ ] URLs — No interesting URLs found for ${t}`;
    case 'jsscan':
    case 'js':
      return `[ ⚪ ] JS Scan — No JavaScript vulnerabilities found for ${t}`;
    case 'reflection':
      return `[ ⚪ ] Reflection — 0 findings for ${t}`;
    case 'nuclei':
      return `[ ⚪ ] Nuclei — No vulnerabilities found for ${t}`;
    case 'gf':
      return `[ ⚪ ] GF Patterns — No vulnerable parameters found for ${t}`;
    case 's3':
      return `[ ⚪ ] S3 Scan — No exposed buckets found for ${t}`;
    case 'githubscan':
      return `[ ⚪ ] GitHub Scan — No secrets found for ${t}`;
    case 'zerodays':
    case '0days':
      return `[ ⚪ ] 0-Days — No zero-day vulnerabilities found for ${t}`;
    case 'ffuf':
      return `[ ⚪ ] FFuf — No hidden directories found for ${t}`;
    case 'dns':
      return `[ ⚪ ] DNS takeover — No vulnerable records or dangling IPs found for ${t}`;
    case 'cf1016':
      return `[ ⚪ ] CF1016 dangling DNS — No missing Cloudflare origins found for ${t}`;
    case 'lite':
      return `[ ⚪ ] Lite Workflow — No result files were indexed for ${t}. Check Discord (if used) for per-phase summaries, or confirm R2 / artifact indexing.`;
    default: {
      const name = st ? st.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) : 'Scan';
      return `[ ⚪ ] ${name} — 0 findings for ${t}`;
    }
  }
}

function goToScanResultsPage(scanID) {
  if (!scanID) return;
  openScanResultsPage(scanID);
}

/** Categorize scan artifacts for ASM-style layout (recon / vulns / other). */
function categorizeScanArtifactFile(fileName) {
  const n = String(fileName || '').toLowerCase();
  if (!n) return 'other';
  const recon = new Set([
    'subdomains.json', 'livehosts.json', 'urls.json', 'js-urls.json', 'interesting-urls.json',
    'tech-detect.json', 'cname-records.json', 'buckets.json',
  ]);
  const legacyRecon = new Set([
    'all-subs.txt', 'live-subs.txt', 'all-urls.txt', 'js-urls.txt',
    'tech-detect.txt', 'cnames.txt', 'buckets.txt',
  ]);
  if (recon.has(n)) return 'recon';
  if (legacyRecon.has(n)) return 'recon';
  if (n.startsWith('nuclei-')) return 'vuln';
  if (n.includes('zerodays') && n.endsWith('.json')) return 'vuln';
  if ((n.startsWith('gf-') && n.endsWith('.txt')) || n === 'gf-results.txt') return 'vuln';
  if (n.includes('misconfig') && n.endsWith('.txt')) return 'vuln';
  if (n.includes('dalfox') || n.includes('sqlmap')) return 'vuln';
  if (n.includes('depconfusion') && n.endsWith('.txt')) return 'vuln';
  if (n.includes('confused2-web') || (n.includes('confused') && n.endsWith('.log'))) return 'vuln';
  if (n.includes('exposure') && n.endsWith('.txt')) return 'vuln';
  if (n.includes('vulnerabilities') && n.endsWith('.txt')) return 'vuln';
  if (n.endsWith('.log')) return 'other';
  return 'other';
}

/** Detect module from filename */
function detectModuleFromFileName(fileName, existingModule) {
  if (existingModule) return existingModule;

  const n = String(fileName || '').toLowerCase();
  if (!n) return 'unknown';
  if (n.includes('/apkx/') || n.includes('\\apkx\\')) return 'apkx';

  // Nuclei vulnerability scanner
  if (n.startsWith('nuclei-') || n.includes('nuclei')) return 'nuclei';

  // Subdomain enumeration tools
  if (n.includes('subdomain') || n.includes('subfinder') || n.includes('amass')) return 'subdomain-enum';

  // HTTP status checking / live hosts
  if (n.includes('live-subs') || n.includes('httpx') || n.includes('livehosts')) return 'httpx';

  // JavaScript analysis
  if (n.includes('js-urls') || n.includes('javascript') || n.includes('js-')) return 'js-analysis';

  // APK analysis
  if (n.includes('apk') || n.includes('androidmanifest') || n.includes('jadx') || n.includes('dex')) return 'apkx';

  // XSS/Reflection
  if (n.includes('kxss') || n.includes('dalfox') || n.includes('xss-reflection')) return 'xss-detection';
  if (n.includes('reflection')) return 'xss-detection';

  // SQL injection
  if (n.includes('sqlmap') || n.includes('sqli')) return 'sql-detection';

  // GF pattern matching
  if (n.startsWith('gf-') || n.includes('gf-')) return 'gf-patterns';

  // Zero-days/CVE scanning
  if (n.includes('zerodays') || n.includes('cve')) return 'zerodays';

  // Backup files detection
  if (n.includes('backup') || n.includes('fuzzuli')) return 'backup-detection';

  // Misconfiguration
  if (n.includes('misconfig')) return 'misconfig';

  // Source exposure (API keys, secrets)
  if (n.includes('exposure')) return 'exposure';

  // CNAME records (DNS but not takeover)
  if (n.includes('cname')) return 'dns-takeover';

  // Dependency confusion
  if (n.includes('depconfusion') || n.includes('confused')) return 'dependency-confusion';

  // S3 bucket scanning
  if (n.includes('s3') || n.includes('bucket')) return 's3-scan';

  // AEM (Adobe Experience Manager)
  if (n.includes('aem')) return 'aem';

  // Gospider URL crawling
  if (n.includes('gospider')) return 'url-enum';

  // DNS takeover
  if (n.includes('dns') || n.includes('takeover')) return 'dns-takeover';

  // Technology detection
  if (n.includes('tech-detect') || n.includes('wappalyzer')) return 'tech-detect';

  // Port scanning (strict to avoid matching "report")
  if (n.includes('port-scan') || n.includes('ports') || n.includes('nmap') || n.includes('masscan')) return 'port-scan';

  // GitHub/Source code (strict to avoid matching "report")
  if (n.includes('github') || n.includes('github-scan') || n.includes('gh-')) return 'github-scan';

  // URL/FFUF fuzzing
  if (n.includes('ffuf') || n.includes('fuzz')) return 'ffuf-fuzzing';

  // Reflection/parameter detection
  if (n.includes('reflection') || n.includes('param')) return 'reflection';

  // URLs
  if (n.includes('urls.txt') || n.includes('all-urls')) return 'url-enum';

  return 'autoar';
}

/** Get module display name with icon */
function normalizeModuleKey(module) {
  const raw = String(module || '').toLowerCase().trim();
  if (!raw) return 'unknown';
  const aliases = {
    'aem-scan': 'aem',
    'ffuf': 'ffuf-fuzzing',
    'dns': 'dns-takeover',
    'cf1016': 'dns-takeover',
    'dns-cf1016': 'dns-takeover',
    'dep-confusion': 'dependency-confusion',
    'dependency_confusion': 'dependency-confusion',
    'unknowns': 'unknown',
    'apk': 'apkx',
    'apk-analysis': 'apkx',
  };
  return aliases[raw] || raw;
}

/** Get module display name with icon */
function getModuleDisplayInfo(module) {
  const mod = normalizeModuleKey(module);
  const modules = {
    'nuclei': { icon: '🚨', name: 'Nuclei', color: '#ef4444' },
    'subdomain-enum': { icon: '🔗', name: 'Subdomains', color: '#6366f1' },
    'httpx': { icon: '🌐', name: 'Live Hosts', color: '#22c55e' },
    'apkx': { icon: '📱', name: 'APK Analysis', color: '#22d3ee' },
    'js-analysis': { icon: '📜', name: 'JS Analysis', color: '#eab308' },
    'xss-detection': { icon: '💥', name: 'XSS / Reflection', color: '#f97316' },
    'sql-detection': { icon: '🗻', name: 'SQLi', color: '#dc2626' },
    'gf-patterns': { icon: '🎯', name: 'GF Patterns', color: '#8b5cf6' },
    'zerodays': { icon: '💣', name: 'Zero-Days', color: '#dc2626' },
    'backup-detection': { icon: '📂', name: 'Backup Files', color: '#94a3b8' },
    'misconfig': { icon: '⚙️', name: 'Misconfig', color: '#f59e0b' },
    'dependency-confusion': { icon: '🧶', name: 'Dep Confusion', color: '#a855f7' },
    's3-scan': { icon: '☁️', name: 'S3 Buckets', color: '#0ea5e9' },
    'aem': { icon: '🧱', name: 'AEM Enum', color: '#f97316' },
    'aem-scan': { icon: '🧱', name: 'AEM Enum', color: '#f97316' },
    'dns-takeover': { icon: '📍', name: 'DNS', color: '#06b6d4' },
    'tech-detect': { icon: '🔬', name: 'Tech Detect', color: '#a855f7' },
    'port-scan': { icon: '📡', name: 'Port Scan', color: '#64748b' },
    'github-scan': { icon: '🐦', name: 'GitHub Recon', color: '#94a3b8' },
    'reflection': { icon: '🔎', name: 'Reflection', color: '#f97316' },
    'xss-detection': { icon: '💥', name: 'XSS Detection', color: '#f97316' },
    'ffuf-fuzzing': { icon: '🎲', name: 'FFUF Fuzzing', color: '#f43f5e' },
    'url-collection': { icon: '🔗', name: 'URL Collection', color: '#38bdf8' },
    'exposure': { icon: '🔑', name: 'Exposure', color: '#f59e0b' },
    'autoar': { icon: '🎯', name: 'AutoAR', color: '#4ade80' },
    'unknown': { icon: '❓', name: 'Unknown', color: '#64748b' },
  };

  return modules[mod] || modules['unknown'];
}

// ── Module Renderers Registry ────────────────────────────────────────────────

const MODULE_RENDERERS = {
  'js-analysis': renderJSAnalysisRow,
  'nuclei': renderNucleiRow,
  'gf-patterns': renderGFPatternsRow,
  'default': renderDefaultRow,
};

function getUnifiedTableColumns(activeKind) {
  const active = String(activeKind || '');
  const moduleTab = active.startsWith('mod:') ? active.slice(4) : (
    active === 'misconfig' ? 'misconfig'
      : active === 'nuclei' ? 'nuclei'
        : active === 'ffuf' ? 'ffuf-fuzzing'
          : (active === 'apkx' || active.startsWith('apkcat:')) ? 'apkx' : ''
  );
  switch (moduleTab) {
    case 'apkx':
      return ['PATH', 'CATEGORY', 'MATCHER VALUE', 'MODULE'];
    case 'nuclei':
      return ['TARGET', 'SEV', 'TEMPLATE', 'MATCH'];
    case 'gf-patterns':
      return ['TARGET', 'PATTERN', 'VALUE', 'SOURCE'];
    case 'misconfig':
      return ['TARGET', 'SEV', 'SERVICE', 'FINDING'];
    case 'ffuf-fuzzing':
      return ['URL', 'STATUS', 'WORD', 'LENGTH'];
    default:
      return ['TARGET', 'SEV', 'VULNERABILITY TYPE', 'MODULE'];
  }
}

function renderRowForUnifiedTab(r, idx, activeKind, modInfo, sevMeta) {
  const active = String(activeKind || '');
  const moduleTab = active.startsWith('mod:') ? active.slice(4) : (active === 'misconfig' ? 'misconfig' : '');
  const isApkCategoryTab = active.startsWith('apkcat:');
  const isApkUnifiedTab = active === 'apkx' || isApkCategoryTab;
  const target = String(r.host || r.target || '-');
  let displayTarget = target;
  let href = target.startsWith('http') ? target : (target !== '-' ? `https://${target}` : '#');
  const finding = String(r.title || r.finding || '—').trim() || '—';
  const findingShort = finding.length > 88 ? `${finding.slice(0, 86)}...` : finding;
  const source = String(r.file || r.source || '—');
  let apkCategoryLabel = String(r.apk_category || '').trim();
  let apkMatcherValue = String(r.matcher_value || finding);

  if (isApkUnifiedTab) {
    const structuredPath = String(r.path || '').trim();
    const structuredCategory = String(r.category_name || '').trim();
    const structuredContext = String(r.context || '').trim();
    if (structuredCategory) apkCategoryLabel = structuredCategory;
    if (structuredPath) {
      displayTarget = structuredPath;
      href = '#';
    }
    if (!apkCategoryLabel && target && target !== '-' && target !== '—') {
      apkCategoryLabel = target;
    }
    let payload = finding;
    if (apkCategoryLabel && payload.toLowerCase().startsWith(`${apkCategoryLabel.toLowerCase()}:`)) {
      payload = payload.slice(apkCategoryLabel.length + 1).trim();
    }
    const pathMatch = payload.match(/^([^:]+):\s*(.+)$/);
    if (pathMatch && (pathMatch[1].includes('/') || pathMatch[1].includes('\\') || pathMatch[1].includes('.'))) {
      displayTarget = pathMatch[1].trim();
      href = '#';
      apkMatcherValue = pathMatch[2].trim() || payload;
    } else {
      displayTarget = structuredPath || (target && target !== '—' ? target : '—');
      href = '#';
      apkMatcherValue = payload;
    }
    if (structuredContext && !apkMatcherValue.includes('Context:')) {
      apkMatcherValue = `${apkMatcherValue} (Context: ${structuredContext})`;
    }
  }

  if (moduleTab === 'js-analysis') {
    const jsCandidates = [
      String(r.source_file || ''),
      String(r.file || ''),
      String(r.target || ''),
      String(r.finding || ''),
    ].join(' ');
    const jsMatch = jsCandidates.match(/https?:\/\/[^\s"')]+(?:\.js|\.mjs|\.jsx)[^\s"')]*?/i);
    if (jsMatch && jsMatch[0]) {
      displayTarget = jsMatch[0];
      href = jsMatch[0];
    }
  }

  const tdTarget = isApkUnifiedTab
    ? `<td style="padding:7px 10px;max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
      <span title="${esc(displayTarget)}" style="color:var(--accent-cyan);text-decoration:none;font-family:var(--font-mono,monospace);font-size:11.5px">${esc(displayTarget)}</span>
    </td>`
    : `<td style="padding:7px 10px;max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
      <a href="${esc(href)}" target="_blank" rel="noopener" onclick="event.stopPropagation()" title="${esc(displayTarget)}" style="color:var(--accent-cyan);text-decoration:none;font-family:var(--font-mono,monospace);font-size:11.5px">${esc(displayTarget)}</a>
    </td>`;
  const tdSev = isApkUnifiedTab
    ? `<td style="padding:7px 8px;text-align:center;white-space:nowrap">
      <span style="display:inline-block;background:rgba(34,211,238,.12);border:1px solid rgba(34,211,238,.35);color:#67e8f9;font-size:9px;font-weight:800;letter-spacing:.5px;padding:2px 7px;border-radius:4px;max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${esc(apkCategoryLabel || 'APK Analysis')}">${esc(apkCategoryLabel || 'APK Analysis')}</span>
    </td>`
    : `<td style="padding:7px 8px;text-align:center;white-space:nowrap">
      <span style="display:inline-block;background:${sevMeta.bg};border:1px solid ${sevMeta.color}44;color:${sevMeta.color};font-size:9px;font-weight:800;letter-spacing:.7px;padding:2px 7px;border-radius:4px;min-width:34px;">${esc(sevMeta.label)}</span>
    </td>`;
  const tdModule = `<td style="padding:7px 10px;white-space:nowrap;max-width:0;overflow:hidden;text-overflow:ellipsis">
      <span style="color:${modInfo.color};font-size:11px;font-weight:500">${modInfo.icon} ${esc(modInfo.name)}</span>
    </td>`;

  let c2 = tdSev;
  let c3 = `<td style="padding:7px 10px;max-width:0;overflow:hidden"><span title="${esc(isApkUnifiedTab ? apkMatcherValue : finding)}" style="display:inline-block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--font-mono,monospace);font-size:11.5px;color:var(--text-primary);">${esc((isApkUnifiedTab ? apkMatcherValue : findingShort))}</span></td>`;
  let c4 = tdModule;

  if (moduleTab === 'nuclei') {
    const templateId = String(r.template_id || finding || '—');
    const match = String(r.matched_at || r.target || target || '—');
    c3 = `<td style="padding:7px 10px;max-width:0;overflow:hidden"><span title="${esc(templateId)}" style="font-family:var(--font-mono,monospace);font-size:11.5px;color:var(--text-primary)">${esc(templateId)}</span></td>`;
    c4 = `<td style="padding:7px 10px;max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><span title="${esc(match)}" style="font-size:11px;color:var(--text-secondary)">${esc(match)}</span></td>`;
  } else if (moduleTab === 'gf-patterns') {
    const pattern = String(r.pattern || r.finding_type || 'gf-pattern');
    const value = String(r.value || r.finding || '—');
    c2 = `<td style="padding:7px 10px;max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><span style="color:var(--accent-purple);font-size:11px;font-weight:700">${esc(pattern)}</span></td>`;
    c3 = `<td style="padding:7px 10px;max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><span title="${esc(value)}" style="font-family:var(--font-mono,monospace);font-size:11px;color:var(--text-primary)">${esc(value)}</span></td>`;
    c4 = `<td style="padding:7px 10px;max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><span style="font-size:11px;color:var(--text-muted)">${esc(source)}</span></td>`;
  } else if (moduleTab === 'js-analysis') {
    let matcher = String(r.matcher || r.finding_type || '').trim();
    let matched = String(r.value || r.match || '').trim();
    if (!matcher || !matched) {
      const m = finding.match(/^\s*\[([^\]]+)\]\s*(?:https?:\/\/\S+)?\s*->\s*(.+)\s*$/i);
      if (m) {
        if (!matcher) matcher = String(m[1] || '').trim();
        if (!matched) matched = String(m[2] || '').trim();
      }
    }
    const vulnType = matcher && matched
      ? `[${matcher}] ${matched}`
      : (matcher ? `[${matcher}]` : findingShort);
    c3 = `<td style="padding:7px 10px;max-width:0;overflow:hidden"><span title="${esc(finding)}" style="display:inline-block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--font-mono,monospace);font-size:11.5px;color:var(--text-primary);">${esc(vulnType)}</span></td>`;
    c4 = tdModule;
  } else if (moduleTab === 'misconfig') {
    const service = String(r.service || r.service_name || r.module || 'misconfig');
    c3 = `<td style="padding:7px 10px;max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><span style="font-size:11px;color:var(--accent-amber)">${esc(service)}</span></td>`;
    c4 = `<td style="padding:7px 10px;max-width:0;overflow:hidden"><span title="${esc(finding)}" style="display:inline-block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px;color:var(--text-primary)">${esc(findingShort)}</span></td>`;
  } else if (moduleTab === 'ffuf-fuzzing') {
    const status = String(r.status || r.status_code || '—');
    const pathWord = String(r.path || r.word || r.finding_type || '—');
    c2 = `<td style="padding:7px 10px;text-align:center;white-space:nowrap"><span style="font-size:11px;color:var(--accent-cyan);font-family:var(--font-mono,monospace)">${esc(status)}</span></td>`;
    c3 = `<td style="padding:7px 10px;max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><span style="font-size:11px;color:var(--accent-purple)">${esc(pathWord)}</span></td>`;
    c4 = `<td style="padding:7px 10px;max-width:0;overflow:hidden"><span title="${esc(finding)}" style="display:inline-block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px;color:var(--text-primary)">${esc(findingShort)}</span></td>`;
  }

  return `<tr class="findings-row" data-target="${escAttr(displayTarget)}" data-finding="${escAttr(isApkUnifiedTab ? apkMatcherValue : finding)}" data-severity="${escAttr(isApkUnifiedTab ? (apkCategoryLabel || 'APK Analysis') : (r.severity || ''))}" data-module="${escAttr(r.module || '')}" data-href="${escAttr(href)}" style="cursor:pointer;${idx % 2 ? 'background:rgba(255,255,255,.012)' : ''}">
    <td style="padding:7px 10px;width:36px;text-align:center">
      <input type="checkbox" class="finding-chk" style="width:14px;height:14px;accent-color:var(--accent-cyan);cursor:pointer" onclick="event.stopPropagation()">
    </td>
    ${tdTarget}
    ${c2}
    ${c3}
    ${c4}
  </tr>`;
}

function renderDefaultRow(r, idx, modInfo, sevMeta) {
  const target = String(r.host || r.target || '-');
  const vulnType = String(r.title || r.finding || '—').trim();
  const typeLabel = vulnType.length > 72 ? vulnType.slice(0, 70) + '…' : vulnType;
  let href = target.startsWith('http') ? target : (target !== '-' ? 'https://' + target : '#');

  return `<tr class="findings-row" data-target="${escAttr(target)}" data-finding="${escAttr(vulnType)}" data-severity="${escAttr(r.severity)}" data-module="${escAttr(r.module || '')}" style="cursor:pointer;${idx % 2 ? 'background:rgba(255,255,255,.012)' : ''}">
    <td style="padding:7px 10px;width:36px;text-align:center">
      <input type="checkbox" class="finding-chk" style="width:14px;height:14px;accent-color:var(--accent-cyan);cursor:pointer" onclick="event.stopPropagation()">
    </td>
    <td style="padding:7px 10px;max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
      <a href="${esc(href)}" target="_blank" rel="noopener" onclick="event.stopPropagation()" title="${esc(target)}" style="color:var(--accent-cyan);text-decoration:none;font-family:var(--font-mono,monospace);font-size:11.5px">${esc(target)}</a>
    </td>
    <td style="padding:7px 8px;text-align:center;white-space:nowrap">
      <span style="display:inline-block;background:${sevMeta.bg};border:1px solid ${sevMeta.color}44;color:${sevMeta.color};font-size:9px;font-weight:800;letter-spacing:.7px;padding:2px 7px;border-radius:4px;min-width:34px;">${esc(sevMeta.label)}</span>
    </td>
    <td style="padding:7px 10px;max-width:0;overflow:hidden">
      <span title="${esc(vulnType)}" style="display:inline-block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--font-mono,monospace);font-size:11.5px;color:var(--text-primary);">${esc(typeLabel)}</span>
    </td>
    <td style="padding:7px 10px;white-space:nowrap;max-width:0;overflow:hidden;text-overflow:ellipsis">
      <span style="color:${modInfo.color};font-size:11px;font-weight:500">${modInfo.icon} ${esc(modInfo.name)}</span>
    </td>
  </tr>`;
}

function renderJSAnalysisRow(r, idx, modInfo, sevMeta) {
  // Enhanced JS Analysis row: [matcher] - [value]
  const jsFile = String(r.source_file || r.file || '-');
  const matcher = r.matcher || r.finding_type || 'Secret';
  const matchValue = r.finding || r.value || '-';
  const typeDisplay = `[${matcher}] - [${matchValue}]`;
  const typeLabel = typeDisplay.length > 72 ? typeDisplay.slice(0, 70) + '…' : typeDisplay;

  return `<tr class="findings-row js-analysis-row" style="cursor:pointer;${idx % 2 ? 'background:rgba(255,255,255,.012)' : ''}">
    <td style="padding:7px 10px;width:36px;text-align:center">
      <input type="checkbox" class="finding-chk" onclick="event.stopPropagation()">
    </td>
    <td style="padding:7px 10px;max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
      <span title="${esc(jsFile)}" style="color:var(--accent-amber);font-family:var(--font-mono);font-size:11px">${esc(jsFile)}</span>
    </td>
    <td style="padding:7px 8px;text-align:center">
      <span style="background:${sevMeta.bg};color:${sevMeta.color};font-size:9px;padding:2px 6px;border-radius:4px;font-weight:bold">JS</span>
    </td>
    <td style="padding:7px 10px;max-width:0;overflow:hidden">
      <span title="${esc(typeDisplay)}" style="color:var(--text-primary);font-family:var(--font-mono);font-size:11.5px">${esc(typeLabel)}</span>
    </td>
    <td style="padding:7px 10px;white-space:nowrap">
       <span style="color:${modInfo.color};font-size:11px">${modInfo.icon} JS Analysis</span>
    </td>
  </tr>`;
}

function renderNucleiRow(r, idx, modInfo, sevMeta) {
  const target = String(r.host || r.target || '-');
  const templateId = r.template_id || r.finding || '—';
  const info = r.info || {};
  const name = info.name || templateId;

  return `<tr class="findings-row nuclei-row" style="cursor:pointer;${idx % 2 ? 'background:rgba(255,255,255,.012)' : ''}">
    <td style="padding:7px 10px;width:36px;text-align:center">
      <input type="checkbox" class="finding-chk" onclick="event.stopPropagation()">
    </td>
    <td style="padding:7px 10px;max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
      <a href="${target.startsWith('http') ? target : 'https://' + target}" target="_blank" style="color:var(--accent-cyan);font-family:var(--font-mono);font-size:11.5px">${esc(target)}</a>
    </td>
    <td style="padding:7px 8px;text-align:center">
       <span style="background:${sevMeta.bg};border:1px solid ${sevMeta.color}44;color:${sevMeta.color};font-size:9px;font-weight:800;padding:2px 7px;border-radius:4px;">${esc(sevMeta.label)}</span>
    </td>
    <td style="padding:7px 10px;max-width:0;overflow:hidden">
      <div style="color:var(--text-primary);font-weight:600;font-size:12px">${esc(name)}</div>
      <div style="color:var(--text-muted);font-size:10px;font-family:var(--font-mono)">${esc(templateId)}</div>
    </td>
    <td style="padding:7px 10px;white-space:nowrap">
      <span style="color:#ef4444;font-size:11px">☢️ Nuclei</span>
    </td>
  </tr>`;
}

function renderGFPatternsRow(r, idx, modInfo, sevMeta) {
  const target = String(r.host || r.target || '-');
  const pattern = r.pattern || r.module || '—';
  const value = r.finding || r.value || '-';

  return `<tr class="findings-row gf-row" style="cursor:pointer;${idx % 2 ? 'background:rgba(255,255,255,.012)' : ''}">
    <td style="padding:7px 10px;width:36px;text-align:center">
      <input type="checkbox" class="finding-chk" onclick="event.stopPropagation()">
    </td>
    <td style="padding:7px 10px;max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
      <span style="color:var(--accent-cyan);font-family:var(--font-mono);font-size:11.5px">${esc(target)}</span>
    </td>
    <td style="padding:7px 8px;text-align:center">
       <span style="background:rgba(139, 92, 246, 0.1);color:#8b5cf6;font-size:9px;padding:2px 6px;border-radius:4px;font-weight:bold">GF</span>
    </td>
    <td style="padding:7px 10px;max-width:0;overflow:hidden">
      <span style="color:var(--accent-purple);font-weight:700">[${esc(pattern)}]</span>
      <span style="color:var(--text-secondary);font-family:var(--font-mono);font-size:11px;margin-left:4px">${esc(value)}</span>
    </td>
    <td style="padding:7px 10px;white-space:nowrap">
      <span style="color:#8b5cf6;font-size:11px">🎯 GF Patterns</span>
    </td>
  </tr>`;
}

/** Get category display info */
function getCategoryDisplayInfo(category) {
  const cat = String(category || '').toLowerCase();
  const categories = {
    'vulnerability': { icon: '⚠️', name: 'Vulnerability', badge: 'badge-failed' },
    'recon': { icon: '🔭', name: 'Reconnaissance', badge: 'badge-running' },
    'config': { icon: '⚙️', name: 'Configuration', badge: 'badge-starting' },
    'output': { icon: '📊', name: 'Output', badge: 'badge-done' },
    'log': { icon: '📝', name: 'Log', badge: 'badge-monitor-off' },
  };

  return categories[cat] || { icon: '📄', name: 'File', badge: '' };
}

function parseNucleiFindingLine(line) {
  const t = String(line || '').trim();
  if (!t || t.startsWith('#')) return null;
  if (t.startsWith('{')) {
    try {
      const o = JSON.parse(t);
      const url = o['matched-at'] || o.matched_at || o.url || o.host || o.matched || '';
      const template = o['template-id'] || o.template_id || o.templateID || o.template || o.id || '—';
      const sev = (o.info && o.info.severity) || o.severity || '—';
      return { url: String(url || ''), template: String(template), severity: String(sev) };
    } catch {
      return null;
    }
  }
  if (/^https?:\/\//i.test(t)) return { url: t, template: '—', severity: '—' };
  if (t.length > 4 && !/^Nuclei /i.test(t) && !/^Found /i.test(t)) return { url: t, template: '—', severity: '—' };
  return null;
}

function scanArtifactRowHtml(f) {
  const jm = f.is_json ? '✓' : '—';
  const fnAttr = encodeURIComponent(f.file_name);
  return `<tr class="scan-file-row" data-r2="${rkAttr}" style="cursor:pointer">
    <td class="mono scan-asm-fname">${esc(f.file_name)}</td>
    <td>${fmtSize(f.size_bytes)}</td>
    <td><span class="scan-asm-src">${esc(f.source)}</span></td>
    <td>${jm}</td>
    <td><button type="button" class="btn btn-ghost scan-asm-preview-btn" style="font-size:11px;padding:4px 10px">Preview</button></td>
  </tr>`;
}

function scanAsmSectionHtml(id, icon, title, subtitle, files, emptyNote) {
  const body = files.length
    ? `<div class="scan-asm-table-wrap"><table class="data-table scan-asm-file-table"><thead><tr><th>File</th><th>Size</th><th>Source</th><th>JSON</th><th></th></tr></thead><tbody>
        ${files.map(f => scanArtifactRowHtml(f)).join('')}
      </tbody></table></div>`
    : `<div class="scan-asm-empty">${esc(emptyNote)}</div>`;
  return `<section class="scan-asm-section" id="${id}">
    <div class="scan-asm-section-head">
      <span class="scan-asm-sec-icon">${icon}</span>
      <div class="scan-asm-sec-titles">
        <h2 class="scan-asm-sec-title">${esc(title)}</h2>
        <p class="scan-asm-sec-sub">${esc(subtitle)}</p>
      </div>
      <span class="scan-asm-badge">${files.length}</span>
    </div>
    ${body}
  </section>`;
}

async function loadScanDetailVulnerabilityInsights(scanId, allFiles) {
  const nucleiHost = document.getElementById('scan-nuclei-findings-body');
  const zeroHost = document.getElementById('scan-zerodays-insight-body');
  if (nucleiHost) nucleiHost.innerHTML = '<div class="scan-asm-muted">Loading Nuclei findings…</div>';
  if (zeroHost) zeroHost.innerHTML = '<div class="scan-asm-muted">Loading…</div>';

  const nucleiFiles = allFiles.filter(f => {
    const n = (f.file_name || '').toLowerCase();
    return n.startsWith('nuclei-') && n !== 'nuclei-summary.txt';
  });
  const rows = [];
  let anyTrunc = false;
  for (const f of nucleiFiles) {
    try {
      const q = `file_name=${encodeURIComponent(f.file_name)}&page=1&per_page=500`;
      const data = await apiFetch(`/api/scans/${encodeURIComponent(scanId)}/results/file?${q}`);
      if (data.format !== 'text' || !data.lines) continue;
      if ((data.total_lines || 0) > 500) anyTrunc = true;
      for (const line of data.lines) {
        const p = parseNucleiFindingLine(line);
        if (p && p.url) rows.push({ ...p, sourceFile: f.file_name });
      }
    } catch (e) {
      console.warn('[scan detail] nuclei file', f.file_name, e);
    }
  }
  if (nucleiHost) {
    if (!rows.length) {
      nucleiHost.innerHTML = nucleiFiles.length
        ? '<div class="scan-asm-muted">No URL or JSON lines parsed from Nuclei output files (summary-only or empty).</div>'
        : '<div class="scan-asm-muted">No per-template Nuclei outputs (e.g. nuclei-custom-*.txt) for this scan.</div>';
    } else {
      const maxShow = 200;
      const show = rows.slice(0, maxShow);
      let tb = '<table class="scan-asm-data-table"><thead><tr><th>Source file</th><th>Template</th><th>Severity</th><th>Matched</th></tr></thead><tbody>';
      for (const r of show) {
        if (!r.url) continue;
        tb += `<tr><td class="mono">${esc(r.sourceFile)}</td><td class="mono">${esc(r.template)}</td><td><span class="scan-asm-sev">${esc(r.severity)}</span></td><td class="mono scan-asm-url-cell"><a href="${esc(r.url)}" target="_blank" rel="noopener" class="scan-result-link">${esc(r.url)}</a></td></tr>`;
      }
      tb += '</tbody></table>';
      if (rows.length > maxShow) {
        tb += `<p class="scan-asm-muted" style="margin-top:10px">Showing ${maxShow} of ${rows.length} parsed lines.</p>`;
      }
      if (anyTrunc) {
        tb += '<p class="scan-asm-muted" style="margin-top:6px">Some files had more than 500 lines — only the first page was read. Use Preview on a file for full content.</p>';
      }
      nucleiHost.innerHTML = tb;
    }
  }

  const zf = allFiles.find(f => (f.file_name || '').toLowerCase() === 'zerodays-results.json');
  if (zeroHost) {
    if (!zf) {
      zeroHost.innerHTML = '<div class="scan-asm-muted">No zerodays-results.json for this scan.</div>';
    } else {
      try {
        const q = `file_name=${encodeURIComponent(zf.file_name)}&page=1&per_page=80`;
        const data = await apiFetch(`/api/scans/${encodeURIComponent(scanId)}/results/file?${q}`);
        if (data.format === 'json-array' && data.items && data.items.length) {
          const sample = data.items[0];
          const keys = sample && typeof sample === 'object' ? Object.keys(sample) : [];
          let tb = '<table class="scan-asm-data-table"><thead><tr>';
          keys.slice(0, 10).forEach(k => { tb += `<th>${esc(k)}</th>`; });
          tb += '</tr></thead><tbody>';
          for (const item of data.items.slice(0, 40)) {
            tb += '<tr>';
            keys.slice(0, 10).forEach(k => {
              const v = item[k];
              const s = v == null ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v);
              tb += `<td class="mono" style="word-break:break-all">${esc(s.length > 240 ? `${s.slice(0, 240)}…` : s)}</td>`;
            });
            tb += '</tr>';
          }
          tb += '</tbody></table>';
          if ((data.total_items || 0) > 40) {
            tb += `<p class="scan-asm-muted" style="margin-top:8px">Showing 40 of ${data.total_items} items — open Preview on the JSON file for pagination.</p>`;
          }
          zeroHost.innerHTML = tb;
        } else if (data.format === 'json-object' && data.data) {
          zeroHost.innerHTML = `<pre class="scan-asm-json-pre">${esc(JSON.stringify(data.data, null, 2))}</pre>`;
        } else {
          zeroHost.innerHTML = '<div class="scan-asm-muted">Could not parse zerodays JSON.</div>';
        }
      } catch (e) {
        zeroHost.innerHTML = `<div class="scan-asm-muted">${esc(e.message || String(e))}</div>`;
      }
    }
  }
}

function wireScanFileRows(container, scanId) {
  container.querySelectorAll('.scan-file-row').forEach(row => {
    row.addEventListener('click', e => {
      if (e.target.closest('button')) return;
      const raw = row.getAttribute('data-r2');
      const k = raw ? decodeURIComponent(raw) : '';
      if (k) loadScanFilePreview(scanId, k);
    });
  });
  container.querySelectorAll('.scan-file-row button').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const row = e.target.closest('.scan-file-row');
      const raw = row && row.getAttribute('data-r2');
      const k = raw ? decodeURIComponent(raw) : '';
      if (k) loadScanFilePreview(scanId, k);
    });
  });
}

/** Group files by module */
function groupFilesByModule(files) {
  const modules = {};
  files.forEach(f => {
    const mod = detectModuleFromFileName(f.file_name, f.module);
    if (!modules[mod]) modules[mod] = [];
    f._module = mod;
    modules[mod].push(f);
  });
  return modules;
}

/** Parse and render results from a JSON file */
async function parseAndRenderResults(scanId, file, container) {
  try {
    const data = await apiFetch(`/api/scans/${encodeURIComponent(scanId)}/results/file?file_name=${encodeURIComponent(file.file_name)}&page=1&per_page=500`);

    let items = [];
    let resultType = 'generic-json';
    if (data.format === 'json-array') {
      items = data.items || [];
      resultType = detectResultType(items, file);
    } else if (data.format === 'json-object' && data.data) {
      // Try to extract array from common fields
      const obj = data.data;
      for (const key of ['results', 'findings', 'matches', 'issues', 'vulnerabilities', 'data', 'items', 'hosts', 'subdomains']) {
        if (Array.isArray(obj[key])) {
          items = obj[key];
          break;
        }
      }
      if (!items.length) items = [obj];
      resultType = detectResultType(items, file);
    } else if (data.format === 'text' && Array.isArray(data.lines)) {
      const lines = data.lines.map(x => String(x || '').trim()).filter(Boolean);
      const mod = detectModuleFromFileName(file.file_name, file.module);
      if (mod === 'nuclei') {
        const parsed = [];
        for (const line of lines) {
          const p = parseNucleiFindingLine(line);
          if (p) parsed.push({
            template: p.template || '—',
            severity: p.severity || 'info',
            url: p.url || '',
          });
        }
        items = parsed.length ? parsed : lines;
      } else {
        items = lines;
      }
      resultType = detectResultType(items, file);
    }

    if (!items.length) {
      container.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text-muted)">No parseable results in this file</div>';
      return;
    }

    // Detect result type and render appropriate table
    const html = renderResultTable(items, resultType, file);
    container.innerHTML = html;

  } catch (e) {
    container.innerHTML = `<div style="padding:20px;color:var(--accent-red)">Error loading results: ${esc(e.message)}</div>`;
  }
}

/** Detect what type of results we're dealing with */
function detectResultType(items, file) {
  if (!items.length) return 'unknown';

  const first = items[0];
  const fileName = (file.file_name || '').toLowerCase();
  const module = file.module || detectModuleFromFileName(file.file_name);

  // Subdomain results
  if (module === 'subdomain-enum' || fileName.includes('subdomain') || fileName.includes('subs')) {
    if (typeof first === 'string') return 'subdomain-list';
    if (first.subdomain || first.domain || first.host) return 'subdomain-object';
  }

  // HTTPX/Live hosts results
  if (module === 'httpx' || fileName.includes('live') || fileName.includes('httpx') || fileName.includes('livehosts')) {
    if (first.url || first.URL || first.host || first.Host || first.status_code || first.StatusCode || first.status || first.title) return 'httpx-results';
  }

  // Nuclei vulnerability results
  if (module === 'nuclei' || fileName.includes('nuclei')) {
    if (first['template-id'] || first.template_id || first.template || first.severity || first['matched-at']) return 'nuclei-findings';
  }

  // Zerodays results
  if (module === 'zerodays' || fileName.includes('zeroday')) {
    if (first.cve || first.vulnerability || first.exploit) return 'zerodays-findings';
  }

  // JS analysis results
  if (module === 'js-analysis' || fileName.includes('js-')) {
    if (first.url || first.endpoint || first.secret || first.key) return 'js-findings';
  }

  // XSS/Dalfox results
  if (module === 'xss-detection' || fileName.includes('dalfox') || fileName.includes('kxss')) {
    if (first.url && (first.payload || first.parameter)) return 'xss-findings';
  }

  // SQL injection results
  if (module === 'sql-detection' || fileName.includes('sqlmap')) {
    if (first.url && (first.parameter || first.type)) return 'sqli-findings';
  }

  // GF pattern results
  if (module === 'gf-patterns' || fileName.startsWith('gf-')) {
    if (typeof first === 'string') return 'url-list';
    if (first.url) return 'url-list';
  }

  // Backup files
  if (module === 'backup-detection' || fileName.includes('backup')) {
    if (first.url || first.path) return 'backup-findings';
  }

  // Misconfiguration
  if (module === 'misconfig') {
    if (first.url || first.service || first.service_name || first.service_id || first.config || first['matched-at']) return 'misconfig-findings';
  }

  // AEM findings
  if (module === 'aem' || fileName.includes('aem')) {
    if (first.url || first.vulnerable || first.reason) return 'aem-findings';
  }

  // Port scan
  if (module === 'port-scan' || fileName.includes('port') || fileName.includes('nmap')) {
    if (first.port || first.protocol || first.service) return 'port-results';
  }

  // S3 buckets
  if (module === 's3-scan' || fileName.includes('s3') || fileName.includes('bucket')) {
    if (first.bucket || first.key || first.url) return 's3-findings';
  }

  // DNS takeover
  if (module === 'dns-takeover' || fileName.includes('dns')) {
    if (first.domain || first.cname || first.fingerprint) return 'dns-findings';
  }

  // Tech detect
  if (module === 'tech-detect') {
    if (first.url && (first.tech || first.technology || first.framework)) return 'tech-findings';
  }

  // URLs
  if (typeof first === 'string') return 'url-list';
  if (first.url) return 'url-list';

  return 'generic-json';
}

/** Render appropriate table based on result type */
function renderResultTable(items, type, file) {
  const module = file.module || detectModuleFromFileName(file.file_name);
  const moduleInfo = getModuleDisplayInfo(module);

  const header = `
    <div class="result-table-header">
      <div class="result-table-title">
        ${moduleInfo.icon} ${moduleInfo.name} Results
        <span style="font-size:12px;color:var(--text-muted);margin-left:8px">(${items.length} items)</span>
      </div>
    </div>`;

  switch (type) {
    case 'subdomain-list':
      return header + renderSubdomainListTable(items);

    case 'subdomain-object':
      return header + renderSubdomainObjectTable(items);

    case 'httpx-results':
      return header + renderHTTPXTable(items);

    case 'nuclei-findings':
      return header + renderNucleiTable(items);

    case 'zerodays-findings':
      return header + renderZeroDaysTable(items);

    case 'js-findings':
      return header + renderJSFindingsTable(items);

    case 'xss-findings':
      return header + renderXSSFindingsTable(items);

    case 'sqli-findings':
      return header + renderSQLiFindingsTable(items);

    case 'url-list':
      return header + renderURLListTable(items);

    case 'backup-findings':
      return header + renderBackupFindingsTable(items);

    case 'misconfig-findings':
      return header + renderMisconfigTable(items);

    case 'port-results':
      return header + renderPortResultsTable(items);

    case 's3-findings':
      return header + renderS3FindingsTable(items);

    case 'dns-findings':
      return header + renderDNSFindingsTable(items);

    case 'aem-findings':
      return header + renderAEMTable(items);

    case 'tech-findings':
      return header + renderTechFindingsTable(items);

    case 'generic-json':
      return header + renderGenericJSONTable(items);

    default:
      return header + renderGenericJSONTable(items);
  }
}

/** Render subdomain list (simple strings) */
function renderSubdomainListTable(items) {
  const rows = items.map(sub => `
    <tr>
      <td>
        <div style="font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--accent-cyan)">${esc(String(sub))}</div>
      </td>
      <td><span class="badge badge-live">● live</span></td>
      <td style="color:var(--text-muted)">—</td>
      <td style="color:var(--text-muted)">—</td>
    </tr>`).join('');

  return `
    <div class="result-table-wrap">
      <table class="result-table">
        <thead>
          <tr>
            <th>SUBDOMAIN</th>
            <th>STATUS</th>
            <th>HTTP</th>
            <th>HTTPS</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

/** Render subdomain objects with status info */
function renderSubdomainObjectTable(items) {
  const rows = items.map(item => {
    const subdomain = item.subdomain || item.domain || item.host || '—';
    const isLive = item.is_live || item.live || item.status === 'live';
    const httpStatus = item.http_status || item.http || null;
    const httpsStatus = item.https_status || item.https || null;

    return `
      <tr>
        <td>
          <div style="font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--accent-cyan)">${esc(String(subdomain))}</div>
        </td>
        <td>
          <span class="badge ${isLive ? 'badge-live' : 'badge-dead'}">
            ${isLive ? '● live' : '● dead'}
          </span>
        </td>
        <td style="color:var(--text-muted);font-family:'JetBrains Mono',monospace">
          ${httpStatus ? `<span style="color:${getStatusColor(httpStatus)}">${httpStatus}</span>` : '—'}
        </td>
        <td style="color:var(--text-muted);font-family:'JetBrains Mono',monospace">
          ${httpsStatus ? `<span style="color:${getStatusColor(httpsStatus)}">${httpsStatus}</span>` : '—'}
        </td>
      </tr>`;
  }).join('');

  return `
    <div class="result-table-wrap">
      <table class="result-table">
        <thead>
          <tr>
            <th>SUBDOMAIN</th>
            <th>STATUS</th>
            <th>HTTP</th>
            <th>HTTPS</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

/** Render HTTPX results */
function renderHTTPXTable(items) {
  const rows = items.map(item => {
    const url = item.url || item.host || '—';
    const status = item.status_code || item.status || '—';
    const title = item.title || '—';
    const tech = item.tech || item.technologies || '—';

    return `
      <tr>
        <td>
          <div style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan)">${esc(String(url))}</div>
        </td>
        <td>
          <span class="badge ${isLiveStatus(status) ? 'badge-live' : 'badge-dead'}">
            ${status}
          </span>
        </td>
        <td style="color:var(--text-secondary);font-size:12px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
          ${esc(String(title))}
        </td>
        <td style="color:var(--text-muted);font-size:11px;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
          ${esc(String(tech))}
        </td>
      </tr>`;
  }).join('');

  return `
    <div class="result-table-wrap">
      <table class="result-table">
        <thead>
          <tr>
            <th>URL</th>
            <th>STATUS</th>
            <th>TITLE</th>
            <th>TECH</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

/** Render Nuclei vulnerability findings */
function renderNucleiTable(items) {
  const rows = items.map(item => {
    const template = item['template-id'] || item.template_id || item.template || '—';
    const severity = item.info?.severity || item.severity || 'info';
    const matchedAt = item['matched-at'] || item.matched_at || item.url || item.host || '—';
    const description = item.info?.name || item.name || '—';

    return `
      <tr>
        <td>
          <div style="font-size:12px;color:var(--text-secondary);max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
            ${esc(String(template))}
          </div>
        </td>
        <td><span class="severity-${severity.toLowerCase()}">${severity.toUpperCase()}</span></td>
        <td>
          <div style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan);max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
            ${esc(String(matchedAt))}
          </div>
        </td>
        <td style="font-size:12px;color:var(--text-muted);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
          ${esc(String(description))}
        </td>
      </tr>`;
  }).join('');

  return `
    <div class="result-table-wrap">
      <table class="result-table">
        <thead>
          <tr>
            <th>TEMPLATE</th>
            <th>SEVERITY</th>
            <th>MATCHED AT</th>
            <th>DESCRIPTION</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

/** Render ZeroDays findings */
function renderZeroDaysTable(items) {
  const rows = items.map(item => {
    const cve = item.cve || item.vulnerability || '—';
    const host = item.host || item.url || '—';
    const status = item.status || item.result || '—';
    const details = item.details || item.description || '—';

    return `
      <tr>
        <td><span class="severity-high">${esc(String(cve))}</span></td>
        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan)">${esc(String(host))}</td>
        <td><span class="badge ${status === 'vulnerable' ? 'badge-failed' : 'badge-done'}">${esc(String(status))}</span></td>
        <td style="font-size:12px;color:var(--text-muted);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(String(details))}</td>
      </tr>`;
  }).join('');

  return `
    <div class="result-table-wrap">
      <table class="result-table">
        <thead>
          <tr>
            <th>CVE</th>
            <th>HOST</th>
            <th>STATUS</th>
            <th>DETAILS</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

/** Render JS findings with enhanced parsing */
function renderJSFindingsTable(items) {
  const rows = items.map(item => {
    let url = item.url || item.endpoint || '—';
    let secret = item.secret || item.key || item.type || '—';
    let details = item.details || item.description || '—';
    let tag = '';
    let matcher = '';

    // If it's a raw string from the JS analysis module, parse it:
    // Format: [tag] URL -> matcher
    const rawStr = typeof item === 'string' ? item : (item.url && item.url.includes(' -> ') ? item.url : '');
    if (rawStr) {
      const tagMatch = rawStr.match(/^\[(.*?)\]/);
      if (tagMatch) {
        tag = tagMatch[1];
        const rest = rawStr.substring(tagMatch[0].length).trim();
        if (rest.includes(' -> ')) {
          const parts = rest.split(' -> ');
          url = parts[0].trim();
          matcher = parts[1].trim();
        } else {
          url = rest;
        }
      }
    }

    return `
      <tr>
        <td>
          <div style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan);max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(url)}">
            ${esc(url)}
          </div>
        </td>
        <td>
          ${tag ? `<span class="badge badge-info" style="background:rgba(56,189,248,0.15);color:var(--accent-cyan);border:1px solid rgba(56,189,248,0.3)">${esc(tag)}</span>` : `<span class="badge badge-running">${esc(secret)}</span>`}
        </td>
        <td>
          ${matcher ? `<code style="font-size:11px;background:rgba(234,179,8,0.1);color:#eab308;padding:2px 6px;border-radius:4px;border:1px solid rgba(234,179,8,0.2)">${esc(matcher)}</code>` : `<span style="font-size:12px;color:var(--text-muted)">${esc(details)}</span>`}
        </td>
      </tr>`;
  }).join('');

  return `
    <div class="result-table-wrap">
      <table class="result-table">
        <thead>
          <tr>
            <th>TARGET (JS FILE)</th>
            <th>VULN TYPE</th>
            <th>MATCH / LEAK</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

/** Render XSS findings */
function renderXSSFindingsTable(items) {
  const rows = items.map(item => {
    const url = item.url || '—';
    const parameter = item.parameter || item.param || '—';
    const payload = item.payload || '—';

    return `
      <tr>
        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan);max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(String(url))}</td>
        <td><code style="font-size:11px;background:var(--accent-amber-dim);padding:2px 6px;border-radius:4px">${esc(String(parameter))}</code></td>
        <td style="font-size:11px;color:var(--text-muted);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:'JetBrains Mono',monospace">${esc(String(payload))}</td>
      </tr>`;
  }).join('');

  return `
    <div class="result-table-wrap">
      <table class="result-table">
        <thead>
          <tr>
            <th>URL</th>
            <th>PARAMETER</th>
            <th>PAYLOAD</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

/** Render SQL injection findings */
function renderSQLiFindingsTable(items) {
  const rows = items.map(item => {
    const url = item.url || '—';
    const parameter = item.parameter || item.param || '—';
    const type = item.type || '—';
    const db = item.dbms || item.database || '—';

    return `
      <tr>
        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(String(url))}</td>
        <td><code style="font-size:11px;background:var(--accent-red-dim);padding:2px 6px;border-radius:4px">${esc(String(parameter))}</code></td>
        <td><span class="severity-high">${esc(String(type))}</span></td>
        <td style="font-size:12px;color:var(--text-muted)">${esc(String(db))}</td>
      </tr>`;
  }).join('');

  return `
    <div class="result-table-wrap">
      <table class="result-table">
        <thead>
          <tr>
            <th>URL</th>
            <th>PARAMETER</th>
            <th>TYPE</th>
            <th>DBMS</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

/** Render URL list */
function renderURLListTable(items) {
  const rows = items.map(item => {
    const url = typeof item === 'string' ? item : (item.url || '—');
    return `
      <tr>
        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan);word-break:break-all">${esc(String(url))}</td>
      </tr>`;
  }).join('');

  return `
    <div class="result-table-wrap">
      <table class="result-table">
        <thead>
          <tr>
            <th>URL</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

/** Render backup findings */
function renderBackupFindingsTable(items) {
  const rows = items.map(item => {
    const url = item.url || '—';
    const path = item.path || item.file || '—';
    const size = item.size || '—';

    return `
      <tr>
        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan);max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(String(url))}</td>
        <td style="font-size:12px;color:var(--text-secondary)">${esc(String(path))}</td>
        <td style="font-size:12px;color:var(--text-muted)">${esc(String(size))}</td>
      </tr>`;
  }).join('');

  return `
    <div class="result-table-wrap">
      <table class="result-table">
        <thead>
          <tr>
            <th>URL</th>
            <th>PATH</th>
            <th>SIZE</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

/** Render misconfiguration findings */
function renderMisconfigTable(items) {
  const rows = items.map(item => {
    const url = item.url || '—';
    const service = item.service_name || item.service_id || item.service || '—';
    const config = item['matched-at'] || item.matched_at || item.config || item.setting || '—';
    const severity = item.severity || 'medium';

    return `
      <tr>
        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(String(url))}</td>
        <td style="font-size:12px;color:var(--text-secondary)">${esc(String(service))}</td>
        <td style="font-size:12px;color:var(--text-muted);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(String(config))}</td>
        <td><span class="severity-${severity.toLowerCase()}">${severity.toUpperCase()}</span></td>
      </tr>`;
  }).join('');

  return `
    <div class="result-table-wrap">
      <table class="result-table">
        <thead>
          <tr>
            <th>URL / TARGET</th>
            <th>SERVICE</th>
            <th>MATCHED AT / CONFIG</th>
            <th>SEVERITY</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

/** Render AEM findings */
function renderAEMTable(items) {
  const rows = items.map(item => {
    const url = item.url || '—';
    const vulnerable = item.vulnerable ? '<span class="badge badge-live">VULNERABLE</span>' : '<span class="badge badge-dead">INFO</span>';
    const reason = item.reason || '—';
    const severity = item.severity || (item.vulnerable ? 'high' : 'info');

    return `
      <tr>
        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan)">${esc(String(url))}</td>
        <td>${vulnerable}</td>
        <td style="font-size:12px;color:var(--text-muted)">${esc(String(reason))}</td>
        <td><span class="severity-${severity.toLowerCase()}">${severity.toUpperCase()}</span></td>
      </tr>`;
  }).join('');

  return `
    <div class="result-table-wrap">
      <table class="result-table">
        <thead>
          <tr>
            <th>URL</th>
            <th>STATUS</th>
            <th>REASON / EVIDENCE</th>
            <th>SEVERITY</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

/** Render port scan results */
function renderPortResultsTable(items) {
  const rows = items.map(item => {
    const host = item.host || item.ip || '—';
    const port = item.port || '—';
    const protocol = item.protocol || 'tcp';
    const service = item.service || item.name || '—';
    const state = item.state || item.status || 'open';

    return `
      <tr>
        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan)">${esc(String(host))}</td>
        <td><span style="color:var(--accent-purple);font-weight:600">${esc(String(port))}</span></td>
        <td style="font-size:12px;color:var(--text-muted);text-transform:uppercase">${esc(String(protocol))}</td>
        <td style="font-size:12px;color:var(--text-secondary)">${esc(String(service))}</td>
        <td><span class="badge ${state === 'open' ? 'badge-live' : 'badge-dead'}">${esc(String(state))}</span></td>
      </tr>`;
  }).join('');

  return `
    <div class="result-table-wrap">
      <table class="result-table">
        <thead>
          <tr>
            <th>HOST</th>
            <th>PORT</th>
            <th>PROTOCOL</th>
            <th>SERVICE</th>
            <th>STATE</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

/** Render S3 findings */
function renderS3FindingsTable(items) {
  const rows = items.map(item => {
    const bucket = item.bucket || '—';
    const url = item.url || '—';
    const keys = item.keys || item.objects || '—';
    const public_ = item.public || item.open || false;

    return `
      <tr>
        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan)">${esc(String(bucket))}</td>
        <td style="font-size:12px;color:var(--text-secondary);max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(String(url))}</td>
        <td style="font-size:12px;color:var(--text-muted)">${esc(String(keys))}</td>
        <td><span class="badge ${public_ ? 'badge-failed' : 'badge-done'}">${public_ ? 'PUBLIC' : 'PRIVATE'}</span></td>
      </tr>`;
  }).join('');

  return `
    <div class="result-table-wrap">
      <table class="result-table">
        <thead>
          <tr>
            <th>BUCKET</th>
            <th>URL</th>
            <th>OBJECTS</th>
            <th>ACCESS</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

/** Render DNS takeover findings */
function renderDNSFindingsTable(items) {
  const rows = items.map(item => {
    const domain = item.domain || item.subdomain || '—';
    const cname = item.cname || '—';
    const fingerprint = item.fingerprint || item.provider || '—';
    const vulnerable = item.vulnerable || item.takoverable || false;

    return `
      <tr>
        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan)">${esc(String(domain))}</td>
        <td style="font-size:12px;color:var(--text-muted);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(String(cname))}</td>
        <td style="font-size:12px;color:var(--text-secondary)">${esc(String(fingerprint))}</td>
        <td><span class="badge ${vulnerable ? 'badge-failed' : 'badge-done'}">${vulnerable ? 'VULNERABLE' : 'SAFE'}</span></td>
      </tr>`;
  }).join('');

  return `
    <div class="result-table-wrap">
      <table class="result-table">
        <thead>
          <tr>
            <th>DOMAIN</th>
            <th>CNAME</th>
            <th>FINGERPRINT</th>
            <th>STATUS</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

/** Render technology detection findings */
function renderTechFindingsTable(items) {
  const rows = items.map(item => {
    const url = item.url || '—';
    const tech = item.tech || item.technology || item.name || '—';
    const version = item.version || '—';
    const category = item.category || '—';

    return `
      <tr>
        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(String(url))}</td>
        <td><span class="badge badge-running">${esc(String(tech))}</span></td>
        <td style="font-size:12px;color:var(--text-muted)">${esc(String(version))}</td>
        <td style="font-size:12px;color:var(--text-secondary)">${esc(String(category))}</td>
      </tr>`;
  }).join('');

  return `
    <div class="result-table-wrap">
      <table class="result-table">
        <thead>
          <tr>
            <th>URL</th>
            <th>TECHNOLOGY</th>
            <th>VERSION</th>
            <th>CATEGORY</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

/** Render generic JSON table */
function renderGenericJSONTable(items) {
  const headers = Object.keys(items[0] || {});
  const headerRow = headers.map(h => `<th style="text-transform:uppercase">${esc(h)}</th>`).join('');

  const rows = items.slice(0, 100).map(item => {
    const cells = headers.map(h => {
      const val = item[h];
      const display = typeof val === 'object' ? JSON.stringify(val) : String(val);
      return `<td style="font-size:12px;color:var(--text-secondary);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(display)}</td>`;
    }).join('');
    return `<tr>${cells}</tr>`;
  }).join('');

  return `
    <div class="result-table-wrap">
      <table class="result-table">
        <thead><tr>${headerRow}</tr></thead>
        <tbody>${rows}</tbody>
      </table>
      ${items.length > 100 ? `<div style="padding:12px;text-align:center;color:var(--text-muted);font-size:12px">Showing first 100 of ${items.length} items</div>` : ''}
    </div>`;
}

/** Helper: Get color for HTTP status */
function getStatusColor(status) {
  if (!status) return 'var(--text-muted)';
  const s = Number(status);
  if (s >= 200 && s < 300) return 'var(--accent-emerald)';
  if (s >= 300 && s < 400) return 'var(--accent-cyan)';
  if (s >= 400 && s < 500) return 'var(--accent-amber)';
  if (s >= 500) return 'var(--accent-red)';
  return 'var(--text-muted)';
}

/** Helper: Check if status indicates live */
function isLiveStatus(status) {
  if (!status) return false;
  const s = Number(status);
  return s >= 200 && s < 400;
}

/** Filter files based on search query and filters */
function filterScanFiles(files, searchQuery, filters = {}) {
  let filtered = files;

  // Apply search query
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(f =>
      f.file_name.toLowerCase().includes(q) ||
      (f.source && f.source.toLowerCase().includes(q)) ||
      (f.module && f.module.toLowerCase().includes(q)) ||
      (f.category && f.category.toLowerCase().includes(q))
    );
  }

  // Apply module filter
  if (filters.module) {
    filtered = filtered.filter(f => {
      const mod = detectModuleFromFileName(f.file_name, f.module);
      return mod === filters.module;
    });
  }

  // Apply category filter
  if (filters.category) {
    filtered = filtered.filter(f => {
      const cat = f.category || categorizeScanArtifactFile(f.file_name);
      return cat === filters.category;
    });
  }

  // Apply type filter (JSON/Text)
  if (filters.type) {
    filtered = filtered.filter(f => {
      if (filters.type === 'json') return f.is_json;
      if (filters.type === 'text') return !f.is_json;
      return true;
    });
  }

  return filtered;
}

/** Render module badge */
function renderModuleBadge(module) {
  const info = getModuleDisplayInfo(module);
  return `<span class="module-badge" style="background:${info.color}22;color:${info.color};border:1px solid ${info.color}44">
    ${info.icon} ${info.name}
  </span>`;
}

/** Render category badge */
function renderCategoryBadge(category) {
  const info = getCategoryDisplayInfo(category);
  return `<span class="category-badge ${info.badge}">
    ${info.icon} ${info.name}
  </span>`;
}

/** Copy all results to clipboard */
async function copyAllScanResults(scanId) {
  try {
    showToast('info', 'Copying results...', 'Fetching all file contents');

    const sum = await apiFetch(`/api/scans/${encodeURIComponent(scanId)}/results/summary?page=1&per_page=200`);
    const files = sum.files || [];

    let allContent = `AutoAR Scan Results - ${scanId}\n`;
    allContent += `Generated: ${new Date().toISOString()}\n`;
    allContent += `${'='.repeat(80)}\n\n`;

    for (const f of files) {
      allContent += `\n${'='.repeat(80)}\n`;
      allContent += `FILE: ${f.file_name}\n`;
      allContent += `MODULE: ${detectModuleFromFileName(f.file_name, f.module)}\n`;
      allContent += `SOURCE: ${f.source}\n`;
      allContent += `${'='.repeat(80)}\n\n`;

      try {
        const data = await apiFetch(`/api/scans/${encodeURIComponent(scanId)}/results/file?file_name=${encodeURIComponent(f.file_name)}&page=1&per_page=500`);
        if (data.format === 'text' && data.lines) {
          allContent += data.lines.join('\n');
        } else if (data.format === 'json-array' && data.items) {
          allContent += JSON.stringify(data.items, null, 2);
        } else if (data.format === 'json-object' && data.data) {
          allContent += JSON.stringify(data.data, null, 2);
        } else {
          allContent += '[Content not available or too large]';
        }
      } catch (e) {
        allContent += `[Error loading file: ${e.message}]`;
      }

      allContent += '\n\n';
    }

    await copyToClipboard(allContent);
    showToast('success', 'Results copied!', `${files.length} files copied to clipboard`);
  } catch (e) {
    showToast('error', 'Copy failed', e.message);
  }
}

/** Render scan results with enhanced filtering and module display */
async function renderScanDetailView(scanId) {
  const container = document.getElementById('scan-detail-container');
  const sub = document.getElementById('scan-detail-sub');
  const apiA = document.getElementById('scan-detail-api');
  if (!container) return;
  const ui = state.scanDetailUI;

  // Show modern loading skeleton
  container.innerHTML = `
    <div class="scan-detail-modern">
      <div class="scan-summary-stats">
        ${[1, 2, 3, 4].map(() => `
          <div class="skeleton-card">
            <div class="skeleton-line skeleton-title"></div>
            <div class="skeleton-line skeleton-text"></div>
          </div>
        `).join('')}
      </div>
      <div class="skeleton-card">
        <div class="skeleton-line skeleton-title"></div>
        <div class="skeleton-line skeleton-text"></div>
        <div class="skeleton-line skeleton-text"></div>
      </div>
    </div>`;

  try {
    const sum = await apiFetch(
      `/api/scans/${encodeURIComponent(scanId)}/results/summary?page=${ui.filesPage}&per_page=${ui.filesPerPage}`
    );
    const manifestResp = await fetchScanManifest(scanId);
    const scan = sum.scan;
    const target = scan.target || scan.Target || '';
    const st = scan.scan_type || scan.ScanType || '';
    const stat = scan.status || scan.Status || '';
    const statLower = stat.toLowerCase();
    const titleEl = document.getElementById('scan-detail-title');
    if (titleEl) titleEl.textContent = target || 'Scan results';

    // Render scan type + status with live badge if running
    if (sub) {
      const isActive = /running|starting|paused|cancelling/i.test(stat);
      if (isActive) {
        const isCancelling = /cancelling/i.test(stat);
        const isPaused = /paused/i.test(stat);
        const liveBadge = isPaused
          ? `<span class="badge badge-starting" style="font-size:10px;padding:2px 8px;margin-left:8px">⏸ paused</span>`
          : isCancelling
            ? `<span class="badge badge-starting" style="font-size:10px;padding:2px 8px;margin-left:8px">⋯ stopping</span>`
            : `<span class="badge badge-running" style="font-size:10px;padding:2px 8px;margin-left:8px;animation:pulse 1.4s ease-in-out infinite">● live</span>`;
        sub.innerHTML = `${esc(st)} · ${esc(statLower)}${liveBadge}`;
      } else {
        sub.textContent = `${st} · ${statLower}`;
      }
    }
    if (apiA) {
      apiA.href = `/api/scans/${encodeURIComponent(scanId)}`;
      apiA.style.display = 'inline-flex';
    }

    // Wire Rescan button — only show for completed/failed scans, not running ones.
    const rescanDetailBtn = document.getElementById('scan-detail-rescan-btn');
    if (rescanDetailBtn) {
      const isActive = /running|starting|paused|cancelling/i.test(stat);
      if (!isActive) {
        rescanDetailBtn.style.display = 'inline-flex';
        rescanDetailBtn._rescan = () => rescanScan(scanId);
      } else {
        rescanDetailBtn.style.display = 'none';
        rescanDetailBtn._rescan = null;
      }
    }
    const clearCacheBtn = document.getElementById('scan-detail-clear-cache-btn');
    if (clearCacheBtn) {
      const isApkx = /apkx/i.test(String(st || ''));
      clearCacheBtn.style.display = isApkx ? 'inline-flex' : 'none';
      clearCacheBtn.onclick = isApkx ? () => clearApkxCacheForScan(scan) : null;
    }

    const files = sum.files || [];
    const total = sum.total || 0;


    const totalFiles = total;

    const statNorm = String(stat || '').trim();
    const finishedOk = /^(completed|done|success)$/i.test(statNorm);
    const stillRunning = /^(running|pending|queued|active|in_progress|in progress)$/i.test(statNorm);
    const failedish = /fail|error|cancel/i.test(statNorm);

    // Build empty summary bar (removed - all modules now generate JSON files)
    const summaryStatsHtml = '';

    const zipURL = scan.result_url || scan.ResultURL || '';
    const zipBanner = zipURL
      ? `<div class="modern-card" style="padding:18px">
          <div style="display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap">
            <div>
              <div style="font-size:14px;font-weight:600;color:var(--text-primary);margin-bottom:4px">📦 Full Scan Archive</div>
              <div style="font-size:12px;color:var(--text-muted)">Download complete scan results as ZIP</div>
            </div>
            <a href="${esc(zipURL)}" target="_blank" rel="noopener" class="btn btn-primary">Download ZIP</a>
          </div>
        </div>`
      : '';
    const manifestCard = renderScanManifestCard(manifestResp?.manifest || null, scan);

    let emptyBanner = '';
    if (!files.length) {
      let emptyMsg;
      if (finishedOk) {
        emptyMsg = `<div class="scan-no-results-banner">${esc(scanNoArtifactsMessage(st, target))}</div>
          <p class="scan-asm-muted" style="margin-top:12px">No files were indexed for this scan. Confirm uploads and artifact indexing.</p>`;
      } else if (stillRunning) {
        emptyMsg = '<div style="text-align:center;padding:20px"><div style="font-size:40px;margin-bottom:12px">⏳</div><div style="font-size:14px;color:var(--text-secondary)">Scan is still running or processing. Check back soon for results.</div></div>';
      } else if (failedish) {
        emptyMsg = `<div style="text-align:center;padding:20px"><div style="font-size:40px;margin-bottom:12px">❌</div><div style="font-size:14px;color:var(--accent-red)">No result files indexed. Status: ${esc(statNorm)}</div></div>`;
      } else {
        emptyMsg = '<div style="text-align:center;padding:20px"><div style="font-size:40px;margin-bottom:12px">📋</div><div style="font-size:14px;color:var(--text-muted)">No indexed artifacts for this scan yet.</div></div>';
      }
      emptyBanner = `<div class="modern-card" style="padding:20px">${emptyMsg}</div>`;
    }

    const overflowNote = total > ui.filesPerPage
      ? `<p class="scan-asm-muted" style="margin:12px 0 0;text-align:center">Showing first ${ui.filesPerPage} of ${total} indexed artifacts.</p>`
      : '';

    // Clean table view for Files tab
    const fileGridHtml = files.length ? `
      <div class="modern-card">
        <div class="card-header">
          <div class="card-title"><span class="card-title-icon">📁</span>All Files</div>
          <button class="btn btn-ghost" id="copy-all-results-btn" style="font-size:12px;padding:6px 12px">
            📋 Copy All
          </button>
        </div>

        <!-- Search and Filter Bar -->
        <div style="padding:16px;border-bottom:1px solid var(--border)">
          <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:center">
            <div style="flex:1;min-width:250px">
              <input
                type="text"
                id="scan-file-search"
                placeholder="🔍 Search files, modules, sources..."
                style="width:100%;padding:8px 12px;background:var(--bg-input);border:1px solid var(--border);border-radius:8px;color:var(--text-primary);font-size:13px"
              />
            </div>
            <div style="min-width:150px">
              <select id="scan-module-filter" style="width:100%;padding:8px 12px;background:var(--bg-input);border:1px solid var(--border);border-radius:8px;color:var(--text-primary);font-size:13px;cursor:pointer">
                <option value="">All Modules</option>
                <option value="nuclei">☢️ Nuclei</option>
                <option value="subdomain-enum">🔍 Subdomain Enum</option>
                <option value="httpx">🌐 HTTPX</option>
                <option value="js-analysis">📜 JS Analysis</option>
                <option value="xss-detection">⚡ XSS Detection</option>
                <option value="sql-detection">💉 SQL Detection</option>
                <option value="gf-patterns">🎯 GF Patterns</option>
                <option value="zerodays">🚨 ZeroDays</option>
                <option value="backup-detection">💾 Backup Files</option>
                <option value="misconfig">⚙️ Misconfig</option>
                <option value="dependency-confusion">📦 Dep Confusion</option>
                <option value="s3-scan">🪣 S3 Scan</option>
                <option value="dns-takeover">🔀 DNS Takeover</option>
                <option value="tech-detect">🔬 Tech Detect</option>
                <option value="port-scan">🔌 Port Scan</option>
                <option value="github-scan">🐙 GitHub Scan</option>
                <option value="ffuf-fuzzing">🎲 FFUF Fuzzing</option>
                <option value="reflection">🔎 Reflection</option>
              </select>
            </div>
            <div style="min-width:130px">
              <select id="scan-category-filter" style="width:100%;padding:8px 12px;background:var(--bg-input);border:1px solid var(--border);border-radius:8px;color:var(--text-primary);font-size:13px;cursor:pointer">
                <option value="">All Categories</option>
                <option value="vulnerability">⚠️ Vulnerability</option>
                <option value="recon">🔭 Recon</option>
                <option value="config">⚙️ Config</option>
                <option value="output">📊 Output</option>
                <option value="log">📝 Log</option>
              </select>
            </div>
            <div style="min-width:110px">
              <select id="scan-type-filter" style="width:100%;padding:8px 12px;background:var(--bg-input);border:1px solid var(--border);border-radius:8px;color:var(--text-primary);font-size:13px;cursor:pointer">
                <option value="">All Types</option>
                <option value="json">🟣 JSON</option>
                <option value="text">📝 Text</option>
              </select>
            </div>
          </div>
        </div>

        <!-- Files Table -->
        <div style="overflow-x:auto">
          <table class="dashboard-table" id="files-table">
            <thead>
              <tr id="recon-unified-headrow">
                <th style="width:50px">#</th>
                <th style="width:32px">📄</th>
                <th>Filename</th>
                <th>Module</th>
                <th>Size</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              ${files.map((f, idx) => {
      const fileType = getFileTypeFromName(f.file_name);
      const icon = getFileTypeIcon(fileType);
      const module = detectModuleFromFileName(f.file_name, f.module);
      const moduleInfo = getModuleDisplayInfo(module);

      return `
                  <tr class="dashboard-table-row" data-file-name="${encodeURIComponent(f.file_name)}" onclick="loadScanFilePreview('${scanId}', '${esc(f.file_name)}')">
                    <td style="color:var(--text-muted);font-size:12px">${idx + 1}</td>
                    <td class="table-cell-icon">${icon}</td>
                    <td class="table-cell-mono" title="${esc(f.file_name)}">${esc(f.file_name)}</td>
                    <td>
                      <span class="module-badge" style="background:${moduleInfo.color}20;color:${moduleInfo.color};border-color:${moduleInfo.color}40">
                        ${moduleInfo.icon} ${moduleInfo.name}
                      </span>
                    </td>
                    <td class="table-cell-mono" style="font-size:12px">${fmtSize(f.size_bytes)}</td>
                    <td>
                      <span class="badge badge-${f.is_json ? 'done' : 'neutral'}">${f.is_json ? 'JSON' : 'TXT'}</span>
                    </td>
                  </tr>`;
    }).join('')}
            </tbody>
          </table>
        </div>
        <div style="padding:16px;border-top:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;background:var(--bg-secondary);border-radius:0 0 12px 12px">
          <div style="font-size:12px;color:var(--text-muted)">
            Showing ${files.length} of ${total} files (Page ${ui.filesPage})
          </div>
          <div style="display:flex;gap:8px">
            <button class="btn btn-ghost" onclick="prevFilesPage('${scanId}')" ${ui.filesPage === 1 ? 'disabled' : ''} style="padding:4px 12px;font-size:12px">
              ← Previous
            </button>
            <button class="btn btn-ghost" onclick="nextFilesPage('${scanId}', ${total})" ${ui.filesPage * ui.filesPerPage >= total ? 'disabled' : ''} style="padding:4px 12px;font-size:12px">
              Next →
            </button>
          </div>
        </div>
      </div>` : '';



    // Other Files section removed — all files are now shown in the Findings tabs above

    let html;
    if (!files.length) {
      html = `
        <div class="scan-detail-modern">
          ${zipBanner}
          ${manifestCard}
          ${emptyBanner}
          <div class="modern-card" style="padding:20px">
            <div style="text-align:center;color:var(--text-muted)">No files to preview.</div>
          </div>
        </div>`;
    } else {
      html = `
        <div class="scan-detail-modern">
          ${zipBanner}
          ${manifestCard}
          ${emptyBanner}
          
          <!-- Unified Findings Card -->
          <div class="modern-card">
            <div class="card-header">
              <div class="card-title"><span class="card-title-icon">📊</span>Findings</div>
              <span class="badge badge-running" id="unified-parsed-badge">${total} files</span>
            </div>
            <div id="unified-parsed-results" style="padding:16px">
              <div style="text-align:center;padding:20px;color:var(--text-muted)">Loading all findings...</div>
            </div>
          </div>
        </div>`;
    }

    container.innerHTML = html;

    // Wire export CSV button
    const exportCsvBtn = document.getElementById('scan-detail-export-csv-btn');
    if (exportCsvBtn) {
      exportCsvBtn.onclick = () => exportScanResultsCSV(scanId);
    }

    // Wire up file clicks for legacy table rows if any
    wireScanFileRows(container, scanId);

    // Wire up search and filter functionality
    wireScanDetailFilters(scanId, files);

    // Load unified findings table (all files in one table with sub-tabs)
    loadReconUnifiedTable(scanId, files, 'unified-parsed-results', scan);

    // Load vulnerability insights if files exist
    if (files.length) {
      loadScanDetailVulnerabilityInsights(scanId, files);
    }

    // Restore selected file if any
    if (ui.selectedFileName) {
      requestAnimationFrame(() => {
        loadScanFilePreview(scanId, ui.selectedFileName, { retainPage: true });
      });
    }
    // ── Auto-refresh while scan is running ───────────────────────────────────
    if (stillRunning) {
      scheduleScanDetailRefresh(scanId);
    } else {
      clearScanDetailRefreshTimer();
    }

  } catch (e) {
    container.innerHTML = `<div class="modern-card" style="padding:20px;border-color:var(--accent-red)"><div style="color:var(--accent-red)">${esc(e.message || String(e))}</div></div>`;
  }
}

async function clearApkxCacheForScan(scan) {
  const target = String(scan?.target || scan?.Target || '').trim();
  const looksLikePackage = /^[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+$/.test(target);
  const scopeLabel = looksLikePackage ? `package cache for ${target}` : 'ALL APK cache';
  if (!confirm(`Clear ${scopeLabel}?`)) return;
  try {
    const body = looksLikePackage ? { package: target } : { all: true };
    const res = await apiPost('/api/apkx/cache/clear', body);
    const localN = Number(res?.local_removed || 0);
    const r2N = Number(res?.r2_removed || 0);
    const r2Err = String(res?.r2_error || '').trim();
    showToast('success', 'APK cache cleared', `Local: ${localN}, R2: ${r2N}${r2Err ? ' (R2 warning)' : ''}`);
    if (r2Err) console.warn('[apkx cache clear] r2 warning:', r2Err);
  } catch (e) {
    showToast('error', 'Failed to clear APK cache', e.message || String(e));
  }
}

// ── Scan detail real-time refresh helpers ────────────────────────────────────

function clearScanDetailRefreshTimer() {
  if (_scanDetailRefreshTimer) {
    clearTimeout(_scanDetailRefreshTimer);
    _scanDetailRefreshTimer = null;
  }
}

function scheduleScanDetailRefresh(scanId, ms = 4000) {
  clearScanDetailRefreshTimer();
  _scanDetailRefreshId = scanId;
  _scanDetailRefreshTimer = setTimeout(() => doScanDetailRefresh(scanId), ms);
}

async function refreshScanDetailIfRunning(scanId) {
  // Called by startPolling; only act if scan detail page is active for THIS scan
  if (state.view !== 'scan-detail' || state.scanDetailId !== scanId) return;

  // Double check it's actually in our active scans list to avoid polling completed scans
  const activeIds = (state.scans?.active_scans || []).map(s => String(s.id || s.Id || ''));
  if (!activeIds.includes(String(scanId))) {
    // If not active anymore, ensure we stop any detail timers
    clearScanDetailRefreshTimer();
    return;
  }

  await doScanDetailRefresh(scanId);
}

async function doScanDetailRefresh(scanId) {
  // Guard: only refresh if still on this scan's detail page
  if (state.view !== 'scan-detail' || state.scanDetailId !== scanId) return;

  try {
    const sum = await apiFetch(`/api/scans/${encodeURIComponent(scanId)}/results/summary?page=1&per_page=200`);
    const scan = sum.scan || {};
    const stat = String(scan.status || scan.Status || '').toLowerCase();
    const files = sum.files || [];
    const stillRunning = /^(running|pending|queued|active|in_progress|starting)$/.test(stat);

    // Update the status subtitle with live badge if still running
    const sub = document.getElementById('scan-detail-sub');
    if (sub) {
      if (stillRunning) {
        const isCancelling = /cancelling/.test(stat);
        const isPaused = /paused/.test(stat);
        const scanType = scan.scan_type || '';
        const liveBadge = isPaused
          ? `<span class="badge badge-starting" style="font-size:10px;padding:2px 8px;margin-left:8px">⏸ paused</span>`
          : isCancelling
            ? `<span class="badge badge-starting" style="font-size:10px;padding:2px 8px;margin-left:8px">⋯ stopping</span>`
            : `<span class="badge badge-running" style="font-size:10px;padding:2px 8px;margin-left:8px;animation:pulse 1.4s ease-in-out infinite">● live</span>`;
        sub.innerHTML = `${esc(scanType)} · ${esc(stat)}${liveBadge}`;
      } else {
        sub.textContent = `${scan.scan_type || ''} · ${stat}`;
      }
    }

    // Update or inject phase banner
    updatePhaseBanner(scan);
    await refreshScanManifestCard(scanId, scan);

    // Refresh the file-count badge
    const badge = document.getElementById('unified-parsed-badge');
    if (badge) {
      const countStr = `${files.length} files`;
      if (badge.textContent !== countStr) badge.textContent = countStr;
    }

    // Find newly indexed files (not seen before) and append to Findings table
    const newFiles = files.filter(f => !_scanDetailKnownFiles.has(f.file_name));
    if (newFiles.length) {
      newFiles.forEach(f => _scanDetailKnownFiles.add(f.file_name));
      // Trigger a lightweight re-render of just the unified table
      const unifiedRoot = document.getElementById('unified-parsed-results');
      if (unifiedRoot) {
        // Optimization: only re-render if we actually have a DOM container
        loadReconUnifiedTable(scanId, files, 'unified-parsed-results');
        _assetsCache = null;
      }
    }

    if (stillRunning) {
      scheduleScanDetailRefresh(scanId, 4500); // slightly slower refresh for local timer
    } else {
      clearScanDetailRefreshTimer();
      // Do a final full re-render once scan completes
      await renderScanDetailView(scanId);
    }
  } catch (e) {
    // Silently retry on network issues
    scheduleScanDetailRefresh(scanId, 8000);
  }
}

async function fetchScanManifest(scanId) {
  try {
    return await apiFetch(`/api/scans/${encodeURIComponent(scanId)}/manifest`);
  } catch (e) {
    return null;
  }
}

function formatManifestDuration(ms) {
  const n = Number(ms || 0);
  if (!Number.isFinite(n) || n <= 0) return '—';
  const sec = Math.floor(n / 1000);
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function manifestStatusBadge(status) {
  const st = String(status || '').toLowerCase();
  if (/completed|done|success/.test(st)) return 'badge-done';
  if (/running|starting|queued|active/.test(st)) return 'badge-running';
  if (/paused|cancelling/.test(st)) return 'badge-starting';
  if (/failed|error|cancel/.test(st)) return 'badge-failed';
  return 'badge-neutral';
}

function renderScanManifestCard(manifest, scan) {
  const modules = Array.isArray(manifest?.modules) ? manifest.modules : [];
  const scanStatus = scan?.status || scan?.Status || '';
  const fallbackModule = {
    module: scan?.scan_type || scan?.ScanType || 'scan',
    status: scanStatus || 'unknown',
    duration_ms: 0,
    output_files: [],
    scanner_version: '—',
  };
  const m = modules[0] || fallbackModule;
  const outputs = Array.isArray(m.output_files) ? m.output_files : [];
  const outputPreview = outputs.slice(0, 8).map(f => `<code style="font-size:11px">${esc(f)}</code>`).join(' ');
  return `
    <div class="modern-card" id="scan-manifest-card" style="padding:14px 16px">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          <strong style="font-size:13px">🧭 Module execution</strong>
          <span class="badge ${manifestStatusBadge(m.status)}">${esc(String(m.status || 'unknown'))}</span>
          <span class="badge badge-neutral">${esc(String(m.module || 'scan'))}</span>
          <span class="badge badge-neutral">⏱ ${esc(formatManifestDuration(m.duration_ms))}</span>
          <span class="badge badge-neutral">📦 ${outputs.length} outputs</span>
        </div>
        <div style="font-size:11px;color:var(--text-muted)">scanner ${esc(String(m.scanner_version || '—'))}</div>
      </div>
      ${outputPreview
      ? `<div style="margin-top:10px;display:flex;gap:6px;flex-wrap:wrap">${outputPreview}${outputs.length > 8 ? `<span style="font-size:11px;color:var(--text-muted)">+${outputs.length - 8} more</span>` : ''}</div>`
      : `<div style="margin-top:8px;font-size:12px;color:var(--text-muted)">No output files indexed yet.</div>`}
    </div>`;
}

async function refreshScanManifestCard(scanId, scan) {
  const host = document.getElementById('scan-manifest-card');
  if (!host) return;
  const manifestResp = await fetchScanManifest(scanId);
  host.outerHTML = renderScanManifestCard(manifestResp?.manifest || null, scan);
}

function updatePhaseBanner(scan) {
  const existing = document.getElementById('scan-live-phase-banner');
  const stat = String(scan.status || scan.Status || '').toLowerCase();
  const stillRunning = /^(running|pending|queued|active|in_progress|starting)$/.test(stat);

  if (!stillRunning) {
    if (existing) existing.remove();
    return;
  }

  const phaseName = scan.phase_name || scan.PhaseName || '';
  const currentPhase = scan.current_phase || scan.CurrentPhase || 0;
  const totalPhases = scan.total_phases || scan.TotalPhases || 0;
  const pct = totalPhases > 0 ? Math.round((currentPhase / totalPhases) * 100) : 0;
  const phaseText = phaseName
    ? `${currentPhase}/${totalPhases} — ${phaseName}`
    : (currentPhase > 0 ? `Phase ${currentPhase}/${totalPhases}` : 'Starting…');

  const bannerHtml = `
    <div id="scan-live-phase-banner" style="margin-bottom:14px;padding:12px 16px;background:rgba(6,182,212,.08);border:1px solid rgba(6,182,212,.25);border-radius:10px;display:flex;align-items:center;gap:12px;flex-wrap:wrap">
      <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#10b981;box-shadow:0 0 6px #10b981;flex-shrink:0;animation:pulse 1.2s ease-in-out infinite"></span>
      <div style="flex:1;min-width:0">
        <div style="font-size:12px;font-weight:600;color:var(--accent-cyan)">Scan running — results will appear as modules complete</div>
        <div style="font-size:11px;color:var(--text-secondary);margin-top:2px">${esc(phaseText)}</div>
      </div>
      ${totalPhases > 0 ? `
        <div style="display:flex;align-items:center;gap:8px">
          <div style="width:120px;height:5px;background:rgba(255,255,255,.1);border-radius:3px;overflow:hidden">
            <div style="height:100%;width:${pct}%;background:var(--accent-cyan);border-radius:3px;transition:width .3s ease"></div>
          </div>
          <span style="font-size:11px;color:var(--text-muted);white-space:nowrap">${pct}%</span>
        </div>` : ''}
    </div>`;

  if (existing) {
    existing.outerHTML = bannerHtml;
  } else {
    // Inject before the Findings card
    const findingsCard = document.querySelector('.scan-detail-modern .modern-card');
    if (findingsCard) findingsCard.insertAdjacentHTML('beforebegin', bannerHtml);
  }
}

/** Load and display parsed results from all JSON files */
async function loadModuleResults(scanId, files) {
  const container = document.getElementById('module-results-container');
  if (!container) return;

  // Parse both JSON and text artifacts (many modules output text).
  const parseableFiles = files.filter(f => {
    const n = (f.file_name || '').toLowerCase();
    if (n.endsWith('.json') || n.endsWith('.txt') || n.endsWith('.log') || n.endsWith('.csv')) return true;
    return false;
  });

  if (!parseableFiles.length) {
    container.innerHTML = '<div style="padding:40px;text-align:center;color:var(--text-muted)">No parseable result files found</div>';
    return;
  }

  // Group files by module
  const modules = {};
  parseableFiles.forEach(f => {
    const mod = detectModuleFromFileName(f.file_name, f.module);
    if (!modules[mod]) modules[mod] = [];
    modules[mod].push(f);
  });

  // Build HTML for each module
  let html = '';
  for (const [module, modFiles] of Object.entries(modules)) {
    const moduleInfo = getModuleDisplayInfo(module);

    html += `
      <div class="module-results-group" style="margin-bottom:20px">
        <div class="module-group-header" style="padding:14px 20px;background:var(--bg-surface);border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between">
          <div style="display:flex;align-items:center;gap:10px">
            <span style="font-size:18px">${moduleInfo.icon}</span>
            <div>
              <div style="font-size:14px;font-weight:600;color:var(--text-primary)">${moduleInfo.name}</div>
              <div style="font-size:11px;color:var(--text-muted)">${modFiles.length} file(s)</div>
            </div>
          </div>
          <button class="btn btn-ghost" style="font-size:11px;padding:4px 10px" onclick="toggleModuleGroup(this)">
            ▼ Collapse
          </button>
        </div>
        <div class="module-group-content">`;

    // Render each file's results
    for (const file of modFiles) {
      html += `
          <div class="module-file-result" style="border-bottom:1px solid var(--border)">
            <div class="module-file-header" style="padding:12px 20px;background:rgba(255,255,255,0.02);cursor:pointer" onclick="toggleModuleFileResult(this)">
              <div style="display:flex;align-items:center;justify-content:space-between">
                <div style="font-size:12px;font-weight:600;color:var(--accent-cyan);font-family:'JetBrains Mono',monospace">
                  📄 ${esc(file.file_name)}
                </div>
                <div style="font-size:11px;color:var(--text-muted)">
                  ${fmtSize(file.size_bytes)} · ${file.line_count || '?'} lines
                  <span style="margin-left:8px">▼</span>
                </div>
              </div>
            </div>
            <div class="module-file-content" data-file-name="${esc(file.file_name)}" style="display:block">
              <div style="padding:16px 20px">
                <div class="result-loading" style="text-align:center;padding:20px;color:var(--text-muted)">
                  Loading...
                </div>
              </div>
            </div>
          </div>`;
    }

    html += `
        </div>
      </div>`;
  }

  container.innerHTML = html;

  // Load results for each file
  for (const file of parseableFiles) {
    const contentEl = findModuleFileContent(container, file.file_name);
    if (contentEl) {
      parseAndRenderResults(scanId, file, contentEl);
    }
  }
}

/** Render parsed results cards into a target container for a file group. */
async function loadParsedResultsList(scanId, files, containerId) {
  const root = document.getElementById(containerId);
  if (!root) return;
  if (!files || !files.length) {
    root.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted)">No files in this section.</div>';
    return;
  }
  root.innerHTML = files.map(f => {
    const module = detectModuleFromFileName(f.file_name, f.module);
    const info = getModuleDisplayInfo(module);
    return `
      <div class="module-file-result" style="border:1px solid var(--border);border-radius:10px;margin-bottom:12px;overflow:hidden">
        <div class="module-file-header" style="padding:10px 14px;background:rgba(255,255,255,.02);display:flex;justify-content:space-between;gap:8px;align-items:center">
          <div style="font-size:12px;font-family:'JetBrains Mono',monospace;color:var(--accent-cyan);display:flex;gap:8px;align-items:center">
            <span>${info.icon}</span><span>${esc(f.file_name)}</span>
          </div>
          <div style="font-size:11px;color:var(--text-muted)">${fmtSize(f.size_bytes)} · ${esc(f.source)}</div>
        </div>
        <div class="module-file-content" data-file-name="${esc(f.file_name)}" style="padding:12px">
          <div class="result-loading" style="text-align:center;padding:12px;color:var(--text-muted)">Loading…</div>
        </div>
      </div>`;
  }).join('');

  for (const f of files) {
    const el = findModuleFileContent(root, f.file_name);
    if (el) await parseAndRenderResults(scanId, f, el);
  }
}

function normalizeFindingText(v) {
  if (v == null) return '';
  if (typeof v === 'string') return v.trim();
  try { return JSON.stringify(v); } catch { return String(v); }
}

function previewDataToFlatRows(data, file) {
  const rows = [];
  // Empty file — return nothing silently
  if (!data || data.format === 'empty' || data.format === 'too_large') return rows;
  let module = detectModuleFromFileName(file.file_name, file.module);
  const looksLikeApkxObject = (obj) => {
    if (!obj || typeof obj !== 'object') return false;
    const keys = Object.keys(obj).map((k) => String(k).toLowerCase());
    return keys.some((k) => (
      k.includes('apk') ||
      k.includes('manifest') ||
      k.includes('permission') ||
      k.includes('package') ||
      k.includes('activity') ||
      k.includes('receiver') ||
      k.includes('provider') ||
      k.includes('service')
    ));
  };
  const pushObj = (obj) => {
    if (!obj || typeof obj !== 'object') return;
    const severity = obj.info?.severity || obj.severity || obj.level || (obj.vulnerable ? 'high' : '—');
    const target = obj['matched-at'] || obj.matched_at || obj.url || obj.host || obj.domain || obj.target || '—';
    const finding = obj['template-id'] || obj.template_id || obj.template || obj.name || obj.title || obj.issue || obj.vulnerability || obj.service_name || obj.reason || obj.message || normalizeFindingText(obj);
    rows.push({
      file: file.file_name,
      module,
      source: file.source || '—',
      severity: normalizeFindingText(severity) || '—',
      target: normalizeFindingText(target) || '—',
      finding: normalizeFindingText(finding) || '—',
    });
  };

  if (data.format === 'json-array' && Array.isArray(data.items)) {

    for (const item of data.items) {
      if (typeof item === 'object') pushObj(item);
      else {
        rows.push({
          file: file.file_name,
          module,
          source: file.source || '—',
          severity: '—',
          target: '—',
          finding: normalizeFindingText(item),
        });
      }
    }
    return rows;
  }

  if (data.format === 'json-object' && data.data && typeof data.data === 'object') {
    const obj = data.data;
    if ((module === 'autoar' || module === 'unknown') && (String(file.file_name || '').toLowerCase().includes('results.json') || looksLikeApkxObject(obj))) {
      module = 'apkx';
    }
    // APK results.json is typically map<string, string[]>; flatten each category entry.
    if (module === 'apkx') {
      let flattened = 0;
      Object.entries(obj).forEach(([k, v]) => {
        if (Array.isArray(v)) {
          v.forEach((item) => {
            const str = String(item || '').trim();
            if (!str) return;
            rows.push({
              file: file.file_name,
              module,
              source: file.source || '—',
              severity: 'info',
              target: '—',
              finding: `${k}: ${str}`,
            });
            flattened += 1;
          });
        }
      });
      if (flattened > 0) return rows;
    }
    let foundArray = false;
    for (const k of ['results', 'findings', 'matches', 'issues', 'vulnerabilities', 'data', 'items']) {
      if (Array.isArray(obj[k])) {
        foundArray = true;
        for (const item of obj[k]) {
          if (typeof item === 'object') pushObj(item);
          else {
            const str = String(item || '').trim();
            const isURL = str.startsWith('http://') || str.startsWith('https://');
            rows.push({
              file: file.file_name, module, source: file.source || '—',
              severity: '—',
              target: isURL ? str : '—',
              finding: isURL ? module : normalizeFindingText(str)
            });
          }
        }
      }
    }
    if (!foundArray) pushObj(obj);
    return rows;
  }

  if (data.format === 'text' && Array.isArray(data.lines)) {
    const lines = data.lines.map(x => String(x || '').trim()).filter(l => l && !l.startsWith('#'));
    // Nuclei JSONL inside text file
    if (module === 'nuclei') {
      for (const line of lines) {
        const p = parseNucleiFindingLine(line);
        if (p) {
          rows.push({
            file: file.file_name, module, source: file.source || '—',
            severity: p.severity || '—', target: p.url || '—', finding: p.template || '—'
          });
        } else if (line) {
          rows.push({
            file: file.file_name, module, source: file.source || '—',
            severity: '—', target: '—', finding: line
          });
        }
      }
      if (rows.length) return rows;
    }
    // Any other text file — smart line classification
    for (const line of lines) {
      const isURL = /^https?:\/\//i.test(line);
      const isHost = /^[\w.-]+\.\w{2,}(:\d+)?$/.test(line);
      const isIP = /^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/.test(line);
      if (isURL) {
        rows.push({
          file: file.file_name, module, source: file.source || '—',
          severity: '—', target: line, finding: module
        });
      } else if (isHost || isIP) {
        rows.push({
          file: file.file_name, module, source: file.source || '—',
          severity: '—', target: line, finding: module
        });
      } else {
        rows.push({
          file: file.file_name, module, source: file.source || '—',
          severity: '—', target: '—', finding: line
        });
      }
    }
    return rows;
  }

  return rows;
}

async function loadCombinedVulnerabilityTable(scanId, files, containerId) {
  const root = document.getElementById(containerId);
  if (!root) return;
  if (!files || !files.length) {
    root.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted)">No vulnerability files found.</div>';
    return;
  }

  root.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted)">Parsing vulnerability findings…</div>';
  let allRows = [];
  try {
    const parsed = await apiFetch(`/api/scans/${encodeURIComponent(scanId)}/results/parsed?section=vulnerability&limit=2500`);
    if (Array.isArray(parsed.rows)) {
      allRows = parsed.rows;
    }
  } catch (e) {
    console.warn('[scan detail] parsed vulnerability api fallback', e);
  }
  // Fallback for older backend versions that don't expose /results/parsed yet.
  if (!allRows.length) {
    for (const f of files) {
      try {
        const data = await apiFetch(`/api/scans/${encodeURIComponent(scanId)}/results/file?file_name=${encodeURIComponent(f.file_name)}&page=1&per_page=500`);
        const rows = previewDataToFlatRows(data, f);
        allRows.push(...rows);
      } catch (e) {
        allRows.push({
          file: f.file_name,
          module: detectModuleFromFileName(f.file_name, f.module),
          source: f.source || '—',
          severity: '—',
          target: '—',
          finding: `[Error reading file] ${e.message || e}`,
        });
      }
    }
  }

  if (!allRows.length) {
    root.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted)">No parseable vulnerability findings.</div>';
    return;
  }

  const maxRows = 1200;
  const rows = allRows.slice(0, maxRows);
  const body = rows.map(r => {
    const info = getModuleDisplayInfo(r.module);
    return `<tr>
      <td class="mono" style="font-size:11px;color:var(--accent-cyan)">${esc(r.file)}</td>
      <td style="font-size:11px;color:${info.color}">${info.icon} ${esc(info.name)}</td>
      <td style="font-size:11px;color:var(--text-muted)">${esc(r.source)}</td>
      <td><span class="severity-${String(r.severity || 'info').toLowerCase()}">${esc(String(r.severity || '—').toUpperCase())}</span></td>
      <td class="mono" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.target)}</td>
      <td style="max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.finding)}</td>
    </tr>`;
  }).join('');

  root.innerHTML = `
    <div class="result-table-wrap">
      <table class="result-table">
        <thead>
          <tr>
            <th>FILE</th>
            <th>MODULE</th>
            <th>SOURCE</th>
            <th>SEVERITY</th>
            <th>TARGET</th>
            <th>FINDING</th>
          </tr>
        </thead>
        <tbody>${body}</tbody>
      </table>
      ${allRows.length > maxRows ? `<div style="padding:10px 12px;font-size:12px;color:var(--text-muted)">Showing first ${maxRows} of ${allRows.length} findings.</div>` : ''}
    </div>`;
}

/** Mirror backend inferReconKind for client-side fallback when /results/parsed is unavailable. */
function inferReconKindFromFileName(fileName) {
  const b = String(fileName || '').split(/[/\\]/).pop().toLowerCase();
  if (!b) return 'other';
  if (b.includes('js-url') || b.includes('jsurl')) return 'js_urls';
  if (b.includes('all-subs') || b.includes('live-subs') || b.endsWith('subs.txt')) return 'subdomains';
  if (b.includes('all-url') || b.includes('interesting-url') || (b.endsWith('urls.txt') && !b.includes('js'))) return 'urls';
  if (b.includes('tech-detect') || b.includes('technologies') || b.includes('wappalyzer')) return 'tech';
  if (b.includes('ffuf')) return 'ffuf';
  if (b.includes('bucket')) return 'buckets';
  return 'other';
}

/** Infer finding kind from any file name (recon + vuln + all other modules). */
function inferKindFromFileName(fileName) {
  const full = String(fileName || '').toLowerCase();
  const b = full.split(/[/\\]/).pop();
  if (!b) return 'other';
  if (full.includes('/apkx/') || full.includes('\\apkx\\')) return 'apkx';
  // APK analysis artifacts
  if (b.includes('apk') || b.includes('androidmanifest') || b.includes('jadx') || b.includes('dex')) return 'apkx';
  // Log files — separate tab
  if (b.endsWith('.log')) return 'logs';
  // Subdomains
  if (b.includes('all-subs') || b.includes('live-subs') || b.endsWith('subs.txt') || b.includes('subdomain')) return 'subdomains';
  if (b.includes('live') && (b.includes('host') || b.includes('subs'))) return 'subdomains';
  if (b.includes('httpx') || b.includes('live-hosts')) return 'subdomains';
  // URLs
  if (b.includes('all-url') || b.includes('interesting-url') || b.includes('urls.json') || b.includes('url-enum') || b.includes('url-collection') || (b.endsWith('urls.txt') && !b.includes('js'))) return 'urls';
  if (b.includes('cname')) return 'urls';
  // JS URLs
  if (b.includes('js-url') || b.includes('jsurl') || b.includes('js_url') || b.includes('js-enum') || b === 'js-urls.json') return 'js_urls';
  // JS secrets / exposures
  if (b.includes('js-secret') || b.includes('js-exposure') || ((b.includes('secret') || b.includes('exposure')) && b.includes('js'))) return 'js-analysis';
  // Tech detection
  if (b.includes('tech-detect') || b.includes('technologies') || b.includes('wappalyzer')) return 'tech';
  // FFUF
  if (b.includes('ffuf') || b.includes('fuzz')) return 'ffuf';
  // Buckets / S3
  if (b.includes('bucket') || b.includes('s3-')) return 'buckets';
  // Nuclei / Vulnerabilities
  if (b.startsWith('nuclei') || b.includes('nuclei')) return 'nuclei';
  // Zerodays
  if (b.includes('zeroday') || b.includes('0day')) return 'zerodays';
  // Misconfig
  if (b.includes('misconfig')) return 'misconfig';
  // AEM
  if (b.includes('aem')) return 'aem';
  // DNS / cloud takeover (including aws, azure, cloudflare, gcp)
  if (b.includes('dns') || b.includes('takeover') || b.includes('dnsreap') ||
    b.includes('aws-') || b.includes('azure-') || b.includes('gcp-') ||
    b.includes('cloudflare') || b.includes('dangling')) return 'dns';
  // Backup
  if (b.includes('backup') || b.includes('fuzzuli')) return 'backup';
  // Ports (strict to avoid matching "report")
  if (b.includes('port-scan') || b.includes('ports') || b.includes('nmap') || b.includes('masscan')) return 'ports';
  // GF patterns
  if (b.startsWith('gf-') || b.includes('gf-')) return 'gf';
  // Reflection / XSS
  if (b.includes('reflection') || b.includes('kxss') || b.includes('dalfox') || b.includes('xss')) return 'vuln';
  // Dependency confusion / supply chain
  if (b.includes('confusion') || b.includes('depconf')) return 'vuln';
  // GH / source code scanning (strict to avoid matching "report")
  if (b.includes('github') || b.includes('github-scan') || b.includes('gh-')) return 'vuln';
  return 'other';
}

async function loadReconUnifiedTable(scanId, allFiles, containerId, scanRecord) {
  const root = document.getElementById(containerId);
  if (!root) return;
  const stNorm = String(scanRecord?.scan_type || scanRecord?.ScanType || '').toLowerCase();
  const isAPKScan = stNorm.includes('apkx');
  // Support both the unified badge and legacy recon badge
  const badge = document.getElementById('unified-parsed-badge') || document.getElementById('recon-parsed-badge');

  if (!allFiles || !allFiles.length) {
    if (badge) badge.textContent = '0 artifacts';
    root.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted)">No artifacts found.</div>';
    return;
  }

  root.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted)">Loading all findings…</div>';
  let allRows = [];
  try {
    const parsed = await apiFetch(`/api/scans/${encodeURIComponent(scanId)}/results/parsed?section=all&limit=5000`);
    if (Array.isArray(parsed.rows)) {
      allRows = parsed.rows;
    }
  } catch (e) {
    console.warn('[scan detail] parsed recon api fallback', e);
  }

  if (!allRows.length) {
    for (const f of allFiles) {
      try {
        const data = await apiFetch(`/api/scans/${encodeURIComponent(scanId)}/results/file?file_name=${encodeURIComponent(f.file_name)}&page=1&per_page=500`);
        const rows = previewDataToFlatRows(data, f).map((r) => ({
          ...r,
          kind: inferKindFromFileName(r.file),
          category: categorizeScanArtifactFile(r.file),
        }));
        allRows.push(...rows);
      } catch (e) {
        allRows.push({
          file: f.file_name,
          module: detectModuleFromFileName(f.file_name, f.module),
          source: f.source || '—',
          category: categorizeScanArtifactFile(f.file_name),
          kind: inferKindFromFileName(f.file_name),
          severity: '—',
          target: '—',
          finding: `[Error reading file] ${e.message || e}`,
        });
      }
    }
  }

  if (badge) {
    badge.textContent = `${allRows.length} rows · ${allFiles.length} files`;
  }

  if (!allRows.length) {
    root.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted)">No parseable findings.</div>';
    return;
  }

  if (isAPKScan) {
    const hasJsonRows = allRows.some((r) => String(r.file || '').toLowerCase().endsWith('.json'));
    if (hasJsonRows) {
      allRows = allRows.filter((r) => String(r.file || '').toLowerCase().endsWith('.json'));
    }
  }

  allRows = allRows
    .map((r) => {
      let kind = String(r.kind || inferKindFromFileName(r.file) || 'other').toLowerCase().trim();
      const file = String(r.file || '').toLowerCase();
      const target = String(r.target || r.host || '').toLowerCase();
      const finding = String(r.title || r.finding || '').trim();
      const moduleNorm = normalizeModuleKey(r.module);

      if (kind === 'js-urls') kind = 'js_urls';
      if (kind === 'unknown' || kind === 'unknowns') kind = 'other';

      const looksLikeJSMatcher = /^\s*\[[^\]]+\].*->/i.test(finding) || file.includes('js-secret') || file.includes('js-exposure');
      const looksLikeJSURL = file.includes('js-url') || /\.m?jsx?(\?|$)/i.test(target);

      if (looksLikeJSMatcher) kind = 'js-analysis';
      else if (looksLikeJSURL && kind === 'other') kind = 'js_urls';
      if (isAPKScan) kind = 'apkx';

      const normalizedModule = (moduleNorm === 'unknown' && (kind === 'js-analysis' || kind === 'js_urls'))
        ? 'js-analysis'
        : (isAPKScan ? 'apkx' : moduleNorm);

      return {
        ...r,
        kind,
        module: normalizedModule,
      };
    })
    .filter((r) => {
      const finding = String(r.title || r.finding || '').trim().toLowerCase();
      const target = String(r.target || r.host || '').trim();
      // Drop synthetic placeholder rows emitted for empty result sets.
      if (finding === 'no findings found' && (target === '' || target === '-' || target === '—')) {
        return false;
      }
      if (isAPKScan) {
        if ((target === '' || target === '-' || target === '—') && (finding === '' || finding === '—' || finding === 'autoar' || finding === 'apkx')) {
          return false;
        }
      }
      return true;
    });

  const maxRows = 2500;
  const VULN_KINDS = new Set(['vuln', 'nuclei', 'reflection', 'ports', 'buckets', 'backup', 'zerodays', 'aem', 'misconfig', 's3', 'gf', 'ffuf', 'dns', 'github', 'sqlmap', 'aem-findings']);
  const totalVuln = Array.from(VULN_KINDS).reduce((acc, k) => acc + (allRows.filter(r => (r.kind || 'other') === k).length), 0);

  const isReconScan = stNorm === 'recon' || stNorm === 'lite' || stNorm === 'domain_scan' || stNorm === 'subdomain_scan' || stNorm === 'subdomain_run';
  let activeKind = isReconScan ? 'assets' : 'urls';
  if (totalVuln === 0 && !isReconScan && (allRows.some(r => r.kind === 'urls'))) activeKind = 'urls';
  let searchHost = '';
  let searchTitle = '';
  let searchModule = 'all';
  let filterSeverity = 'any';

  // Build dynamic tabs from actual data
  const _kindCounts = {};
  for (const r of allRows) _kindCounts[r.kind || 'other'] = (_kindCounts[r.kind || 'other'] || 0) + 1;
  const HIDDEN_KINDS = new Set(['logs', 'log', 'tech']);
  const TAB_LABELS = {
    assets: '🏠 Assets',
    urls: '🔗 Links',
    js_urls: '📄 JS URLs',
    apkx: '📱 APK Analysis',
    'js-analysis': '📜 JS Analysis',
    'gf-patterns': '🎯 GF Patterns',
    nuclei: '☢️ Nuclei',
    ffuf: '🎲 FFUF',
    buckets: '🪣 Buckets',
    ports: '📡 Ports',
    reflection: '🔎 Reflection',
    other: '📁 Other',
  };

  // Build dynamic tabs from actual data
  const dynamicKinds = [...new Set(allRows.map(r => r.kind || 'other'))];
  const DATASET_TABS = [];
  
  // Always add Assets if it's a recon scan or has data
  if (isReconScan || allRows.some(r => r.kind === 'subdomains' || r.kind === 'assets')) {
    DATASET_TABS.push(['assets', TAB_LABELS.assets]);
  }

  // Add other kinds as their own tabs
  dynamicKinds.forEach(k => {
    if (k === 'subdomains' || k === 'assets' || k === 'vuln' || VULN_KINDS.has(k)) {
      // Already covered by Assets or Vulnerabilities main tabs for now, 
      // but let's add specific ones as requested:
      if (['js-analysis', 'gf-patterns', 'nuclei', 'ffuf', 'reflection'].includes(k)) {
        DATASET_TABS.push([k, TAB_LABELS[k] || k]);
      }
      return;
    }
    if (k === 'urls') {
      DATASET_TABS.push(['urls', TAB_LABELS.urls]);
      return;
    }
    if (!['logs', 'log', 'tech'].includes(k)) {
       DATASET_TABS.push([k, TAB_LABELS[k] || k]);
    }
  });

  // Deduplicate tabs
  const seenTabs = new Set();
  let UNIQUE_TABS = DATASET_TABS.filter(t => {
    if (seenTabs.has(t[0])) return false;
    seenTabs.add(t[0]);
    return true;
  });

  const preferredModuleOrder = [
    'nuclei',
    'gf-patterns',
    'misconfig',
    'ffuf-fuzzing',
    'dns-takeover',
    'backup-detection',
    'js-analysis',
    'xss-detection',
    'sql-detection',
    's3-scan',
    'port-scan',
    'zerodays',
    'aem',
    'github-scan',
  ];
  const usedModulesRaw = [...new Set(allRows.map(r => normalizeModuleKey(r.module)).filter(Boolean))];
  const usedModules = usedModulesRaw.sort((a, b) => {
    const ai = preferredModuleOrder.indexOf(a);
    const bi = preferredModuleOrder.indexOf(b);
    if (ai !== -1 && bi !== -1) return ai - bi;
    if (ai !== -1) return -1;
    if (bi !== -1) return 1;
    return a.localeCompare(b);
  });
  const excludedModuleTabs = new Set(['autoar', 'unknown', 'tech-detect', 'ffuf-fuzzing', 'js-analysis']);
  // "Links" (kind urls) already lists URL-collection findings; skip duplicate module tab.
  const hasUrlsDatasetTab = UNIQUE_TABS.some((t) => t[0] === 'urls');
  if (hasUrlsDatasetTab) {
    excludedModuleTabs.add('url-collection');
  }
  // APK dataset tab already exists; skip duplicate module tab.
  const hasApkxDatasetTab = UNIQUE_TABS.some((t) => t[0] === 'apkx');
  if (hasApkxDatasetTab) {
    excludedModuleTabs.add('apkx');
  }
  const moduleTabs = usedModules.filter((mod) => !excludedModuleTabs.has(mod)).map((mod) => {
    const info = getModuleDisplayInfo(mod);
    return [`mod:${mod}`, `${info.icon} ${info.name}`];
  });
  UNIQUE_TABS = [...UNIQUE_TABS, ...moduleTabs].filter((t, i, arr) => arr.findIndex(x => x[0] === t[0]) === i);
  // Pin Assets first; keep all other tabs dynamic after.
  const pinnedKinds = ['assets'];
  UNIQUE_TABS = [
    ...pinnedKinds.map((k) => UNIQUE_TABS.find((t) => t[0] === k)).filter(Boolean),
    ...UNIQUE_TABS.filter((t) => !pinnedKinds.includes(t[0])),
  ];
  if (!UNIQUE_TABS.some((t) => t[0] === activeKind)) {
    activeKind = UNIQUE_TABS[0]?.[0] || 'assets';
  }

  // Cache for assets data (uses global _assetsCache so doScanDetailRefresh can bust it)
  let _assetsLoading = false;
  let _currentPage = 1;
  const _pageSize = 250;

  const parseStatusCode = (v) => {
    const m = String(v || '').match(/\b([1-5][0-9]{2})\b/);
    return m ? Number(m[1]) : null;
  };
  const parseTitle = (v) => {
    const s = String(v || '').trim();
    if (!s || s === '—') return '-';
    return s.length > 120 ? `${s.slice(0, 117)}...` : s;
  };
  const rowToGrid = (r) => {
    const host = String(r.target || '—');
    const code = parseStatusCode(`${r.target || ''} ${r.finding || ''}`);
    const status = code && code < 400 ? 'Alive' : (code ? 'Issue' : '-');
    const title = parseTitle(r.finding);
    const tech = String(r.module || '').replace(/-/g, ' ') || '-';
    return { ...r, host, code, status, title, tech };
  };

  allRows = allRows.map(rowToGrid);

  const extractApkPackageInfo = (rows) => {
    const info = {};
    const consumed = new Set();
    const aliases = {
      package_name: 'package_name',
      package: 'package_name',
      packageid: 'package_name',
      package_id: 'package_name',
      applicationid: 'package_name',
      application_id: 'package_name',
      appid: 'package_name',
      app_name: 'app_name',
      appname: 'app_name',
      name: 'app_name',
      version: 'version',
      version_name: 'version',
      versionname: 'version',
      version_code: 'version_code',
      versioncode: 'version_code',
      min_sdk: 'min_sdk',
      minsdk: 'min_sdk',
      minsdkversion: 'min_sdk',
      target_sdk: 'target_sdk',
      targetsdk: 'target_sdk',
      targetsdkversion: 'target_sdk',
      compile_sdk: 'compile_sdk',
      compilesdk: 'compile_sdk',
      compilesdkversion: 'compile_sdk',
    };
    const takeKV = (k, v) => {
      const key = String(k || '').trim().toLowerCase().replace(/[^a-z0-9_]/g, '');
      const mapped = aliases[key];
      if (!mapped) return;
      const val = String(v ?? '').trim();
      if (!val) return;
      if (!info[mapped]) info[mapped] = val;
    };

    rows.forEach((r, idx) => {
      const target = String(r.target || '');
      const finding = String(r.finding || '').trim();
      if (!/[{]/.test(finding) && !/(package|version|sdk|app_name|application_id)/i.test(`${target} ${finding}`)) return;

      let consumedRow = false;
      try {
        const parsed = JSON.parse(finding);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          Object.entries(parsed).forEach(([k, v]) => takeKV(k, v));
          consumedRow = Object.keys(parsed).length > 0;
        }
      } catch (_) {
        // ignore
      }
      const kvs = finding.match(/"?([A-Za-z_][A-Za-z0-9_ ]*)"?\s*:\s*"?([^,"}]+)"?/g) || [];
      kvs.forEach((frag) => {
        const m = frag.match(/"?([A-Za-z_][A-Za-z0-9_ ]*)"?\s*:\s*"?([^,"}]+)"?/);
        if (m) takeKV(m[1], m[2]);
      });
      if (kvs.length) consumedRow = true;
      if (consumedRow) consumed.add(idx);
    });

    return { info, rows: rows.filter((_, idx) => !consumed.has(idx)) };
  };

  let apkPackageInfo = null;
  if (isAPKScan) {
    const extracted = extractApkPackageInfo(allRows);
    allRows = extracted.rows;
    apkPackageInfo = extracted.info;
  }

  const apkCategoryKey = (r) => {
    const explicit = String(r.category_name || r.apk_category || '').trim();
    if (explicit) return explicit;
    const t = String(r.target || '').trim();
    if (t && t !== '-' && t !== '—') return t;
    const f = String(r.finding || '').trim();
    const idx = f.indexOf(':');
    if (idx > 0) return f.slice(0, idx).trim();
    return '';
  };
  const slugifyApkCategory = (s) => String(s || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');

  const apkCategoryCounts = {};
  if (isAPKScan) {
    allRows = allRows.map((r) => {
      const cat = apkCategoryKey(r);
      const slug = slugifyApkCategory(cat);
      if (slug) {
        apkCategoryCounts[slug] = apkCategoryCounts[slug] || { label: cat, count: 0 };
        apkCategoryCounts[slug].count += 1;
      }
      return { ...r, apk_category: cat, apk_category_slug: slug };
    });
    const apkCategoryTabs = Object.entries(apkCategoryCounts)
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 30)
      .map(([slug, meta]) => [`apkcat:${slug}`, `🧩 ${meta.label}`]);
    if (apkCategoryTabs.length) {
      const baseTabs = UNIQUE_TABS.filter(([k]) => k !== 'apkx');
      UNIQUE_TABS = [['apkx', TAB_LABELS.apkx], ...apkCategoryTabs, ...baseTabs]
        .filter((t, i, arr) => arr.findIndex(x => x[0] === t[0]) === i);
    }
  }

  const kindCounts = {};
  for (const r of allRows) kindCounts[r.kind || 'other'] = (kindCounts[r.kind || 'other'] || 0) + 1;

  const datasetCount = (k) => (k === 'all' ? allRows.length : (kindCounts[k] || 0));


  let searchJsOnly = false;
  let presetMode = 'smart';
  let quickChip = 'none';
  let railSearch = '';
  let currentRenderedRows = [];
  let _virtualScrollTop = 0;
  const presetStorageKey = `autoar.recon.filtersets.${stNorm || 'generic'}`;
  const uiStateKey = `autoar.recon.uistate.${stNorm || 'generic'}`;
  const colStateKey = `autoar.recon.colwidths.${stNorm || 'generic'}`;
  let savedFilterSets = {};

  const loadSavedSets = () => {
    try { savedFilterSets = JSON.parse(localStorage.getItem(presetStorageKey) || '{}') || {}; } catch { savedFilterSets = {}; }
  };
  const persistSavedSets = () => {
    try { localStorage.setItem(presetStorageKey, JSON.stringify(savedFilterSets)); } catch (_) { }
  };
  const persistUIState = () => {
    try {
      localStorage.setItem(uiStateKey, JSON.stringify({
        activeKind,
        presetMode,
        quickChip,
        searchModule,
        searchJsOnly,
      }));
    } catch (_) { }
  };
  const loadUIState = () => {
    try { return JSON.parse(localStorage.getItem(uiStateKey) || '{}') || {}; } catch { return {}; }
  };
  const persistColumnWidths = () => {
    const cg = root.querySelector('#recon-colgroup');
    if (!cg) return;
    const cols = Array.from(cg.querySelectorAll('col')).map((c) => c.style.width || '');
    try { localStorage.setItem(colStateKey, JSON.stringify(cols)); } catch (_) { }
  };
  const applyColumnWidths = () => {
    const cg = root.querySelector('#recon-colgroup');
    if (!cg) return;
    let widths = null;
    try { widths = JSON.parse(localStorage.getItem(colStateKey) || 'null'); } catch { widths = null; }
    if (!Array.isArray(widths) || widths.length < 5) return;
    const cols = Array.from(cg.querySelectorAll('col'));
    cols.forEach((c, i) => {
      if (widths[i]) c.style.width = widths[i];
    });
  };

  const rowMatch = (r) => {
    const k = r.kind || 'other';
    if (String(activeKind || '').startsWith('mod:')) {
      const moduleKind = String(activeKind).slice(4);
      if (normalizeModuleKey(r.module) !== moduleKind) return false;
    } else if (String(activeKind || '').startsWith('apkcat:')) {
      const categorySlug = String(activeKind).slice(7);
      if (String(r.apk_category_slug || '') !== categorySlug) return false;
    } else if (activeKind === 'vuln') {
      if (!VULN_KINDS.has(k)) return false;
      if (searchModule !== 'all' && normalizeModuleKey(r.module) !== searchModule) return false;
    } else if (k !== activeKind) {
      return false;
    }
    if (activeKind === 'urls' && searchJsOnly && !r.is_js) return false;
    if (searchHost && !String(r.host || r.target || '').toLowerCase().includes(searchHost)) return false;
    if (searchTitle && !String(r.title || r.finding || '').toLowerCase().includes(searchTitle)) return false;
    if (filterSeverity !== 'any') {
      const sev = String(r.severity || 'info').toLowerCase();
      if (sev !== filterSeverity) return false;
    }
    const sev = String(r.severity || 'info').toLowerCase();
    const targetStr = String(r.target || '').toLowerCase();
    const findingStr = String(r.finding || '').toLowerCase();
    if (quickChip === 'highplus' && !(sev === 'high' || sev === 'critical')) return false;
    if (quickChip === 'hasurl' && !(/https?:\/\//i.test(targetStr) || /https?:\/\//i.test(findingStr))) return false;
    if (quickChip === 'exported' && !(findingStr.includes('exported') || String(r.apk_category || '').toLowerCase().includes('exported'))) return false;
    if (quickChip === 'secrets' && !/(secret|token|apikey|api key|password|authorization)/i.test(findingStr)) return false;
    if (quickChip === 'onlyjs' && !(/\.m?jsx?(\?|$)/i.test(targetStr) || findingStr.includes('javascript') || String(r.apk_category || '').toLowerCase().includes('js'))) return false;
    return true;
  };

  root.innerHTML = `
    <div style="border:1px solid var(--border);border-radius:10px;background:var(--bg-surface);overflow:hidden">
      <div style="display:grid;grid-template-columns:240px 1fr;min-height:720px">
        <aside style="border-right:1px solid var(--border);background:rgba(2,6,23,.55);display:flex;flex-direction:column;min-width:0">
          <div style="padding:10px 12px;border-bottom:1px solid var(--border);font-size:11px;color:var(--text-muted);letter-spacing:.6px;text-transform:uppercase">Findings Views</div>
          <div style="padding:8px;border-bottom:1px solid var(--border)">
            <input id="recon-rail-search" type="search" placeholder="Search views..." style="width:100%;padding:7px 9px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-size:11px"/>
          </div>
          <div id="recon-left-rail" style="display:flex;flex-direction:column;gap:6px;padding:8px;overflow-y:auto;overflow-x:hidden;max-height:780px;scrollbar-width:thin"></div>
        </aside>
        <section style="min-width:0;position:relative">
      <div id="recon-apk-meta" style="display:none;padding:10px 12px;border-bottom:1px solid var(--border);background:rgba(34,211,238,.06)"></div>
      <div id="recon-filter-bar" style="display:grid;grid-template-columns:minmax(200px,1.5fr) 140px 140px minmax(180px,1fr) auto;gap:8px;padding:10px;border-bottom:1px solid var(--border);background:rgba(2,6,23,.5)">
        <input id="recon-filter-host" type="search" placeholder="🔍 Filter by target URL..." style="padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-size:12px"/>
        <select id="recon-filter-severity" style="padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-size:12px">
          <option value="any">Any Severity</option>
          <option value="critical">🔴 Critical</option>
          <option value="high">🟠 High</option>
          <option value="medium">🟡 Medium</option>
          <option value="low">🔵 Low</option>
          <option value="info">🟢 Info</option>
        </select>
        <select id="recon-filter-module" style="display:${activeKind === 'vuln' ? 'block' : 'none'};padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-size:12px">
          <option value="all">All Modules</option>
        </select>
        <input id="recon-filter-title" type="search" placeholder="🔍 Filter by type / finding..." style="padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-size:12px"/>
        <div style="display:flex;align-items:center;justify-content:flex-end;gap:8px;font-size:11px;color:var(--text-muted);white-space:nowrap">
          <label id="recon-filter-js-wrap" style="display:none;align-items:center;gap:4px;font-size:12px;color:var(--text-primary);cursor:pointer;background:rgba(255,255,255,0.05);padding:4px 8px;border-radius:4px">
            <input type="checkbox" id="recon-filter-js-only" style="accent-color:var(--accent-cyan)"> Only JS
          </label>
          <span><span id="recon-unified-shown">0</span> rows</span>
        </div>
      </div>
      <div id="recon-quick-tools" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:8px 10px;border-bottom:1px solid var(--border);background:rgba(2,6,23,.38)">
        <div id="recon-quick-chips" style="display:flex;align-items:center;gap:6px;flex-wrap:wrap"></div>
        <div style="margin-left:auto;display:flex;align-items:center;gap:6px">
          <select id="recon-view-mode" style="padding:6px 8px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-size:11px">
            <option value="smart">Smart columns</option>
            <option value="raw">Raw columns</option>
          </select>
          <select id="recon-saved-filters" style="min-width:160px;padding:6px 8px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-size:11px">
            <option value="">Saved filters…</option>
          </select>
          <input id="recon-filter-name" type="text" placeholder="Filter name" style="width:130px;padding:6px 8px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-size:11px"/>
          <button id="recon-save-filter" type="button" style="padding:6px 10px;border:1px solid var(--border);border-radius:6px;background:rgba(34,211,238,.1);color:var(--accent-cyan);font-size:11px;cursor:pointer">Save</button>
          <button id="recon-delete-filter" type="button" style="padding:6px 10px;border:1px solid var(--border);border-radius:6px;background:rgba(248,113,113,.08);color:#fca5a5;font-size:11px;cursor:pointer">Delete</button>
        </div>
      </div>
      <!-- Standard findings table -->
      <div id="recon-standard-view">
        <div class="result-table-wrap" style="max-height:640px;overflow:auto">
          <table class="dashboard-table" style="margin:0;table-layout:fixed;width:100%">
            <colgroup id="recon-colgroup">
              <col style="width:36px">
              <col style="width:31%">
              <col style="width:8%">
              <col style="width:43%">
              <col style="width:16%">
            </colgroup>
            <thead style="position:sticky;top:0;z-index:2;background:rgba(2,6,23,.97);backdrop-filter:blur(4px)">
              <tr id="recon-unified-headrow">
                <th style="width:36px;text-align:center;padding-left:10px">
                  <input type="checkbox" id="findings-select-all" title="Select all" style="width:14px;height:14px;accent-color:var(--accent-cyan);cursor:pointer">
                </th>
                <th style="position:relative">TARGET<span class="col-resizer" data-col-index="1" style="position:absolute;top:0;right:-3px;width:6px;height:100%;cursor:col-resize;user-select:none"></span></th>
                <th style="text-align:center;position:relative">SEV<span class="col-resizer" data-col-index="2" style="position:absolute;top:0;right:-3px;width:6px;height:100%;cursor:col-resize;user-select:none"></span></th>
                <th style="position:relative">VULNERABILITY TYPE<span class="col-resizer" data-col-index="3" style="position:absolute;top:0;right:-3px;width:6px;height:100%;cursor:col-resize;user-select:none"></span></th>
                <th style="width:16%">MODULE</th>
              </tr>
            </thead>
            <tbody id="recon-unified-tbody"></tbody>
          </table>
        </div>
        <div id="recon-unified-cap" style="display:none;padding:10px 12px;font-size:12px;color:var(--text-muted);border-top:1px solid var(--border)"></div>
        <div id="recon-pagination" style="padding:10px 12px;background:rgba(2,6,23,0.3);border-top:1px solid var(--border);display:flex;justify-content:center;align-items:center;gap:15px;font-size:12px"></div>
      </div>
      <!-- Assets view (shown when Assets tab active) -->
      <div id="recon-assets-view" style="display:none">
        <div id="recon-assets-content" style="padding:16px;min-height:200px;max-height:680px;overflow:auto">
          <div style="text-align:center;padding:40px;color:var(--text-muted)">Loading assets…</div>
        </div>
      </div>
      <div id="recon-details-drawer" style="display:none;position:absolute;top:0;right:0;width:420px;height:100%;background:rgba(2,6,23,.98);border-left:1px solid var(--border);z-index:20;box-shadow:-12px 0 40px rgba(0,0,0,.45)">
        <div style="display:flex;align-items:center;justify-content:space-between;padding:12px;border-bottom:1px solid var(--border)">
          <div style="font-size:12px;color:var(--text-secondary);text-transform:uppercase;letter-spacing:.5px">Finding Details</div>
          <button id="recon-drawer-close" type="button" style="background:transparent;border:none;color:var(--text-muted);font-size:18px;cursor:pointer">✕</button>
        </div>
        <div id="recon-drawer-body" style="padding:12px;overflow:auto;height:calc(100% - 52px)"></div>
      </div>
        </section>
      </div>
    </div>`;

  const tabsEl = root.querySelector('#recon-left-rail');
  const railSearchInput = root.querySelector('#recon-rail-search');
  const apkMetaBar = root.querySelector('#recon-apk-meta');
  const filterBar = root.querySelector('#recon-filter-bar');
  const chipBar = root.querySelector('#recon-quick-chips');
  const viewModeSel = root.querySelector('#recon-view-mode');
  const savedFiltersSel = root.querySelector('#recon-saved-filters');
  const saveFilterBtn = root.querySelector('#recon-save-filter');
  const deleteFilterBtn = root.querySelector('#recon-delete-filter');
  const filterNameInput = root.querySelector('#recon-filter-name');
  const standardView = root.querySelector('#recon-standard-view');
  const assetsView = root.querySelector('#recon-assets-view');
  const assetsContent = root.querySelector('#recon-assets-content');
  const standardTable = root.querySelector('#recon-standard-view table.dashboard-table');
  const drawer = root.querySelector('#recon-details-drawer');
  const drawerBody = root.querySelector('#recon-drawer-body');
  const drawerClose = root.querySelector('#recon-drawer-close');

  if (apkMetaBar) {
    if (isAPKScan && apkPackageInfo) {
      const toInt = (v) => {
        const m = String(v || '').match(/\d+/);
        return m ? Number(m[0]) : NaN;
      };
      const targetSdk = toInt(apkPackageInfo.target_sdk);
      const minSdk = toInt(apkPackageInfo.min_sdk);
      const hasSingleTaskSignals = allRows.some((r) => {
        const t = String(r.target || '').toLowerCase();
        const f = String(r.finding || '').toLowerCase();
        return t.includes('singletasklaunchmode') || f.includes('launchmode: singletask');
      });
      const hasTaskAffinitySignals = allRows.some((r) => {
        const t = String(r.target || '').toLowerCase();
        const f = String(r.finding || '').toLowerCase();
        return t.includes('taskaffinity') || f.includes('taskaffinity');
      });
      let hijackLabel = 'Unknown';
      let hijackColor = '#94a3b8';
      if (!Number.isNaN(targetSdk)) {
        if (targetSdk <= 28) {
          hijackLabel = 'Likely';
          hijackColor = '#f97316';
        } else if (targetSdk <= 30) {
          hijackLabel = 'Possible';
          hijackColor = '#f59e0b';
        } else {
          hijackLabel = 'Harder';
          hijackColor = '#22c55e';
        }
      }
      const signalLabel = `${hasSingleTaskSignals ? 'singleTask' : 'no-singleTask'} / ${hasTaskAffinitySignals ? 'taskAffinity' : 'no-taskAffinity'}`;

      const ordered = [
        ['package_name', 'Package ID'],
        ['app_name', 'App Name'],
        ['version', 'Version'],
        ['version_code', 'Version Code'],
        ['min_sdk', 'Min SDK'],
        ['target_sdk', 'Target SDK'],
        ['compile_sdk', 'Compile SDK'],
      ].filter(([k]) => apkPackageInfo[k]);
      if (ordered.length) {
        apkMetaBar.style.display = 'flex';
        apkMetaBar.style.flexWrap = 'wrap';
        apkMetaBar.style.gap = '8px';
        apkMetaBar.innerHTML = [
          ...ordered.map(([k, label]) => (
          `<div style="display:flex;align-items:center;gap:6px;padding:6px 10px;border:1px solid rgba(34,211,238,.28);border-radius:8px;background:rgba(2,6,23,.45)">
            <span style="font-size:11px;color:#67e8f9">${esc(label)}:</span>
            <span style="font-size:11px;color:var(--text-primary);font-family:var(--font-mono,monospace)">${esc(apkPackageInfo[k])}</span>
          </div>`
        )),
          `<div style="display:flex;align-items:center;gap:6px;padding:6px 10px;border:1px solid ${hijackColor}55;border-radius:8px;background:rgba(2,6,23,.45)" title="Heuristic based on targetSdk + detected manifest signals">
            <span style="font-size:11px;color:${hijackColor}">singleTask Hijack:</span>
            <span style="font-size:11px;color:var(--text-primary);font-family:var(--font-mono,monospace)">${esc(hijackLabel)} (${esc(signalLabel)})</span>
          </div>`,
          !Number.isNaN(minSdk) ? `<div style="display:flex;align-items:center;gap:6px;padding:6px 10px;border:1px solid rgba(34,211,238,.28);border-radius:8px;background:rgba(2,6,23,.45)">
            <span style="font-size:11px;color:#67e8f9">Min API:</span>
            <span style="font-size:11px;color:var(--text-primary);font-family:var(--font-mono,monospace)">${esc(String(minSdk))}</span>
          </div>` : '',
          !Number.isNaN(targetSdk) ? `<div style="display:flex;align-items:center;gap:6px;padding:6px 10px;border:1px solid rgba(34,211,238,.28);border-radius:8px;background:rgba(2,6,23,.45)">
            <span style="font-size:11px;color:#67e8f9">Target API:</span>
            <span style="font-size:11px;color:var(--text-primary);font-family:var(--font-mono,monospace)">${esc(String(targetSdk))}</span>
          </div>` : '',
        ].join('');
      } else {
        apkMetaBar.style.display = 'none';
        apkMetaBar.innerHTML = '';
      }
    } else {
      apkMetaBar.style.display = 'none';
      apkMetaBar.innerHTML = '';
    }
  }

  const modSelect = root.querySelector('#recon-filter-module');
  if (modSelect) {
    const usedModules = [...new Set(allRows.map(r => normalizeModuleKey(r.module)))]
      .filter((m) => m && m !== 'unknown')
      .sort();
    modSelect.innerHTML = '<option value="all">All Modules</option>' + usedModules.map(m => {
      return `<option value="${esc(m)}">${esc(getModuleDisplayInfo(m).name)}</option>`;
    }).join('');
    modSelect.addEventListener('change', () => {
      searchModule = modSelect.value;
      renderBody();
    });
  }

  const renderSavedFilters = () => {
    if (!savedFiltersSel) return;
    const names = Object.keys(savedFilterSets).sort();
    savedFiltersSel.innerHTML = '<option value="">Saved filters…</option>' + names.map((n) => `<option value="${esc(n)}">${esc(n)}</option>`).join('');
  };
  const readCurrentFilterSet = () => ({
    activeKind,
    searchHost,
    searchTitle,
    filterSeverity,
    searchModule,
    searchJsOnly,
    quickChip,
    presetMode,
  });
  const applyFilterSet = (fs) => {
    if (!fs) return;
    activeKind = fs.activeKind || activeKind;
    searchHost = String(fs.searchHost || '');
    searchTitle = String(fs.searchTitle || '');
    filterSeverity = String(fs.filterSeverity || 'any');
    searchModule = String(fs.searchModule || 'all');
    searchJsOnly = !!fs.searchJsOnly;
    quickChip = String(fs.quickChip || 'none');
    presetMode = String(fs.presetMode || 'smart');
    const hostInputEl = root.querySelector('#recon-filter-host');
    const titleInputEl = root.querySelector('#recon-filter-title');
    const severitySelEl = root.querySelector('#recon-filter-severity');
    const jsChkEl = root.querySelector('#recon-filter-js-only');
    if (hostInputEl) hostInputEl.value = searchHost;
    if (titleInputEl) titleInputEl.value = searchTitle;
    if (severitySelEl) severitySelEl.value = filterSeverity;
    if (modSelect) modSelect.value = searchModule;
    if (jsChkEl) jsChkEl.checked = searchJsOnly;
    if (viewModeSel) viewModeSel.value = presetMode;
  };

  const chipDefs = [
    { id: 'highplus', label: 'High+' },
    { id: 'hasurl', label: 'Has URL' },
    { id: 'exported', label: 'Exported Components' },
    { id: 'secrets', label: 'Secrets' },
    { id: 'onlyjs', label: 'Only JS' },
  ];
  const renderChips = () => {
    if (!chipBar) return;
    chipBar.innerHTML = chipDefs.map((c) => {
      const active = quickChip === c.id;
      return `<button type="button" data-chip="${escAttr(c.id)}" style="padding:5px 10px;border:1px solid ${active ? 'rgba(34,211,238,.5)' : 'var(--border)'};border-radius:999px;background:${active ? 'rgba(34,211,238,.13)' : 'rgba(255,255,255,.02)'};color:${active ? 'var(--accent-cyan)' : 'var(--text-secondary)'};font-size:11px;cursor:pointer">${esc(c.label)}</button>`;
    }).join('');
  };

  const renderTabs = () => {
    if (!tabsEl) return;
    tabsEl.innerHTML = UNIQUE_TABS.filter(([, label]) => {
      if (!railSearch) return true;
      return String(label || '').toLowerCase().includes(railSearch);
    }).map(([kind, label]) => {
      const isActive = activeKind === kind;
      const isModuleTab = String(kind).startsWith('mod:');
      const isApkCategoryTab = String(kind).startsWith('apkcat:');
      const moduleKind = isModuleTab ? String(kind).slice(4) : '';
      const count = isModuleTab
        ? allRows.filter(r => normalizeModuleKey(r.module) === moduleKind).length
        : isApkCategoryTab
          ? (apkCategoryCounts[String(kind).slice(7)]?.count || 0)
          : ((kind === 'assets' || kind === 'vuln') ? datasetCount(kind) : (kindCounts[kind] || 0));
      const cntDisplay = count > 0 ? `<span class="tab-count">${count}</span>` : '';
      const labelText = `${label}`.trim();
      return `<button class="tab-pill${isActive ? ' active' : ''}" data-recon-kind="${escAttr(kind)}" title="${escAttr(labelText)}" style="display:flex;align-items:center;justify-content:space-between;gap:8px;width:100%;border:1px solid ${isActive ? 'rgba(34,211,238,.45)' : 'var(--border)'};border-radius:8px;padding:8px 10px;background:${isActive ? 'rgba(34,211,238,.1)' : 'rgba(255,255,255,.02)'};color:${isActive ? 'var(--accent-cyan)' : 'var(--text-secondary)'};font-size:12px;text-align:left;cursor:pointer">
        <span style="display:inline-block;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:middle">${esc(labelText)}</span> ${cntDisplay}
      </button>`;
    }).join('');
  };

  const renderBody = () => {
    const filtered = allRows.filter(r => {
      if (!rowMatch(r)) return false;
      if (HIDDEN_KINDS.has(r.kind)) return false; // always hide logs + tech rows
      return true;
    });
    
    const totalPages = Math.ceil(filtered.length / _pageSize) || 1;
    if (_currentPage > totalPages) _currentPage = totalPages;
    const slice = filtered.slice((_currentPage - 1) * _pageSize, _currentPage * _pageSize);
    const tbody = root.querySelector('#recon-unified-tbody');
    const headRow = root.querySelector('#recon-unified-headrow');
    const shown = root.querySelector('#recon-unified-shown');
    const cap = root.querySelector('#recon-unified-cap');
    const wrap = root.querySelector('.result-table-wrap');
    if (shown) shown.textContent = String(filtered.length);
    if (headRow) {
      const cols = presetMode === 'raw'
        ? ['TARGET', 'SEV', 'VULNERABILITY TYPE', 'MODULE']
        : getUnifiedTableColumns(activeKind);
      headRow.innerHTML = `
        <th style="width:36px;text-align:center;padding-left:10px">
          <input type="checkbox" id="findings-select-all" title="Select all" style="width:14px;height:14px;accent-color:var(--accent-cyan);cursor:pointer">
        </th>
        <th style="position:relative">${esc(cols[0])}<span class="col-resizer" data-col-index="1" style="position:absolute;top:0;right:-3px;width:6px;height:100%;cursor:col-resize;user-select:none"></span></th>
        <th style="text-align:center;position:relative">${esc(cols[1])}<span class="col-resizer" data-col-index="2" style="position:absolute;top:0;right:-3px;width:6px;height:100%;cursor:col-resize;user-select:none"></span></th>
        <th style="position:relative">${esc(cols[2])}<span class="col-resizer" data-col-index="3" style="position:absolute;top:0;right:-3px;width:6px;height:100%;cursor:col-resize;user-select:none"></span></th>
        <th style="width:16%">${esc(cols[3])}</th>
      `;
    }
    if (tbody) {
      currentRenderedRows = slice;
      const virtualEnabled = slice.length > 150;
      const rowHeight = 34;
      const overscan = 12;
      const viewportH = Math.max(320, Math.round((wrap?.clientHeight || 640)));
      const visibleRows = Math.ceil(viewportH / rowHeight) + overscan * 2;
      const vStart = virtualEnabled ? Math.max(0, Math.floor(_virtualScrollTop / rowHeight) - overscan) : 0;
      const vEnd = virtualEnabled ? Math.min(slice.length, vStart + visibleRows) : slice.length;
      const renderSlice = slice.slice(vStart, vEnd);
      const topPad = virtualEnabled ? vStart * rowHeight : 0;
      const bottomPad = virtualEnabled ? Math.max(0, (slice.length - vEnd) * rowHeight) : 0;
      const rowsHtml = renderSlice.map((r, idx) => {
        const rowIdx = vStart + idx;
        const sev = String(r.severity || '').toLowerCase().replace(/[—\-]/g, '').trim();
        const sevMeta = {
          critical: { color: '#fc8181', bg: '#fc818120', label: 'CRIT' },
          high: { color: '#f6ad55', bg: '#f6ad5520', label: 'HIGH' },
          medium: { color: '#f6e05e', bg: '#f6e05e20', label: 'MED' },
          low: { color: '#63b3ed', bg: '#63b3ed20', label: 'LOW' },
          info: { color: '#68d391', bg: '#68d39120', label: 'INFO' },
          warning: { color: '#f6ad55', bg: '#f6ad5520', label: 'WARN' },
        }[sev] || { color: '#718096', bg: '#71809615', label: '—' };

        const modInfo = getModuleDisplayInfo(r.module);
        if (presetMode === 'raw') return renderDefaultRow(r, rowIdx, modInfo, sevMeta);
        return renderRowForUnifiedTab(r, rowIdx, activeKind, modInfo, sevMeta);
      }).join('');
      if (!slice.length) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:28px;color:var(--text-muted);font-size:13px">No findings match the current filter.</td></tr>';
      } else {
        tbody.innerHTML = `${topPad ? `<tr class="virtual-pad-top"><td colspan="5" style="padding:0;border:none;height:${topPad}px"></td></tr>` : ''}${rowsHtml}${bottomPad ? `<tr class="virtual-pad-bottom"><td colspan="5" style="padding:0;border:none;height:${bottomPad}px"></td></tr>` : ''}`;
      }
      if (renderSlice.length) {
        Array.from(tbody.querySelectorAll('.findings-row')).forEach((tr, i) => {
          tr.setAttribute('data-row-index', String(vStart + i));
        });
      }
    }
    const pagContainer = root.querySelector('#recon-pagination');
    if (pagContainer) {
      if (totalPages <= 1) {
        pagContainer.style.display = 'none';
      } else {
        pagContainer.style.display = 'flex';
        pagContainer.innerHTML = `
          <button id="recon-prev" class="btn btn-sm" ${_currentPage === 1 ? 'disabled' : ''} style="padding:4px 10px;font-size:11px;background:var(--bg-card);border:1px solid var(--border);color:var(--text-primary);cursor:pointer">← Prev</button>
          <span style="color:var(--text-secondary);font-weight:600">Page ${_currentPage} of ${totalPages}</span>
          <button id="recon-next" class="btn btn-sm" ${_currentPage === totalPages ? 'disabled' : ''} style="padding:4px 10px;font-size:11px;background:var(--bg-card);border:1px solid var(--border);color:var(--text-primary);cursor:pointer">Next →</button>
          <span style="color:var(--text-muted);margin-left:auto">${filtered.length} total rows</span>
        `;
        pagContainer.querySelector('#recon-prev').onclick = () => {
          if (_currentPage > 1) { _currentPage--; renderBody(); root.querySelector('.result-table-wrap').scrollTop = 0; }
        };
        pagContainer.querySelector('#recon-next').onclick = () => {
          if (_currentPage < totalPages) { _currentPage++; renderBody(); root.querySelector('.result-table-wrap').scrollTop = 0; }
        };
      }
    }
  };

  // ── Assets tab renderer ──────────────────────────────────────────────────
  const showAssetsView = async () => {
    if (filterBar) filterBar.style.display = 'none';
    if (standardView) standardView.style.display = 'none';
    if (assetsView) assetsView.style.display = 'block';
    if (!assetsContent) return;
    if (_assetsCache) { renderAssetsGrid(assetsContent, _assetsCache); return; }
    if (_assetsLoading) return;
    _assetsLoading = true;
    assetsContent.innerHTML = '<div style="text-align:center;padding:40px;color:var(--text-muted)"><div style="font-size:28px;margin-bottom:12px">🔍</div>Building asset inventory…</div>';
    try {
      const data = await apiFetch(`/api/scans/${encodeURIComponent(scanId)}/results/assets`);
      _assetsCache = data.assets || [];
      renderAssetsGrid(assetsContent, _assetsCache);
    } catch (e) {
      assetsContent.innerHTML = `<div style="padding:24px;color:var(--accent-red)">Failed to load assets: ${esc(e.message)}</div>`;
    } finally {
      _assetsLoading = false;
    }
  };

  const showStandardView = () => {
    if (filterBar) filterBar.style.display = '';
    if (standardView) standardView.style.display = 'block';
    if (assetsView) assetsView.style.display = 'none';
  };

  const switchReconView = (kind) => {
    activeKind = kind;
    persistUIState();
    renderTabs();
    
    const modSelectEl = root.querySelector('#recon-filter-module');
    if (modSelectEl) {
      const isModuleTab = String(activeKind || '').startsWith('mod:');
      modSelectEl.style.display = (activeKind === 'vuln' && !isModuleTab) ? 'block' : 'none';
      if (activeKind !== 'vuln' || isModuleTab) {
        modSelectEl.value = 'all';
        searchModule = 'all';
      }
    }

    const jsWrap = root.querySelector('#recon-filter-js-wrap');
    if (jsWrap) {
      jsWrap.style.display = (activeKind === 'urls') ? 'inline-flex' : 'none';
      if (activeKind !== 'urls') {
        const jsChk = root.querySelector('#recon-filter-js-only');
        if (jsChk && jsChk.checked) {
          jsChk.checked = false;
          searchJsOnly = false;
        }
      }
    }

    if (activeKind === 'assets') {
      if (filterBar) filterBar.style.display = 'none';
      if (standardView) standardView.style.display = 'none';
      if (assetsView) assetsView.style.display = 'block';
      showAssetsView();
    } else {
      if (filterBar) filterBar.style.display = '';
      if (standardView) standardView.style.display = 'block';
      if (assetsView) assetsView.style.display = 'none';
      _currentPage = 1;
      renderBody();
    }
  };

  // Initial load
  const uiState = loadUIState();
  if (uiState && typeof uiState === 'object') {
    if (uiState.activeKind && UNIQUE_TABS.some((t) => t[0] === uiState.activeKind)) activeKind = uiState.activeKind;
    if (uiState.presetMode === 'raw' || uiState.presetMode === 'smart') presetMode = uiState.presetMode;
    if (uiState.quickChip) quickChip = uiState.quickChip;
    if (uiState.searchModule) searchModule = uiState.searchModule;
    if (typeof uiState.searchJsOnly === 'boolean') searchJsOnly = uiState.searchJsOnly;
  }
  loadSavedSets();
  renderSavedFilters();
  renderChips();
  switchReconView(activeKind);
  applyColumnWidths();
  if (viewModeSel) viewModeSel.value = presetMode;
  if (railSearchInput) {
    railSearchInput.addEventListener('input', () => {
      railSearch = String(railSearchInput.value || '').trim().toLowerCase();
      renderTabs();
    });
  }

  const renderDrawerRow = (r) => {
    if (!drawerBody) return;
    const safeJson = esc(JSON.stringify(r, null, 2));
    drawerBody.innerHTML = `
      <div style="display:grid;gap:10px">
        <div><div style="font-size:11px;color:var(--text-muted)">Target</div><div style="font-family:var(--font-mono,monospace);font-size:12px;color:var(--text-primary);word-break:break-all">${esc(String(r.target || r.host || '—'))}</div></div>
        <div><div style="font-size:11px;color:var(--text-muted)">Severity</div><div style="font-size:12px;color:var(--text-primary)">${esc(String(r.severity || '—'))}</div></div>
        <div><div style="font-size:11px;color:var(--text-muted)">Module</div><div style="font-size:12px;color:var(--text-primary)">${esc(String(r.module || '—'))}</div></div>
        <div><div style="font-size:11px;color:var(--text-muted)">Finding</div><div style="font-family:var(--font-mono,monospace);font-size:12px;color:var(--text-primary);word-break:break-word">${esc(String(r.finding || '—'))}</div></div>
        <div><div style="font-size:11px;color:var(--text-muted)">Source File</div><div style="font-family:var(--font-mono,monospace);font-size:12px;color:var(--text-primary);word-break:break-all">${esc(String(r.file || '—'))}</div></div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;padding-top:4px">
          <button id="drawer-copy-finding" type="button" style="padding:6px 10px;border:1px solid var(--border);border-radius:6px;background:rgba(34,211,238,.1);color:var(--accent-cyan);font-size:11px;cursor:pointer">Copy Finding</button>
          <button id="drawer-copy-json" type="button" style="padding:6px 10px;border:1px solid var(--border);border-radius:6px;background:rgba(255,255,255,.03);color:var(--text-primary);font-size:11px;cursor:pointer">Copy JSON</button>
          <button id="drawer-export-json" type="button" style="padding:6px 10px;border:1px solid var(--border);border-radius:6px;background:rgba(52,211,153,.1);color:#34d399;font-size:11px;cursor:pointer">Export JSON</button>
        </div>
        <pre style="margin:0;padding:10px;border:1px solid var(--border);border-radius:8px;background:rgba(255,255,255,.02);font-size:11px;line-height:1.45;color:var(--text-muted);overflow:auto;max-height:280px">${safeJson}</pre>
      </div>`;
    const copyFinding = drawerBody.querySelector('#drawer-copy-finding');
    const copyJson = drawerBody.querySelector('#drawer-copy-json');
    const exportJson = drawerBody.querySelector('#drawer-export-json');
    if (copyFinding) copyFinding.onclick = async () => { await copyToClipboard(String(r.finding || '')); showToast('success', 'Copied', 'Finding copied'); };
    if (copyJson) copyJson.onclick = async () => { await copyToClipboard(JSON.stringify(r, null, 2)); showToast('success', 'Copied', 'JSON copied'); };
    if (exportJson) exportJson.onclick = () => {
      const blob = new Blob([JSON.stringify(r, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `finding-${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    };
  };
  const openDrawerForRow = (r) => {
    if (!drawer) return;
    renderDrawerRow(r);
    drawer.style.display = 'block';
  };
  const closeDrawer = () => { if (drawer) drawer.style.display = 'none'; };
  if (drawerClose) drawerClose.addEventListener('click', closeDrawer);

  // ── Draggable column widths ───────────────────────────────────────────────
  const ensureColPixels = () => {
    const cg = root.querySelector('#recon-colgroup');
    if (!cg || !standardTable) return;
    const cols = Array.from(cg.querySelectorAll('col'));
    if (cols.length < 5) return;
    const ths = Array.from(root.querySelectorAll('#recon-unified-headrow th'));
    if (ths.length < 5) return;
    for (let i = 1; i <= 4; i++) {
      const w = cols[i].style.width || '';
      if (w.includes('%')) cols[i].style.width = `${Math.max(70, Math.round(ths[i].getBoundingClientRect().width))}px`;
    }
  };
  const startColumnResize = (colIndex, startX) => {
    const cg = root.querySelector('#recon-colgroup');
    if (!cg) return;
    const cols = Array.from(cg.querySelectorAll('col'));
    const left = cols[colIndex];
    const right = cols[colIndex + 1];
    if (!left || !right) return;
    ensureColPixels();
    const leftStart = parseFloat(left.style.width || '0');
    const rightStart = parseFloat(right.style.width || '0');
    const minLeft = 90;
    const minRight = 90;
    const onMove = (ev) => {
      const dx = ev.clientX - startX;
      const newLeft = leftStart + dx;
      const newRight = rightStart - dx;
      if (newLeft < minLeft || newRight < minRight) return;
      left.style.width = `${newLeft}px`;
      right.style.width = `${newRight}px`;
    };
    const onUp = () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      persistColumnWidths();
    };
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
  };

  root.addEventListener('click', (e) => {
    const tabBtn = e.target.closest('[data-recon-kind]');
    if (!tabBtn || !root.contains(tabBtn)) return;
    const kind = tabBtn.getAttribute('data-recon-kind') || 'all';
    switchReconView(kind);
  });
  if (chipBar) {
    chipBar.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-chip]');
      if (!btn) return;
      const id = String(btn.getAttribute('data-chip') || 'none');
      quickChip = quickChip === id ? 'none' : id;
      renderChips();
      _currentPage = 1;
      renderBody();
    });
  }
  if (viewModeSel) {
    viewModeSel.addEventListener('change', () => {
      presetMode = String(viewModeSel.value || 'smart');
      persistUIState();
      _currentPage = 1;
      renderBody();
    });
  }
  if (saveFilterBtn) {
    saveFilterBtn.addEventListener('click', () => {
      const name = String(filterNameInput?.value || '').trim();
      if (!name) {
        showToast('error', 'Missing name', 'Enter a filter name first');
        return;
      }
      savedFilterSets[name] = readCurrentFilterSet();
      persistSavedSets();
      renderSavedFilters();
      if (savedFiltersSel) savedFiltersSel.value = name;
      showToast('success', 'Saved', `Filter "${name}" saved`);
    });
  }
  if (deleteFilterBtn) {
    deleteFilterBtn.addEventListener('click', () => {
      const name = String(savedFiltersSel?.value || '').trim();
      if (!name || !savedFilterSets[name]) return;
      delete savedFilterSets[name];
      persistSavedSets();
      renderSavedFilters();
      showToast('success', 'Deleted', `Filter "${name}" deleted`);
    });
  }
  if (savedFiltersSel) {
    savedFiltersSel.addEventListener('change', () => {
      const name = String(savedFiltersSel.value || '').trim();
      if (!name || !savedFilterSets[name]) return;
      applyFilterSet(savedFilterSets[name]);
      renderChips();
      switchReconView(activeKind);
      persistUIState();
    });
  }
  root.addEventListener('mousedown', (e) => {
    const handle = e.target.closest('.col-resizer');
    if (!handle || !root.contains(handle)) return;
    const idx = Number(handle.getAttribute('data-col-index') || '0');
    if (!idx) return;
    e.preventDefault();
    startColumnResize(idx, e.clientX);
  });
  const tableWrap = root.querySelector('.result-table-wrap');
  if (tableWrap) {
    tableWrap.addEventListener('scroll', () => {
      _virtualScrollTop = tableWrap.scrollTop || 0;
      if (currentRenderedRows.length > 150) renderBody();
    });
  }

  const hostInput = root.querySelector('#recon-filter-host');
  const titleInput = root.querySelector('#recon-filter-title');
  const severitySel = root.querySelector('#recon-filter-severity');
  let debounceTimer = null;
  const applyFilters = () => {
    searchHost = String(hostInput?.value || '').trim().toLowerCase();
    searchTitle = String(titleInput?.value || '').trim().toLowerCase();
    filterSeverity = String(severitySel?.value || 'any').toLowerCase();
    _currentPage = 1;
    renderBody();
  };
  const applyFiltersDebounced = () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(applyFilters, 200);
  };
  if (hostInput) hostInput.addEventListener('input', applyFiltersDebounced);
  if (titleInput) titleInput.addEventListener('input', applyFiltersDebounced);
  if (severitySel) severitySel.addEventListener('change', applyFilters);
  
  const jsChk = root.querySelector('#recon-filter-js-only');
  if (jsChk) {
    jsChk.addEventListener('change', (e) => {
      searchJsOnly = e.target.checked;
      _currentPage = 1;
      renderBody();
    });
  }

  // ── Selection toolbar ─────────────────────────────────────────────────────
  // Build the floating toolbar (once, outside the root so it stays on DOM)
  let _selToolbar = document.getElementById('findings-sel-toolbar');
  if (!_selToolbar) {
    _selToolbar = document.createElement('div');
    _selToolbar.id = 'findings-sel-toolbar';
    _selToolbar.style.cssText = [
      'position:fixed;bottom:28px;left:50%;transform:translateX(-50%) translateY(80px)',
      'z-index:9000;background:var(--bg-card,#1e293b)',
      'border:1px solid var(--accent-cyan,#22d3ee)44',
      'border-radius:14px;padding:10px 18px',
      'display:flex;align-items:center;gap:12px',
      'box-shadow:0 8px 40px rgba(0,0,0,.7)',
      'transition:transform .25s cubic-bezier(.34,1.56,.64,1),opacity .2s',
      'opacity:0;pointer-events:none;white-space:nowrap',
    ].join(';');
    _selToolbar.innerHTML = `
      <span id="sel-count-badge" style="background:var(--accent-cyan,#22d3ee);color:#0f172a;font-size:11px;font-weight:700;padding:3px 9px;border-radius:20px;min-width:22px;text-align:center">0</span>
      <span style="font-size:12px;color:var(--text-secondary)">selected</span>
      <div style="width:1px;height:20px;background:var(--border)"></div>
      <button id="sel-copy-targets" title="Copy all selected targets" style="background:transparent;border:1px solid var(--border);border-radius:8px;padding:5px 12px;font-size:12px;color:var(--text-primary);cursor:pointer">📋 Copy Targets</button>
      <button id="sel-copy-findings" title="Copy full details for selected findings" style="background:transparent;border:1px solid var(--border);border-radius:8px;padding:5px 12px;font-size:12px;color:var(--text-primary);cursor:pointer">📝 Copy Findings</button>
      <button id="sel-open-urls" title="Open all selected targets in new tabs" style="background:transparent;border:1px solid var(--border);border-radius:8px;padding:5px 12px;font-size:12px;color:var(--accent-cyan,#22d3ee);cursor:pointer">🌐 Open URLs</button>
      <button id="sel-validate-ai" title="AI-validate the first selected finding" style="background:rgba(167,139,250,.15);border:1px solid #a78bfa44;border-radius:8px;padding:5px 12px;font-size:12px;color:#a78bfa;cursor:pointer">🤖 Validate with AI</button>
      <button id="sel-report-ai" title="Generate a bug report for the first selected finding" style="background:rgba(52,211,153,.12);border:1px solid #34d39944;border-radius:8px;padding:5px 12px;font-size:12px;color:#34d399;cursor:pointer">📄 Report with AI</button>
      <button id="sel-clear" title="Clear selection" style="background:transparent;border:none;font-size:17px;color:var(--text-muted);cursor:pointer;padding:0 2px;line-height:1">✕</button>`;
    document.body.appendChild(_selToolbar);

    // Hover effect on toolbar buttons
    _selToolbar.querySelectorAll('button').forEach(b => {
      if (b.id === 'sel-clear') return;
      b.addEventListener('mouseenter', () => b.style.opacity = '0.8');
      b.addEventListener('mouseleave', () => b.style.opacity = '1');
    });
  }


  const _getSelectedRows = () => Array.from(root.querySelectorAll('.finding-chk:checked')).map(cb => cb.closest('.findings-row')).filter(Boolean);

  const _updateToolbar = () => {
    const rows = _getSelectedRows();
    const n = rows.length;
    const badge = _selToolbar.querySelector('#sel-count-badge');
    if (badge) badge.textContent = String(n);
    if (n > 0) {
      _selToolbar.style.opacity = '1';
      _selToolbar.style.pointerEvents = 'auto';
      _selToolbar.style.transform = 'translateX(-50%) translateY(0)';
    } else {
      _selToolbar.style.opacity = '0';
      _selToolbar.style.pointerEvents = 'none';
      _selToolbar.style.transform = 'translateX(-50%) translateY(80px)';
    }
  };

  // Delegate checkbox change events from the findings table
  root.addEventListener('change', e => {
    if (e.target.classList.contains('finding-chk') || e.target.id === 'findings-select-all') {
      if (e.target.id === 'findings-select-all') {
        root.querySelectorAll('.finding-chk').forEach(cb => cb.checked = e.target.checked);
      }
      _updateToolbar();
    }
  });

  // Clicking a row opens details drawer (selection stays checkbox-driven)
  root.addEventListener('click', e => {
    const row = e.target.closest('.findings-row');
    if (!row) return;
    if (e.target.tagName === 'A' || e.target.tagName === 'INPUT' || e.target.tagName === 'BUTTON') return;
    const idx = Number(row.getAttribute('data-row-index') || '-1');
    const data = idx >= 0 ? currentRenderedRows[idx] : null;
    if (data) openDrawerForRow(data);
  });

  // Toolbar actions
  _selToolbar.querySelector('#sel-copy-targets').addEventListener('click', async () => {
    const rows = _getSelectedRows();
    if (!rows.length) return;
    const text = rows.map(r => r.dataset.target || '').filter(Boolean).join('\n');
    await copyToClipboard(text).catch(() => { });
    showToast('success', 'Copied', `${rows.length} target(s) copied`);
  });

  _selToolbar.querySelector('#sel-copy-findings').addEventListener('click', async () => {
    const rows = _getSelectedRows();
    if (!rows.length) return;
    // Copy full details: TARGET | SEV | VULNERABILITY TYPE | MODULE
    const text = rows.map(r => [
      r.dataset.target || '',
      (r.dataset.severity || '').toUpperCase(),
      r.dataset.finding || '',
      r.dataset.module || ''
    ].join(' | ')).join('\n');
    await copyToClipboard(text).catch(() => { });
    showToast('success', 'Copied', `${rows.length} finding(s) — full details copied`);
  });

  _selToolbar.querySelector('#sel-open-urls').addEventListener('click', () => {
    const rows = _getSelectedRows();
    if (!rows.length) return;
    let opened = 0;
    rows.forEach(r => {
      const href = r.dataset.href;
      if (href && href !== '#') { window.open(href, '_blank', 'noopener'); opened++; }
    });
    if (!opened) showToast('error', 'No URLs', 'None of the selected rows have valid URLs.');
    else showToast('success', 'Opened', `${opened} URL(s) opened in new tabs`);
  });

  _selToolbar.querySelector('#sel-validate-ai').addEventListener('click', () => {
    const rows = _getSelectedRows();
    if (!rows.length) return;
    const r = rows[0];
    openValidateModal(r.dataset.target, r.dataset.finding, r.dataset.severity, r.dataset.module);
  });

  _selToolbar.querySelector('#sel-report-ai').addEventListener('click', () => {
    const rows = _getSelectedRows();
    if (!rows.length) return;
    const r = rows[0];
    openReportModal(r.dataset.target, r.dataset.finding, r.dataset.severity, r.dataset.module);
  });

  _selToolbar.querySelector('#sel-clear').addEventListener('click', () => {
    root.querySelectorAll('.finding-chk').forEach(cb => cb.checked = false);
    const sa = root.querySelector('#findings-select-all');
    if (sa) sa.checked = false;
    _updateToolbar();
  });
}


// ── AI Validate Finding Modal ─────────────────────────────────────────────────
function openValidateModal(target, findingType, severity, module_) {
  let modal = document.getElementById('validate-finding-modal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'validate-finding-modal';
    modal.style.cssText = 'position:fixed;inset:0;z-index:10000;background:rgba(0,0,0,.7);backdrop-filter:blur(4px);display:flex;align-items:center;justify-content:center;padding:20px';
    modal.innerHTML = `
      <div style="background:var(--bg-card,#1e293b);border:1px solid var(--border);border-radius:16px;max-width:780px;width:100%;max-height:85vh;display:flex;flex-direction:column;box-shadow:0 24px 64px rgba(0,0,0,.8)">
        <div style="padding:20px 24px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-shrink:0">
          <div>
            <div style="font-size:16px;font-weight:700;color:var(--text-primary)">🤖 AI Finding Validation</div>
            <div id="validate-modal-sub" style="font-size:12px;color:var(--text-muted);margin-top:2px"></div>
          </div>
          <button id="validate-modal-close" style="background:transparent;border:none;color:var(--text-muted);font-size:20px;cursor:pointer;padding:4px 8px">✕</button>
        </div>
        <div id="validate-modal-body" style="padding:24px;overflow-y:auto;flex:1;font-size:13px;line-height:1.7;color:var(--text-secondary)">
          <div style="text-align:center;padding:40px">
            <div style="font-size:32px;margin-bottom:12px">⏳</div>
            <div style="color:var(--text-muted)">Asking AI to validate this finding…</div>
          </div>
        </div>
      </div>`;
    document.body.appendChild(modal);
    modal.addEventListener('click', e => { if (e.target === modal) modal.style.display = 'none'; });
    modal.querySelector('#validate-modal-close').addEventListener('click', () => { modal.style.display = 'none'; });
  }
  modal.style.display = 'flex';
  modal.querySelector('#validate-modal-sub').textContent = `${target || '—'} · ${findingType || '—'}`;
  const body = modal.querySelector('#validate-modal-body');
  body.innerHTML = `<div style="text-align:center;padding:40px"><div style="font-size:32px;margin-bottom:12px">⏳</div><div style="color:var(--text-muted)">Asking AI to validate this finding…</div></div>`;

  // ── Call backend validate endpoint ──────────────────────────────────────────
  apiPost('/api/findings/validate', {
    target: target || '',
    finding_type: findingType || '',
    severity: severity || '',
    module: module_ || ''
  }, { 'X-OpenRouter-Key': localStorage.getItem('autoar_or_key') || '' }).then(res => {
    // Render markdown-ish response
    const html = (res.analysis || 'No analysis returned.')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/^#{1,3}\s(.+)$/gm, '<div style="font-size:14px;font-weight:700;color:var(--accent-cyan);margin:16px 0 6px">$1</div>')
      .replace(/^(\d+)\.\s/gm, '<br><strong>$1.</strong> ')
      .replace(/`([^`]+)`/g, '<code style="background:rgba(255,255,255,.08);border-radius:4px;padding:1px 6px;font-family:monospace;font-size:11px">$1</code>')
      .replace(/\n/g, '<br>');
    body.innerHTML = `<div style="padding:4px 0">${html}</div>
      <div style="margin-top:20px;padding-top:16px;border-top:1px solid var(--border);display:flex;gap:10px;flex-wrap:wrap">
        <button onclick="copyToClipboard(document.getElementById('validate-finding-modal').querySelector('#validate-modal-body').innerText).then(()=>showToast('success','Copied','Analysis copied to clipboard'))" class="btn btn-ghost" style="font-size:12px;padding:6px 14px">📋 Copy Analysis</button>
      </div>`;
  }).catch(err => {
    body.innerHTML = `<div style="color:#ef4444;padding:20px">❌ AI validation failed: ${esc(err.message)}</div>`;
  });
}

// ── AI Report Generation Modal ───────────────────────────────────────────────
function openReportModal(target, findingType, severity, module_) {
  let modal = document.getElementById('report-finding-modal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'report-finding-modal';
    modal.style.cssText = 'position:fixed;inset:0;z-index:10000;background:rgba(0,0,0,.7);backdrop-filter:blur(4px);display:flex;align-items:center;justify-content:center;padding:20px';
    modal.innerHTML = `
      <div style="background:var(--bg-card,#1e293b);border:1px solid var(--border);border-radius:16px;max-width:850px;width:100%;height:85vh;display:flex;flex-direction:column;box-shadow:0 24px 64px rgba(0,0,0,.8)">
        <div style="padding:20px 24px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-shrink:0">
          <div>
            <div style="font-size:16px;font-weight:700;color:var(--text-primary)">📄 Bug Bounty Report</div>
            <div id="report-modal-sub" style="font-size:12px;color:var(--text-muted);margin-top:2px"></div>
          </div>
          <button id="report-modal-close" style="background:transparent;border:none;color:var(--text-muted);font-size:20px;cursor:pointer;padding:4px 8px">✕</button>
        </div>
        <div id="report-modal-body" style="padding:24px;overflow-y:auto;flex:1;font-size:13.5px;line-height:1.7;color:var(--text-secondary)">
          <div style="text-align:center;padding:40px">
            <div style="font-size:32px;margin-bottom:12px">⏳</div>
            <div style="color:var(--text-muted)">Generating report with AI…</div>
          </div>
        </div>
      </div>`;
    document.body.appendChild(modal);
    modal.addEventListener('click', e => { if (e.target === modal) modal.style.display = 'none'; });
    modal.querySelector('#report-modal-close').addEventListener('click', () => { modal.style.display = 'none'; });
  }
  modal.style.display = 'flex';
  modal.querySelector('#report-modal-sub').textContent = `${target || '—'} · ${findingType || '—'}`;
  const body = modal.querySelector('#report-modal-body');
  body.innerHTML = `<div style="text-align:center;padding:40px"><div style="font-size:32px;margin-bottom:12px">⏳</div><div style="color:var(--text-muted)">Generating report with AI…</div></div>`;

  apiPost('/api/findings/report', {
    target: target || '',
    finding_type: findingType || '',
    severity: severity || '',
    module: module_ || ''
  }, { 'X-OpenRouter-Key': localStorage.getItem('autoar_or_key') || '' }).then(res => {
    // Basic Markdown conversion
    const html = (res.report || 'No report generated.')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/^#{1,3}\s(.+)$/gm, '<div style="font-size:18px;font-weight:700;color:var(--text-primary);margin:24px 0 8px;border-bottom:1px solid var(--border);padding-bottom:6px">$1</div>')
      .replace(/^(\d+)\.\s(.+)$/gm, '<div style="margin-left:14px;display:flex"><strong style="margin-right:6px">$1.</strong><span>$2</span></div>')
      .replace(/^- (.+)$/gm, '<div style="margin-left:14px">• $1</div>')
      .replace(/`([^`]+)`/g, '<code style="background:rgba(255,255,255,.08);border-radius:4px;padding:1px 6px;font-family:monospace;font-size:12px">$1</code>')
      .replace(/\n/g, '<br>');
    
    body.innerHTML = `<div style="padding:4px 0;font-family:var(--font-sans);color:#e2e8f0">${html}</div>
      <div style="margin-top:30px;padding-top:16px;border-top:1px solid var(--border);display:flex;gap:10px;justify-content:flex-end">
        <button onclick="copyToClipboard(document.getElementById('report-finding-modal').querySelector('#report-modal-body > div').innerText).then(()=>showToast('success','Copied','Report copied to clipboard'))" class="btn btn-primary" style="font-size:13px;padding:8px 18px">📋 Copy Report</button>
      </div>`;
  }).catch(err => {
    body.innerHTML = `<div style="color:#ef4444;padding:20px;background:rgba(239,68,68,0.1);border-radius:8px;border:1px solid rgba(239,68,68,0.2)">
      <div style="font-weight:700;margin-bottom:8px">❌ AI Report Generation Failed</div>
      <div>${esc(err.message)}</div>
    </div>`;
  });
}


// ── Find module file content helper (existing) ───────────────────────────────
/** Find module file content container by file_name */
function findModuleFileContent(container, r2Key) {
  const allContent = container.querySelectorAll('.module-file-content[data-r2-key]');
  for (const el of allContent) {
    if (el.getAttribute('data-r2-key') === r2Key) return el;
  }
  return null;
}

// ── AssetEye-style Assets grid ───────────────────────────────────────────────
function renderAssetsGrid(container, assets) {
  if (!assets || !assets.length) {
    container.innerHTML = '<div style="text-align:center;padding:40px;color:var(--text-muted)"><div style="font-size:40px;margin-bottom:12px">🌐</div><div>No subdomains discovered yet — run a subdomain enumeration scan first.</div></div>';
    return;
  }

  const liveCount = assets.filter(a => a.is_live).length;
  const deadCount = assets.length - liveCount;

  const codeColor = (code) => {
    if (!code) return 'var(--text-muted)';
    if (code < 300) return '#10b981';
    if (code < 400) return '#f59e0b';
    if (code < 500) return '#ef4444';
    return '#8b5cf6';
  };

  const renderRows = (list) => list.map(a => {
    const liveIcon = a.is_live
      ? `<span style="display:inline-flex;align-items:center;gap:5px;background:rgba(16,185,129,.15);border:1px solid rgba(16,185,129,.4);border-radius:20px;padding:3px 10px;font-size:11px;color:#10b981;white-space:nowrap"><span style="width:6px;height:6px;border-radius:50%;background:#10b981;box-shadow:0 0 5px #10b981;flex-shrink:0"></span>Alive</span>`
      : `<span style="display:inline-flex;align-items:center;gap:5px;background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.3);border-radius:20px;padding:3px 10px;font-size:11px;color:#ef4444;white-space:nowrap"><span style="width:6px;height:6px;border-radius:50%;background:#ef4444;flex-shrink:0"></span>Dead</span>`;
    const codeEl = a.status_code
      ? `<code style="font-size:13px;font-weight:700;color:${codeColor(a.status_code)}">${a.status_code}</code>`
      : `<span style="color:var(--text-muted)">—</span>`;
    const techBadges = (a.technologies || []).slice(0, 5).map(t =>
      `<span style="background:rgba(99,102,241,.15);border:1px solid rgba(99,102,241,.35);border-radius:4px;padding:1px 7px;font-size:10px;color:#818cf8;white-space:nowrap">${esc(t)}</span>`
    ).join('') + ((a.technologies || []).length > 5
      ? `<span style="font-size:10px;color:var(--text-muted)"> +${(a.technologies || []).length - 5}</span>` : '');
    // IP column was removed, old cnames variable replaced with cnameCell
    const hostDisplay = a.url
      ? `<a href="${esc(a.url)}" target="_blank" rel="noopener" style="color:var(--accent-cyan);font-family:'JetBrains Mono',monospace;font-size:12px;text-decoration:none;word-break:break-all">${esc(a.host)}</a>`
      : `<span style="color:var(--text-secondary);font-family:'JetBrains Mono',monospace;font-size:12px;word-break:break-all">${esc(a.host)}</span>`;
    const title = a.title ? `<div style="font-size:11px;color:var(--text-muted);margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:280px" title="${esc(a.title)}">${esc(a.title.length > 60 ? a.title.slice(0, 60) + '…' : a.title)}</div>` : '';
    const cnames = (a.cnames || []);
    const cnameCell = cnames.length === 0
      ? `<span style="color:var(--text-muted)">—</span>`
      : `<div style="position:relative;display:inline-block" class="cname-cell">
          <div style="font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--accent-cyan)">
            ${esc(cnames[0])}${cnames.length > 1 ? `<span style="color:var(--text-muted);font-size:10px"> +${cnames.length - 1}</span>` : ''}
          </div>
          ${cnames.length > 1 ? `<div class="cname-tooltip" style="display:none;position:absolute;right:0;top:100%;z-index:100;background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:8px 12px;min-width:260px;max-width:380px;box-shadow:0 8px 24px rgba(0,0,0,.5)">
            ${cnames.map(c => `<div style="font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--accent-cyan);word-break:break-all;padding:2px 0">${esc(c)}</div>`).join('')}
          </div>` : ''}
        </div>`;
    return `<tr class="dashboard-table-row" style="border-bottom:1px solid rgba(255,255,255,.04)">
      <td style="padding:11px 14px">${liveIcon}</td>
      <td style="padding:11px 14px;max-width:295px">${hostDisplay}${title}</td>
      <td style="padding:11px 14px;text-align:center">${codeEl}</td>
      <td style="padding:11px 14px"><div style="display:flex;flex-wrap:wrap;gap:4px">${techBadges || '<span style="color:var(--text-muted);font-size:12px">—</span>'}</div></td>
      <td style="padding:11px 14px">${cnameCell}</td>
    </tr>`;
  }).join('');

  container.innerHTML = `
    <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px;align-items:center;justify-content:space-between">
      <div style="display:flex;gap:12px;flex-wrap:wrap">
        <div style="background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.3);border-radius:8px;padding:8px 16px;display:flex;align-items:center;gap:8px">
          <span style="width:8px;height:8px;border-radius:50%;background:#10b981;box-shadow:0 0 6px #10b981;display:inline-block"></span>
          <span style="font-size:14px;font-weight:700;color:#10b981">${liveCount}</span>
          <span style="font-size:12px;color:var(--text-secondary)">Alive</span>
        </div>
        <div style="background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);border-radius:8px;padding:8px 16px;display:flex;align-items:center;gap:8px">
          <span style="width:8px;height:8px;border-radius:50%;background:#ef4444;display:inline-block"></span>
          <span style="font-size:14px;font-weight:700;color:#ef4444">${deadCount}</span>
          <span style="font-size:12px;color:var(--text-secondary)">Dead / Unknown</span>
        </div>
        <div style="background:rgba(6,182,212,.08);border:1px solid rgba(6,182,212,.25);border-radius:8px;padding:8px 16px;display:flex;align-items:center;gap:8px">
          <span style="font-size:14px;font-weight:700;color:var(--accent-cyan)">${assets.length}</span>
          <span style="font-size:12px;color:var(--text-secondary)">Total Hosts</span>
        </div>
      </div>
      <button class="btn btn-ghost" id="copy-all-assets-btn" style="font-size:12px;padding:6px 12px;height:auto">
        📋 Copy All Assets
      </button>
    </div>
    <div style="display:flex;gap:10px;margin-bottom:12px;flex-wrap:wrap">
      <input id="asset-search" type="search" placeholder="🔍 Filter hosts, technologies, titles…"
        style="flex:1;min-width:220px;padding:8px 12px;background:var(--bg-input);border:1px solid var(--border);border-radius:8px;color:var(--text-primary);font-size:12px"/>
      <select id="asset-status-filter" style="padding:8px 12px;background:var(--bg-input);border:1px solid var(--border);border-radius:8px;color:var(--text-primary);font-size:12px">
        <option value="all">All Status</option>
        <option value="live">Alive Only</option>
        <option value="dead">Dead / Unknown</option>
      </select>
      <select id="asset-code-filter" style="padding:8px 12px;background:var(--bg-input);border:1px solid var(--border);border-radius:8px;color:var(--text-primary);font-size:12px">
        <option value="all">Any HTTP Code</option>
        <option value="200">2xx Success</option>
        <option value="301">3xx Redirect</option>
        <option value="403">403 Forbidden</option>
        <option value="404">404 Not Found</option>
        <option value="500">5xx Error</option>
      </select>
      <div style="display:flex;align-items:center;font-size:12px;color:var(--text-muted);padding:0 6px">
        <span id="asset-count-shown">${assets.length}</span>&nbsp;hosts shown
      </div>
    </div>
    <div style="border:1px solid var(--border);border-radius:10px;overflow:hidden">
      <table class="dashboard-table" style="margin:0;table-layout:auto;width:100%">
        <thead style="position:sticky;top:0;z-index:2;background:rgba(2,6,23,.95)">
          <tr>
            <th style="width:90px">STATUS</th>
            <th>HOST / TITLE</th>
            <th style="width:65px;text-align:center">CODE</th>
            <th>TECHNOLOGIES</th>
            <th style="width:155px">CNAMES</th>
          </tr>
        </thead>
        <tbody id="asset-tbody">${renderRows(assets)}</tbody>
      </table>
    </div>`;

  // Live filter wiring
  const searchEl = container.querySelector('#asset-search');
  const statusEl = container.querySelector('#asset-status-filter');
  const codeEl = container.querySelector('#asset-code-filter');
  const countEl = container.querySelector('#asset-count-shown');
  const tbody = container.querySelector('#asset-tbody');
  const applyFilter = () => {
    const q = (searchEl?.value || '').toLowerCase().trim();
    const st = statusEl?.value || 'all';
    const cd = codeEl?.value || 'all';
    const filtered = assets.filter(a => {
      if (st === 'live' && !a.is_live) return false;
      if (st === 'dead' && a.is_live) return false;
      if (cd !== 'all') {
        const code = a.status_code || 0;
        if (cd === '200' && !(code >= 200 && code < 300)) return false;
        if (cd === '301' && !(code >= 300 && code < 400)) return false;
        if (cd === '403' && code !== 403) return false;
        if (cd === '404' && code !== 404) return false;
        if (cd === '500' && !(code >= 500)) return false;
      }
      if (q) {
        const haystack = [a.host, a.title || '', ...(a.technologies || []), ...(a.cnames || [])].join(' ').toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });
    if (countEl) countEl.textContent = String(filtered.length);
    if (tbody) tbody.innerHTML = renderRows(filtered);
  };
  if (searchEl) searchEl.addEventListener('input', applyFilter);
  if (statusEl) statusEl.addEventListener('change', applyFilter);
  if (codeEl) codeEl.addEventListener('change', applyFilter);

  const copyBtn = container.querySelector('#copy-all-assets-btn');
  if (copyBtn) copyBtn.addEventListener('click', async () => {
    try {
      const texts = Array.from(tbody.querySelectorAll('.dashboard-table-row'))
        .map(tr => {
          const aTag = tr.querySelector('td:nth-child(2) a') || tr.querySelector('td:nth-child(2) span');
          return aTag ? aTag.textContent.trim() : '';
        }).filter(Boolean);
      await copyToClipboard(texts.join('\n'));
      showToast('success', 'Copied!', `${texts.length} visible hosts copied to clipboard`);
    } catch (e) {
      showToast('error', 'Copy failed', e.message);
    }
  });
}

/** Toggle module group collapse */
function toggleModuleGroup(btn) {
  const group = btn.closest('.module-results-group');
  const content = group.querySelector('.module-group-content');
  if (content.style.display === 'none') {
    content.style.display = 'block';
    btn.innerHTML = '▼ Collapse';
  } else {
    content.style.display = 'none';
    btn.innerHTML = '▶ Expand';
  }
}

/** Toggle module file result collapse */
function toggleModuleFileResult(header) {
  const content = header.nextElementSibling;
  const arrow = header.querySelector('span:last-child');
  if (content.style.display === 'none') {
    content.style.display = 'block';
    arrow.textContent = '▲';
  } else {
    content.style.display = 'none';
    arrow.textContent = '▼';
  }
}

/** Wire up search and filter controls for scan detail page */
function wireScanDetailFilters(scanId, allFiles) {
  const searchInput = document.getElementById('scan-file-search');
  const moduleFilter = document.getElementById('scan-module-filter');
  const categoryFilter = document.getElementById('scan-category-filter');
  const typeFilter = document.getElementById('scan-type-filter');
  const copyBtn = document.getElementById('copy-all-results-btn');

  if (copyBtn) {
    copyBtn.addEventListener('click', () => copyAllScanResults(scanId));
  }

  function applyFilters() {
    const query = searchInput ? searchInput.value : '';
    const filters = {
      module: moduleFilter ? moduleFilter.value : '',
      category: categoryFilter ? categoryFilter.value : '',
      type: typeFilter ? typeFilter.value : '',
    };

    const filtered = filterScanFiles(allFiles, query, filters);
    renderFilteredFileGrid(filtered, scanId);
  }

  if (searchInput) searchInput.addEventListener('input', applyFilters);
  if (moduleFilter) moduleFilter.addEventListener('change', applyFilters);
  if (categoryFilter) categoryFilter.addEventListener('change', applyFilters);
  if (typeFilter) typeFilter.addEventListener('change', applyFilters);
}

/** Render filtered file grid */
function renderFilteredFileGrid(files, scanId) {
  const container = document.getElementById('filtered-file-grid');
  if (!container) return;

  if (!files.length) {
    container.innerHTML = '<div style="padding:40px;text-align:center;color:var(--text-muted)">No files match your filters</div>';
    return;
  }

  container.innerHTML = files.map(f => {
    const fileType = getFileTypeFromName(f.file_name);
    const icon = getFileTypeIcon(fileType);
    const module = detectModuleFromFileName(f.file_name, f.module);
    const moduleInfo = getModuleDisplayInfo(module);

    return `
      <div class="file-grid-item" data-file-name="${encodeURIComponent(f.file_name)}" onclick="loadScanFilePreview('${scanId}', '${esc(f.file_name)}'))">
        <div class="file-grid-header">
          <div class="file-type-icon file-type-${fileType}">${icon}</div>
          <div class="file-grid-name" title="${esc(f.file_name)}">${esc(f.file_name)}</div>
        </div>
        <div class="file-grid-module" style="color:${moduleInfo.color}">
          ${moduleInfo.icon} ${moduleInfo.name}
        </div>
        <div class="file-grid-meta">
          <div class="file-grid-stat">📏 ${fmtSize(f.size_bytes)}</div>
          ${f.line_count ? `<div class="file-grid-stat">📊 ${f.line_count.toLocaleString()} lines</div>` : ''}
          <div class="file-grid-stat">${f.is_json ? '🟣 JSON' : '📝 Text'}</div>
          <div class="file-grid-stat" style="font-size:10px">📍 ${esc(f.source)}</div>
        </div>
      </div>`;
  }).join('');

  // Update count
  const countEl = document.getElementById('filtered-file-count');
  if (countEl) countEl.textContent = files.length;
}

async function loadScanFilePreview(scanId, fileName, opts = {}) {
  if (!fileName) return;
  const ui = state.scanDetailUI;
  ui.selectedFileName = fileName;
  if (!opts.retainPage) ui.previewPage = 1;
  const body = document.getElementById('scan-preview-body');
  const ptitle = document.getElementById('scan-preview-title');
  if (body) {
    body.innerHTML = '<div class="empty-state"><div class="empty-icon">⏳</div><div class="empty-title">Loading…</div></div>';
  }
  try {
    const q = `file_name=${encodeURIComponent(fileName)}&page=${ui.previewPage}&per_page=${ui.previewPerPage}`;
    const data = await apiFetch(`/api/scans/${encodeURIComponent(scanId)}/results/file?${q}`);
    if (ptitle) ptitle.textContent = data.file_name || fileName || 'Preview';

    if (data.format === 'too_large') {
      body.innerHTML = `<p style="color:var(--text-muted)">${esc(data.error || 'File too large')}</p>
        <p style="font-size:12px">Size: ${(data.size_bytes || 0).toLocaleString()} bytes (max ${(data.max_bytes || 0).toLocaleString()})</p>
        ${data.public_url ? `<p><a class="scan-result-link" target="_blank" href="${esc(data.public_url)}">Download from R2</a></p>` : ''}`;
      return;
    }
    if (data.error && data.format === 'binary') {
      body.innerHTML = `<p style="color:var(--text-muted)">${esc(data.error)}</p>
        ${data.public_url ? `<p><a class="scan-result-link" target="_blank" href="${esc(data.public_url)}">Open in R2</a></p>` : ''}`;
      return;
    }
    if (data.error && data.format === 'json') {
      body.innerHTML = `<pre style="font-size:12px;white-space:pre-wrap">${esc(data.error)}</pre>`;
      return;
    }

    const srcNote = `<div style="font-size:11px;color:var(--text-muted);margin-bottom:8px">Source: <strong>${esc(data.source_used || '')}</strong>
      ${data.public_url ? ` · <a class="scan-result-link" target="_blank" href="${esc(data.public_url)}">Raw URL</a>` : ''}</div>`;

    if (data.format === 'json-array') {
      const total = data.total_items || 0;
      const pp = data.per_page || ui.previewPerPage;
      const pages = Math.max(1, Math.ceil(total / pp) || 1);
      let block = srcNote;
      if (data.array_field) {
        block += `<div style="font-size:12px;margin-bottom:8px">Array field: <code>${esc(data.array_field)}</code></div>`;
      }
      if (data.object_preview && typeof data.object_preview === 'object') {
        block += `<div class="json-viewer">${formatJSONWithHighlighting(data.object_preview)}</div>`;
      }
      block += `<div class="json-viewer">${formatJSONWithHighlighting(data.items || [])}</div>`;
      block += `<div style="margin-top:12px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <button type="button" class="btn btn-ghost" ${ui.previewPage <= 1 ? 'disabled' : ''} id="pv-prev">Prev</button>
        <span style="font-size:12px;color:var(--text-muted)">Items ${((ui.previewPage - 1) * pp) + 1}–${Math.min(ui.previewPage * pp, total)} of ${total}</span>
        <button type="button" class="btn btn-ghost" ${ui.previewPage >= pages ? 'disabled' : ''} id="pv-next">Next</button>
      </div>`;
      body.innerHTML = block;
      document.getElementById('pv-prev')?.addEventListener('click', () => {
        if (ui.previewPage > 1) {
          ui.previewPage -= 1;
          loadScanFilePreview(scanId, fileName, { retainPage: true });
        }
      });
      document.getElementById('pv-next')?.addEventListener('click', () => {
        if (ui.previewPage < pages) {
          ui.previewPage += 1;
          loadScanFilePreview(scanId, fileName, { retainPage: true });
        }
      });
      return;
    }

    if (data.format === 'json-object') {
      body.innerHTML = srcNote + `<div class="json-viewer">${formatJSONWithHighlighting(data.data)}</div>`;
      return;
    }

    if (data.format === 'text') {
      const lines = data.lines || [];
      const total = data.total_lines || 0;
      const pp = data.per_page || ui.previewPerPage;
      const pages = Math.max(1, Math.ceil(total / pp) || 1);
      body.innerHTML = srcNote + `<pre style="font-size:12px;white-space:pre-wrap;font-family:'JetBrains Mono',monospace">${esc(lines.join('\n'))}</pre>
        <div style="margin-top:12px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          <button type="button" class="btn btn-ghost" ${ui.previewPage <= 1 ? 'disabled' : ''} id="tx-prev">Prev</button>
          <span style="font-size:12px;color:var(--text-muted)">Lines page ${ui.previewPage} / ${pages}</span>
          <button type="button" class="btn btn-ghost" ${ui.previewPage >= pages ? 'disabled' : ''} id="tx-next">Next</button>
        </div>`;
      document.getElementById('tx-prev')?.addEventListener('click', () => {
        if (ui.previewPage > 1) {
          ui.previewPage -= 1;
          loadScanFilePreview(scanId, fileName, { retainPage: true });
        }
      });
      document.getElementById('tx-next')?.addEventListener('click', () => {
        if (ui.previewPage < pages) {
          ui.previewPage += 1;
          loadScanFilePreview(scanId, fileName, { retainPage: true });
        }
      });
      return;
    }

    body.innerHTML = srcNote + `<pre style="font-size:12px;white-space:pre-wrap">${esc(JSON.stringify(data, null, 2))}</pre>`;
  } catch (e) {
    if (body) body.innerHTML = `<p style="color:var(--accent-red)">${esc(e.message || String(e))}</p>`;
  }
}

function renderDomainGrid() {
  const container = document.getElementById('domains-container');
  if (!container) return;
  const domains = state.domains?.domains || [];

  if (!domains.length) {
    container.innerHTML = emptyState('🌐', 'No domains tracked', 'Run a scan with autoar domain run -d <domain> to start tracking.');
    return;
  }

  const searchInput = document.getElementById('domain-search');
  const query = searchInput ? searchInput.value.toLowerCase() : '';
  const filtered = query ? domains.filter(d => d.domain.toLowerCase().includes(query)) : domains;

  container.innerHTML = `
    <div class="domain-grid">
      ${filtered.map(d => `
        <div class="domain-card" style="position:relative" onclick="loadDomainSubdomains('${esc(d.domain)}')">
          <button type="button" class="btn btn-ghost" style="position:absolute;top:8px;right:8px;z-index:1;padding:4px 10px;font-size:11px;color:var(--accent-red);border-color:rgba(248,113,113,.35)" onclick='event.stopPropagation();deleteDomainRecord(${JSON.stringify(d.domain)})'>Delete</button>
          <div class="domain-name" style="padding-right:76px">${esc(d.domain)}</div>
          <div class="domain-stats">
            <div class="domain-stat">
              <div class="domain-stat-value" style="color:var(--accent-cyan)">${d.subdomain_count}</div>
              <div class="domain-stat-label">subdomains</div>
            </div>
            <div class="domain-stat">
              <div class="domain-stat-value" style="color:var(--accent-emerald)">${d.live_count}</div>
              <div class="domain-stat-label">live</div>
            </div>
            <div class="domain-stat">
              <div class="domain-stat-value" style="color:var(--text-muted)">${d.subdomain_count - d.live_count}</div>
              <div class="domain-stat-label">dead</div>
            </div>
          </div>
        </div>`).join('')}
    </div>`;
}

function renderSubdomainView(domain) {
  const container = document.getElementById('domains-container');
  if (!container) return;
  const subs = state.subdomains || [];

  const liveCount = subs.filter(s => s.IsLive || s.is_live).length;
  const searchInput = document.getElementById('subdomain-search');
  const q = searchInput ? searchInput.value.toLowerCase() : '';
  const filtered = q ? subs.filter(s => (s.Subdomain || s.subdomain || '').toLowerCase().includes(q)) : subs;
  const allSubNames = subs.map(s => s.Subdomain || s.subdomain || '').filter(Boolean);

  container.innerHTML = `
    <div style="display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:12px;margin-bottom:8px">
      <div onclick="backToDomains()" class="back-btn" style="margin:0">← Back to Domains</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button type="button" id="copy-domain-subs-btn" class="btn btn-ghost" style="font-size:12px;padding:6px 12px">
          📋 Copy All (${allSubNames.length})
        </button>
        <button type="button" class="btn btn-ghost" style="font-size:12px;padding:6px 12px;color:var(--accent-red);border-color:rgba(248,113,113,.35)" onclick='deleteDomainRecord(${JSON.stringify(domain)})'>
          Delete domain…
        </button>
      </div>
    </div>
    <div class="view-header">
      <div class="view-title">${esc(domain)}</div>
      <div class="view-subtitle">${subs.length} subdomains — ${liveCount} live / ${subs.length - liveCount} dead</div>
    </div>
    <div class="filter-bar" style="margin-bottom:16px">
      <input class="search-input" id="subdomain-search" placeholder="Filter subdomains…"
        oninput="renderSubdomainView('${esc(domain)}')" value="${q}">
    </div>
    <div class="card">
      <div class="card-body">
        <table class="data-table">
          <thead><tr>
            <th>Subdomain</th><th>Technology</th><th>CNAME</th><th>Status</th><th>HTTP</th><th>HTTPS</th>
          </tr></thead>
          <tbody>
            ${!filtered.length
      ? `<tr><td colspan="4" style="text-align:center;padding:40px;color:var(--text-muted)">No results</td></tr>`
      : filtered.map(s => {
        const subN = s.Subdomain || s.subdomain || '';
        const live = s.IsLive || s.is_live;
        const httpS = s.HTTPStatus || s.http_status || 0;
        const httpsS = s.HTTPSStatus || s.https_status || 0;

        const techsHtml = s.techs
          ? s.techs.split(',').filter(x => x).slice(0, 4).map(t => `<span style="display:inline-block;padding:2px 6px;margin:2px;background:rgba(255,255,255,0.08);border-radius:4px;font-size:10px;white-space:nowrap">${esc(t.trim())}</span>`).join('')
          : '<span style="color:var(--text-muted)">—</span>';

        const cnamesHtml = s.cnames
          ? `<div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:rgba(180,180,180,0.8);word-break:break-all">${esc(s.cnames)}</div>`
          : '<span style="color:var(--text-muted)">—</span>';

        return `<tr>
                    <td><span style="font-family:'JetBrains Mono',monospace;font-size:12px">${esc(subN)}</span></td>
                    <td><div style="display:flex;flex-wrap:wrap;min-width:140px">${techsHtml}</div></td>
                    <td>${cnamesHtml}</td>
                    <td>${live ? `<span class="badge badge-live">● live</span>` : `<span class="badge badge-dead">dead</span>`}</td>
                    <td><span style="font-size:12px;color:${httpColor(httpS)}">${httpS || '—'}</span></td>
                    <td><span style="font-size:12px;color:${httpColor(httpsS)}">${httpsS || '—'}</span></td>
                  </tr>`;
      }).join('')}
          </tbody>
        </table>
      </div>
    </div>`;

  // Wire copy button
  const copyDomainBtn = document.getElementById('copy-domain-subs-btn');
  if (copyDomainBtn) {
    copyDomainBtn.addEventListener('click', async () => {
      try {
        await copyToClipboard(allSubNames.join('\n'));
        showToast('success', 'Copied!', `${allSubNames.length} subdomains copied to clipboard`);
      } catch (e) {
        showToast('error', 'Copy failed', e.message);
      }
    });
  }
}

function renderSubdomainsPage() {
  const container = document.getElementById('subdomains-container');
  if (!container) return;
  if (state.loading.subdomains) {
    container.innerHTML = emptyState('⏳', 'Loading subdomains…', 'Please wait while paginated results are loaded.');
    return;
  }
  if (state.error.subdomains) {
    container.innerHTML = emptyState('⚠️', 'Failed to load subdomains', esc(state.error.subdomains));
    return;
  }
  const subs = state.allSubdomains || [];
  const total = state.allSubdomainsTotal || 0;
  const page = state.subdomainsPage || 1;
  const limit = state.subdomainsLimit || 30;
  const pages = Math.max(1, Math.ceil(total / limit));

  if (!subs.length && !state.subdomainsSearch) {
    container.innerHTML = emptyState('🔗', 'No subdomains tracked', 'Run a scan with autoar domain run -d <domain> to start tracking.');
    return;
  }

  const codeColor = (code) => {
    if (!code) return 'var(--text-muted)';
    if (code < 300) return '#10b981';
    if (code < 400) return '#f59e0b';
    if (code < 500) return '#ef4444';
    return '#8b5cf6';
  };

  const renderRows = (list) => list.map(s => {
    const isLive = s.is_live;
    const dom = s.domain || '';
    const subN = s.subdomain || '';
    const httpS = s.http_status || 0;
    const httpsS = s.https_status || 0;

    const liveIcon = isLive
      ? `<span style="display:inline-flex;align-items:center;gap:5px;background:rgba(16,185,129,.15);border:1px solid rgba(16,185,129,.4);border-radius:20px;padding:3px 10px;font-size:11px;color:#10b981;white-space:nowrap"><span style="width:6px;height:6px;border-radius:50%;background:#10b981;box-shadow:0 0 5px #10b981;flex-shrink:0"></span>Alive</span>`
      : `<span style="display:inline-flex;align-items:center;gap:5px;background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.3);border-radius:20px;padding:3px 10px;font-size:11px;color:#ef4444;white-space:nowrap"><span style="width:6px;height:6px;border-radius:50%;background:#ef4444;flex-shrink:0"></span>Dead</span>`;

    const httpEl = httpS ? `<code style="font-size:13px;font-weight:700;color:${codeColor(httpS)}">${httpS}</code>` : `<span style="color:var(--text-muted)">—</span>`;
    const httpsEl = httpsS ? `<code style="font-size:13px;font-weight:700;color:${codeColor(httpsS)}">${httpsS}</code>` : `<span style="color:var(--text-muted)">—</span>`;

    const techsHtml = s.techs
      ? s.techs.split(',').filter(x => x).slice(0, 5).map(t => `<span style="display:inline-block;padding:2px 6px;margin:2px;background:rgba(255,255,255,0.08);border-radius:4px;font-size:10px;white-space:nowrap">${esc(t.trim())}</span>`).join('')
      : '<span style="color:var(--text-muted)">—</span>';

    const cnamesHtml = s.cnames
      ? `<div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:rgba(180,180,180,0.8);word-break:break-all">${esc(s.cnames)}</div>`
      : '<span style="color:var(--text-muted)">—</span>';

    return `<tr class="dashboard-table-row" style="border-bottom:1px solid rgba(255,255,255,.04)">
      <td style="padding:11px 14px">${liveIcon}</td>
      <td style="padding:11px 14px"><span style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-secondary)">${esc(dom)}</span></td>
      <td style="padding:11px 14px;max-width:260px"><span style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan);word-break:break-all">${esc(subN)}</span></td>
      <td style="padding:11px 14px"><div style="display:flex;flex-wrap:wrap;min-width:140px">${techsHtml}</div></td>
      <td style="padding:11px 14px;max-width:200px">${cnamesHtml}</td>
      <td style="padding:11px 14px;text-align:center">${httpEl}</td>
      <td style="padding:11px 14px;text-align:center">${httpsEl}</td>
    </tr>`;
  }).join('');

  container.innerHTML = `
    <div style="display:flex;flex-wrap:wrap;align-items:center;justify-content:flex-start;gap:12px;margin-bottom:14px">
      <div style="background:rgba(6,182,212,.08);border:1px solid rgba(6,182,212,.25);border-radius:8px;padding:8px 16px;display:flex;align-items:center;gap:8px">
        <span style="font-size:14px;font-weight:700;color:var(--accent-cyan)">${total}</span>
        <span style="font-size:12px;color:var(--text-secondary)">Total Subdomains Match</span>
      </div>
    </div>

    <div class="card" style="margin-bottom:12px">
      <div class="card-body" style="padding:0;overflow-x:auto">
        <table class="dashboard-table" style="width:100%;border-collapse:collapse;min-width:700px">
          <thead>
            <tr style="border-bottom:1px solid rgba(255,255,255,.05);background:rgba(0,0,0,.15)">
              <th style="padding:12px 14px;text-align:left;font-size:11px;font-weight:800;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em;width:70px">Status</th>
              <th style="padding:12px 14px;text-align:left;font-size:11px;font-weight:800;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em;width:130px">Domain</th>
              <th style="padding:12px 14px;text-align:left;font-size:11px;font-weight:800;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em;width:240px">Subdomain</th>
              <th style="padding:12px 14px;text-align:left;font-size:11px;font-weight:800;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em">Technology</th>
              <th style="padding:12px 14px;text-align:left;font-size:11px;font-weight:800;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em;width:180px">CNAME</th>
              <th style="padding:12px 14px;text-align:center;font-size:11px;font-weight:800;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em;width:60px">HTTP</th>
              <th style="padding:12px 14px;text-align:center;font-size:11px;font-weight:800;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em;width:60px">HTTPS</th>
            </tr>
          </thead>
          <tbody>
            ${!subs.length ? `<tr><td colspan="7" style="text-align:center;padding:40px;color:var(--text-muted)">No subdomains match search</td></tr>` : renderRows(subs)}
          </tbody>
        </table>
      </div>
    </div>
    
    <div style="display:flex;justify-content:center;gap:12px;align-items:center;margin-bottom:24px">
      <button type="button" class="btn btn-ghost" id="subd-prev" ${page <= 1 ? 'disabled' : ''}>← Previous</button>
      <div style="font-size:12px;color:var(--text-muted)">Page ${page} of ${pages}</div>
      <button type="button" class="btn btn-ghost" id="subd-next" ${page >= pages ? 'disabled' : ''}>Next →</button>
    </div>
  `;

  const searchBar = document.getElementById('subdomains-search');
  if (searchBar && document.activeElement !== searchBar) {
    searchBar.value = state.subdomainsSearch || '';
  }

  // Rewire Pagination buttons
  const bp = document.getElementById('subd-prev');
  const bn = document.getElementById('subd-next');
  if (bp && page > 1) {
    bp.onclick = () => loadSubdomains(page - 1, state.subdomainsSearch);
  }
  if (bn && page < pages) {
    bn.onclick = () => loadSubdomains(page + 1, state.subdomainsSearch);
  }

  // Bind real-time input event listeners for advanced filters
  const fStatus = document.getElementById('subdomains-status-filter');
  const fTech = document.getElementById('subdomains-tech-filter');
  const fCname = document.getElementById('subdomains-cname-filter');

  if (fStatus) fStatus.onchange = () => loadSubdomains(1, state.subdomainsSearch);
  if (fTech) fTech.oninput = () => { clearTimeout(state._subdebounce); state._subdebounce = setTimeout(() => loadSubdomains(1, state.subdomainsSearch), 500); };
  if (fCname) fCname.oninput = () => { clearTimeout(state._subdebounce); state._subdebounce = setTimeout(() => loadSubdomains(1, state.subdomainsSearch), 500); };
}

function backToDomains() {
  state.selectedDomain = null;
  const fb = document.getElementById('filter-bar-domains');
  if (fb) fb.style.display = '';
  renderDomainGrid();
}

function syncMonitorUrlPatternVisibility() {
  const strat = document.getElementById('monitor-url-strategy');
  const wrap = document.getElementById('monitor-url-pattern-wrap');
  if (!strat || !wrap) return;
  wrap.style.display = strat.value === 'regex' ? 'block' : 'none';
}

async function quickAddUrlMonitor() {
  const urlEl = document.getElementById('monitor-url-input');
  const stratEl = document.getElementById('monitor-url-strategy');
  const patEl = document.getElementById('monitor-url-pattern');
  const startEl = document.getElementById('monitor-url-autostart');
  if (!urlEl) return;
  const rawUrl = urlEl.value.trim();
  if (!rawUrl) {
    showToast('error', 'URL required', 'Enter a page to watch for changes.');
    return;
  }
  const strategy = stratEl ? stratEl.value : 'hash';
  const pattern = patEl ? patEl.value.trim() : '';
  const start = startEl ? startEl.checked : true;
  try {
    await apiPost('/api/monitor/url-targets', {
      url: rawUrl,
      strategy,
      pattern: strategy === 'regex' ? pattern : '',
      start,
    });
    showToast('success', 'URL monitor added', start ? 'The URL worker is checking in the background.' : 'Saved; enable from CLI with monitor updates start if needed.');
    urlEl.value = '';
    await loadMonitor();
    loadStats();
  } catch (e) {
    showToast('error', 'Could not add URL monitor', e.message);
  }
}

async function quickAddSubdomainMonitor() {
  const dEl = document.getElementById('monitor-sub-domain-input');
  const intEl = document.getElementById('monitor-sub-interval');
  const thEl = document.getElementById('monitor-sub-threads');
  const cnEl = document.getElementById('monitor-sub-checknew');
  const stEl = document.getElementById('monitor-sub-autostart');
  if (!dEl) return;
  const domain = dEl.value.trim().toLowerCase();
  if (!domain) {
    showToast('error', 'Domain required', 'Enter a root domain (e.g. example.com).');
    return;
  }
  const interval_seconds = intEl ? Math.max(60, parseInt(intEl.value, 10) || 3600) : 3600;
  const threads = thEl ? Math.min(500, Math.max(1, parseInt(thEl.value, 10) || 100)) : 100;
  const check_new = cnEl ? cnEl.checked : true;
  const start = stEl ? stEl.checked : true;
  try {
    await apiPost('/api/monitor/subdomain-targets', {
      domain,
      interval_seconds,
      threads,
      check_new,
      start,
    });
    showToast('success', 'Subdomain monitor added', start ? 'The subdomain monitor daemon will run on your interval.' : 'Saved; start from CLI when ready.');
    dEl.value = '';
    await loadMonitor();
    loadStats();
  } catch (e) {
    showToast('error', 'Could not add subdomain monitor', e.message);
  }
}

async function runMonitorAISuggest() {
  const inp = document.getElementById('monitor-ai-domain');
  const btn = document.getElementById('monitor-ai-suggest-btn');
  const meta = document.getElementById('monitor-ai-suggest-meta');
  const box = document.getElementById('monitor-ai-suggest-results');
  if (!inp) return;
  const domain = inp.value.trim();
  if (!domain) {
    showToast('error', 'Domain required', 'e.g. example.com');
    return;
  }
  if (btn) btn.disabled = true;
  if (meta) {
    meta.style.display = 'block';
    meta.textContent = 'Probing common release/changelog paths (may take up to a minute)…';
  }
  if (box) {
    box.style.display = 'none';
    box.innerHTML = '';
  }
  try {
    const res = await apiPost('/api/monitor/suggest-from-domain', { domain });
    state._monitorSuggestCache = res;
    if (meta) {
      const mode = res.ai ? 'AI-ranked' : 'Heuristic ranking (set OPENROUTER_API_KEY on the API server for AI)';
      meta.textContent = `${mode} · ${res.candidates_probed || 0} HTML pages found`;
    }
    renderMonitorAISuggestResults(res);
  } catch (e) {
    if (meta) meta.textContent = '';
    showToast('error', 'Suggest failed', e.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}

function renderMonitorAISuggestResults(res) {
  const box = document.getElementById('monitor-ai-suggest-results');
  if (!box) return;
  const rows = res.suggestions || [];
  if (!rows.length) {
    box.style.display = 'block';
    box.innerHTML = '<div class="empty-state" style="padding:12px"><div class="empty-title">No pages found</div><div style="font-size:12px;color:var(--text-muted)">Try another domain or add a URL manually above.</div></div>';
    return;
  }
  let html = '<table class="data-table"><thead><tr><th style="width:36px"></th><th>URL</th><th>Score</th><th>Strategy</th><th>Reason</th></tr></thead><tbody>';
  rows.forEach((r, i) => {
    const url = r.URL || r.url || '';
    const strat = (r.Strategy || r.strategy || 'hash').toLowerCase();
    const score = r.Score ?? r.score ?? 0;
    const reason = r.Reason || r.reason || '';
    const title = r.Title || r.title || '';
    html += `<tr data-index="${i}">
      <td><input type="checkbox" class="monitor-suggest-cb" data-url="${esc(url)}" data-strategy="${esc(strat)}" checked /></td>
      <td><span style="font-size:12px;color:var(--accent-cyan)">${esc(url)}</span>${title ? `<div style="font-size:11px;color:var(--text-muted)">${esc(title)}</div>` : ''}</td>
      <td>${esc(String(score))}</td>
      <td><span class="scan-type">${esc(strat)}</span></td>
      <td style="font-size:11px;color:var(--text-muted)">${esc(reason).slice(0, 200)}</td>
    </tr>`;
  });
  html += '</tbody></table>';
  html += '<div style="margin-top:12px"><button type="button" class="btn btn-primary" onclick="addSelectedMonitorSuggestions()">Add selected as monitors</button></div>';
  box.innerHTML = html;
  box.style.display = 'block';
}

async function addSelectedMonitorSuggestions() {
  const cbs = Array.from(document.querySelectorAll('.monitor-suggest-cb:checked'));
  if (!cbs.length) {
    showToast('error', 'None selected', 'Check at least one URL.');
    return;
  }
  let ok = 0;
  for (const cb of cbs) {
    const url = cb.getAttribute('data-url');
    const strategy = cb.getAttribute('data-strategy') || 'hash';
    try {
      await apiPost('/api/monitor/url-targets', {
        url,
        strategy,
        pattern: '',
        start: true,
      });
      ok++;
    } catch (e) {
      showToast('error', 'Add failed', `${url}: ${e.message}`);
      return;
    }
  }
  showToast('success', 'Monitors added', `${ok} URL monitor(s) started.`);
  const resBox = document.getElementById('monitor-ai-suggest-results');
  if (resBox) resBox.style.display = 'none';
  const meta = document.getElementById('monitor-ai-suggest-meta');
  if (meta) meta.style.display = 'none';
  await loadMonitor();
  loadStats();
}

async function pauseUrlMonitor(id) {
  try {
    await apiPost(`/api/monitor/url-targets/${encodeURIComponent(id)}/pause`, {});
    showToast('success', 'Monitor paused', 'URL checks are stopped for this target.');
    await loadMonitor();
    loadStats();
  } catch (e) {
    showToast('error', 'Pause failed', e.message);
  }
}

async function resumeUrlMonitor(id) {
  try {
    await apiPost(`/api/monitor/url-targets/${encodeURIComponent(id)}/resume`, {});
    showToast('success', 'Monitor resumed', 'The URL worker will pick this target up.');
    await loadMonitor();
    loadStats();
  } catch (e) {
    showToast('error', 'Resume failed', e.message);
  }
}

async function deleteUrlMonitor(id) {
  if (!confirm('Remove this URL monitor? It will be deleted from the database.')) return;
  try {
    await apiDelete(`/api/monitor/url-targets/${encodeURIComponent(id)}`);
    showToast('success', 'Monitor removed', '');
    await loadMonitor();
    loadStats();
  } catch (e) {
    showToast('error', 'Delete failed', e.message);
  }
}

async function pauseSubdomainMonitor(id) {
  try {
    await apiPost(`/api/monitor/subdomain-targets/${encodeURIComponent(id)}/pause`, {});
    showToast('success', 'Subdomain monitor paused', '');
    await loadMonitor();
    loadStats();
  } catch (e) {
    showToast('error', 'Pause failed', e.message);
  }
}

async function resumeSubdomainMonitor(id) {
  try {
    await apiPost(`/api/monitor/subdomain-targets/${encodeURIComponent(id)}/resume`, {});
    showToast('success', 'Subdomain monitor resumed', '');
    await loadMonitor();
    loadStats();
  } catch (e) {
    showToast('error', 'Resume failed', e.message);
  }
}

async function deleteSubdomainMonitor(id) {
  if (!confirm('Remove this subdomain monitor?')) return;
  try {
    await apiDelete(`/api/monitor/subdomain-targets/${encodeURIComponent(id)}`);
    showToast('success', 'Monitor removed', '');
    await loadMonitor();
    loadStats();
  } catch (e) {
    showToast('error', 'Delete failed', e.message);
  }
}

async function clearMonitorChangeHistory() {
  if (!confirm('Clear all monitor change history? URL monitor “Changes” counters reset to 0. This cannot be undone.')) return;
  try {
    await apiDelete('/api/monitor/changes');
    showToast('success', 'History cleared', '');
    await loadMonitor();
    loadStats();
  } catch (e) {
    showToast('error', 'Clear failed', e.message);
  }
}

/** Short preview for monitor_changes.detail JSON (hash vs regex). */
function formatMonitorDetailPreview(detail) {
  if (!detail || typeof detail !== 'string') return '';
  try {
    const o = JSON.parse(detail);
    if (o.strategy === 'regex') {
      const om = String(o.old_match ?? '');
      const nm = String(o.new_match ?? '');
      return `regex: "${om.slice(0, 60)}${om.length > 60 ? '…' : ''}" → "${nm.slice(0, 60)}${nm.length > 60 ? '…' : ''}"`;
    }
    if (o.old_hash && o.new_hash) {
      return `hash: ${String(o.old_hash).slice(0, 10)}… → ${String(o.new_hash).slice(0, 10)}…`;
    }
  } catch (e) { /* use raw */ }
  return detail;
}

function renderMonitor() {
  const urlContainer = document.getElementById('monitor-url-container');
  const subContainer = document.getElementById('monitor-sub-container');
  const feedContainer = document.getElementById('monitor-changes-feed');
  if (!urlContainer || !subContainer || !feedContainer) return;

  // URL targets table
  const targets = state.monitorTargets;
  if (!targets.length) {
    urlContainer.innerHTML = emptyState('🔗', 'No URL monitors yet', 'Use Quick launch above, or CLI: autoar monitor updates add -u <url>');
  } else {
    urlContainer.innerHTML = `<table class="data-table">
      <thead><tr><th>URL</th><th>Strategy</th><th>Status</th><th>Changes</th><th>Last Run</th><th>Actions</th></tr></thead>
      <tbody>${targets.map((t) => {
      const id = t.ID ?? t.id;
      const running = !!(t.IsRunning || t.is_running);
      const pauseResume = running
        ? `<button type="button" class="btn btn-ghost" style="font-size:11px;padding:4px 10px" onclick="pauseUrlMonitor(${id})">Pause</button>`
        : `<button type="button" class="btn btn-ghost" style="font-size:11px;padding:4px 10px" onclick="resumeUrlMonitor(${id})">Resume</button>`;
      return `<tr>
        <td><span style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan)">${esc(t.URL || t.url || '')}</span></td>
        <td><span class="scan-type">${esc(t.Strategy || t.strategy || 'hash')}</span></td>
        <td>${running
          ? `<span class="badge badge-monitor-on">● running</span>`
          : `<span class="badge badge-monitor-off">stopped</span>`}</td>
        <td style="font-size:12px;color:var(--text-muted)">${t.ChangeCount || t.change_count || 0}</td>
        <td style="font-size:11px;color:var(--text-muted)">${fmtDate(t.LastRunAt || t.last_run_at)}</td>
        <td style="white-space:nowrap">${pauseResume}
          <button type="button" class="btn btn-ghost" style="font-size:11px;padding:4px 10px;margin-left:4px;color:var(--danger,#f87171)" onclick="deleteUrlMonitor(${id})">Delete</button></td>
      </tr>`;
    }).join('')}</tbody>
    </table>`;
  }

  // Subdomain monitor targets
  const subTargets = state.subMonitorTargets;
  if (!subTargets.length) {
    subContainer.innerHTML = emptyState('🌐', 'No subdomain monitors yet', 'Use Quick launch above, or CLI: autoar monitor subdomains manage add -d <domain>');
  } else {
    subContainer.innerHTML = `<table class="data-table">
      <thead><tr><th>Domain</th><th>Interval</th><th>Status</th><th>Last Run</th><th>Actions</th></tr></thead>
      <tbody>${subTargets.map((t) => {
      const id = t.ID ?? t.id;
      const running = !!(t.IsRunning || t.is_running);
      const pauseResume = running
        ? `<button type="button" class="btn btn-ghost" style="font-size:11px;padding:4px 10px" onclick="pauseSubdomainMonitor(${id})">Pause</button>`
        : `<button type="button" class="btn btn-ghost" style="font-size:11px;padding:4px 10px" onclick="resumeSubdomainMonitor(${id})">Resume</button>`;
      return `<tr>
        <td><span style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-purple)">${esc(t.Domain || t.domain || '')}</span></td>
        <td style="font-size:12px;color:var(--text-muted)">${fmtInterval(t.Interval || t.interval)}</td>
        <td>${running
          ? `<span class="badge badge-monitor-on">● running</span>`
          : `<span class="badge badge-monitor-off">stopped</span>`}</td>
        <td style="font-size:11px;color:var(--text-muted)">${fmtDate(t.LastRunAt || t.last_run_at)}</td>
        <td style="white-space:nowrap">${pauseResume}
          <button type="button" class="btn btn-ghost" style="font-size:11px;padding:4px 10px;margin-left:4px;color:var(--danger,#f87171)" onclick="deleteSubdomainMonitor(${id})">Delete</button></td>
      </tr>`;
    }).join('')}</tbody>
    </table>`;
  }

  // Change feed
  const changes = state.monitorChanges;
  if (!changes.length) {
    feedContainer.innerHTML = emptyState('📭', 'No changes recorded', 'Changes will appear here once monitors run.');
  } else {
    feedContainer.innerHTML = changes.map(c => changeItemHtml(c)).join('');
  }
}

function changeItemHtml(c) {
  const ctype = c.ChangeType || c.change_type || '';
  const domain = c.Domain || c.domain || '';
  const detail = c.Detail || c.detail || '';
  const at = c.DetectedAt || c.detected_at || '';
  const detailPreview = formatMonitorDetailPreview(detail);
  const iconMap = {
    new_subdomain: '🆕', became_live: '🟢', became_dead: '💀',
    content_changed: '📝', status_changed: '🔄',
  };
  return `<div class="change-item">
    <div class="change-dot ${ctype}"></div>
    <div class="change-body">
      <div class="change-title">${iconMap[ctype] || '📌'} ${esc(humanChangeType(ctype))}</div>
      <div class="change-detail">${esc(domain)}${detailPreview ? ` — ${esc(detailPreview).slice(0, 200)}` : ''}</div>
    </div>
    <div class="change-time">${timeAgo(at)}</div>
  </div>`;
}

function renderR2() {
  const treeEl = document.getElementById('r2-tree-list');
  const filesEl = document.getElementById('r2-files-list');
  const pathEl = document.getElementById('r2-path');
  if (!treeEl || !filesEl) return;

  const { prefix, dirs, files } = state.r2;
  if (pathEl) pathEl.textContent = '/' + (prefix || '');

  // Tree — root always + current dirs
  let treeHtml = `<div class="r2-tree-item ${!prefix ? 'active' : ''}">
    <span class="r2-tree-nav" onclick="loadR2('')">📦</span>
    <span class="r2-tree-nav r2-tree-label" onclick="loadR2('')">root</span>
  </div>`;
  (dirs || []).forEach(d => {
    const name = d.replace(prefix, '').replace(/\/$/, '');
    treeHtml += `<div class="r2-tree-item" data-r2-prefix="${escAttr(d)}">
      <span class="r2-tree-nav" onclick='loadR2(${JSON.stringify(d)})'>📁</span>
      <span class="r2-tree-nav r2-tree-label" onclick='loadR2(${JSON.stringify(d)})'>${esc(name || d)}</span>
      <button type="button" class="r2-row-action" title="Delete folder" aria-label="Delete folder" onclick='event.stopPropagation();r2DeletePrefixInteractive(${JSON.stringify(d)})'>🗑</button>
    </div>`;
  });
  treeEl.innerHTML = treeHtml;

  // Files list
  if (!files.length && !dirs.length) {
    filesEl.innerHTML = emptyState('📂', 'Empty folder', 'No files in this prefix.');
    r2UpdateDeleteSelectedVisibility();
    return;
  }

  let html = '';
  // Show parent nav if in a sub-prefix
  if (prefix) {
    const parent = prefix.split('/').slice(0, -2).join('/');
    html += `<div class="r2-file-row" style="cursor:pointer" onclick='loadR2(${JSON.stringify(parent)})'>
      <span class="r2-file-icon">⬆️</span>
      <span class="r2-file-name">.. (go up)</span>
    </div>`;
  }
  // Sub-dirs as rows (navigate on name/icon; delete / checkbox separate)
  (dirs || []).forEach(d => {
    const name = d.replace(prefix, '').replace(/\/$/, '');
    html += `<div class="r2-file-row r2-file-row-dir" data-r2-prefix="${escAttr(d)}">
      <input type="checkbox" class="r2-row-cb" data-r2-prefix="${escAttr(d)}" onclick="event.stopPropagation()" title="Select for bulk delete" />
      <span class="r2-file-icon r2-file-row-nav" onclick='loadR2(${JSON.stringify(d)})'>📁</span>
      <span class="r2-file-name r2-file-row-nav" onclick='loadR2(${JSON.stringify(d)})'>${esc(name || d)}/</span>
      <span class="r2-file-size">—</span>
      <span class="r2-file-date">—</span>
      <button type="button" class="r2-row-action" title="Delete folder" aria-label="Delete folder" onclick='event.stopPropagation();r2DeletePrefixInteractive(${JSON.stringify(d)})'>🗑</button>
    </div>`;
  });
  // Files
  (files || []).forEach(f => {
    const name = f.key.replace(prefix, '');
    const ext = name.split('.').pop().toLowerCase();
    html += `<div class="r2-file-row" data-file-name="${escAttr(f.key)}">
      <input type="checkbox" class="r2-row-cb" data-file-name="${escAttr(f.key)}" onclick="event.stopPropagation()" title="Select for bulk delete" />
      <span class="r2-file-icon">${fileIcon(ext)}</span>
      <span class="r2-file-name" title="${esc(f.key)}">${esc(name)}</span>
      <span class="r2-file-size">${fmtSize(f.size)}</span>
      <span class="r2-file-date">${fmtDate(f.last_modified)}</span>
      <button type="button" class="r2-row-action" title="Delete file" aria-label="Delete file" onclick='event.stopPropagation();r2DeleteKeyInteractive(${JSON.stringify(f.key)})'>🗑</button>
      <a href="${esc(f.public_url)}" target="_blank" class="r2-download-btn" title="Download" onclick="event.stopPropagation()">⬇</a>
    </div>`;
  });
  filesEl.innerHTML = html;
  r2UpdateDeleteSelectedVisibility();
}

function renderSettings() {
  const cfg = state.config;
  const el = document.getElementById('settings-container');
  if (!el || !cfg) return;

  const row = (k, v, cls) => `<div class="setting-row">
    <span class="setting-key">${k}</span>
    <span class="setting-val ${cls || ''}">${esc(String(v ?? '—'))}</span>
  </div>`;

  el.innerHTML = `<div class="settings-grid">
    <div class="setting-card">
      <div class="setting-card-header">🔧 AutoAR</div>
      ${row('Version', cfg.version)}
      ${row('Mode', cfg.mode)}
      ${row('DB Type', cfg.db_type)}
    </div>
    <div class="setting-card">
      <div class="setting-card-header">🔐 Authentication</div>
      ${row('Provider', 'Local (username + password)', 'ok')}
      ${row('Status', cfg.auth_enabled ? 'Enabled' : 'Disabled (open access)', cfg.auth_enabled ? 'ok' : 'warn')}
    </div>
    <div class="setting-card">
      <div class="setting-card-header">🤖 AI Configuration</div>
      <div class="setting-row" style="flex-direction:column;align-items:flex-start;gap:8px">
        <span class="setting-key" style="margin-bottom:4px">OpenRouter API Key <span style="font-size:10px;color:var(--text-muted)">(synced with server)</span></span>
        <div style="display:flex;width:100%;gap:10px">
          <input type="password" id="or-key-input"
            value="${esc(localStorage.getItem('autoar_or_key') || '')}"
            placeholder="sk-or-v1-…"
            class="form-control" style="flex:1;font-family:var(--font-mono);font-size:12px">
          <button class="btn btn-primary" onclick="saveOpenRouterKey()">Save</button>
        </div>
        <span style="font-size:11px;color:var(--text-muted)">Used for <strong>Validate with AI</strong> and <strong>Report with AI</strong>. Get a key at <a href="https://openrouter.ai/keys" target="_blank" style="color:var(--accent-cyan)">openrouter.ai/keys</a>.</span>
      </div>
      <div class="setting-row" style="flex-direction:column;align-items:flex-start;gap:8px;margin-top:16px;border-top:1px solid var(--border);padding-top:16px">
        <span class="setting-key" style="margin-bottom:4px">Gemini API Key <span style="font-size:10px;color:var(--text-muted)">(optional fallback)</span></span>
        <div style="display:flex;width:100%;gap:10px">
          <input type="password" id="gemini-key-input"
            value="${esc(localStorage.getItem('autoar_gemini_key') || '')}"
            placeholder="AIza…"
            class="form-control" style="flex:1;font-family:var(--font-mono);font-size:12px">
          <button class="btn btn-primary" onclick="saveGeminiKey()">Save</button>
        </div>
      </div>
    </div>
    <div class="setting-card">
      <div class="setting-card-header">🔔 Webhooks</div>
      <div class="setting-row" style="flex-direction:column;align-items:flex-start;gap:8px">
        <span class="setting-key" style="margin-bottom:4px;">Monitor Webhook URL (Discord / Generic)</span>
        <div style="display:flex;width:100%;gap:10px;">
          <input type="text" id="monitor-webhook-input" value="${esc(cfg.monitor_webhook || '')}" placeholder="https://discord.com/api/webhooks/..." class="form-control" style="flex:1;">
          <button class="btn btn-primary" onclick="saveWebhookSettings()">Save</button>
        </div>
      </div>
    </div>
    <div class="setting-card">
      <div class="setting-card-header">☁️ Cloudflare R2</div>
      ${row('Enabled', cfg.r2_enabled ? 'Yes' : 'No', cfg.r2_enabled ? 'ok' : 'warn')}
      ${row('Bucket', cfg.r2_bucket || '—', cfg.r2_bucket ? 'ok' : 'warn')}
      ${row('Public URL', cfg.r2_public_url
    ? cfg.r2_public_url.slice(0, 35) + (cfg.r2_public_url.length > 35 ? '…' : '')
    : '—', cfg.r2_public_url ? 'ok' : 'warn')}
    </div>
    <div class="setting-card">
      <div class="setting-card-header">📡 API Endpoints</div>
      ${row('Dashboard', window.location.origin + '/ui')}
      ${row('API Base', window.location.origin + '/api')}
      ${row('Health', window.location.origin + '/health')}
      ${row('Scan', window.location.origin + '/scan/*')}
    </div>
  </div>`;
}

window.saveOpenRouterKey = async function () {
  const input = document.getElementById('or-key-input');
  if (!input) return;
  const key = input.value.trim();
  const btn = document.querySelector('button[onclick="saveOpenRouterKey()"]');
  if (btn) btn.innerHTML = '<span class="loading-spinner"></span>';
  try {
    const headers = await buildAuthHeaders({ 'Content-Type': 'application/json' });
    const res = await fetch(`${API}/api/settings`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ openrouter_key: key })
    });
    if (!res.ok) throw new Error('Failed to update server config');
    
    if (key) localStorage.setItem('autoar_or_key', key);
    else localStorage.removeItem('autoar_or_key');
    
    showToast('success', 'Saved!', 'OpenRouter key updated on server.');
  } catch (e) {
    showToast('error', 'Error', e.message);
  }
  if (btn) btn.textContent = 'Save';
};

window.saveGeminiKey = async function () {
  const input = document.getElementById('gemini-key-input');
  if (!input) return;
  const key = input.value.trim();
  const btn = document.querySelector('button[onclick="saveGeminiKey()"]');
  if (btn) btn.innerHTML = '<span class="loading-spinner"></span>';
  try {
    const headers = await buildAuthHeaders({ 'Content-Type': 'application/json' });
    const res = await fetch(`${API}/api/settings`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ gemini_key: key })
    });
    if (!res.ok) throw new Error('Failed to update server config');
    
    if (key) localStorage.setItem('autoar_gemini_key', key);
    else localStorage.removeItem('autoar_gemini_key');
    
    showToast('success', 'Saved!', 'Gemini key updated on server.');
  } catch (e) {
    showToast('error', 'Error', e.message);
  }
  if (btn) btn.textContent = 'Save';
};

window.saveWebhookSettings = async function () {
  const url = document.getElementById('monitor-webhook-input').value.trim();
  const btn = document.querySelector('button[onclick="saveWebhookSettings()"]');
  if (btn) btn.innerHTML = '<span class="loading-spinner"></span>';
  try {
    const headers = await buildAuthHeaders({ 'Content-Type': 'application/json' });
    const res = await fetch(`${API}/api/settings`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ monitor_webhook: url })
    });
    if (!res.ok) throw new Error('Failed to update config');
    showToast('success', 'Saved!', 'Webhook settings updated successfully.');
    // Keep it in state so it doesn't revert visually
    if (state.config) state.config.monitor_webhook = url;
  } catch (e) {
    showToast('error', 'Error', e.message);
  }
  if (btn) btn.textContent = 'Save';
};

function updateStatusDot() {
  const dot = document.getElementById('status-dot');
  const text = document.getElementById('status-text');
  if (!dot || !text) return;
  if (state.config) {
    dot.className = 'status-dot';
    text.textContent = 'Connected';
  } else {
    dot.className = 'status-dot error';
    text.textContent = 'Offline';
  }
}

// ── Scan Launcher ─────────────────────────────────────────────────────────────

function launchTypeSpec() {
  const sel = document.getElementById('launch-type');
  return sel ? LAUNCH_SCAN_TYPES[sel.value] : null;
}

function parseTargets(raw) {
  return raw
    .split(/\r?\n|,/g)
    .map(s => s.trim())
    .filter(Boolean);
}

function inferDomainFromSubdomain(subdomain) {
  const cleaned = String(subdomain || '').trim().replace(/^https?:\/\//i, '').split('/')[0];
  const parts = cleaned.split('.').filter(Boolean);
  if (parts.length >= 2) return `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  return cleaned;
}

function buildScanRequestBodies(spec, mode, rawInput) {
  const listMode = mode.endsWith('_list');
  const items = listMode ? parseTargets(rawInput) : [rawInput.trim()].filter(Boolean);
  const bodies = [];
  for (const item of items) {
    const body = { ...(spec.extra || {}) };
    switch (mode) {
      case 'domain':
      case 'domain_list':
        body.domain = item;
        break;
      case 'subdomain':
      case 'subdomain_list':
        if (spec.path === 'subdomain_run') {
          body.subdomain = item;
        } else if (spec.path === 'js') {
          body.domain = inferDomainFromSubdomain(item);
          body.subdomain = item;
        } else if (spec.path === 'nuclei') {
          body.domain = inferDomainFromSubdomain(item);
        } else {
          body.subdomain = item;
        }
        break;
      case 'url':
      case 'url_list':
        if (spec.path === 'nuclei') body.url = item;
        else body.target = item;
        break;
      case 'target':
      case 'target_list':
        body.target = item;
        break;
      case 'repo':
      case 'repo_list':
        body.repo = item;
        break;
      case 'bucket':
      case 'bucket_list':
        body.bucket = item;
        break;
      case 'token':
        body.token = item;
        break;
      case 'file_path':
        body.file_path = item;
        break;
      case 'package_id':
        body.package_id = item;
        break;
      case 'upload':
        body.file_path = item;
        break;
      default:
        body.domain = item;
        break;
    }
    bodies.push(body);
  }
  return bodies;
}

function syncLaunchPlaceholder(rebuildModes = false) {
  const modeSel = document.getElementById('launch-target-mode');
  const input = document.getElementById('launch-target');
  const listInput = document.getElementById('launch-target-list');
  const help = document.getElementById('launch-help');
  const spec = launchTypeSpec();
  if (!modeSel || !input || !listInput || !help || !spec) return;

  if (rebuildModes) {
    modeSel.innerHTML = (spec.modes || []).map(m => `<option value="${esc(m)}">${esc(LAUNCH_MODE_LABELS[m] || m)}</option>`).join('');
  }
  if (!modeSel.value || !(spec.modes || []).includes(modeSel.value)) {
    modeSel.value = (spec.modes && spec.modes[0]) || 'domain';
  }

  const mode = modeSel.value;
  const isList = mode.endsWith('_list');
  const ph = (spec.placeholders && spec.placeholders[mode]) || 'Target';
  input.placeholder = ph;
  listInput.placeholder = ph;

  input.style.display = (isList || mode === 'upload') ? 'none' : '';
  listInput.style.display = isList ? '' : 'none';
  help.textContent = isList
    ? 'Bulk mode: one target per line (comma also supported).'
    : `Single target mode: ${LAUNCH_MODE_LABELS[mode] || mode}.`;
  // Special UI for upload mode
  const uploadWrapperId = 'launch-upload-wrapper';
  let wrapper = document.getElementById(uploadWrapperId);
  if (mode === 'upload') {
    input.style.display = 'none';
    if (!wrapper) {
      input.insertAdjacentHTML('afterend', `
        <div id="${uploadWrapperId}" style="display:flex;gap:8px;align-items:center;flex:1">
          <input type="text" id="launch-upload-path" class="input" placeholder="No file uploaded" readonly style="flex:1">
          <button type="button" class="btn btn-ghost" onclick="document.getElementById('launch-file-input').click()">📁 Choose</button>
          <input type="file" id="launch-file-input" style="display:none" onchange="handleLaunchFileUpload(this)">
        </div>
      `);
    } else {
      wrapper.style.display = 'flex';
    }
  } else {
    if (wrapper) wrapper.style.display = 'none';
  }

  renderLaunchFlags();
  updateLaunchPreview();
}

function renderLaunchFlags() {
  const essential = document.getElementById('launch-flags-essential');
  const advanced = document.getElementById('launch-flags-advanced');
  const sel = document.getElementById('launch-type');
  if (!essential || !advanced || !sel) return;
  const defs = SCAN_FLAG_DEFS[sel.value] || [];
  essential.innerHTML = '';
  advanced.innerHTML = '';
  if (!defs.length) {
    essential.innerHTML = `<div style="font-size:12px;color:var(--text-muted)">No extra flags for this scan type.</div>`;
    advanced.innerHTML = `<div style="font-size:12px;color:var(--text-muted)">No advanced flags.</div>`;
    return;
  }
  defs.forEach(d => {
    const target = d.advanced ? advanced : essential;
    const id = `flag-${d.key}`;
    let field = '';
    if (d.type === 'bool') {
      field = `<input id="${id}" data-flag-key="${esc(d.key)}" data-flag-type="bool" type="checkbox" ${d.key === 'dns_type' ? '' : ''}>`;
    } else if (d.type === 'select') {
      field = `<select id="${id}" data-flag-key="${esc(d.key)}" data-flag-type="select">${(d.options || []).map(v => `<option value="${esc(v)}">${esc(v)}</option>`).join('')}</select>`;
    } else if (d.type === 'number') {
      field = `<input id="${id}" data-flag-key="${esc(d.key)}" data-flag-type="number" type="number" ${d.min != null ? `min="${d.min}"` : ''}>`;
    } else {
      field = `<input id="${id}" data-flag-key="${esc(d.key)}" data-flag-type="text" type="text">`;
    }
    target.insertAdjacentHTML('beforeend', `<div class="launch-flag-item"><label for="${id}">${esc(d.label)}</label>${field}</div>`);
  });

  // Apply defaults for DNS flavor convenience
  if (sel.value === 'dns_dangling') {
    const dnsType = document.getElementById('flag-dns_type');
    if (dnsType) dnsType.value = 'dangling-ip';
  } else if (sel.value === 'dns') {
    const dnsType = document.getElementById('flag-dns_type');
    if (dnsType) dnsType.value = 'takeover';
  }
}

function collectFlagValues() {
  const out = {};
  document.querySelectorAll('[data-flag-key]').forEach(el => {
    const key = el.getAttribute('data-flag-key');
    const typ = el.getAttribute('data-flag-type');
    if (!key) return;
    if (typ === 'bool') {
      if (el.checked) out[key] = true;
      return;
    }
    const val = (el.value || '').trim();
    if (!val) return;
    if (typ === 'number') {
      const n = Number(val);
      if (!Number.isNaN(n)) out[key] = n;
      return;
    }
    if (key === 'extensions' || key === 'cves') {
      out[key] = val.split(',').map(v => v.trim()).filter(Boolean);
      return;
    }
    out[key] = val;
  });
  return out;
}

function updateLaunchPreview() {
  const pre = document.getElementById('launch-preview');
  if (!pre) return;
  const key = document.getElementById('launch-type')?.value;
  const mode = document.getElementById('launch-target-mode')?.value;
  const spec = key ? LAUNCH_SCAN_TYPES[key] : null;
  const singleInput = document.getElementById('launch-target');
  const listInput = document.getElementById('launch-target-list');
  if (!spec) {
    pre.textContent = '{}';
    return;
  }
  const raw = (mode && mode.endsWith('_list') ? listInput?.value : singleInput?.value || '').trim();
  const bodies = raw ? buildScanRequestBodies(spec, mode, raw) : [];
  const flags = collectFlagValues();
  const previewBodies = bodies.slice(0, 2).map(b => ({ ...b, ...flags }));
  pre.textContent = JSON.stringify({
    endpoint: `/scan/${spec.path}`,
    count: bodies.length || 1,
    sample_payloads: previewBodies.length ? previewBodies : [{ ...flags }],
  }, null, 2);
}

async function triggerScan() {
  const key = document.getElementById('launch-type').value;
  const mode = document.getElementById('launch-target-mode').value;
  const singleInput = document.getElementById('launch-target');
  const listInput = document.getElementById('launch-target-list');
  const spec = LAUNCH_SCAN_TYPES[key];
  const raw = (mode && mode.endsWith('_list') ? listInput.value : singleInput.value).trim();
  if (!spec) {
    showToast('error', 'Unknown scan type', 'Pick a scan from the list.');
    return;
  }
  if (!raw) {
    showToast('error', 'Input required', 'Enter the target for this scan type.');
    return;
  }

  const btn = document.getElementById('launch-btn');
  btn.disabled = true;

  const bodies = buildScanRequestBodies(spec, mode, raw);
  if (!bodies.length) {
    showToast('error', 'Input required', 'No valid targets parsed from input.');
    btn.disabled = false;
    return;
  }

  try {
    const scanIds = [];
    const failures = [];
    const flags = collectFlagValues();
    for (const body of bodies) {
      try {
        const result = await apiPost(`/scan/${spec.path}`, { ...body, ...flags });
        if (result && result.scan_id) scanIds.push(result.scan_id);
      } catch (e) {
        failures.push(e.message || 'failed');
      }
    }
    if (scanIds.length) {
      showToast('success', 'Scan started', `${scanIds.length} started${scanIds.length === 1 ? ` (ID: ${scanIds[0]})` : ''}`);
    }
    if (failures.length) {
      showToast('error', 'Some launches failed', `${failures.length} failed`);
    }
    singleInput.value = '';
    listInput.value = '';
    loadStats();
    loadScans();
  } catch (e) {
    showToast('error', 'Failed to start scan', e.message);
  } finally {
    btn.disabled = false;
  }
}

async function handleLaunchFileUpload(inputEl) {
  const file = inputEl.files[0];
  if (!file) return;

  const pathDisplay = document.getElementById('launch-upload-path');
  const mainInput = document.getElementById('launch-target');
  
  if (pathDisplay) pathDisplay.value = `Uploading ${file.name}...`;

  const formData = new FormData();
  formData.append('file', file);

  try {
    const resp = await fetch('/api/upload', {
      method: 'POST',
      body: formData,
      // Note: Don't set Content-Type header when using FormData, 
      // the browser will set it with the correct boundary.
      headers: state._authAccessToken ? { 'Authorization': `Bearer ${state._authAccessToken}` } : {}
    });

    if (!resp.ok) {
      const err = await resp.json();
      throw new Error(err.error || `Upload failed with status ${resp.status}`);
    }

    const data = await resp.json();
    if (pathDisplay) pathDisplay.value = file.name;
    if (mainInput) {
      mainInput.value = data.file_path;
      updateLaunchPreview();
    }
    showToast('success', 'Upload', `File uploaded to ${data.file_path}`);
  } catch (e) {
    if (pathDisplay) pathDisplay.value = 'Upload failed';
    showToast('error', 'Upload failed', e.message);
  }
}

// ── Utilities ─────────────────────────────────────────────────────────────────

function esc(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Escape for HTML attribute values (e.g. data-r2-prefix). */
function escAttr(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;');
}

function fmtDate(d) {
  if (!d) return '—';
  try {
    const dt = new Date(d);
    if (isNaN(dt)) return '—';
    return dt.toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  } catch { return '—'; }
}

function timeAgo(d) {
  if (!d) return '—';
  try {
    const diff = Date.now() - new Date(d).getTime();
    if (isNaN(diff)) return '—';
    if (diff < 60000) return 'just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    return `${Math.floor(diff / 86400000)}d ago`;
  } catch { return '—'; }
}

function elapsedStr(start) {
  try {
    const diff = Date.now() - new Date(start).getTime();
    if (isNaN(diff)) return '';
    const h = Math.floor(diff / 3600000);
    const m = Math.floor((diff % 3600000) / 60000);
    const s = Math.floor((diff % 60000) / 1000);
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  } catch { return ''; }
}

function elapsedBetween(start, end) {
  try {
    const diff = new Date(end).getTime() - new Date(start).getTime();
    if (isNaN(diff) || diff < 0) return '—';
    const h = Math.floor(diff / 3600000);
    const m = Math.floor((diff % 3600000) / 60000);
    const s = Math.floor((diff % 60000) / 1000);
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  } catch { return '—'; }
}

function fmtSize(bytes) {
  if (!bytes) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return (bytes / Math.pow(k, i)).toFixed(i > 0 ? 1 : 0) + ' ' + sizes[i];
}

function fmtInterval(secs) {
  if (!secs) return '—';
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  return `${Math.floor(secs / 3600)}h`;
}

function statusBadge(status) {
  const map = {
    running: 'badge-running',
    starting: 'badge-starting',
    paused: 'badge-starting',
    done: 'badge-done',
    completed: 'badge-done',
    failed: 'badge-failed',
    error: 'badge-failed',
    cancelled: 'badge-starting',
  };
  const cls = map[status] || 'badge-done';
  return `<span class="badge ${cls}">${esc(status)}</span>`;
}

function httpColor(code) {
  if (!code) return 'var(--text-muted)';
  if (code >= 200 && code < 300) return 'var(--accent-emerald)';
  if (code >= 300 && code < 400) return 'var(--accent-cyan)';
  if (code >= 400 && code < 500) return 'var(--accent-amber)';
  if (code >= 500) return 'var(--accent-red)';
  return 'var(--text-muted)';
}

function fileIcon(ext) {
  const map = {
    txt: '📄', log: '📋', json: '📊', zip: '📦', gz: '📦', html: '🌐',
    pdf: '📑', png: '🖼', jpg: '🖼', jpeg: '🖼', apk: '📱', ipa: '📱',
    db: '🗄', sql: '🗄', md: '📝'
  };
  return map[ext] || '📄';
}

function humanChangeType(t) {
  const map = {
    new_subdomain: 'New Subdomain',
    became_live: 'Host Came Online',
    became_dead: 'Host Went Down',
    content_changed: 'Content Changed',
    status_changed: 'Status Changed',
  };
  return map[t] || t;
}

function emptyState(icon, title, desc) {
  return `<div class="empty-state">
    <div class="empty-icon">${icon}</div>
    <div class="empty-title">${esc(title)}</div>
    <div class="empty-desc">${esc(desc)}</div>
  </div>`;
}

// ── Toast ─────────────────────────────────────────────────────────────────────

function showToast(type, title, msg) {
  const container = document.getElementById('toast-container');
  const icons = { success: '✅', error: '❌', info: 'ℹ️' };
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `<div class="toast-icon">${icons[type] || 'ℹ️'}</div>
    <div class="toast-body">
      <div class="toast-title">${esc(title)}</div>
      ${msg ? `<div class="toast-msg">${esc(msg)}</div>` : ''}
    </div>`;
  container.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

// ── Clock ─────────────────────────────────────────────────────────────────────

function updateClock() {
  const el = document.getElementById('topbar-time');
  if (el) el.textContent = new Date().toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

// ── Manual Refresh ────────────────────────────────────────────────────────────

function manualRefresh() {
  const btn = document.getElementById('refresh-btn');
  if (btn) btn.classList.add('spinning');
  refreshCurrentView();
  setTimeout(() => { if (btn) btn.classList.remove('spinning'); }, 1200);
}

// ── Boot ──────────────────────────────────────────────────────────────────────

async function boot() {
  updateClock();
  setInterval(updateClock, 1000);

  await loadConfig();

  if (state.config?.auth_enabled) {
    // Try to restore token from localStorage
    const stored = localTokenGet();
    if (stored) {
      // Quick validation: check if token is not expired by verifying we get a 200 from /api/config
      // (a lightweight endpoint; real validation is done server-side on every protected call)
      state._authAccessToken = stored;
      // Do a quick ping to ensure token is still valid
      try {
        const probe = await fetch(`${API}/api/dashboard/stats`, {
          headers: { Authorization: `Bearer ${stored}` },
        });
        if (probe.status === 401) {
          localTokenClear();
          state._authAccessToken = null;
          showAuthGate();
          wireAuthForm();
          return;
        }
      } catch {
        // Network error — still try to start (will fail gracefully per-request)
      }
    } else {
      showAuthGate();
      wireAuthForm();
      return;
    }
  }

  await startDashboard();
}

document.addEventListener('DOMContentLoaded', boot);

// ══════════════════════════════════════════════════════════════════════════════
// Bug Bounty Targets Page
// ══════════════════════════════════════════════════════════════════════════════

const PLATFORM_COLORS = {
  h1: { bg: '#1a2e1a', border: '#2a5a2a', accent: '#2ecc71', text: '#2ecc71' },
  bc: { bg: '#2e1e10', border: '#5a3820', accent: '#e67e22', text: '#e67e22' },
  ywh: { bg: '#10182e', border: '#1e2e5a', accent: '#3498db', text: '#3498db' },
  it: { bg: '#1e1028', border: '#3c1e55', accent: '#9b59b6', text: '#9b59b6' },
  immunefi: { bg: '#1a1a2e', border: '#2a2a55', accent: '#667eea', text: '#667eea' },
};

// State for the targets page
const targetsState = {
  platforms: [],
  selectedPlatform: null,
  credentials: {},   // {platform: {token, username, email, password}}
  domains: [],       // last fetched root domains
  filtered: [],      // after filter
};

async function loadTargetsPlatforms() {
  if (state.view !== 'targets') return;
  try {
    const data = await apiFetch('/api/scope/platforms');
    targetsState.platforms = data.platforms || [];
    renderTargetsPlatforms();
  } catch (e) {
    showToast('error', 'Scope Error', e.message);
  }
}

function renderTargetsPlatforms() {
  const grid = document.getElementById('targets-platforms-grid');
  if (!grid) return;
  grid.innerHTML = '';
  for (const p of targetsState.platforms) {
    const colors = PLATFORM_COLORS[p.id] || PLATFORM_COLORS['immunefi'];
    const isSelected = targetsState.selectedPlatform === p.id;
    const card = document.createElement('div');
    card.id = `targets-platform-${p.id}`;
    card.style.cssText = `
      background:${colors.bg};border:2px solid ${isSelected ? colors.accent : colors.border};
      border-radius:16px;padding:20px;cursor:pointer;transition:all 0.2s;
      ${isSelected ? `box-shadow:0 0 24px ${colors.accent}33;` : ''}
    `;
    card.innerHTML = `
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">
        <span style="font-size:28px">${p.logo}</span>
        <div>
          <div style="font-weight:700;font-size:15px;color:${colors.text}">${p.name}</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:2px">
            ${p.env_configured
        ? `<span style="color:#2ecc71">✓ Credentials configured</span>`
        : `<span style="color:#e74c3c">⚠ Credentials needed</span>`}
          </div>
        </div>
      </div>
      <div style="font-size:12px;color:var(--text-muted);line-height:1.5;margin-bottom:14px">${p.description}</div>
      ${renderPlatformCredFields(p, colors)}
      <button onclick="targetsSelectPlatform('${p.id}')"
        style="width:100%;margin-top:14px;padding:9px;border-radius:10px;border:none;
               background:${isSelected ? colors.accent : colors.border};
               color:${isSelected ? '#fff' : colors.text};font-weight:600;font-size:13px;cursor:pointer;transition:all 0.2s;">
        ${isSelected ? '✓ Selected' : 'Select'}
      </button>
    `;
    card.addEventListener('mouseenter', () => {
      if (!isSelected) card.style.borderColor = colors.accent;
    });
    card.addEventListener('mouseleave', () => {
      if (!isSelected) card.style.borderColor = colors.border;
    });
    grid.appendChild(card);
  }
}

function renderPlatformCredFields(p, colors) {
  if (!p.auth_fields || p.auth_fields.length === 0) return '';
  const creds = targetsState.credentials[p.id] || {};
  return p.auth_fields.map(field => {
    const label = field.charAt(0).toUpperCase() + field.slice(1);
    const isPass = field === 'password' || field === 'token';
    return `
      <div style="margin-bottom:8px;">
        <label style="font-size:11px;font-weight:600;color:${colors.text};text-transform:uppercase;letter-spacing:0.05em;">${label}</label>
        <input type="${isPass ? 'password' : 'text'}"
          id="targets-cred-${p.id}-${field}"
          value="${escapeSafe(creds[field] || '')}"
          placeholder="${field === 'token' ? 'API Token' : field === 'username' ? 'Username' : field}"
          oninput="targetsUpdateCred('${p.id}','${field}',this.value)"
          style="width:100%;box-sizing:border-box;background:rgba(0,0,0,0.3);border:1px solid ${colors.border};
                 border-radius:8px;padding:7px 10px;color:#fff;font-size:12px;margin-top:4px;outline:none;" />
      </div>
    `;
  }).join('');
}

function escapeSafe(s) {
  return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
}

function targetsUpdateCred(platformId, field, value) {
  if (!targetsState.credentials[platformId]) targetsState.credentials[platformId] = {};
  targetsState.credentials[platformId][field] = value;
}

function targetsSelectPlatform(id) {
  targetsState.selectedPlatform = id;
  renderTargetsPlatforms();
  const p = targetsState.platforms.find(x => x.id === id);
  const fetchCard = document.getElementById('targets-fetch-card');
  if (fetchCard) {
    fetchCard.style.display = 'block';
    const titleEl = document.getElementById('targets-fetch-card-title');
    if (titleEl && p) titleEl.textContent = `Fetch from ${p.name}`;
  }
  // Hide previous results
  const resultsCard = document.getElementById('targets-results-card');
  if (resultsCard) resultsCard.style.display = 'none';
}

async function targetsDoFetch() {
  const platformId = targetsState.selectedPlatform;
  if (!platformId) { showToast('warning', 'No platform', 'Select a platform first'); return; }

  const creds = targetsState.credentials[platformId] || {};
  const btn = document.getElementById('targets-fetch-btn');
  if (btn) { btn.textContent = 'Fetching…'; btn.disabled = true; }

  try {
    const body = {
      platform: platformId,
      username: creds.username || '',
      token: creds.token || '',
      email: creds.email || '',
      password: creds.password || '',
      bbp_only: document.getElementById('targets-bbp-only')?.checked || false,
      pvt_only: document.getElementById('targets-pvt-only')?.checked || false,
      public_only: document.getElementById('targets-public-only')?.checked || false,
      include_oos: document.getElementById('targets-include-oos')?.checked || false,
      extract_roots: true,
    };
    const data = await apiPost('/api/scope/fetch', body);
    targetsState.domains = data.root_domains || [];
    targetsState.filtered = [...targetsState.domains];

    const p = targetsState.platforms.find(x => x.id === platformId);
    const header = document.getElementById('targets-result-header');
    if (header) header.textContent = `${data.domain_count} root domains from ${p?.name || platformId} (${data.programs} programs)`;

    const resultsCard = document.getElementById('targets-results-card');
    if (resultsCard) resultsCard.style.display = 'block';

    targetsRenderDomainList(targetsState.filtered);
    showToast('success', 'Done', `Fetched ${data.domain_count} root domains from ${data.programs} programs`);
  } catch (e) {
    showToast('error', 'Fetch failed', e.message);
  } finally {
    if (btn) { btn.textContent = 'Fetch Targets'; btn.disabled = false; }
  }
}

function targetsApplyFilter() {
  const q = (document.getElementById('targets-filter-input')?.value || '').toLowerCase();
  targetsState.filtered = q
    ? targetsState.domains.filter(d => d.toLowerCase().includes(q))
    : [...targetsState.domains];
  targetsRenderDomainList(targetsState.filtered);
}

function targetsRenderDomainList(domains) {
  const container = document.getElementById('targets-domain-list');
  if (!container) return;
  if (!domains.length) {
    container.innerHTML = `<div style="padding:24px;text-align:center;color:var(--text-muted)">No domains found.</div>`;
    return;
  }
  const colors = PLATFORM_COLORS[targetsState.selectedPlatform] || PLATFORM_COLORS['immunefi'];
  container.innerHTML = `
    <table style="width:100%;border-collapse:collapse;font-size:13px;">
      <thead>
        <tr style="border-bottom:1px solid var(--border);">
          <th style="text-align:left;padding:8px 12px;color:var(--text-muted);font-weight:600;">#</th>
          <th style="text-align:left;padding:8px 12px;color:var(--text-muted);font-weight:600;">Root Domain</th>
          <th style="text-align:right;padding:8px 12px;color:var(--text-muted);font-weight:600;">Actions</th>
        </tr>
      </thead>
      <tbody>
        ${domains.map((d, i) => `
          <tr style="border-bottom:1px solid rgba(255,255,255,0.04);transition:background 0.15s;"
              onmouseenter="this.style.background='rgba(255,255,255,0.03)'"
              onmouseleave="this.style.background='transparent'">
            <td style="padding:9px 12px;color:var(--text-muted);width:40px">${i + 1}</td>
            <td style="padding:9px 12px;">
              <span style="color:${colors.text};font-family:monospace">${escapeSafe(d)}</span>
            </td>
            <td style="padding:9px 12px;text-align:right;">
              <div style="display:flex;gap:6px;justify-content:flex-end;">
                <button onclick="targetsAddDomain('${escapeSafe(d)}')"
                  style="padding:4px 12px;border-radius:8px;border:1px solid ${colors.border};
                         background:transparent;color:${colors.text};font-size:11px;cursor:pointer;">
                  + Add
                </button>
                <button onclick="targetsLaunchScan('${escapeSafe(d)}')"
                  style="padding:4px 12px;border-radius:8px;border:none;
                         background:${colors.accent};color:#fff;font-size:11px;cursor:pointer;font-weight:600;">
                  ▶ Scan
                </button>
              </div>
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

async function targetsAddDomain(domain) {
  try {
    await apiPost('/api/domains', { domain });
    showToast('success', 'Added', `${domain} added to Domains DB`);
  } catch (e) {
    showToast('error', 'Add failed', e.message);
  }
}

async function targetsAddAllDomains() {
  const domains = targetsState.filtered;
  if (!domains.length) return;
  const btn = document.getElementById('targets-add-all-btn');
  if (btn) { btn.textContent = 'Adding…'; btn.disabled = true; }
  try {
    // Use the bulk endpoint — one HTTP request for all domains
    const data = await apiPost('/api/domains/bulk', { domains });
    showToast('success', 'Bulk Add', `Added ${data.added} domains${data.errors?.length ? ` (${data.errors.length} errors)` : ''}`);
  } catch (e) {
    showToast('error', 'Bulk add failed', e.message);
  } finally {
    if (btn) { btn.textContent = '+ Add All to Domains DB'; btn.disabled = false; }
  }
}

function targetsLaunchScan(domain) {
  // Navigate to scans page with a pre-filled new scan modal if available,
  // or navigate to scans and open a full domain scan.
  navigateTo('scans');
  setTimeout(() => {
    if (typeof openNewScanModal === 'function') {
      openNewScanModal({ target: domain, scanType: 'domain_run' });
    } else {
      showToast('info', 'Launch Scan', `Start a scan for ${domain} from the Scans page`);
    }
  }, 300);
}

async function targetsCopyAll() {
  const domains = targetsState.filtered;
  if (!domains.length) return;
  const text = domains.join('\n');

  // Try the modern Clipboard API first (requires HTTPS or localhost)
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      showToast('success', 'Copied', `${domains.length} domains copied to clipboard`);
      return;
    } catch { /* fall through to textarea fallback */ }
  }

  // Textarea fallback for HTTP (non-secure) contexts
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;left:-9999px;top:-9999px;opacity:0;';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    if (ok) {
      showToast('success', 'Copied', `${domains.length} domains copied to clipboard`);
    } else {
      showToast('warning', 'Manual copy needed', 'Auto-copy failed — open the text in the toast');
    }
  } catch (e) {
    showToast('error', 'Copy failed', e.message);
  }
}

// Helper: POST with JSON body (reuses auth headers like apiFetch)
async function apiPost(path, body) {
  const headers = await buildAuthHeaders({ 'Content-Type': 'application/json' });
  const res = await fetch(`${API}${path}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
  if (res.status === 401 && state.config?.auth_enabled) { handleAuthError(); throw new Error('Unauthorized'); }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

// ── Keyhacks ─────────────────────────────────────────────────────────────────

async function loadKeyhacks(query = '') {
  const container = document.getElementById('keyhacks-container');
  if (!container) return;

  try {
    const path = query ? `/api/keyhacks/search?q=${encodeURIComponent(query)}` : '/api/keyhacks';
    const data = await apiFetch(path);
    renderKeyhacks(data);
  } catch (e) {
    container.innerHTML = `<div class="empty-state"><div class="empty-title" style="color:var(--accent-red)">Error loading templates</div><div class="empty-subtitle">${e.message}</div></div>`;
  }
}

function renderKeyhacks(templates) {
  const container = document.getElementById('keyhacks-container');
  if (!container) return;

  if (!templates || templates.length === 0) {
    container.innerHTML = '<div class="empty-state"><div class="empty-icon">🔍</div><div class="empty-title">No templates found</div><div class="empty-subtitle">Try a different search query</div></div>';
    return;
  }

  let html = `<div class="keyhacks-grid">`;

  templates.forEach(t => {
    const method = (t.Method || 'GET').toUpperCase();
    const cmd = t.CommandTemplate || '';
    const methodClass = method === 'POST' ? 'method-post' : 'method-get';
    
    html += `
      <div class="keyhack-card">
        <div class="keyhack-header">
          <div class="keyhack-title">
            <span class="nav-icon" style="font-size:14px">🔑</span>
            ${escapeHTML(t.Keyname)}
          </div>
          <div class="keyhack-badge ${methodClass}">${method}</div>
        </div>
        <div class="keyhack-body">
          <div class="keyhack-desc">${escapeHTML(t.Description || 'No description available for this template.')}</div>
          
          <div class="keyhack-cmd-section">
            <div class="keyhack-cmd-label">Validation Command Template</div>
            <div class="keyhack-cmd-box">
              <pre class="keyhack-pre">${escapeHTML(cmd)}</pre>
              <button class="keyhack-copy-btn" title="Copy to clipboard" data-cmd="${escAttr(cmd)}">
                <span style="font-size:14px">📋</span>
              </button>
            </div>
          </div>

          ${t.Notes ? `
          <div class="keyhack-notes">
            <div class="keyhack-notes-label">💡 Usage Notes</div>
            <div class="keyhack-notes-text">${escapeHTML(t.Notes)}</div>
          </div>
          ` : ''}
        </div>
      </div>
    `;
  });

  html += '</div>';
  container.innerHTML = html;
  container.querySelectorAll('.keyhack-copy-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const cmd = btn.getAttribute('data-cmd') || '';
      try {
        await copyToClipboard(cmd);
        showToast('success', 'Copied to clipboard', '');
      } catch (e) {
        showToast('error', 'Copy failed', e?.message || String(e));
      }
    });
  });
}

function escapeHTML(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// Keyhacks check

// ── Export ──────────────────────────────────────────────────────────────────────

function csvEscape(value) {
  const str = String(value ?? '');
  return `"${str.replace(/"/g, '""')}"`;
}

async function exportScanResultsCSV(scanId) {
  try {
    showToast('info', 'Exporting CSV', `Preparing scan ${scanId} findings...`);
    const parsed = await apiFetch(`/api/scans/${encodeURIComponent(scanId)}/results/parsed?section=all&limit=10000`);
    const rows = Array.isArray(parsed?.rows) ? parsed.rows : [];
    if (!rows.length) {
      showToast('error', 'No data', 'No findings available to export for this scan.');
      return;
    }

    const headers = ['target', 'severity', 'finding', 'module', 'kind', 'category', 'file', 'source'];
    const csvLines = [
      headers.join(','),
      ...rows.map((r) => {
        const target = r.host || r.target || '';
        const severity = r.severity || '';
        const finding = r.title || r.finding || '';
        const module = r.module || '';
        const kind = r.kind || '';
        const category = r.category || '';
        const file = r.file || r.file_name || '';
        const source = r.source || '';
        return [
          csvEscape(target),
          csvEscape(severity),
          csvEscape(finding),
          csvEscape(module),
          csvEscape(kind),
          csvEscape(category),
          csvEscape(file),
          csvEscape(source),
        ].join(',');
      }),
    ];

    const blob = new Blob([csvLines.join('\n')], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const ts = new Date().toISOString().replace(/[:.]/g, '-');
    a.href = url;
    a.download = `scan-${scanId}-results-${ts}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    showToast('success', 'CSV exported', `${rows.length} row(s) downloaded.`);
  } catch (e) {
    showToast('error', 'CSV export failed', e?.message || String(e));
  }
}

async function generateScanReport(scanId) {
  showToast('info', 'Generating Report', 'Gathering data for scan ' + scanId);
  try {
    const data = await apiFetch(`/api/scans/${encodeURIComponent(scanId)}/report`);
    const reportWindow = window.open('', '_blank');
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>AutoAR Scan Report - ${scanId}</title>
        <style>
          body { font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; line-height: 1.6; color: #333; padding: 40px; max-width: 900px; margin: auto; }
          h1 { border-bottom: 2px solid #06b6d4; padding-bottom: 10px; color: #0f172a; }
          .meta { background: #f8fafc; padding: 20px; border-radius: 8px; margin-bottom: 30px; }
          .finding-card { border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 16px; page-break-inside: avoid; }
          .severity-high { border-left: 5px solid #f97316; }
          .severity-critical { border-left: 5px solid #ef4444; }
          .badge { font-size: 11px; padding: 2px 8px; border-radius: 4px; font-weight: bold; }
        </style>
      </head>
      <body>
        <h1>Security Scan Report</h1>
        <div class="meta">
          <div><strong>Target:</strong> ${data.scan_info?.target || 'N/A'}</div>
          <div><strong>Type:</strong> ${data.scan_info?.scan_type || 'N/A'}</div>
          <div><strong>Status:</strong> ${data.scan_info?.status || 'N/A'}</div>
          <div><strong>Generated:</strong> ${new Date().toLocaleString()}</div>
        </div>
        <h2>Summary of Findings</h2>
        <p>This scan identified ${data.files?.length || 0} result artifacts.</p>
        <div id="findings">
          ${data.files?.map(f => `
            <div class="finding-card">
              <strong>${f.file_name}</strong> (${f.module})
              <div style="font-size: 13px; color: #64748b">Size: ${f.size_bytes} bytes</div>
            </div>
          `).join('')}
        </div>
        <script>window.print();</script>
      </body>
      </html>
    `;
    reportWindow.document.write(html);
    reportWindow.document.close();
  } catch (e) {
    showToast('error', 'Report Failed', e.message);
  }
}

// ── Nuclei Template Manager ──────────────────────────────────────────────────


// ── Report Templates ─────────────────────────────────────────────────────────

async function renderReportTemplates(search = '') {
  const container = document.getElementById('report-templates-container');
  if (!container) return;

  try {
    let templates = await apiFetch('/api/report-templates');

    if (search) {
      const q = search.toLowerCase();
      templates = templates.filter(name => name.toLowerCase().includes(q));
    }

    const headerBlock = `
      <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:14px;">
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          <button class="btn btn-ghost" onclick="exportReportTemplates()">⬇️ Export JSON</button>
          <button class="btn btn-ghost" onclick="triggerImportReportTemplates()">⬆️ Import JSON</button>
        </div>
        <button class="btn btn-primary" onclick="openReportTemplateModal()">➕ Add Template</button>
      </div>
    `;

    if (!templates || templates.length === 0) {
      container.innerHTML = `
        ${headerBlock}
        <div class="empty-state">
          <div class="empty-icon">📝</div>
          <div class="empty-title">No templates found</div>
          <p class="empty-sub">Create your first markdown report template.</p>
        </div>
      `;
      return;
    }

    container.innerHTML = `
      ${headerBlock}
      <div class="domain-grid">
        ${templates.map(name => `
          <div class="domain-card" onclick="openReportTemplateModalByName('${encodeURIComponent(name)}')">
            <div class="domain-name">📄 ${esc(name)}</div>
            <div class="domain-stats">
              <div class="domain-stat">
                <div class="domain-stat-label">Format</div>
                <div class="domain-stat-value" style="font-size: 14px;">Markdown</div>
              </div>
            </div>
            <div style="margin-top: 16px; display: flex; gap: 8px;">
              <button class="btn btn-ghost btn-sm" onclick="event.stopPropagation(); openReportTemplateModalByName('${encodeURIComponent(name)}')">✏️ Edit</button>
              <button class="btn btn-ghost btn-sm" style="color: var(--accent-red);" onclick="event.stopPropagation(); deleteReportTemplateByName('${encodeURIComponent(name)}')">🗑️ Delete</button>
            </div>
          </div>
        `).join('')}
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<div class="error-state">❌ ${esc(err.message)}</div>`;
  }
}

function openReportTemplateModalByName(encodedName) {
  openReportTemplateModal(decodeURIComponent(encodedName || ''));
}

async function openReportTemplateModal(name = '') {
  const modal = document.getElementById('modal-report-template');
  const title = document.getElementById('report-template-modal-title');
  const nameInput = document.getElementById('report-template-name');
  const contentInput = document.getElementById('report-template-content');

  if (!modal || !title || !nameInput || !contentInput) return;

  nameInput.value = name;
  // Allow renaming existing templates.
  nameInput.readOnly = false;
  state.reportTemplateOriginalName = name || '';
  contentInput.value = '';
  title.textContent = name ? '📝 Edit Template' : '➕ New Template';

  if (name) {
    try {
      const data = await apiFetch(`/api/report-templates/${encodeURIComponent(name)}`);
      contentInput.value = data.content;
    } catch (err) {
      showToast('error', 'Failed to load template', err.message);
    }
  }

  modal.style.display = 'flex';
  updateTemplatePreview();
}

function updateTemplatePreview() {
  const content = document.getElementById('report-template-content').value;
  const preview = document.getElementById('report-template-preview');
  if (!preview) return;
  
  if (typeof marked !== 'undefined') {
    preview.innerHTML = marked.parse(content || '*No content yet...*');
  } else {
    preview.textContent = content;
  }
}

function closeReportTemplateModal() {
  const modal = document.getElementById('modal-report-template');
  state.reportTemplateOriginalName = '';
  if (modal) modal.style.display = 'none';
}

async function saveReportTemplate() {
  const name = document.getElementById('report-template-name').value.trim();
  const content = document.getElementById('report-template-content').value;
  const originalName = String(state.reportTemplateOriginalName || '').trim();

  if (!name || !content) {
    showToast('error', 'Validation', 'Name and content are required');
    return;
  }

  try {
    const headers = await buildAuthHeaders({ 'Content-Type': 'application/json' });
    const res = await fetch(`${API}/api/report-templates`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ name, content })
    });

    if (!res.ok) {
      const data = await res.json();
      throw new Error(data.error || 'Failed to save template');
    }

    // If this was a rename, remove the old template key.
    if (originalName && originalName !== name) {
      try {
        const delHeaders = await buildAuthHeaders();
        await fetch(`${API}/api/report-templates/${encodeURIComponent(originalName)}`, {
          method: 'DELETE',
          headers: delHeaders,
        });
      } catch (_) {
        // Best effort: keep successful save even if old key cleanup fails.
      }
    }

    showToast('success', 'Template Saved', `Template "${name}" saved successfully`);
    closeReportTemplateModal();
    renderReportTemplates();
  } catch (err) {
    showToast('error', 'Save Failed', err.message);
  }
}

function deleteReportTemplateByName(encodedName) {
  deleteReportTemplate(decodeURIComponent(encodedName || ''));
}

async function exportReportTemplates() {
  try {
    const headers = await buildAuthHeaders();
    const res = await fetch(`${API}/api/report-templates/export`, { method: 'GET', headers });
    if (!res.ok) {
      let msg = 'Failed to export templates';
      try {
        const data = await res.json();
        msg = data.error || msg;
      } catch (_) {}
      throw new Error(msg);
    }
    const blob = await res.blob();
    const ts = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
    const filename = `report-templates-${ts}.json`;
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    showToast('success', 'Export Ready', `Downloaded ${filename}`);
  } catch (err) {
    showToast('error', 'Export Failed', err.message);
  }
}

function triggerImportReportTemplates() {
  const input = document.getElementById('report-templates-import-file');
  if (!input) return;
  input.value = '';
  input.click();
}

async function handleImportReportTemplatesFile(event) {
  const file = event?.target?.files?.[0];
  if (!file) return;

  try {
    const headers = await buildAuthHeaders();
    const form = new FormData();
    form.append('file', file);
    form.append('overwrite', 'true');

    const res = await fetch(`${API}/api/report-templates/import`, {
      method: 'POST',
      headers,
      body: form,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.error || 'Failed to import templates');
    }
    showToast('success', 'Import Completed', `Imported ${data.imported || 0}, skipped ${data.skipped || 0}`);
    renderReportTemplates((document.getElementById('report-templates-search')?.value || '').trim());
  } catch (err) {
    showToast('error', 'Import Failed', err.message);
  } finally {
    if (event?.target) event.target.value = '';
  }
}

async function deleteReportTemplate(name) {
  if (!confirm(`Are you sure you want to delete the template "${name}"?`)) return;

  try {
    const headers = await buildAuthHeaders();
    const res = await fetch(`${API}/api/report-templates/${encodeURIComponent(name)}`, {
      method: 'DELETE',
      headers
    });

    if (!res.ok) {
      const data = await res.json();
      throw new Error(data.error || 'Failed to delete template');
    }

    showToast('success', 'Template Deleted', `Template "${name}" removed`);
    renderReportTemplates();
  } catch (err) {
    showToast('error', 'Delete Failed', err.message);
  }
}

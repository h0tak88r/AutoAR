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
  apkx: { path: 'apkx', modes: ['file_path'], placeholders: { file_path: '/absolute/path/to/app.apk' } },
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
  _sbClient: null,
  /** Latest access_token; avoids races right after login before getSession() is consistent. */
  _authAccessToken: null,
  _sbAuthListener: false,
  _dashboardStarted: false,
  _shellWired: false,
  _r2BrowserWired: false,
};

// ── Router ────────────────────────────────────────────────────────────────────

const VIEWS = ['overview', 'scans', 'domains', 'subdomains', 'targets', 'monitor', 'r2', 'settings'];

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
    monitor: 'Monitor', r2: 'R2 Storage', settings: 'Settings'
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
      // If on scan detail AND there's an active scan, also refresh that view
      if (state.view === 'scan-detail' && state.scanDetailId) {
        const n = state.stats?.active_scans ?? 0;
        if (n > 0) {
          // Only do a lightweight status check, not a full re-render
          refreshScanDetailIfRunning(state.scanDetailId);
        }
      }
    } catch (e) { /* ignore */ }
    const n = state.stats?.active_scans ?? 0;
    const onScans = state.view === 'scans';
    const onDetail = state.view === 'scan-detail';
    let ms = POLL_INTERVAL;
    if ((onScans || onDetail) && n > 0) ms = POLL_FAST_SCANS;
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
    case 'r2': loadR2(state.r2.prefix); break;
    case 'settings': loadConfig(); break;
    case 'scan-detail':
      if (state.scanDetailId) renderScanDetailView(state.scanDetailId);
      break;
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

  let html = '';
  if (scanErr) {
    html += `<div class="card" style="margin-bottom:16px;border:1px solid var(--accent-red);background:rgba(239,68,68,0.08)">
      <div class="card-body" style="padding:14px 16px;font-size:13px;color:var(--accent-red)">Could not load scans: ${esc(scanErr)}</div>
    </div>`;
  }

  if (active_scans.length) {
    html += `<div class="card" style="margin-bottom:20px">
      <div class="card-header">
        <div class="card-title">⚡ Active Scans <span class="badge badge-running">${active_scans.length}</span></div>
      </div>
      <div class="card-body">
        ${active_scans.map(s => scanItemHtml(s)).join('')}
      </div>
    </div>`;
  }

  html += `<div class="card">
    <div class="card-header" style="display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:12px">
      <div class="card-title">🕐 Recent Scans</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
        <button type="button" class="btn btn-ghost" style="font-size:12px;padding:6px 12px" onclick="deleteSelectedScans()">Delete selected</button>
        <button type="button" class="btn btn-ghost" style="font-size:12px;padding:6px 12px;color:var(--accent-red);border-color:rgba(248,113,113,.35)" onclick="clearAllScans()">Clear all</button>
      </div>
    </div>
    <div class="card-body">`;

  if (!recent_scans.length && !active_scans.length) {
    html += scanErr
      ? emptyState('⚠️', 'Scans unavailable', 'Fix the error above or check that the API is reachable.')
      : emptyState('📋', 'No scans yet', 'Start a scan from the Overview tab or via the CLI.');
  } else if (!recent_scans.length) {
    html += `<div style="padding:20px;text-align:center;color:var(--text-muted);font-size:13px">No completed scans yet</div>`;
  } else {
    html += `<table class="data-table" id="recent-scans-table">
      <thead><tr>
        <th style="width:36px" onclick="event.stopPropagation()"><input type="checkbox" title="Select all" aria-label="Select all" onclick="event.stopPropagation();toggleSelectAllRecentScans(this)" /></th>
        <th>Target</th><th>Type</th><th>Status</th><th>Phase</th><th>Started</th><th>Elapsed</th><th>Results</th>
      </tr></thead>
      <tbody>${recent_scans.map(s => scanRowHtml(s)).join('')}</tbody>
    </table>`;
  }
  html += `</div></div>`;
  container.innerHTML = html;
}


/**
 * Return a human-friendly badge label + optional icon for a raw scan_type string.
 * Falls back to capitalising the raw value if no mapping exists.
 */
function scanTypeLabel(rawType) {
  const t = String(rawType || '').toLowerCase().trim();
  const map = {
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
    'all-subs.txt', 'live-subs.txt', 'all-urls.txt', 'js-urls.txt', 'interesting-urls.txt',
    'tech-detect.txt', 'buckets.txt', 'ffuf-results.txt',
  ]);
  if (recon.has(n)) return 'recon';
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

  // Nuclei vulnerability scanner
  if (n.startsWith('nuclei-') || n.includes('nuclei')) return 'nuclei';

  // Subdomain enumeration tools
  if (n.includes('subdomain') || n.includes('subfinder') || n.includes('amass')) return 'subdomain-enum';

  // HTTP status checking
  if (n.includes('live-subs') || n.includes('httpx') || n.includes('livehosts')) return 'httpx';

  // JavaScript analysis
  if (n.includes('js-urls') || n.includes('javascript') || n.includes('js-')) return 'js-analysis';

  // XSS/Reflection
  if (n.includes('kxss') || n.includes('dalfox') || n.includes('reflection')) return 'xss-detection';

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

  // Dependency confusion
  if (n.includes('depconfusion') || n.includes('confused')) return 'dependency-confusion';

  // S3 bucket scanning
  if (n.includes('s3') || n.includes('bucket')) return 's3-scan';

  // DNS takeover
  if (n.includes('dns') || n.includes('takeover')) return 'dns-takeover';

  // Technology detection
  if (n.includes('tech-detect') || n.includes('wappalyzer')) return 'tech-detect';

  // Port scanning
  if (n.includes('port') || n.includes('nmap')) return 'port-scan';

  // GitHub/Source code
  if (n.includes('github') || n.includes('repo')) return 'github-scan';

  // URL/FFUF fuzzing
  if (n.includes('ffuf') || n.includes('fuzz')) return 'ffuf-fuzzing';

  // Reflection/parameter detection
  if (n.includes('reflection') || n.includes('param')) return 'reflection';

  return 'autoar';
}

/** Get module display name with icon */
function getModuleDisplayInfo(module) {
  const mod = String(module || '').toLowerCase();
  const modules = {
    'nuclei': { icon: '☢️', name: 'Nuclei', color: '#f59e0b' },
    'subdomain-enum': { icon: '🔍', name: 'Subdomain Enum', color: '#06b6d4' },
    'httpx': { icon: '🌐', name: 'HTTPX', color: '#10b981' },
    'js-analysis': { icon: '📜', name: 'JS Analysis', color: '#818cf8' },
    'xss-detection': { icon: '⚡', name: 'XSS Detection', color: '#f59e0b' },
    'sql-detection': { icon: '💉', name: 'SQL Detection', color: '#ef4444' },
    'gf-patterns': { icon: '🎯', name: 'GF Patterns', color: '#10b981' },
    'zerodays': { icon: '🚨', name: 'ZeroDays', color: '#ef4444' },
    'backup-detection': { icon: '💾', name: 'Backup Files', color: '#8b5cf6' },
    'misconfig': { icon: '⚙️', name: 'Misconfig', color: '#f97316' },
    'dependency-confusion': { icon: '📦', name: 'Dep Confusion', color: '#ec4899' },
    's3-scan': { icon: '🪣', name: 'S3 Scan', color: '#06b6d4' },
    'dns-takeover': { icon: '🔀', name: 'DNS Takeover', color: '#14b8a6' },
    'tech-detect': { icon: '🔬', name: 'Tech Detect', color: '#a855f7' },
    'port-scan': { icon: '🔌', name: 'Port Scan', color: '#64748b' },
    'github-scan': { icon: '🐙', name: 'GitHub Scan', color: '#6366f1' },
    'ffuf-fuzzing': { icon: '🎲', name: 'FFUF Fuzzing', color: '#f43f5e' },
    'reflection': { icon: '🔎', name: 'Reflection', color: '#0ea5e9' },
    'autoar': { icon: '🎯', name: 'AutoAR', color: '#06b6d4' },
    'unknown': { icon: '❓', name: 'Unknown', color: '#64748b' },
  };

  return modules[mod] || modules['autoar'];
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
  if (module === 'httpx' || fileName.includes('live') || fileName.includes('httpx')) {
    if (first.url || first.status_code || first.status || first.title) return 'httpx-results';
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
    if (first.url || first.service || first.config) return 'misconfig-findings';
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

/** Render JS findings */
function renderJSFindingsTable(items) {
  const rows = items.map(item => {
    const url = item.url || item.endpoint || '—';
    const secret = item.secret || item.key || item.type || '—';
    const details = item.details || item.description || '—';

    return `
      <tr>
        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan);max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(String(url))}</td>
        <td><span class="badge badge-running">${esc(String(secret))}</span></td>
        <td style="font-size:12px;color:var(--text-muted);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(String(details))}</td>
      </tr>`;
  }).join('');

  return `
    <div class="result-table-wrap">
      <table class="result-table">
        <thead>
          <tr>
            <th>URL</th>
            <th>TYPE</th>
            <th>DETAILS</th>
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
    const service = item.service || '—';
    const config = item.config || item.setting || '—';
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
            <th>URL</th>
            <th>SERVICE</th>
            <th>CONFIG</th>
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
      `/api/scans/${encodeURIComponent(scanId)}/results/summary?page=1&per_page=${ui.filesPerPage}`
    );
    const scan = sum.scan;
    const target = scan.target || scan.Target || '';
    const st = scan.scan_type || scan.ScanType || '';
    const stat = scan.status || scan.Status || '';
    const titleEl = document.getElementById('scan-detail-title');
    if (titleEl) titleEl.textContent = target || 'Scan results';
    if (sub) sub.textContent = `${st} · ${stat}`;
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
              <tr>
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
                  <tr class="dashboard-table-row" data-file-name="${encodeURIComponent(f.file_name)}" onclick="loadScanFilePreview('${scanId}', '${esc(f.file_name)}'))">
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
        <div id="files-count-footer" style="padding:12px 16px;border-top:1px solid var(--border);font-size:12px;color:var(--text-muted)">
          Showing ${files.length} files
        </div>
      </div>` : '';



    // Other Files section removed — all files are now shown in the Findings tabs above

    let html;
    if (!files.length) {
      html = `
        <div class="scan-detail-modern">
          ${zipBanner}
          ${emptyBanner}
          <div class="modern-card" style="padding:20px">
            <div style="text-align:center;color:var(--text-muted)">No files to preview.</div>
          </div>
        </div>`;
    } else {
      html = `
        <div class="scan-detail-modern">
          ${zipBanner}
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

    // Wire up file clicks for legacy table rows if any
    wireScanFileRows(container, scanId);

    // Wire up search and filter functionality
    wireScanDetailFilters(scanId, files);

    // Load unified findings table (all files in one table with sub-tabs)
    loadReconUnifiedTable(scanId, files, 'unified-parsed-results');

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
  // Called by startPolling; only act if scan detail page is active
  if (state.view !== 'scan-detail' || state.scanDetailId !== scanId) return;
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

    // Update the status subtitle
    const sub = document.getElementById('scan-detail-sub');
    if (sub) sub.textContent = `${scan.scan_type || ''} · ${stat}`;

    // Update or inject phase banner
    updatePhaseBanner(scan);

    // Refresh the file-count badge
    const badge = document.getElementById('unified-parsed-badge');
    if (badge && files.length) badge.textContent = `${files.length} files`;

    // Find newly indexed files (not seen before) and append to Findings table
    const newFiles = files.filter(f => !_scanDetailKnownFiles.has(f.file_name));
    if (newFiles.length) {
      newFiles.forEach(f => _scanDetailKnownFiles.add(f.file_name));
      // Trigger a lightweight re-render of just the unified table
      const unifiedRoot = document.getElementById('unified-parsed-results');
      if (unifiedRoot) {
        // Don't re-render from scratch if already built — just re-load with full file list
        loadReconUnifiedTable(scanId, files, 'unified-parsed-results');
        // Also refresh assets cache
        _assetsCache = null;
      }
    }

    if (stillRunning) {
      scheduleScanDetailRefresh(scanId, 4000);
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
  const module = detectModuleFromFileName(file.file_name, file.module);
  const pushObj = (obj) => {
    if (!obj || typeof obj !== 'object') return;
    const severity = obj.info?.severity || obj.severity || obj.level || '—';
    const target = obj['matched-at'] || obj.matched_at || obj.url || obj.host || obj.domain || obj.target || '—';
    const finding = obj['template-id'] || obj.template_id || obj.template || obj.name || obj.title || obj.issue || obj.vulnerability || obj.message || normalizeFindingText(obj);
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
    let foundArray = false;
    for (const k of ['results', 'findings', 'matches', 'issues', 'vulnerabilities', 'data', 'items']) {
      if (Array.isArray(obj[k])) {
        foundArray = true;
        for (const item of obj[k]) {
          if (typeof item === 'object') pushObj(item);
          else {
            rows.push({ file: file.file_name, module, source: file.source || '—', severity: '—', target: '—', finding: normalizeFindingText(item) });
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
  const b = String(fileName || '').split(/[/\\]/).pop().toLowerCase();
  if (!b) return 'other';
  // Log files — separate tab
  if (b.endsWith('.log')) return 'logs';
  // Subdomains
  if (b.includes('all-subs') || b.includes('live-subs') || b.endsWith('subs.txt') || b.includes('subdomain')) return 'subdomains';
  if (b.includes('live') && (b.includes('host') || b.includes('subs'))) return 'subdomains';
  if (b.includes('httpx') || b.includes('live-hosts')) return 'subdomains';
  // URLs
  if (b.includes('all-url') || b.includes('interesting-url') || (b.endsWith('urls.txt') && !b.includes('js'))) return 'urls';
  if (b.includes('cname')) return 'urls';
  // JS URLs
  if (b.includes('js-url') || b.includes('jsurl') || b === 'js-urls.json') return 'js_urls';
  // JS secrets / exposures
  if (b.includes('js-secret') || b.includes('js-exposure') || b.includes('secret') || b.includes('exposure')) return 'vuln';
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
  // DNS / cloud takeover (including aws, azure, cloudflare, gcp)
  if (b.includes('dns') || b.includes('takeover') || b.includes('dnsreap') ||
    b.includes('aws-') || b.includes('azure-') || b.includes('gcp-') ||
    b.includes('cloudflare') || b.includes('dangling')) return 'dns';
  // Backup
  if (b.includes('backup') || b.includes('fuzzuli')) return 'backup';
  // Ports
  if (b.includes('port') || b.includes('nmap') || b.includes('masscan')) return 'ports';
  // GF patterns
  if (b.startsWith('gf-') || b.includes('gf-')) return 'gf';
  // Reflection / XSS
  if (b.includes('reflection') || b.includes('kxss') || b.includes('dalfox') || b.includes('xss')) return 'vuln';
  // Dependency confusion / supply chain
  if (b.includes('confusion') || b.includes('depconf')) return 'vuln';
  // GH / source code scanning
  if (b.includes('github') || b.includes('repo')) return 'vuln';
  return 'other';
}

async function loadReconUnifiedTable(scanId, allFiles, containerId) {
  const root = document.getElementById(containerId);
  if (!root) return;
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

  allRows = allRows.map((r) => ({
    ...r,
    kind: String(r.kind || inferKindFromFileName(r.file) || 'other').toLowerCase(),
  }));

  const maxRows = 2500;
  let activeKind = 'all';
  let searchHost = '';
  let searchTitle = '';
  let filterSeverity = 'any';

  // Build dynamic tabs from actual data
  const _kindCounts = {};
  for (const r of allRows) _kindCounts[r.kind || 'other'] = (_kindCounts[r.kind || 'other'] || 0) + 1;
  const TAB_LABELS = {
    subdomains: 'Subdomains', urls: 'Links', js_urls: 'JS URLs',
    ffuf: 'FFUF', buckets: 'Buckets',
    vuln: 'Vulnerabilities', zerodays: '0-Days',
    misconfig: 'Misconfig', dns: 'DNS',
    backup: 'Backup', s3: 'S3', ports: 'Ports',
    reflection: 'Reflection', gf: 'GF Patterns',
    other: 'Other',
  };
  // Kinds that are hidden from standalone tabs (merged into Assets or suppressed)
  const HIDDEN_KINDS = new Set(['logs', 'log', 'tech']);
  // Merge nuclei + vuln + reflection into same display key so they share a single tab
  for (const r of allRows) {
    if (r.kind === 'nuclei' || r.kind === 'reflection') r.kind = 'vuln';
  }
  // Show Assets tab first, then All, then data tabs that have rows (excluding hidden kinds)
  const DATASET_TABS = [
    ['assets', '🏠 Assets'],  // always present
    ['all', 'All'],
    ...Object.entries(_kindCounts)
      .filter(([k, c]) => c > 0 && !HIDDEN_KINDS.has(k))
      .sort((a, b) => b[1] - a[1])
      .map(([k]) => [k, TAB_LABELS[k] || k]),
  ];

  // Cache for assets data (uses global _assetsCache so doScanDetailRefresh can bust it)
  let _assetsLoading = false;

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

  const kindCounts = {};
  for (const r of allRows) kindCounts[r.kind || 'other'] = (kindCounts[r.kind || 'other'] || 0) + 1;

  const datasetCount = (k) => (k === 'all' ? allRows.length : (kindCounts[k] || 0));


  const rowMatch = (r) => {
    if (activeKind !== 'all' && (r.kind || 'other') !== activeKind) return false;
    if (searchHost && !String(r.host || r.target || '').toLowerCase().includes(searchHost)) return false;
    if (searchTitle && !String(r.title || r.finding || '').toLowerCase().includes(searchTitle)) return false;
    if (filterSeverity !== 'any') {
      const sev = String(r.severity || 'info').toLowerCase();
      if (sev !== filterSeverity) return false;
    }
    return true;
  };

  root.innerHTML = `
    <div style="border:1px solid var(--border);border-radius:10px;background:var(--bg-surface);overflow:hidden">
      <div id="recon-top-tabs" style="display:flex;gap:2px;overflow:auto;padding:0 10px;background:rgba(2,6,23,.6);border-bottom:1px solid var(--border)"></div>
      <div id="recon-filter-bar" style="display:grid;grid-template-columns:minmax(200px,1.5fr) 140px minmax(180px,1fr) auto;gap:8px;padding:10px;border-bottom:1px solid var(--border);background:rgba(2,6,23,.5)">
        <input id="recon-filter-host" type="search" placeholder="🔍 Filter by target URL..." style="padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-size:12px"/>
        <select id="recon-filter-severity" style="padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-size:12px">
          <option value="any">Any Severity</option>
          <option value="critical">🔴 Critical</option>
          <option value="high">🟠 High</option>
          <option value="medium">🟡 Medium</option>
          <option value="low">🔵 Low</option>
          <option value="info">🟢 Info</option>
        </select>
        <input id="recon-filter-title" type="search" placeholder="🔍 Filter by type / finding..." style="padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-size:12px"/>
        <div style="display:flex;align-items:center;justify-content:flex-end;gap:4px;font-size:11px;color:var(--text-muted);white-space:nowrap">
          <span id="recon-unified-shown">0</span>&nbsp;rows
        </div>
      </div>
      <!-- Standard findings table -->
      <div id="recon-standard-view">
        <div class="result-table-wrap" style="max-height:640px;overflow:auto">
          <table class="dashboard-table" style="margin:0;table-layout:fixed;width:100%">
            <thead style="position:sticky;top:0;z-index:2;background:rgba(2,6,23,.97);backdrop-filter:blur(4px)">
              <tr>
                <th style="width:36px;text-align:center;padding-left:10px">
                  <input type="checkbox" id="findings-select-all" title="Select all" style="width:14px;height:14px;accent-color:var(--accent-cyan);cursor:pointer">
                </th>
                <th style="width:31%">TARGET</th>
                <th style="width:8%;text-align:center">SEV</th>
                <th style="width:43%">VULNERABILITY TYPE</th>
                <th style="width:16%">MODULE</th>
              </tr>
            </thead>
            <tbody id="recon-unified-tbody"></tbody>
          </table>
        </div>
        <div id="recon-unified-cap" style="display:none;padding:10px 12px;font-size:12px;color:var(--text-muted);border-top:1px solid var(--border)"></div>
      </div>
      <!-- Assets view (shown when Assets tab active) -->
      <div id="recon-assets-view" style="display:none">
        <div id="recon-assets-content" style="padding:16px;min-height:200px;max-height:680px;overflow:auto">
          <div style="text-align:center;padding:40px;color:var(--text-muted)">Loading assets…</div>
        </div>
      </div>
    </div>`;

  const tabsEl = root.querySelector('#recon-top-tabs');
  const filterBar = root.querySelector('#recon-filter-bar');
  const standardView = root.querySelector('#recon-standard-view');
  const assetsView = root.querySelector('#recon-assets-view');
  const assetsContent = root.querySelector('#recon-assets-content');

  const renderTabs = () => {
    if (!tabsEl) return;
    tabsEl.innerHTML = DATASET_TABS.map(([kind, label]) => {
      const isActive = activeKind === kind;
      const cnt = kind === 'assets' ? '' : `<span class="tab-count">${datasetCount(kind)}</span>`;
      return `<button class="tab-pill${isActive ? ' active' : ''}" data-recon-kind="${escAttr(kind)}" style="border:none;border-bottom:2px solid ${isActive ? 'var(--accent-cyan)' : 'transparent'};border-radius:0;padding:11px 12px;white-space:nowrap;background:transparent;color:${isActive ? 'var(--accent-cyan)' : 'var(--text-secondary)'};font-size:12px">
        ${esc(label)} ${cnt}
      </button>`;
    }).join('');
  };

  const renderBody = () => {
    if (activeKind === 'assets') return;
    // Filter out hidden kinds (logs, tech) from all tabs including 'all'
    const filtered = allRows.filter(r => {
      if (!rowMatch(r)) return false;
      if (HIDDEN_KINDS.has(r.kind)) return false; // always hide logs + tech rows
      return true;
    });
    const slice = filtered.slice(0, maxRows);
    const tbody = root.querySelector('#recon-unified-tbody');
    const shown = root.querySelector('#recon-unified-shown');
    const cap = root.querySelector('#recon-unified-cap');
    if (shown) shown.textContent = String(filtered.length);
    if (tbody) {
      tbody.innerHTML = slice.length ? slice.map((r, idx) => {
        // ── Severity ───────────────────────────────────────────────────
        const sev = String(r.severity || '').toLowerCase().replace(/[—\-]/g, '').trim();
        const sevMeta = {
          critical: { color: '#fc8181', bg: '#fc818120', label: 'CRIT' },
          high: { color: '#f6ad55', bg: '#f6ad5520', label: 'HIGH' },
          medium: { color: '#f6e05e', bg: '#f6e05e20', label: 'MED' },
          low: { color: '#63b3ed', bg: '#63b3ed20', label: 'LOW' },
          info: { color: '#68d391', bg: '#68d39120', label: 'INFO' },
          warning: { color: '#f6ad55', bg: '#f6ad5520', label: 'WARN' },
        }[sev] || { color: '#718096', bg: '#71809615', label: '—' };

        // ── Vuln type / template-id ─────────────────────────────────────
        // r.finding = template-id from nuclei JSON (e.g. "graphql-get")
        // r.title   = same or parsed name
        const vulnType = String(r.title || r.finding || '—').trim();
        // Detect if it's a URL-only finding (no real type name)
        const isURL = vulnType.startsWith('http://') || vulnType.startsWith('https://');
        const typeDisplay = isURL ? '—' : vulnType;
        const typeLabel = typeDisplay.length > 72 ? typeDisplay.slice(0, 70) + '…' : typeDisplay;

        // ── Module badge ───────────────────────────────────────────────
        const modInfo = getModuleDisplayInfo(r.module);

        // ── Target URL ─────────────────────────────────────────────────
        const target = String(r.host || r.target || '-');
        let href = '#';
        if (target.startsWith('http://') || target.startsWith('https://')) {
          href = target;
        } else if (target && target !== '-' && target !== '—') {
          href = 'https://' + target;
        }

        return `<tr class="findings-row" data-target="${escAttr(target)}" data-finding="${escAttr(vulnType)}" data-severity="${escAttr(sev)}" data-module="${escAttr(r.module || '')}" data-href="${escAttr(href)}" style="cursor:pointer;${idx % 2 ? 'background:rgba(255,255,255,.012)' : ''}">
          <td style="padding:7px 10px;width:36px;text-align:center">
            <input type="checkbox" class="finding-chk" style="width:14px;height:14px;accent-color:var(--accent-cyan);cursor:pointer" onclick="event.stopPropagation()">
          </td>
          <td style="padding:7px 10px;max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
            <a href="${esc(href)}" target="_blank" rel="noopener"
               onclick="event.stopPropagation()"
               title="${esc(target)}"
               style="color:var(--accent-cyan);text-decoration:none;font-family:var(--font-mono,monospace);font-size:11.5px">${esc(target)}</a>
          </td>
          <td style="padding:7px 8px;text-align:center;white-space:nowrap">
            <span style="
              display:inline-block;
              background:${sevMeta.bg};
              border:1px solid ${sevMeta.color}44;
              color:${sevMeta.color};
              font-size:9px;
              font-weight:800;
              letter-spacing:.7px;
              padding:2px 7px;
              border-radius:4px;
              min-width:34px;
            ">${esc(sevMeta.label)}</span>
          </td>
          <td style="padding:7px 10px;max-width:0;overflow:hidden">
            ${typeDisplay !== '—' ? `
            <span title="${esc(typeDisplay)}" style="
              display:inline-block;
              max-width:100%;
              overflow:hidden;
              text-overflow:ellipsis;
              white-space:nowrap;
              font-family:var(--font-mono,monospace);
              font-size:11.5px;
              color:var(--text-primary);
            ">${esc(typeLabel)}</span>` : `<span style="color:var(--text-muted);font-size:11px">—</span>`}
          </td>
          <td style="padding:7px 10px;white-space:nowrap;max-width:0;overflow:hidden;text-overflow:ellipsis">
            <span style="color:${modInfo.color};font-size:11px;font-weight:500">${modInfo.icon} ${esc(modInfo.name)}</span>
          </td>
        </tr>`;
      }).join('') : '<tr><td colspan="5" style="text-align:center;padding:28px;color:var(--text-muted);font-size:13px">No findings match the current filter.</td></tr>';
    }
    if (cap) {
      cap.style.display = filtered.length > maxRows ? 'block' : 'none';
      cap.textContent = filtered.length > maxRows ? `Showing first ${maxRows} of ${filtered.length} rows.` : '';
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

  renderTabs();
  renderBody();

  root.addEventListener('click', (e) => {
    const tabBtn = e.target.closest('[data-recon-kind]');
    if (!tabBtn || !root.contains(tabBtn)) return;
    activeKind = tabBtn.getAttribute('data-recon-kind') || 'all';
    renderTabs();
    if (activeKind === 'assets') {
      showAssetsView();
    } else {
      showStandardView();
      renderBody();
    }
  });

  const hostInput = root.querySelector('#recon-filter-host');
  const titleInput = root.querySelector('#recon-filter-title');
  const severitySel = root.querySelector('#recon-filter-severity');
  let debounceTimer = null;
  const applyFilters = () => {
    searchHost = String(hostInput?.value || '').trim().toLowerCase();
    searchTitle = String(titleInput?.value || '').trim().toLowerCase();
    filterSeverity = String(severitySel?.value || 'any').toLowerCase();
    renderBody();
  };
  const applyFiltersDebounced = () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(applyFilters, 200);
  };
  if (hostInput) hostInput.addEventListener('input', applyFiltersDebounced);
  if (titleInput) titleInput.addEventListener('input', applyFiltersDebounced);
  if (severitySel) severitySel.addEventListener('change', applyFilters);

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

  // Clicking a row (not a link/checkbox) toggles its checkbox
  root.addEventListener('click', e => {
    const row = e.target.closest('.findings-row');
    if (!row) return;
    if (e.target.tagName === 'A' || e.target.tagName === 'INPUT') return;
    const chk = row.querySelector('.finding-chk');
    if (chk) { chk.checked = !chk.checked; _updateToolbar(); }
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
          loadScanFilePreview(scanId, r2Key, { retainPage: true });
        }
      });
      document.getElementById('pv-next')?.addEventListener('click', () => {
        if (ui.previewPage < pages) {
          ui.previewPage += 1;
          loadScanFilePreview(scanId, r2Key, { retainPage: true });
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
          loadScanFilePreview(scanId, r2Key, { retainPage: true });
        }
      });
      document.getElementById('tx-next')?.addEventListener('click', () => {
        if (ui.previewPage < pages) {
          ui.previewPage += 1;
          loadScanFilePreview(scanId, r2Key, { retainPage: true });
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
        <span class="setting-key" style="margin-bottom:4px">OpenRouter API Key <span style="font-size:10px;color:var(--text-muted)">(stored locally in your browser)</span></span>
        <div style="display:flex;width:100%;gap:10px">
          <input type="password" id="or-key-input"
            value="${esc(localStorage.getItem('autoar_or_key') || '')}"
            placeholder="sk-or-v1-…"
            class="form-control" style="flex:1;font-family:var(--font-mono);font-size:12px">
          <button class="btn btn-primary" onclick="saveOpenRouterKey()">Save</button>
        </div>
        <span style="font-size:11px;color:var(--text-muted)">Used for <strong>Validate with AI</strong> and <strong>Report with AI</strong>. Get a key at <a href="https://openrouter.ai/keys" target="_blank" style="color:var(--accent-cyan)">openrouter.ai/keys</a> — free tier available.</span>
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

window.saveOpenRouterKey = function () {
  const input = document.getElementById('or-key-input');
  if (!input) return;
  const key = input.value.trim();
  if (key) {
    localStorage.setItem('autoar_or_key', key);
    showToast('success', 'Saved!', 'OpenRouter key stored in your browser.');
  } else {
    localStorage.removeItem('autoar_or_key');
    showToast('info', 'Cleared', 'OpenRouter key removed.');
  }
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
  input.style.display = isList ? 'none' : '';
  listInput.style.display = isList ? '' : 'none';
  help.textContent = isList
    ? 'Bulk mode: one target per line (comma also supported).'
    : `Single target mode: ${LAUNCH_MODE_LABELS[mode] || mode}.`;
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

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
  apkxCacheStats: null,
  // Keyhacks templates are fetched once from DB and then used fully in-browser
  // for inspector detection + command suggestion (no DB calls per paste/search).
  keyhacksAllTemplates: null,
  keyhacksTemplatesLoading: null,
};

// ── Router ────────────────────────────────────────────────────────────────────

const VIEWS = ['overview', 'scans', 'domains', 'subdomains', 'targets', 'keyhacks', 'monitor', 'r2', 'settings', 'report-templates', 'apkauditor', 'ipaauditor', 'adbauditor', 'securitylab'];

function pathScanId() {
  const m = String(location.pathname || '').match(/^\/scans\/([^/]+)\/?$/);
  return m ? decodeURIComponent(m[1]) : null;
}

function openAuditorInNewTab(view) {
  const tok = state._authAccessToken || localTokenGet();
  const pathMap = { 'apkauditor': '/ui/apkauditor/', 'ipaauditor': '/ui/ipaauditor/', 'adbauditor': '/ui/adbauditor/', 'securitylab': '/ui/securitylab/' };
  const targetPath = pathMap[view] || '/ui/apkauditor/';
  
  if (tok) {
    // Stamp the cookie so the new tab's request passes the server-side auth guard
    // We set it for the specific subpaths
    document.cookie = `autoar_token=${tok}; path=/ui/apkauditor; max-age=3600; SameSite=Strict`;
    document.cookie = `autoar_token=${tok}; path=/ui/ipaauditor; max-age=3600; SameSite=Strict`;
    document.cookie = `autoar_token=${tok}; path=/ui/adbauditor; max-age=3600; SameSite=Strict`;
    document.cookie = `autoar_token=${tok}; path=/ui/securitylab; max-age=3600; SameSite=Strict`;
  }
  window.open(targetPath, '_blank');
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

  // When entering APK Auditor, stamp a short-lived cookie so the iframe's
  // request to /ui/apkauditor/ passes the server-side auth guard.
  // We also lazily inject the iframe src so it doesn't fire on page load.
  if (['apkauditor', 'ipaauditor', 'adbauditor', 'securitylab'].includes(view)) {
    const tok = state._authAccessToken || localTokenGet();
    if (tok) {
      document.cookie = `autoar_token=${tok}; path=/ui/apkauditor; max-age=3600; SameSite=Strict`;
      document.cookie = `autoar_token=${tok}; path=/ui/ipaauditor; max-age=3600; SameSite=Strict`;
      document.cookie = `autoar_token=${tok}; path=/ui/adbauditor; max-age=3600; SameSite=Strict`;
      document.cookie = `autoar_token=${tok}; path=/ui/securitylab; max-age=3600; SameSite=Strict`;
    }
    const modeMap = { 'apkauditor': 'android', 'ipaauditor': 'ios', 'adbauditor': 'adb' };
    const auditorPathMap = {
      apkauditor: '/ui/apkauditor/?mode=android',
      ipaauditor: '/ui/ipaauditor/?mode=ios',
      adbauditor: '/ui/adbauditor/?mode=adb',
    };
    const frame = document.getElementById(`${view}-frame`);
    if (frame && !frame.getAttribute('data-loaded')) {
      frame.setAttribute('data-loaded', '1');
      setTimeout(() => {
        if (view === 'securitylab') frame.src = '/ui/securitylab/';
        else frame.src = auditorPathMap[view] || `/ui/apkauditor/?mode=${modeMap[view]}`;
      }, 30);
    }
  }

  VIEWS.forEach(v => {
    const el = document.getElementById(`view-${v}`);
    const nav = document.getElementById(`nav-${v}`);
    if (el) {
      const isActive = v === view;
      el.classList.toggle('active', isActive);
      // Auditor views are full-height, use flex for their containers
      if (['apkauditor', 'ipaauditor', 'adbauditor', 'securitylab'].includes(v)) {
        el.style.display = isActive ? 'flex' : 'none';
      }
    }
    if (nav) nav.classList.toggle('active', v === view);
  });
  document.getElementById('topbar-title').textContent = viewTitle(view);
  state.selectedDomain = null;
  if (!['apkauditor', 'ipaauditor', 'adbauditor', 'securitylab'].includes(view)) {
    refreshCurrentView();
  }
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
    'report-templates': 'Report Templates',
    apkauditor: '🤖 APK Auditor',
    ipaauditor: '🍏 IPA Auditor',
    adbauditor: '⚡ ADB Auditor',
    securitylab: '🧪 Security Lab'
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
  const tok = state._authAccessToken || localTokenGet();
  if (tok) h.Authorization = `Bearer ${tok}`;
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
  if (res.status === 401) {
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
  if (res.status === 401) {
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
  if (res.status === 401) {
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

function settingsPageMethod(name) {
  return window.SettingsPage && typeof window.SettingsPage[name] === 'function'
    ? window.SettingsPage[name]
    : null;
}

async function loadConfig() {
  const fn = settingsPageMethod('loadConfig');
  if (fn) return fn();
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
    if (el) {
      el.addEventListener('click', () => {
        if (el.getAttribute('data-newtab') === 'true') {
          openAuditorInNewTab(v);
        } else {
          navigateTo(v);
        }
      });
    }
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
    backBtn.addEventListener('click', () => navigateTo('overview'));
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
  renderOverviewActiveScans();
  if (state.view === 'scans') renderScans();
}

function monitorPageMethod(name) {
  return window.MonitorPage && typeof window.MonitorPage[name] === 'function'
    ? window.MonitorPage[name]
    : null;
}

async function loadMonitor() {
  const fn = monitorPageMethod('loadMonitor');
  if (fn) return fn();
}

function r2PageMethod(name) {
  return window.R2Page && typeof window.R2Page[name] === 'function'
    ? window.R2Page[name]
    : null;
}

async function loadR2(prefix = '') {
  const fn = r2PageMethod('loadR2');
  if (fn) return fn(prefix);
}

function wireR2BrowserOnce() {
  const fn = r2PageMethod('wireR2BrowserOnce');
  if (fn) return fn();
}

function r2UpdateDeleteSelectedVisibility() {
  const fn = r2PageMethod('r2UpdateDeleteSelectedVisibility');
  if (fn) return fn();
}
function r2DeletePrefixInteractive(prefix) {
  const fn = r2PageMethod('r2DeletePrefixInteractive');
  if (fn) return fn(prefix);
}
function r2DeleteKeyInteractive(key) {
  const fn = r2PageMethod('r2DeleteKeyInteractive');
  if (fn) return fn(key);
}
function r2DeleteSelected() {
  const fn = r2PageMethod('r2DeleteSelected');
  if (fn) return fn();
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
    const onScans = false; // scans view removed

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

function changeItemHtml(c) {
  const ctype = c.ChangeType || c.change_type || '';
  const domain = c.Domain || c.domain || '';
  const detail = c.Detail || c.detail || '';
  const at = c.DetectedAt || c.detected_at || '';
  const iconMap = {
    new_subdomain: '🆕',
    became_live: '🟢',
    became_dead: '💀',
    content_changed: '📝',
    status_changed: '🔄',
  };
  const preview = String(detail || '').slice(0, 200);
  return `<div class="change-item">
    <div class="change-dot ${esc(ctype)}"></div>
    <div class="change-body">
      <div class="change-title">${iconMap[ctype] || '📌'} ${esc(humanChangeType(ctype))}</div>
      <div class="change-detail">${esc(domain)}${preview ? ` — ${esc(preview)}` : ''}</div>
    </div>
    <div class="change-time">${timeAgo(at)}</div>
  </div>`;
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
    case 'apkx':
      return `[ ⚪ ] Apkx — No files indexed yet for ${t}. Results are stored in R2 — use Browse R2 to view them, or trigger a Rescan.`;
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
      return ['TARGET', 'SEV', 'TEMPLATE', 'MATCHED AT / MATCHER'];
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
    const normalizeApkPath = (p) => String(p || '').replace(/^\s*[-*•]\s*/, '').trim();
    const structuredPath = normalizeApkPath(r.path || '');
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
      displayTarget = normalizeApkPath(pathMatch[1]);
      href = '#';
      apkMatcherValue = pathMatch[2].trim() || payload;
    } else {
      // Fallback: try to recover path from matcher_value when backend path is missing.
      const mPath = String(apkMatcherValue || '').match(/^([^:]+):\s*(.+)$/);
      if (mPath && (mPath[1].includes('/') || mPath[1].includes('\\') || mPath[1].includes('.'))) {
        displayTarget = normalizeApkPath(mPath[1]);
        apkMatcherValue = mPath[2].trim() || apkMatcherValue;
      } else {
        displayTarget = structuredPath || (target && target !== '—' ? target : '—');
        apkMatcherValue = payload;
      }
      href = '#';
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
  // r.raw = original nuclei JSONL object (all fields, hyphens normalized to underscores).
  // Falls back to the normalized top-level fields for plain-text nuclei output.
  const raw = r.raw || {};
  const info = raw.info || r.info || {};

  const target  = String(raw.matched_at || raw.host || r.host || r.target || '-');
  const templateId = String(raw.template_id || r.template_id || r.finding || '—');
  const name    = String(info.name || raw.name || templateId);
  const sev     = String((info.severity) || raw.severity || r.severity || '—');
  const matchedAt     = String(raw.matched_at || raw.matched || r.target || '-');
  const matcherName   = String(raw.matcher_name || '');
  const extractedRaw  = raw.extracted_results;
  const extractedResults = Array.isArray(extractedRaw) ? extractedRaw.join(', ') : (extractedRaw || '');
  const curlCmd   = String(raw.curl_command || '');
  const description = String(info.description || raw.description || '');
  const refsRaw   = info.reference || raw.reference;
  const refs = Array.isArray(refsRaw) ? refsRaw.join(', ') : (refsRaw || '');
  const tagsRaw   = info.tags || raw.tags;
  const tags = Array.isArray(tagsRaw) ? tagsRaw.join(', ') : (typeof tagsRaw === 'object' && tagsRaw ? Object.values(tagsRaw).join(', ') : (tagsRaw || ''));
  const rowId = `nuclei-detail-${idx}-${Math.random().toString(36).slice(2)}`;

  // Collect every key from raw that isn't already rendered above.
  const MAIN_KEYS = new Set(['template_id','matched_at','matched','host','info','severity','matcher_name',
    'extracted_results','curl_command','description','reference','tags','name','type']);
  const extraFields = Object.entries(raw)
    .filter(([k, v]) => !MAIN_KEYS.has(k) && v !== null && v !== undefined) 
    .map(([k, v]) => {
      const label = k.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
      const val = (typeof v === 'object') ? JSON.stringify(v, null, 2) : String(v);
      if (!val || val === 'null' || val === '{}' || val === '[]' || val === '—' || val === '-') return '';
      const isLong = val.length > 80 || val.includes('\n');
      return `<div style="${isLong ? 'grid-column:1/-1;' : ''}margin-bottom:6px">
        <span style="color:var(--text-muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px">${esc(label)}</span><br>
        ${isLong
          ? `<pre style="font-size:10px;color:#a0ffb0;background:rgba(0,0,0,.3);padding:6px 8px;border-radius:5px;overflow-x:auto;margin:3px 0 0;white-space:pre-wrap;word-break:break-all">${esc(val)}</pre>`
          : `<span style="font-family:var(--font-mono);font-size:11px;color:var(--text-primary);word-break:break-all">${esc(val)}</span>`
        }
      </div>`;
    }).filter(Boolean);

  const hasDetail = matchedAt !== '-' || matcherName || extractedResults || description || tags || refs || curlCmd || extraFields.length;

  const detailPanel = hasDetail ? `<tr id="${rowId}" style="display:none">
    <td colspan="5" style="padding:0;border-top:1px solid rgba(255,255,255,.07)">
      <div style="padding:14px 20px;background:rgba(0,0,0,.25);display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:12px 20px;border-radius:0 0 8px 8px">
        ${matchedAt !== '-' ? `<div><span style="color:var(--text-muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px">Matched At</span><br><a href="${esc(matchedAt)}" target="_blank" style="font-family:var(--font-mono);font-size:11px;color:var(--accent-cyan);word-break:break-all">${esc(matchedAt)}</a></div>` : ''}
        ${matcherName ? `<div><span style="color:var(--text-muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px">Matcher Name</span><br><span style="font-family:var(--font-mono);font-size:11px;color:var(--accent-amber)">${esc(matcherName)}</span></div>` : ''}
        ${extractedResults ? `<div><span style="color:var(--text-muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px">Extracted Results</span><br><span style="font-family:var(--font-mono);font-size:11px;color:#a3e635;word-break:break-all">${esc(extractedResults)}</span></div>` : ''}
        ${description ? `<div style="grid-column:1/-1"><span style="color:var(--text-muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px">Description</span><br><span style="font-size:11.5px;color:var(--text-primary)">${esc(description)}</span></div>` : ''}
        ${tags ? `<div><span style="color:var(--text-muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px">Tags</span><br><span style="font-size:11px;color:var(--accent-purple)">${esc(tags)}</span></div>` : ''}
        ${refs ? `<div style="grid-column:1/-1"><span style="color:var(--text-muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px">References</span><br><span style="font-size:11px;color:var(--text-secondary);word-break:break-all">${esc(refs)}</span></div>` : ''}
        ${curlCmd ? `<div style="grid-column:1/-1"><span style="color:var(--text-muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px">Curl Command</span><br><pre style="font-size:10px;color:#a0ffb0;background:rgba(0,0,0,.3);padding:8px;border-radius:6px;overflow-x:auto;margin:4px 0 0;white-space:pre-wrap;word-break:break-all">${esc(curlCmd)}</pre></div>` : ''}
        ${extraFields.join('')}
      </div>
    </td>
  </tr>` : '';

  const expandIcon = hasDetail ? `<span style="float:right;font-size:10px;color:var(--text-muted);margin-left:4px">&#9660;</span>` : '';
  const mainRow = `<tr class="findings-row nuclei-row" style="cursor:pointer;${idx % 2 ? 'background:rgba(255,255,255,.012)' : ''}" onclick="(function(){var d=document.getElementById('${rowId}');if(d)d.style.display=d.style.display==='none'?'table-row':'none';})()">
    <td style="padding:7px 10px;width:36px;text-align:center">
      <input type="checkbox" class="finding-chk" onclick="event.stopPropagation()">
    </td>
    <td style="padding:7px 10px;max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
      <a href="${target.startsWith('http') ? target : 'https://' + target}" target="_blank" onclick="event.stopPropagation()" style="color:var(--accent-cyan);font-family:var(--font-mono);font-size:11.5px">${esc(target)}</a>
    </td>
    <td style="padding:7px 8px;text-align:center;white-space:nowrap">
       <span style="background:${sevMeta.bg};border:1px solid ${sevMeta.color}44;color:${sevMeta.color};font-size:9px;font-weight:800;padding:2px 7px;border-radius:4px;">${esc(sevMeta.label)}</span>
    </td>
    <td style="padding:7px 10px;max-width:0;overflow:hidden">
      <div style="color:var(--text-primary);font-weight:600;font-size:12px">${esc(name)}</div>
      <div style="color:var(--text-muted);font-size:10px;font-family:var(--font-mono)">${esc(templateId)}</div>
    </td>
    <td style="padding:7px 10px;white-space:nowrap;min-width:120px">
      <span style="color:var(--text-secondary);font-size:11px;font-family:var(--font-mono);overflow:hidden;text-overflow:ellipsis;display:inline-block;max-width:200px" title="${esc(matchedAt)}">${esc(matchedAt.length > 40 ? matchedAt.slice(0,38)+'…' : matchedAt)}</span>
      ${matcherName ? `<div style="color:var(--accent-amber);font-size:9px;margin-top:2px">${esc(matcherName)}</div>` : ''}
    </td>
  </tr>`;

  return mainRow + detailPanel;
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
  if (window.ScanDetailPage) {
    return window.ScanDetailPage.renderScanDetailView(scanId);
  }
}

async function loadReconUnifiedTable(scanId, files, containerId, scan) {
  if (window.ScanDetailPage) {
    return window.ScanDetailPage.loadReconUnifiedTable(scanId, files, containerId, scan);
  }
}

function wireScanDetailFilters(scanId, files) {
  if (window.ScanDetailPage) {
    return window.ScanDetailPage.wireScanDetailFilters(scanId, files);
  }
}

async function loadScanFilePreview(scanId, fileName, opts) {
  if (window.ScanDetailPage) {
    return window.ScanDetailPage.loadScanFilePreview(scanId, fileName, opts);
  }
}

function clearScanDetailRefreshTimer() {
  if (window.ScanDetailPage) {
    return window.ScanDetailPage.clearScanDetailRefreshTimer();
  }
}

function scheduleScanDetailRefresh(scanId, ms) {
  if (window.ScanDetailPage) {
    return window.ScanDetailPage.scheduleScanDetailRefresh(scanId, ms);
  }
}

function refreshScanDetailIfRunning(scanId) {
  if (window.ScanDetailPage) {
    return window.ScanDetailPage.doScanDetailRefresh(scanId);
  }
}

function clearApkxCacheForScan(scan) {
  if (window.ScanDetailPage) {
    return window.ScanDetailPage.clearApkxCacheForScan(scan);
  }
}

function renderDomainGrid() {
  if (window.DomainsPage) {
    return window.DomainsPage.renderDomainGrid();
  }
}

function renderSubdomainView(domain) {
  if (window.DomainsPage) {
    return window.DomainsPage.renderSubdomainView(domain);
  }
}

function renderSubdomainsPage() {
  if (window.DomainsPage) {
    return window.DomainsPage.renderSubdomainsPage();
  }
}

function backToDomains() {
  if (window.DomainsPage) {
    return window.DomainsPage.backToDomains();
  }
}


function syncMonitorUrlPatternVisibility() {
  const fn = monitorPageMethod('syncMonitorUrlPatternVisibility');
  if (fn) return fn();
}
async function quickAddUrlMonitor() {
  const fn = monitorPageMethod('quickAddUrlMonitor');
  if (fn) return fn();
}
async function quickAddSubdomainMonitor() {
  const fn = monitorPageMethod('quickAddSubdomainMonitor');
  if (fn) return fn();
}
async function runMonitorAISuggest() {
  const fn = monitorPageMethod('runMonitorAISuggest');
  if (fn) return fn();
}
function renderMonitorAISuggestResults(res) {
  const fn = monitorPageMethod('renderMonitorAISuggestResults');
  if (fn) return fn(res);
}
async function addSelectedMonitorSuggestions() {
  const fn = monitorPageMethod('addSelectedMonitorSuggestions');
  if (fn) return fn();
}
async function pauseUrlMonitor(id) {
  const fn = monitorPageMethod('pauseUrlMonitor');
  if (fn) return fn(id);
}
async function resumeUrlMonitor(id) {
  const fn = monitorPageMethod('resumeUrlMonitor');
  if (fn) return fn(id);
}
async function deleteUrlMonitor(id) {
  const fn = monitorPageMethod('deleteUrlMonitor');
  if (fn) return fn(id);
}
async function pauseSubdomainMonitor(id) {
  const fn = monitorPageMethod('pauseSubdomainMonitor');
  if (fn) return fn(id);
}
async function resumeSubdomainMonitor(id) {
  const fn = monitorPageMethod('resumeSubdomainMonitor');
  if (fn) return fn(id);
}
async function deleteSubdomainMonitor(id) {
  const fn = monitorPageMethod('deleteSubdomainMonitor');
  if (fn) return fn(id);
}
async function clearMonitorChangeHistory() {
  const fn = monitorPageMethod('clearMonitorChangeHistory');
  if (fn) return fn();
}
function renderMonitor() {
  const fn = monitorPageMethod('renderMonitor');
  if (fn) return fn();
}

function renderR2() {
  const fn = r2PageMethod('renderR2');
  if (fn) return fn();
}

function renderSettings() {
  const fn = settingsPageMethod('renderSettings');
  if (fn) return fn();
}

function saveOpenRouterKey() {
  const fn = settingsPageMethod('saveOpenRouterKey');
  if (fn) return fn();
}
function saveGeminiKey() {
  const fn = settingsPageMethod('saveGeminiKey');
  if (fn) return fn();
}
function saveTimeoutSettings() {
  const fn = settingsPageMethod('saveTimeoutSettings');
  if (fn) return fn();
}
function saveWebhookSettings() {
  const fn = settingsPageMethod('saveWebhookSettings');
  if (fn) return fn();
}

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

function launcherPageMethod(name) {
  return window.LauncherPage && typeof window.LauncherPage[name] === 'function'
    ? window.LauncherPage[name]
    : null;
}

function syncLaunchPlaceholder(rebuildModes = false) {
  const fn = launcherPageMethod('syncLaunchPlaceholder');
  if (fn) return fn(rebuildModes);
}

function renderLaunchFlags() {
  const fn = launcherPageMethod('renderLaunchFlags');
  if (fn) return fn();
}

function updateLaunchPreview() {
  const fn = launcherPageMethod('updateLaunchPreview');
  if (fn) return fn();
}

async function triggerScan() {
  const fn = launcherPageMethod('triggerScan');
  if (fn) return fn();
}

async function handleLaunchFileUpload(inputEl) {
  const fn = launcherPageMethod('handleLaunchFileUpload');
  if (fn) return fn(inputEl);
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

function uiHelpersMethod(name) {
  return window.UIHelpers && typeof window.UIHelpers[name] === 'function'
    ? window.UIHelpers[name]
    : null;
}

function fmtDate(d) {
  const fn = uiHelpersMethod('fmtDate');
  return fn ? fn(d) : '—';
}

function timeAgo(d) {
  const fn = uiHelpersMethod('timeAgo');
  return fn ? fn(d) : '—';
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
  const fn = uiHelpersMethod('fmtInterval');
  return fn ? fn(secs) : '—';
}

function statusBadge(status) {
  const fn = uiHelpersMethod('statusBadge');
  return fn ? fn(status) : `<span class="badge badge-done">${esc(status)}</span>`;
}

function httpColor(code) {
  const fn = uiHelpersMethod('httpColor');
  return fn ? fn(code) : 'var(--text-muted)';
}

function fileIcon(ext) {
  const fn = uiHelpersMethod('fileIcon');
  return fn ? fn(ext) : '📄';
}

function humanChangeType(t) {
  const fn = uiHelpersMethod('humanChangeType');
  return fn ? fn(t) : t;
}

function emptyState(icon, title, desc) {
  const fn = uiHelpersMethod('emptyState');
  if (fn) return fn(icon, title, desc);
  return `<div class="empty-state"><div class="empty-icon">${icon}</div><div class="empty-title">${esc(title)}</div><div class="empty-desc">${esc(desc)}</div></div>`;
}

// ── Toast ─────────────────────────────────────────────────────────────────────

function showToast(type, title, msg) {
  const fn = uiHelpersMethod('showToast');
  if (fn) return fn(type, title, msg);
}

// ── Clock ─────────────────────────────────────────────────────────────────────

function updateClock() {
  const fn = uiHelpersMethod('updateClock');
  if (fn) return fn();
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

function targetsPageMethod(name) {
  return window.TargetsPage && typeof window.TargetsPage[name] === 'function'
    ? window.TargetsPage[name]
    : null;
}
async function loadTargetsPlatforms() {
  const fn = targetsPageMethod('loadTargetsPlatforms');
  if (fn) return fn();
}
function renderTargetsPlatforms() {
  const fn = targetsPageMethod('renderTargetsPlatforms');
  if (fn) return fn();
}
function renderPlatformCredFields(p, colors) {
  const fn = targetsPageMethod('renderPlatformCredFields');
  if (fn) return fn(p, colors);
  return '';
}
function escapeSafe(s) {
  const fn = targetsPageMethod('escapeSafe');
  if (fn) return fn(s);
  return String(s || '');
}
function targetsUpdateCred(platformId, field, value) {
  const fn = targetsPageMethod('targetsUpdateCred');
  if (fn) return fn(platformId, field, value);
}
function targetsSelectPlatform(id) {
  const fn = targetsPageMethod('targetsSelectPlatform');
  if (fn) return fn(id);
}
async function targetsDoFetch() {
  const fn = targetsPageMethod('targetsDoFetch');
  if (fn) return fn();
}
function targetsApplyFilter() {
  const fn = targetsPageMethod('targetsApplyFilter');
  if (fn) return fn();
}
function targetsRenderDomainList(domains) {
  const fn = targetsPageMethod('targetsRenderDomainList');
  if (fn) return fn(domains);
}
async function targetsAddDomain(domain) {
  const fn = targetsPageMethod('targetsAddDomain');
  if (fn) return fn(domain);
}
async function targetsAddAllDomains() {
  const fn = targetsPageMethod('targetsAddAllDomains');
  if (fn) return fn();
}
function targetsLaunchScan(domain) {
  const fn = targetsPageMethod('targetsLaunchScan');
  if (fn) return fn(domain);
}
async function targetsCopyAll() {
  const fn = targetsPageMethod('targetsCopyAll');
  if (fn) return fn();
}

// ── Keyhacks ─────────────────────────────────────────────────────────────────

async function loadKeyhacks(query = '') {
  if (!window.KeyhacksPage || typeof window.KeyhacksPage.loadKeyhacks !== 'function') {
    const container = document.getElementById('keyhacks-container');
    if (container) {
      container.innerHTML = '<div class="empty-state"><div class="empty-title" style="color:var(--accent-red)">Keyhacks module not loaded</div></div>';
    }
    return;
  }
  return window.KeyhacksPage.loadKeyhacks(query);
}

// Keyhacks check

// ── Export ──────────────────────────────────────────────────────────────────────

function opsToolsPageMethod(name) {
  return window.OpsToolsPage && typeof window.OpsToolsPage[name] === 'function'
    ? window.OpsToolsPage[name]
    : null;
}
async function exportScanResultsCSV(scanId) {
  const fn = opsToolsPageMethod('exportScanResultsCSV');
  if (fn) return fn(scanId);
}
async function generateScanReport(scanId) {
  const fn = opsToolsPageMethod('generateScanReport');
  if (fn) return fn(scanId);
}

// ── Nuclei Template Manager ──────────────────────────────────────────────────


// ── Report Templates ─────────────────────────────────────────────────────────
function reportTemplatesPageMethod(name) {
  return window.ReportTemplatesPage && typeof window.ReportTemplatesPage[name] === 'function'
    ? window.ReportTemplatesPage[name]
    : null;
}
async function renderReportTemplates(search = '') {
  const fn = reportTemplatesPageMethod('renderReportTemplates');
  if (fn) return fn(search);
}
function openReportTemplateModalByName(encodedName) {
  const fn = reportTemplatesPageMethod('openReportTemplateModalByName');
  if (fn) return fn(encodedName);
}
async function openReportTemplateModal(name = '') {
  const fn = reportTemplatesPageMethod('openReportTemplateModal');
  if (fn) return fn(name);
}
function updateTemplatePreview() {
  const fn = reportTemplatesPageMethod('updateTemplatePreview');
  if (fn) return fn();
}
function closeReportTemplateModal() {
  const fn = reportTemplatesPageMethod('closeReportTemplateModal');
  if (fn) return fn();
}
async function saveReportTemplate() {
  const fn = reportTemplatesPageMethod('saveReportTemplate');
  if (fn) return fn();
}
function deleteReportTemplateByName(encodedName) {
  const fn = reportTemplatesPageMethod('deleteReportTemplateByName');
  if (fn) return fn(encodedName);
}
async function exportReportTemplates() {
  const fn = reportTemplatesPageMethod('exportReportTemplates');
  if (fn) return fn();
}
function triggerImportReportTemplates() {
  const fn = reportTemplatesPageMethod('triggerImportReportTemplates');
  if (fn) return fn();
}
async function handleImportReportTemplatesFile(event) {
  const fn = reportTemplatesPageMethod('handleImportReportTemplatesFile');
  if (fn) return fn(event);
}
async function deleteReportTemplate(name) {
  const fn = reportTemplatesPageMethod('deleteReportTemplate');
  if (fn) return fn(name);
}

async function promptRetryCnames() {
  const fn = opsToolsPageMethod('promptRetryCnames');
  if (fn) return fn();
}
async function startCnamesProgressPolling() {
  const fn = opsToolsPageMethod('startCnamesProgressPolling');
  if (fn) return fn();
}
function promptRunGlobalNuclei() {
  const fn = opsToolsPageMethod('promptRunGlobalNuclei');
  if (fn) return fn();
}
function closeNucleiModal() {
  const fn = opsToolsPageMethod('closeNucleiModal');
  if (fn) return fn();
}
async function submitNucleiModal() {
  const fn = opsToolsPageMethod('submitNucleiModal');
  if (fn) return fn();
}

// Expose to window for modularized pages
window.API = API;
window.state = state;
window.apiFetch = apiFetch;
window.apiPost = apiPost;
window.apiDelete = apiDelete;
window.showToast = showToast;
window.navigateTo = navigateTo;
window.buildAuthHeaders = buildAuthHeaders;
window.esc = esc;
window.fmtDate = fmtDate;
window.fmtInterval = fmtInterval;
window.timeAgo = timeAgo;
window.humanChangeType = humanChangeType;
window.copyToClipboard = copyToClipboard;
window.emptyState = emptyState;
window.fmtSize = fmtSize;
window.fileIcon = fileIcon;
window.updateStatusDot = updateStatusDot;
window.loadStats = loadStats;
window.refreshCurrentView = refreshCurrentView;

// More helpers for modularized pages
window.getModuleDisplayInfo = getModuleDisplayInfo;
window.scanNoArtifactsMessage = scanNoArtifactsMessage;
window.escAttr = escAttr;
window.getFileTypeFromName = getFileTypeFromName;
window.getFileTypeIcon = getFileTypeIcon;
window.detectModuleFromFileName = detectModuleFromFileName;
window.normalizeModuleKey = normalizeModuleKey;
window.categorizeScanArtifactFile = categorizeScanArtifactFile;
window.filterScanFiles = filterScanFiles;
window.copyAllScanResults = copyAllScanResults;
window.getUnifiedTableColumns = getUnifiedTableColumns;
window.renderRowForUnifiedTab = renderRowForUnifiedTab;
window.renderDefaultRow = renderDefaultRow;
window.formatJSONWithHighlighting = formatJSONWithHighlighting;

// Table Renderers
window.renderResultTable = renderResultTable;
window.renderSubdomainListTable = renderSubdomainListTable;
window.renderSubdomainObjectTable = renderSubdomainObjectTable;
window.renderHTTPXTable = renderHTTPXTable;
window.renderNucleiTable = renderNucleiTable;
window.renderZeroDaysTable = renderZeroDaysTable;
window.renderJSFindingsTable = renderJSFindingsTable;
window.renderXSSFindingsTable = renderXSSFindingsTable;
window.renderSQLiFindingsTable = renderSQLiFindingsTable;
window.renderURLListTable = renderURLListTable;
window.renderBackupFindingsTable = renderBackupFindingsTable;
window.renderMisconfigTable = renderMisconfigTable;
window.renderAEMTable = renderAEMTable;
window.renderPortResultsTable = renderPortResultsTable;
window.renderS3FindingsTable = renderS3FindingsTable;
window.renderDNSFindingsTable = renderDNSFindingsTable;
window.renderTechFindingsTable = renderTechFindingsTable;
window.renderGenericJSONTable = renderGenericJSONTable;
window.renderModuleBadge = renderModuleBadge;
window.renderCategoryBadge = renderCategoryBadge;

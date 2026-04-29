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

function authSessionPageMethod(name) {
  return window.AuthSessionPage && typeof window.AuthSessionPage[name] === 'function'
    ? window.AuthSessionPage[name]
    : null;
}

function apiClientPageMethod(name) {
  return window.ApiClientPage && typeof window.ApiClientPage[name] === 'function'
    ? window.ApiClientPage[name]
    : null;
}

function localTokenGet() {
  const fn = authSessionPageMethod('localTokenGet');
  if (fn) return fn();
  try { return localStorage.getItem(LOCAL_TOKEN_KEY) || null; } catch { return null; }
}
function localTokenSet(tok) {
  const fn = authSessionPageMethod('localTokenSet');
  if (fn) return fn(tok);
  try { localStorage.setItem(LOCAL_TOKEN_KEY, tok); } catch { /* ignore */ }
}
function localTokenClear() {
  const fn = authSessionPageMethod('localTokenClear');
  if (fn) return fn();
  try { localStorage.removeItem(LOCAL_TOKEN_KEY); } catch { /* ignore */ }
}

async function buildAuthHeaders(extra = {}) {
  const fn = apiClientPageMethod('buildAuthHeaders');
  if (fn) return fn(extra);
  const h = { ...extra };
  const tok = state._authAccessToken || localTokenGet();
  if (tok) h.Authorization = `Bearer ${tok}`;
  return h;
}

function handleAuthError() {
  const fn = apiClientPageMethod('handleAuthError');
  if (fn) return fn();
  localTokenClear();
  state._authAccessToken = null;
  state._dashboardStarted = false;
  showAuthGate();
}

async function apiFetch(path) {
  const fn = apiClientPageMethod('apiFetch');
  if (fn) return fn(path);
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
  const fn = apiClientPageMethod('apiPost');
  if (fn) return fn(path, body, customHeaders);
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
  const fn = apiClientPageMethod('apiDelete');
  if (fn) return fn(path);
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
  const fn = authSessionPageMethod('showAuthGate');
  if (fn) return fn(hintMsg);
}

function hideAuthGate() {
  const fn = authSessionPageMethod('hideAuthGate');
  if (fn) return fn();
}

function scanActionsPageMethod(name) {
  return window.ScanActionsPage && typeof window.ScanActionsPage[name] === 'function'
    ? window.ScanActionsPage[name]
    : null;
}

async function cancelScan(scanID) {
  const fn = scanActionsPageMethod('cancelScan');
  if (fn) return fn(scanID);
}

async function deleteScan(scanID, target = '') {
  const fn = scanActionsPageMethod('deleteScan');
  if (fn) return fn(scanID, target);
}

async function rescanScan(scanID) {
  const fn = scanActionsPageMethod('rescanScan');
  if (fn) return fn(scanID);
}

function toggleSelectAllRecentScans(master) {
  const fn = scanActionsPageMethod('toggleSelectAllRecentScans');
  if (fn) return fn(master);
}

async function deleteSelectedScans() {
  const fn = scanActionsPageMethod('deleteSelectedScans');
  if (fn) return fn();
}

async function clearAllScans() {
  const fn = scanActionsPageMethod('clearAllScans');
  if (fn) return fn();
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
  const fn = scanActionsPageMethod('pauseScan');
  if (fn) return fn(scanID);
}

async function resumeScan(scanID) {
  const fn = scanActionsPageMethod('resumeScan');
  if (fn) return fn(scanID);
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

function dashboardDataPageMethod(name) {
  return window.DashboardDataPage && typeof window.DashboardDataPage[name] === 'function'
    ? window.DashboardDataPage[name]
    : null;
}

async function loadConfig() {
  const fn = settingsPageMethod('loadConfig');
  if (fn) return fn();
}

function wireAuthForm() {
  const fn = authSessionPageMethod('wireAuthForm');
  if (fn) return fn();
}

function shellWiringPageMethod(name) {
  return window.ShellWiringPage && typeof window.ShellWiringPage[name] === 'function'
    ? window.ShellWiringPage[name]
    : null;
}

function wireShellOnce() {
  const fn = shellWiringPageMethod('wireShellOnce');
  if (fn) return fn();
}

function dashboardBootstrapPageMethod(name) {
  return window.DashboardBootstrapPage && typeof window.DashboardBootstrapPage[name] === 'function'
    ? window.DashboardBootstrapPage[name]
    : null;
}

async function startDashboard() {
  const fn = dashboardBootstrapPageMethod('startDashboard');
  if (fn) return fn();
}

async function loadStats() {
  const fn = dashboardDataPageMethod('loadStats');
  if (fn) return fn();
}

async function loadDomains() {
  const fn = dashboardDataPageMethod('loadDomains');
  if (fn) return fn();
}

async function loadSubdomains(page = 1, search = '') {
  const fn = dashboardDataPageMethod('loadSubdomains');
  if (fn) return fn(page, search);
}

/** Copy every subdomain string matching the current search (paginates at API max page size). */
async function copyAllSubdomainsMatching() {
  const fn = domainsPageMethod('copyAllSubdomainsMatching');
  if (fn) return fn();
}

async function loadScans() {
  const fn = dashboardDataPageMethod('loadScans');
  if (fn) return fn();
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

function r2PrefixesPageMethod(name) {
  return window.R2PrefixesPage && typeof window.R2PrefixesPage[name] === 'function'
    ? window.R2PrefixesPage[name]
    : null;
}

function domainR2ActionsPageMethod(name) {
  return window.DomainR2ActionsPage && typeof window.DomainR2ActionsPage[name] === 'function'
    ? window.DomainR2ActionsPage[name]
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

function pollingPageMethod(name) {
  return window.PollingPage && typeof window.PollingPage[name] === 'function'
    ? window.PollingPage[name]
    : null;
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
  const fn = r2PrefixesPageMethod('targetToHostname');
  if (fn) return fn(target);
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
  const fn = r2PrefixesPageMethod('uniquePrefixList');
  if (fn) return fn(prefixes);
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
  const fn = r2PrefixesPageMethod('r2PrefixesForScan');
  if (fn) return fn(target, scanType);
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
  const fn = domainR2ActionsPageMethod('browseR2ForScan');
  if (fn) return fn(target, scanType);
}

async function loadDomainSubdomains(domain) {
  const fn = domainR2ActionsPageMethod('loadDomainSubdomains');
  if (fn) return fn(domain);
}

// ── Polling ───────────────────────────────────────────────────────────────────

function startPolling() {
  const fn = pollingPageMethod('startPolling');
  if (fn) return fn();
}

function refreshCurrentView() {
  const fn = pollingPageMethod('refreshCurrentView');
  if (fn) return fn();
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

function overviewPageMethod(name) {
  return window.OverviewPage && typeof window.OverviewPage[name] === 'function'
    ? window.OverviewPage[name]
    : null;
}

function renderStats() {
  const fn = overviewPageMethod('renderStats');
  if (fn) return fn();
}

function renderOverviewActiveScans() {
  const fn = overviewPageMethod('renderOverviewActiveScans');
  if (fn) return fn();
}

// ── System Metrics ────────────────────────────────────────────────────────────

function startMetricsPolling() {
  const fn = overviewPageMethod('startMetricsPolling');
  if (fn) return fn();
}

function updateMetricsUI(data) {
  const fn = overviewPageMethod('updateMetricsUI');
  if (fn) return fn(data);
}

function renderRecentChanges() {
  const fn = overviewPageMethod('renderRecentChanges');
  if (fn) return fn();
}

function changeItemHtml(c) {
  const fn = overviewPageMethod('changeItemHtml');
  if (fn) return fn(c);
  return '';
}

function scansPageMethod(name) {
  return window.ScansPage && typeof window.ScansPage[name] === 'function'
    ? window.ScansPage[name]
    : null;
}

function renderScans() {
  const fn = scansPageMethod('renderScans');
  if (fn) return fn();
}


/**
 * Return a human-friendly badge label + optional icon for a raw scan_type string.
 * Falls back to capitalising the raw value if no mapping exists.
 */
function scanTypeLabel(rawType) {
  const fn = scansPageMethod('scanTypeLabel');
  return fn ? fn(rawType) : rawType;
}

function scanItemHtml(s) {
  const fn = scansPageMethod('scanItemHtml');
  if (fn) return fn(s);
  return '';
}

function scanRowHtml(s) {
  const fn = scansPageMethod('scanRowHtml');
  if (fn) return fn(s);
  return '';
}

// ── Scan results page (/scans/:id) ─────────────────────────────────────────────

/** Determine file type category from filename for icon display */
function scanCommonPageMethod(name) {
  return window.ScanCommonPage && typeof window.ScanCommonPage[name] === 'function'
    ? window.ScanCommonPage[name]
    : null;
}

function getFileTypeFromName(fileName) {
  const fn = scanCommonPageMethod('getFileTypeFromName');
  return fn ? fn(fileName) : 'text';
}

/** Get icon emoji for file type */
function getFileTypeIcon(fileType) {
  const fn = scanCommonPageMethod('getFileTypeIcon');
  return fn ? fn(fileType) : '📄';
}

/** Toggle collapsible sections */
function toggleCollapsible(header) {
  const fn = scanCommonPageMethod('toggleCollapsible');
  if (fn) return fn(header);
}

/** Switch between scan detail tabs */
function switchScanDetailTab(tabName) {
  const fn = scanCommonPageMethod('switchScanDetailTab');
  if (fn) return fn(tabName);
}

/** Format JSON with syntax highlighting */
function formatJSONWithHighlighting(jsonObj) {
  const fn = scanCommonPageMethod('formatJSONWithHighlighting');
  return fn ? fn(jsonObj) : '';
}

/** Apply syntax highlighting to JSON string */
function syntaxHighlightJSON(json) {
  const fn = scanCommonPageMethod('syntaxHighlightJSON');
  return fn ? fn(json) : '';
}

/** Plain-text line when a finished scan has no indexed artifacts (aligned with Discord phaseNoResultsMessage). */
function scanNoArtifactsMessage(scanType, target) {
  const fn = scanCommonPageMethod('scanNoArtifactsMessage');
  return fn ? fn(scanType, target) : '[ ⚪ ] No artifacts';
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
  const fn = scanCommonPageMethod('detectModuleFromFileName');
  return fn ? fn(fileName, existingModule) : (existingModule || 'unknown');
}

/** Get module display name with icon */
function normalizeModuleKey(module) {
  const fn = scanCommonPageMethod('normalizeModuleKey');
  return fn ? fn(module) : (String(module || '').toLowerCase().trim() || 'unknown');
}

/** Get module display name with icon */
function getModuleDisplayInfo(module) {
  const fn = scanCommonPageMethod('getModuleDisplayInfo');
  return fn ? fn(module) : { icon: '❓', name: 'Unknown', color: '#64748b' };
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
  if (window.ResultTablesPage && typeof window.ResultTablesPage.renderResultTable === 'function') {
    return window.ResultTablesPage.renderResultTable(items, type, file);
  }
  return renderGenericJSONTable(items);
}

function resultTablesPageMethod(name) {
  return window.ResultTablesPage && typeof window.ResultTablesPage[name] === 'function'
    ? window.ResultTablesPage[name]
    : null;
}

/** Render subdomain list (simple strings) */
function renderSubdomainListTable(items) {
  const fn = resultTablesPageMethod('renderSubdomainListTable');
  if (fn) return fn(items);
  return '';
}

/** Render subdomain objects with status info */
function renderSubdomainObjectTable(items) {
  const fn = resultTablesPageMethod('renderSubdomainObjectTable');
  if (fn) return fn(items);
  return '';
}

/** Render HTTPX results */
function renderHTTPXTable(items) {
  const fn = resultTablesPageMethod('renderHTTPXTable');
  if (fn) return fn(items);
  return '';
}

/** Render Nuclei vulnerability findings */
function renderNucleiTable(items) {
  const fn = resultTablesPageMethod('renderNucleiTable');
  if (fn) return fn(items);
  return '';
}

/** Render ZeroDays findings */
function renderZeroDaysTable(items) {
  const fn = resultTablesPageMethod('renderZeroDaysTable');
  if (fn) return fn(items);
  return '';
}

/** Render JS findings with enhanced parsing */
function renderJSFindingsTable(items) {
  const fn = resultTablesPageMethod('renderJSFindingsTable');
  if (fn) return fn(items);
  return '';
}

/** Render XSS findings */
function renderXSSFindingsTable(items) {
  const fn = resultTablesPageMethod('renderXSSFindingsTable');
  if (fn) return fn(items);
  return '';
}

/** Render SQL injection findings */
function renderSQLiFindingsTable(items) {
  const fn = resultTablesPageMethod('renderSQLiFindingsTable');
  if (fn) return fn(items);
  return '';
}

/** Render URL list */
function renderURLListTable(items) {
  const fn = resultTablesPageMethod('renderURLListTable');
  if (fn) return fn(items);
  return '';
}

/** Render backup findings */
function renderBackupFindingsTable(items) {
  const fn = resultTablesPageMethod('renderBackupFindingsTable');
  if (fn) return fn(items);
  return '';
}

/** Render misconfiguration findings */
function renderMisconfigTable(items) {
  const fn = resultTablesPageMethod('renderMisconfigTable');
  if (fn) return fn(items);
  return '';
}

/** Render AEM findings */
function renderAEMTable(items) {
  const fn = resultTablesPageMethod('renderAEMTable');
  if (fn) return fn(items);
  return '';
}

/** Render port scan results */
function renderPortResultsTable(items) {
  const fn = resultTablesPageMethod('renderPortResultsTable');
  if (fn) return fn(items);
  return '';
}

/** Render S3 findings */
function renderS3FindingsTable(items) {
  const fn = resultTablesPageMethod('renderS3FindingsTable');
  if (fn) return fn(items);
  return '';
}

/** Render DNS takeover findings */
function renderDNSFindingsTable(items) {
  const fn = resultTablesPageMethod('renderDNSFindingsTable');
  if (fn) return fn(items);
  return '';
}

/** Render technology detection findings */
function renderTechFindingsTable(items) {
  const fn = resultTablesPageMethod('renderTechFindingsTable');
  if (fn) return fn(items);
  return '';
}

/** Render generic JSON table */
function renderGenericJSONTable(items) {
  const fn = resultTablesPageMethod('renderGenericJSONTable');
  if (fn) return fn(items);
  return '';
}

/** Helper: Get color for HTTP status */
function getStatusColor(status) {
  const fn = resultTablesPageMethod('getStatusColor');
  if (fn) return fn(status);
  return 'var(--text-muted)';
}

/** Helper: Check if status indicates live */
function isLiveStatus(status) {
  const fn = resultTablesPageMethod('isLiveStatus');
  if (fn) return fn(status);
  return false;
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
  const fn = dashboardBootstrapPageMethod('boot');
  if (fn) return fn();
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
window.localTokenGet = localTokenGet;
window.localTokenSet = localTokenSet;
window.localTokenClear = localTokenClear;
window.apiFetch = apiFetch;
window.apiPost = apiPost;
window.apiDelete = apiDelete;
window.showToast = showToast;
window.showAuthGate = showAuthGate;
window.hideAuthGate = hideAuthGate;
window.wireAuthForm = wireAuthForm;
window.navigateTo = navigateTo;
window.openAuditorInNewTab = openAuditorInNewTab;
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
window.loadResource = loadResource;
window.loadStats = loadStats;
window.refreshCurrentView = refreshCurrentView;
window.renderRecentChanges = renderRecentChanges;
window.startDashboard = startDashboard;
window.startPolling = startPolling;
window.startMetricsPolling = startMetricsPolling;
window.manualRefresh = manualRefresh;
window.VIEWS = VIEWS;
window.POLL_INTERVAL = POLL_INTERVAL;
window.POLL_FAST_ANY = POLL_FAST_ANY;
window.POLL_FAST_SCANS = POLL_FAST_SCANS;
window.triggerScan = triggerScan;
window.syncLaunchPlaceholder = syncLaunchPlaceholder;
window.updateLaunchPreview = updateLaunchPreview;
window.syncMonitorUrlPatternVisibility = syncMonitorUrlPatternVisibility;
window.quickAddUrlMonitor = quickAddUrlMonitor;
window.quickAddSubdomainMonitor = quickAddSubdomainMonitor;
window.loadKeyhacks = loadKeyhacks;
window.renderReportTemplates = renderReportTemplates;
window.wireR2BrowserOnce = wireR2BrowserOnce;
window.loadSubdomains = loadSubdomains;
window.loadDomains = loadDomains;
window.loadScans = loadScans;
window.loadMonitor = loadMonitor;
window.loadR2 = loadR2;
window.loadConfig = loadConfig;
window.loadTargetsPlatforms = loadTargetsPlatforms;
window.copyAllSubdomainsMatching = copyAllSubdomainsMatching;
window.renderDomainGrid = renderDomainGrid;
window.refreshScanDetailIfRunning = refreshScanDetailIfRunning;
window.renderScanDetailView = renderScanDetailView;
window.pathScanId = pathScanId;
window.openScanResultsPage = openScanResultsPage;
window.wireShellOnce = wireShellOnce;
window.updateClock = updateClock;
window.browseR2ForScan = browseR2ForScan;
window.loadDomainSubdomains = loadDomainSubdomains;

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
window.scanItemHtml = scanItemHtml;

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

/** Maps launcher <select> values → POST /scan/:path body shape (must match api.go handlers). */
const LAUNCH_SCAN_TYPES = {
  domain_scan:    { path: 'domain_run', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  subdomain_scan: { path: 'subdomain_run', modes: ['subdomain', 'subdomain_list'], placeholders: { subdomain: 'api.example.com', subdomain_list: 'one subdomain per line' } },
  lite:         { path: 'lite', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  subdomains:   { path: 'subdomains', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  livehosts:    { path: 'livehosts', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  urls:         { path: 'urls', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  cnames:       { path: 'cnames', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  js:           { path: 'js', modes: ['domain', 'subdomain', 'domain_list', 'subdomain_list'], placeholders: { domain: 'example.com', subdomain: 'api.example.com', domain_list: 'one domain per line', subdomain_list: 'one subdomain per line' } },
  reflection:   { path: 'reflection', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  nuclei:       { path: 'nuclei', modes: ['domain', 'subdomain', 'url', 'domain_list', 'subdomain_list', 'url_list'], placeholders: { domain: 'example.com', subdomain: 'api.example.com', url: 'https://target.tld/', domain_list: 'one domain per line', subdomain_list: 'one subdomain per line', url_list: 'one URL per line' } },
  tech:         { path: 'tech', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  ports:        { path: 'ports', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  gf:           { path: 'gf', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  backup:       { path: 'backup', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  misconfig:    { path: 'misconfig', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  dns:          { path: 'dns', modes: ['domain', 'domain_list'], extra: { dns_type: 'takeover' }, placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  dns_dangling: { path: 'dns', modes: ['domain', 'domain_list'], extra: { dns_type: 'dangling-ip' }, placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  dns_takeover: { path: 'dns-takeover', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  s3:           { path: 's3', modes: ['bucket', 'bucket_list'], placeholders: { bucket: 'bucket-name', bucket_list: 'one bucket per line' } },
  github:       { path: 'github', modes: ['repo', 'repo_list'], placeholders: { repo: 'owner/repository', repo_list: 'one owner/repo per line' } },
  github_org:   { path: 'github_org', modes: ['repo', 'repo_list'], placeholders: { repo: 'org-name', repo_list: 'one org per line' } },
  zerodays:     { path: 'zerodays', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
  ffuf:         { path: 'ffuf', modes: ['target', 'target_list'], placeholders: { target: 'https://example.com/FUZZ', target_list: 'one FUZZ URL per line' } },
  jwt:          { path: 'jwt', modes: ['token'], placeholders: { token: 'JWT token' } },
  apkx:         { path: 'apkx', modes: ['file_path'], placeholders: { file_path: '/absolute/path/to/app.apk' } },
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
  _sbClient: null,
  /** Latest access_token; avoids races right after login before getSession() is consistent. */
  _authAccessToken: null,
  _sbAuthListener: false,
  _dashboardStarted: false,
  _shellWired: false,
};

// ── Router ────────────────────────────────────────────────────────────────────

const VIEWS = ['overview', 'scans', 'domains', 'monitor', 'r2', 'settings'];

function navigateTo(view) {
  state.view = view;
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

function viewTitle(v) {
  return { overview: 'Overview', scans: 'Scans', domains: 'Domains',
           monitor: 'Monitor', r2: 'R2 Storage', settings: 'Settings' }[v] || v;
}

// ── API Helpers (Supabase JWT when auth_enabled) ─────────────────────────────

function getSupabase() {
  if (!state.config?.auth_enabled || !state.config.supabase_url || !state.config.supabase_anon_key) {
    return null;
  }
  if (state._sbClient) return state._sbClient;
  if (typeof supabase === 'undefined' || !supabase.createClient) {
    return null;
  }
  state._sbClient = supabase.createClient(state.config.supabase_url, state.config.supabase_anon_key, {
    auth: {
      persistSession: true,
      autoRefreshToken: true,
      detectSessionInUrl: true,
    },
  });
  if (!state._sbAuthListener) {
    state._sbAuthListener = true;
    state._sbClient.auth.onAuthStateChange((_event, session) => {
      state._authAccessToken = session?.access_token ?? null;
    });
  }
  return state._sbClient;
}

async function buildAuthHeaders(extra = {}) {
  const h = { ...extra };
  if (state.config?.auth_enabled) {
    const sb = getSupabase();
    if (sb) {
      let tok = state._authAccessToken;
      if (!tok) {
        const { data: { session } } = await sb.auth.getSession();
        tok = session?.access_token;
        if (tok) state._authAccessToken = tok;
      }
      if (tok) {
        h.Authorization = `Bearer ${tok}`;
      }
    }
  }
  return h;
}

async function apiFetch(path) {
  const headers = await buildAuthHeaders();
  const res = await fetch(`${API}${path}`, { headers });
  if (res.status === 401 && state.config?.auth_enabled) {
    const sb = getSupabase();
    if (sb) await sb.auth.signOut();
    state._dashboardStarted = false;
    showAuthGate();
    throw new Error('Session expired — sign in again');
  }
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function apiPost(path, body) {
  const headers = await buildAuthHeaders({ 'Content-Type': 'application/json' });
  const res = await fetch(`${API}${path}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
  if (res.status === 401 && state.config?.auth_enabled) {
    const sb = getSupabase();
    if (sb) await sb.auth.signOut();
    state._dashboardStarted = false;
    showAuthGate();
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
    const sb = getSupabase();
    if (sb) await sb.auth.signOut();
    state._dashboardStarted = false;
    showAuthGate();
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
    const email = (document.getElementById('auth-email') || {}).value || '';
    const password = (document.getElementById('auth-password') || {}).value || '';
    const sb = getSupabase();
    if (!sb) {
      if (errEl) errEl.textContent = 'Auth client not ready.';
      return;
    }
    if (submit) submit.disabled = true;
    const { data, error } = await sb.auth.signInWithPassword({ email, password });
    if (submit) submit.disabled = false;
    if (error) {
      if (errEl) errEl.textContent = error.message;
      return;
    }
    state._authAccessToken = data?.session?.access_token ?? null;
    if (!state._authAccessToken) {
      const { data: d2 } = await sb.auth.getSession();
      state._authAccessToken = d2.session?.access_token ?? null;
    }
    await startDashboard();
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
}

async function startDashboard() {
  if (state._dashboardStarted) return;
  hideAuthGate();

  const so = document.getElementById('sign-out-btn');
  if (so) {
    so.style.display = state.config?.auth_enabled ? 'block' : 'none';
    so.onclick = async () => {
      const sb = getSupabase();
      if (sb) await sb.auth.signOut();
      state._authAccessToken = null;
      state._sbClient = null;
      state._sbAuthListener = false;
      state._dashboardStarted = false;
      showAuthGate();
      wireAuthForm();
    };
  }

  wireShellOnce();
  await loadStats();
  navigateTo('overview');
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
  state.monitorTargets    = targets.status === 'fulfilled'    ? (targets.value.targets    || []) : [];
  state.subMonitorTargets = subTargets.status === 'fulfilled' ? (subTargets.value.targets  || []) : [];
  state.monitorChanges    = changes.status === 'fulfilled'    ? (changes.value.changes    || []) : [];
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

async function loadSubdomains(domain) {
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
    } catch (e) { /* ignore */ }
    const n = state.stats?.active_scans ?? 0;
    const onScans = state.view === 'scans';
    let ms = POLL_INTERVAL;
    if (onScans && n > 0) ms = POLL_FAST_SCANS;
    else if (n > 0) ms = POLL_FAST_ANY;
    state.pollTimer = setTimeout(tick, ms);
  };
  state.pollTimer = setTimeout(tick, 600);
}

function refreshCurrentView() {
  switch (state.view) {
    case 'overview': loadStats(); loadDomains(); loadScans(); break;
    case 'scans':    loadScans(); break;
    case 'domains':  loadDomains(); break;
    case 'monitor':  loadMonitor(); break;
    case 'r2':       loadR2(state.r2.prefix); break;
    case 'settings': loadConfig(); break;
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
  set('stat-domains',    s.domains ?? 0);
  set('stat-subdomains', s.subdomains ?? 0);
  set('stat-live',       s.live_subdomains ?? 0);
  set('stat-monitors',   s.monitor_targets ?? 0);
  set('stat-active',     s.active_scans ?? 0);
  set('stat-completed',  s.completed_scans ?? 0);
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

function scanItemHtml(s) {
  const target = s.target || s.Target || '';
  const scanType = s.scan_type || s.ScanType || '';
  const statusRaw = (s.status || s.Status || 'running').toLowerCase();
  const currentPhase = s.current_phase || s.CurrentPhase || 0;
  const totalPhases = s.total_phases || s.TotalPhases || 0;
  const startedAt = s.started_at || s.StartedAt || '';
  const phaseName = s.phase_name || s.PhaseName || '';

  const pct = totalPhases > 0 ? Math.round((currentPhase / totalPhases) * 100) : 0;
  const elapsed = elapsedStr(startedAt);
  const scanID = s.scan_id || s.ScanID || '';
  const isActive = ['running', 'starting', 'paused', 'cancelling'].includes(statusRaw);
  const showProgress = ['running', 'starting'].includes(statusRaw);
  const modalStatus = statusRaw || 'running';
  const noPhaseYet = showProgress && currentPhase === 0 && pct === 0 && !phaseName;

  let badge = '';
  if (statusRaw === 'paused') badge = '<span class="badge badge-starting">⏸ paused</span>';
  else if (statusRaw === 'cancelling') badge = '<span class="badge badge-starting">… stopping</span>';
  else if (isActive) badge = '<span class="badge badge-running">● live</span>';

  const actions = isActive ? `<div class="scan-actions" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center" onclick="event.stopPropagation()">
    ${statusRaw !== 'paused' && statusRaw !== 'cancelling' ? `<button type="button" class="btn btn-ghost" onclick="pauseScan('${esc(scanID)}')">Pause</button>` : ''}
    ${statusRaw === 'paused' ? `<button type="button" class="btn btn-ghost" onclick="resumeScan('${esc(scanID)}')">Resume</button>` : ''}
    <button type="button" class="btn btn-ghost scan-btn-stop" onclick="cancelScan('${esc(scanID)}')">Stop</button>
  </div>` : '';

  const progressBlock = !showProgress ? '' : noPhaseYet
    ? `<div class="progress-bar indeterminate" style="margin-top:8px"><div class="progress-fill" style="width:40%"></div></div>
    <div style="font-size:11px;color:var(--text-muted);margin-top:4px">Running…</div>`
    : `<div class="progress-bar" style="margin-top:8px"><div class="progress-fill" style="width:${pct}%"></div></div>
    <div style="font-size:11px;color:var(--text-muted);margin-top:4px">Phase ${currentPhase}/${totalPhases} (${pct}%)</div>`;

  return `<div class="scan-item clickable-row" onclick="openScanModal('${esc(target)}', '${esc(scanType)}', '${esc(modalStatus)}', '${esc(scanID)}')">
    <div class="scan-meta">
      <span class="scan-target">${esc(target)}</span>
      <span class="scan-type">${esc(scanType)}</span>
      ${badge}
      <span class="scan-elapsed">${elapsed}</span>
    </div>
    ${phaseName ? `<div class="phase-info">📍 ${esc(phaseName)}</div>` : ''}
    ${progressBlock}
    ${actions}
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
  let phaseCol = '';
  if (done && pct === 0 && !phaseName) {
    phaseCol = '<span style="font-size:11px;color:var(--accent-emerald);font-weight:600">Done</span>';
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
  const deleteBtn = `<button type="button" class="scan-control-btn-r2" style="margin-left:6px;border-color:rgba(248,113,113,.35);color:var(--accent-red)" onclick='event.stopPropagation();deleteScan(${JSON.stringify(scanID)}, ${JSON.stringify(target)})'>Delete</button>`;
  const rowSelect = `<input type="checkbox" class="scan-row-select" data-scan-id="${esc(scanID)}" onclick="event.stopPropagation()" aria-label="Select scan" />`;
  return `<tr class="clickable-row" onclick="openScanModal('${esc(target)}', '${esc(scanType)}', '${esc(status)}', '${esc(scanID)}')">
    <td onclick="event.stopPropagation()">${rowSelect}</td>
    <td><span style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan)">${esc(target)}</span></td>
    <td><span class="scan-type">${esc(scanType)}</span></td>
    <td>${badge}</td>
    <td>${phaseCol}</td>
    <td style="font-size:11px;color:var(--text-muted)">${fmtDate(startedAt)}</td>
    <td style="font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--text-muted)">${elapsed}</td>
    <td onclick="event.stopPropagation()">${resultsCell}${deleteBtn}</td>
  </tr>`;
}

// ── Scan Modal ────────────────────────────────────────────────────────────────

/** List R2 objects (recursive) for this scan’s target + type — matches worker upload layout. */
async function fetchR2FilesForTarget(target, scanType) {
  const prefixes = r2PrefixesForScan(target, scanType);
  const seen = new Set();
  const files = [];
  for (const prefix of prefixes) {
    try {
      const res = await apiFetch(
        `/api/r2/files?prefix=${encodeURIComponent(prefix)}&recursive=1`
      );
      for (const f of res.files || []) {
        if (f.key && !seen.has(f.key)) {
          seen.add(f.key);
          files.push(f);
        }
      }
    } catch (e) {
      /* continue with next prefix */
    }
  }
  return files;
}

async function fetchScanArtifacts(scanID) {
  if (!scanID) return [];
  const res = await apiFetch(`/api/scans/${encodeURIComponent(scanID)}/artifacts`);
  const list = res.artifacts || [];
  const seen = new Set();
  const uniq = [];
  list.forEach(a => {
    const key = a.r2_key || a.public_url || `${a.file_name}:${a.size_bytes}:${a.created_at}`;
    if (seen.has(key)) return;
    seen.add(key);
    uniq.push(a);
  });
  return uniq;
}

function renderIndexedArtifactRows(artifacts) {
  const sorted = [...artifacts].sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  let html = `<div style="font-size:12px;color:var(--text-muted);margin-bottom:12px">Found ${sorted.length} indexed artifacts for this scan.</div>`;
  html += `<table class="data-table">
    <thead><tr><th>File</th><th>Size</th><th>Lines</th><th>Updated</th><th>URL</th></tr></thead><tbody>`;
  sorted.forEach(a => {
    const name = a.file_name || (a.r2_key ? a.r2_key.split('/').pop() : 'file');
    const lines = Number(a.line_count || 0);
    html += `<tr>
      <td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan)">${esc(name)}</td>
      <td style="font-size:12px;color:var(--text-muted)">${fmtSize(a.size_bytes || 0)}</td>
      <td style="font-size:12px;color:var(--text-muted)">${lines > 0 ? lines.toLocaleString() : '—'}</td>
      <td style="font-size:12px;color:var(--text-muted)">${fmtDate(a.created_at)}</td>
      <td>${a.public_url ? `<a href="${esc(a.public_url)}" target="_blank" class="scan-result-link">Open</a>` : '—'}</td>
    </tr>`;
  });
  html += `</tbody></table>`;
  return html;
}

async function openScanModal(target, scanType, status, scanID) {
  const modal = document.getElementById('scan-modal');
  const title = document.getElementById('modal-title');
  const body = document.getElementById('modal-body');
  if (!modal || !title || !body) return;

  const btext = status === 'completed' || status === 'done' ? `<span style="color:var(--accent-emerald)">● done</span>` :
                status === 'running' || status === 'starting' ? `<span style="color:var(--accent-cyan)">⚡ ${status}</span>` :
                status === 'paused' ? `<span style="color:var(--accent-amber)">⏸ paused</span>` :
                status === 'cancelled' ? `<span style="color:var(--text-muted)">⏹ cancelled</span>` :
                status === 'failed' || status === 'error' ? `<span style="color:var(--accent-red)">❌ ${status}</span>` : status;

  title.innerHTML = `Results: <span style="font-family:'JetBrains Mono',monospace">${esc(target)}</span> (${esc(scanType)}) [${btext}]`;
  
  // Find scan in state to check for result_url
  const allScans = [...(state.scans.active_scans || []), ...(state.scans.recent_scans || [])];
  const scan = allScans.find(s => (s.scan_id || s.ScanID) === scanID);
  const resultURL = scan ? (scan.result_url || scan.ResultURL) : null;

  let headerHtml = '';
  if (resultURL) {
    headerHtml = `<div class="scan-result-main" style="background:rgba(16,185,129,0.1);border:1px solid var(--accent-emerald);border-radius:8px;padding:16px;margin-bottom:20px;display:flex;align-items:center;justify-content:space-between">
      <div>
        <div style="font-weight:600;color:var(--accent-emerald);font-size:14px;margin-bottom:4px">📦 Main Scan Result Attached</div>
        <div style="font-size:12px;color:var(--text-muted)">The scan output was automatically zipped and uploaded to R2.</div>
      </div>
      <a href="${esc(resultURL)}" target="_blank" class="btn btn-primary" style="background:var(--accent-emerald);border-color:var(--accent-emerald)">Download Result</a>
    </div>`;
  }

  body.innerHTML = `${headerHtml}<div class="empty-state"><div class="empty-icon">⏳</div><div class="empty-title">Loading results from R2...</div></div>`;
  modal.style.display = 'flex';

  try {
    const artifacts = await fetchScanArtifacts(scanID);
    if (artifacts.length > 0) {
      body.innerHTML = headerHtml + renderIndexedArtifactRows(artifacts);
      return;
    }

    const files = await fetchR2FilesForTarget(target, scanType);
    
    if (files.length === 0) {
      const prefixes = r2PrefixesForScan(target, scanType);
      const searched = prefixes && prefixes.length
        ? `<div style="margin-top:10px;font-size:11px;color:var(--text-muted);line-height:1.5">
             <div style="font-weight:600;color:var(--text-secondary);margin-bottom:6px">Searched R2 prefixes:</div>
             <div style="font-family:'JetBrains Mono',monospace;white-space:pre-wrap">${esc(prefixes.join('\n'))}</div>
           </div>`
        : '';
      body.innerHTML = headerHtml + emptyState('📭', 'No results found', 'This scan either produced no files, or the results were cleaned up from R2.') + searched;
      return;
    }

    // Sort files by last modified descending
    files.sort((a, b) => new Date(b.last_modified) - new Date(a.last_modified));

    let html = `<div style="font-size:12px;color:var(--text-muted);margin-bottom:12px">Found ${files.length} result files in R2 storage matching this target. Download them below:</div>`;
    html += `<div class="r2-browser"><div class="r2-files-panel" style="width:100%"><div id="r2-files-list">`;
    
    files.forEach(f => {
      const name = f.key.split('/').pop();
      const ext  = name.split('.').pop().toLowerCase();
      html += `<div class="r2-file-row">
        <span class="r2-file-icon">${fileIcon(ext)}</span>
        <span class="r2-file-name" title="${esc(f.key)}">${esc(name)}</span>
        <span class="r2-file-size">${fmtSize(f.size)}</span>
        <span class="r2-file-date">${fmtDate(f.last_modified)}</span>
        <a href="${esc(f.public_url)}" target="_blank" class="r2-download-btn" title="Download">⬇</a>
      </div>`;
    });
    
    html += `</div></div></div>`;
    body.innerHTML = headerHtml + html;
  } catch (e) {
    body.innerHTML = headerHtml + emptyState('❌', 'Error loading r2 files', e.message);
  }
}

function closeScanModal() {
  const modal = document.getElementById('scan-modal');
  if (modal) modal.style.display = 'none';
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
        <div class="domain-card" style="position:relative" onclick="loadSubdomains('${esc(d.domain)}')">
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

  container.innerHTML = `
    <div style="display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:12px;margin-bottom:8px">
      <div onclick="backToDomains()" class="back-btn" style="margin:0">← Back to Domains</div>
      <button type="button" class="btn btn-ghost" style="font-size:12px;padding:6px 12px;color:var(--accent-red);border-color:rgba(248,113,113,.35)" onclick='deleteDomainRecord(${JSON.stringify(domain)})'>Delete domain…</button>
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
            <th>Subdomain</th><th>Status</th><th>HTTP</th><th>HTTPS</th>
          </tr></thead>
          <tbody>
            ${!filtered.length
              ? `<tr><td colspan="4" style="text-align:center;padding:40px;color:var(--text-muted)">No results</td></tr>`
              : filtered.map(s => {
                  const sub = s.Subdomain || s.subdomain || '';
                  const live = s.IsLive || s.is_live;
                  const httpS = s.HTTPStatus || s.http_status || 0;
                  const httpsS = s.HTTPSStatus || s.https_status || 0;
                  return `<tr>
                    <td><span style="font-family:'JetBrains Mono',monospace;font-size:12px">${esc(sub)}</span></td>
                    <td>${live ? `<span class="badge badge-live">● live</span>` : `<span class="badge badge-dead">dead</span>`}</td>
                    <td><span style="font-size:12px;color:${httpColor(httpS)}">${httpS || '—'}</span></td>
                    <td><span style="font-size:12px;color:${httpColor(httpsS)}">${httpsS || '—'}</span></td>
                  </tr>`;
                }).join('')}
          </tbody>
        </table>
      </div>
    </div>`;
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
  const urlContainer  = document.getElementById('monitor-url-container');
  const subContainer  = document.getElementById('monitor-sub-container');
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
  const treeEl  = document.getElementById('r2-tree-list');
  const filesEl = document.getElementById('r2-files-list');
  const pathEl  = document.getElementById('r2-path');
  if (!treeEl || !filesEl) return;

  const { prefix, dirs, files } = state.r2;
  if (pathEl) pathEl.textContent = '/' + (prefix || '');

  // Tree — root always + current dirs
  let treeHtml = `<div class="r2-tree-item ${!prefix ? 'active' : ''}" onclick="loadR2('')">
    <span>📦</span><span style="overflow:hidden;text-overflow:ellipsis">root</span>
  </div>`;
  (dirs || []).forEach(d => {
    const name = d.replace(prefix, '').replace(/\/$/, '');
    treeHtml += `<div class="r2-tree-item" onclick="loadR2('${esc(d)}')">
      <span>📁</span><span style="overflow:hidden;text-overflow:ellipsis">${esc(name || d)}</span>
    </div>`;
  });
  treeEl.innerHTML = treeHtml;

  // Files list
  if (!files.length && !dirs.length) {
    filesEl.innerHTML = emptyState('📂', 'Empty folder', 'No files in this prefix.');
    return;
  }

  let html = '';
  // Show parent nav if in a sub-prefix
  if (prefix) {
    const parent = prefix.split('/').slice(0, -2).join('/');
    html += `<div class="r2-file-row" style="cursor:pointer" onclick="loadR2('${parent}')">
      <span class="r2-file-icon">⬆️</span>
      <span class="r2-file-name">.. (go up)</span>
    </div>`;
  }
  // Sub-dirs as clickable rows
  (dirs || []).forEach(d => {
    const name = d.replace(prefix, '').replace(/\/$/, '');
    html += `<div class="r2-file-row" style="cursor:pointer" onclick="loadR2('${esc(d)}')">
      <span class="r2-file-icon">📁</span>
      <span class="r2-file-name">${esc(name || d)}/</span>
      <span class="r2-file-size">—</span>
      <span class="r2-file-date">—</span>
    </div>`;
  });
  // Files
  (files || []).forEach(f => {
    const name = f.key.replace(prefix, '');
    const ext  = name.split('.').pop().toLowerCase();
    html += `<div class="r2-file-row">
      <span class="r2-file-icon">${fileIcon(ext)}</span>
      <span class="r2-file-name" title="${esc(f.key)}">${esc(name)}</span>
      <span class="r2-file-size">${fmtSize(f.size)}</span>
      <span class="r2-file-date">${fmtDate(f.last_modified)}</span>
      <a href="${esc(f.public_url)}" target="_blank" class="r2-download-btn" title="Download">⬇</a>
    </div>`;
  });
  filesEl.innerHTML = html;
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
      <div class="setting-card-header">🗄️ Supabase</div>
      ${row('URL', cfg.supabase_url || '—', cfg.supabase_url ? 'ok' : 'warn')}
      ${row('Status', cfg.supabase_url ? 'Configured' : 'Not set', cfg.supabase_url ? 'ok' : 'warn')}
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

function updateStatusDot() {
  const dot  = document.getElementById('status-dot');
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
    if (diff < 60000)   return 'just now';
    if (diff < 3600000) return `${Math.floor(diff/60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff/3600000)}h ago`;
    return `${Math.floor(diff/86400000)}d ago`;
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
  if (secs < 60)     return `${secs}s`;
  if (secs < 3600)   return `${Math.floor(secs / 60)}m`;
  return `${Math.floor(secs / 3600)}h`;
}

function statusBadge(status) {
  const map = {
    running:    'badge-running',
    starting:   'badge-starting',
    paused:     'badge-starting',
    done:       'badge-done',
    completed:  'badge-done',
    failed:     'badge-failed',
    error:      'badge-failed',
    cancelled:  'badge-starting',
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
  const map = { txt:'📄', log:'📋', json:'📊', zip:'📦', gz:'📦', html:'🌐',
                pdf:'📑', png:'🖼', jpg:'🖼', jpeg:'🖼', apk:'📱', ipa:'📱',
                db:'🗄', sql:'🗄', md:'📝' };
  return map[ext] || '📄';
}

function humanChangeType(t) {
  const map = {
    new_subdomain:   'New Subdomain',
    became_live:     'Host Came Online',
    became_dead:     'Host Went Down',
    content_changed: 'Content Changed',
    status_changed:  'Status Changed',
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
    if (!state.config.supabase_anon_key) {
      showAuthGate('Set SUPABASE_ANON_KEY on the API server (Supabase → Settings → API → anon public key).');
      return;
    }
    const sb = getSupabase();
    if (!sb) {
      showAuthGate('Could not initialize Supabase client (check browser console).');
      return;
    }
    const { data: { session } } = await sb.auth.getSession();
    if (!session) {
      state._authAccessToken = null;
      showAuthGate();
      wireAuthForm();
      return;
    }
    state._authAccessToken = session.access_token ?? null;
  }

  await startDashboard();
}

document.addEventListener('DOMContentLoaded', boot);

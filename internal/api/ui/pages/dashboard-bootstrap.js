(() => {
 // Show/hide the admin-only navigation for the signed-in identity. Runs on every
 // dashboard start (each login), so an admin signing in after a viewer gets the
 // full nav back. An unknown identity is treated as a viewer (UX only — the
 // server enforces roles). Inline display wins over the .nav-item CSS, which a
 // bare `hidden` attribute does not.
 // Member-restricted views: the whole Bug Bounty group, the System group and
// Monitor. Members see their own scans, triage, assets and the auditors.
const MEMBER_HIDDEN_VIEWS = ['targets', 'programs', 'program-lookup', 'cve-radar', 'findings', 'ports',
 'r2', 'report-templates', 'monitor', 'triage', 'ai-agent'];
window.MEMBER_HIDDEN_VIEWS = MEMBER_HIDDEN_VIEWS;

function applyRoleNav(me) {
 const isAdmin = !!(me && me.role === 'admin');
 const show = (el, on) => { if (el) el.style.display = on ? '' : 'none'; };
 // Settings stays reachable for everyone: non-admins only get its Users tab
 // (change own password).
 ['nav-monitor', 'nav-r2', 'nav-report-templates', 'sidebar-metrics'].forEach((id) => show(document.getElementById(id), isAdmin));
 // Members: hide the Bug Bounty group and the System group entirely — the
 // group heads and sub-items never render for them.
 if (!isAdmin) {
  ['nav-group-bb', 'nav-group-system'].forEach((id) => show(document.getElementById(id), false));
  MEMBER_HIDDEN_VIEWS.forEach((v) => show(document.getElementById('nav-' + v), false));
 }
 }

 // Drop everything the previous session loaded that a different user must not
 // see: cached credentials/inventory, rendered Settings/Monitor DOM, timers.
 function clearSessionState(state) {
 if (state._metricsTimer) { clearInterval(state._metricsTimer); state._metricsTimer = null; }
 if (state.pollTimer) { clearTimeout(state.pollTimer); state.pollTimer = null; }
 state.pollGen = (state.pollGen || 0) + 1; // stop any in-flight poll chain
 state._accounts = null;
 state._users = null;
 state._me = null;
 state._settingsTab = null;
 state._monitorSuggestCache = null;
 state.monitorTargets = [];
 state.subMonitorTargets = [];
 state.hunterMonitorTargets = [];
 state.monitorChanges = [];
 ['settings-container', 'monitor-url-container', 'monitor-sub-container', 'monitor-hunter-container', 'monitor-ai-suggest-results']
 .forEach((id) => { const el = document.getElementById(id); if (el) el.innerHTML = ''; });
 // Keep only the public config; the full payload is re-fetched after sign-in.
 if (state.config) {
 state.config = { version: state.config.version, auth_enabled: state.config.auth_enabled, auth_provider: state.config.auth_provider, public: true };
 }
 }

 async function startDashboard() {
 const state = window.state;
 if (state._dashboardStarted) return;
 window.hideAuthGate();

 // Before sign-in /api/config only returns a reduced public payload; load the
 // full one now that a session token exists.
 if (state.config && state.config.public) {
 try { await window.loadConfig(); } catch (_) { /* keep the public payload */ }
 }

 const so = document.getElementById('sign-out-btn');
 if (so) {
 so.style.display = state.config?.auth_enabled ? 'block' : 'none';
 so.onclick = async () => {
 // Best-effort server-side revocation (ends this user's sessions), then
 // clear client state.
 try {
 const tok = state._authAccessToken || window.localTokenGet();
 if (tok) {
 await fetch(`${window.API}/api/auth/logout`, {
 method: 'POST',
 headers: { Authorization: `Bearer ${tok}` },
 });
 }
 } catch (_) { /* ignore network errors on logout */ }
 window.localTokenClear();
 if (typeof window.clearAuditorTokenCookies === 'function') window.clearAuditorTokenCookies();
 clearSessionState(state);
 state._authAccessToken = null;
 state._dashboardStarted = false;
 window.showAuthGate();
 window.wireAuthForm();
 };
 }

 window.wireShellOnce();
 const backBtn = document.getElementById('scan-detail-back');
 if (backBtn && !backBtn.dataset.wired) {
 backBtn.dataset.wired = '1';
 backBtn.addEventListener('click', () => window.navigateTo('scans'));
 }

 // Set dynamic version and wire sidebar collapse toggle
 const versionEl = document.getElementById('logo-version');
 if (versionEl && state.config?.version) {
 versionEl.textContent = `v${state.config.version}`;
 }
 // Edition gating: the public edition hides edge-only controls (full-corpus
 // nuclei sweep, PoC-day race, scope autopilot). Elements marked with the
 // [data-edition-private] attribute are hidden by CSS when edition=public.
 const edition = state.config?.edition || 'private';
 window.APP_EDITION = edition;
 document.body.dataset.edition = edition;
 const collapseBtn = document.getElementById('sidebar-collapse-btn');
 const sidebarEl = document.getElementById('app-sidebar');
 if (collapseBtn && sidebarEl && !collapseBtn.dataset.wired) {
 collapseBtn.dataset.wired = '1';
 // Load saved state
 if (localStorage.getItem('autoar.sidebar.collapsed') === 'true') {
 sidebarEl.classList.add('collapsed');
 }
 collapseBtn.addEventListener('click', () => {
 sidebarEl.classList.toggle('collapsed');
 localStorage.setItem('autoar.sidebar.collapsed', sidebarEl.classList.contains('collapsed'));
 });
 }

 if (!window.__autoarPopstate) {
 window.__autoarPopstate = true;
 window.addEventListener('popstate', () => {
 const sid = window.pathScanId();
 if (sid) {
 window.openScanResultsPage(sid, { noHistory: true });
 } else {
 // Restore the view for the current URL (back/forward between sections)
 // without pushing a new history entry.
 window.navigateTo((window.viewForPath && window.viewForPath(location.pathname)) || 'overview', { noHistory: true });
 }
 });
 }
 await window.loadStats();
 // Load the current user's role up front so we can gate admin-only surfaces
 // (Monitor / R2 Browser / Report Templates; Settings shows only Users to
 // non-admins) before the first view renders (avoids a flash of the
 // restricted nav). If /api/auth/me fails the identity is unknown viewer.
 let me = null;
 try { me = await window.apiFetch('/api/auth/me'); } catch (e) { me = null; }
 window.state._me = me || { username: '', role: 'member', is_admin: false, auth_enforced: true };
 applyRoleNav(window.state._me);
 // System metrics are admin-only on the server.
 if (window.state._me.role === 'admin') window.startMetricsPolling();
 const deepScan = window.pathScanId();
 if (deepScan) {
 await window.openScanResultsPage(deepScan, { replace: true });
 } else {
 // Honor a per-view deep link on hard load (e.g. /settings, /monitor).
 window.navigateTo((window.viewForPath && window.viewForPath(location.pathname)) || 'overview');
 }
 // A 401 while starting (handleAuthError) already cleared the token and showed
 // the login form — stay "not started" so the next sign-in runs this again.
 state._dashboardStarted = !state.config?.auth_enabled || !!(state._authAccessToken || window.localTokenGet());
 }

 async function boot() {
 window.updateClock();
 setInterval(window.updateClock, 1000);

 await window.loadConfig();
 const state = window.state;

 if (state.config?.auth_enabled) {
 const stored = window.localTokenGet();
 if (stored) {
 state._authAccessToken = stored;
 try {
 const probe = await fetch(`${window.API}/api/dashboard/stats`, {
 headers: { Authorization: `Bearer ${stored}` },
 });
 if (probe.status === 401) {
 window.localTokenClear();
 state._authAccessToken = null;
 window.showAuthGate();
 window.wireAuthForm();
 return;
 }
 } catch {
 // Network error; continue and fail gracefully on data requests.
 }
 } else {
 window.showAuthGate();
 window.wireAuthForm();
 return;
 }
 }

 await startDashboard();
 }

 window.DashboardBootstrapPage = {
 startDashboard,
 boot,
 clearSessionState,
 };
})();

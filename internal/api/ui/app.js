/**
 * AutoAR Dashboard — app.js
 * Vanilla JS SPA: router, data fetching, component rendering
 * Bundle: v4.0 — dashboard UI; scan merge, R2, monitors, auth
 */

// ── Constants ─────────────────────────────────────────────────────────────────

const APP_CONFIG_STATE = window.AppConfigState || {};
const API = APP_CONFIG_STATE.API || '';
const POLL_INTERVAL = APP_CONFIG_STATE.POLL_INTERVAL || 15000;
const POLL_FAST_SCANS = APP_CONFIG_STATE.POLL_FAST_SCANS || 3500;
const POLL_FAST_ANY = APP_CONFIG_STATE.POLL_FAST_ANY || 7000;
// Scan detail real-time refresh state (declared early so openScanResultsPage can use them)
let _scanDetailRefreshTimer = null;
let _scanDetailRefreshId = null;
let _scanDetailKnownFiles = new Set();
let _assetsCache = null;


// ── Utilities ─────────────────────────────────────────────────────────────────

function resolvePageMethod(pageKey, name) {
  const page = window[pageKey];
  return page && typeof page[name] === 'function' ? page[name] : null;
}

function callPageMethod(pageKey, name, args = [], fallback) {
  const fn = resolvePageMethod(pageKey, name);
  return fn ? fn(...args) : fallback;
}

function clipboardUtilsPageMethod(name) {
  return resolvePageMethod('ClipboardUtilsPage', name);
}

async function copyToClipboard(text) {
  const fn = clipboardUtilsPageMethod('copyToClipboard');
  if (fn) return fn(text);
}

// ── State ─────────────────────────────────────────────────────────────────────

const state = APP_CONFIG_STATE.state || {};

// ── Router ────────────────────────────────────────────────────────────────────

const VIEWS = APP_CONFIG_STATE.VIEWS || [];

function navigationUIPageMethod(name) {
  return resolvePageMethod('NavigationUIPage', name);
}

function routerCorePageMethod(name) {
  return resolvePageMethod('RouterCorePage', name);
}

function routerNavigationPageMethod(name) {
  return resolvePageMethod('RouterNavigationPage', name);
}

function pathScanId() {
  return callPageMethod('RouterCorePage', 'pathScanId', [], null);
}

function openAuditorInNewTab(view) {
  const fn = navigationUIPageMethod('openAuditorInNewTab');
  if (fn) return fn(view);
}

function navigateTo(view) {
  const fn = routerNavigationPageMethod('navigateTo');
  if (fn) return fn(view);
}

/** Deep-linked scan results page (/scans/:id). */
async function openScanResultsPage(scanId, opts = {}) {
  const fn = routerCorePageMethod('openScanResultsPage');
  if (fn) return fn(scanId, opts);
}


function viewTitle(v) {
  return callPageMethod('NavigationUIPage', 'viewTitle', [v], v);
}

// ── API Helpers (Local JWT auth) ─────────────────────────────────────────────

function authSessionPageMethod(name) {
  return resolvePageMethod('AuthSessionPage', name);
}

function apiClientPageMethod(name) {
  return resolvePageMethod('ApiClientPage', name);
}

function localTokenGet() {
  return callPageMethod('AuthSessionPage', 'localTokenGet', [], null);
}
function localTokenSet(tok) {
  const fn = authSessionPageMethod('localTokenSet');
  if (fn) return fn(tok);
}
function localTokenClear() {
  const fn = authSessionPageMethod('localTokenClear');
  if (fn) return fn();
}

async function buildAuthHeaders(extra = {}) {
  return callPageMethod('ApiClientPage', 'buildAuthHeaders', [extra], { ...extra });
}

function handleAuthError() {
  const fn = apiClientPageMethod('handleAuthError');
  if (fn) return fn();
}

async function apiFetch(path) {
  const fn = apiClientPageMethod('apiFetch');
  if (fn) return fn(path);
  throw new Error('apiFetch unavailable');
}

async function apiPost(path, body, customHeaders = {}) {
  const fn = apiClientPageMethod('apiPost');
  if (fn) return fn(path, body, customHeaders);
  throw new Error('apiPost unavailable');
}

async function apiDelete(path) {
  const fn = apiClientPageMethod('apiDelete');
  if (fn) return fn(path);
  throw new Error('apiDelete unavailable');
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
  return resolvePageMethod('ScanActionsPage', name);
}

function domainActionsPageMethod(name) {
  return resolvePageMethod('DomainActionsPage', name);
}

function appCoreActionsPageMethod(name) {
  return resolvePageMethod('AppCoreActionsPage', name);
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
  const fn = domainActionsPageMethod('deleteDomainRecord');
  if (fn) return fn(domain);
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
  const fn = appCoreActionsPageMethod('loadResource');
  if (fn) return fn(key, path, stateKey);
}

// ── Data Loading ──────────────────────────────────────────────────────────────

function settingsPageMethod(name) {
  return resolvePageMethod('SettingsPage', name);
}

function dashboardDataPageMethod(name) {
  return resolvePageMethod('DashboardDataPage', name);
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
  return resolvePageMethod('ShellWiringPage', name);
}

function wireShellOnce() {
  const fn = shellWiringPageMethod('wireShellOnce');
  if (fn) return fn();
}

function dashboardBootstrapPageMethod(name) {
  return resolvePageMethod('DashboardBootstrapPage', name);
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
  return resolvePageMethod('MonitorPage', name);
}

async function loadMonitor() {
  const fn = monitorPageMethod('loadMonitor');
  if (fn) return fn();
}

function r2PageMethod(name) {
  return resolvePageMethod('R2Page', name);
}

function r2PrefixesPageMethod(name) {
  return resolvePageMethod('R2PrefixesPage', name);
}

function domainR2ActionsPageMethod(name) {
  return resolvePageMethod('DomainR2ActionsPage', name);
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
  return resolvePageMethod('PollingPage', name);
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
  return callPageMethod('R2PrefixesPage', 'targetToHostname', [target], '');
}

function uniquePrefixList(prefixes) {
  return callPageMethod('R2PrefixesPage', 'uniquePrefixList', [prefixes], []);
}

/**
 * R2 key prefixes to search per scan type (mirrors local new-results/ layout + UploadResultsDirectory results/).
 */
function r2PrefixesForScan(target, scanType) {
  return callPageMethod('R2PrefixesPage', 'r2PrefixesForScan', [target, scanType], []);
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

function scanDetailPaginationPageMethod(name) {
  return resolvePageMethod('ScanDetailPaginationPage', name);
}

/** Pagination: previous page of files */
function prevFilesPage(scanId) {
  const fn = scanDetailPaginationPageMethod('prevFilesPage');
  if (fn) return fn(scanId);
}

/** Pagination: next page of files */
function nextFilesPage(scanId, total) {
  const fn = scanDetailPaginationPageMethod('nextFilesPage');
  if (fn) return fn(scanId, total);
}

// ── Renderers ─────────────────────────────────────────────────────────────────

function overviewPageMethod(name) {
  return resolvePageMethod('OverviewPage', name);
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
  return callPageMethod('OverviewPage', 'changeItemHtml', [c], '');
}

function scansPageMethod(name) {
  return resolvePageMethod('ScansPage', name);
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
  return callPageMethod('ScansPage', 'scanItemHtml', [s], '');
}

function scanRowHtml(s) {
  return callPageMethod('ScansPage', 'scanRowHtml', [s], '');
}

// ── Scan results page (/scans/:id) ─────────────────────────────────────────────

/** Determine file type category from filename for icon display */
function scanCommonPageMethod(name) {
  return resolvePageMethod('ScanCommonPage', name);
}

function scanResultsCorePageMethod(name) {
  return resolvePageMethod('ScanResultsCorePage', name);
}

function categoryDisplayPageMethod(name) {
  return resolvePageMethod('CategoryDisplayPage', name);
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
  const fn = scanCommonPageMethod('categorizeScanArtifactFile');
  if (fn) return fn(fileName);
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

function findingsRowsPageMethod(name) {
  return resolvePageMethod('FindingsRowsPage', name);
}

function getUnifiedTableColumns(activeKind) {
  return callPageMethod('FindingsRowsPage', 'getUnifiedTableColumns', [activeKind], ['TARGET', 'SEV', 'VULNERABILITY TYPE', 'MODULE']);
}

function renderRowForUnifiedTab(r, idx, activeKind, modInfo, sevMeta) {
  return callPageMethod('FindingsRowsPage', 'renderRowForUnifiedTab', [r, idx, activeKind, modInfo, sevMeta], '');
}

function renderDefaultRow(r, idx, modInfo, sevMeta) {
  return callPageMethod('FindingsRowsPage', 'renderDefaultRow', [r, idx, modInfo, sevMeta], '');
}

function renderJSAnalysisRow(r, idx, modInfo, sevMeta) {
  return callPageMethod('FindingsRowsPage', 'renderJSAnalysisRow', [r, idx, modInfo, sevMeta], '');
}

function renderNucleiRow(r, idx, modInfo, sevMeta) {
  return callPageMethod('FindingsRowsPage', 'renderNucleiRow', [r, idx, modInfo, sevMeta], '');
}

function renderGFPatternsRow(r, idx, modInfo, sevMeta) {
  return callPageMethod('FindingsRowsPage', 'renderGFPatternsRow', [r, idx, modInfo, sevMeta], '');
}

/** Get category display info */
function getCategoryDisplayInfo(category) {
  const fn = categoryDisplayPageMethod('getCategoryDisplayInfo');
  if (fn) return fn(category);
  return { icon: '📄', name: 'File', badge: '' };
}

function parseNucleiFindingLine(line) {
  return callPageMethod('ScanResultsCorePage', 'parseNucleiFindingLine', [line], null);
}

function scanDetailAsmPageMethod(name) {
  return resolvePageMethod('ScanDetailAsmPage', name);
}

function scanArtifactRowHtml(f) {
  return callPageMethod('ScanDetailAsmPage', 'scanArtifactRowHtml', [f], '');
}

function scanAsmSectionHtml(id, icon, title, subtitle, files, emptyNote) {
  return callPageMethod('ScanDetailAsmPage', 'scanAsmSectionHtml', [id, icon, title, subtitle, files, emptyNote], '');
}

async function loadScanDetailVulnerabilityInsights(scanId, allFiles) {
  const fn = scanDetailAsmPageMethod('loadScanDetailVulnerabilityInsights');
  if (fn) return fn(scanId, allFiles);
}

function wireScanFileRows(container, scanId) {
  const fn = scanDetailAsmPageMethod('wireScanFileRows');
  if (fn) return fn(container, scanId);
}

/** Group files by module */
function groupFilesByModule(files) {
  const fn = scanResultsCorePageMethod('groupFilesByModule');
  if (fn) return fn(files);
  return {};
}

/** Parse and render results from a JSON file */
async function parseAndRenderResults(scanId, file, container) {
  const fn = scanResultsCorePageMethod('parseAndRenderResults');
  if (fn) return fn(scanId, file, container);
}

/** Detect what type of results we're dealing with */
function detectResultType(items, file) {
  const fn = scanResultsCorePageMethod('detectResultType');
  if (fn) return fn(items, file);
  return 'generic-json';
}

/** Render appropriate table based on result type */
function renderResultTable(items, type, file) {
  if (window.ResultTablesPage && typeof window.ResultTablesPage.renderResultTable === 'function') {
    return window.ResultTablesPage.renderResultTable(items, type, file);
  }
  return '';
}

function scanResultsUtilsPageMethod(name) {
  return resolvePageMethod('ScanResultsUtilsPage', name);
}

/** Filter files based on search query and filters */
function filterScanFiles(files, searchQuery, filters = {}) {
  const fn = scanResultsUtilsPageMethod('filterScanFiles');
  if (fn) return fn(files, searchQuery, filters);
  return files;
}

/** Render module badge */
function renderModuleBadge(module) {
  return callPageMethod('ScanResultsUtilsPage', 'renderModuleBadge', [module], '');
}

/** Render category badge */
function renderCategoryBadge(category) {
  return callPageMethod('ScanResultsUtilsPage', 'renderCategoryBadge', [category], '');
}

/** Copy all results to clipboard */
async function copyAllScanResults(scanId) {
  const fn = scanResultsUtilsPageMethod('copyAllScanResults');
  if (fn) return fn(scanId);
}

function scanDetailPageMethod(name) {
  return resolvePageMethod('ScanDetailPage', name);
}

function domainsPageMethod(name) {
  return resolvePageMethod('DomainsPage', name);
}

/** Render scan results with enhanced filtering and module display */
async function renderScanDetailView(scanId) {
  const fn = scanDetailPageMethod('renderScanDetailView');
  if (fn) return fn(scanId);
}

async function loadReconUnifiedTable(scanId, files, containerId, scan) {
  const fn = scanDetailPageMethod('loadReconUnifiedTable');
  if (fn) return fn(scanId, files, containerId, scan);
}

function wireScanDetailFilters(scanId, files) {
  const fn = scanDetailPageMethod('wireScanDetailFilters');
  if (fn) return fn(scanId, files);
}

async function loadScanFilePreview(scanId, fileName, opts) {
  const fn = scanDetailPageMethod('loadScanFilePreview');
  if (fn) return fn(scanId, fileName, opts);
}

function clearScanDetailRefreshTimer() {
  const fn = scanDetailPageMethod('clearScanDetailRefreshTimer');
  if (fn) return fn();
}

function scheduleScanDetailRefresh(scanId, ms) {
  const fn = scanDetailPageMethod('scheduleScanDetailRefresh');
  if (fn) return fn(scanId, ms);
}

function refreshScanDetailIfRunning(scanId) {
  const fn = scanDetailPageMethod('doScanDetailRefresh');
  if (fn) return fn(scanId);
}

function clearApkxCacheForScan(scan) {
  const fn = scanDetailPageMethod('clearApkxCacheForScan');
  if (fn) return fn(scan);
}

function renderDomainGrid() {
  const fn = domainsPageMethod('renderDomainGrid');
  if (fn) return fn();
}

function renderSubdomainView(domain) {
  const fn = domainsPageMethod('renderSubdomainView');
  if (fn) return fn(domain);
}

function renderSubdomainsPage() {
  const fn = domainsPageMethod('renderSubdomainsPage');
  if (fn) return fn();
}

function backToDomains() {
  const fn = domainsPageMethod('backToDomains');
  if (fn) return fn();
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
  const fn = appCoreActionsPageMethod('updateStatusDot');
  if (fn) return fn();
}

// ── Scan Launcher ─────────────────────────────────────────────────────────────

function launcherPageMethod(name) {
  return resolvePageMethod('LauncherPage', name);
}

function htmlEscapePageMethod(name) {
  return resolvePageMethod('HtmlEscapePage', name);
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
  const fn = htmlEscapePageMethod('esc');
  if (fn) return fn(s);
  return String(s ?? '');
}

/** Escape for HTML attribute values (e.g. data-r2-prefix). */
function escAttr(s) {
  const fn = htmlEscapePageMethod('escAttr');
  if (fn) return fn(s);
  return String(s ?? '');
}

function uiHelpersMethod(name) {
  return resolvePageMethod('UIHelpers', name);
}

function formatUtilsPageMethod(name) {
  return resolvePageMethod('FormatUtilsPage', name);
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
  return callPageMethod('FormatUtilsPage', 'elapsedStr', [start], '');
}

function elapsedBetween(start, end) {
  return callPageMethod('FormatUtilsPage', 'elapsedBetween', [start, end], '—');
}

function fmtSize(bytes) {
  const fn = formatUtilsPageMethod('fmtSize');
  if (fn) return fn(bytes);
  return '0 B';
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
  const fn = appCoreActionsPageMethod('manualRefresh');
  if (fn) return fn();
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
  return resolvePageMethod('TargetsPage', name);
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
  return resolvePageMethod('OpsToolsPage', name);
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
  return resolvePageMethod('ReportTemplatesPage', name);
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


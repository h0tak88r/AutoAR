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
// Scan detail real-time refresh state (declared early so openScanResultsPage can use them)
let _scanDetailRefreshTimer = null;
let _scanDetailRefreshId = null;
let _scanDetailKnownFiles = new Set();
let _assetsCache = null;


// ── Utilities ─────────────────────────────────────────────────────────────────

function clipboardUtilsPageMethod(name) {
  return window.ClipboardUtilsPage && typeof window.ClipboardUtilsPage[name] === 'function'
    ? window.ClipboardUtilsPage[name]
    : null;
}

async function copyToClipboard(text) {
  const fn = clipboardUtilsPageMethod('copyToClipboard');
  if (fn) return fn(text);
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

function navigationUIPageMethod(name) {
  return window.NavigationUIPage && typeof window.NavigationUIPage[name] === 'function'
    ? window.NavigationUIPage[name]
    : null;
}

function routerCorePageMethod(name) {
  return window.RouterCorePage && typeof window.RouterCorePage[name] === 'function'
    ? window.RouterCorePage[name]
    : null;
}

function routerNavigationPageMethod(name) {
  return window.RouterNavigationPage && typeof window.RouterNavigationPage[name] === 'function'
    ? window.RouterNavigationPage[name]
    : null;
}

function pathScanId() {
  const fn = routerCorePageMethod('pathScanId');
  if (fn) return fn();
  return null;
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
  const fn = navigationUIPageMethod('viewTitle');
  if (fn) return fn(v);
  return v;
}

// ── API Helpers (Local JWT auth) ─────────────────────────────────────────────

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
  return null;
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
  const fn = apiClientPageMethod('buildAuthHeaders');
  if (fn) return fn(extra);
  return { ...extra };
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
  return window.ScanActionsPage && typeof window.ScanActionsPage[name] === 'function'
    ? window.ScanActionsPage[name]
    : null;
}

function domainActionsPageMethod(name) {
  return window.DomainActionsPage && typeof window.DomainActionsPage[name] === 'function'
    ? window.DomainActionsPage[name]
    : null;
}

function appCoreActionsPageMethod(name) {
  return window.AppCoreActionsPage && typeof window.AppCoreActionsPage[name] === 'function'
    ? window.AppCoreActionsPage[name]
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
  return '';
}

function uniquePrefixList(prefixes) {
  const fn = r2PrefixesPageMethod('uniquePrefixList');
  if (fn) return fn(prefixes);
  return [];
}

/**
 * R2 key prefixes to search per scan type (mirrors local new-results/ layout + UploadResultsDirectory results/).
 */
function r2PrefixesForScan(target, scanType) {
  const fn = r2PrefixesPageMethod('r2PrefixesForScan');
  if (fn) return fn(target, scanType);
  return [];
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
  return window.ScanDetailPaginationPage && typeof window.ScanDetailPaginationPage[name] === 'function'
    ? window.ScanDetailPaginationPage[name]
    : null;
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

function scanResultsCorePageMethod(name) {
  return window.ScanResultsCorePage && typeof window.ScanResultsCorePage[name] === 'function'
    ? window.ScanResultsCorePage[name]
    : null;
}

function categoryDisplayPageMethod(name) {
  return window.CategoryDisplayPage && typeof window.CategoryDisplayPage[name] === 'function'
    ? window.CategoryDisplayPage[name]
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
  return window.FindingsRowsPage && typeof window.FindingsRowsPage[name] === 'function'
    ? window.FindingsRowsPage[name]
    : null;
}

function getUnifiedTableColumns(activeKind) {
  const fn = findingsRowsPageMethod('getUnifiedTableColumns');
  if (fn) return fn(activeKind);
  return ['TARGET', 'SEV', 'VULNERABILITY TYPE', 'MODULE'];
}

function renderRowForUnifiedTab(r, idx, activeKind, modInfo, sevMeta) {
  const fn = findingsRowsPageMethod('renderRowForUnifiedTab');
  if (fn) return fn(r, idx, activeKind, modInfo, sevMeta);
  return '';
}

function renderDefaultRow(r, idx, modInfo, sevMeta) {
  const fn = findingsRowsPageMethod('renderDefaultRow');
  if (fn) return fn(r, idx, modInfo, sevMeta);
  return '';
}

function renderJSAnalysisRow(r, idx, modInfo, sevMeta) {
  const fn = findingsRowsPageMethod('renderJSAnalysisRow');
  if (fn) return fn(r, idx, modInfo, sevMeta);
  return '';
}

function renderNucleiRow(r, idx, modInfo, sevMeta) {
  const fn = findingsRowsPageMethod('renderNucleiRow');
  if (fn) return fn(r, idx, modInfo, sevMeta);
  return '';
}

function renderGFPatternsRow(r, idx, modInfo, sevMeta) {
  const fn = findingsRowsPageMethod('renderGFPatternsRow');
  if (fn) return fn(r, idx, modInfo, sevMeta);
  return '';
}

/** Get category display info */
function getCategoryDisplayInfo(category) {
  const fn = categoryDisplayPageMethod('getCategoryDisplayInfo');
  if (fn) return fn(category);
  return { icon: '📄', name: 'File', badge: '' };
}

function parseNucleiFindingLine(line) {
  const fn = scanResultsCorePageMethod('parseNucleiFindingLine');
  if (fn) return fn(line);
  return null;
}

function scanDetailAsmPageMethod(name) {
  return window.ScanDetailAsmPage && typeof window.ScanDetailAsmPage[name] === 'function'
    ? window.ScanDetailAsmPage[name]
    : null;
}

function scanArtifactRowHtml(f) {
  const fn = scanDetailAsmPageMethod('scanArtifactRowHtml');
  if (fn) return fn(f);
  return '';
}

function scanAsmSectionHtml(id, icon, title, subtitle, files, emptyNote) {
  const fn = scanDetailAsmPageMethod('scanAsmSectionHtml');
  if (fn) return fn(id, icon, title, subtitle, files, emptyNote);
  return '';
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

function scanResultsUtilsPageMethod(name) {
  return window.ScanResultsUtilsPage && typeof window.ScanResultsUtilsPage[name] === 'function'
    ? window.ScanResultsUtilsPage[name]
    : null;
}

/** Filter files based on search query and filters */
function filterScanFiles(files, searchQuery, filters = {}) {
  const fn = scanResultsUtilsPageMethod('filterScanFiles');
  if (fn) return fn(files, searchQuery, filters);
  return files;
}

/** Render module badge */
function renderModuleBadge(module) {
  const fn = scanResultsUtilsPageMethod('renderModuleBadge');
  if (fn) return fn(module);
  return '';
}

/** Render category badge */
function renderCategoryBadge(category) {
  const fn = scanResultsUtilsPageMethod('renderCategoryBadge');
  if (fn) return fn(category);
  return '';
}

/** Copy all results to clipboard */
async function copyAllScanResults(scanId) {
  const fn = scanResultsUtilsPageMethod('copyAllScanResults');
  if (fn) return fn(scanId);
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
  const fn = appCoreActionsPageMethod('updateStatusDot');
  if (fn) return fn();
}

// ── Scan Launcher ─────────────────────────────────────────────────────────────

function launcherPageMethod(name) {
  return window.LauncherPage && typeof window.LauncherPage[name] === 'function'
    ? window.LauncherPage[name]
    : null;
}

function htmlEscapePageMethod(name) {
  return window.HtmlEscapePage && typeof window.HtmlEscapePage[name] === 'function'
    ? window.HtmlEscapePage[name]
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
  return window.UIHelpers && typeof window.UIHelpers[name] === 'function'
    ? window.UIHelpers[name]
    : null;
}

function formatUtilsPageMethod(name) {
  return window.FormatUtilsPage && typeof window.FormatUtilsPage[name] === 'function'
    ? window.FormatUtilsPage[name]
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
  const fn = formatUtilsPageMethod('elapsedStr');
  if (fn) return fn(start);
  return '';
}

function elapsedBetween(start, end) {
  const fn = formatUtilsPageMethod('elapsedBetween');
  if (fn) return fn(start, end);
  return '—';
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


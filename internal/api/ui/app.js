/**
 * AutoAR Dashboard — app.js
 * Vanilla JS SPA: router, data fetching, component rendering
 * Bundle: v4.0 — dashboard UI; scan merge, R2, monitors, auth
 */

// ── Constants ─────────────────────────────────────────────────────────────────

const APP_CONFIG_STATE = window.AppConfigState || {};
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

function pathScanId() {
  return callPageMethod('RouterCorePage', 'pathScanId', [], null);
}

function openAuditorInNewTab(view) {
  return callPageMethod('NavigationUIPage', 'openAuditorInNewTab', [view]);
}

function navigateTo(view) {
  return callPageMethod('RouterNavigationPage', 'navigateTo', [view]);
}

/** Deep-linked scan results page (/scans/:id). */
async function openScanResultsPage(scanId, opts = {}) {
  return callPageMethod('RouterCorePage', 'openScanResultsPage', [scanId, opts]);
}


function viewTitle(v) {
  return callPageMethod('NavigationUIPage', 'viewTitle', [v], v);
}

// ── API Helpers (Local JWT auth) ─────────────────────────────────────────────

function localTokenGet() {
  return callPageMethod('AuthSessionPage', 'localTokenGet', [], null);
}
function localTokenSet(tok) {
  return callPageMethod('AuthSessionPage', 'localTokenSet', [tok]);
}
function localTokenClear() {
  return callPageMethod('AuthSessionPage', 'localTokenClear');
}

async function buildAuthHeaders(extra = {}) {
  return callPageMethod('ApiClientPage', 'buildAuthHeaders', [extra], { ...extra });
}

function handleAuthError() {
  return callPageMethod('ApiClientPage', 'handleAuthError');
}

async function apiFetch(path) {
  const v = callPageMethod('ApiClientPage', 'apiFetch', [path]);
  if (v !== undefined) return v;
  throw new Error('apiFetch unavailable');
}

async function apiPost(path, body, customHeaders = {}) {
  const v = callPageMethod('ApiClientPage', 'apiPost', [path, body, customHeaders]);
  if (v !== undefined) return v;
  throw new Error('apiPost unavailable');
}

async function apiDelete(path) {
  const v = callPageMethod('ApiClientPage', 'apiDelete', [path]);
  if (v !== undefined) return v;
  throw new Error('apiDelete unavailable');
}

function showAuthGate(hintMsg) {
  return callPageMethod('AuthSessionPage', 'showAuthGate', [hintMsg]);
}

function hideAuthGate() {
  return callPageMethod('AuthSessionPage', 'hideAuthGate');
}

async function cancelScan(scanID) {
  return callPageMethod('ScanActionsPage', 'cancelScan', [scanID]);
}

async function deleteScan(scanID, target = '') {
  return callPageMethod('ScanActionsPage', 'deleteScan', [scanID, target]);
}

async function rescanScan(scanID) {
  return callPageMethod('ScanActionsPage', 'rescanScan', [scanID]);
}

function toggleSelectAllRecentScans(master) {
  return callPageMethod('ScanActionsPage', 'toggleSelectAllRecentScans', [master]);
}

async function deleteSelectedScans() {
  return callPageMethod('ScanActionsPage', 'deleteSelectedScans');
}

async function clearAllScans() {
  return callPageMethod('ScanActionsPage', 'clearAllScans');
}

async function deleteDomainRecord(domain) {
  return callPageMethod('DomainActionsPage', 'deleteDomainRecord', [domain]);
}

async function pauseScan(scanID) {
  return callPageMethod('ScanActionsPage', 'pauseScan', [scanID]);
}

async function resumeScan(scanID) {
  return callPageMethod('ScanActionsPage', 'resumeScan', [scanID]);
}

async function loadResource(key, path, stateKey) {
  return callPageMethod('AppCoreActionsPage', 'loadResource', [key, path, stateKey]);
}

// ── Data Loading ──────────────────────────────────────────────────────────────

async function loadConfig() {
  return callPageMethod('SettingsPage', 'loadConfig');
}

function wireAuthForm() {
  return callPageMethod('AuthSessionPage', 'wireAuthForm');
}

function wireShellOnce() {
  return callPageMethod('ShellWiringPage', 'wireShellOnce');
}

async function startDashboard() {
  return callPageMethod('DashboardBootstrapPage', 'startDashboard');
}

async function loadStats() {
  return callPageMethod('DashboardDataPage', 'loadStats');
}

async function loadDomains() {
  return callPageMethod('DashboardDataPage', 'loadDomains');
}

async function loadSubdomains(page = 1, search = '') {
  return callPageMethod('DashboardDataPage', 'loadSubdomains', [page, search]);
}

/** Copy every subdomain string matching the current search (paginates at API max page size). */
async function copyAllSubdomainsMatching() {
  const fn = domainsPageMethod('copyAllSubdomainsMatching');
  if (fn) return fn();
}

async function loadScans() {
  return callPageMethod('DashboardDataPage', 'loadScans');
}

async function loadMonitor() {
  return callPageMethod('MonitorPage', 'loadMonitor');
}

async function loadR2(prefix = '') {
  return callPageMethod('R2Page', 'loadR2', [prefix]);
}

function wireR2BrowserOnce() {
  return callPageMethod('R2Page', 'wireR2BrowserOnce');
}

function r2UpdateDeleteSelectedVisibility() {
  return callPageMethod('R2Page', 'r2UpdateDeleteSelectedVisibility');
}
function r2DeletePrefixInteractive(prefix) {
  return callPageMethod('R2Page', 'r2DeletePrefixInteractive', [prefix]);
}
function r2DeleteKeyInteractive(key) {
  return callPageMethod('R2Page', 'r2DeleteKeyInteractive', [key]);
}
function r2DeleteSelected() {
  return callPageMethod('R2Page', 'r2DeleteSelected');
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
  return callPageMethod('DomainR2ActionsPage', 'browseR2ForScan', [target, scanType]);
}

async function loadDomainSubdomains(domain) {
  return callPageMethod('DomainR2ActionsPage', 'loadDomainSubdomains', [domain]);
}

// ── Polling ───────────────────────────────────────────────────────────────────

function startPolling() {
  return callPageMethod('PollingPage', 'startPolling');
}

function refreshCurrentView() {
  return callPageMethod('PollingPage', 'refreshCurrentView');
}

/** Pagination: previous page of files */
function prevFilesPage(scanId) {
  return callPageMethod('ScanDetailPaginationPage', 'prevFilesPage', [scanId]);
}

/** Pagination: next page of files */
function nextFilesPage(scanId, total) {
  return callPageMethod('ScanDetailPaginationPage', 'nextFilesPage', [scanId, total]);
}

// ── Renderers ─────────────────────────────────────────────────────────────────

function renderStats() {
  return callPageMethod('OverviewPage', 'renderStats');
}

function renderOverviewActiveScans() {
  return callPageMethod('OverviewPage', 'renderOverviewActiveScans');
}

// ── System Metrics ────────────────────────────────────────────────────────────

function startMetricsPolling() {
  return callPageMethod('OverviewPage', 'startMetricsPolling');
}

function updateMetricsUI(data) {
  return callPageMethod('OverviewPage', 'updateMetricsUI', [data]);
}

function renderRecentChanges() {
  return callPageMethod('OverviewPage', 'renderRecentChanges');
}

function changeItemHtml(c) {
  return callPageMethod('OverviewPage', 'changeItemHtml', [c], '');
}

function renderScans() {
  return callPageMethod('ScansPage', 'renderScans');
}


/**
 * Return a human-friendly badge label + optional icon for a raw scan_type string.
 * Falls back to capitalising the raw value if no mapping exists.
 */
function scanTypeLabel(rawType) {
  return callPageMethod('ScansPage', 'scanTypeLabel', [rawType], rawType);
}

function scanItemHtml(s) {
  return callPageMethod('ScansPage', 'scanItemHtml', [s], '');
}

function scanRowHtml(s) {
  return callPageMethod('ScansPage', 'scanRowHtml', [s], '');
}

// ── Scan results page (/scans/:id) ─────────────────────────────────────────────

function getFileTypeFromName(fileName) {
  return callPageMethod('ScanCommonPage', 'getFileTypeFromName', [fileName], 'text');
}

/** Get icon emoji for file type */
function getFileTypeIcon(fileType) {
  return callPageMethod('ScanCommonPage', 'getFileTypeIcon', [fileType], '📄');
}

/** Toggle collapsible sections */
function toggleCollapsible(header) {
  return callPageMethod('ScanCommonPage', 'toggleCollapsible', [header]);
}

/** Switch between scan detail tabs */
function switchScanDetailTab(tabName) {
  return callPageMethod('ScanCommonPage', 'switchScanDetailTab', [tabName]);
}

/** Format JSON with syntax highlighting */
function formatJSONWithHighlighting(jsonObj) {
  return callPageMethod('ScanCommonPage', 'formatJSONWithHighlighting', [jsonObj], '');
}

/** Apply syntax highlighting to JSON string */
function syntaxHighlightJSON(json) {
  return callPageMethod('ScanCommonPage', 'syntaxHighlightJSON', [json], '');
}

/** Plain-text line when a finished scan has no indexed artifacts (aligned with Discord phaseNoResultsMessage). */
function scanNoArtifactsMessage(scanType, target) {
  return callPageMethod('ScanCommonPage', 'scanNoArtifactsMessage', [scanType, target], '[ ⚪ ] No artifacts');
}

function goToScanResultsPage(scanID) {
  if (!scanID) return;
  openScanResultsPage(scanID);
}

/** Categorize scan artifacts for ASM-style layout (recon / vulns / other). */
function categorizeScanArtifactFile(fileName) {
  return callPageMethod('ScanCommonPage', 'categorizeScanArtifactFile', [fileName], 'other');
}

/** Detect module from filename */
function detectModuleFromFileName(fileName, existingModule) {
  return callPageMethod('ScanCommonPage', 'detectModuleFromFileName', [fileName, existingModule], (existingModule || 'unknown'));
}

/** Get module display name with icon */
function normalizeModuleKey(module) {
  return callPageMethod('ScanCommonPage', 'normalizeModuleKey', [module], (String(module || '').toLowerCase().trim() || 'unknown'));
}

/** Get module display name with icon */
function getModuleDisplayInfo(module) {
  return callPageMethod('ScanCommonPage', 'getModuleDisplayInfo', [module], { icon: '❓', name: 'Unknown', color: '#64748b' });
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
  return callPageMethod('CategoryDisplayPage', 'getCategoryDisplayInfo', [category], { icon: '📄', name: 'File', badge: '' });
}

function parseNucleiFindingLine(line) {
  return callPageMethod('ScanResultsCorePage', 'parseNucleiFindingLine', [line], null);
}

function scanArtifactRowHtml(f) {
  return callPageMethod('ScanDetailAsmPage', 'scanArtifactRowHtml', [f], '');
}

function scanAsmSectionHtml(id, icon, title, subtitle, files, emptyNote) {
  return callPageMethod('ScanDetailAsmPage', 'scanAsmSectionHtml', [id, icon, title, subtitle, files, emptyNote], '');
}

async function loadScanDetailVulnerabilityInsights(scanId, allFiles) {
  return callPageMethod('ScanDetailAsmPage', 'loadScanDetailVulnerabilityInsights', [scanId, allFiles]);
}

function wireScanFileRows(container, scanId) {
  return callPageMethod('ScanDetailAsmPage', 'wireScanFileRows', [container, scanId]);
}

/** Group files by module */
function groupFilesByModule(files) {
  return callPageMethod('ScanResultsCorePage', 'groupFilesByModule', [files], {});
}

/** Parse and render results from a JSON file */
async function parseAndRenderResults(scanId, file, container) {
  return callPageMethod('ScanResultsCorePage', 'parseAndRenderResults', [scanId, file, container]);
}

/** Detect what type of results we're dealing with */
function detectResultType(items, file) {
  return callPageMethod('ScanResultsCorePage', 'detectResultType', [items, file], 'generic-json');
}

/** Render appropriate table based on result type */
function renderResultTable(items, type, file) {
  if (window.ResultTablesPage && typeof window.ResultTablesPage.renderResultTable === 'function') {
    return window.ResultTablesPage.renderResultTable(items, type, file);
  }
  return '';
}

/** Filter files based on search query and filters */
function filterScanFiles(files, searchQuery, filters = {}) {
  return callPageMethod('ScanResultsUtilsPage', 'filterScanFiles', [files, searchQuery, filters], files);
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
  return callPageMethod('ScanResultsUtilsPage', 'copyAllScanResults', [scanId]);
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
  return callPageMethod('MonitorPage', 'syncMonitorUrlPatternVisibility');
}
async function quickAddUrlMonitor() {
  return callPageMethod('MonitorPage', 'quickAddUrlMonitor');
}
async function quickAddSubdomainMonitor() {
  return callPageMethod('MonitorPage', 'quickAddSubdomainMonitor');
}
async function runMonitorAISuggest() {
  return callPageMethod('MonitorPage', 'runMonitorAISuggest');
}
function renderMonitorAISuggestResults(res) {
  return callPageMethod('MonitorPage', 'renderMonitorAISuggestResults', [res]);
}
async function addSelectedMonitorSuggestions() {
  return callPageMethod('MonitorPage', 'addSelectedMonitorSuggestions');
}
async function pauseUrlMonitor(id) {
  return callPageMethod('MonitorPage', 'pauseUrlMonitor', [id]);
}
async function resumeUrlMonitor(id) {
  return callPageMethod('MonitorPage', 'resumeUrlMonitor', [id]);
}
async function deleteUrlMonitor(id) {
  return callPageMethod('MonitorPage', 'deleteUrlMonitor', [id]);
}
async function pauseSubdomainMonitor(id) {
  return callPageMethod('MonitorPage', 'pauseSubdomainMonitor', [id]);
}
async function resumeSubdomainMonitor(id) {
  return callPageMethod('MonitorPage', 'resumeSubdomainMonitor', [id]);
}
async function deleteSubdomainMonitor(id) {
  return callPageMethod('MonitorPage', 'deleteSubdomainMonitor', [id]);
}
async function clearMonitorChangeHistory() {
  return callPageMethod('MonitorPage', 'clearMonitorChangeHistory');
}
function renderMonitor() {
  return callPageMethod('MonitorPage', 'renderMonitor');
}

function renderR2() {
  return callPageMethod('R2Page', 'renderR2');
}

function renderSettings() {
  return callPageMethod('SettingsPage', 'renderSettings');
}

function saveOpenRouterKey() {
  return callPageMethod('SettingsPage', 'saveOpenRouterKey');
}
function saveGeminiKey() {
  return callPageMethod('SettingsPage', 'saveGeminiKey');
}
function saveTimeoutSettings() {
  return callPageMethod('SettingsPage', 'saveTimeoutSettings');
}
function saveWebhookSettings() {
  return callPageMethod('SettingsPage', 'saveWebhookSettings');
}

function updateStatusDot() {
  return callPageMethod('AppCoreActionsPage', 'updateStatusDot');
}

// ── Scan Launcher ─────────────────────────────────────────────────────────────

function syncLaunchPlaceholder(rebuildModes = false) {
  return callPageMethod('LauncherPage', 'syncLaunchPlaceholder', [rebuildModes]);
}

function renderLaunchFlags() {
  return callPageMethod('LauncherPage', 'renderLaunchFlags');
}

function updateLaunchPreview() {
  return callPageMethod('LauncherPage', 'updateLaunchPreview');
}

async function triggerScan() {
  return callPageMethod('LauncherPage', 'triggerScan');
}

async function handleLaunchFileUpload(inputEl) {
  return callPageMethod('LauncherPage', 'handleLaunchFileUpload', [inputEl]);
}

// ── Utilities ─────────────────────────────────────────────────────────────────

function esc(s) {
  return callPageMethod('HtmlEscapePage', 'esc', [s], String(s ?? ''));
}

/** Escape for HTML attribute values (e.g. data-r2-prefix). */
function escAttr(s) {
  return callPageMethod('HtmlEscapePage', 'escAttr', [s], String(s ?? ''));
}

function fmtDate(d) {
  return callPageMethod('UIHelpers', 'fmtDate', [d], '—');
}

function timeAgo(d) {
  return callPageMethod('UIHelpers', 'timeAgo', [d], '—');
}

function elapsedStr(start) {
  return callPageMethod('FormatUtilsPage', 'elapsedStr', [start], '');
}

function elapsedBetween(start, end) {
  return callPageMethod('FormatUtilsPage', 'elapsedBetween', [start, end], '—');
}

function fmtSize(bytes) {
  return callPageMethod('FormatUtilsPage', 'fmtSize', [bytes], '0 B');
}

function fmtInterval(secs) {
  return callPageMethod('UIHelpers', 'fmtInterval', [secs], '—');
}

function statusBadge(status) {
  return callPageMethod('UIHelpers', 'statusBadge', [status], `<span class="badge badge-done">${esc(status)}</span>`);
}

function httpColor(code) {
  return callPageMethod('UIHelpers', 'httpColor', [code], 'var(--text-muted)');
}

function fileIcon(ext) {
  return callPageMethod('UIHelpers', 'fileIcon', [ext], '📄');
}

function humanChangeType(t) {
  return callPageMethod('UIHelpers', 'humanChangeType', [t], t);
}

function emptyState(icon, title, desc) {
  return callPageMethod('UIHelpers', 'emptyState', [icon, title, desc], `<div class="empty-state"><div class="empty-icon">${icon}</div><div class="empty-title">${esc(title)}</div><div class="empty-desc">${esc(desc)}</div></div>`);
}

// ── Toast ─────────────────────────────────────────────────────────────────────

function showToast(type, title, msg) {
  return callPageMethod('UIHelpers', 'showToast', [type, title, msg]);
}

// ── Clock ─────────────────────────────────────────────────────────────────────

function updateClock() {
  return callPageMethod('UIHelpers', 'updateClock');
}

// ── Manual Refresh ────────────────────────────────────────────────────────────

function manualRefresh() {
  return callPageMethod('AppCoreActionsPage', 'manualRefresh');
}

// ── Boot ──────────────────────────────────────────────────────────────────────

async function boot() {
  return callPageMethod('DashboardBootstrapPage', 'boot');
}

document.addEventListener('DOMContentLoaded', boot);

// ══════════════════════════════════════════════════════════════════════════════
// Bug Bounty Targets Page
// ══════════════════════════════════════════════════════════════════════════════

async function loadTargetsPlatforms() {
  return callPageMethod('TargetsPage', 'loadTargetsPlatforms');
}
function renderTargetsPlatforms() {
  return callPageMethod('TargetsPage', 'renderTargetsPlatforms');
}
function renderPlatformCredFields(p, colors) {
  return callPageMethod('TargetsPage', 'renderPlatformCredFields', [p, colors], '');
}
function escapeSafe(s) {
  return callPageMethod('TargetsPage', 'escapeSafe', [s], String(s || ''));
}
function targetsUpdateCred(platformId, field, value) {
  return callPageMethod('TargetsPage', 'targetsUpdateCred', [platformId, field, value]);
}
function targetsSelectPlatform(id) {
  return callPageMethod('TargetsPage', 'targetsSelectPlatform', [id]);
}
async function targetsDoFetch() {
  return callPageMethod('TargetsPage', 'targetsDoFetch');
}
function targetsApplyFilter() {
  return callPageMethod('TargetsPage', 'targetsApplyFilter');
}
function targetsRenderDomainList(domains) {
  return callPageMethod('TargetsPage', 'targetsRenderDomainList', [domains]);
}
async function targetsAddDomain(domain) {
  return callPageMethod('TargetsPage', 'targetsAddDomain', [domain]);
}
async function targetsAddAllDomains() {
  return callPageMethod('TargetsPage', 'targetsAddAllDomains');
}
function targetsLaunchScan(domain) {
  return callPageMethod('TargetsPage', 'targetsLaunchScan', [domain]);
}
async function targetsCopyAll() {
  return callPageMethod('TargetsPage', 'targetsCopyAll');
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

async function exportScanResultsCSV(scanId) {
  return callPageMethod('OpsToolsPage', 'exportScanResultsCSV', [scanId]);
}
async function generateScanReport(scanId) {
  return callPageMethod('OpsToolsPage', 'generateScanReport', [scanId]);
}

// ── Nuclei Template Manager ──────────────────────────────────────────────────


// ── Report Templates ─────────────────────────────────────────────────────────
async function renderReportTemplates(search = '') {
  return callPageMethod('ReportTemplatesPage', 'renderReportTemplates', [search]);
}
function openReportTemplateModalByName(encodedName) {
  return callPageMethod('ReportTemplatesPage', 'openReportTemplateModalByName', [encodedName]);
}
async function openReportTemplateModal(name = '') {
  return callPageMethod('ReportTemplatesPage', 'openReportTemplateModal', [name]);
}
function updateTemplatePreview() {
  return callPageMethod('ReportTemplatesPage', 'updateTemplatePreview');
}
function closeReportTemplateModal() {
  return callPageMethod('ReportTemplatesPage', 'closeReportTemplateModal');
}
async function saveReportTemplate() {
  return callPageMethod('ReportTemplatesPage', 'saveReportTemplate');
}
function deleteReportTemplateByName(encodedName) {
  return callPageMethod('ReportTemplatesPage', 'deleteReportTemplateByName', [encodedName]);
}
async function exportReportTemplates() {
  return callPageMethod('ReportTemplatesPage', 'exportReportTemplates');
}
function triggerImportReportTemplates() {
  return callPageMethod('ReportTemplatesPage', 'triggerImportReportTemplates');
}
async function handleImportReportTemplatesFile(event) {
  return callPageMethod('ReportTemplatesPage', 'handleImportReportTemplatesFile', [event]);
}
async function deleteReportTemplate(name) {
  return callPageMethod('ReportTemplatesPage', 'deleteReportTemplate', [name]);
}

async function promptRetryCnames() {
  return callPageMethod('OpsToolsPage', 'promptRetryCnames');
}
async function startCnamesProgressPolling() {
  return callPageMethod('OpsToolsPage', 'startCnamesProgressPolling');
}
function promptRunGlobalNuclei() {
  return callPageMethod('OpsToolsPage', 'promptRunGlobalNuclei');
}
function closeNucleiModal() {
  return callPageMethod('OpsToolsPage', 'closeNucleiModal');
}
async function submitNucleiModal() {
  return callPageMethod('OpsToolsPage', 'submitNucleiModal');
}


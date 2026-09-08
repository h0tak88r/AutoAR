(() => {
  function pathScanId() {
    const m = String(location.pathname || '').match(/^\/scans\/([^/]+)\/?$/);
    return m ? decodeURIComponent(m[1]) : null;
  }

  // Per-view deep-link paths: each SPA view gets its own bookmarkable URL so
  // sections have a real address with working back/forward. Views not listed
  // (the iframe auditors) fall back to /ui (no distinct URL); scan-detail uses
  // /scans/:id via openScanResultsPage/pathScanId. The server serves the SPA for
  // each of these paths (see the per-view routes in api.go).
  const VIEW_PATHS = {
    overview: '/ui', scans: '/scans', monitor: '/monitor', domains: '/domains',
    subdomains: '/subdomains', targets: '/targets', programs: '/programs',
    'program-lookup': '/program-lookup', keyhacks: '/keyhacks', r2: '/r2',
    settings: '/settings', 'report-templates': '/report-templates',
  };
  function pathForView(view) { return VIEW_PATHS[view] || '/ui'; }
  function viewForPath(pathname) {
    const p = (String(pathname || '/').replace(/\/+$/, '')) || '/';
    if (p === '/' || p === '/ui') return 'overview';
    for (const v in VIEW_PATHS) { if (VIEW_PATHS[v] === p) return v; }
    return null; // unknown path → caller defaults to overview
  }
  window.pathForView = pathForView;
  window.viewForPath = viewForPath;

  async function openScanResultsPage(scanId, opts = {}) {
    const { replace = false, noHistory = false } = opts;
    const state = window.state;
    if (state.scanDetailId !== scanId) {
      state.scanDetailUI = { filesPage: 1, filesPerPage: 200, previewPage: 1, previewPerPage: 100, selectedFileName: null };
      window.clearScanDetailRefreshTimer();
      window._scanDetailKnownFiles = new Set();
      window._scanDetailRefreshId = scanId;
    }
    state.scanDetailId = scanId;
    state.view = 'scan-detail';
    (window.VIEWS || []).forEach((v) => {
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
    await window.renderScanDetailView(scanId);
    window.startPolling();
  }

  window.RouterCorePage = {
    pathScanId,
    openScanResultsPage,
  };
})();

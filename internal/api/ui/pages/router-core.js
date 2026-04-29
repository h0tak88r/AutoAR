(() => {
  function pathScanId() {
    const m = String(location.pathname || '').match(/^\/scans\/([^/]+)\/?$/);
    return m ? decodeURIComponent(m[1]) : null;
  }

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

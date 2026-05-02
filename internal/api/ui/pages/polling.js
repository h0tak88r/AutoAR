(() => {
  function startPolling() {
    const state = window.state;
    if (state.pollTimer) {
      clearTimeout(state.pollTimer);
      state.pollTimer = null;
    }
    const tick = async () => {
      try {
        await window.loadStats();
        await window.loadScans();
        if (state.view === 'monitor') await window.loadMonitor();

        if (state.view === 'scan-detail' && state.scanDetailId) {
          const activeIds = (state.scans?.active_scans || []).map((s) => String(s.id || s.Id || ''));
          if (activeIds.includes(String(state.scanDetailId))) window.refreshScanDetailIfRunning(state.scanDetailId);
        }
      } catch (e) { /* ignore */ }

      const n = state.stats?.active_scans ?? 0;
      const onScans = state.view === 'scans';
      let isViewingActiveScan = false;
      if (state.view === 'scan-detail' && state.scanDetailId) {
        const activeIds = (state.scans?.active_scans || []).map((s) => String(s.id || s.Id || ''));
        if (activeIds.includes(String(state.scanDetailId))) isViewingActiveScan = true;
      }

      let ms = window.POLL_INTERVAL;
      if ((onScans || isViewingActiveScan) && n > 0) ms = window.POLL_FAST_SCANS;
      else if (n > 0) ms = window.POLL_FAST_ANY;
      // Scans page should not aggressively rerender launcher/UI controls.
      if (onScans) ms = Math.max(ms, 30000);

      state.pollTimer = setTimeout(tick, ms);
    };
    state.pollTimer = setTimeout(tick, 1500);
  }

  function refreshCurrentView() {
    const state = window.state;
    switch (state.view) {
      case 'overview': window.loadStats(); window.loadDomains(); window.loadScans(); break;
      case 'scans': window.loadScans(); break;
      case 'domains': window.loadDomains(); break;
      case 'subdomains': window.loadSubdomains(); break;
      case 'targets': window.loadTargetsPlatforms(); break;
      case 'monitor': window.loadMonitor(); break;
      case 'keyhacks': window.loadKeyhacks(); break;
      case 'report-templates': window.renderReportTemplates(); break;
      case 'r2': window.loadR2(state.r2.prefix); break;
      case 'settings': window.loadConfig(); break;
      case 'scan-detail':
        if (state.scanDetailId) {
          state.scanDetailUI.filesPage = 1;
          window.renderScanDetailView(state.scanDetailId);
        }
        break;
    }
  }

  window.PollingPage = {
    startPolling,
    refreshCurrentView,
  };
})();

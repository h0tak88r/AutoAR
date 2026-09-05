(() => {
  function startPolling() {
    const state = window.state;
    if (state.pollTimer) {
      clearTimeout(state.pollTimer);
      state.pollTimer = null;
    }
    // Generation token: a later startPolling() supersedes any in-flight tick. A tick
    // that was already awaiting when we (re)started must not reschedule, or two
    // overlapping timer chains accumulate and hammer the API.
    const myGen = (state.pollGen = (state.pollGen || 0) + 1);
    // active_scans records are db.ScanRecord — the string id is `scan_id` (the DB
    // integer `id` never matches state.scanDetailId, which is the scan_id string).
    const isDetailScanActive = () =>
      (state.scans?.active_scans || [])
        .map((s) => String(s.scan_id || s.ScanID || ''))
        .includes(String(state.scanDetailId));
    const tick = async () => {
      if (myGen !== state.pollGen) return;
      try {
        await window.loadStats();
        await window.loadScans();
        if (state.view === 'monitor') await window.loadMonitor();

        if (state.view === 'scan-detail' && state.scanDetailId && isDetailScanActive()) {
          window.refreshScanDetailIfRunning(state.scanDetailId);
        }
      } catch (e) { /* ignore */ }

      if (myGen !== state.pollGen) return; // superseded while awaiting — stop this chain

      const n = state.stats?.active_scans ?? 0;
      const onScans = state.view === 'scans';
      const isViewingActiveScan = state.view === 'scan-detail' && state.scanDetailId && isDetailScanActive();

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
      case 'programs':
        // Manual Refresh on Programs should actually pull fresh scope from the
        // platforms — not just re-read the cached payload. refreshNow() triggers a
        // backend warmer rebuild, then re-renders the table once it's done.
        window.ProgramsPage.refreshNow();
        break;
      case 'program-lookup': window.loadProgramLookup(); break;
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

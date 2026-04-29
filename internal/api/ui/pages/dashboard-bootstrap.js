(() => {
  async function startDashboard() {
    const state = window.state;
    if (state._dashboardStarted) return;
    window.hideAuthGate();

    const so = document.getElementById('sign-out-btn');
    if (so) {
      so.style.display = state.config?.auth_enabled ? 'block' : 'none';
      so.onclick = () => {
        window.localTokenClear();
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
      backBtn.addEventListener('click', () => window.navigateTo('overview'));
    }
    if (!window.__autoarPopstate) {
      window.__autoarPopstate = true;
      window.addEventListener('popstate', () => {
        const sid = window.pathScanId();
        if (sid) {
          window.openScanResultsPage(sid, { noHistory: true });
        } else {
          state.scanDetailId = null;
          state.view = 'overview';
          document.getElementById('view-scan-detail')?.classList.remove('active');
          (window.VIEWS || []).forEach((v) => {
            document.getElementById(`view-${v}`)?.classList.toggle('active', v === 'overview');
            document.getElementById(`nav-${v}`)?.classList.toggle('active', v === 'overview');
          });
          document.getElementById('topbar-title').textContent = 'Overview';
          window.refreshCurrentView();
          window.startPolling();
        }
      });
    }
    window.startMetricsPolling();
    await window.loadStats();
    const deepScan = window.pathScanId();
    if (deepScan) {
      await window.openScanResultsPage(deepScan, { replace: true });
    } else {
      window.navigateTo('overview');
    }
    state._dashboardStarted = true;
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
  };
})();

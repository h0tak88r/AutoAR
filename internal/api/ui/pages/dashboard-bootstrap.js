(() => {
  async function startDashboard() {
    const state = window.state;
    if (state._dashboardStarted) return;
    window.hideAuthGate();

    const so = document.getElementById('sign-out-btn');
    if (so) {
      so.style.display = state.config?.auth_enabled ? 'block' : 'none';
      so.onclick = async () => {
        // Best-effort server-side revocation (invalidates the token for its
        // remaining lifetime), then clear client state.
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
    window.startMetricsPolling();
    await window.loadStats();
    // Load the current user's role up front so we can gate admin-only surfaces
    // (the System category: Settings / R2 Browser / Report Templates) for viewers,
    // before the first view renders (avoids a flash of the restricted nav).
    try {
      window.state._me = await window.apiFetch('/api/auth/me');
    } catch (e) { /* not signed in / no auth — leave nav as-is */ }
    if (window.state._me && window.state._me.role === 'viewer') {
      document.getElementById('nav-group-system')?.closest('.nav-group')?.setAttribute('hidden', '');
    }
    const deepScan = window.pathScanId();
    if (deepScan) {
      await window.openScanResultsPage(deepScan, { replace: true });
    } else {
      // Honor a per-view deep link on hard load (e.g. /settings, /monitor).
      window.navigateTo((window.viewForPath && window.viewForPath(location.pathname)) || 'overview');
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

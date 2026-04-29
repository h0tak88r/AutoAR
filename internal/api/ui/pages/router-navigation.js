(() => {
  function navigateTo(view) {
    const state = window.state;
    const prev = state.view;
    state.view = view;
    if (view !== 'scan-detail') {
      state.scanDetailId = null;
      document.getElementById('view-scan-detail')?.classList.remove('active');
      if (prev === 'scan-detail' && /^\/scans\//.test(location.pathname)) {
        try { history.pushState({}, '', '/ui'); } catch (e) { /* ignore */ }
      }
    }

    if (['apkauditor', 'ipaauditor', 'adbauditor', 'securitylab'].includes(view)) {
      const tok = state._authAccessToken || window.localTokenGet();
      if (tok) {
        document.cookie = `autoar_token=${tok}; path=/ui/apkauditor; max-age=3600; SameSite=Strict`;
        document.cookie = `autoar_token=${tok}; path=/ui/ipaauditor; max-age=3600; SameSite=Strict`;
        document.cookie = `autoar_token=${tok}; path=/ui/adbauditor; max-age=3600; SameSite=Strict`;
        document.cookie = `autoar_token=${tok}; path=/ui/securitylab; max-age=3600; SameSite=Strict`;
      }
      const modeMap = { apkauditor: 'android', ipaauditor: 'ios', adbauditor: 'adb' };
      const auditorPathMap = {
        apkauditor: '/ui/apkauditor/?mode=android',
        ipaauditor: '/ui/ipaauditor/?mode=ios',
        adbauditor: '/ui/adbauditor/?mode=adb',
      };
      const frame = document.getElementById(`${view}-frame`);
      if (frame && !frame.getAttribute('data-loaded')) {
        frame.setAttribute('data-loaded', '1');
        setTimeout(() => {
          try {
            if (view === 'securitylab') frame.src = '/ui/securitylab/';
            else frame.src = auditorPathMap[view] || `/ui/apkauditor/?mode=${modeMap[view]}`;
          } catch (e) {
            // Keep SPA navigation alive even if iframe init fails in a browser/extension edge case.
            console.warn('[router] auditor iframe init failed', e);
          }
        }, 30);
      }
    }

    (window.VIEWS || []).forEach((v) => {
      const el = document.getElementById(`view-${v}`);
      const nav = document.getElementById(`nav-${v}`);
      if (el) {
        const isActive = v === view;
        el.classList.toggle('active', isActive);
        if (['apkauditor', 'ipaauditor', 'adbauditor', 'securitylab'].includes(v)) {
          el.style.display = isActive ? 'flex' : 'none';
        }
      }
      if (nav) nav.classList.toggle('active', v === view);
    });

    document.getElementById('topbar-title').textContent = window.viewTitle(view);
    state.selectedDomain = null;
    if (!['apkauditor', 'ipaauditor', 'adbauditor', 'securitylab'].includes(view)) window.refreshCurrentView();
    window.startPolling();
  }

  window.RouterNavigationPage = { navigateTo };
})();

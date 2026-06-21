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
        document.cookie = `autoar_token=${tok}; path=/ui/apkauditor; max-age=3600; SameSite=Strict${location.protocol === 'https:' ? '; Secure' : ''}`;
        document.cookie = `autoar_token=${tok}; path=/ui/ipaauditor; max-age=3600; SameSite=Strict${location.protocol === 'https:' ? '; Secure' : ''}`;
        document.cookie = `autoar_token=${tok}; path=/ui/adbauditor; max-age=3600; SameSite=Strict${location.protocol === 'https:' ? '; Secure' : ''}`;
        document.cookie = `autoar_token=${tok}; path=/ui/securitylab; max-age=3600; SameSite=Strict${location.protocol === 'https:' ? '; Secure' : ''}`;
      }
      const modeMap = { apkauditor: 'android', ipaauditor: 'ios', adbauditor: 'adb' };
      const auditorPathMap = {
        apkauditor: '/ui/apkauditor/?mode=android',
        ipaauditor: '/ui/ipaauditor/?mode=ios',
        adbauditor: '/ui/adbauditor/?mode=adb',
      };
      const frame = document.getElementById(`${view}-frame`);
      if (view === 'securitylab') {
        // Deep-link a specific tool when chosen from the sidebar submenu.
        const slTab = state._securityLabTab;
        state._securityLabTab = null;
        if (frame && !frame.getAttribute('data-loaded')) {
          frame.setAttribute('data-loaded', '1');
          setTimeout(() => {
            try { frame.src = '/ui/securitylab/' + (slTab ? '#' + slTab : ''); }
            catch (e) { console.warn('[router] securitylab iframe init failed', e); }
          }, 30);
        } else if (frame && slTab) {
          // Already loaded — switch tab in place, no reload.
          try { frame.contentWindow.postMessage({ type: 'securitylab-tab', tab: slTab }, '*'); }
          catch (e) { /* ignore cross-frame edge cases */ }
        }
      } else if (frame && !frame.getAttribute('data-loaded')) {
        frame.setAttribute('data-loaded', '1');
        setTimeout(() => {
          try { frame.src = auditorPathMap[view] || `/ui/apkauditor/?mode=${modeMap[view]}`; }
          catch (e) {
            // Keep SPA navigation alive even if iframe init fails in a browser/extension edge case.
            console.warn('[router] auditor iframe init failed', e);
          }
        }, 30);
      }
    }

    // Reset group-head "contains the active view" markers; recomputed in the loop below.
    document.querySelectorAll('.nav-group-head').forEach((h) => h.classList.remove('has-active-child'));

    // Security Lab tool tabs (data-sltab) aren't views — clear their highlight whenever
    // we leave the Security Lab view, so its dropdown never shows two active items
    // (e.g. Keyhacks active + a stale tool still highlighted).
    if (view !== 'securitylab') {
      document.querySelectorAll('#securitylab-subnav .nav-subitem[data-sltab].active').forEach((x) => x.classList.remove('active'));
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
      if (nav) {
        const navActive = v === view;
        nav.classList.toggle('active', navActive);
        // If the active view lives inside a collapsible group (Mobile / Asset Management),
        // expand that group so the highlighted item is visible.
        if (navActive && nav.classList.contains('nav-subitem')) {
          const head = nav.closest('.nav-group')?.querySelector('.nav-group-head');
          if (head) {
            head.classList.add('expanded');
            head.setAttribute('aria-expanded', 'true');
            head.classList.add('has-active-child'); // surfaces active state when collapsed
          }
        }
      }
    });

    document.getElementById('topbar-title').textContent = window.viewTitle(view);
    state.selectedDomain = null;
    if (!['apkauditor', 'ipaauditor', 'adbauditor', 'securitylab'].includes(view)) window.refreshCurrentView();
    window.startPolling();
  }

  window.RouterNavigationPage = { navigateTo };
})();

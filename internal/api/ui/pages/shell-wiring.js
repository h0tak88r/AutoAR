(() => {
  function wireShellOnce() {
    if (window.state._shellWired) return;
    window.state._shellWired = true;

    // Sidebar items are <div>s, not buttons — make them keyboard-operable: focusable
    // and activated by Enter/Space, in addition to click.
    const bindActivate = (el, fn) => {
      if (!el) return;
      el.setAttribute('tabindex', '0');
      if (!el.getAttribute('role')) el.setAttribute('role', 'button');
      el.addEventListener('click', fn);
      el.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fn(); }
      });
    };

    (window.VIEWS || []).forEach((v) => {
      const el = document.getElementById(`nav-${v}`);
      // A group head that is also a view (Security Lab) must NOT navigate on click —
      // it only opens its submenu (handled below); binding navigate here too would
      // double-fire. Its sub-items do the navigating.
      if (el && !el.classList.contains('nav-group-head')) {
        bindActivate(el, () => window.navigateTo(v));
      }
    });

    // Expandable nav groups (Asset Management, Mobile, Security Lab): the head toggles
    // its submenu, and the open/closed choice is remembered across reloads.
    const GROUPS_KEY = 'autoar.sidebar.groups';
    const saveGroupState = () => {
      const m = {};
      document.querySelectorAll('.nav-group-head').forEach((h) => { if (h.id) m[h.id] = h.classList.contains('expanded'); });
      try { localStorage.setItem(GROUPS_KEY, JSON.stringify(m)); } catch (e) { /* ignore */ }
    };
    let savedGroups = {};
    try { savedGroups = JSON.parse(localStorage.getItem(GROUPS_KEY) || '{}'); } catch (e) { /* ignore */ }

    document.querySelectorAll('.nav-group-head').forEach((head) => {
      if (savedGroups[head.id]) {
        head.classList.add('expanded');
        head.setAttribute('aria-expanded', 'true');
      }
      bindActivate(head, () => {
        const sidebar = document.getElementById('app-sidebar');
        // In icon-only (collapsed) mode the submenu is hidden, so expand the sidebar
        // first — otherwise the grouped views would be unreachable. Then open the group.
        if (sidebar && sidebar.classList.contains('collapsed')) {
          sidebar.classList.remove('collapsed');
          try { localStorage.setItem('autoar.sidebar.collapsed', 'false'); } catch (e) { /* ignore */ }
          head.classList.add('expanded');
          head.setAttribute('aria-expanded', 'true');
        } else {
          const expanded = head.classList.toggle('expanded');
          head.setAttribute('aria-expanded', expanded ? 'true' : 'false');
        }
        saveGroupState();
      });
    });

    // Security Lab tool tabs (data-sltab) deep-link into the single Security Lab view.
    // (Keyhacks also lives in this submenu but is a real view, so it's wired by the
    // VIEWS loop above — exclude it here via the [data-sltab] filter.)
    document.querySelectorAll('#securitylab-subnav .nav-subitem[data-sltab]').forEach((el) => {
      bindActivate(el, () => {
        const tab = el.dataset.sltab;
        document.querySelectorAll('#securitylab-subnav .nav-subitem[data-sltab]').forEach((x) => x.classList.remove('active'));
        el.classList.add('active');
        window.state._securityLabTab = tab;
        window.navigateTo('securitylab');
      });
    });

    const refreshBtn = document.getElementById('refresh-btn');
    if (refreshBtn) refreshBtn.addEventListener('click', window.manualRefresh);

    const dsearch = document.getElementById('domain-search');
    if (dsearch) dsearch.addEventListener('input', window.renderDomainGrid);

    // Reload the subdomains list (page 1) while preserving whatever is in the search box,
    // since the status/tech/cname/live controls don't carry the search term themselves.
    const reloadSubsWithSearch = () => {
      const term = document.getElementById('subdomains-search')?.value.trim() || '';
      window.loadSubdomains(1, term);
    };

    const ssearch = document.getElementById('subdomains-search');
    if (ssearch) {
      let subSearchDebounce;
      ssearch.addEventListener('input', (e) => {
        clearTimeout(subSearchDebounce);
        subSearchDebounce = setTimeout(() => window.loadSubdomains(1, e.target.value.trim()), 300);
      });
    }
    // The status dropdown and live-only toggle apply immediately on change.
    const sstatus = document.getElementById('subdomains-status-filter');
    if (sstatus) sstatus.addEventListener('change', reloadSubsWithSearch);
    const sliveOnly = document.getElementById('subdomains-live-only');
    if (sliveOnly) sliveOnly.addEventListener('change', reloadSubsWithSearch);
    // Tech and CNAME are free-text inputs, so debounce like the search box.
    const stech = document.getElementById('subdomains-tech-filter');
    if (stech) {
      let techDebounce;
      stech.addEventListener('input', () => {
        clearTimeout(techDebounce);
        techDebounce = setTimeout(reloadSubsWithSearch, 300);
      });
    }
    const scname = document.getElementById('subdomains-cname-filter');
    if (scname) {
      let cnameDebounce;
      scname.addEventListener('input', () => {
        clearTimeout(cnameDebounce);
        cnameDebounce = setTimeout(reloadSubsWithSearch, 300);
      });
    }
    const copyAllSubsBtn = document.getElementById('copy-all-subs-btn');
    if (copyAllSubsBtn) copyAllSubsBtn.addEventListener('click', () => window.copyAllSubdomainsMatching());

    // NOTE: the Quick Scan Launcher is rendered on demand by renderScans() (it does
    // not exist at boot), and renderScans() wires its own controls every time it
    // rebuilds the DOM. Wiring those elements here would attach to nothing at boot
    // and only duplicate handlers later, so it lives entirely in scans-page.js.

    const urlStrat = document.getElementById('monitor-url-strategy');
    if (urlStrat) urlStrat.addEventListener('change', window.syncMonitorUrlPatternVisibility);
    window.syncMonitorUrlPatternVisibility();

    const urlInput = document.getElementById('monitor-url-input');
    if (urlInput) {
      urlInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          window.quickAddUrlMonitor();
        }
      });
    }
    const subInput = document.getElementById('monitor-sub-domain-input');
    if (subInput) {
      subInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          window.quickAddSubdomainMonitor();
        }
      });
    }
    const khSearch = document.getElementById('keyhacks-search');
    if (khSearch) {
      let khDebounce;
      khSearch.addEventListener('input', (e) => {
        clearTimeout(khDebounce);
        khDebounce = setTimeout(() => window.loadKeyhacks(e.target.value.trim()), 300);
      });
    }

    const rtSearch = document.getElementById('report-templates-search');
    if (rtSearch) {
      let rtDebounce;
      rtSearch.addEventListener('input', (e) => {
        clearTimeout(rtDebounce);
        rtDebounce = setTimeout(() => window.renderReportTemplates(e.target.value.trim()), 300);
      });
    }

    window.wireR2BrowserOnce();
  }

  window.ShellWiringPage = { wireShellOnce };
})();

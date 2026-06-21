(() => {
  function wireShellOnce() {
    if (window.state._shellWired) return;
    window.state._shellWired = true;

    (window.VIEWS || []).forEach((v) => {
      const el = document.getElementById(`nav-${v}`);
      // A group head that is also a view (Security Lab) must NOT navigate on click —
      // it only opens its submenu (handled by the group-toggle wiring below); its
      // sub-items do the navigating. Binding navigate here too would double-fire.
      if (el && !el.classList.contains('nav-group-head')) {
        el.addEventListener('click', () => window.navigateTo(v));
      }
    });

    // Expandable nav groups (Asset Management, Mobile, Security Lab): clicking a group
    // head toggles its submenu. Security Lab's head is also a real view, so it still
    // navigates via the VIEWS loop above; the Mobile / Asset Management heads are pure
    // toggles whose sub-items (real views) navigate via the VIEWS loop too.
    document.querySelectorAll('.nav-group-head').forEach((head) => {
      head.addEventListener('click', () => {
        // In icon-only (collapsed) mode the submenu is hidden, so expand the sidebar
        // first — otherwise the grouped views would be unreachable. Then open the group.
        const sidebar = document.getElementById('app-sidebar');
        if (sidebar && sidebar.classList.contains('collapsed')) {
          sidebar.classList.remove('collapsed');
          try { localStorage.setItem('autoar.sidebar.collapsed', 'false'); } catch (e) { /* ignore */ }
          head.classList.add('expanded');
          head.setAttribute('aria-expanded', 'true');
          return;
        }
        const expanded = head.classList.toggle('expanded');
        head.setAttribute('aria-expanded', expanded ? 'true' : 'false');
      });
    });

    // Security Lab sub-items are tabs within the single Security Lab view — deep-link to them.
    document.querySelectorAll('#securitylab-subnav .nav-subitem').forEach((el) => {
      el.addEventListener('click', (e) => {
        e.stopPropagation();
        const tab = el.dataset.sltab;
        document.querySelectorAll('#securitylab-subnav .nav-subitem').forEach((x) => x.classList.remove('active'));
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

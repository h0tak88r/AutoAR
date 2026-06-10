(() => {
  function wireShellOnce() {
    if (window.state._shellWired) return;
    window.state._shellWired = true;

    (window.VIEWS || []).forEach((v) => {
      const el = document.getElementById(`nav-${v}`);
      if (el) {
        el.addEventListener('click', () => window.navigateTo(v));
      }
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

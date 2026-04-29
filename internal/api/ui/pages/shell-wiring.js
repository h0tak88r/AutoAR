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

    const ssearch = document.getElementById('subdomains-search');
    if (ssearch) {
      let subSearchDebounce;
      ssearch.addEventListener('input', (e) => {
        clearTimeout(subSearchDebounce);
        subSearchDebounce = setTimeout(() => window.loadSubdomains(1, e.target.value.trim()), 300);
      });
    }
    const copyAllSubsBtn = document.getElementById('copy-all-subs-btn');
    if (copyAllSubsBtn) copyAllSubsBtn.addEventListener('click', () => window.copyAllSubdomainsMatching());

    const launchBtn = document.getElementById('launch-btn');
    if (launchBtn) launchBtn.addEventListener('click', window.triggerScan);
    const launchType = document.getElementById('launch-type');
    const launchTargetMode = document.getElementById('launch-target-mode');
    if (launchType) launchType.addEventListener('change', () => window.syncLaunchPlaceholder(true));
    if (launchTargetMode) launchTargetMode.addEventListener('change', () => window.syncLaunchPlaceholder(false));
    const launchTarget = document.getElementById('launch-target');
    const launchTargetList = document.getElementById('launch-target-list');
    if (launchTarget) launchTarget.addEventListener('input', window.updateLaunchPreview);
    if (launchTargetList) launchTargetList.addEventListener('input', window.updateLaunchPreview);
    document.addEventListener('input', (e) => {
      if (e.target && e.target.matches('[data-flag-key]')) window.updateLaunchPreview();
    });
    document.addEventListener('change', (e) => {
      if (e.target && e.target.matches('[data-flag-key]')) window.updateLaunchPreview();
    });
    window.syncLaunchPlaceholder(true);

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

(() => {
  const state = () => window.state;
  const byId = (id) => document.getElementById(id);

  async function loadStats() {
    await window.loadResource('stats', '/api/dashboard/stats', 'stats');
    window.renderStats();
    window.renderRecentChanges();
    const badge = byId('scans-badge');
    if (badge && state().stats) {
      badge.textContent = state().stats.active_scans;
      badge.classList.toggle('pulse', state().stats.active_scans > 0);
    }
    // Sidebar subdomains badge reflects the unfiltered grand total so it is correct
    // from boot and is not skewed by the per-page live-only / status filters.
    const sdBadge = byId('subdomains-badge');
    if (sdBadge && state().stats) {
      const n = state().stats.subdomains || 0;
      sdBadge.textContent = n;
      sdBadge.style.display = n ? '' : 'none';
    }
  }

  async function loadDomains() {
    await window.loadResource('domains', '/api/domains', 'domains');
    if (state().view === 'domains' && !state().selectedDomain) window.renderDomainGrid();
    if (state().view === 'overview') window.renderStats();
  }

  async function loadSubdomains(page = 1, search = '') {
    const reqId = Date.now();
    state()._subdomainsReqId = reqId;
    state().subdomainsPage = page;

    const searchInput = byId('subdomains-search');
    const actualSearch = searchInput && document.activeElement === searchInput ? searchInput.value : search;
    state().subdomainsSearch = actualSearch;

    const st = byId('subdomains-status-filter')?.value || '0';
    const tc = byId('subdomains-tech-filter')?.value || '';
    const cn = byId('subdomains-cname-filter')?.value || '';
    const liveEl = byId('subdomains-live-only');
    // Default to live-only when the toggle is absent (first render before it mounts).
    const live = liveEl ? (liveEl.checked ? '1' : '0') : '1';

    state().subdStatus = st;
    state().subdTech = tc;
    state().subdCname = cn;
    state().subdLive = live;
    state().subdomainsLimit = 30;
    state().loading.subdomains = true;
    state().error.subdomains = null;
    if (state().view === 'subdomains') {
      const container = byId('subdomains-container');
      if (container) container.innerHTML = window.emptyState('...', 'Loading subdomains…', 'Fetching paginated rows from database.');
    }

    if (!state().domains || !state().domains.length) {
      await window.loadResource('domains', '/api/domains', 'domains');
    }

    try {
      const q = encodeURIComponent(state().subdomainsSearch);
      const qs = `page=${page}&limit=${state().subdomainsLimit}&search=${q}&status=${state().subdStatus}&tech=${encodeURIComponent(state().subdTech)}&cname=${encodeURIComponent(state().subdCname)}&live=${state().subdLive}`;
      const data = await window.apiFetch(`/api/subdomains?${qs}`);
      if (state()._subdomainsReqId !== reqId) return;
      state().allSubdomains = data.subdomains || [];
      state().allSubdomainsTotal = data.total || 0;
      // Note: the filtered total is shown in the page header ("Total Subdomains Match").
      // The sidebar nav badge is the unfiltered grand total, set in loadStats().
    } catch (e) {
      if (state()._subdomainsReqId !== reqId) return;
      state().allSubdomains = [];
      state().allSubdomainsTotal = 0;
      state().error.subdomains = e?.message || String(e);
      window.showToast('error', 'Subdomains load failed', state().error.subdomains);
    } finally {
      if (state()._subdomainsReqId === reqId) state().loading.subdomains = false;
    }
    if (state().view === 'subdomains') window.renderSubdomainsPage();
  }

  async function loadScans() {
    await window.loadResource('scans', '/api/scans', 'scans');
    window.renderOverviewActiveScans();
    if (state().view === 'scans') window.renderScans();
  }

  window.DashboardDataPage = {
    loadStats,
    loadDomains,
    loadSubdomains,
    loadScans,
  };
})();

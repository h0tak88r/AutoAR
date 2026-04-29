(() => {
  async function browseR2ForScan(target, scanType) {
    const candidates = window.r2PrefixesForScan(target, scanType);
    if (!candidates.length) {
      window.showToast('error', 'R2', 'No R2 search paths for this scan.');
      return;
    }
    let chosen = candidates[0];
    for (const prefix of candidates) {
      try {
        const data = await window.apiFetch(`/api/r2/files?prefix=${encodeURIComponent(prefix)}&recursive=0`);
        const has = (data.files && data.files.length) || (data.dirs && data.dirs.length);
        if (has) {
          chosen = prefix;
          break;
        }
      } catch (e) { /* try next */ }
    }
    window.state.r2.prefix = chosen;
    window.navigateTo('r2');
    window.showToast('info', 'R2', `Opened ${chosen}`);
  }

  async function loadDomainSubdomains(domain) {
    window.state.selectedDomain = domain;
    window.state.loading.subdomains = true;
    try {
      const data = await window.apiFetch(`/api/domains/${encodeURIComponent(domain)}/subdomains`);
      window.state.subdomains = data.subdomains || [];
      window.renderSubdomainView(domain);
    } catch (e) {
      window.showToast('error', 'Failed to load subdomains', e.message);
    } finally {
      window.state.loading.subdomains = false;
    }
  }

  window.DomainR2ActionsPage = {
    browseR2ForScan,
    loadDomainSubdomains,
  };
})();

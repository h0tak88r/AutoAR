(() => {
  async function deleteDomainRecord(domain) {
    if (!domain) return;
    if (!confirm(`Remove "${domain}" from the database? This deletes subdomains, related scans (and their R2 artifacts), monitor history for this root, and the subdomain monitor target if present.`)) return;
    try {
      await window.apiDelete(`/api/domains/${encodeURIComponent(domain)}`);
      window.showToast('success', 'Domain removed', domain);
      window.state.selectedDomain = null;
      const fb = document.getElementById('filter-bar-domains');
      if (fb) fb.style.display = '';
      window.loadStats();
      window.loadDomains();
      window.loadScans();
    } catch (e) {
      window.showToast('error', 'Could not delete domain', e.message);
    }
  }

  window.DomainActionsPage = {
    deleteDomainRecord,
  };
})();

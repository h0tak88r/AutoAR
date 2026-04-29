(() => {
  async function cancelScan(scanID) {
    if (!confirm('Stop this scan? The worker process will be killed.')) return;
    try {
      await window.apiPost(`/api/scans/${encodeURIComponent(scanID)}/cancel`, {});
      window.showToast('success', 'Scan stopped', '');
      window.loadStats();
      window.loadScans();
    } catch (e) {
      window.showToast('error', 'Could not stop scan', e.message);
    }
  }

  async function deleteScan(scanID, target = '') {
    const label = target ? ` for ${target}` : '';
    if (!confirm(`Delete this scan record${label} and remove its R2 indexed artifacts?`)) return;
    try {
      await window.apiDelete(`/api/scans/${encodeURIComponent(scanID)}`);
      window.showToast('success', 'Scan deleted', '');
      window.loadStats();
      window.loadScans();
    } catch (e) {
      window.showToast('error', 'Delete failed', e.message);
    }
  }

  async function rescanScan(scanID) {
    try {
      const result = await window.apiPost(`/api/scans/${encodeURIComponent(scanID)}/rescan`, {});
      window.showToast('success', '🔁 Rescan started', `New scan queued (ID: ${result.new_scan_id || ''})`);
      window.loadScans();
      if (result.new_scan_id) {
        setTimeout(() => window.goToScanResultsPage(result.new_scan_id), 900);
      }
    } catch (e) {
      window.showToast('error', 'Rescan failed', e.message);
    }
  }

  function toggleSelectAllRecentScans(master) {
    const on = master.checked;
    document.querySelectorAll('#recent-scans-table .scan-row-select').forEach((cb) => { cb.checked = on; });
  }

  async function deleteSelectedScans() {
    const cbs = Array.from(document.querySelectorAll('#recent-scans-table .scan-row-select:checked'));
    const ids = cbs.map((cb) => cb.getAttribute('data-scan-id')).filter(Boolean);
    if (!ids.length) {
      window.showToast('error', 'No scans selected', 'Check the rows you want to remove.');
      return;
    }
    if (!confirm(`Delete ${ids.length} scan record(s) and remove their indexed R2 artifacts?`)) return;
    try {
      const res = await window.apiPost('/api/scans/bulk-delete', { scan_ids: ids });
      let msg = `Removed ${res.deleted} scan(s).`;
      if (res.skipped_active) msg += ` ${res.skipped_active} skipped (still active).`;
      if (res.failed) msg += ` ${res.failed} failed.`;
      window.showToast(res.ok && !res.failed ? 'success' : 'error', res.ok ? 'Bulk delete done' : 'Some deletes failed', msg);
      window.loadStats();
      window.loadScans();
    } catch (e) {
      window.showToast('error', 'Bulk delete failed', e.message);
    }
  }

  async function clearAllScans() {
    if (!confirm('Delete all scan history? Active scans stay; finished scans are removed with their indexed R2 objects.')) return;
    try {
      const res = await window.apiPost('/api/scans/clear-all', {});
      let msg = `Removed ${res.deleted} scan(s).`;
      if (res.skipped_active) msg += ` ${res.skipped_active} active scan(s) were skipped.`;
      if (res.failed) msg += ` ${res.failed} failed.`;
      window.showToast(res.ok && !res.failed ? 'success' : 'error', 'Clear all', msg);
      window.loadStats();
      window.loadScans();
    } catch (e) {
      window.showToast('error', 'Clear all failed', e.message);
    }
  }

  async function pauseScan(scanID) {
    try {
      await window.apiPost(`/api/scans/${encodeURIComponent(scanID)}/pause`, {});
      window.showToast('success', 'Scan paused', '');
      window.loadStats();
      window.loadScans();
    } catch (e) {
      window.showToast('error', 'Pause failed', e.message);
    }
  }

  async function resumeScan(scanID) {
    try {
      await window.apiPost(`/api/scans/${encodeURIComponent(scanID)}/resume`, {});
      window.showToast('success', 'Scan resumed', '');
      window.loadStats();
      window.loadScans();
    } catch (e) {
      window.showToast('error', 'Resume failed', e.message);
    }
  }

  window.ScanActionsPage = {
    cancelScan,
    deleteScan,
    rescanScan,
    toggleSelectAllRecentScans,
    deleteSelectedScans,
    clearAllScans,
    pauseScan,
    resumeScan,
  };
})();

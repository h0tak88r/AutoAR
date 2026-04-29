(() => {
  function renderStats() {
    const s = window.state.stats;
    if (!s) return;
    const set = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val;
    };
    set('stat-domains', s.domains ?? 0);
    set('stat-subdomains', s.subdomains ?? 0);
    set('stat-live', s.live_subdomains ?? 0);
    set('stat-monitors', s.monitor_targets ?? 0);
    set('stat-active', s.active_scans ?? 0);
    set('stat-completed', s.completed_scans ?? 0);
  }

  function renderOverviewActiveScans() {
    const card = document.getElementById('overview-running-scans');
    const body = document.getElementById('overview-active-scans-body');
    if (!card || !body) return;
    const active = window.state.scans?.active_scans || [];
    if (!active.length) {
      card.style.display = 'none';
      return;
    }
    card.style.display = 'block';
    body.innerHTML = active.map((s) => window.scanItemHtml(s)).join('');
  }

  function updateMetricsUI(data) {
    const cpu = Math.round(data.cpu_percent || 0);
    const ram = Math.round(data.memory_percent || 0);

    const cpuEl = document.getElementById('metric-cpu');
    const cpuFill = document.getElementById('metric-cpu-fill');
    const ramEl = document.getElementById('metric-ram');
    const ramFill = document.getElementById('metric-ram-fill');

    if (cpuEl) cpuEl.textContent = `${cpu}%`;
    if (cpuFill) cpuFill.style.width = `${cpu}%`;
    if (ramEl) ramEl.textContent = `${ram}%`;
    if (ramFill) ramFill.style.width = `${ram}%`;
  }

  function startMetricsPolling() {
    if (window.state._metricsTimer) clearInterval(window.state._metricsTimer);
    const poll = async () => {
      try {
        const data = await window.apiFetch('/api/system/metrics');
        updateMetricsUI(data);
      } catch (e) {
        console.warn('[metrics] poll failed', e);
      }
    };
    poll();
    window.state._metricsTimer = setInterval(poll, 10000);
  }

  function changeItemHtml(c) {
    const ctype = c.ChangeType || c.change_type || '';
    const domain = c.Domain || c.domain || '';
    const detail = c.Detail || c.detail || '';
    const at = c.DetectedAt || c.detected_at || '';
    const iconMap = {
      new_subdomain: '🆕',
      became_live: '🟢',
      became_dead: '💀',
      content_changed: '📝',
      status_changed: '🔄',
    };
    const preview = String(detail || '').slice(0, 200);
    return `<div class="change-item">
    <div class="change-dot ${window.esc(ctype)}"></div>
    <div class="change-body">
      <div class="change-title">${iconMap[ctype] || '📌'} ${window.esc(window.humanChangeType(ctype))}</div>
      <div class="change-detail">${window.esc(domain)}${preview ? ` — ${window.esc(preview)}` : ''}</div>
    </div>
    <div class="change-time">${window.timeAgo(at)}</div>
  </div>`;
  }

  function renderRecentChanges() {
    const el = document.getElementById('recent-changes-feed');
    if (!el) return;
    const changes = window.state.stats?.recent_changes || [];
    if (!changes.length) {
      el.innerHTML = window.emptyState('📭', 'No recent changes', 'Monitor targets have not detected any changes yet.');
      return;
    }
    el.innerHTML = changes.map((c) => changeItemHtml(c)).join('');
  }

  window.OverviewPage = {
    renderStats,
    renderOverviewActiveScans,
    startMetricsPolling,
    updateMetricsUI,
    renderRecentChanges,
    changeItemHtml,
  };
})();

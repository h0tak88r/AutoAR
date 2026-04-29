(() => {
  const { esc, fmtDate, fmtInterval, timeAgo, humanChangeType } = window;

  async function loadMonitor() {
    const [targets, subTargets, changes] = await Promise.allSettled([
      window.apiFetch('/api/monitor/targets'),
      window.apiFetch('/api/monitor/subdomain-targets'),
      window.apiFetch('/api/monitor/changes'),
    ]);
    window.state.monitorTargets = targets.status === 'fulfilled' ? (targets.value.targets || []) : [];
    window.state.subMonitorTargets = subTargets.status === 'fulfilled' ? (subTargets.value.targets || []) : [];
    window.state.monitorChanges = changes.status === 'fulfilled' ? (changes.value.changes || []) : [];
    if (window.state.view === 'monitor') renderMonitor();
  }

  function syncMonitorUrlPatternVisibility() {
    const strat = document.getElementById('monitor-url-strategy');
    const wrap = document.getElementById('monitor-url-pattern-wrap');
    if (!strat || !wrap) return;
    wrap.style.display = strat.value === 'regex' ? 'block' : 'none';
  }

  async function quickAddUrlMonitor() {
    const urlEl = document.getElementById('monitor-url-input');
    const stratEl = document.getElementById('monitor-url-strategy');
    const patEl = document.getElementById('monitor-url-pattern');
    const startEl = document.getElementById('monitor-url-autostart');
    if (!urlEl) return;
    const rawUrl = urlEl.value.trim();
    if (!rawUrl) {
      window.showToast('error', 'URL required', 'Enter a page to watch for changes.');
      return;
    }
    const strategy = stratEl ? stratEl.value : 'hash';
    const pattern = patEl ? patEl.value.trim() : '';
    const start = startEl ? startEl.checked : true;
    try {
      await window.apiPost('/api/monitor/url-targets', {
        url: rawUrl,
        strategy,
        pattern: strategy === 'regex' ? pattern : '',
        start,
      });
      window.showToast('success', 'URL monitor added', start ? 'The URL worker is checking in the background.' : 'Saved; enable from CLI with monitor updates start if needed.');
      urlEl.value = '';
      await loadMonitor();
      window.loadStats();
    } catch (e) {
      window.showToast('error', 'Could not add URL monitor', e.message);
    }
  }

  async function quickAddSubdomainMonitor() {
    const dEl = document.getElementById('monitor-sub-domain-input');
    const intEl = document.getElementById('monitor-sub-interval');
    const thEl = document.getElementById('monitor-sub-threads');
    const cnEl = document.getElementById('monitor-sub-checknew');
    const stEl = document.getElementById('monitor-sub-autostart');
    if (!dEl) return;
    const domain = dEl.value.trim().toLowerCase();
    if (!domain) {
      window.showToast('error', 'Domain required', 'Enter a root domain (e.g. example.com).');
      return;
    }
    const interval_seconds = intEl ? Math.max(60, parseInt(intEl.value, 10) || 3600) : 3600;
    const threads = thEl ? Math.min(500, Math.max(1, parseInt(thEl.value, 10) || 100)) : 100;
    const check_new = cnEl ? cnEl.checked : true;
    const start = stEl ? stEl.checked : true;
    try {
      await window.apiPost('/api/monitor/subdomain-targets', {
        domain,
        interval_seconds,
        threads,
        check_new,
        start,
      });
      window.showToast('success', 'Subdomain monitor added', start ? 'The subdomain monitor daemon will run on your interval.' : 'Saved; start from CLI when ready.');
      dEl.value = '';
      await loadMonitor();
      window.loadStats();
    } catch (e) {
      window.showToast('error', 'Could not add subdomain monitor', e.message);
    }
  }

  async function runMonitorAISuggest() {
    const inp = document.getElementById('monitor-ai-domain');
    const btn = document.getElementById('monitor-ai-suggest-btn');
    const meta = document.getElementById('monitor-ai-suggest-meta');
    const box = document.getElementById('monitor-ai-suggest-results');
    if (!inp) return;
    const domain = inp.value.trim();
    if (!domain) {
      window.showToast('error', 'Domain required', 'e.g. example.com');
      return;
    }
    if (btn) btn.disabled = true;
    if (meta) {
      meta.style.display = 'block';
      meta.textContent = 'Probing common release/changelog paths (may take up to a minute)…';
    }
    if (box) {
      box.style.display = 'none';
      box.innerHTML = '';
    }
    try {
      const res = await window.apiPost('/api/monitor/suggest-from-domain', { domain });
      window.state._monitorSuggestCache = res;
      if (meta) {
        const mode = res.ai ? 'AI-ranked' : 'Heuristic ranking (set OPENROUTER_API_KEY on the API server for AI)';
        meta.textContent = `${mode} · ${res.candidates_probed || 0} HTML pages found`;
      }
      renderMonitorAISuggestResults(res);
    } catch (e) {
      if (meta) meta.textContent = '';
      window.showToast('error', 'Suggest failed', e.message);
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  function renderMonitorAISuggestResults(res) {
    const box = document.getElementById('monitor-ai-suggest-results');
    if (!box) return;
    const rows = res.suggestions || [];
    if (!rows.length) {
      box.style.display = 'block';
      box.innerHTML = '<div class="empty-state" style="padding:12px"><div class="empty-title">No pages found</div><div style="font-size:12px;color:var(--text-muted)">Try another domain or add a URL manually above.</div></div>';
      return;
    }
    let html = '<table class="data-table"><thead><tr><th style="width:36px"></th><th>URL</th><th>Score</th><th>Strategy</th><th>Reason</th></tr></thead><tbody>';
    rows.forEach((r, i) => {
      const url = r.URL || r.url || '';
      const strat = (r.Strategy || r.strategy || 'hash').toLowerCase();
      const score = r.Score ?? r.score ?? 0;
      const reason = r.Reason || r.reason || '';
      const title = r.Title || r.title || '';
      html += `<tr data-index="${i}">
        <td><input type="checkbox" class="monitor-suggest-cb" data-url="${esc(url)}" data-strategy="${esc(strat)}" checked /></td>
        <td><span style="font-size:12px;color:var(--accent-cyan)">${esc(url)}</span>${title ? `<div style="font-size:11px;color:var(--text-muted)">${esc(title)}</div>` : ''}</td>
        <td>${esc(String(score))}</td>
        <td><span class="scan-type">${esc(strat)}</span></td>
        <td style="font-size:11px;color:var(--text-muted)">${esc(reason).slice(0, 200)}</td>
      </tr>`;
    });
    html += '</tbody></table>';
    html += '<div style="margin-top:12px"><button type="button" class="btn btn-primary" onclick="window.MonitorPage.addSelectedMonitorSuggestions()">Add selected as monitors</button></div>';
    box.innerHTML = html;
    box.style.display = 'block';
  }

  async function addSelectedMonitorSuggestions() {
    const cbs = Array.from(document.querySelectorAll('.monitor-suggest-cb:checked'));
    if (!cbs.length) {
      window.showToast('error', 'None selected', 'Check at least one URL.');
      return;
    }
    let ok = 0;
    for (const cb of cbs) {
      const url = cb.getAttribute('data-url');
      const strategy = cb.getAttribute('data-strategy') || 'hash';
      try {
        await window.apiPost('/api/monitor/url-targets', {
          url,
          strategy,
          pattern: '',
          start: true,
        });
        ok++;
      } catch (e) {
        window.showToast('error', 'Add failed', `${url}: ${e.message}`);
        return;
      }
    }
    window.showToast('success', 'Monitors added', `${ok} URL monitor(s) started.`);
    const resBox = document.getElementById('monitor-ai-suggest-results');
    if (resBox) resBox.style.display = 'none';
    const meta = document.getElementById('monitor-ai-suggest-meta');
    if (meta) meta.style.display = 'none';
    await loadMonitor();
    window.loadStats();
  }

  async function pauseUrlMonitor(id) {
    try {
      await window.apiPost(`/api/monitor/url-targets/${encodeURIComponent(id)}/pause`, {});
      window.showToast('success', 'Monitor paused', 'URL checks are stopped for this target.');
      await loadMonitor();
      window.loadStats();
    } catch (e) {
      window.showToast('error', 'Pause failed', e.message);
    }
  }

  async function resumeUrlMonitor(id) {
    try {
      await window.apiPost(`/api/monitor/url-targets/${encodeURIComponent(id)}/resume`, {});
      window.showToast('success', 'Monitor resumed', 'The URL worker will pick this target up.');
      await loadMonitor();
      window.loadStats();
    } catch (e) {
      window.showToast('error', 'Resume failed', e.message);
    }
  }

  async function deleteUrlMonitor(id) {
    if (!confirm('Remove this URL monitor? It will be deleted from the database.')) return;
    try {
      await window.apiDelete(`/api/monitor/url-targets/${encodeURIComponent(id)}`);
      window.showToast('success', 'Monitor removed', '');
      await loadMonitor();
      window.loadStats();
    } catch (e) {
      window.showToast('error', 'Delete failed', e.message);
    }
  }

  async function pauseSubdomainMonitor(id) {
    try {
      await window.apiPost(`/api/monitor/subdomain-targets/${encodeURIComponent(id)}/pause`, {});
      window.showToast('success', 'Subdomain monitor paused', '');
      await loadMonitor();
      window.loadStats();
    } catch (e) {
      window.showToast('error', 'Pause failed', e.message);
    }
  }

  async function resumeSubdomainMonitor(id) {
    try {
      await window.apiPost(`/api/monitor/subdomain-targets/${encodeURIComponent(id)}/resume`, {});
      window.showToast('success', 'Subdomain monitor resumed', '');
      await loadMonitor();
      window.loadStats();
    } catch (e) {
      window.showToast('error', 'Resume failed', e.message);
    }
  }

  async function deleteSubdomainMonitor(id) {
    if (!confirm('Remove this subdomain monitor?')) return;
    try {
      await window.apiDelete(`/api/monitor/subdomain-targets/${encodeURIComponent(id)}`);
      window.showToast('success', 'Monitor removed', '');
      await loadMonitor();
      window.loadStats();
    } catch (e) {
      window.showToast('error', 'Delete failed', e.message);
    }
  }

  async function clearMonitorChangeHistory() {
    if (!confirm('Clear all monitor change history? URL monitor “Changes” counters reset to 0. This cannot be undone.')) return;
    try {
      await window.apiDelete('/api/monitor/changes');
      window.showToast('success', 'History cleared', '');
      await loadMonitor();
      window.loadStats();
    } catch (e) {
      window.showToast('error', 'Clear failed', e.message);
    }
  }

  function formatMonitorDetailPreview(detail) {
    if (!detail || typeof detail !== 'string') return '';
    try {
      const o = JSON.parse(detail);
      if (o.strategy === 'regex') {
        const om = String(o.old_match ?? '');
        const nm = String(o.new_match ?? '');
        return `regex: "${om.slice(0, 60)}${om.length > 60 ? '…' : ''}" → "${nm.slice(0, 60)}${nm.length > 60 ? '…' : ''}"`;
      }
      if (o.old_hash && o.new_hash) {
        return `hash: ${String(o.old_hash).slice(0, 10)}… → ${String(o.new_hash).slice(0, 10)}…`;
      }
    } catch (e) { /* use raw */ }
    return detail;
  }

  function renderMonitor() {
    const urlContainer = document.getElementById('monitor-url-container');
    const subContainer = document.getElementById('monitor-sub-container');
    const feedContainer = document.getElementById('monitor-changes-feed');
    if (!urlContainer || !subContainer || !feedContainer) return;

    const targets = window.state.monitorTargets;
    if (!targets.length) {
      urlContainer.innerHTML = window.emptyState('🔗', 'No URL monitors yet', 'Use Quick launch above, or CLI: autoar monitor updates add -u <url>');
    } else {
      urlContainer.innerHTML = `<table class="data-table">
        <thead><tr><th>URL</th><th>Strategy</th><th>Status</th><th>Changes</th><th>Last Run</th><th>Actions</th></tr></thead>
        <tbody>${targets.map((t) => {
        const id = t.ID ?? t.id;
        const running = !!(t.IsRunning || t.is_running);
        const pauseResume = running
          ? `<button type="button" class="btn btn-ghost" style="font-size:11px;padding:4px 10px" onclick="window.MonitorPage.pauseUrlMonitor(${id})">Pause</button>`
          : `<button type="button" class="btn btn-ghost" style="font-size:11px;padding:4px 10px" onclick="window.MonitorPage.resumeUrlMonitor(${id})">Resume</button>`;
        return `<tr>
          <td><span style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan)">${esc(t.URL || t.url || '')}</span></td>
          <td><span class="scan-type">${esc(t.Strategy || t.strategy || 'hash')}</span></td>
          <td>${running
            ? `<span class="badge badge-monitor-on">● running</span>`
            : `<span class="badge badge-monitor-off">stopped</span>`}</td>
          <td style="font-size:12px;color:var(--text-muted)">${t.ChangeCount || t.change_count || 0}</td>
          <td style="font-size:11px;color:var(--text-muted)">${fmtDate(t.LastRunAt || t.last_run_at)}</td>
          <td style="white-space:nowrap">${pauseResume}
            <button type="button" class="btn btn-ghost" style="font-size:11px;padding:4px 10px;margin-left:4px;color:var(--danger,#f87171)" onclick="window.MonitorPage.deleteUrlMonitor(${id})">Delete</button></td>
        </tr>`;
      }).join('')}</tbody>
      </table>`;
    }

    const subTargets = window.state.subMonitorTargets;
    if (!subTargets.length) {
      subContainer.innerHTML = window.emptyState('🌐', 'No subdomain monitors yet', 'Use Quick launch above, or CLI: autoar monitor subdomains manage add -d <domain>');
    } else {
      subContainer.innerHTML = `<table class="data-table">
        <thead><tr><th>Domain</th><th>Interval</th><th>Status</th><th>Last Run</th><th>Actions</th></tr></thead>
        <tbody>${subTargets.map((t) => {
        const id = t.ID ?? t.id;
        const running = !!(t.IsRunning || t.is_running);
        const pauseResume = running
          ? `<button type="button" class="btn btn-ghost" style="font-size:11px;padding:4px 10px" onclick="window.MonitorPage.pauseSubdomainMonitor(${id})">Pause</button>`
          : `<button type="button" class="btn btn-ghost" style="font-size:11px;padding:4px 10px" onclick="window.MonitorPage.resumeSubdomainMonitor(${id})">Resume</button>`;
        return `<tr>
          <td><span style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-purple)">${esc(t.Domain || t.domain || '')}</span></td>
          <td style="font-size:12px;color:var(--text-muted)">${fmtInterval(t.Interval || t.interval)}</td>
          <td>${running
            ? `<span class="badge badge-monitor-on">● running</span>`
            : `<span class="badge badge-monitor-off">stopped</span>`}</td>
          <td style="font-size:11px;color:var(--text-muted)">${fmtDate(t.LastRunAt || t.last_run_at)}</td>
          <td style="white-space:nowrap">${pauseResume}
            <button type="button" class="btn btn-ghost" style="font-size:11px;padding:4px 10px;margin-left:4px;color:var(--danger,#f87171)" onclick="window.MonitorPage.deleteSubdomainMonitor(${id})">Delete</button></td>
        </tr>`;
      }).join('')}</tbody>
      </table>`;
    }

    const changes = window.state.monitorChanges;
    if (!changes.length) {
      feedContainer.innerHTML = window.emptyState('📭', 'No changes recorded', 'Changes will appear here once monitors run.');
    } else {
      feedContainer.innerHTML = changes.map(c => changeItemHtml(c)).join('');
    }
  }

  function changeItemHtml(c) {
    const ctype = c.ChangeType || c.change_type || '';
    const domain = c.Domain || c.domain || '';
    const detail = c.Detail || c.detail || '';
    const at = c.DetectedAt || c.detected_at || '';
    const detailPreview = formatMonitorDetailPreview(detail);
    const iconMap = {
      new_subdomain: '🆕', became_live: '🟢', became_dead: '💀',
      content_changed: '📝', status_changed: '🔄',
    };
    return `<div class="change-item">
      <div class="change-dot ${ctype}"></div>
      <div class="change-body">
        <div class="change-title">${iconMap[ctype] || '📌'} ${esc(humanChangeType(ctype))}</div>
        <div class="change-detail">${esc(domain)}${detailPreview ? ` — ${esc(detailPreview).slice(0, 200)}` : ''}</div>
      </div>
      <div class="change-time">${timeAgo(at)}</div>
    </div>`;
  }

  window.MonitorPage = {
    loadMonitor,
    syncMonitorUrlPatternVisibility,
    quickAddUrlMonitor,
    quickAddSubdomainMonitor,
    runMonitorAISuggest,
    renderMonitorAISuggestResults,
    addSelectedMonitorSuggestions,
    pauseUrlMonitor,
    resumeUrlMonitor,
    deleteUrlMonitor,
    pauseSubdomainMonitor,
    resumeSubdomainMonitor,
    deleteSubdomainMonitor,
    clearMonitorChangeHistory,
    renderMonitor,
  };
})();

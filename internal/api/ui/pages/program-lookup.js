(() => {
  const SOURCE_META = {
    h1: { name: 'HackerOne', color: '#2ecc71' },
    bc: { name: 'Bugcrowd', color: '#e67e22' },
    it: { name: 'Intigriti', color: '#9b59b6' },
    ywh: { name: 'YesWeHack', color: '#3498db' },
    as93: { name: 'External', color: '#95a5a6' },
  };

  const esc = (s) =>
    window.esc ? window.esc(s) : String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  async function refreshStatus() {
    try {
      const s = await window.apiFetch('/api/assets/catalog-status');
      const el = document.getElementById('plookup-status');
      if (el) {
        const last = s.last_sync_at ? new Date(s.last_sync_at).toLocaleString() : 'never';
        el.innerHTML =
          `Catalog: <b>${s.programs || 0}</b> programs · <b>${s.domains || 0}</b> scoped domains · last sync: ${esc(last)}` +
          (s.sync_running ? ' · <span style="color:#f1c40f">syncing…</span>' : '');
      }
      return s;
    } catch (e) {
      return null;
    }
  }

  async function loadProgramLookup() {
    await refreshStatus();
  }

  async function programLookupSearch() {
    const q = (document.getElementById('plookup-search')?.value || '').trim();
    const box = document.getElementById('plookup-results');
    if (!q || !box) return;
    box.innerHTML = '<div class="empty-state"><div class="empty-title">Searching…</div></div>';
    try {
      const data = await window.apiFetch('/api/assets/program-lookup?q=' + encodeURIComponent(q));
      renderResults(data);
    } catch (e) {
      box.innerHTML = `<div class="empty-state"><div class="empty-title" style="color:var(--accent-red)">Search failed: ${esc(e.message)}</div></div>`;
    }
  }

  function renderResults(data) {
    const box = document.getElementById('plookup-results');
    const results = data.results || [];
    if (!results.length) {
      box.innerHTML =
        `<div class="empty-state"><div class="empty-icon">∅</div><div class="empty-title">No paying programs found for “${esc(data.query)}”</div>` +
        `<div style="font-size:12px;color:var(--text-muted);margin-top:6px">Try a different keyword, or Sync the catalog if you haven't yet.</div></div>`;
      return;
    }
    const rows = results
      .map((r) => {
        const meta = SOURCE_META[r.source] || { name: r.source, color: '#888' };
        let scopeBadge = '';
        if (r.match_type === 'domain') {
          scopeBadge = r.in_scope
            ? `<span style="flex-shrink:0;background:rgba(46,204,113,.15);color:#2ecc71;border:1px solid #2ecc7155;font-size:10px;font-weight:700;padding:2px 8px;border-radius:6px">IN-SCOPE</span>`
            : `<span style="flex-shrink:0;background:rgba(231,76,60,.15);color:#e74c3c;border:1px solid #e74c3c55;font-size:10px;font-weight:700;padding:2px 8px;border-radius:6px">OUT-OF-SCOPE</span>`;
        }
        const sub = [
          r.match_type === 'domain' ? 'matched: ' + esc(r.matched_domain) : '',
          r.rewards ? esc(r.rewards) : '',
          r.safe_harbor ? 'safe-harbor: ' + esc(r.safe_harbor) : '',
        ].filter(Boolean).join(' · ');
        return `
      <div style="display:flex;align-items:center;gap:12px;padding:12px 14px;border:1px solid var(--border);border-radius:10px;margin-bottom:8px;background:rgba(255,255,255,.02)">
        <span style="flex-shrink:0;font-size:10px;font-weight:800;color:${meta.color};border:1px solid ${meta.color}66;border-radius:6px;padding:3px 8px">${esc(meta.name)}</span>
        <div style="flex:1;min-width:0">
          <div style="font-weight:600;color:var(--text-primary);font-size:14px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.company)}</div>
          <div style="font-size:11px;color:var(--text-muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${sub}</div>
        </div>
        ${scopeBadge}
        <a href="${esc(r.url)}" target="_blank" rel="noopener" class="btn btn-sm" style="flex-shrink:0">Open</a>
      </div>`;
      })
      .join('');
    box.innerHTML =
      `<div style="font-size:12px;color:var(--text-muted);margin-bottom:10px">${results.length} paying program(s) for “${esc(data.query)}”${data.is_domain ? ' · domain search' : ''}</div>` +
      rows;
  }

  async function programLookupSync() {
    const btn = document.getElementById('plookup-sync-btn');
    if (btn) { btn.disabled = true; btn.textContent = '⟳ Syncing…'; }
    try {
      await window.apiPost('/api/assets/program-sync', {});
      window.showToast('info', 'Sync started', 'Rebuilding the program catalog in the background…');
      const poll = setInterval(async () => {
        const s = await refreshStatus();
        if (s && !s.sync_running) {
          clearInterval(poll);
          if (btn) { btn.disabled = false; btn.textContent = '⟳ Sync catalog'; }
          window.showToast('success', 'Catalog synced', `${s.programs || 0} programs · ${s.domains || 0} domains`);
        }
      }, 3000);
    } catch (e) {
      if (btn) { btn.disabled = false; btn.textContent = '⟳ Sync catalog'; }
      window.showToast('error', 'Sync failed', e.message);
    }
  }

  window.loadProgramLookup = loadProgramLookup;
  window.programLookupSearch = programLookupSearch;
  window.programLookupSync = programLookupSync;
})();

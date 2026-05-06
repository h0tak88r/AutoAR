// scan-detail-assets.js — Assets inventory grid and file-filter wiring.
// Extracted from scan-detail.js for maintainability.
// Exposes: window.ScanDetailAssets
(() => {
  const esc = (...args) => (typeof window.esc === 'function' ? window.esc(...args) : String(args[0] ?? ''));
  const fmtSize = (...args) => window.fmtSize(...args);

  function renderAssetsGrid(container, assets) {
    const renderRows = (list) => list.map(a => {
      const url = a.url || (a.host ? `https://${a.host}` : '#');
      const cname = Array.isArray(a.cnames) && a.cnames.length ? a.cnames.join(', ') : '—';
      const tech = Array.isArray(a.technologies) && a.technologies.length ? a.technologies.join(', ') : '—';
      return `<tr class="dashboard-table-row">
        <td>${a.is_live ? 'Alive' : 'Dead'}</td>
        <td><a href="${esc(url)}" target="_blank" rel="noopener" style="color:var(--accent-cyan)">${esc(a.host || '—')}</a></td>
        <td style="text-align:center">${a.status_code || '—'}</td>
        <td style="font-family:var(--font-mono,monospace);font-size:11px;color:var(--text-secondary)">${esc(cname)}</td>
        <td>${esc(tech)}</td>
      </tr>`;
    }).join('');

    container.innerHTML = `
      <div style="margin-bottom:12px;display:flex;gap:12px">
        <input id="asset-search" type="search" placeholder="Search hosts, CNAME, or tech…"
          style="flex:1;padding:8px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-size:12px"/>
      </div>
      <div style="border:1px solid var(--border);border-radius:8px;overflow:hidden">
        <table class="dashboard-table" style="margin:0;width:100%">
          <thead><tr><th>STATUS</th><th>HOST</th><th style="text-align:center">CODE</th><th>CNAME</th><th>TECHNOLOGIES</th></tr></thead>
          <tbody id="asset-tbody">${renderRows(assets)}</tbody>
        </table>
      </div>`;

    container.querySelector('#asset-search').addEventListener('input', e => {
      const q = e.target.value.toLowerCase().trim();
      const filtered = assets.filter(a =>
        String(a.host || '').toLowerCase().includes(q) ||
        (Array.isArray(a.cnames) ? a.cnames.join(' ').toLowerCase().includes(q) : false) ||
        (Array.isArray(a.technologies) ? a.technologies.some(t => String(t).toLowerCase().includes(q)) : false)
      );
      container.querySelector('#asset-tbody').innerHTML = renderRows(filtered);
    });
  }

  function wireScanDetailFilters(scanId, allFiles) {
    const s = document.getElementById('scan-file-search');
    const m = document.getElementById('scan-module-filter');
    const c = document.getElementById('scan-category-filter');
    const t = document.getElementById('scan-type-filter');

    const apply = () => {
      const q = s?.value.toLowerCase() || '';
      const f = { module: m?.value, category: c?.value, type: t?.value };
      const filtered = window.filterScanFiles(allFiles, q, f);
      const grid = document.getElementById('filtered-file-grid');
      if (grid) {
        grid.innerHTML = filtered.map(f =>
          `<div class="file-grid-item" onclick="window.loadScanFilePreview('${scanId}', '${esc(f.file_name)}')">
            <div class="file-grid-name">${esc(f.file_name)}</div>
            <div class="file-grid-meta">${fmtSize(f.size_bytes)} · ${f.is_json ? 'JSON' : 'TXT'}</div>
          </div>`
        ).join('');
      }
    };

    [s, m, c, t].forEach(el => el?.addEventListener('change', apply));
    if (s) s.addEventListener('input', apply);
  }

  window.ScanDetailAssets = {
    renderAssetsGrid,
    wireScanDetailFilters,
  };

  // Back-compat: also expose directly on window so existing callers keep working.
  window.renderAssetsGrid = renderAssetsGrid;
  window.wireScanDetailFilters = wireScanDetailFilters;
})();

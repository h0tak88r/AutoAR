(() => {
  function scanArtifactRowHtml(f) {
    const jm = f.is_json ? '✓' : '—';
    const fnAttr = encodeURIComponent(f.file_name);
    const rkAttr = fnAttr;
    return `<tr class="scan-file-row" data-r2="${rkAttr}" style="cursor:pointer">
    <td class="mono scan-asm-fname">${window.esc(f.file_name)}</td>
    <td>${window.fmtSize(f.size_bytes)}</td>
    <td><span class="scan-asm-src">${window.esc(f.source)}</span></td>
    <td>${jm}</td>
    <td><button type="button" class="btn btn-ghost scan-asm-preview-btn" style="font-size:11px;padding:4px 10px">Preview</button></td>
  </tr>`;
  }

  function scanAsmSectionHtml(id, icon, title, subtitle, files, emptyNote) {
    const body = files.length
      ? `<div class="scan-asm-table-wrap"><table class="data-table scan-asm-file-table"><thead><tr><th>File</th><th>Size</th><th>Source</th><th>JSON</th><th></th></tr></thead><tbody>
        ${files.map((f) => scanArtifactRowHtml(f)).join('')}
      </tbody></table></div>`
      : `<div class="scan-asm-empty">${window.esc(emptyNote)}</div>`;
    return `<section class="scan-asm-section" id="${id}">
    <div class="scan-asm-section-head">
      <span class="scan-asm-sec-icon">${icon}</span>
      <div class="scan-asm-sec-titles">
        <h2 class="scan-asm-sec-title">${window.esc(title)}</h2>
        <p class="scan-asm-sec-sub">${window.esc(subtitle)}</p>
      </div>
      <span class="scan-asm-badge">${files.length}</span>
    </div>
    ${body}
  </section>`;
  }

  async function loadScanDetailVulnerabilityInsights(scanId, allFiles) {
    const nucleiHost = document.getElementById('scan-nuclei-findings-body');
    const zeroHost = document.getElementById('scan-zerodays-insight-body');
    if (nucleiHost) nucleiHost.innerHTML = '<div class="scan-asm-muted">Loading Nuclei findings…</div>';
    if (zeroHost) zeroHost.innerHTML = '<div class="scan-asm-muted">Loading…</div>';

    const nucleiFiles = allFiles.filter((f) => {
      const n = (f.file_name || '').toLowerCase();
      return n.startsWith('nuclei-') && n !== 'nuclei-summary.txt';
    });
    const rows = [];
    let anyTrunc = false;
    for (const f of nucleiFiles) {
      try {
        const q = `file_name=${encodeURIComponent(f.file_name)}&page=1&per_page=500`;
        const data = await window.apiFetch(`/api/scans/${encodeURIComponent(scanId)}/results/file?${q}`);
        if (data.format !== 'text' || !data.lines) continue;
        if ((data.total_lines || 0) > 500) anyTrunc = true;
        for (const line of data.lines) {
          const p = window.parseNucleiFindingLine(line);
          if (p && p.url) rows.push({ ...p, sourceFile: f.file_name });
        }
      } catch (e) {
        console.warn('[scan detail] nuclei file', f.file_name, e);
      }
    }
    if (nucleiHost) {
      if (!rows.length) {
        nucleiHost.innerHTML = nucleiFiles.length
          ? '<div class="scan-asm-muted">No URL or JSON lines parsed from Nuclei output files (summary-only or empty).</div>'
          : '<div class="scan-asm-muted">No per-template Nuclei outputs (e.g. nuclei-custom-*.txt) for this scan.</div>';
      } else {
        const maxShow = 200;
        const show = rows.slice(0, maxShow);
        let tb = '<table class="scan-asm-data-table"><thead><tr><th>Source file</th><th>Template</th><th>Severity</th><th>Matched</th></tr></thead><tbody>';
        for (const r of show) {
          if (!r.url) continue;
          tb += `<tr><td class="mono">${window.esc(r.sourceFile)}</td><td class="mono">${window.esc(r.template)}</td><td><span class="scan-asm-sev">${window.esc(r.severity)}</span></td><td class="mono scan-asm-url-cell"><a href="${window.esc(r.url)}" target="_blank" rel="noopener" class="scan-result-link">${window.esc(r.url)}</a></td></tr>`;
        }
        tb += '</tbody></table>';
        if (rows.length > maxShow) tb += `<p class="scan-asm-muted" style="margin-top:10px">Showing ${maxShow} of ${rows.length} parsed lines.</p>`;
        if (anyTrunc) tb += '<p class="scan-asm-muted" style="margin-top:6px">Some files had more than 500 lines — only the first page was read. Use Preview on a file for full content.</p>';
        nucleiHost.innerHTML = tb;
      }
    }

    const zf = allFiles.find((f) => (f.file_name || '').toLowerCase() === 'zerodays-results.json');
    if (zeroHost) {
      if (!zf) {
        zeroHost.innerHTML = '<div class="scan-asm-muted">No zerodays-results.json for this scan.</div>';
      } else {
        try {
          const q = `file_name=${encodeURIComponent(zf.file_name)}&page=1&per_page=80`;
          const data = await window.apiFetch(`/api/scans/${encodeURIComponent(scanId)}/results/file?${q}`);
          if (data.format === 'json-array' && data.items && data.items.length) {
            const sample = data.items[0];
            const keys = sample && typeof sample === 'object' ? Object.keys(sample) : [];
            let tb = '<table class="scan-asm-data-table"><thead><tr>';
            keys.slice(0, 10).forEach((k) => { tb += `<th>${window.esc(k)}</th>`; });
            tb += '</tr></thead><tbody>';
            for (const item of data.items.slice(0, 40)) {
              tb += '<tr>';
              keys.slice(0, 10).forEach((k) => {
                const v = item[k];
                const s = v == null ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v);
                tb += `<td class="mono" style="word-break:break-all">${window.esc(s.length > 240 ? `${s.slice(0, 240)}…` : s)}</td>`;
              });
              tb += '</tr>';
            }
            tb += '</tbody></table>';
            if ((data.total_items || 0) > 40) tb += `<p class="scan-asm-muted" style="margin-top:8px">Showing 40 of ${data.total_items} items — open Preview on the JSON file for pagination.</p>`;
            zeroHost.innerHTML = tb;
          } else if (data.format === 'json-object' && data.data) {
            zeroHost.innerHTML = `<pre class="scan-asm-json-pre">${window.esc(JSON.stringify(data.data, null, 2))}</pre>`;
          } else {
            zeroHost.innerHTML = '<div class="scan-asm-muted">Could not parse zerodays JSON.</div>';
          }
        } catch (e) {
          zeroHost.innerHTML = `<div class="scan-asm-muted">${window.esc(e.message || String(e))}</div>`;
        }
      }
    }
  }

  function wireScanFileRows(container, scanId) {
    container.querySelectorAll('.scan-file-row').forEach((row) => {
      row.addEventListener('click', (e) => {
        if (e.target.closest('button')) return;
        const raw = row.getAttribute('data-r2');
        const k = raw ? decodeURIComponent(raw) : '';
        if (k) window.loadScanFilePreview(scanId, k);
      });
    });
    container.querySelectorAll('.scan-file-row button').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const row = e.target.closest('.scan-file-row');
        const raw = row && row.getAttribute('data-r2');
        const k = raw ? decodeURIComponent(raw) : '';
        if (k) window.loadScanFilePreview(scanId, k);
      });
    });
  }

  window.ScanDetailAsmPage = {
    scanArtifactRowHtml,
    scanAsmSectionHtml,
    loadScanDetailVulnerabilityInsights,
    wireScanFileRows,
  };
})();

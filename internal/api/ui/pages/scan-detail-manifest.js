// scan-detail-manifest.js — Execution pipeline / manifest card rendering.
// Exposes: window.ScanDetailManifest
(() => {
  const esc = (s) => {
    if (typeof window.esc === 'function') return window.esc(s);
    return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]);
  };
  const apiFetch = (...args) => window.apiFetch(...args);

  function formatManifestDuration(ms) {
    const n = Number(ms || 0);
    if (!Number.isFinite(n) || n <= 0) return '—';
    const sec = Math.floor(n / 1000);
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    if (h > 0) return `${h}h ${m}m ${s}s`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  }

  function manifestStatusBadge(status) {
    const st = String(status || '').toLowerCase();
    if (/completed|done|success/.test(st)) return 'badge-done';
    if (/running|starting|queued|active/.test(st)) return 'badge-running';
    if (/skipped|not_started/.test(st)) return 'badge-neutral';
    if (/pending/.test(st)) return 'badge-neutral';
    if (/paused|cancelling/.test(st)) return 'badge-starting';
    if (/failed|error|cancel/.test(st)) return 'badge-failed';
    if (/unknown/.test(st)) return 'badge-starting';
    return 'badge-neutral';
  }

  function manifestArtifactLabel(moduleEntry) {
    const files = Array.isArray(moduleEntry?.output_files) ? moduleEntry.output_files : [];
    const status = String(moduleEntry?.status || '').toLowerCase();
    if (files.length) return `${files.length} file${files.length === 1 ? '' : 's'}`;
    if (/completed|done|success/.test(status)) return '0 results (empty)';
    if (/skipped/.test(status)) return 'no results/skipped';
    if (/failed|error|cancel/.test(status)) return 'failed';
    if (/running|starting|queued|active/.test(status)) return 'processing...';
    if (/unknown/.test(status)) return '—';
    return 'pending';
  }

  function manifestStartedLabel(moduleEntry) {
    const raw = moduleEntry?.started_at || moduleEntry?.start_time || '';
    if (!raw) return '—';
    const d = new Date(raw);
    if (Number.isNaN(d.getTime())) return '—';
    return d.toLocaleTimeString();
  }

  function _moduleRow(m, scanId) {
    const mod = esc(m.module || m.name || 'unknown');
    const phaseKey = esc(m.phase_key || m.module || 'unknown');
    return `
      <tr class="manifest-row" data-module="${mod}" data-phase-key="${phaseKey}" data-scan-id="${esc(scanId)}" style="cursor:pointer">
        <td style="font-weight:600;font-size:13px">${mod}</td>
        <td><span class="badge ${manifestStatusBadge(m.status)}">${esc(m.status)}</span></td>
        <td style="font-family:monospace;font-size:12px;color:var(--text-muted)">${manifestArtifactLabel(m)}</td>
        <td style="font-size:11px;color:var(--text-muted)">${manifestStartedLabel(m)}</td>
        <td style="font-family:monospace;font-size:12px">${formatManifestDuration(m.duration_ms)}</td>
      </tr>
      <tr class="manifest-log-row" id="manifest-log-row-${phaseKey}" style="display:none;background:rgba(0,0,0,.25)">
        <td colspan="5" style="padding:0;border:none">
          <div class="manifest-log-panel" id="manifest-log-panel-${phaseKey}" style="padding:12px 16px;max-height:400px;overflow:auto;font-family:var(--font-mono,monospace);font-size:12px">
            <div style="color:var(--text-muted)">Click to load logs…</div>
          </div>
        </td>
      </tr>`;
  }

  async function loadModuleLogs(scanId, module, container) {
    container.innerHTML = '<div style="color:var(--text-muted);padding:8px 0">Loading logs…</div>';
    try {
      const resp = await apiFetch(`/api/scans/${encodeURIComponent(scanId)}/logs?module=${encodeURIComponent(module)}`);
      const lines = Array.isArray(resp?.lines) ? resp.lines : [];
      if (!lines.length) {
        container.innerHTML = '<div style="color:var(--text-muted);padding:8px 0">No logs captured for this phase yet.</div>';
        return;
      }
      const html = lines.map((ln) => {
        const ts = ln.timestamp ? new Date(ln.timestamp).toLocaleTimeString() : '';
        const level = String(ln.level || 'info').toLowerCase();
        let color = 'var(--text-secondary)';
        if (level === 'error' || level === 'fatal' || level === 'panic') color = '#ef4444';
        else if (level === 'warn' || level === 'warning') color = '#f59e0b';
        else if (level === 'debug') color = '#94a3b8';
        else if (level === 'info') color = '#22c55e';
        const msg = esc(ln.message || '');
        const fields = ln.fields && Object.keys(ln.fields).length
          ? ' <span style="color:var(--text-muted);font-size:11px">' + esc(JSON.stringify(ln.fields)) + '</span>'
          : '';
        return `<div style="padding:3px 0;border-bottom:1px solid rgba(255,255,255,.04)"><span style="color:var(--text-muted);font-size:11px;margin-right:8px">${esc(ts)}</span><span style="color:${color};font-weight:600;margin-right:8px">${esc(level.toUpperCase())}</span><span style="color:var(--text-primary)">${msg}</span>${fields}</div>`;
      }).join('');
      container.innerHTML = html;
    } catch (e) {
      container.innerHTML = `<div style="color:var(--accent-red);padding:8px 0">Failed to load logs: ${esc(e.message || String(e))}</div>`;
    }
  }

  function wireManifestRowClicks(root) {
    if (!root) return;
    root.querySelectorAll('.manifest-row').forEach((row) => {
      row.onclick = null; // ensure idempotent
      row.addEventListener('click', async () => {
        const scanId = row.getAttribute('data-scan-id');
        const phaseKey = row.getAttribute('data-phase-key');
        const logRow = document.getElementById(`manifest-log-row-${phaseKey}`);
        const panel = document.getElementById(`manifest-log-panel-${phaseKey}`);
        if (!logRow || !panel) return;

        const isOpen = logRow.style.display !== 'none';
        // Close any open log rows first
        root.querySelectorAll('.manifest-log-row').forEach((r) => { r.style.display = 'none'; });

        if (!isOpen) {
          logRow.style.display = 'table-row';
          // Load logs only on first open
          if (panel.dataset.loaded !== '1') {
            panel.dataset.loaded = '1';
            await loadModuleLogs(scanId, phaseKey, panel);
          }
        }
      });
    });
  }

  function renderScanManifestCard(manifest, scan) {
    const modules = Array.isArray(manifest?.modules) ? manifest.modules : [];
    const scanStatus = scan?.status || scan?.Status || '';
    const isActive = /running|starting|paused|cancelling/i.test(scanStatus);
    const scanId = scan?.scan_id || scan?.ScanID || '';

    if (!modules.length && !isActive) return '';

    return `
      <div class="modern-card" style="margin-bottom:20px">
        <div class="card-header" style="cursor:pointer" onclick="const b=this.nextElementSibling; b.style.display=b.style.display==='none'?'block':'none'">
          <div class="card-title"><span class="card-title-icon"></span>Execution Pipeline</div>
          <div style="font-size:11px;color:var(--text-muted)">${modules.length} phases documented · click any row for logs</div>
        </div>
        <div class="card-body" style="padding:0;display:block">
          <table class="dashboard-table" style="width:100%">
            <thead><tr><th>Phase</th><th>Status</th><th>Artifacts</th><th>Started</th><th>Duration</th></tr></thead>
            <tbody id="scan-manifest-tbody">
              ${modules.map((m) => _moduleRow(m, scanId)).join('')}
            </tbody>
          </table>
        </div>
      </div>`;
  }

  async function fetchScanManifest(scanId) {
    try {
      return await apiFetch(`/api/scans/${encodeURIComponent(scanId)}/manifest`);
    } catch (e) {
      return null;
    }
  }

  async function refreshScanManifestCard(scanId, scan) {
    const resp = await fetchScanManifest(scanId);
    if (!resp || !resp.manifest) return;
    const modules = Array.isArray(resp.manifest.modules) ? resp.manifest.modules : [];
    const scanIdVal = scan?.scan_id || scan?.ScanID || '';
    const tbody = document.getElementById('scan-manifest-tbody');
    if (tbody) {
      tbody.innerHTML = modules.map((m) => _moduleRow(m, scanIdVal)).join('');
      wireManifestRowClicks(tbody.closest('.modern-card'));
    }
  }

  window.ScanDetailManifest = {
    formatManifestDuration,
    manifestStatusBadge,
    manifestArtifactLabel,
    manifestStartedLabel,
    renderScanManifestCard,
    fetchScanManifest,
    refreshScanManifestCard,
    wireManifestRowClicks,
  };
})();

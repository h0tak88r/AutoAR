// scan-detail-manifest.js — Execution pipeline / manifest card rendering.
// Extracted from scan-detail.js for maintainability.
// Exposes: window.ScanDetailManifest
(() => {
  const esc = (...args) => (typeof window.esc === 'function' ? window.esc(...args) : String(args[0] ?? ''));
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

  function _moduleRow(m) {
    return `
      <tr>
        <td style="font-weight:600;font-size:13px">${esc(m.module || m.name || 'unknown')}</td>
        <td><span class="badge ${manifestStatusBadge(m.status)}">${esc(m.status)}</span></td>
        <td style="font-family:monospace;font-size:12px;color:var(--text-muted)">${manifestArtifactLabel(m)}</td>
        <td style="font-size:11px;color:var(--text-muted)">${manifestStartedLabel(m)}</td>
        <td style="font-family:monospace;font-size:12px">${formatManifestDuration(m.duration_ms)}</td>
      </tr>`;
  }

  function renderScanManifestCard(manifest, scan) {
    const modules = Array.isArray(manifest?.modules) ? manifest.modules : [];
    const scanStatus = scan?.status || scan?.Status || '';
    const isActive = /running|starting|paused|cancelling/i.test(scanStatus);

    if (!modules.length && !isActive) return '';

    return `
      <div class="modern-card" style="margin-bottom:20px">
        <div class="card-header" style="cursor:pointer" onclick="const b=this.nextElementSibling; b.style.display=b.style.display==='none'?'block':'none'">
          <div class="card-title"><span class="card-title-icon">⚙</span>Execution Pipeline</div>
          <div style="font-size:11px;color:var(--text-muted)">${modules.length} phases documented</div>
        </div>
        <div class="card-body" style="padding:0">
          <table class="dashboard-table" style="width:100%">
            <thead><tr><th>Phase</th><th>Status</th><th>Artifacts</th><th>Started</th><th>Duration</th></tr></thead>
            <tbody id="scan-manifest-tbody">
              ${modules.map(_moduleRow).join('')}
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
    const tbody = document.getElementById('scan-manifest-tbody');
    if (tbody) {
      tbody.innerHTML = modules.map(_moduleRow).join('');
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
  };
})();

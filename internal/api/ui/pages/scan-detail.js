(() => {
  const esc = (...args) => (typeof window.esc === 'function' ? window.esc(...args) : String(args[0] ?? ''));
  const apiFetch = (...args) => window.apiFetch(...args);
  const navigateTo = (...args) => window.navigateTo(...args);
  const showToast = (...args) => window.showToast(...args);
  const API = '';
  const apiPost = (...args) => window.apiPost(...args);
  const fmtSize = (...args) => window.fmtSize(...args);
  const getFileTypeFromName = (...args) => window.getFileTypeFromName(...args);
  const getFileTypeIcon = (...args) => window.getFileTypeIcon(...args);
  const detectModuleFromFileName = (...args) => window.detectModuleFromFileName(...args);
  const getModuleDisplayInfo = (...args) => window.getModuleDisplayInfo(...args);
  const scanNoArtifactsMessage = (...args) => window.scanNoArtifactsMessage(...args);
  const escAttr = (...args) => window.escAttr(...args);
  const copyToClipboard = (...args) => window.copyToClipboard(...args);

  // ── State for Scan Detail Page ──────────────────────────────────────────
  window._scanDetailKnownFiles = new Set();
  window._scanDetailRefreshTimer = null;
  window._scanDetailRefreshId = null;
  let _assetsCache = null;

  async function renderScanDetailView(scanId) {
    const container = document.getElementById('scan-detail-container');
    const sub = document.getElementById('scan-detail-sub');
    const apiA = document.getElementById('scan-detail-api');
    if (!container) return;
    const ui = window.state.scanDetailUI;

    // Show modern loading skeleton
    container.innerHTML = `
      <div class="scan-detail-modern">
        <div class="scan-summary-stats">
          ${[1, 2, 3, 4].map(() => `
            <div class="skeleton-card">
              <div class="skeleton-line skeleton-title"></div>
              <div class="skeleton-line skeleton-text"></div>
            </div>
          `).join('')}
        </div>
        <div class="skeleton-card">
          <div class="skeleton-line skeleton-title"></div>
          <div class="skeleton-line skeleton-text"></div>
          <div class="skeleton-line skeleton-text"></div>
        </div>
      </div>`;

    try {
      const sum = await apiFetch(
        `/api/scans/${encodeURIComponent(scanId)}/results/summary?page=${ui.filesPage}&per_page=${ui.filesPerPage}`
      );
      const manifestResp = await fetchScanManifest(scanId);
      const scan = sum.scan;
      const target = scan.target || scan.Target || '';
      const st = scan.scan_type || scan.ScanType || '';
      const stat = scan.status || scan.Status || '';
      const statLower = stat.toLowerCase();
      const titleEl = document.getElementById('scan-detail-title');
      if (titleEl) titleEl.textContent = target || 'Scan results';

      // Render scan type + status with live badge if running
      if (sub) {
        const isActive = /running|starting|paused|cancelling/i.test(stat);
        if (isActive) {
          const isCancelling = /cancelling/i.test(stat);
          const isPaused = /paused/i.test(stat);
          const liveBadge = isPaused
            ? `<span class="badge badge-starting" style="font-size:10px;padding:2px 8px;margin-left:8px">⏸ paused</span>`
            : isCancelling
              ? `<span class="badge badge-starting" style="font-size:10px;padding:2px 8px;margin-left:8px">⋯ stopping</span>`
              : `<span class="badge badge-running" style="font-size:10px;padding:2px 8px;margin-left:8px;animation:pulse 1.4s ease-in-out infinite">● live</span>`;
          sub.innerHTML = `${esc(st)} · ${esc(statLower)}${liveBadge}`;
        } else {
          sub.textContent = `${st} · ${statLower}`;
        }
      }
      if (apiA) apiA.style.display = 'none';
      const r2DetailBtn = document.getElementById('scan-detail-r2-btn');
      if (r2DetailBtn) {
        if (st) {
          r2DetailBtn.style.display = 'inline-flex';
          if (target) {
            r2DetailBtn.disabled = false;
            r2DetailBtn.title = 'Browse scan artifacts in R2';
            r2DetailBtn.onclick = () => window.browseR2ForScan(target, st);
          } else {
            r2DetailBtn.disabled = true;
            r2DetailBtn.title = 'Target is unavailable for this scan record';
            r2DetailBtn.onclick = null;
          }
        } else {
          r2DetailBtn.style.display = 'none';
          r2DetailBtn.disabled = false;
          r2DetailBtn.title = '';
          r2DetailBtn.onclick = null;
        }
      }

      const rescanDetailBtn = document.getElementById('scan-detail-rescan-btn');
      if (rescanDetailBtn) {
        const isActive = /running|starting|paused|cancelling/i.test(stat);
        if (!isActive) {
          rescanDetailBtn.style.display = 'inline-flex';
          rescanDetailBtn._rescan = () => window.rescanScan(scanId);
        } else {
          rescanDetailBtn.style.display = 'none';
          rescanDetailBtn._rescan = null;
        }
      }
      const deleteDetailBtn = document.getElementById('scan-detail-delete-btn');
      if (deleteDetailBtn) {
        deleteDetailBtn.onclick = async () => {
          await window.deleteScan(scanId, target);
          navigateTo('overview');
        };
      }

      const clearCacheBtn = document.getElementById('scan-detail-clear-cache-btn');
      if (clearCacheBtn) {
        const isApkx = /apkx/i.test(String(st || ''));
        clearCacheBtn.style.display = isApkx ? 'inline-flex' : 'none';
        clearCacheBtn.onclick = isApkx ? () => clearApkxCacheForScan(scan) : null;
      }

      const files = sum.files || [];
      const total = sum.total || 0;

      const statNorm = String(stat || '').trim();
      const finishedOk = /^(completed|done|success)$/i.test(statNorm);
      const stillRunning = /^(running|pending|queued|active|in_progress|starting)$/i.test(statNorm);
      const failedish = /fail|error|cancel/i.test(statNorm);

      const zipURL = scan.result_url || scan.ResultURL || '';
      const zipBanner = zipURL
        ? `<div class="modern-card" style="padding:18px">
            <div style="display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap">
              <div>
                <div style="font-size:14px;font-weight:600;color:var(--text-primary);margin-bottom:4px">📦 Full Scan Archive</div>
                <div style="font-size:12px;color:var(--text-muted)">Download complete scan results as ZIP</div>
              </div>
              <a href="${esc(zipURL)}" target="_blank" rel="noopener" class="btn btn-primary">Download ZIP</a>
            </div>
          </div>`
        : '';

      const manifestCard = renderScanManifestCard(manifestResp?.manifest || null, scan);

      let emptyBanner = '';
      if (!files.length) {
        let emptyMsg;
        if (finishedOk) {
          emptyMsg = `<div class="scan-no-results-banner">${esc(scanNoArtifactsMessage(st, target))}</div>
            <p class="scan-asm-muted" style="margin-top:12px">No files were indexed for this scan. Confirm uploads and artifact indexing.</p>`;
        } else if (stillRunning) {
          emptyMsg = '<div style="text-align:center;padding:20px"><div style="font-size:40px;margin-bottom:12px">⏳</div><div style="font-size:14px;color:var(--text-secondary)">Scan is still running or processing. Check back soon for results.</div></div>';
        } else if (failedish) {
          emptyMsg = `<div style="text-align:center;padding:20px"><div style="font-size:40px;margin-bottom:12px">❌</div><div style="font-size:14px;color:var(--accent-red)">No result files indexed. Status: ${esc(statNorm)}</div></div>`;
        } else {
          emptyMsg = '<div style="text-align:center;padding:20px"><div style="font-size:40px;margin-bottom:12px">📋</div><div style="font-size:14px;color:var(--text-muted)">No indexed artifacts for this scan yet.</div></div>';
        }
        emptyBanner = `<div class="modern-card" style="padding:20px">${emptyMsg}</div>`;
      }

      let html;
      if (!files.length) {
        html = `
          <div class="scan-detail-modern">
            ${zipBanner}
            ${manifestCard}
            ${emptyBanner}
            <div class="modern-card" style="padding:20px">
              <div style="text-align:center;color:var(--text-muted)">No files to preview.</div>
            </div>
          </div>`;
      } else {
        const reportCard = `
          <div class="modern-card" id="scan-report-card">
            <div class="card-header">
              <div class="card-title"><span class="card-title-icon">📄</span>Generate Report</div>
            </div>
            <div style="padding:16px;display:flex;gap:12px;align-items:center;flex-wrap:wrap">
              <select id="scan-report-template-sel" style="
                flex:1;min-width:180px;
                padding:8px 12px;
                background:var(--bg-input);
                border:1px solid var(--border);
                border-radius:8px;
                color:var(--text-primary);
                font-size:13px
              ">
                <option value="default">Default template</option>
              </select>
              <button id="scan-report-preview-btn" class="btn btn-ghost" style="font-size:12px;padding:8px 14px">
                👁 Preview
              </button>
              <a id="scan-report-download-btn" class="btn btn-primary" style="font-size:12px;padding:8px 14px;text-decoration:none" href="#" download>
                ⬇ Download .md
              </a>
            </div>
            <div id="scan-report-preview" style="
              display:none;
              padding:16px;
              border-top:1px solid var(--border);
              max-height:400px;
              overflow-y:auto;
              font-size:13px;
              white-space:pre-wrap;
              color:var(--text-primary)
            "></div>
          </div>`;

        html = `
          <div class="scan-detail-modern">
            ${zipBanner}
            ${manifestCard}
            ${reportCard}
            ${emptyBanner}
            
            <div class="modern-card">
              <div class="card-header">
                <div class="card-title"><span class="card-title-icon">📊</span>Findings</div>
                <span class="badge badge-running" id="unified-parsed-badge">${total} files</span>
              </div>
              <div id="unified-parsed-results" style="padding:16px">
                <div style="text-align:center;padding:20px;color:var(--text-muted)">Loading all findings...</div>
              </div>
            </div>
          </div>`;
      }

      container.innerHTML = html;

      // Wire report generation card
      const reportTemplateSel = document.getElementById('scan-report-template-sel');
      const reportPreviewBtn  = document.getElementById('scan-report-preview-btn');
      const reportDownloadBtn = document.getElementById('scan-report-download-btn');
      const reportPreviewDiv  = document.getElementById('scan-report-preview');

      if (reportTemplateSel) {
        apiFetch('/api/report-templates').then(resp => {
          const templates = Array.isArray(resp) ? resp : (resp?.templates || []);
          templates.forEach(t => {
            const opt = document.createElement('option');
            opt.value = t.name || t;
            opt.textContent = t.name || t;
            if (opt.value !== 'default') reportTemplateSel.appendChild(opt);
          });
        }).catch(() => {});
      }

      if (reportDownloadBtn && reportTemplateSel) {
        const buildReportUrl = () => {
          const tmpl = encodeURIComponent(reportTemplateSel.value || 'default');
          return `/api/scans/${encodeURIComponent(scanId)}/report?template=${tmpl}&format=markdown`;
        };
        reportDownloadBtn.href = buildReportUrl();
        reportTemplateSel.addEventListener('change', () => {
          reportDownloadBtn.href = buildReportUrl();
          if (reportPreviewDiv && reportPreviewDiv.style.display !== 'none') {
            previewReport();
          }
        });
      }

      const previewReport = async () => {
        if (!reportPreviewDiv || !reportTemplateSel) return;
        const tmpl = encodeURIComponent(reportTemplateSel.value || 'default');
        try {
          const r = await apiFetch(`/api/scans/${encodeURIComponent(scanId)}/report?template=${tmpl}&format=json`);
          reportPreviewDiv.textContent = r.rendered || '(empty)';
          reportPreviewDiv.style.display = 'block';
        } catch (e) {
          reportPreviewDiv.textContent = 'Error loading preview: ' + e.message;
          reportPreviewDiv.style.display = 'block';
        }
      };
      if (reportPreviewBtn) reportPreviewBtn.addEventListener('click', previewReport);

      window.wireScanFileRows(container, scanId);
      window.wireScanDetailFilters(scanId, files);
      loadReconUnifiedTable(scanId, files, 'unified-parsed-results', scan);

      if (files.length) {
        window.loadScanDetailVulnerabilityInsights(scanId, files);
      }

      if (ui.selectedFileName) {
        requestAnimationFrame(() => {
          window.loadScanFilePreview(scanId, ui.selectedFileName, { retainPage: true });
        });
      }
      if (stillRunning) {
        scheduleScanDetailRefresh(scanId);
      } else {
        clearScanDetailRefreshTimer();
      }

    } catch (e) {
      container.innerHTML = `<div class="modern-card" style="padding:20px;border-color:var(--accent-red)"><div style="color:var(--accent-red)">${esc(e.message || String(e))}</div></div>`;
    }
  }

  async function clearApkxCacheForScan(scan) {
    const target = String(scan?.target || scan?.Target || '').trim();
    const looksLikePackage = /^[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+$/.test(target);
    const scopeLabel = looksLikePackage ? `package cache for ${target}` : 'ALL APK cache';
    if (!confirm(`Clear ${scopeLabel}?`)) return;
    try {
      const body = looksLikePackage ? { package: target } : { all: true };
      const res = await apiPost('/api/apkx/cache/clear', body);
      const localN = Number(res?.local_removed || 0);
      const r2N = Number(res?.r2_removed || 0);
      const r2Err = String(res?.r2_error || '').trim();
      window.showToast('success', 'APK cache cleared', `Local: ${localN}, R2: ${r2N}${r2Err ? ' (R2 warning)' : ''}`);
    } catch (e) {
      window.showToast('error', 'Failed to clear APK cache', e.message || String(e));
    }
  }

  function clearScanDetailRefreshTimer() {
    if (window._scanDetailRefreshTimer) {
      clearTimeout(window._scanDetailRefreshTimer);
      window._scanDetailRefreshTimer = null;
    }
  }

  function scheduleScanDetailRefresh(scanId, ms = 4000) {
    clearScanDetailRefreshTimer();
    window._scanDetailRefreshId = scanId;
    window._scanDetailRefreshTimer = setTimeout(() => doScanDetailRefresh(scanId), ms);
  }

  async function doScanDetailRefresh(scanId) {
    if (window.state.view !== 'scan-detail' || window.state.scanDetailId !== scanId) return;

    try {
      const sum = await apiFetch(`/api/scans/${encodeURIComponent(scanId)}/results/summary?page=1&per_page=200`);
      const scan = sum.scan || {};
      const stat = String(scan.status || scan.Status || '').toLowerCase();
      const files = sum.files || [];
      const stillRunning = /^(running|pending|queued|active|in_progress|starting)$/.test(stat);

      const sub = document.getElementById('scan-detail-sub');
      if (sub) {
        if (stillRunning) {
          const isCancelling = /cancelling/.test(stat);
          const isPaused = /paused/.test(stat);
          const scanType = scan.scan_type || '';
          const liveBadge = isPaused
            ? `<span class="badge badge-starting" style="font-size:10px;padding:2px 8px;margin-left:8px">⏸ paused</span>`
            : isCancelling
              ? `<span class="badge badge-starting" style="font-size:10px;padding:2px 8px;margin-left:8px">⋯ stopping</span>`
              : `<span class="badge badge-running" style="font-size:10px;padding:2px 8px;margin-left:8px;animation:pulse 1.4s ease-in-out infinite">● live</span>`;
          sub.innerHTML = `${esc(scanType)} · ${esc(stat)}${liveBadge}`;
        } else {
          sub.textContent = `${scan.scan_type || ''} · ${stat}`;
        }
      }

      refreshScanManifestCard(scanId, scan);

      const badge = document.getElementById('unified-parsed-badge');
      if (badge) {
        const countStr = `${files.length} files`;
        if (badge.textContent !== countStr) badge.textContent = countStr;
      }

      const newFiles = files.filter(f => !window._scanDetailKnownFiles.has(f.file_name));
      if (newFiles.length) {
        newFiles.forEach(f => window._scanDetailKnownFiles.add(f.file_name));
        const unifiedRoot = document.getElementById('unified-parsed-results');
        if (unifiedRoot) {
          loadReconUnifiedTable(scanId, files, 'unified-parsed-results');
          _assetsCache = null;
        }
      }

      if (stillRunning) {
        scheduleScanDetailRefresh(scanId, 4500);
      } else {
        clearScanDetailRefreshTimer();
        await renderScanDetailView(scanId);
      }
    } catch (e) {
      scheduleScanDetailRefresh(scanId, 8000);
    }
  }

  async function fetchScanManifest(scanId) {
    try {
      return await apiFetch(`/api/scans/${encodeURIComponent(scanId)}/manifest`);
    } catch (e) {
      return null;
    }
  }

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
    if (/paused|cancelling/.test(st)) return 'badge-starting';
    if (/failed|error|cancel/.test(st)) return 'badge-failed';
    return 'badge-neutral';
  }

  function renderScanManifestCard(manifest, scan) {
    const modules = Array.isArray(manifest?.modules) ? manifest.modules : [];
    const scanStatus = scan?.status || scan?.Status || '';
    const isActive = /running|starting|paused|cancelling/i.test(scanStatus);
    
    if (!modules.length && !isActive) return '';

    return `
      <div class="modern-card" style="margin-bottom:20px">
        <div class="card-header" style="cursor:pointer" onclick="const b=this.nextElementSibling; b.style.display=b.style.display==='none'?'block':'none'">
          <div class="card-title"><span class="card-title-icon">⚙️</span>Execution Pipeline</div>
          <div style="font-size:11px;color:var(--text-muted)">${modules.length} phases documented</div>
        </div>
        <div class="card-body" style="padding:0">
          <table class="dashboard-table" style="width:100%">
            <thead><tr><th>Phase</th><th>Status</th><th>Started</th><th>Duration</th></tr></thead>
            <tbody id="scan-manifest-tbody">
              ${modules.map(m => `
                <tr>
                  <td style="font-weight:600;font-size:13px">${esc(m.name)}</td>
                  <td><span class="badge ${manifestStatusBadge(m.status)}">${esc(m.status)}</span></td>
                  <td style="font-size:11px;color:var(--text-muted)">${m.start_time ? new Date(m.start_time).toLocaleTimeString() : '—'}</td>
                  <td style="font-family:monospace;font-size:12px">${formatManifestDuration(m.duration_ms)}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>`;
  }

  async function refreshScanManifestCard(scanId, scan) {
    const resp = await fetchScanManifest(scanId);
    if (!resp || !resp.manifest) return;
    const modules = Array.isArray(resp.manifest.modules) ? resp.manifest.modules : [];
    const tbody = document.getElementById('scan-manifest-tbody');
    if (tbody) {
      tbody.innerHTML = modules.map(m => `
        <tr>
          <td style="font-weight:600;font-size:13px">${esc(m.name)}</td>
          <td><span class="badge ${manifestStatusBadge(m.status)}">${esc(m.status)}</span></td>
          <td style="font-size:11px;color:var(--text-muted)">${m.start_time ? new Date(m.start_time).toLocaleTimeString() : '—'}</td>
          <td style="font-family:monospace;font-size:12px">${formatManifestDuration(m.duration_ms)}</td>
        </tr>
      `).join('');
    }
  }

  // ── Unified Findings Table Implementation ──────────────────────────────────
  async function loadReconUnifiedTable(scanId, allFiles, containerId, scanRecord) {
    const root = document.getElementById(containerId);
    if (!root) return;
    let wrap = null;
    const stNorm = String(scanRecord?.scan_type || scanRecord?.ScanType || '').toLowerCase();
    const isAPKScan = stNorm.includes('apkx');
    const badge = document.getElementById('unified-parsed-badge') || document.getElementById('recon-parsed-badge');

    if (!allFiles || !allFiles.length) {
      if (badge) badge.textContent = '0 artifacts';
      root.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted)">No artifacts found.</div>';
      return;
    }

    root.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted)">Loading all findings…</div>';
    let allRows = [];
    try {
      const parsed = await apiFetch(`/api/scans/${encodeURIComponent(scanId)}/results/parsed?section=all&limit=5000`);
      if (Array.isArray(parsed.rows)) {
        allRows = parsed.rows;
      }
    } catch (e) {
      console.warn('[scan detail] parsed recon api fallback', e);
    }

    if (!allRows.length) {
      for (const f of allFiles) {
        try {
          const data = await apiFetch(`/api/scans/${encodeURIComponent(scanId)}/results/file?file_name=${encodeURIComponent(f.file_name)}&page=1&per_page=500`);
          const rows = window.previewDataToFlatRows(data, f).map((r) => ({
            ...r,
            kind: window.inferKindFromFileName(r.file),
            category: window.categorizeScanArtifactFile(r.file),
          }));
          allRows.push(...rows);
        } catch (e) {
          allRows.push({
            file: f.file_name,
            module: detectModuleFromFileName(f.file_name, f.module),
            source: f.source || '—',
            category: window.categorizeScanArtifactFile(f.file_name),
            kind: window.inferKindFromFileName(f.file_name),
            severity: '—',
            target: '—',
            finding: `[Error reading file] ${e.message || e}`,
          });
        }
      }
    }

    if (badge) {
      badge.textContent = `${allRows.length} rows · ${allFiles.length} files`;
    }

    if (!allRows.length) {
      root.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted)">No parseable findings.</div>';
      return;
    }

    if (isAPKScan) {
      const hasJsonRows = allRows.some((r) => String(r.file || '').toLowerCase().endsWith('.json'));
      if (hasJsonRows) {
        allRows = allRows.filter((r) => String(r.file || '').toLowerCase().endsWith('.json'));
      }
    }

    allRows = allRows
      .map((r) => {
        let kind = String(r.kind || window.inferKindFromFileName(r.file) || 'other').toLowerCase().trim();
        const file = String(r.file || '').toLowerCase();
        const target = String(r.target || r.host || '').toLowerCase();
        const finding = String(r.title || r.finding || '').trim();
        const moduleNorm = window.normalizeModuleKey(r.module);

        if (kind === 'js-urls') kind = 'js_urls';
        if (kind === 'unknown' || kind === 'unknowns') kind = 'other';

        const looksLikeJSMatcher = /^\s*\[[^\]]+\].*->/i.test(finding) || file.includes('js-secret') || file.includes('js-exposure');
        const looksLikeJSURL = file.includes('js-url') || /\.m?jsx?(\?|$)/i.test(target);

        if (looksLikeJSMatcher) kind = 'js-analysis';
        else if (looksLikeJSURL && kind === 'other') kind = 'js_urls';
        if (isAPKScan) kind = 'apkx';

        const isJS = kind === 'js_urls' || looksLikeJSURL;
        if (kind === 'js_urls') kind = 'urls';

        const normalizedModule = (moduleNorm === 'unknown' && (kind === 'js-analysis' || isJS))
          ? 'js-analysis'
          : (isAPKScan ? 'apkx' : moduleNorm);

        return {
          ...r,
          kind,
          module: normalizedModule,
          is_js: isJS || r.is_js || false,
        };
      })
      .filter((r) => {
        const finding = String(r.title || r.finding || '').trim().toLowerCase();
        const target = String(r.target || r.host || '').trim();
        if (finding === 'no findings found' && (target === '' || target === '-' || target === '—')) {
          return false;
        }
        if (isAPKScan) {
          if ((target === '' || target === '-' || target === '—') && (finding === '' || finding === '—' || finding === 'autoar' || finding === 'apkx')) {
            return false;
          }
        }
        return true;
      });

    const VULN_KINDS = new Set(['vuln', 'nuclei', 'reflection', 'ports', 'buckets', 'backup', 'zerodays', 'aem', 'misconfig', 's3', 'gf', 'ffuf', 'dns', 'github', 'sqlmap', 'aem-findings']);
    const totalVuln = Array.from(VULN_KINDS).reduce((acc, k) => acc + (allRows.filter(r => (r.kind || 'other') === k).length), 0);

    const isReconScan = stNorm === 'recon' || stNorm === 'lite' || stNorm === 'domain_scan' || stNorm === 'subdomain_scan' || stNorm === 'subdomain_run';
    let activeKind = isReconScan ? 'assets' : 'urls';
    if (totalVuln === 0 && !isReconScan && (allRows.some(r => r.kind === 'urls'))) activeKind = 'urls';
    let searchHost = '';
    let searchTitle = '';
    let searchModule = 'all';
    let filterSeverity = 'any';

    const _kindCounts = {};
    for (const r of allRows) _kindCounts[r.kind || 'other'] = (_kindCounts[r.kind || 'other'] || 0) + 1;
    const HIDDEN_KINDS = new Set(['logs', 'log', 'tech', 'js_urls']);
    const TAB_LABELS = {
      assets: '🏠 Assets',
      urls: '🔗 Links',
      apkx: '📱 APK Analysis',
      'js-analysis': '📜 JS Analysis',
      'gf-patterns': '🎯 GF Patterns',
      nuclei: '☢️ Nuclei',
      ffuf: '🎲 FFUF',
      buckets: '🪣 S3 Buckets',
      ports: '📡 Ports',
      reflection: '🔎 Reflection',
      other: '📁 Other',
    };

    const dynamicKinds = [...new Set(allRows.map(r => r.kind || 'other'))];
    const DATASET_TABS = [];
    
    if (isReconScan || allRows.some(r => r.kind === 'subdomains' || r.kind === 'assets')) {
      DATASET_TABS.push(['assets', TAB_LABELS.assets]);
    }

    dynamicKinds.forEach(k => {
      if (k === 'subdomains' || k === 'assets' || k === 'vuln' || VULN_KINDS.has(k)) {
        if (['js-analysis', 'gf-patterns', 'nuclei', 'ffuf', 'reflection'].includes(k)) {
          DATASET_TABS.push([k, TAB_LABELS[k] || k]);
        }
        return;
      }
      if (k === 'urls') {
        DATASET_TABS.push(['urls', TAB_LABELS.urls]);
        return;
      }
      if (!['logs', 'log', 'tech'].includes(k)) {
         DATASET_TABS.push([k, TAB_LABELS[k] || k]);
      }
    });

    const seenTabs = new Set();
    let UNIQUE_TABS = DATASET_TABS.filter(t => {
      if (seenTabs.has(t[0])) return false;
      seenTabs.add(t[0]);
      return true;
    });

    const preferredModuleOrder = [
      'nuclei', 'gf-patterns', 'misconfig', 'ffuf-fuzzing', 'dns-takeover', 
      'backup-detection', 'js-analysis', 'xss-detection', 'sql-detection', 
      's3-scan', 'port-scan', 'zerodays', 'aem', 'github-scan'
    ];
    const usedModulesRaw = [...new Set(allRows.map(r => window.normalizeModuleKey(r.module)).filter(Boolean))];
    const usedModules = usedModulesRaw.sort((a, b) => {
      const ai = preferredModuleOrder.indexOf(a);
      const bi = preferredModuleOrder.indexOf(b);
      if (ai !== -1 && bi !== -1) return ai - bi;
      if (ai !== -1) return -1;
      if (bi !== -1) return 1;
      return a.localeCompare(b);
    });
    const excludedModuleTabs = new Set(['autoar', 'unknown', 'tech-detect', 'ffuf-fuzzing', 'js-analysis']);
    const hasUrlsDatasetTab = UNIQUE_TABS.some((t) => t[0] === 'urls');
    if (hasUrlsDatasetTab) excludedModuleTabs.add('url-collection');
    const hasApkxDatasetTab = UNIQUE_TABS.some((t) => t[0] === 'apkx');
    if (hasApkxDatasetTab) excludedModuleTabs.add('apkx');
    
    const moduleTabs = usedModules.filter((mod) => !excludedModuleTabs.has(mod)).map((mod) => {
      const info = getModuleDisplayInfo(mod);
      return [`mod:${mod}`, `${info.icon} ${info.name}`];
    });
    UNIQUE_TABS = [...UNIQUE_TABS, ...moduleTabs].filter((t, i, arr) => arr.findIndex(x => x[0] === t[0]) === i);
    const pinnedKinds = ['assets'];
    UNIQUE_TABS = [
      ...pinnedKinds.map((k) => UNIQUE_TABS.find((t) => t[0] === k)).filter(Boolean),
      ...UNIQUE_TABS.filter((t) => !pinnedKinds.includes(t[0])),
    ];
    if (!UNIQUE_TABS.some((t) => t[0] === activeKind)) {
      activeKind = UNIQUE_TABS[0]?.[0] || 'assets';
    }

    let _assetsLoading = false;
    let _currentPage = 1;
    const _pageSize = 250;

    const parseStatusCode = (v) => {
      const m = String(v || '').match(/\b([1-5][0-9]{2})\b/);
      return m ? Number(m[1]) : null;
    };
    const parseTitle = (v) => {
      const s = String(v || '').trim();
      if (!s || s === '—') return '-';
      return s.length > 120 ? `${s.slice(0, 117)}...` : s;
    };
    const rowToGrid = (r) => {
      const host = String(r.target || '—');
      const code = parseStatusCode(`${r.target || ''} ${r.finding || ''}`);
      const status = code && code < 400 ? 'Alive' : (code ? 'Issue' : '-');
      const title = parseTitle(r.finding);
      const tech = String(r.module || '').replace(/-/g, ' ') || '-';
      return { ...r, host, code, status, title, tech };
    };

    allRows = allRows.map(rowToGrid);

    const extractApkPackageInfo = (rows) => {
      const info = {};
      const consumed = new Set();
      const aliases = {
        package_name: 'package_name', package: 'package_name', packageid: 'package_name', package_id: 'package_name',
        applicationid: 'package_name', application_id: 'package_name', appid: 'package_name',
        app_name: 'app_name', appname: 'app_name', name: 'app_name',
        version: 'version', version_name: 'version', versionname: 'version',
        version_code: 'version_code', versioncode: 'version_code',
        min_sdk: 'min_sdk', minsdk: 'min_sdk', minsdkversion: 'min_sdk',
        target_sdk: 'target_sdk', targetsdk: 'target_sdk', targetsdkversion: 'target_sdk',
        compile_sdk: 'compile_sdk', compilesdk: 'compile_sdk', compilesdkversion: 'compile_sdk',
      };
      const takeKV = (k, v) => {
        const key = String(k || '').trim().toLowerCase().replace(/[^a-z0-9_]/g, '');
        const mapped = aliases[key];
        if (!mapped) return;
        const val = String(v ?? '').trim();
        if (!val) return;
        if (!info[mapped]) info[mapped] = val;
      };

      rows.forEach((r, idx) => {
        const target = String(r.target || '');
        const finding = String(r.finding || '').trim();
        if (!/[{]/.test(finding) && !/(package|version|sdk|app_name|application_id)/i.test(`${target} ${finding}`)) return;

        let consumedRow = false;
        try {
          const parsed = JSON.parse(finding);
          if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
            Object.entries(parsed).forEach(([k, v]) => takeKV(k, v));
            consumedRow = Object.keys(parsed).length > 0;
          }
        } catch (_) {}
        const kvs = finding.match(/"?([A-Za-z_][A-Za-z0-9_ ]*)"?\s*:\s*"?([^,"}]+)"?/g) || [];
        kvs.forEach((frag) => {
          const m = frag.match(/"?([A-Za-z_][A-Za-z0-9_ ]*)"?\s*:\s*"?([^,"}]+)"?/);
          if (m) takeKV(m[1], m[2]);
        });
        if (kvs.length) consumedRow = true;
        if (consumedRow) consumed.add(idx);
      });

      return { info, rows: rows.filter((_, idx) => !consumed.has(idx)) };
    };

    let apkPackageInfo = null;
    if (isAPKScan) {
      const extracted = extractApkPackageInfo(allRows);
      allRows = extracted.rows;
      apkPackageInfo = extracted.info;
      if (!apkPackageInfo.package_name) {
        const tgt = String(scanRecord?.target || scanRecord?.Target || '').trim();
        if (tgt) apkPackageInfo.package_name = tgt;
      }
      apiFetch(`/api/scans/${encodeURIComponent(scanId)}/results/apk-meta`)
        .then((meta) => {
          if (!meta) return;
          if (meta.package_name) apkPackageInfo.package_name = meta.package_name;
          if (meta.version)      apkPackageInfo.version      = meta.version;
          if (meta.version_code) apkPackageInfo.version_code = meta.version_code;
          if (meta.min_sdk)      apkPackageInfo.min_sdk      = meta.min_sdk;
          if (meta.target_sdk)   apkPackageInfo.target_sdk   = meta.target_sdk;
          if (meta.task_hijacking_risk) apkPackageInfo.task_hijacking_risk = meta.task_hijacking_risk;
          if (apkMetaBar && isAPKScan) renderAPKMetaBar();
        }).catch(() => {});
    }

    const apkCategoryKey = (r) => {
      const explicit = String(r.category_name || r.apk_category || '').trim();
      if (explicit) return explicit;
      const t = String(r.target || '').trim();
      if (t && t !== '-' && t !== '—') return t;
      const f = String(r.finding || '').trim();
      const idx = f.indexOf(':');
      if (idx > 0) return f.slice(0, idx).trim();
      return '';
    };
    const slugifyApkCategory = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');

    const apkCategoryCounts = {};
    if (isAPKScan) {
      allRows = allRows.map((r) => {
        const cat = apkCategoryKey(r);
        const slug = slugifyApkCategory(cat);
        if (slug) {
          apkCategoryCounts[slug] = apkCategoryCounts[slug] || { label: cat, count: 0 };
          apkCategoryCounts[slug].count += 1;
        }
        return { ...r, apk_category: cat, apk_category_slug: slug };
      });
      const apkCategoryTabs = Object.entries(apkCategoryCounts)
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, 30)
        .map(([slug, meta]) => [`apkcat:${slug}`, `🧩 ${meta.label}`]);
      if (apkCategoryTabs.length) {
        const baseTabs = UNIQUE_TABS.filter(([k]) => k !== 'apkx');
        UNIQUE_TABS = [['apkx', TAB_LABELS.apkx], ...apkCategoryTabs, ...baseTabs]
          .filter((t, i, arr) => arr.findIndex(x => x[0] === t[0]) === i);
      }
    }

    const kindCounts = {};
    for (const r of allRows) kindCounts[r.kind || 'other'] = (kindCounts[r.kind || 'other'] || 0) + 1;
    const datasetCount = (k) => (k === 'all' ? allRows.length : (kindCounts[k] || 0));

    let searchJsOnly = false;
    let presetMode = 'smart';
    let quickChip = 'none';
    let railSearch = '';
    let currentRenderedRows = [];
    let _virtualScrollTop = 0;
    const presetStorageKey = `autoar.recon.filtersets.${stNorm || 'generic'}`;
    const uiStateKey = `autoar.recon.uistate.${stNorm || 'generic'}`;
    const colStateKey = `autoar.recon.colwidths.${stNorm || 'generic'}`;
    let savedFilterSets = {};

    const loadSavedSets = () => { try { savedFilterSets = JSON.parse(localStorage.getItem(presetStorageKey) || '{}') || {}; } catch { savedFilterSets = {}; } };
    const persistSavedSets = () => { try { localStorage.setItem(presetStorageKey, JSON.stringify(savedFilterSets)); } catch (_) { } };
    const persistUIState = () => { try { localStorage.setItem(uiStateKey, JSON.stringify({ activeKind, presetMode, quickChip, searchModule, searchJsOnly, })); } catch (_) { } };
    const loadUIState = () => { try { return JSON.parse(localStorage.getItem(uiStateKey) || '{}') || {}; } catch { return {}; } };
    const persistColumnWidths = () => {
      const cg = root.querySelector('#recon-colgroup');
      if (!cg) return;
      const cols = Array.from(cg.querySelectorAll('col')).map((c) => c.style.width || '');
      try { localStorage.setItem(colStateKey, JSON.stringify(cols)); } catch (_) { }
    };
    const applyColumnWidths = () => {
      const cg = root.querySelector('#recon-colgroup');
      if (!cg) return;
      let widths = null;
      try { widths = JSON.parse(localStorage.getItem(colStateKey) || 'null'); } catch { widths = null; }
      if (!Array.isArray(widths) || widths.length < 5) return;
      const cols = Array.from(cg.querySelectorAll('col'));
      cols.forEach((c, i) => { if (widths[i]) c.style.width = widths[i]; });
    };

    const rowMatch = (r) => {
      const k = r.kind || 'other';
      if (String(activeKind || '').startsWith('mod:')) {
        const moduleKind = String(activeKind).slice(4);
        if (window.normalizeModuleKey(r.module) !== moduleKind) return false;
      } else if (String(activeKind || '').startsWith('apkcat:')) {
        const categorySlug = String(activeKind).slice(7);
        if (String(r.apk_category_slug || '') !== categorySlug) return false;
      } else if (activeKind === 'vuln') {
        if (!VULN_KINDS.has(k)) return false;
        if (searchModule !== 'all' && window.normalizeModuleKey(r.module) !== searchModule) return false;
      } else if (k !== activeKind) return false;
      
      if (activeKind === 'urls' && searchJsOnly && !r.is_js) return false;
      if (searchHost && !String(r.host || r.target || '').toLowerCase().includes(searchHost)) return false;
      if (searchTitle && !String(r.title || r.finding || '').toLowerCase().includes(searchTitle)) return false;
      if (filterSeverity !== 'any') {
        const sev = String(r.severity || 'info').toLowerCase();
        if (sev !== filterSeverity) return false;
      }
      const sev = String(r.severity || 'info').toLowerCase();
      const targetStr = String(r.target || '').toLowerCase();
      const findingStr = String(r.finding || '').toLowerCase();
      if (quickChip === 'highplus' && !(sev === 'high' || sev === 'critical')) return false;
      if (quickChip === 'hasurl' && !(/https?:\/\//i.test(targetStr) || /https?:\/\//i.test(findingStr))) return false;
      if (quickChip === 'exported' && !(findingStr.includes('exported') || String(r.apk_category || '').toLowerCase().includes('exported'))) return false;
      if (quickChip === 'secrets' && !/(secret|token|apikey|api key|password|authorization)/i.test(findingStr)) return false;
      if (quickChip === 'onlyjs' && !(r.is_js || /\.m?jsx?(\?|$)/i.test(targetStr) || findingStr.includes('javascript') || String(r.apk_category || '').toLowerCase().includes('js'))) return false;
      return true;
    };

    root.innerHTML = `
      <div style="border:1px solid var(--border);border-radius:10px;background:var(--bg-surface);overflow:hidden">
        <div style="display:grid;grid-template-columns:240px 1fr;min-height:720px">
          <aside style="border-right:1px solid var(--border);background:rgba(2,6,23,.55);display:flex;flex-direction:column;min-width:0">
            <div style="padding:10px 12px;border-bottom:1px solid var(--border);font-size:11px;color:var(--text-muted);letter-spacing:.6px;text-transform:uppercase">Findings Views</div>
            <div style="padding:8px;border-bottom:1px solid var(--border)">
              <input id="recon-rail-search" type="search" placeholder="Search views..." style="width:100%;padding:7px 9px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-size:11px"/>
            </div>
            <div id="recon-left-rail" style="display:flex;flex-direction:column;gap:6px;padding:8px;overflow-y:auto;overflow-x:hidden;max-height:780px;scrollbar-width:thin"></div>
          </aside>
          <section style="min-width:0;position:relative">
            <div id="recon-apk-meta" style="display:none;padding:10px 12px;border-bottom:1px solid var(--border);background:rgba(34,211,238,.06)"></div>
            <div id="recon-severity-bar" style="display:none;padding:8px 10px;border-bottom:1px solid var(--border);background:rgba(2,6,23,.6);display:flex;align-items:center;gap:8px;flex-wrap:wrap"></div>
            <div id="recon-filter-bar" style="display:grid;grid-template-columns:minmax(200px,1.5fr) 140px 140px minmax(180px,1fr) auto;gap:8px;padding:10px;border-bottom:1px solid var(--border);background:rgba(2,6,23,.5)">
              <input id="recon-filter-host" type="search" placeholder="🔍 Filter by target URL..." style="padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-size:12px"/>
              <select id="recon-filter-severity" style="padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-size:12px">
                <option value="any">Any Severity</option>
                <option value="critical">🔴 Critical</option>
                <option value="high">🟠 High</option>
                <option value="medium">🟡 Medium</option>
                <option value="low">🔵 Low</option>
                <option value="info">🟢 Info</option>
              </select>
              <select id="recon-filter-module" style="display:${activeKind === 'vuln' ? 'block' : 'none'};padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-size:12px">
                <option value="all">All Modules</option>
              </select>
              <input id="recon-filter-title" type="search" placeholder="🔍 Filter by type / finding..." style="padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-size:12px"/>
              <div style="display:flex;align-items:center;justify-content:flex-end;gap:8px;font-size:11px;color:var(--text-muted);white-space:nowrap">
                <span><span id="recon-unified-shown">0</span> rows</span>
              </div>
            </div>
            <div id="recon-quick-tools" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:8px 10px;border-bottom:1px solid var(--border);background:rgba(2,6,23,.38)">
              <div id="recon-quick-chips" style="display:flex;align-items:center;gap:6px;flex-wrap:wrap"></div>
              <div style="margin-left:auto;display:flex;align-items:center;gap:6px">
                <select id="recon-view-mode" style="padding:6px 8px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-size:11px">
                  <option value="smart">Smart columns</option>
                  <option value="raw">Raw columns</option>
                </select>
                <select id="recon-saved-filters" style="min-width:160px;padding:6px 8px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-size:11px">
                  <option value="">Saved filters…</option>
                </select>
                <input id="recon-filter-name" type="text" placeholder="Filter name" style="width:130px;padding:6px 8px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-size:11px"/>
                <button id="recon-save-filter" type="button" style="padding:6px 10px;border:1px solid var(--border);border-radius:6px;background:rgba(34,211,238,.1);color:var(--accent-cyan);font-size:11px;cursor:pointer">Save</button>
                <button id="recon-delete-filter" type="button" style="padding:6px 10px;border:1px solid var(--border);border-radius:6px;background:rgba(248,113,113,.08);color:#fca5a5;font-size:11px;cursor:pointer">Delete</button>
              </div>
            </div>
            <div id="recon-standard-view">
              <div class="result-table-wrap" style="max-height:640px;overflow:auto">
                <table class="dashboard-table" style="margin:0;table-layout:fixed;width:100%">
                  <colgroup id="recon-colgroup"><col style="width:36px"><col style="width:31%"><col style="width:8%"><col style="width:43%"><col style="width:16%"></colgroup>
                  <thead style="position:sticky;top:0;z-index:2;background:rgba(2,6,23,.97);backdrop-filter:blur(4px)">
                    <tr id="recon-unified-headrow">
                      <th style="width:36px;text-align:center;padding-left:10px"><input type="checkbox" id="findings-select-all" title="Select all" style="width:14px;height:14px;accent-color:var(--accent-cyan);cursor:pointer"></th>
                      <th style="position:relative">TARGET<span class="col-resizer" data-col-index="1" style="position:absolute;top:0;right:-3px;width:6px;height:100%;cursor:col-resize;user-select:none"></span></th>
                      <th style="text-align:center;position:relative">SEV<span class="col-resizer" data-col-index="2" style="position:absolute;top:0;right:-3px;width:6px;height:100%;cursor:col-resize;user-select:none"></span></th>
                      <th style="position:relative">VULNERABILITY TYPE<span class="col-resizer" data-col-index="3" style="position:absolute;top:0;right:-3px;width:6px;height:100%;cursor:col-resize;user-select:none"></span></th>
                      <th style="width:16%">MODULE</th>
                    </tr>
                  </thead>
                  <tbody id="recon-unified-tbody"></tbody>
                </table>
              </div>
              <div id="recon-unified-cap" style="display:none;padding:10px 12px;font-size:12px;color:var(--text-muted);border-top:1px solid var(--border)"></div>
              <div id="recon-pagination" style="padding:10px 12px;background:rgba(2,6,23,0.3);border-top:1px solid var(--border);display:flex;justify-content:center;align-items:center;gap:15px;font-size:12px"></div>
            </div>
            <div id="recon-assets-view" style="display:none">
              <div id="recon-assets-content" style="padding:16px;min-height:200px;max-height:680px;overflow:auto">
                <div style="text-align:center;padding:40px;color:var(--text-muted)">Loading assets…</div>
              </div>
            </div>
            <div id="recon-urls-view" style="display:none">
              <div style="padding:10px 12px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px;flex-wrap:wrap;background:rgba(2,6,23,.5)">
                <input id="recon-urls-search" type="search" placeholder="🔍 Search URLs…" style="flex:1;min-width:180px;padding:7px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-size:12px"/>
                <select id="recon-urls-type" style="padding:7px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-size:12px"><option value="all">All URLs</option><option value="js">JS Only</option><option value="interesting">Interesting Only</option></select>
                <span id="recon-urls-count" style="color:var(--text-muted);font-size:12px;white-space:nowrap"></span>
                <button id="recon-urls-copy" type="button" style="padding:6px 12px;background:rgba(167,139,250,.12);border:1px solid rgba(167,139,250,.35);border-radius:6px;color:#a78bfa;font-size:11px;cursor:pointer">📋 Copy</button>
                <button id="recon-urls-export" type="button" style="padding:6px 12px;background:rgba(34,211,238,.1);border:1px solid rgba(34,211,238,.3);border-radius:6px;color:var(--accent-cyan);font-size:11px;cursor:pointer">⬇ Export</button>
              </div>
              <div id="recon-urls-content" style="min-height:200px;max-height:580px;overflow:auto;font-family:var(--font-mono);font-size:12px"><div style="text-align:center;padding:40px;color:var(--text-muted)">Loading URLs…</div></div>
              <div id="recon-urls-pagination" style="padding:10px 12px;background:rgba(2,6,23,0.3);border-top:1px solid var(--border);display:flex;justify-content:center;align-items:center;gap:15px;font-size:12px"></div>
            </div>
            <div id="recon-details-drawer" style="display:none;position:absolute;top:0;right:0;width:420px;height:100%;background:rgba(2,6,23,.98);border-left:1px solid var(--border);z-index:20;box-shadow:-12px 0 40px rgba(0,0,0,.45)">
              <div style="display:flex;align-items:center;justify-content:space-between;padding:12px;border-bottom:1px solid var(--border)">
                <div style="font-size:12px;color:var(--text-secondary);text-transform:uppercase;letter-spacing:.5px">Finding Details</div>
                <button id="recon-drawer-close" type="button" style="background:transparent;border:none;color:var(--text-muted);font-size:18px;cursor:pointer">✕</button>
              </div>
              <div id="recon-drawer-body" style="padding:12px;overflow:auto;height:calc(100% - 52px)"></div>
            </div>
          </section>
        </div>
      </div>`;

    const tabsEl = root.querySelector('#recon-left-rail');
    const railSearchInput = root.querySelector('#recon-rail-search');
    const apkMetaBar = root.querySelector('#recon-apk-meta');
    const severityBar = root.querySelector('#recon-severity-bar');
    const filterBar = root.querySelector('#recon-filter-bar');
    const chipBar = root.querySelector('#recon-quick-chips');
    const viewModeSel = root.querySelector('#recon-view-mode');
    const savedFiltersSel = root.querySelector('#recon-saved-filters');
    const saveFilterBtn = root.querySelector('#recon-save-filter');
    const deleteFilterBtn = root.querySelector('#recon-delete-filter');
    const filterNameInput = root.querySelector('#recon-filter-name');
    const standardView = root.querySelector('#recon-standard-view');
    const assetsView = root.querySelector('#recon-assets-view');
    const assetsContent = root.querySelector('#recon-assets-content');
    const urlsView = root.querySelector('#recon-urls-view');
    const urlsContent = root.querySelector('#recon-urls-content');
    const standardTable = root.querySelector('#recon-standard-view table.dashboard-table');
    const drawer = root.querySelector('#recon-details-drawer');
    const drawerBody = root.querySelector('#recon-drawer-body');
    const drawerClose = root.querySelector('#recon-drawer-close');

    const SEV_DEFS = [
      { key: 'critical', label: 'Critical', color: '#fc8181', bg: 'rgba(252,129,129,.13)', border: 'rgba(252,129,129,.35)' },
      { key: 'high',     label: 'High',     color: '#f6ad55', bg: 'rgba(246,173,85,.13)',  border: 'rgba(246,173,85,.35)' },
      { key: 'medium',   label: 'Medium',   color: '#f6e05e', bg: 'rgba(246,224,94,.13)',  border: 'rgba(246,224,94,.35)' },
      { key: 'low',      label: 'Low',      color: '#63b3ed', bg: 'rgba(99,179,237,.13)',  border: 'rgba(99,179,237,.35)' },
      { key: 'info',     label: 'Info',     color: '#68d391', bg: 'rgba(104,211,145,.13)', border: 'rgba(104,211,145,.35)' },
    ];

    const renderSeverityBar = () => {
      if (!severityBar) return;
      const counts = {};
      for (const r of allRows) {
        const sev = String(r.severity || '').toLowerCase().replace(/[—\-]/g, '').trim() || 'info';
        counts[sev] = (counts[sev] || 0) + 1;
      }
      const hasCounts = SEV_DEFS.some(d => counts[d.key] > 0);
      if (!hasCounts) { severityBar.style.display = 'none'; return; }
      severityBar.style.display = 'flex';
      const pills = SEV_DEFS.filter(d => counts[d.key] > 0).map(d => {
        const isActive = filterSeverity === d.key;
        return `<button type="button" data-sev="${esc(d.key)}" title="Filter by ${d.label}" style="display:inline-flex;align-items:center;gap:5px;padding:4px 10px;border:1px solid ${isActive ? d.color : d.border};border-radius:999px;background:${isActive ? d.bg : 'rgba(255,255,255,.02)'};color:${isActive ? d.color : 'var(--text-secondary)'};font-size:11px;font-weight:${isActive ? '600' : '400'};cursor:pointer;transition:all .15s"><span style="font-size:13px">${d.key === 'critical' ? '🔴' : d.key === 'high' ? '🟠' : d.key === 'medium' ? '🟡' : d.key === 'low' ? '🔵' : '🟢'}</span><span>${d.label}</span><span style="background:${isActive ? d.color : 'rgba(255,255,255,.1)'};color:${isActive ? '#000' : 'var(--text-muted)'};border-radius:999px;padding:0 5px;font-size:10px;font-weight:600">${counts[d.key]}</span></button>`;
      }).join('');
      const total = Object.values(counts).reduce((a, b) => a + b, 0);
      const allActive = filterSeverity === 'any';
      severityBar.innerHTML = `<span style="font-size:11px;color:var(--text-muted);white-space:nowrap;padding-right:4px">Severity:</span><button type="button" data-sev="any" title="Show all severities" style="display:inline-flex;align-items:center;gap:4px;padding:4px 10px;border:1px solid ${allActive ? 'rgba(34,211,238,.5)' : 'var(--border)'};border-radius:999px;background:${allActive ? 'rgba(34,211,238,.1)' : 'rgba(255,255,255,.02)'};color:${allActive ? 'var(--accent-cyan)' : 'var(--text-secondary)'};font-size:11px;cursor:pointer">All <span style="background:rgba(255,255,255,.1);color:var(--text-muted);border-radius:999px;padding:0 5px;font-size:10px;font-weight:600">${total}</span></button>${pills}`;
      severityBar.querySelectorAll('button[data-sev]').forEach(btn => btn.addEventListener('click', () => { filterSeverity = btn.dataset.sev || 'any'; const sel = root.querySelector('#recon-filter-severity'); if (sel) sel.value = filterSeverity; _currentPage = 1; renderSeverityBar(); renderBody(); }));
    };

    const renderAPKMetaBar = () => {
      if (!apkMetaBar || !isAPKScan || !apkPackageInfo) { if (apkMetaBar) { apkMetaBar.style.display = 'none'; apkMetaBar.innerHTML = ''; } return; }
      const riskFromBackend = String(apkPackageInfo.task_hijacking_risk || '').toLowerCase();
      let hijackLabel, hijackColor;
      if (riskFromBackend === 'possible') { hijackLabel = '⚠ Possible (minSdk ≤ 28)'; hijackColor = '#f97316'; }
      else if (riskFromBackend === 'mitigated') { hijackLabel = '⚡ Partially mitigated (minSdk 29–30)'; hijackColor = '#f59e0b'; }
      else if (riskFromBackend === 'unlikely') { hijackLabel = '✅ Unlikely (minSdk ≥ 31)'; hijackColor = '#22c55e'; }
      else { hijackLabel = '? Unknown'; hijackColor = '#94a3b8'; }

      const fields = [['package_name','Package ID'],['app_name','App Name'],['version','Version'],['version_code','Version Code'],['min_sdk','Min SDK'],['target_sdk','Target SDK'],['compile_sdk','Compile SDK']].filter(([k]) => apkPackageInfo[k]);
      if (!fields.length && hijackLabel === '? Unknown') { apkMetaBar.style.display = 'none'; return; }
      apkMetaBar.style.display = 'flex';
      apkMetaBar.innerHTML = [...fields.map(([k, label]) => `<div style="display:flex;align-items:center;gap:6px;padding:6px 10px;border:1px solid rgba(34,211,238,.28);border-radius:8px;background:rgba(2,6,23,.45)"><span style="font-size:11px;color:#67e8f9">${esc(label)}:</span><span style="font-size:11px;color:var(--text-primary);font-family:var(--font-mono,monospace)">${esc(apkPackageInfo[k])}</span></div>`), `<div style="display:flex;align-items:center;gap:6px;padding:6px 10px;border:1px solid ${hijackColor}55;border-radius:8px;background:rgba(2,6,23,.45)"><span style="font-size:11px;color:${hijackColor}">Task Hijack Risk:</span><span style="font-size:11px;color:var(--text-primary);font-family:var(--font-mono,monospace)">${esc(hijackLabel)}</span></div>`].join('');
    };

    const modSelect = root.querySelector('#recon-filter-module');
    if (modSelect) {
      const usedModules = [...new Set(allRows.map(r => window.normalizeModuleKey(r.module)))].filter(m => m && m !== 'unknown').sort();
      modSelect.innerHTML = '<option value="all">All Modules</option>' + usedModules.map(m => `<option value="${esc(m)}">${esc(getModuleDisplayInfo(m).name)}</option>`).join('');
      modSelect.addEventListener('change', () => { searchModule = modSelect.value; renderBody(); });
    }

    const renderSavedFilters = () => { if (!savedFiltersSel) return; const names = Object.keys(savedFilterSets).sort(); savedFiltersSel.innerHTML = '<option value="">Saved filters…</option>' + names.map(n => `<option value="${esc(n)}">${esc(n)}</option>`).join(''); };
    const readCurrentFilterSet = () => ({ activeKind, searchHost, searchTitle, filterSeverity, searchModule, searchJsOnly, quickChip, presetMode, });
    const applyFilterSet = (fs) => { if (!fs) return; activeKind = fs.activeKind || activeKind; searchHost = String(fs.searchHost || ''); searchTitle = String(fs.searchTitle || ''); filterSeverity = String(fs.filterSeverity || 'any'); searchModule = String(fs.searchModule || 'all'); searchJsOnly = !!fs.searchJsOnly; quickChip = String(fs.quickChip || 'none'); presetMode = String(fs.presetMode || 'smart'); const h = root.querySelector('#recon-filter-host'), t = root.querySelector('#recon-filter-title'), s = root.querySelector('#recon-filter-severity'); if (h) h.value = searchHost; if (t) t.value = searchTitle; if (s) s.value = filterSeverity; if (modSelect) modSelect.value = searchModule; if (viewModeSel) viewModeSel.value = presetMode; };

    const chipDefs = [{ id: 'highplus', label: 'High+' },{ id: 'hasurl', label: 'Has URL' },{ id: 'exported', label: 'Exported Components' },{ id: 'secrets', label: 'Secrets' },{ id: 'onlyjs', label: 'Only JS' }];
    const renderChips = () => { if (!chipBar) return; chipBar.innerHTML = chipDefs.map(c => { const active = quickChip === c.id; return `<button type="button" data-chip="${escAttr(c.id)}" style="padding:5px 10px;border:1px solid ${active ? 'rgba(34,211,238,.5)' : 'var(--border)'};border-radius:999px;background:${active ? 'rgba(34,211,238,.13)' : 'rgba(255,255,255,.02)'};color:${active ? 'var(--accent-cyan)' : 'var(--text-secondary)'};font-size:11px;cursor:pointer">${esc(c.label)}</button>`; }).join(''); };

    const renderTabs = () => {
      if (!tabsEl) return;
      tabsEl.innerHTML = UNIQUE_TABS.filter(([, label]) => !railSearch || String(label || '').toLowerCase().includes(railSearch)).map(([kind, label]) => {
        const isActive = activeKind === kind, isModuleTab = String(kind).startsWith('mod:'), isApkCategoryTab = String(kind).startsWith('apkcat:'), moduleKind = isModuleTab ? String(kind).slice(4) : '';
        const count = isModuleTab ? allRows.filter(r => window.normalizeModuleKey(r.module) === moduleKind).length : isApkCategoryTab ? (apkCategoryCounts[String(kind).slice(7)]?.count || 0) : ((kind === 'assets' || kind === 'vuln') ? datasetCount(kind) : (kindCounts[kind] || 0));
        const cntDisplay = count > 0 ? `<span class="tab-count">${count}</span>` : '';
        const labelText = `${label}`.trim();
        return `<button class="tab-pill${isActive ? ' active' : ''}" data-recon-kind="${escAttr(kind)}" title="${escAttr(labelText)}" style="display:flex;align-items:center;justify-content:space-between;gap:8px;width:100%;border:1px solid ${isActive ? 'rgba(34,211,238,.45)' : 'var(--border)'};border-radius:8px;padding:8px 10px;background:${isActive ? 'rgba(34,211,238,.1)' : 'rgba(255,255,255,.02)'};color:${isActive ? 'var(--accent-cyan)' : 'var(--text-secondary)'};font-size:12px;text-align:left;cursor:pointer"><span style="display:inline-block;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:middle">${esc(labelText)}</span> ${cntDisplay}</button>`;
      }).join('');
    };

    const renderBody = () => {
      renderSeverityBar();
      const filtered = allRows.filter(r => rowMatch(r) && !HIDDEN_KINDS.has(r.kind));
      const totalPages = Math.ceil(filtered.length / _pageSize) || 1;
      if (_currentPage > totalPages) _currentPage = totalPages;
      const slice = filtered.slice((_currentPage - 1) * _pageSize, _currentPage * _pageSize);
      const tbody = root.querySelector('#recon-unified-tbody'), headRow = root.querySelector('#recon-unified-headrow'), shown = root.querySelector('#recon-unified-shown');
      wrap = root.querySelector('.result-table-wrap');
      if (shown) shown.textContent = String(filtered.length);
      if (headRow) {
        const cols = presetMode === 'raw' ? ['TARGET', 'SEV', 'VULNERABILITY TYPE', 'MODULE'] : window.getUnifiedTableColumns(activeKind);
        headRow.innerHTML = `<th style="width:36px;text-align:center;padding-left:10px"><input type="checkbox" id="findings-select-all" title="Select all" style="width:14px;height:14px;accent-color:var(--accent-cyan);cursor:pointer"></th><th style="position:relative">${esc(cols[0])}<span class="col-resizer" data-col-index="1" style="position:absolute;top:0;right:-3px;width:6px;height:100%;cursor:col-resize;user-select:none"></span></th><th style="text-align:center;position:relative">${esc(cols[1])}<span class="col-resizer" data-col-index="2" style="position:absolute;top:0;right:-3px;width:6px;height:100%;cursor:col-resize;user-select:none"></span></th><th style="position:relative">${esc(cols[2])}<span class="col-resizer" data-col-index="3" style="position:absolute;top:0;right:-3px;width:6px;height:100%;cursor:col-resize;user-select:none"></span></th><th style="width:16%">${esc(cols[3])}</th>`;
      }
      if (tbody) {
        currentRenderedRows = slice;
        const virtualEnabled = slice.length > 150, rowHeight = 34, overscan = 12, viewportH = Math.max(320, Math.round((wrap?.clientHeight || 640)));
        const visibleRows = Math.ceil(viewportH / rowHeight) + overscan * 2;
        const vStart = virtualEnabled ? Math.max(0, Math.floor(_virtualScrollTop / rowHeight) - overscan) : 0;
        const vEnd = virtualEnabled ? Math.min(slice.length, vStart + visibleRows) : slice.length;
        const renderSlice = slice.slice(vStart, vEnd), topPad = virtualEnabled ? vStart * rowHeight : 0, bottomPad = virtualEnabled ? Math.max(0, (slice.length - vEnd) * rowHeight) : 0;
        const rowsHtml = renderSlice.map((r, idx) => {
          const rowIdx = vStart + idx, sev = String(r.severity || '').toLowerCase().replace(/[—\-]/g, '').trim();
          const sevMeta = { critical: { color: '#fc8181', bg: '#fc818120', label: 'CRIT' }, high: { color: '#f6ad55', bg: '#f6ad5520', label: 'HIGH' }, medium: { color: '#f6e05e', bg: '#f6e05e20', label: 'MED' }, low: { color: '#63b3ed', bg: '#63b3ed20', label: 'LOW' }, info: { color: '#68d391', bg: '#68d39120', label: 'INFO' }, warning: { color: '#f6ad55', bg: '#f6ad5520', label: 'WARN' }, }[sev] || { color: '#718096', bg: '#71809615', label: '—' };
          const modInfo = getModuleDisplayInfo(r.module);
          if (presetMode === 'raw') return window.renderDefaultRow(r, rowIdx, modInfo, sevMeta);
          return window.renderRowForUnifiedTab(r, rowIdx, activeKind, modInfo, sevMeta);
        }).join('');
        tbody.innerHTML = slice.length ? `${topPad ? `<tr class="virtual-pad-top"><td colspan="5" style="padding:0;border:none;height:${topPad}px"></td></tr>` : ''}${rowsHtml}${bottomPad ? `<tr class="virtual-pad-bottom"><td colspan="5" style="padding:0;border:none;height:${bottomPad}px"></td></tr>` : ''}` : '<tr><td colspan="5" style="text-align:center;padding:28px;color:var(--text-muted);font-size:13px">No findings match the current filter.</td></tr>';
      }
      const pag = root.querySelector('#recon-pagination');
      if (pag) { if (totalPages <= 1) pag.style.display = 'none'; else { pag.style.display = 'flex'; pag.innerHTML = `<button id="recon-prev" class="btn btn-sm" ${_currentPage === 1 ? 'disabled' : ''}>← Prev</button> <span style="color:var(--text-secondary);font-weight:600">Page ${_currentPage} of ${totalPages}</span> <button id="recon-next" class="btn btn-sm" ${_currentPage === totalPages ? 'disabled' : ''}>Next →</button> <span style="color:var(--text-muted);margin-left:auto">${filtered.length} total rows</span>`; pag.querySelector('#recon-prev').onclick = () => { if (_currentPage > 1) { _currentPage--; renderBody(); wrap.scrollTop = 0; } }; pag.querySelector('#recon-next').onclick = () => { if (_currentPage < totalPages) { _currentPage++; renderBody(); wrap.scrollTop = 0; } }; } }
    };

    const switchReconView = (kind) => {
      activeKind = kind; persistUIState(); renderTabs();
      const m = root.querySelector('#recon-filter-module'); if (m) { const isM = String(activeKind).startsWith('mod:'); m.style.display = (activeKind === 'vuln' && !isM) ? 'block' : 'none'; if (activeKind !== 'vuln' || isM) { m.value = 'all'; searchModule = 'all'; } }
      if (activeKind === 'assets') { standardView.style.display = 'none'; assetsView.style.display = 'block'; urlsView.style.display = 'none'; showAssetsView(); }
      else if (activeKind === 'urls') { assetsView.style.display = 'none'; showURLsView(); }
      else { standardView.style.display = 'block'; assetsView.style.display = 'none'; urlsView.style.display = 'none'; _currentPage = 1; renderBody(); }
    };

    const showAssetsView = async () => { if (_assetsCache) { renderAssetsGrid(assetsContent, _assetsCache); return; } if (_assetsLoading) return; _assetsLoading = true; assetsContent.innerHTML = '<div style="text-align:center;padding:40px;color:var(--text-muted)">Building asset inventory…</div>'; try { const data = await apiFetch(`/api/scans/${encodeURIComponent(scanId)}/results/assets`); _assetsCache = data.assets || []; renderAssetsGrid(assetsContent, _assetsCache); } catch (e) { assetsContent.innerHTML = `<div style="padding:24px;color:var(--accent-red)">Failed: ${esc(e.message)}</div>`; } finally { _assetsLoading = false; } };
    const showURLsView = () => { standardView.style.display = 'none'; assetsView.style.display = 'none'; urlsView.style.display = 'block'; loadURLsView(); };
    const loadURLsView = async () => { try { const qs = new URLSearchParams({ page: 1, limit: 500, type: 'all', q: '' }).toString(); const data = await apiFetch(`/api/scans/${encodeURIComponent(scanId)}/results/urls?${qs}`); renderURLsTable(data.urls || [], data.total || 0, 1); } catch (e) {} };
    const renderURLsTable = (urls, total, page) => { urlsContent.innerHTML = `<table style="width:100%"><tbody>${urls.map((e, i) => `<tr><td style="padding:5px 12px;font-size:11px"><a href="${esc(e.url)}" target="_blank" style="color:var(--accent-cyan);text-decoration:none">${esc(e.url)}</a></td></tr>`).join('')}</tbody></table>`; };

    // Initial setup
    const uiS = loadUIState(); if (uiS.activeKind && UNIQUE_TABS.some(t => t[0] === uiS.activeKind)) activeKind = uiS.activeKind; if (uiS.presetMode) presetMode = uiS.presetMode; if (uiS.quickChip) quickChip = uiS.quickChip;
    loadSavedSets(); renderSavedFilters(); renderChips(); switchReconView(activeKind); applyColumnWidths();

    // Event listeners
    root.addEventListener('click', e => { const b = e.target.closest('[data-recon-kind]'); if (b) switchReconView(b.getAttribute('data-recon-kind')); });
    if (chipBar) chipBar.addEventListener('click', e => { const b = e.target.closest('[data-chip]'); if (b) { const id = b.dataset.chip; quickChip = quickChip === id ? 'none' : id; renderChips(); _currentPage = 1; renderBody(); } });
    if (viewModeSel) viewModeSel.addEventListener('change', () => { presetMode = viewModeSel.value; persistUIState(); _currentPage = 1; renderBody(); });
    if (saveFilterBtn) saveFilterBtn.addEventListener('click', () => { const n = filterNameInput?.value.trim(); if (!n) return; savedFilterSets[n] = readCurrentFilterSet(); persistSavedSets(); renderSavedFilters(); });
    if (deleteFilterBtn) deleteFilterBtn.addEventListener('click', () => { const n = savedFiltersSel?.value; if (n) { delete savedFilterSets[n]; persistSavedSets(); renderSavedFilters(); } });
    if (savedFiltersSel) savedFiltersSel.addEventListener('change', () => { const n = savedFiltersSel.value; if (savedFilterSets[n]) { applyFilterSet(savedFilterSets[n]); renderChips(); switchReconView(activeKind); } });
    
    const hostI = root.querySelector('#recon-filter-host'), titleI = root.querySelector('#recon-filter-title'), sevS = root.querySelector('#recon-filter-severity');
    const applyF = () => { searchHost = hostI?.value.toLowerCase().trim(); searchTitle = titleI?.value.toLowerCase().trim(); filterSeverity = sevS?.value; _currentPage = 1; renderBody(); };
    if (hostI) hostI.addEventListener('input', applyF); if (titleI) titleI.addEventListener('input', applyF); if (sevS) sevS.addEventListener('change', applyF);
    
    if (wrap) wrap.addEventListener('scroll', () => { _virtualScrollTop = wrap.scrollTop; if (currentRenderedRows.length > 150) renderBody(); });
    
    root.addEventListener('click', e => { const r = e.target.closest('.findings-row'); if (r && !e.target.closest('input,a,button')) { const idx = Number(r.dataset.rowIndex); if (currentRenderedRows[idx]) openDrawerForRow(currentRenderedRows[idx]); } });
    if (drawerClose) drawerClose.addEventListener('click', () => drawer.style.display = 'none');
    
    function openDrawerForRow(r) { drawerBody.innerHTML = `<pre style="padding:12px;font-size:11px;color:var(--text-primary)">${esc(JSON.stringify(r, null, 2))}</pre>`; drawer.style.display = 'block'; }
  }

  function renderAssetsGrid(container, assets) {
    const renderRows = (list) => list.map(a => `<tr class="dashboard-table-row"><td>${a.is_live ? 'Alive' : 'Dead'}</td><td><a href="${esc(a.url)}" target="_blank" style="color:var(--accent-cyan)">${esc(a.host)}</a></td><td style="text-align:center">${a.status_code || '—'}</td><td>${(a.technologies || []).join(', ')}</td></tr>`).join('');
    container.innerHTML = `<div style="margin-bottom:12px;display:flex;gap:12px"><input id="asset-search" type="search" placeholder="Search hosts…" style="flex:1;padding:8px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-size:12px"/></div><div style="border:1px solid var(--border);border-radius:8px;overflow:hidden"><table class="dashboard-table" style="margin:0;width:100%"><thead><tr><th>STATUS</th><th>HOST</th><th style="text-align:center">CODE</th><th>TECHNOLOGIES</th></tr></thead><tbody id="asset-tbody">${renderRows(assets)}</tbody></table></div>`;
    container.querySelector('#asset-search').addEventListener('input', e => { const q = e.target.value.toLowerCase().trim(); const filtered = assets.filter(a => a.host.toLowerCase().includes(q) || (a.technologies || []).some(t => t.toLowerCase().includes(q))); container.querySelector('#asset-tbody').innerHTML = renderRows(filtered); });
  }

  function wireScanDetailFilters(scanId, allFiles) {
    const s = document.getElementById('scan-file-search'), m = document.getElementById('scan-module-filter'), c = document.getElementById('scan-category-filter'), t = document.getElementById('scan-type-filter');
    const apply = () => {
      const q = s?.value.toLowerCase() || '', f = { module: m?.value, category: c?.value, type: t?.value };
      const filtered = window.filterScanFiles(allFiles, q, f);
      const grid = document.getElementById('filtered-file-grid');
      if (grid) grid.innerHTML = filtered.map(f => `<div class="file-grid-item" onclick="window.loadScanFilePreview('${scanId}', '${esc(f.file_name)}')"><div class="file-grid-name">${esc(f.file_name)}</div><div class="file-grid-meta">${fmtSize(f.size_bytes)} · ${f.is_json ? 'JSON' : 'TXT'}</div></div>`).join('');
    };
    [s,m,c,t].forEach(el => el?.addEventListener('change', apply));
    if (s) s.addEventListener('input', apply);
  }

  window.ScanDetailPage = {
    renderScanDetailView,
    clearScanDetailRefreshTimer,
    scheduleScanDetailRefresh,
    doScanDetailRefresh,
    loadReconUnifiedTable,
    wireScanDetailFilters,
    clearApkxCacheForScan,
  };
})();

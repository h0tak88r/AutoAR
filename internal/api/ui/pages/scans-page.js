(() => {
  function elapsedStr(start) {
    try {
      const diff = Date.now() - new Date(start).getTime();
      if (isNaN(diff)) return '';
      const h = Math.floor(diff / 3600000);
      const m = Math.floor((diff % 3600000) / 60000);
      const s = Math.floor((diff % 60000) / 1000);
      if (h > 0) return `${h}h ${m}m`;
      if (m > 0) return `${m}m ${s}s`;
      return `${s}s`;
    } catch (_) {
      return '';
    }
  }

  function elapsedBetween(start, end) {
    try {
      const diff = new Date(end).getTime() - new Date(start).getTime();
      if (isNaN(diff) || diff < 0) return '—';
      const h = Math.floor(diff / 3600000);
      const m = Math.floor((diff % 3600000) / 60000);
      const s = Math.floor((diff % 60000) / 1000);
      if (h > 0) return `${h}h ${m}m`;
      if (m > 0) return `${m}m ${s}s`;
      return `${s}s`;
    } catch (_) {
      return '—';
    }
  }

  function scanTypeLabel(rawType) {
    const t = String(rawType || '').toLowerCase().trim();
    const map = {
      recon: '🔭 Recon Discovery',
      domain_run: '🌍 Full Domain',
      subdomain_run: '🔬 Subdomain',
      lite: '⚡ Lite Workflow',
      fastlook: '👁 Fast Look',
      subdomains: '🔍 Subdomains',
      livehosts: '🌐 Live Hosts',
      cnames: '🔗 CNAMEs',
      urls: '🔗 URLs',
      js: '📜 JS Scan',
      jsscan: '📜 JS Scan',
      reflection: '⚡  Reflection',
      gf: '🎯 GF Patterns',
      nuclei: '☢️ Nuclei',
      'nuclei-full': '☢️ Nuclei Full',
      'nuclei-cves': '☢️ Nuclei CVEs',
      'nuclei-panels': '☢️ Nuclei Panels',
      'nuclei-vulnerabilities': '☢️ Nuclei Vulns',
      'nuclei-default-logins': '☢️ Nuclei Logins',
      ports: '🔌 Ports',
      tech: '🔬 Tech Detect',
      dns: '🔀 DNS Takeover',
      'dns-takeover': '🔀 DNS Takeover',
      'dns-dangling-ip': '🔀 Dangling IP',
      dns_cf1016: '☁️ CF1016 Dangling',
      'dns-cf1016': '☁️ CF1016 Dangling',
      backup: '💾 Backup Files',
      misconfig: '⚙️ Misconfig',
      s3: '🪣 S3 Scan',
      github: '🐙 GitHub',
      github_org: '🐙 GitHub Org',
      github_scan: '🐙 GitHub',
      ffuf: '🎲 FFuf Fuzz',
      zerodays: '🚨 Zero-Days',
      apkx: '📱 APK Scan',
      jwt: '🔑 JWT Scan',
      aem: '🏗 AEM Scan',
      aem_scan: '🏗 AEM Scan',
      cleanup: '🧹 Cleanup',
      depconfusion: '📦 Dep Confusion',
      wp_confusion: '📦 WP Confusion',
    };
    if (map[t]) return map[t];
    return t.replace(/_/g, ' ').replace(/-/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()) || rawType;
  }

  function scanItemHtml(s) {
    const target = s.target || s.Target || '';
    const scanType = s.scan_type || s.ScanType || '';
    const statusRaw = (s.status || s.Status || 'running').toLowerCase();
    const currentPhase = s.current_phase || s.CurrentPhase || 0;
    const totalPhases = s.total_phases || s.TotalPhases || 0;
    const startedAt = s.started_at || s.StartedAt || '';
    const phaseName = s.phase_name || s.PhaseName || '';
    const phaseStartTime = s.phase_start_time || s.PhaseStartTime || '';
    const completedPhases = s.completed_phases || s.CompletedPhases || [];
    const failedPhases = s.failed_phases || s.FailedPhases || [];
    const filesUploaded = s.files_uploaded || s.FilesUploaded || 0;
    const errorCount = s.error_count || s.ErrorCount || 0;
    const lastUpdate = s.last_update || s.LastUpdate || '';
    const scanID = s.scan_id || s.ScanID || '';

    const pct = totalPhases > 0 ? Math.round((currentPhase / totalPhases) * 100) : 0;
    const elapsed = elapsedStr(startedAt);
    const isActive = ['running', 'starting', 'paused', 'cancelling'].includes(statusRaw);
    const showProgress = ['running', 'starting'].includes(statusRaw);
    const noPhaseYet = showProgress && currentPhase === 0 && !phaseName;

    let badge = '';
    if (statusRaw === 'paused') badge = '<span class="badge badge-starting">⏸ paused</span>';
    else if (statusRaw === 'cancelling') badge = '<span class="badge badge-starting">⋯ stopping</span>';
    else if (isActive) badge = '<span class="badge badge-running" style="animation:pulse 1.4s ease-in-out infinite">● live</span>';

    const actions = isActive ? `
    <div class="scan-actions" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center" onclick="event.stopPropagation()">
      ${statusRaw !== 'paused' && statusRaw !== 'cancelling'
    ? `<button type="button" class="btn btn-ghost" style="font-size:11px;padding:4px 10px" onclick="pauseScan('${window.esc(scanID)}')">⏸ Pause</button>` : ''}
      ${statusRaw === 'paused'
    ? `<button type="button" class="btn btn-ghost" style="font-size:11px;padding:4px 10px" onclick="resumeScan('${window.esc(scanID)}')">▶ Resume</button>` : ''}
      <button type="button" class="btn btn-ghost scan-btn-stop" style="font-size:11px;padding:4px 10px" onclick="cancelScan('${window.esc(scanID)}')">■ Stop</button>
      <button type="button" class="btn btn-ghost" style="font-size:11px;padding:4px 10px" onclick="goToScanResultsPage('${window.esc(scanID)}');event.stopPropagation()">→ View</button>
    </div>` : '';

    const phaseElapsed = phaseStartTime ? elapsedStr(phaseStartTime) : '';
    const phaseSteps = completedPhases.length || phaseName
      ? [...completedPhases.map((p) => ({ name: p, state: failedPhases.includes(p) ? 'failed' : 'done' })), ...(phaseName ? [{ name: phaseName, state: 'active' }] : [])]
      : [];
    const phaseTimeline = phaseSteps.length ? `
    <div style="display:flex;flex-direction:column;gap:4px;margin-top:10px;margin-bottom:6px;padding:10px 12px;background:rgba(0,0,0,.2);border-radius:8px;border:1px solid rgba(255,255,255,.05)">
      ${phaseSteps.map((step, i) => {
    const isLast = i === phaseSteps.length - 1;
    const icon = step.state === 'done' ? '<span style="color:#10b981;font-size:11px">✓</span>'
      : step.state === 'failed' ? '<span style="color:#ef4444;font-size:11px">✗</span>'
        : '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--accent-cyan);box-shadow:0 0 6px var(--accent-cyan);animation:pulse 1s ease-in-out infinite;vertical-align:middle"></span>';
    const color = step.state === 'done' ? 'var(--text-muted)' : step.state === 'failed' ? '#ef4444' : 'var(--text-primary)';
    const weight = isLast ? '600' : '400';
    const timer = (isLast && phaseElapsed) ? `<span style="font-size:10px;color:var(--text-muted);margin-left:6px">${phaseElapsed}</span>` : '';
    return `<div style="display:flex;align-items:center;gap:8px;font-size:11px;color:${color};font-weight:${weight}">
          <div style="width:16px;text-align:center;flex-shrink:0">${icon}</div>
          <span style="flex:1">${window.esc(step.name)}</span>${timer}
        </div>`;
  }).join('')}
    </div>` : '';

    let progressBlock = '';
    if (showProgress) {
      if (noPhaseYet) {
        progressBlock = `<div class="progress-bar indeterminate" style="margin-top:10px"><div class="progress-fill" style="width:40%"></div></div><div style="font-size:11px;color:var(--text-muted);margin-top:5px">Starting up…</div>`;
      } else {
        const barColor = errorCount > 0 ? '#f59e0b' : 'var(--accent-cyan)';
        progressBlock = `
        <div style="margin-top:10px;background:rgba(255,255,255,.06);border-radius:6px;height:6px;overflow:hidden">
          <div style="height:100%;width:${pct}%;background:linear-gradient(90deg,${barColor},${barColor}cc);border-radius:6px;transition:width .4s ease"></div>
        </div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-top:5px">
          <span style="font-size:11px;color:var(--text-muted)">Phase ${currentPhase}${totalPhases > 0 ? '/' + totalPhases : ''} · ${pct}%</span>
          <div style="display:flex;gap:10px;align-items:center">
            ${filesUploaded > 0 ? `<span style="font-size:10px;color:var(--text-muted)">📁 ${filesUploaded} files</span>` : ''}
            ${errorCount > 0 ? `<span style="font-size:10px;color:#f59e0b">⚠ ${errorCount} error${errorCount !== 1 ? 's' : ''}</span>` : ''}
            ${lastUpdate ? `<span style="font-size:10px;color:var(--text-muted)" title="${window.esc(lastUpdate)}">updated ${elapsedStr(lastUpdate)} ago</span>` : ''}
          </div>
        </div>`;
      }
    }

    return `<div class="scan-item clickable-row" onclick='goToScanResultsPage(${JSON.stringify(scanID)})' style="padding:14px 16px;border-radius:10px;border:1px solid ${statusRaw === 'paused' ? 'rgba(251,191,36,.25)' : 'rgba(6,182,212,.2)'};background:${statusRaw === 'paused' ? 'rgba(251,191,36,.04)' : 'rgba(6,182,212,.04)'};margin-bottom:12px">
    <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;min-width:0">
        <div style="min-width:0">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
            <span class="scan-target" style="font-size:14px;font-weight:700;color:var(--text-primary)">${window.esc(target)}</span>
            <span style="font-size:11px;background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.1);border-radius:4px;padding:1px 7px;color:var(--text-secondary)" title="${window.esc(scanType)}">${window.esc(scanTypeLabel(scanType))}</span>
            ${badge}
          </div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:2px">Started ${elapsed} ago</div>
        </div>
      </div>
      ${actions}
    </div>
    ${phaseTimeline}
    ${progressBlock}
  </div>`;
  }

  function scanRowHtml(s) {
    const target = s.target || s.Target || '';
    const scanType = s.scan_type || s.ScanType || '';
    const status = s.status || s.Status || '';
    const statusLc = status.toLowerCase();
    const currentPhase = s.current_phase || s.CurrentPhase || 0;
    const totalPhases = s.total_phases || s.TotalPhases || 0;
    const phaseName = s.phase_name || s.PhaseName || '';
    const startedAt = s.started_at || s.StartedAt || '';
    const completedAt = s.completed_at || s.CompletedAt || '';
    const pct = totalPhases > 0 ? Math.round((currentPhase / totalPhases) * 100) : 0;
    const resultURL = s.result_url || s.ResultURL || '';
    const done = ['completed', 'done'].includes(statusLc);
    const compPhases = s.completed_phases || s.CompletedPhases || [];
    const failPhases = s.failed_phases || s.FailedPhases || [];
    const cleanName = (n) => n.replace(/^\[Stage \d+\]\s*/i, '').replace(/^\[.*?\]\s*/, '');
    let phaseCol = '';
    if (done) {
      const skipped = Math.max(0, totalPhases - (compPhases.length + failPhases.length));
      const compList = compPhases.length ? compPhases.map((p) => `✓ ${cleanName(p)}`).join('\n') : 'None';
      const failList = failPhases.length ? failPhases.map((p) => `✗ ${cleanName(p)}`).join('\n') : 'None';
      const skipCount = skipped > 0 ? `${skipped} stage(s) did not run (timeout/skipped/unlaunched)` : 'All stages accounted for';
      const tooltipText = `Completed (${compPhases.length}):\n${compList}\n\nFailed (${failPhases.length}):\n${failList}\n\nSkipped: ${skipCount}`;
      if (pct < 100 && skipped > 0) {
        const failPart = failPhases.length ? ` · ${failPhases.length} failed` : '';
        phaseCol = `<span style="font-size:11px;color:var(--text-muted);border-bottom:1px dashed var(--text-muted);cursor:help" title="${window.esc(tooltipText)}">Ended at ${pct}% · ${compPhases.length} done${failPart} · ${skipped} skipped</span>`;
      } else {
        const failPart = failPhases.length ? ` · <span style="color:#ef4444">${failPhases.length} failed</span>` : '';
        phaseCol = `<span style="font-size:11px;color:var(--accent-emerald);font-weight:600;border-bottom:1px dashed var(--accent-emerald);cursor:help" title="${window.esc(tooltipText)}">Done · ${compPhases.length} stages${failPart}</span>`;
      }
    } else {
      phaseCol = `<span style="font-size:11px;color:var(--text-muted)">${pct}%${phaseName ? ` — ${window.esc(phaseName)}` : ''}</span>`;
    }

    const badge = window.statusBadge(status);
    const elapsed = completedAt ? elapsedBetween(startedAt, completedAt) : elapsedStr(startedAt);
    const scanID = s.scan_id || s.ScanID || '';
    const resultsCell = resultURL
      ? `<a href="${window.esc(resultURL)}" target="_blank" onclick="event.stopPropagation()" class="scan-result-link">Download</a>`
      : `<button type="button" class="scan-control-btn-r2" onclick='event.stopPropagation();browseR2ForScan(${JSON.stringify(target)}, ${JSON.stringify(scanType)})'>Browse R2</button>`;
    const running = ['running', 'starting', 'paused'].includes(statusLc);
    const rescanBtn = !running
      ? `<button type="button" class="scan-control-btn-r2" style="margin-left:6px;border-color:rgba(52,211,153,.35);color:var(--accent-emerald)" onclick='event.stopPropagation();rescanScan(${JSON.stringify(scanID)})' title="Re-run with same command">🔁 Rescan</button>`
      : '';
    const deleteBtn = `<button type="button" class="scan-control-btn-r2" style="margin-left:6px;border-color:rgba(248,113,113,.35);color:var(--accent-red)" onclick='event.stopPropagation();deleteScan(${JSON.stringify(scanID)}, ${JSON.stringify(target)})'>Delete</button>`;
    const rowSelect = `<input type="checkbox" class="scan-row-select" data-scan-id="${window.esc(scanID)}" onclick="event.stopPropagation()" aria-label="Select scan" />`;
    return `<tr class="clickable-row" onclick='goToScanResultsPage(${JSON.stringify(scanID)})'>
    <td onclick="event.stopPropagation()">${rowSelect}</td>
    <td><span style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan)">${window.esc(target)}</span></td>
    <td><span class="scan-type" title="${window.esc(scanType)}">${window.esc(scanTypeLabel(scanType))}</span></td>
    <td>${badge}</td>
    <td>${phaseCol}</td>
    <td style="font-size:11px;color:var(--text-muted)">${window.fmtDate(startedAt)}</td>
    <td style="font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--text-muted)">${elapsed}</td>
    <td onclick="event.stopPropagation()">${resultsCell}${rescanBtn}${deleteBtn}</td>
  </tr>`;
  }

  function renderScans() {
    const container = document.getElementById('scans-container');
    if (!container) return;
    const scanErr = window.state.error.scans;
    const { active_scans = [], recent_scans = [] } = window.state.scans;
    const sUI = window.state.scanListUI;
    const filterFn = (s) => {
      const target = (s.target || s.Target || '').toLowerCase();
      const type = (s.scan_type || s.ScanType || '').toLowerCase();
      const status = (s.status || s.Status || '').toLowerCase();
      const matchesSearch = !sUI.search || target.includes(sUI.search.toLowerCase());
      const matchesType = sUI.typeFilter === 'all' || type === sUI.typeFilter.toLowerCase();
      let matchesStatus = sUI.statusFilter === 'all' || status === sUI.statusFilter.toLowerCase();
      if (sUI.statusFilter === 'stopped' && (status === 'cancelled' || status === 'stopped')) matchesStatus = true;
      return matchesSearch && matchesType && matchesStatus;
    };
    const filteredActive = active_scans.filter(filterFn);
    const filteredRecent = recent_scans.filter(filterFn);
    let html = '';
    if (scanErr) {
      html += `<div class="card" style="margin-bottom:16px;border:1px solid var(--accent-red);background:rgba(239,68,68,0.08)"><div class="card-body" style="padding:14px 16px;font-size:13px;color:var(--accent-red)">Could not load scans: ${window.esc(scanErr)}</div></div>`;
    }
    html += `<div class="scan-launcher" style="margin-bottom:20px">
      <div class="scan-launcher-title">🚀 Quick Scan Launcher</div>
      <div class="scan-form">
        <select id="launch-type">
          <optgroup label="Workflows">
            <option value="recon" selected>recon (Asset Discovery)</option>
            <option value="domain_scan">domain_scan (Full Workflow)</option>
            <option value="subdomain_scan">subdomain_scan (Single Subdomain)</option>
          </optgroup>
          <optgroup label="Modules">
            <option value="urls">urls</option>
            <option value="tech">tech</option>
            <option value="nuclei">nuclei</option>
            <option value="ports">ports</option>
          </optgroup>
          <optgroup label="DNS">
            <option value="dns">dns (takeover)</option>
            <option value="dns_dangling">dns (dangling-ip)</option>
            <option value="dns_cf1016">dns-cf1016</option>
          </optgroup>
          <optgroup label="Cloud &amp; source">
            <option value="s3">s3 (bucket)</option>
            <option value="github">github</option>
            <option value="github_org">github_org</option>
          </optgroup>
          <optgroup label="Advanced">
            <option value="js">js</option>
            <option value="reflection">reflection</option>
            <option value="gf">gf</option>
            <option value="backup">backup</option>
            <option value="misconfig">misconfig</option>
            <option value="zerodays">zerodays</option>
            <option value="ffuf">ffuf</option>
            <option value="jwt">jwt</option>
            <option value="apkx">apkx</option>
          </optgroup>
        </select>
        <select id="launch-target-mode"></select>
        <input type="text" id="launch-target" placeholder="e.g. example.com" autocomplete="off" spellcheck="false" />
        <textarea id="launch-target-list" class="launch-target-list" placeholder="one target per line" style="display:none"></textarea>
        <button class="btn-primary" id="launch-btn">
          <span>▶</span>
          <span>Launch</span>
        </button>
      </div>
      <div id="launch-help" class="launch-help"></div>
      <details class="launcher-accordion" open>
        <summary>Essential flags</summary>
        <div id="launch-flags-essential" class="launch-flags-grid"></div>
      </details>
      <details class="launcher-accordion">
        <summary>Advanced flags</summary>
        <div id="launch-flags-advanced" class="launch-flags-grid"></div>
      </details>
    </div>`;
    html += `<div class="card" style="margin-bottom:20px; border:1px solid var(--border); background:rgba(13,17,23,0.4)"><div class="card-body" style="padding:16px"><div style="display:flex;gap:16px;flex-wrap:wrap;align-items:center"><div style="flex:1;min-width:280px;position:relative"><input type="text" id="scan-search-input" class="search-input" placeholder="🔍 Search targets or scan types..." value="${window.esc(sUI.search)}" style="width:100%; padding-left:36px; background:var(--bg-secondary)"><span style="position:absolute; left:12px; top:50%; transform:translateY(-50%); color:var(--text-muted); pointer-events:none"></span></div><div style="min-width:180px"><select id="scan-type-filter" class="input" style="width:100%; background:var(--bg-secondary)"><option value="all">All Scan Types</option><optgroup label="Workflows"><option value="recon" ${sUI.typeFilter === 'recon' ? 'selected' : ''}>Recon</option><option value="domain_run" ${sUI.typeFilter === 'domain_run' ? 'selected' : ''}>Full Domain</option><option value="subdomain_run" ${sUI.typeFilter === 'subdomain_run' ? 'selected' : ''}>Subdomain Run</option></optgroup><optgroup label="Modules"><option value="nuclei" ${sUI.typeFilter === 'nuclei' ? 'selected' : ''}>Nuclei</option><option value="subdomains" ${sUI.typeFilter === 'subdomains' ? 'selected' : ''}>Subdomains</option><option value="livehosts" ${sUI.typeFilter === 'livehosts' ? 'selected' : ''}>Live Hosts</option><option value="tech" ${sUI.typeFilter === 'tech' ? 'selected' : ''}>Tech Detect</option><option value="ffuf" ${sUI.typeFilter === 'ffuf' ? 'selected' : ''}>FFuf Fuzz</option><option value="js" ${sUI.typeFilter === 'js' ? 'selected' : ''}>JS Scan</option><option value="dns" ${sUI.typeFilter === 'dns' ? 'selected' : ''}>DNS Takeover</option></optgroup></select></div><div style="min-width:180px"><select id="scan-status-filter" class="input" style="width:100%; background:var(--bg-secondary)"><option value="all" ${sUI.statusFilter === 'all' ? 'selected' : ''}>Any Status</option><option value="completed" ${sUI.statusFilter === 'completed' ? 'selected' : ''}>Completed</option><option value="failed" ${sUI.statusFilter === 'failed' ? 'selected' : ''}>Failed</option><option value="running" ${sUI.statusFilter === 'running' ? 'selected' : ''}>Running</option><option value="stopped" ${sUI.statusFilter === 'stopped' ? 'selected' : ''}>Stopped / Cancelled</option></select></div></div></div></div>`;
    if (filteredActive.length) {
      html += `<div class="card" style="margin-bottom:20px"><div class="card-header"><div class="card-title">⚡ Active Scans <span class="badge badge-running">${filteredActive.length}</span></div></div><div class="card-body">${filteredActive.map((s) => scanItemHtml(s)).join('')}</div></div>`;
    }
    html += `<div class="card"><div class="card-header" style="display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:12px"><div class="card-title">🕐 Recent Scans ${filteredRecent.length !== recent_scans.length ? `<span style="font-size:12px;color:var(--text-muted);font-weight:400;margin-left:8px">(${filteredRecent.length} filtered)</span>` : ''}</div><div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center"><button type="button" class="btn btn-ghost" style="font-size:12px;padding:6px 12px" onclick="deleteSelectedScans()">Delete selected</button><button type="button" class="btn btn-ghost" style="font-size:12px;padding:6px 12px;color:var(--accent-red);border-color:rgba(248,113,113,.35)" onclick="clearAllScans()">Clear all</button></div></div><div class="card-body">`;
    if (!filteredRecent.length && !filteredActive.length) {
      if (sUI.search || sUI.typeFilter !== 'all' || sUI.statusFilter !== 'all') html += window.emptyState('🔍', 'No matches found', 'Adjust your filters or search term to see more scans.');
      else html += scanErr ? window.emptyState('⚠️', 'Scans unavailable', 'Fix the error above or check that the API is reachable.') : window.emptyState('📋', 'No scans yet', 'Start a scan from the launcher above or via the CLI.');
    } else if (!filteredRecent.length && recent_scans.length > 0) {
      html += '<div style="padding:20px;text-align:center;color:var(--text-muted);font-size:13px">No completed scans match the current filter</div>';
    } else if (filteredRecent.length > 0) {
      html += `<table class="data-table" id="recent-scans-table"><thead><tr><th style="width:36px" onclick="event.stopPropagation()"><input type="checkbox" title="Select all" aria-label="Select all" onclick="event.stopPropagation();toggleSelectAllRecentScans(this)" /></th><th>Target</th><th>Type</th><th>Status</th><th>Phase</th><th>Started</th><th>Elapsed</th><th>Results</th></tr></thead><tbody>${filteredRecent.map((s) => scanRowHtml(s)).join('')}</tbody></table>`;
    }
    html += '</div></div>';
    container.innerHTML = html;
    const searchIn = container.querySelector('#scan-search-input');
    if (searchIn) searchIn.oninput = (e) => { const pos = e.target.selectionStart; window.state.scanListUI.search = e.target.value; renderScans(); const inp = document.getElementById('scan-search-input'); if (inp) { inp.focus(); inp.setSelectionRange(pos, pos); } };
    const typeSel = container.querySelector('#scan-type-filter');
    if (typeSel) typeSel.onchange = (e) => { window.state.scanListUI.typeFilter = e.target.value; renderScans(); };
    const statusSel = container.querySelector('#scan-status-filter');
    if (statusSel) statusSel.onchange = (e) => { window.state.scanListUI.statusFilter = e.target.value; renderScans(); };
    const launchBtn = container.querySelector('#launch-btn');
    const launchType = container.querySelector('#launch-type');
    const launchTargetMode = container.querySelector('#launch-target-mode');
    const launchTarget = container.querySelector('#launch-target');
    const launchTargetList = container.querySelector('#launch-target-list');
    if (launchBtn) launchBtn.onclick = window.triggerScan;
    if (launchType) launchType.onchange = () => window.syncLaunchPlaceholder(true);
    if (launchTargetMode) launchTargetMode.onchange = () => window.syncLaunchPlaceholder(false);
    if (launchTarget) launchTarget.oninput = window.updateLaunchPreview;
    if (launchTargetList) launchTargetList.oninput = window.updateLaunchPreview;
    container.oninput = (e) => { if (e.target && e.target.matches('[data-flag-key]')) window.updateLaunchPreview(); };
    container.onchange = (e) => { if (e.target && e.target.matches('[data-flag-key]')) window.updateLaunchPreview(); };
    window.syncLaunchPlaceholder(true);
  }

  window.ScansPage = {
    scanTypeLabel,
    scanItemHtml,
    scanRowHtml,
    renderScans,
  };
})();

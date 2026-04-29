(() => {
  function csvEscape(value) {
    const str = String(value ?? '');
    return `"${str.replace(/"/g, '""')}"`;
  }

  async function exportScanResultsCSV(scanId) {
    try {
      window.showToast('info', 'Exporting CSV', `Preparing scan ${scanId} findings...`);
      const parsed = await window.apiFetch(`/api/scans/${encodeURIComponent(scanId)}/results/parsed?section=all&limit=10000`);
      const rows = Array.isArray(parsed?.rows) ? parsed.rows : [];
      if (!rows.length) {
        window.showToast('error', 'No data', 'No findings available to export for this scan.');
        return;
      }

      const headers = ['target', 'severity', 'finding', 'module', 'kind', 'category', 'file', 'source'];
      const csvLines = [
        headers.join(','),
        ...rows.map((r) => {
          const target = r.host || r.target || '';
          const severity = r.severity || '';
          const finding = r.title || r.finding || '';
          const module = r.module || '';
          const kind = r.kind || '';
          const category = r.category || '';
          const file = r.file || r.file_name || '';
          const source = r.source || '';
          return [
            csvEscape(target),
            csvEscape(severity),
            csvEscape(finding),
            csvEscape(module),
            csvEscape(kind),
            csvEscape(category),
            csvEscape(file),
            csvEscape(source),
          ].join(',');
        }),
      ];

      const blob = new Blob([csvLines.join('\n')], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      const ts = new Date().toISOString().replace(/[:.]/g, '-');
      a.href = url;
      a.download = `scan-${scanId}-results-${ts}.csv`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      window.showToast('success', 'CSV exported', `${rows.length} row(s) downloaded.`);
    } catch (e) {
      window.showToast('error', 'CSV export failed', e?.message || String(e));
    }
  }

  async function generateScanReport(scanId) {
    window.showToast('info', 'Generating Report', `Gathering data for scan ${scanId}`);
    try {
      const data = await window.apiFetch(`/api/scans/${encodeURIComponent(scanId)}/report`);
      const reportWindow = window.open('', '_blank');
      const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>AutoAR Scan Report - ${scanId}</title>
        <style>
          body { font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; line-height: 1.6; color: #333; padding: 40px; max-width: 900px; margin: auto; }
          h1 { border-bottom: 2px solid #06b6d4; padding-bottom: 10px; color: #0f172a; }
          .meta { background: #f8fafc; padding: 20px; border-radius: 8px; margin-bottom: 30px; }
          .finding-card { border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 16px; page-break-inside: avoid; }
          .severity-high { border-left: 5px solid #f97316; }
          .severity-critical { border-left: 5px solid #ef4444; }
          .badge { font-size: 11px; padding: 2px 8px; border-radius: 4px; font-weight: bold; }
        </style>
      </head>
      <body>
        <h1>Security Scan Report</h1>
        <div class="meta">
          <div><strong>Target:</strong> ${data.scan_info?.target || 'N/A'}</div>
          <div><strong>Type:</strong> ${data.scan_info?.scan_type || 'N/A'}</div>
          <div><strong>Status:</strong> ${data.scan_info?.status || 'N/A'}</div>
          <div><strong>Generated:</strong> ${new Date().toLocaleString()}</div>
        </div>
        <h2>Summary of Findings</h2>
        <p>This scan identified ${data.files?.length || 0} result artifacts.</p>
        <div id="findings">
          ${data.files?.map((f) => `
            <div class="finding-card">
              <strong>${f.file_name}</strong> (${f.module})
              <div style="font-size: 13px; color: #64748b">Size: ${f.size_bytes} bytes</div>
            </div>
          `).join('')}
        </div>
        <script>window.print();</script>
      </body>
      </html>
    `;
      reportWindow.document.write(html);
      reportWindow.document.close();
    } catch (e) {
      window.showToast('error', 'Report Failed', e.message);
    }
  }

  let cnamesPollInterval = null;

  async function startCnamesProgressPolling() {
    if (cnamesPollInterval) clearInterval(cnamesPollInterval);

    const progressDiv = document.getElementById('cnames-progress');
    const progressText = document.getElementById('cnames-progress-text');
    if (progressDiv) progressDiv.style.display = 'flex';

    const poll = async () => {
      try {
        const data = await window.apiFetch('/api/subdomains/cnames/progress');
        if (progressText) {
          progressText.textContent = `${data.processed} / ${data.total} (${data.matches} matches)`;
        }
        if (!data.is_running) {
          clearInterval(cnamesPollInterval);
          cnamesPollInterval = null;
          setTimeout(() => {
            if (progressDiv) progressDiv.style.display = 'none';
          }, 5000);
        }
      } catch (_) {}
    };

    poll();
    cnamesPollInterval = setInterval(poll, 2000);
  }

  async function promptRetryCnames() {
    const matchString = prompt("Enter an optional match string (e.g. 's3.amazonaws.com' or 'phenomepeople') to alert on matches, or leave empty to just resolve all missing CNAMEs:", '');
    if (matchString === null) return;
    try {
      const data = await window.apiPost('/api/subdomains/cnames/retry', { match_string: matchString });
      window.showToast('success', 'Started', data.message || 'CNAME resolution started in background');
      startCnamesProgressPolling();
    } catch (err) {
      window.showToast('error', 'Error', err.message);
    }
  }

  function promptRunGlobalNuclei() {
    document.getElementById('nuclei-template-input').value = '';
    document.getElementById('nuclei-modal').style.display = 'flex';
  }

  function closeNucleiModal() {
    document.getElementById('nuclei-modal').style.display = 'none';
  }

  async function submitNucleiModal() {
    const template = document.getElementById('nuclei-template-input').value.trim();
    if (!template) {
      window.showToast('error', 'Error', 'Template cannot be empty');
      return;
    }
    try {
      const data = await window.apiPost('/api/subdomains/nuclei/run', { template });
      window.showToast('success', 'Started', data.message || 'Global Nuclei scan started');
      closeNucleiModal();
      if (data.scan_id) {
        setTimeout(() => {
          document.getElementById('nav-scans')?.click();
        }, 1500);
      }
    } catch (err) {
      window.showToast('error', 'Error', err.message);
    }
  }

  window.OpsToolsPage = {
    exportScanResultsCSV,
    generateScanReport,
    promptRetryCnames,
    startCnamesProgressPolling,
    promptRunGlobalNuclei,
    closeNucleiModal,
    submitNucleiModal,
  };

  window.promptRetryCnames = promptRetryCnames;
  window.promptRunGlobalNuclei = promptRunGlobalNuclei;
  window.closeNucleiModal = closeNucleiModal;
  window.submitNucleiModal = submitNucleiModal;
  setTimeout(startCnamesProgressPolling, 1000);
})();

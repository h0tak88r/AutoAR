(() => {
  const esc = (v) => window.esc(v);
  const detectModuleFromFileName = (...args) => window.detectModuleFromFileName(...args);
  const getModuleDisplayInfo = (...args) => window.getModuleDisplayInfo(...args);

  function getStatusColor(status) {
    if (!status) return 'var(--text-muted)';
    const s = Number(status);
    if (s >= 200 && s < 300) return 'var(--accent-emerald)';
    if (s >= 300 && s < 400) return 'var(--accent-cyan)';
    if (s >= 400 && s < 500) return 'var(--accent-amber)';
    if (s >= 500) return 'var(--accent-red)';
    return 'var(--text-muted)';
  }

  function isLiveStatus(status) {
    if (!status) return false;
    const s = Number(status);
    return s >= 200 && s < 400;
  }

  function renderSubdomainListTable(items) {
    const rows = items.map((sub) => `<tr><td><div style="font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--accent-cyan)">${esc(String(sub))}</div></td><td><span class="badge badge-live">● live</span></td><td style="color:var(--text-muted)">—</td><td style="color:var(--text-muted)">—</td></tr>`).join('');
    return `<div class="result-table-wrap"><table class="result-table"><thead><tr><th>SUBDOMAIN</th><th>STATUS</th><th>HTTP</th><th>HTTPS</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function renderSubdomainObjectTable(items) {
    const rows = items.map((item) => {
      const subdomain = item.subdomain || item.domain || item.host || '—';
      const isLive = item.is_live || item.live || item.status === 'live';
      const httpStatus = item.http_status || item.http || null;
      const httpsStatus = item.https_status || item.https || null;
      return `<tr><td><div style="font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--accent-cyan)">${esc(String(subdomain))}</div></td><td><span class="badge ${isLive ? 'badge-live' : 'badge-dead'}">${isLive ? '● live' : '● dead'}</span></td><td style="color:var(--text-muted);font-family:'JetBrains Mono',monospace">${httpStatus ? `<span style="color:${getStatusColor(httpStatus)}">${httpStatus}</span>` : '—'}</td><td style="color:var(--text-muted);font-family:'JetBrains Mono',monospace">${httpsStatus ? `<span style="color:${getStatusColor(httpsStatus)}">${httpsStatus}</span>` : '—'}</td></tr>`;
    }).join('');
    return `<div class="result-table-wrap"><table class="result-table"><thead><tr><th>SUBDOMAIN</th><th>STATUS</th><th>HTTP</th><th>HTTPS</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function renderHTTPXTable(items) {
    const rows = items.map((item) => {
      const url = item.url || item.host || '—';
      const status = item.status_code || item.status || '—';
      const title = item.title || '—';
      const tech = item.tech || item.technologies || '—';
      return `<tr><td><div style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan)">${esc(String(url))}</div></td><td><span class="badge ${isLiveStatus(status) ? 'badge-live' : 'badge-dead'}">${status}</span></td><td style="color:var(--text-secondary);font-size:12px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(String(title))}</td><td style="color:var(--text-muted);font-size:11px;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(String(tech))}</td></tr>`;
    }).join('');
    return `<div class="result-table-wrap"><table class="result-table"><thead><tr><th>URL</th><th>STATUS</th><th>TITLE</th><th>TECH</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function renderNucleiTable(items) {
    const rows = items.map((item) => {
      const template = item['template-id'] || item.template_id || item.template || '—';
      const severity = item.info?.severity || item.severity || 'info';
      const matchedAt = item['matched-at'] || item.matched_at || item.url || item.host || '—';
      const description = item.info?.name || item.name || '—';
      return `<tr><td><div style="font-size:12px;color:var(--text-secondary);max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(String(template))}</div></td><td><span class="severity-${severity.toLowerCase()}">${severity.toUpperCase()}</span></td><td><div style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan);max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(String(matchedAt))}</div></td><td style="font-size:12px;color:var(--text-muted);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(String(description))}</td></tr>`;
    }).join('');
    return `<div class="result-table-wrap"><table class="result-table"><thead><tr><th>TEMPLATE</th><th>SEVERITY</th><th>MATCHED AT</th><th>DESCRIPTION</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function renderZeroDaysTable(items) {
    const rows = items.map((item) => {
      const cve = item.cve || item.vulnerability || '—';
      const host = item.host || item.url || '—';
      const status = item.status || item.result || '—';
      const details = item.details || item.description || '—';
      return `<tr><td><span class="severity-high">${esc(String(cve))}</span></td><td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan)">${esc(String(host))}</td><td><span class="badge ${status === 'vulnerable' ? 'badge-failed' : 'badge-done'}">${esc(String(status))}</span></td><td style="font-size:12px;color:var(--text-muted);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(String(details))}</td></tr>`;
    }).join('');
    return `<div class="result-table-wrap"><table class="result-table"><thead><tr><th>CVE</th><th>HOST</th><th>STATUS</th><th>DETAILS</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function renderJSFindingsTable(items) { return window.renderJSFindingsTable ? window.renderJSFindingsTable(items) : renderGenericJSONTable(items); }
  function renderXSSFindingsTable(items) { return window.renderXSSFindingsTable ? window.renderXSSFindingsTable(items) : renderGenericJSONTable(items); }
  function renderSQLiFindingsTable(items) { return window.renderSQLiFindingsTable ? window.renderSQLiFindingsTable(items) : renderGenericJSONTable(items); }
  function renderURLListTable(items) { return window.renderURLListTable ? window.renderURLListTable(items) : renderGenericJSONTable(items); }
  function renderBackupFindingsTable(items) { return window.renderBackupFindingsTable ? window.renderBackupFindingsTable(items) : renderGenericJSONTable(items); }
  function renderMisconfigTable(items) { return window.renderMisconfigTable ? window.renderMisconfigTable(items) : renderGenericJSONTable(items); }
  function renderAEMTable(items) { return window.renderAEMTable ? window.renderAEMTable(items) : renderGenericJSONTable(items); }
  function renderPortResultsTable(items) { return window.renderPortResultsTable ? window.renderPortResultsTable(items) : renderGenericJSONTable(items); }
  function renderS3FindingsTable(items) { return window.renderS3FindingsTable ? window.renderS3FindingsTable(items) : renderGenericJSONTable(items); }
  function renderDNSFindingsTable(items) { return window.renderDNSFindingsTable ? window.renderDNSFindingsTable(items) : renderGenericJSONTable(items); }
  function renderTechFindingsTable(items) { return window.renderTechFindingsTable ? window.renderTechFindingsTable(items) : renderGenericJSONTable(items); }

  function renderGenericJSONTable(items) {
    const headers = Object.keys(items[0] || {});
    const headerRow = headers.map((h) => `<th style="text-transform:uppercase">${esc(h)}</th>`).join('');
    const rows = items.slice(0, 100).map((item) => {
      const cells = headers.map((h) => {
        const val = item[h];
        const display = typeof val === 'object' ? JSON.stringify(val) : String(val);
        return `<td style="font-size:12px;color:var(--text-secondary);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(display)}</td>`;
      }).join('');
      return `<tr>${cells}</tr>`;
    }).join('');
    return `<div class="result-table-wrap"><table class="result-table"><thead><tr>${headerRow}</tr></thead><tbody>${rows}</tbody></table>${items.length > 100 ? `<div style="padding:12px;text-align:center;color:var(--text-muted);font-size:12px">Showing first 100 of ${items.length} items</div>` : ''}</div>`;
  }

  function renderResultTable(items, type, file) {
    const module = file.module || detectModuleFromFileName(file.file_name);
    const moduleInfo = getModuleDisplayInfo(module);
    const header = `<div class="result-table-header"><div class="result-table-title">${moduleInfo.icon} ${moduleInfo.name} Results<span style="font-size:12px;color:var(--text-muted);margin-left:8px">(${items.length} items)</span></div></div>`;
    switch (type) {
      case 'subdomain-list': return header + renderSubdomainListTable(items);
      case 'subdomain-object': return header + renderSubdomainObjectTable(items);
      case 'httpx-results': return header + renderHTTPXTable(items);
      case 'nuclei-findings': return header + renderNucleiTable(items);
      case 'zerodays-findings': return header + renderZeroDaysTable(items);
      case 'js-findings': return header + renderJSFindingsTable(items);
      case 'xss-findings': return header + renderXSSFindingsTable(items);
      case 'sqli-findings': return header + renderSQLiFindingsTable(items);
      case 'url-list': return header + renderURLListTable(items);
      case 'backup-findings': return header + renderBackupFindingsTable(items);
      case 'misconfig-findings': return header + renderMisconfigTable(items);
      case 'port-results': return header + renderPortResultsTable(items);
      case 's3-findings': return header + renderS3FindingsTable(items);
      case 'dns-findings': return header + renderDNSFindingsTable(items);
      case 'aem-findings': return header + renderAEMTable(items);
      case 'tech-findings': return header + renderTechFindingsTable(items);
      case 'generic-json':
      default: return header + renderGenericJSONTable(items);
    }
  }

  window.ResultTablesPage = {
    renderResultTable,
    renderSubdomainListTable,
    renderSubdomainObjectTable,
    renderHTTPXTable,
    renderNucleiTable,
    renderZeroDaysTable,
    renderJSFindingsTable,
    renderXSSFindingsTable,
    renderSQLiFindingsTable,
    renderURLListTable,
    renderBackupFindingsTable,
    renderMisconfigTable,
    renderAEMTable,
    renderPortResultsTable,
    renderS3FindingsTable,
    renderDNSFindingsTable,
    renderTechFindingsTable,
    renderGenericJSONTable,
    getStatusColor,
    isLiveStatus,
  };
})();

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

  function renderJSFindingsTable(items) {
    const rows = items.map((item) => {
      let url = item.url || item.endpoint || '—';
      let secret = item.secret || item.key || item.type || '—';
      let details = item.details || item.description || '—';
      let tag = '';
      let matcher = '';
      const rawStr = typeof item === 'string' ? item : (item.url && item.url.includes(' -> ') ? item.url : '');
      if (rawStr) {
        const tagMatch = rawStr.match(/^\[(.*?)\]/);
        if (tagMatch) {
          tag = tagMatch[1];
          const rest = rawStr.substring(tagMatch[0].length).trim();
          if (rest.includes(' -> ')) {
            const parts = rest.split(' -> ');
            url = parts[0].trim();
            matcher = parts[1].trim();
          } else {
            url = rest;
          }
        }
      }
      return `<tr><td><div style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan);max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(url)}">${esc(url)}</div></td><td>${tag ? `<span class="badge badge-info" style="background:rgba(56,189,248,0.15);color:var(--accent-cyan);border:1px solid rgba(56,189,248,0.3)">${esc(tag)}</span>` : `<span class="badge badge-running">${esc(secret)}</span>`}</td><td>${matcher ? `<code style="font-size:11px;background:rgba(234,179,8,0.1);color:#eab308;padding:2px 6px;border-radius:4px;border:1px solid rgba(234,179,8,0.2)">${esc(matcher)}</code>` : `<span style="font-size:12px;color:var(--text-muted)">${esc(details)}</span>`}</td></tr>`;
    }).join('');
    return `<div class="result-table-wrap"><table class="result-table"><thead><tr><th>TARGET (JS FILE)</th><th>VULN TYPE</th><th>MATCH / LEAK</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function renderXSSFindingsTable(items) {
    const rows = items.map((item) => {
      const url = item.url || '—';
      const parameter = item.parameter || item.param || '—';
      const payload = item.payload || '—';
      return `<tr><td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan);max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(String(url))}</td><td><code style="font-size:11px;background:var(--accent-amber-dim);padding:2px 6px;border-radius:4px">${esc(String(parameter))}</code></td><td style="font-size:11px;color:var(--text-muted);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:'JetBrains Mono',monospace">${esc(String(payload))}</td></tr>`;
    }).join('');
    return `<div class="result-table-wrap"><table class="result-table"><thead><tr><th>URL</th><th>PARAMETER</th><th>PAYLOAD</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function renderSQLiFindingsTable(items) {
    const rows = items.map((item) => {
      const url = item.url || '—';
      const parameter = item.parameter || item.param || '—';
      const type = item.type || '—';
      const db = item.dbms || item.database || '—';
      return `<tr><td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(String(url))}</td><td><code style="font-size:11px;background:var(--accent-red-dim);padding:2px 6px;border-radius:4px">${esc(String(parameter))}</code></td><td><span class="severity-high">${esc(String(type))}</span></td><td style="font-size:12px;color:var(--text-muted)">${esc(String(db))}</td></tr>`;
    }).join('');
    return `<div class="result-table-wrap"><table class="result-table"><thead><tr><th>URL</th><th>PARAMETER</th><th>TYPE</th><th>DBMS</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function renderURLListTable(items) {
    const rows = items.map((item) => {
      const url = typeof item === 'string' ? item : (item.url || '—');
      return `<tr><td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan);word-break:break-all">${esc(String(url))}</td></tr>`;
    }).join('');
    return `<div class="result-table-wrap"><table class="result-table"><thead><tr><th>URL</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function renderBackupFindingsTable(items) {
    const rows = items.map((item) => {
      const url = item.url || '—';
      const path = item.path || item.file || '—';
      const size = item.size || '—';
      return `<tr><td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan);max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(String(url))}</td><td style="font-size:12px;color:var(--text-secondary)">${esc(String(path))}</td><td style="font-size:12px;color:var(--text-muted)">${esc(String(size))}</td></tr>`;
    }).join('');
    return `<div class="result-table-wrap"><table class="result-table"><thead><tr><th>URL</th><th>PATH</th><th>SIZE</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function renderMisconfigTable(items) {
    const rows = items.map((item) => {
      const url = item.url || '—';
      const service = item.service_name || item.service_id || item.service || '—';
      const config = item['matched-at'] || item.matched_at || item.config || item.setting || '—';
      const severity = item.severity || 'medium';
      return `<tr><td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(String(url))}</td><td style="font-size:12px;color:var(--text-secondary)">${esc(String(service))}</td><td style="font-size:12px;color:var(--text-muted);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(String(config))}</td><td><span class="severity-${severity.toLowerCase()}">${severity.toUpperCase()}</span></td></tr>`;
    }).join('');
    return `<div class="result-table-wrap"><table class="result-table"><thead><tr><th>URL / TARGET</th><th>SERVICE</th><th>MATCHED AT / CONFIG</th><th>SEVERITY</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function renderAEMTable(items) {
    const rows = items.map((item) => {
      const url = item.url || '—';
      const vulnerable = item.vulnerable ? '<span class="badge badge-live">VULNERABLE</span>' : '<span class="badge badge-dead">INFO</span>';
      const reason = item.reason || '—';
      const severity = item.severity || (item.vulnerable ? 'high' : 'info');
      return `<tr><td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan)">${esc(String(url))}</td><td>${vulnerable}</td><td style="font-size:12px;color:var(--text-muted)">${esc(String(reason))}</td><td><span class="severity-${severity.toLowerCase()}">${severity.toUpperCase()}</span></td></tr>`;
    }).join('');
    return `<div class="result-table-wrap"><table class="result-table"><thead><tr><th>URL</th><th>STATUS</th><th>REASON / EVIDENCE</th><th>SEVERITY</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function renderPortResultsTable(items) {
    const rows = items.map((item) => {
      const host = item.host || item.ip || '—';
      const port = item.port || '—';
      const protocol = item.protocol || 'tcp';
      const service = item.service || item.name || '—';
      const state = item.state || item.status || 'open';
      return `<tr><td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan)">${esc(String(host))}</td><td><span style="color:var(--accent-purple);font-weight:600">${esc(String(port))}</span></td><td style="font-size:12px;color:var(--text-muted);text-transform:uppercase">${esc(String(protocol))}</td><td style="font-size:12px;color:var(--text-secondary)">${esc(String(service))}</td><td><span class="badge ${state === 'open' ? 'badge-live' : 'badge-dead'}">${esc(String(state))}</span></td></tr>`;
    }).join('');
    return `<div class="result-table-wrap"><table class="result-table"><thead><tr><th>HOST</th><th>PORT</th><th>PROTOCOL</th><th>SERVICE</th><th>STATE</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function renderS3FindingsTable(items) {
    const rows = items.map((item) => {
      const bucket = item.bucket || '—';
      const url = item.url || '—';
      const keys = item.keys || item.objects || '—';
      const public_ = item.public || item.open || false;
      return `<tr><td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan)">${esc(String(bucket))}</td><td style="font-size:12px;color:var(--text-secondary);max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(String(url))}</td><td style="font-size:12px;color:var(--text-muted)">${esc(String(keys))}</td><td><span class="badge ${public_ ? 'badge-failed' : 'badge-done'}">${public_ ? 'PUBLIC' : 'PRIVATE'}</span></td></tr>`;
    }).join('');
    return `<div class="result-table-wrap"><table class="result-table"><thead><tr><th>BUCKET</th><th>URL</th><th>OBJECTS</th><th>ACCESS</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function renderDNSFindingsTable(items) {
    const rows = items.map((item) => {
      const domain = item.domain || item.subdomain || '—';
      const cname = item.cname || '—';
      const fingerprint = item.fingerprint || item.provider || '—';
      const vulnerable = item.vulnerable || item.takoverable || false;
      return `<tr><td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan)">${esc(String(domain))}</td><td style="font-size:12px;color:var(--text-muted);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(String(cname))}</td><td style="font-size:12px;color:var(--text-secondary)">${esc(String(fingerprint))}</td><td><span class="badge ${vulnerable ? 'badge-failed' : 'badge-done'}">${vulnerable ? 'VULNERABLE' : 'SAFE'}</span></td></tr>`;
    }).join('');
    return `<div class="result-table-wrap"><table class="result-table"><thead><tr><th>DOMAIN</th><th>CNAME</th><th>FINGERPRINT</th><th>STATUS</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function renderTechFindingsTable(items) {
    const rows = items.map((item) => {
      const url = item.url || '—';
      const tech = item.tech || item.technology || item.name || '—';
      const version = item.version || '—';
      const category = item.category || '—';
      return `<tr><td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(String(url))}</td><td><span class="badge badge-running">${esc(String(tech))}</span></td><td style="font-size:12px;color:var(--text-muted)">${esc(String(version))}</td><td style="font-size:12px;color:var(--text-secondary)">${esc(String(category))}</td></tr>`;
    }).join('');
    return `<div class="result-table-wrap"><table class="result-table"><thead><tr><th>URL</th><th>TECHNOLOGY</th><th>VERSION</th><th>CATEGORY</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

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

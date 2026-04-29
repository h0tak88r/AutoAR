(() => {
  function parseNucleiFindingLine(line) {
    const s = String(line || '').trim();
    if (!s) return null;

    let m = s.match(/\[([a-zA-Z]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)/);
    if (m) {
      return { severity: m[1].toLowerCase(), template: m[2], matcher: m[3], url: m[4] };
    }

    m = s.match(/\[([a-zA-Z]+)\]\s+\[([^\]]+)\]\s+(\S+)/);
    if (m) {
      return { severity: m[1].toLowerCase(), template: m[2], matcher: '', url: m[3] };
    }

    if (/\[.*\]/.test(s) && /(https?:\/\/|[a-z0-9.-]+\.[a-z]{2,})/i.test(s)) {
      return { severity: 'info', template: s.slice(0, 80), matcher: '', url: s.match(/(https?:\/\/\S+|[a-z0-9.-]+\.[a-z]{2,}\S*)/i)?.[1] || '' };
    }
    return null;
  }

  function groupFilesByModule(files) {
    const modules = {};
    (files || []).forEach((f) => {
      const mod = window.detectModuleFromFileName(f.file_name, f.module);
      if (!modules[mod]) modules[mod] = [];
      f._module = mod;
      modules[mod].push(f);
    });
    return modules;
  }

  function detectResultType(items, file) {
    if (!items.length) return 'unknown';

    const first = items[0];
    const fileName = (file.file_name || '').toLowerCase();
    const module = file.module || window.detectModuleFromFileName(file.file_name);

    if (module === 'subdomain-enum' || fileName.includes('subdomain') || fileName.includes('subs')) {
      if (typeof first === 'string') return 'subdomain-list';
      if (first.subdomain || first.domain || first.host) return 'subdomain-object';
    }
    if (module === 'httpx' || fileName.includes('live') || fileName.includes('httpx') || fileName.includes('livehosts')) {
      if (first.url || first.URL || first.host || first.Host || first.status_code || first.StatusCode || first.status || first.title) return 'httpx-results';
    }
    if (module === 'nuclei' || fileName.includes('nuclei')) {
      if (first['template-id'] || first.template_id || first.template || first.severity || first['matched-at']) return 'nuclei-findings';
    }
    if (module === 'zerodays' || fileName.includes('zeroday')) {
      if (first.cve || first.vulnerability || first.exploit) return 'zerodays-findings';
    }
    if (module === 'js-analysis' || fileName.includes('js-')) {
      if (first.url || first.endpoint || first.secret || first.key) return 'js-findings';
    }
    if (module === 'xss-detection' || fileName.includes('dalfox') || fileName.includes('kxss')) {
      if (first.url && (first.payload || first.parameter)) return 'xss-findings';
    }
    if (module === 'sql-detection' || fileName.includes('sqlmap')) {
      if (first.url && (first.parameter || first.type)) return 'sqli-findings';
    }
    if (module === 'gf-patterns' || fileName.startsWith('gf-')) {
      if (typeof first === 'string') return 'url-list';
      if (first.url) return 'url-list';
    }
    if (module === 'backup-detection' || fileName.includes('backup')) {
      if (first.url || first.path) return 'backup-findings';
    }
    if (module === 'misconfig') {
      if (first.url || first.service || first.service_name || first.service_id || first.config || first['matched-at']) return 'misconfig-findings';
    }
    if (module === 'aem' || fileName.includes('aem')) {
      if (first.url || first.vulnerable || first.reason) return 'aem-findings';
    }
    if (module === 'port-scan' || fileName.includes('port') || fileName.includes('nmap')) {
      if (first.port || first.protocol || first.service) return 'port-results';
    }
    if (module === 's3-scan' || fileName.includes('s3') || fileName.includes('bucket')) {
      if (first.bucket || first.key || first.url) return 's3-findings';
    }
    if (module === 'dns-takeover' || fileName.includes('dns')) {
      if (first.domain || first.cname || first.fingerprint) return 'dns-findings';
    }
    if (module === 'tech-detect') {
      if (first.url && (first.tech || first.technology || first.framework)) return 'tech-findings';
    }
    if (typeof first === 'string') return 'url-list';
    if (first.url) return 'url-list';
    return 'generic-json';
  }

  async function parseAndRenderResults(scanId, file, container) {
    try {
      const data = await window.apiFetch(`/api/scans/${encodeURIComponent(scanId)}/results/file?file_name=${encodeURIComponent(file.file_name)}&page=1&per_page=500`);

      let items = [];
      let resultType = 'generic-json';
      if (data.format === 'json-array') {
        items = data.items || [];
        resultType = detectResultType(items, file);
      } else if (data.format === 'json-object' && data.data) {
        const obj = data.data;
        for (const key of ['results', 'findings', 'matches', 'issues', 'vulnerabilities', 'data', 'items', 'hosts', 'subdomains']) {
          if (Array.isArray(obj[key])) {
            items = obj[key];
            break;
          }
        }
        if (!items.length) items = [obj];
        resultType = detectResultType(items, file);
      } else if (data.format === 'text' && Array.isArray(data.lines)) {
        const lines = data.lines.map((x) => String(x || '').trim()).filter(Boolean);
        const mod = window.detectModuleFromFileName(file.file_name, file.module);
        if (mod === 'nuclei') {
          const parsed = [];
          for (const line of lines) {
            const p = parseNucleiFindingLine(line);
            if (p) parsed.push({ template: p.template || '—', severity: p.severity || 'info', url: p.url || '' });
          }
          items = parsed.length ? parsed : lines;
        } else {
          items = lines;
        }
        resultType = detectResultType(items, file);
      }

      if (!items.length) {
        container.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text-muted)">No parseable results in this file</div>';
        return;
      }

      container.innerHTML = window.renderResultTable(items, resultType, file);
    } catch (e) {
      container.innerHTML = `<div style="padding:20px;color:var(--accent-red)">Error loading results: ${window.esc(e.message)}</div>`;
    }
  }

  window.ScanResultsCorePage = {
    parseNucleiFindingLine,
    groupFilesByModule,
    detectResultType,
    parseAndRenderResults,
  };
})();

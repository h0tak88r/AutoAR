(() => {
  function getFileTypeFromName(fileName) {
    const name = String(fileName || '').toLowerCase();
    if (name.endsWith('.json')) return 'json';
    if (name.endsWith('.csv')) return 'csv';
    if (name.endsWith('.log')) return 'log';
    if (name.endsWith('.txt')) return 'text';
    return 'text';
  }

  function getFileTypeIcon(fileType) {
    switch (fileType) {
      case 'json': return 'JSON';
      case 'csv': return 'CSV';
      case 'log': return 'LOG';
      case 'text': return 'TXT';
      default: return 'TXT';
    }
  }

  function toggleCollapsible(header) {
    const content = header.nextElementSibling;
    content.classList.toggle('expanded');
    header.classList.toggle('active');
  }

  function switchScanDetailTab(tabName) {
    const tabsRoot = document.getElementById('scan-detail-tabs');
    if (!tabsRoot) return;
    tabsRoot.querySelectorAll('.tab-btn, .tab-pill').forEach((btn) => {
      btn.classList.remove('active');
      if (btn.getAttribute('data-tab') === tabName) btn.classList.add('active');
    });
    document.querySelectorAll('[id^="tab-panel-"]').forEach((panel) => panel.classList.remove('active'));
    const panel = document.getElementById(`tab-panel-${tabName}`);
    if (panel) panel.classList.add('active');
  }

  function syntaxHighlightJSON(json) {
    if (!json) return '';
    let escaped = window.esc(json);
    return escaped
      .replace(/&quot;([^&]+?)&quot;(\s*:\s*)/g, '<span class="json-key">"$1"</span>$2')
      .replace(/:\s*&quot;([^&]*?)&quot;/g, ': <span class="json-string">"$1"</span>')
      .replace(/\b(\d+\.?\d*)\b/g, '<span class="json-number">$1</span>')
      .replace(/\b(true|false)\b/g, '<span class="json-boolean">$1</span>')
      .replace(/\bnull\b/g, '<span class="json-null">null</span>')
      .replace(/([{}[\]])/g, '<span class="json-bracket">$1</span>');
  }

  function formatJSONWithHighlighting(jsonObj) {
    const jsonStr = JSON.stringify(jsonObj, null, 2);
    return syntaxHighlightJSON(jsonStr);
  }

  function scanNoArtifactsMessage(scanType, target) {
    const t = (target && String(target).trim()) || 'this target';
    const st = String(scanType || '').toLowerCase().trim();
    switch (st) {
      case 'ports': return `[ -- ] Port Scan — No open ports found (excluding 80, 443, 8080, 8443) for ${t}`;
      case 'aem':
      case 'aem_scan': return `[ -- ] AEM Scan — No AEM instances discovered for ${t}`;
      case 'tech': return `[ -- ] Tech Detection — No live hosts found for ${t}`;
      case 'backup': return `[ -- ] Backup Scan — No backup files found for ${t}`;
      case 'misconfig': return `[ -- ] Misconfig Scan — No misconfigurations found for ${t}`;
      case 'subdomains': return `[ -- ] Subdomains — No subdomains found for ${t}`;
      case 'livehosts': return `[ -- ] Live hosts — No live hosts found for ${t}`;
      case 'urls': return `[ -- ] URLs — No interesting URLs found for ${t}`;
      case 'jsscan':
      case 'js': return `[ -- ] JS Scan — No JavaScript vulnerabilities found for ${t}`;
      case 'reflection': return `[ -- ] Reflection — 0 findings for ${t}`;
      case 'nuclei': return `[ -- ] Nuclei — No vulnerabilities found for ${t}`;
      case 'gf': return `[ -- ] GF Patterns — No vulnerable parameters found for ${t}`;
      case 's3': return `[ -- ] S3 Scan — No exposed buckets found for ${t}`;
      case 'githubscan': return `[ -- ] GitHub Scan — No secrets found for ${t}`;
      case 'zerodays':
      case '0days': return `[ -- ] 0-Days — No zero-day vulnerabilities found for ${t}`;
      case 'ffuf': return `[ -- ] FFuf — No hidden directories found for ${t}`;
      case 'dns': return `[ -- ] DNS takeover — No vulnerable records or dangling IPs found for ${t}`;
      case 'cf1016': return `[ -- ] CF1016 dangling DNS — No missing Cloudflare origins found for ${t}`;
      default: {
        const name = st ? st.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()) : 'Scan';
        return `[ -- ] ${name} — 0 findings for ${t}`;
      }
    }
  }

  function detectModuleFromFileName(fileName, existingModule) {
    if (existingModule) return existingModule;
    const n = String(fileName || '').toLowerCase();
    if (!n) return 'unknown';
    // JS secret artifacts (check this before generic github/secret checks)
    if (n.includes('js-endpoint')) return 'js-endpoints';
    if (n.includes('katana')) return 'katana-crawler';
    if (n.includes('js-secret') || n.includes('js-exposure') || n.includes('js-analysis') || n.startsWith('js-sec')) return 'js-analysis';
    // GitHub must be BEFORE generic "secret" match
    if (n.includes('github-secret') || n.includes('github-secrets') || (n.includes('github') && n.includes('secret'))) return 'github-scan';
    if (n.includes('github') || n.includes('trufflehog') || (n.endsWith('.json') && n.includes('github')) || n.includes('git-secret')) return 'github-scan';
    if (n.startsWith('nuclei-') || n.includes('nuclei')) return 'nuclei';
    if (n.includes('kxss') || n.includes('dalfox') || n.includes('xss-reflection')) return 'xss-detection';
    if (n.includes('reflection')) return 'xss-detection';
    if (n.includes('sqlmap') || n.includes('sqli')) return 'sql-detection';
    if (n.startsWith('gf-') || n.includes('gf-')) return 'gf-patterns';
    if (n.includes('zerodays') || n.includes('cve')) return 'zerodays';
    if (n.includes('backup') || n.includes('fuzzuli')) return 'backup-detection';
    if (n.includes('misconfig')) return 'misconfig';
    if (n.includes('exposure')) return 'exposure';
    if (n.includes('cname')) return 'dns-takeover';
    if (n.includes('wp-confusion') || n.includes('wp_confusion')) return 'wordpress-confusion';
    if (n.includes('depconfusion')) return 'dependency-confusion';
    if (n.includes('s3') || n.includes('bucket')) return 's3-scan';
    if (n.includes('aem')) return 'aem';
    if (n.includes('gospider')) return 'url-enum';
    if (n.includes('dns') || n.includes('takeover')) return 'dns-takeover';
    if (n.includes('tech-detect') || n.includes('wappalyzer')) return 'tech-detect';
    if (n.includes('port-scan') || n.includes('ports') || n.includes('nmap') || n.includes('masscan')) return 'port-scan';
    if (n.includes('github') || n.includes('github-scan') || n.includes('gh-')) return 'github-scan';
    if (n.includes('ffuf') || n.includes('fuzz')) return 'ffuf-fuzzing';
    if (n.includes('reflection') || n.includes('param')) return 'reflection';
    if (n.includes('urls.txt') || n.includes('all-urls')) return 'url-enum';
    return 'autoar';
  }

  function normalizeModuleKey(module) {
    const raw = String(module || '').toLowerCase().trim();
    if (!raw) return 'unknown';
    const aliases = {
      'aem-scan': 'aem',
      ffuf: 'ffuf-fuzzing',
      dns: 'dns-takeover',
      cf1016: 'dns-takeover',
      'dns-cf1016': 'dns-takeover',
      'dep-confusion': 'dependency-confusion',
      dependency_confusion: 'dependency-confusion',
      'wp-confusion': 'wordpress-confusion',
      wordpress_confusion: 'wordpress-confusion',
      unknowns: 'unknown',
      github: 'github-scan',
      'github-secrets': 'github-scan',
    };
    return aliases[raw] || raw;
  }

  function getModuleDisplayInfo(module) {
    const mod = normalizeModuleKey(module);
    const modules = {
      nuclei: { icon: '', name: 'Nuclei', color: '#ef4444' },
      'subdomain-enum': { icon: '', name: 'Subdomains', color: '#6366f1' },
      httpx: { icon: '', name: 'Live Hosts', color: '#22c55e' },
      apkx: { icon: '', name: 'APK Analysis', color: '#22d3ee' },
      'js-analysis': { icon: '', name: 'JS Secrets', color: '#eab308' },
      'js-endpoints': { icon: '', name: 'JS Endpoints', color: '#10b981' },
      'katana-crawler': { icon: '', name: 'Katana Crawler', color: '#8b5cf6' },
      'xss-detection': { icon: '', name: 'XSS Detection', color: '#f97316' },
      'sql-detection': { icon: '', name: 'SQLi', color: '#dc2626' },
      'gf-patterns': { icon: '', name: 'GF Patterns', color: '#8b5cf6' },
      zerodays: { icon: '', name: 'Zero-Days', color: '#dc2626' },
      'backup-detection': { icon: '', name: 'Backup Files', color: '#94a3b8' },
      misconfig: { icon: '', name: 'Misconfig', color: '#f59e0b' },
      'wordpress-confusion': { icon: '', name: 'WP Plugin Confusion', color: '#a855f7' },
      'dependency-confusion': { icon: '', name: 'Dep Confusion', color: '#c084fc' },
      's3-scan': { icon: '', name: 'S3 Buckets', color: '#0ea5e9' },
      aem: { icon: '', name: 'AEM Enum', color: '#f97316' },
      'dns-takeover': { icon: '', name: 'DNS', color: '#06b6d4' },
      'tech-detect': { icon: '', name: 'Tech Detect', color: '#a855f7' },
      'port-scan': { icon: '', name: 'Port Scan', color: '#64748b' },
      'github-scan': { icon: '', name: 'GitHub Secrets', color: '#94a3b8' },
      reflection: { icon: '', name: 'Reflection', color: '#f97316' },
      'ffuf-fuzzing': { icon: '', name: 'FFUF Fuzzing', color: '#f43f5e' },
      'url-collection': { icon: '', name: 'URL Collection', color: '#38bdf8' },
      exposure: { icon: '', name: 'Exposure', color: '#f59e0b' },
      autoar: { icon: '', name: 'AutoAR', color: '#4ade80' },
      unknown: { icon: '', name: 'Unknown', color: '#64748b' },
    };
    return modules[mod] || modules.unknown;
  }

  // Flatten one file-preview payload (from /results/file) into table rows. Used as
  // the fallback in scan-detail when the parsed-findings API returns nothing (e.g.
  // a scan still running with no findings yet). Must never throw — an empty/binary
  // file yields [] so the UI shows "No findings" instead of a JS error row.
  function pdGetPath(obj, path) {
    if (!obj || typeof obj !== 'object') return undefined;
    if (path.indexOf('.') === -1) return obj[path];
    return path.split('.').reduce((o, k) => (o == null ? undefined : o[k]), obj);
  }
  function pdFirstOf(o, keys) {
    for (const k of keys) {
      const v = pdGetPath(o, k);
      if (v != null && v !== '') return v;
    }
    return '';
  }
  function previewDataToFlatRows(data, f) {
    if (!data || typeof data !== 'object') return [];
    const base = {
      file: (f && (f.file_name || f.fileName)) || data.file_name || '',
      module: (f && f.module) || '',
      source: (f && f.source) || '—',
      severity: '—',
      target: '—',
      finding: '',
    };

    // Already-flat rows, or one of the preview array shapes.
    if (Array.isArray(data.rows)) return data.rows;
    let items = [];
    if (Array.isArray(data.items)) items = data.items;
    else if (Array.isArray(data.findings)) items = data.findings;
    else if (Array.isArray(data.results)) items = data.results;
    else if (Array.isArray(data.lines)) items = data.lines;
    if (!items.length) return []; // empty / binary / too_large / no findings

    const str = (v) => (v == null ? '' : (typeof v === 'string' ? v : String(v)));
    return items.map((it) => {
      if (it == null) return { ...base };
      if (typeof it !== 'object') {
        const s = str(it).trim();
        return s ? { ...base, target: s } : { ...base };
      }
      const target = str(pdFirstOf(it, ['matched-at', 'matched_at', 'host', 'matched', 'url', 'target', 'input', 'subdomain', 'ip'])) || '—';
      const severity = str(pdFirstOf(it, ['info.severity', 'severity'])) || '—';
      let finding = str(pdFirstOf(it, ['info.name', 'template-id', 'templateID', 'template', 'name', 'title', 'finding', 'description']));
      if (!finding) {
        try { finding = JSON.stringify(it).slice(0, 300); } catch (_) { finding = ''; }
      }
      return { ...base, target, severity, finding };
    });
  }
  window.previewDataToFlatRows = previewDataToFlatRows;

  window.ScanCommonPage = {
    getFileTypeFromName,
    getFileTypeIcon,
    toggleCollapsible,
    switchScanDetailTab,
    formatJSONWithHighlighting,
    syntaxHighlightJSON,
    scanNoArtifactsMessage,
    detectModuleFromFileName,
    normalizeModuleKey,
    getModuleDisplayInfo,
    previewDataToFlatRows,
  };
})();

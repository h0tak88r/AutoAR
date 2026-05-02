(() => {
  const LAUNCH_SCAN_TYPES = {
    domain_scan: { path: 'domain_run', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
    subdomain_scan: { path: 'subdomain_run', modes: ['subdomain', 'subdomain_list'], placeholders: { subdomain: 'api.example.com', subdomain_list: 'one subdomain per line' } },
    recon: { path: 'recon', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
    subdomains: { path: 'subdomains', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
    livehosts: { path: 'livehosts', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
    urls: { path: 'urls', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
    cnames: { path: 'cnames', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
    js: { path: 'js', modes: ['domain', 'subdomain', 'domain_list', 'subdomain_list'], placeholders: { domain: 'example.com', subdomain: 'api.example.com', domain_list: 'one domain per line', subdomain_list: 'one subdomain per line' } },
    reflection: { path: 'reflection', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
    nuclei: { path: 'nuclei', modes: ['domain', 'subdomain', 'url', 'domain_list', 'subdomain_list', 'url_list'], placeholders: { domain: 'example.com', subdomain: 'api.example.com', url: 'https://target.tld/', domain_list: 'one domain per line', subdomain_list: 'one subdomain per line', url_list: 'one URL per line' } },
    tech: { path: 'tech', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
    ports: { path: 'ports', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
    gf: { path: 'gf', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
    backup: { path: 'backup', modes: ['domain', 'subdomain', 'domain_list', 'subdomain_list'], placeholders: { domain: 'example.com', subdomain: 'api.example.com', domain_list: 'one domain per line', subdomain_list: 'one subdomain per line' } },
    misconfig: { path: 'misconfig', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
    dns: { path: 'dns', modes: ['domain', 'domain_list'], extra: { dns_type: 'takeover' }, placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
    dns_dangling: { path: 'dns', modes: ['domain', 'domain_list'], extra: { dns_type: 'dangling-ip' }, placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
    dns_takeover: { path: 'dns-takeover', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
    dns_cf1016: { path: 'dns-cf1016', modes: ['domain', 'subdomain', 'domain_list', 'subdomain_list'], placeholders: { domain: 'example.com', subdomain: 'api.example.com', domain_list: 'one domain per line', subdomain_list: 'one subdomain per line' } },
    s3: { path: 's3', modes: ['bucket', 'bucket_list'], placeholders: { bucket: 'bucket-name', bucket_list: 'one bucket per line' } },
    github: { path: 'github', modes: ['repo', 'repo_list'], placeholders: { repo: 'owner/repository or github.com/owner/repo', repo_list: 'one owner/repo per line' } },
    github_org: { path: 'github_org', modes: ['domain', 'domain_list'], placeholders: { domain: 'org-name or github.com/org', domain_list: 'one org per line' } },
    zerodays: { path: 'zerodays', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
    ffuf: { path: 'ffuf', modes: ['target', 'target_list'], placeholders: { target: 'https://example.com/FUZZ', target_list: 'one FUZZ URL per line' } },
    jwt: { path: 'jwt', modes: ['token'], placeholders: { token: 'JWT token' } },
    apkx: { path: 'apkx', modes: ['file_path', 'package_id', 'upload'], placeholders: { file_path: '/absolute/path/to/app.apk', package_id: 'com.example.app', upload: 'Click to upload APK/IPA' } },
  };

  const LAUNCH_MODE_LABELS = {
    domain: 'Domain',
    subdomain: 'Subdomain',
    url: 'URL',
    target: 'Target URL',
    repo: 'Repository',
    bucket: 'Bucket',
    token: 'Token',
    file_path: 'File path',
    domain_list: 'Domain list',
    subdomain_list: 'Subdomain list',
    url_list: 'URL list',
    target_list: 'Target list',
    repo_list: 'Repo/Org list',
    bucket_list: 'Bucket list',
    package_id: 'Package ID',
    upload: 'Direct Upload',
  };

  const SCAN_FLAG_DEFS = {
    domain_scan: [{ key: 'skip_ffuf', label: 'Skip FFuf', type: 'bool', advanced: false }],
    subdomain_scan: [{ key: 'skip_ffuf', label: 'Skip FFuf', type: 'bool', advanced: false }],
    recon: [
      { key: 'threads', label: 'Threads', type: 'number', min: 1, max: 500, advanced: false },
    ],
    nuclei: [{ key: 'mode', label: 'Mode', type: 'select', options: ['full', 'cves', 'panels', 'default-logins', 'vulnerabilities'], advanced: false }],
    dns: [{ key: 'dns_type', label: 'DNS type', type: 'select', options: ['takeover', 'dangling-ip'], advanced: false }],
    dns_dangling: [{ key: 'dns_type', label: 'DNS type', type: 'select', options: ['dangling-ip', 'takeover'], advanced: false }],
    s3: [
      { key: 'region', label: 'Region (optional)', type: 'text', advanced: false },
      { key: 'threads', label: 'Threads (reserved)', type: 'number', min: 1, advanced: true },
    ],
    ffuf: [
      { key: 'threads', label: 'Threads', type: 'number', min: 1, advanced: false },
      { key: 'recursion', label: 'Enable recursion', type: 'bool', advanced: false },
      { key: 'recursion_depth', label: 'Recursion depth', type: 'number', min: 1, advanced: true },
      { key: 'bypass_403', label: 'Bypass 403 checks', type: 'bool', advanced: true },
      { key: 'extensions', label: 'Extensions (csv)', type: 'text', advanced: true },
      { key: 'wordlist', label: 'Wordlist path', type: 'text', advanced: true },
    ],
    zerodays: [
      { key: 'threads', label: 'Threads', type: 'number', min: 1, advanced: false },
      { key: 'dos_test', label: 'Enable DoS test', type: 'bool', advanced: true },
      { key: 'enable_source_exposure', label: 'Enable source exposure', type: 'bool', advanced: true },
      { key: 'silent', label: 'Silent mode', type: 'bool', advanced: true },
      { key: 'cves', label: 'CVEs (csv)', type: 'text', advanced: true },
      { key: 'mongodb_host', label: 'MongoDB host', type: 'text', advanced: true },
      { key: 'mongodb_port', label: 'MongoDB port', type: 'number', min: 1, advanced: true },
    ],
    jwt: [
      { key: 'skip_crack', label: 'Skip crack', type: 'bool', advanced: false },
      { key: 'skip_payloads', label: 'Skip payloads', type: 'bool', advanced: false },
      { key: 'wordlist_path', label: 'Wordlist path', type: 'text', advanced: true },
      { key: 'max_crack_attempts', label: 'Max crack attempts', type: 'number', min: 1, advanced: true },
    ],
    backup: [{ key: 'threads', label: 'Threads', type: 'number', min: 1, advanced: false }],
    misconfig: [
      { key: 'service_id', label: 'Service filter', type: 'text', advanced: false },
      { key: 'delay', label: 'Delay ms', type: 'number', min: 0, advanced: true },
      { key: 'permutations', label: 'Enable permutations', type: 'bool', advanced: true },
    ],
    apkx: [
      { key: 'mitm', label: 'MITM Analysis', type: 'bool', advanced: false },
      { key: 'platform', label: 'Platform', type: 'select', options: ['android', 'ios'], advanced: false },
      { key: 'skip_regex', label: 'Skip Secret Scan', type: 'bool', advanced: false },
    ],
  };

  function esc(s) {
    return window.esc(s);
  }

  function launchTypeSpec() {
    const sel = document.getElementById('launch-type');
    return sel ? LAUNCH_SCAN_TYPES[sel.value] : null;
  }

  function parseTargets(rawInput) {
    return String(rawInput || '')
      .split(/\r?\n|,/g)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  function normalizeGithubRepoInput(value) {
    const input = String(value || '').trim();
    if (!input) return '';
    const noProto = input.replace(/^https?:\/\//i, '').replace(/^www\./i, '');
    if (/^github\.com\//i.test(noProto)) {
      const parts = noProto.split('/').filter(Boolean);
      if (parts.length >= 3) {
        const owner = parts[1];
        const repo = parts[2].replace(/\.git$/i, '');
        return owner && repo ? `${owner}/${repo}` : '';
      }
    }
    return input.replace(/\.git$/i, '');
  }

  function normalizeGithubOrgInput(value) {
    const input = String(value || '').trim();
    if (!input) return '';
    const noProto = input.replace(/^https?:\/\//i, '').replace(/^www\./i, '');
    if (/^github\.com\//i.test(noProto)) {
      const parts = noProto.split('/').filter(Boolean);
      return parts[1] || '';
    }
    return input.replace(/^@/, '').split('/')[0].trim();
  }

  function buildScanRequestBodies(spec, mode, rawInput) {
    const values = parseTargets(rawInput);
    const bodies = [];
    const extras = spec.extra || {};

    for (const item of values) {
      const normalizedItem = spec.path === 'github_org'
        ? normalizeGithubOrgInput(item)
        : (spec.path === 'github' ? normalizeGithubRepoInput(item) : item);
      if (!normalizedItem) continue;
      const body = { ...extras };
      switch (mode) {
        case 'domain':
        case 'domain_list':
          body.domain = normalizedItem;
          break;
        case 'subdomain':
        case 'subdomain_list':
          body.subdomain = item;
          break;
        case 'url':
        case 'url_list':
        case 'target':
        case 'target_list':
          body.url = item;
          break;
        case 'repo':
        case 'repo_list':
          if (spec.path === 'github_org') body.domain = normalizeGithubOrgInput(normalizedItem);
          else body.repo = normalizedItem;
          break;
        case 'bucket':
        case 'bucket_list':
          body.bucket = item;
          break;
        case 'token':
          body.token = item;
          break;
        case 'file_path':
          body.file_path = item;
          break;
        case 'package_id':
          body.package_id = item;
          break;
        case 'upload':
          body.file_path = item;
          break;
        default:
          body.domain = normalizedItem;
          break;
      }
      bodies.push(body);
    }
    return bodies;
  }

  function syncLaunchPlaceholder(rebuildModes = false) {
    const modeSel = document.getElementById('launch-target-mode');
    const input = document.getElementById('launch-target');
    const listInput = document.getElementById('launch-target-list');
    const help = document.getElementById('launch-help');
    const spec = launchTypeSpec();
    if (!modeSel || !input || !listInput || !help || !spec) return;

    if (rebuildModes) {
      modeSel.innerHTML = (spec.modes || []).map((m) => `<option value="${esc(m)}">${esc(LAUNCH_MODE_LABELS[m] || m)}</option>`).join('');
      const preferred = modeSel.dataset.preferred || window.state?.scanLaunchUI?.targetMode || '';
      if (preferred && (spec.modes || []).includes(preferred)) modeSel.value = preferred;
    }
    if (!modeSel.value || !(spec.modes || []).includes(modeSel.value)) {
      modeSel.value = (spec.modes && spec.modes[0]) || 'domain';
    }

    const mode = modeSel.value;
    const isList = mode.endsWith('_list');
    const ph = (spec.placeholders && spec.placeholders[mode]) || 'Target';
    input.placeholder = ph;
    listInput.placeholder = ph;

    input.style.display = (isList || mode === 'upload') ? 'none' : '';
    listInput.style.display = isList ? '' : 'none';
    help.textContent = isList
      ? 'Bulk mode: one target per line (comma also supported).'
      : `Single target mode: ${LAUNCH_MODE_LABELS[mode] || mode}.`;
    if (document.getElementById('launch-type')?.value === 's3') {
      help.textContent += ' S3 scan probes unauthenticated LIST/READ/PUT/DELETE behavior and records exposed permissions.';
    }

    const uploadWrapperId = 'launch-upload-wrapper';
    let wrapper = document.getElementById(uploadWrapperId);
    if (mode === 'upload') {
      input.style.display = 'none';
      if (!wrapper) {
        input.insertAdjacentHTML('afterend', `
          <div id="${uploadWrapperId}" style="display:flex;gap:8px;align-items:center;flex:1">
            <input type="text" id="launch-upload-path" class="input" placeholder="No file uploaded" readonly style="flex:1">
            <button type="button" class="btn btn-ghost" onclick="document.getElementById('launch-file-input').click()">📁 Choose</button>
            <input type="file" id="launch-file-input" style="display:none" onchange="handleLaunchFileUpload(this)">
          </div>
        `);
      } else {
        wrapper.style.display = 'flex';
      }
    } else if (wrapper) {
      wrapper.style.display = 'none';
    }

    renderLaunchFlags();
    updateLaunchPreview();
  }

  function renderLaunchFlags() {
    const essential = document.getElementById('launch-flags-essential');
    const advanced = document.getElementById('launch-flags-advanced');
    const sel = document.getElementById('launch-type');
    if (!essential || !advanced || !sel) return;
    const defs = SCAN_FLAG_DEFS[sel.value] || [];
    essential.innerHTML = '';
    advanced.innerHTML = '';
    if (!defs.length) {
      essential.innerHTML = '<div style="font-size:12px;color:var(--text-muted)">No extra flags for this scan type.</div>';
      advanced.innerHTML = '<div style="font-size:12px;color:var(--text-muted)">No advanced flags.</div>';
      return;
    }
    defs.forEach((d) => {
      const target = d.advanced ? advanced : essential;
      const id = `flag-${d.key}`;
      let field = '';
      if (d.type === 'bool') {
        field = `<input id="${id}" data-flag-key="${esc(d.key)}" data-flag-type="bool" type="checkbox">`;
      } else if (d.type === 'select') {
        field = `<select id="${id}" data-flag-key="${esc(d.key)}" data-flag-type="select">${(d.options || []).map((v) => `<option value="${esc(v)}">${esc(v)}</option>`).join('')}</select>`;
      } else if (d.type === 'number') {
        field = `<input id="${id}" data-flag-key="${esc(d.key)}" data-flag-type="number" type="number" ${d.min != null ? `min="${d.min}"` : ''}>`;
      } else {
        field = `<input id="${id}" data-flag-key="${esc(d.key)}" data-flag-type="text" type="text">`;
      }
      target.insertAdjacentHTML('beforeend', `<div class="launch-flag-item"><label for="${id}">${esc(d.label)}</label>${field}</div>`);
    });

    if (sel.value === 'dns_dangling') {
      const dnsType = document.getElementById('flag-dns_type');
      if (dnsType) dnsType.value = 'dangling-ip';
    } else if (sel.value === 'dns') {
      const dnsType = document.getElementById('flag-dns_type');
      if (dnsType) dnsType.value = 'takeover';
    }
  }

  function collectFlagValues() {
    const out = {};
    document.querySelectorAll('[data-flag-key]').forEach((el) => {
      const key = el.getAttribute('data-flag-key');
      const typ = el.getAttribute('data-flag-type');
      if (!key) return;
      if (typ === 'bool') {
        if (el.checked) out[key] = true;
        return;
      }
      const val = (el.value || '').trim();
      if (!val) return;
      if (typ === 'number') {
        const n = Number(val);
        if (!Number.isNaN(n)) out[key] = n;
        return;
      }
      if (key === 'extensions' || key === 'cves') {
        out[key] = val.split(',').map((v) => v.trim()).filter(Boolean);
        return;
      }
      out[key] = val;
    });
    return out;
  }

  function updateLaunchPreview() {
    const pre = document.getElementById('launch-preview');
    if (!pre) return;
    const key = document.getElementById('launch-type')?.value;
    const mode = document.getElementById('launch-target-mode')?.value;
    const spec = key ? LAUNCH_SCAN_TYPES[key] : null;
    const singleInput = document.getElementById('launch-target');
    const listInput = document.getElementById('launch-target-list');
    if (!spec) {
      pre.textContent = '{}';
      return;
    }
    const raw = (mode && mode.endsWith('_list') ? listInput?.value : singleInput?.value || '').trim();
    if (window.state) {
      window.state.scanLaunchUI = window.state.scanLaunchUI || { scanType: 'recon', targetMode: 'domain', target: '', targetList: '' };
      window.state.scanLaunchUI.scanType = key || window.state.scanLaunchUI.scanType;
      window.state.scanLaunchUI.targetMode = mode || window.state.scanLaunchUI.targetMode;
      window.state.scanLaunchUI.target = singleInput?.value || '';
      window.state.scanLaunchUI.targetList = listInput?.value || '';
    }
    const bodies = raw ? buildScanRequestBodies(spec, mode, raw) : [];
    const flags = collectFlagValues();
    const previewBodies = bodies.slice(0, 2).map((b) => ({ ...b, ...flags }));
    pre.textContent = JSON.stringify({
      endpoint: `/scan/${spec.path}`,
      count: bodies.length || 1,
      sample_payloads: previewBodies.length ? previewBodies : [{ ...flags }],
    }, null, 2);
  }

  async function triggerScan() {
    const key = document.getElementById('launch-type').value;
    const mode = document.getElementById('launch-target-mode').value;
    const singleInput = document.getElementById('launch-target');
    const listInput = document.getElementById('launch-target-list');
    const spec = LAUNCH_SCAN_TYPES[key];
    const raw = (mode && mode.endsWith('_list') ? listInput.value : singleInput.value).trim();
    if (!spec) {
      window.showToast('error', 'Unknown scan type', 'Pick a scan from the list.');
      return;
    }
    if (!raw) {
      window.showToast('error', 'Input required', 'Enter the target for this scan type.');
      return;
    }

    const btn = document.getElementById('launch-btn');
    btn.disabled = true;
    const bodies = buildScanRequestBodies(spec, mode, raw);
    if (!bodies.length) {
      window.showToast('error', 'Input required', 'No valid targets parsed from input.');
      btn.disabled = false;
      return;
    }

    try {
      const scanIds = [];
      const failures = [];
      const flags = collectFlagValues();
      for (const body of bodies) {
        try {
          const result = await window.apiPost(`/scan/${spec.path}`, { ...body, ...flags });
          if (result && result.scan_id) scanIds.push(result.scan_id);
        } catch (e) {
          failures.push(e.message || 'failed');
        }
      }
      if (scanIds.length) {
        window.showToast('success', 'Scan started', `${scanIds.length} started${scanIds.length === 1 ? ` (ID: ${scanIds[0]})` : ''}`);
      }
      if (failures.length) {
        const firstError = failures[0] ? ` First error: ${failures[0]}` : '';
        window.showToast('error', 'Some launches failed', `${failures.length} failed.${firstError}`);
      }
      singleInput.value = '';
      listInput.value = '';
      window.loadStats();
      window.loadScans();
    } catch (e) {
      window.showToast('error', 'Failed to start scan', e.message);
    } finally {
      btn.disabled = false;
    }
  }

  async function handleLaunchFileUpload(inputEl) {
    const file = inputEl.files[0];
    if (!file) return;
    const pathDisplay = document.getElementById('launch-upload-path');
    const mainInput = document.getElementById('launch-target');
    if (pathDisplay) pathDisplay.value = `Uploading ${file.name}...`;

    const formData = new FormData();
    formData.append('file', file);

    try {
      const resp = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
        headers: window.state?._authAccessToken ? { Authorization: `Bearer ${window.state._authAccessToken}` } : {},
      });

      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.error || `Upload failed with status ${resp.status}`);
      }
      const data = await resp.json();
      if (pathDisplay) pathDisplay.value = file.name;
      if (mainInput) {
        mainInput.value = data.file_path;
        updateLaunchPreview();
      }
      window.showToast('success', 'Upload', `File uploaded to ${data.file_path}`);
    } catch (e) {
      if (pathDisplay) pathDisplay.value = 'Upload failed';
      window.showToast('error', 'Upload failed', e.message);
    }
  }

  window.LauncherPage = {
    syncLaunchPlaceholder,
    renderLaunchFlags,
    updateLaunchPreview,
    triggerScan,
    handleLaunchFileUpload,
  };
})();

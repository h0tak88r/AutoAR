(() => {
  const LAUNCH_SCAN_TYPES = {
    domain_scan: { path: 'domain_run', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
    subdomain_scan: { path: 'subdomain_run', modes: ['subdomain', 'subdomain_list'], placeholders: { subdomain: 'api.example.com', subdomain_list: 'one subdomain per line' } },
    asr: { path: 'asr', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
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
    s3: { path: 's3', modes: ['bucket', 'bucket_list', 'domain', 'domain_list'], placeholders: { bucket: 'bucket-name', bucket_list: 'one bucket per line', domain: 'example.com', domain_list: 'one domain per line' } },
    github: { path: 'github', modes: ['repo', 'repo_list'], placeholders: { repo: 'owner/repository or github.com/owner/repo', repo_list: 'one owner/repo per line' } },
    github_org: { path: 'github_org', modes: ['domain', 'domain_list'], placeholders: { domain: 'org-name or github.com/org', domain_list: 'one org per line' } },
    zerodays: { path: 'zerodays', modes: ['domain', 'domain_list'], placeholders: { domain: 'example.com', domain_list: 'one domain per line' } },
    ffuf: { path: 'ffuf', modes: ['target', 'target_list'], placeholders: { target: 'https://example.com/FUZZ', target_list: 'one FUZZ URL per line' } },
  };

  const LAUNCH_MODE_LABELS = {
    domain: 'Domain',
    subdomain: 'Subdomain',
    url: 'URL',
    target: 'Target URL',
    repo: 'Repository',
    bucket: 'Bucket',
    domain_list: 'Domain list',
    subdomain_list: 'Subdomain list',
    url_list: 'URL list',
    target_list: 'Target list',
    repo_list: 'Repo/Org list',
    bucket_list: 'Bucket list',
  };

  // Flag definitions. `default` is shown (as a select/bool value, or as a
  // "default: X" placeholder for number/text so an empty field uses the server
  // default). `help` renders as a tooltip + a one-line hint under the field.
  const SCAN_FLAG_DEFS = {
    domain_scan: [{ key: 'skip_ffuf', label: 'Skip FFuf', type: 'bool', advanced: false, help: 'Skip the directory-fuzzing phase to finish faster.' }],
    subdomain_scan: [{ key: 'skip_ffuf', label: 'Skip FFuf', type: 'bool', advanced: false, help: 'Skip the directory-fuzzing phase to finish faster.' }],
    asr: [
      { key: 'mode', label: 'ASR Mode', type: 'select', options: ['5', '4', '3', '2', '1'], default: '5', advanced: false, help: '5 = deepest (passive + brute + permute + resolve); 1 = fastest/lightest.' },
      { key: 'threads', label: 'Threads', type: 'number', min: 1, default: 50, advanced: true, help: 'Concurrent DNS/HTTP workers.' },
      { key: 'resolvers', label: 'Resolvers file path', type: 'text', advanced: true, help: 'Path to a custom DNS resolvers list on the server (optional).' },
    ],
    recon: [
      { key: 'threads', label: 'Threads', type: 'number', min: 1, max: 500, default: 100, advanced: false, help: 'Concurrency for subdomain enumeration.' },
    ],
    nuclei: [{ key: 'mode', label: 'Mode', type: 'select', options: ['full', 'cves', 'panels', 'default-logins', 'vulnerabilities'], default: 'full', advanced: false, help: 'Which template set to run. Runs recon first automatically if live hosts are missing.' }],
    dns: [{ key: 'dns_type', label: 'DNS type', type: 'select', options: ['takeover', 'dangling-ip'], default: 'takeover', advanced: false, help: 'takeover = CNAME/NS takeover checks; dangling-ip = dangling A-record checks.' }],
    dns_dangling: [{ key: 'dns_type', label: 'DNS type', type: 'select', options: ['dangling-ip', 'takeover'], default: 'dangling-ip', advanced: false, help: 'dangling-ip = dangling A-record checks.' }],
    s3: [
      { key: 'region', label: 'Region (optional)', type: 'text', advanced: false, help: 'AWS region for the bucket, e.g. us-east-1. Leave empty to auto-detect.' },
      { key: 'threads', label: 'Threads (reserved)', type: 'number', min: 1, advanced: true, help: 'Reserved for future concurrent bucket probing.' },
    ],
    ffuf: [
      { key: 'threads', label: 'Threads', type: 'number', min: 1, default: 40, advanced: false, help: 'Concurrent fuzzing requests.' },
      { key: 'recursion', label: 'Enable recursion', type: 'bool', advanced: false, help: 'Recurse into discovered directories.' },
      { key: 'recursion_depth', label: 'Recursion depth', type: 'number', min: 1, default: 1, advanced: true, help: 'Max recursion depth when recursion is enabled.' },
      { key: 'bypass_403', label: 'Bypass 403 checks', type: 'bool', advanced: true, help: 'Try header/path tricks to bypass 403 responses on hits.' },
      { key: 'extensions', label: 'Extensions (csv)', type: 'text', advanced: true, help: 'Comma-separated, e.g. php,bak,zip,json.' },
      { key: 'wordlist', label: 'Wordlist path', type: 'text', advanced: true, help: 'Server-side wordlist path. Empty = built-in quick_fuzz list.' },
    ],
    zerodays: [
      { key: 'threads', label: 'Threads', type: 'number', min: 1, default: 20, advanced: false, help: 'Concurrent CVE probes.' },
      { key: 'dos_test', label: 'Enable DoS test', type: 'bool', advanced: true, help: 'Includes DoS checks — only run on assets you own / have permission to disrupt.' },
      { key: 'enable_source_exposure', label: 'Enable source exposure', type: 'bool', advanced: true, help: 'Probe React2Shell source-map / source exposure.' },
      { key: 'silent', label: 'Silent mode', type: 'bool', advanced: true, help: 'Only emit confirmed-vulnerable hosts.' },
      { key: 'cves', label: 'CVEs (csv)', type: 'text', advanced: true, help: 'Limit to specific CVE IDs, comma-separated. Empty = all supported.' },
      { key: 'mongodb_host', label: 'MongoDB host', type: 'text', advanced: true, help: 'Target host for the MongoDB CVE-2025-14847 check.' },
      { key: 'mongodb_port', label: 'MongoDB port', type: 'number', min: 1, default: 27017, advanced: true, help: 'MongoDB port (default 27017).' },
    ],
    backup: [{ key: 'threads', label: 'Threads', type: 'number', min: 1, default: 20, advanced: false, help: 'Concurrent backup-file probes.' }],
    misconfig: [
      { key: 'service_id', label: 'Service filter', type: 'text', advanced: false, help: 'Limit to one service id (e.g. jenkins). Empty = all 100+ checks.' },
      { key: 'delay', label: 'Delay ms', type: 'number', min: 0, default: 0, advanced: true, help: 'Delay between requests in milliseconds.' },
      { key: 'permutations', label: 'Enable permutations', type: 'bool', advanced: true, help: 'Also test path permutations per service.' },
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
          // Some endpoints (e.g. /scan/backup) intentionally accept only "domain"
          // but can still operate on a single subdomain value.
          if (spec.path === 'backup' || spec.path === 'tech' || spec.path === 'ports' || spec.path === 'gf' || spec.path === 'misconfig' || spec.path === 'recon' || spec.path === 'domain_run') {
            body.domain = item;
          } else {
            body.subdomain = item;
          }
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
      const s3Mode = modeSel.value;
      if (s3Mode === 'domain' || s3Mode === 'domain_list') {
        help.textContent += ' Domain mode: enumerates potential bucket names from the domain, then scans each discovered bucket for public access.';
      } else {
        help.textContent += ' S3 scan probes unauthenticated LIST/READ/PUT/DELETE behavior and records exposed permissions.';
      }
    }

    const uploadWrapperId = 'launch-upload-wrapper';
    let wrapper = document.getElementById(uploadWrapperId);
    if (mode === 'upload') {
      input.style.display = 'none';
      if (!wrapper) {
        input.insertAdjacentHTML('afterend', `
          <div id="${uploadWrapperId}" style="display:flex;gap:8px;align-items:center;flex:1">
            <input type="text" id="launch-upload-path" class="input" placeholder="No file uploaded" readonly style="flex:1">
            <button type="button" class="btn btn-ghost" onclick="document.getElementById('launch-file-input').click()"> Choose</button>
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
      const titleAttr = d.help ? ` title="${esc(d.help)}"` : '';
      const ph = d.default != null ? ` placeholder="default: ${esc(String(d.default))}"` : '';
      let field = '';
      if (d.type === 'bool') {
        field = `<input id="${id}" data-flag-key="${esc(d.key)}" data-flag-type="bool" type="checkbox"${d.default === true ? ' checked' : ''}>`;
      } else if (d.type === 'select') {
        field = `<select id="${id}" data-flag-key="${esc(d.key)}" data-flag-type="select">${(d.options || []).map((v) => `<option value="${esc(v)}"${String(d.default) === String(v) ? ' selected' : ''}>${esc(v)}</option>`).join('')}</select>`;
      } else if (d.type === 'number') {
        field = `<input id="${id}" data-flag-key="${esc(d.key)}" data-flag-type="number" type="number" ${d.min != null ? `min="${d.min}"` : ''}${ph}>`;
      } else {
        field = `<input id="${id}" data-flag-key="${esc(d.key)}" data-flag-type="text" type="text"${ph}>`;
      }
      const helpLine = d.help ? `<div class="launch-flag-help" style="font-size:10px;color:var(--text-muted);line-height:1.3;margin-top:2px">${esc(d.help)}</div>` : '';
      target.insertAdjacentHTML('beforeend', `<div class="launch-flag-item"><label for="${id}"${titleAttr}>${esc(d.label)}</label>${field}${helpLine}</div>`);
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
    const statusEl = document.getElementById('launch-status');
    const setStatus = (txt, color) => {
      // Persist the message so the final summary survives the loadScans()
      // re-render that rebuilds the launcher DOM (renderScans restores it once).
      window.state = window.state || {};
      window.state.scanLaunchUI = window.state.scanLaunchUI || {};
      window.state.scanLaunchUI._launchStatus = txt ? { text: txt, color: color || 'var(--text-muted)' } : null;
      if (!statusEl) return;
      statusEl.textContent = txt;
      statusEl.style.color = color || 'var(--text-muted)';
      statusEl.style.display = txt ? '' : 'none';
    };
    btn.disabled = true;
    const bodies = buildScanRequestBodies(spec, mode, raw);
    if (!bodies.length) {
      window.showToast('error', 'Input required', 'No valid targets parsed from input.');
      btn.disabled = false;
      return;
    }

    const bodyLabel = (b) => b.domain || b.subdomain || b.url || b.repo || b.bucket || '(target)';
    const total = bodies.length;

    try {
      const scanIds = [];
      const failures = []; // { target, error }
      const flags = collectFlagValues();
      for (let i = 0; i < bodies.length; i++) {
        const body = bodies[i];
        const label = bodyLabel(body);
        if (total > 1) setStatus(`Launching ${i + 1}/${total}…  ${label}`, 'var(--accent-cyan)');
        try {
          const result = await window.apiPost(`/scan/${spec.path}`, { ...body, ...flags });
          if (result && result.scan_id) scanIds.push(result.scan_id);
          else failures.push({ target: label, error: 'no scan_id returned' });
        } catch (e) {
          failures.push({ target: label, error: e.message || 'failed' });
        }
      }

      const failList = failures.slice(0, 5).map((f) => `${f.target}: ${f.error}`).join('\n');
      const moreFails = failures.length > 5 ? `\n…and ${failures.length - 5} more` : '';

      if (scanIds.length && !failures.length) {
        setStatus(`Started ${scanIds.length} scan${scanIds.length > 1 ? 's' : ''}.`, 'var(--accent-emerald)');
        window.showToast('success', 'Scan started', `${scanIds.length} started${scanIds.length === 1 ? ` (ID: ${scanIds[0]})` : ''}`);
      } else if (scanIds.length && failures.length) {
        setStatus(`${scanIds.length} started · ${failures.length} failed (failed targets kept below to retry).`, '#f59e0b');
        window.showToast('error', `${failures.length} of ${total} failed`, failList + moreFails);
      } else {
        setStatus(`All ${total} launch${total > 1 ? 'es' : ''} failed.`, 'var(--accent-red)');
        window.showToast('error', 'All launches failed', failList || 'No scans started.');
      }

      // Clear on full success; on partial failure keep just the failed targets
      // in the bulk box so the user can fix + relaunch them.
      if (!failures.length) {
        singleInput.value = '';
        listInput.value = '';
      } else if (mode.endsWith('_list')) {
        listInput.value = failures.map((f) => f.target).join('\n');
      }
      updateLaunchPreview();
      window.loadStats();
      window.loadScans();
    } catch (e) {
      setStatus('', '');
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

  // launcherKeyForScanType maps a stored scan_type (the backend path, possibly
  // with a mode suffix like "nuclei-full") back to a Quick-Launcher type key.
  // Keys that actually have an <option> in the Quick Launcher select
  // (kept in sync with scans-page.js renderScans). A clone must resolve to one
  // of these, otherwise the <select> silently falls back to its first option.
  const LAUNCH_DROPDOWN_KEYS = new Set([
    'recon', 'domain_scan', 'subdomain_scan', 'asr', 'urls', 'tech', 'nuclei', 'ports',
    'dns', 'dns_dangling', 'dns_cf1016', 's3', 'github', 'github_org', 'js', 'reflection',
    'gf', 'backup', 'misconfig', 'zerodays', 'ffuf',
  ]);

  function launcherKeyForScanType(scanType) {
    const st = String(scanType || '').toLowerCase().trim();
    if (!st) return '';
    const aliases = {
      domain_run: 'domain_scan',
      subdomain_run: 'subdomain_scan',
      github_scan: 'github',
      'dns-takeover': 'dns', // dropdown "dns (takeover)" runs the same takeover scan
      'dns-cf1016': 'dns_cf1016',
      'dns-dangling-ip': 'dns_dangling',
    };
    let key = '';
    if (aliases[st]) key = aliases[st];
    else if (st.startsWith('nuclei')) key = 'nuclei'; // nuclei-full, nuclei-cves, …
    else if (LAUNCH_DROPDOWN_KEYS.has(st)) key = st;
    else {
      for (const [k, spec] of Object.entries(LAUNCH_SCAN_TYPES)) {
        if (spec.path === st) { key = k; break; }
      }
    }
    // Only return a key the dropdown can actually select; otherwise '' so the
    // caller fills the target and prompts the user to pick a type.
    return LAUNCH_DROPDOWN_KEYS.has(key) ? key : '';
  }

  // cloneScanToLauncher prefills the Quick Scan Launcher from a past scan so the
  // user can tweak type/mode/flags before relaunching (unlike Rescan, which
  // re-runs the exact same command). Original flags aren't persisted, so only
  // type + target are restored.
  function cloneScanToLauncher(scanType, target) {
    const key = launcherKeyForScanType(scanType);
    const spec = key ? LAUNCH_SCAN_TYPES[key] : null;
    const tgt = String(target || '').trim();
    window.state = window.state || {};
    window.state.scanLaunchUI = window.state.scanLaunchUI || {};
    const lui = window.state.scanLaunchUI;
    if (spec) {
      lui.scanType = key;
      lui.targetMode = (spec.modes && spec.modes[0]) || 'domain';
    }
    lui.target = tgt;
    lui.targetList = '';
    // renderScans focuses + scrolls the launcher after it (re)renders, which is
    // robust to the async loadScans fetch (a fixed setTimeout would race it).
    lui._pendingCloneFocus = true;
    if (typeof window.navigateTo === 'function') window.navigateTo('scans');
    if (spec) {
      window.showToast && window.showToast('info', 'Cloned to launcher', `${key} → ${tgt} — adjust flags/mode, then Launch.`);
    } else {
      window.showToast && window.showToast('info', 'Pick a scan type', `Target filled in — choose a scan type, then Launch (original type "${scanType}" isn't a standalone launcher option).`);
    }
  }

  window.cloneScanToLauncher = cloneScanToLauncher;

  window.LauncherPage = {
    syncLaunchPlaceholder,
    renderLaunchFlags,
    updateLaunchPreview,
    triggerScan,
    handleLaunchFileUpload,
    cloneScanToLauncher,
  };
})();

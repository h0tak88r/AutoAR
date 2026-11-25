(() => {
 // ── New Scan wizard: pick a card, configure, launch ──────────────────
 // Covers every launchable scan family: the /api/* runners (discover,
 // fleet nuclei, pipeline, ports, verifiers) and the classic /scan/*
 // per-domain modules from the old launcher.
 const esc = (v) =>
 window.esc ? window.esc(v) : String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

 // cat: section header in the picker. endpoint: '' = /api runner with a
 // custom payload in launch(); otherwise the /scan/<endpoint> module.
 const TYPES = [
 // ── Asset discovery ──
 { id: 'discover', cat: 'Asset discovery', title: 'Discover Assets', accent: '#3291ff', badge: 'per-root',
 blurb: 'Passive subdomain enumeration + liveness for one root. Counts how many assets are NEW.' },
 { id: 'recon', cat: 'Asset discovery', title: 'Unified Recon', accent: '#38bdf8', badge: 'per-domain',
 blurb: 'Subdomains + live hosts + tech + CNAMEs in one pass for a domain.' },
 { id: 'pipeline', cat: 'Asset discovery', title: 'Root Pipeline', accent: '#10b981', badge: 'multi-root',
 blurb: 'Enumerate roots, hosts, optional nuclei. Collect-only mode just fills the asset DB.' },
 { id: 'ports', cat: 'Asset discovery', title: 'Port Surface', accent: '#22d3ee', badge: 'corpus',
 blurb: 'naabu top-100 ports over every live host (or one root) — unlocks appliance/gateway CVEs.' },
 { id: 'php2shell', cat: 'Vulnerabilities', title: 'php2shell (CVE-2026-109618/19)', accent: '#ef4444', badge: 'corpus',
 blurb: 'PHP version + presence + session-injection primitive scan for CVE-2026-109618/109619. PHP-only mode probes just the fingerprinted PHP hosts (fast — wins the dup race); clear it for the whole corpus. Creates findings rows for vulnerable hosts.' },
 // ── Subdomain intel ──
 { id: 'subdomains', cat: 'Subdomain intel', title: 'Subdomain Enumeration', accent: '#a78bfa', badge: 'per-domain',
 blurb: 'Passive sources only (no workflow) — fast asset list for a domain.' },
 { id: 'livehosts', cat: 'Subdomain intel', title: 'Live Hosts', accent: '#34d399', badge: 'per-domain',
 blurb: 'httpx liveness filter over a domain known subdomains.' },
 { id: 'cnames', cat: 'Subdomain intel', title: 'CNAME Records', accent: '#fbbf24', badge: 'per-domain',
 blurb: 'Collect CNAMEs — dangling/third-party takeover leads.' },
 { id: 'dns-takeover', cat: 'Subdomain intel', title: 'DNS Takeover', accent: '#f87171', badge: 'per-domain',
 blurb: 'Check a domain subdomains for takeover-able DNS records.' },
 { id: 'dns', cat: 'Subdomain intel', title: 'DNS (unified)', accent: '#a3e635', badge: 'per-domain',
 blurb: 'Unified DNS scan: takeover + dangling-IP checks.' },
 // ── Content & params ──
 { id: 'urls', cat: 'Content & params', title: 'URL Collection', accent: '#60a5fa', badge: 'per-domain',
 blurb: 'Wayback/common-crawl/alpha queue URL harvesting for a domain.' },
 { id: 'js', cat: 'Content & params', title: 'Client-side Scan', accent: '#c084fc', badge: 'domain or host',
 blurb: 'Pull the JS and flag secrets plus DOM XSS, postMessage, open-redirect and prototype-pollution sinks. A host scans only that app.' },
 { id: 'js-endpoints', cat: 'Content & params', title: 'JS Endpoints', accent: '#d8b4fe', badge: 'per-domain',
 blurb: 'Extract API endpoints/paths from a domain JavaScript.' },
 { id: 'reflection', cat: 'Content & params', title: 'Reflection Params', accent: '#f472b6', badge: 'per-domain',
 blurb: 'Probe a domain URLs for reflected parameters (XSS leads).' },
 { id: 'gf', cat: 'Content & params', title: 'GF Patterns', accent: '#fb923c', badge: 'per-domain',
 blurb: 'Tag a domain URLs with gf patterns (xss/ssrf/sqli/...).' },
 { id: 'tech', cat: 'Content & params', title: 'Tech Detect', accent: '#2dd4bf', badge: 'per-domain',
 blurb: 'Fingerprint technologies on a domain live hosts.' },
 { id: 'backup', cat: 'Content & params', title: 'Backup Files', accent: '#facc15', badge: 'per-domain',
 blurb: 'Hunt backup/archive files (.zip, .sql, .bak) on a domain.' },
 { id: 'ffuf', cat: 'Content & params', title: 'FFuf Fuzzing', accent: '#f97316', badge: 'per-target',
 blurb: 'Content discovery against one URL (wordlist, recursion, 403 bypass).' },
 // ── Vulnerabilities ──
 { id: 'nuclei', cat: 'Vulnerabilities', title: 'Nuclei Template', accent: '#a855f7', badge: 'targeted',
 blurb: 'One template (path/ID or raw YAML) against every live host in the database.' },
 { id: 'nuclei-domain', cat: 'Vulnerabilities', title: 'Nuclei (domain)', accent: '#9333ea', badge: 'per-domain',
 blurb: 'Full nuclei suite over one domain — mode picks the template set.' },
 { id: 'zerodays', cat: 'Vulnerabilities', title: 'Zerodays', accent: '#ef4444', badge: 'per-domain',
 blurb: 'React2Shell / MongoDB exposed / WP zeroday checks for a domain.' },
 { id: 'misconfig', cat: 'Vulnerabilities', title: 'Cloud Misconfig', accent: '#f59e0b', badge: 'per-domain',
 blurb: 'Cloud misconfiguration scan across a domain assets.' },
 { id: 'asr', cat: 'Vulnerabilities', title: 'ASR', accent: '#fb7185', badge: 'per-domain',
 blurb: 'Attack Surface Reduction sweep (mode 0/1/2) for a domain.' },
 { id: 'mcp-discovery', cat: 'Vulnerabilities', title: 'MCP Discovery', accent: '#4ade80', badge: 'per-domain',
 blurb: 'Find exposed MCP (Model Context Protocol) endpoints on a domain.' },
 { id: 'smarty', cat: 'Vulnerabilities', title: 'Smarty Verifier', accent: '#f59e0b', badge: 'verifier',
 blurb: 'CVE-2026-82531 cache-poisoning verifier (computed-output, benign). Blank hosts = full corpus.' },
 { id: 'zammad', cat: 'Vulnerabilities', title: 'Zammad Verifier', accent: '#ef4444', badge: 'verifier',
 blurb: 'CVE-2026-102489 WebSocket session-disclosure probe. Blank hosts = full corpus.' },
 // ── Cloud & code ──
 { id: 'firebase', cat: 'Cloud & code', title: 'Firebase', accent: '#fbbf24', badge: 'per-domain',
 blurb: 'Firebase misconfiguration exposure (open DB/rules) for a domain.' },
 { id: 's3', cat: 'Cloud & code', title: 'S3 Bucket', accent: '#38bdf8', badge: 'per-bucket',
 blurb: 'Probe one bucket name/region for open access.' },
 { id: 'github', cat: 'Cloud & code', title: 'GitHub Repo', accent: '#e2e8f0', badge: 'per-repo',
 blurb: 'Hunt secrets/keys in one GitHub repository.' },
 // ── Workflows ──
 { id: 'domain_run', cat: 'Workflows', title: 'Domain Workflow', accent: '#10b981', badge: 'heavy',
 blurb: 'The full per-domain pipeline: subs, hosts, URLs, JS, nuclei. Skip FFuf to run lean.' },
 { id: 'subdomain_run', cat: 'Workflows', title: 'Subdomain Workflow', accent: '#14b8a6', badge: 'heavy',
 blurb: 'Full workflow scoped to one subdomain. Skip FFuf to run lean.' },
 ];

 function cardHTML(t, i) {
 return `<button type="button" class="wiz-type-card" data-wiz-type="${t.id}" style="--wiz-i:${i};text-align:left;display:flex;flex-direction:column;gap:8px;padding:16px;border-radius:12px;cursor:pointer;background:var(--bg-raise);border:1px solid var(--border);transition:transform 150ms ease-out,border-color 150ms ease-out,background-color 150ms ease-out"
 onmouseover="this.style.borderColor='${t.accent}66';this.style.background='var(--bg-raise)';this.style.transform='translateY(-2px)'"
 onmouseout="this.style.borderColor='var(--border)';this.style.background='var(--bg-raise)';this.style.transform='none'">
 <div style="display:flex;align-items:center;justify-content:space-between">
 <span style="font-size:13px;font-weight:800;letter-spacing:.3px;color:${t.accent}">${esc(t.title)}</span>
 <span style="font-size:10px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;color:${t.accent};border:1px solid ${t.accent}44;border-radius:6px;padding:2px 8px">${t.badge}</span>
 </div>
 <div style="font-size:11.5px;line-height:1.5;color:var(--text-secondary)">${esc(t.blurb)}</div>
 </button>`;
 }

 const input = (id, ph, extra) =>
 `<input id="${id}" class="search-input auth-input" placeholder="${esc(ph)}" style="margin-bottom:10px;${extra || ''}" />`;
 const area = (id, ph, extra) =>
 `<textarea id="${id}" class="search-input auth-input" placeholder="${esc(ph)}" style="min-height:120px;font-family:'JetBrains Mono',monospace;font-size:12px;margin-bottom:10px;resize:vertical;${extra || ''}"></textarea>`;
 const check = (id, label, checked) =>
 `<label style="display:flex;align-items:center;gap:8px;font-size:12.5px;margin-bottom:10px;cursor:pointer"><input type="checkbox" id="${id}" ${checked ? 'checked' : ''} /> ${esc(label)}</label>`;
 const select = (id, opts, extra) =>
 `<select id="${id}" class="search-input auth-input" style="margin-bottom:10px;${extra || ''}">${opts.map((o) => `<option value="${esc(o[0])}">${esc(o[1])}</option>`).join('')}</select>`;

 const NUCLEI_MODES = [['full', 'full — all templates'], ['cves', 'cves — CVE templates'], ['panels', 'panels — login panels'], ['default-logins', 'default-logins'], ['vulnerabilities', 'vulnerabilities (non-CVE)']];

 // Forms. Generic per-domain form first, specialized ones after.
 const domainForm = () => input('wiz-domain', 'Domain (e.g. example.com)');

 const FORMS = {
 discover: () => input('wiz-root', 'Root domain (e.g. example.com)'),
 recon: domainForm,
 subdomains: domainForm,
 livehosts: domainForm,
 cnames: domainForm,
 'dns-takeover': domainForm,
 dns: domainForm,
 urls: domainForm,
 js: domainForm,
 'js-endpoints': domainForm,
 reflection: domainForm,
 gf: domainForm,
 tech: domainForm,
 backup: domainForm,
 'mcp-discovery': domainForm,
 misconfig: domainForm,
 firebase: domainForm,
 zerodays: domainForm,
 asr: () => domainForm() + select('wiz-mode', [['2', 'mode 2 (default)'], ['0', 'mode 0'], ['1', 'mode 1']], 'width:180px'),
 'nuclei-domain': () => domainForm() + select('wiz-mode', NUCLEI_MODES, 'width:260px'),
 s3: () => input('wiz-bucket', 'Bucket name (without s3://)') + input('wiz-region', 'Region (default us-east-1)'),
 github: () => input('wiz-repo', 'Repository (owner/name)'),
 ffuf: () =>
 input('wiz-target', 'Target URL (e.g. https://example.com/FUZZ)') +
 input('wiz-wordlist', 'Wordlist path (blank = default)') +
 input('wiz-threads', 'Threads (default 40)', 'width:140px') +
 check('wiz-recursion', 'Recursion') +
 check('wiz-bypass403', 'Try 403 bypass'),
 'domain_run': () => input('wiz-domain', 'Domain (e.g. example.com)') + check('wiz-skipffuf', 'Skip FFuf phase', true),
 'subdomain_run': () => input('wiz-subdomain', 'Subdomain (e.g. app.example.com)') + check('wiz-skipffuf', 'Skip FFuf phase', true),
 // /api runners keep their original forms
 nuclei: () => area('wiz-template', 'Template path/ID\n\n-- or raw YAML --\n\nid: my-template\ninfo:\n name: ...') +
 check('wiz-nuclei-targeted', 'Fingerprint-targeted — only hosts matching the template\u2019s tech tags (fast; uncheck to sweep every host)', true),
 pipeline: () =>
 input('wiz-threads', 'Threads (default 30)', 'width:140px') +
 input('wiz-maxroots', 'Max roots (0 = all)', 'width:140px') +
 check('wiz-newonly', 'New roots only (skip roots that already have subdomains)', true) +
 check('wiz-collectonly', 'Collect only (no nuclei — just fill assets)') +
 area('wiz-template', 'Optional nuclei template (blank = default)'),
 smarty: () =>
 area('wiz-hosts', 'Hosts, one per line (blank = ALL live hosts)') +
 input('wiz-params', 'Custom param names (comma-separated, optional)'),
 zammad: () => area('wiz-hosts', 'Hosts, one per line (blank = ALL live hosts)'),
 ports: () => input('wiz-root', 'Root domain (optional — blank = ALL live hosts)'),
 php2shell: () => input('wiz-root', 'Root domain (optional — blank = ALL live hosts)') +
 check('wiz-php-only', 'PHP-fingerprinted hosts only (fast — recommended for the dup race)', true),
 };

 let current = null;

 function openWizard() {
 current = null;
 renderPick();
 document.getElementById('launch-wizard-modal').style.display = 'flex';
 }
 function closeWizard() {
 document.getElementById('launch-wizard-modal').style.display = 'none';
 }

 function renderPick() {
 const body = document.getElementById('wiz-body');
 const cats = [];
 for (const t of TYPES) {
 let c = cats.find((x) => x.name === t.cat);
 if (!c) { c = { name: t.cat, items: [] }; cats.push(c); }
 c.items.push(t);
 }
 let idx = 0;
 body.innerHTML = `<div style="font-size:12px;color:var(--text-muted);margin-bottom:14px">What do you want to run?</div>` +
 cats.map((c) => `<div style="font-size:10.5px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:var(--text-muted);margin:14px 0 8px">${esc(c.name)}</div>
 <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:12px">${c.items.map((t) => cardHTML(t, idx++)).join('')}</div>`).join('');
 body.querySelectorAll('[data-wiz-type]').forEach((el) => {
 el.addEventListener('click', () => selectType(el.getAttribute('data-wiz-type')));
 });
 document.getElementById('wiz-back').style.visibility = 'hidden';
 document.getElementById('wiz-launch').style.display = 'none';
 }

 function selectType(id) {
 current = TYPES.find((t) => t.id === id);
 const body = document.getElementById('wiz-body');
 body.innerHTML = `<div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
 <span style="font-size:13px;font-weight:800;color:${current.accent}">${esc(current.title)}</span>
 <span style="font-size:10px;font-weight:700;text-transform:uppercase;color:${current.accent};border:1px solid ${current.accent}44;border-radius:6px;padding:1px 8px">${current.badge}</span>
 </div>
 <div style="font-size:11.5px;color:var(--text-muted);margin-bottom:14px">${esc(current.blurb)}</div>${FORMS[id]()}${window.ScanMeta ? window.ScanMeta.launchMetaFields('wiz') : ''}`;
 document.getElementById('wiz-back').style.visibility = 'visible';
 document.getElementById('wiz-launch').style.display = 'inline-flex';
 }

 const val = (id) => (document.getElementById(id)?.value || '').trim();
 const list = (id) => val(id) ? val(id).split(/\n+/).map((l) => l.trim()).filter(Boolean) : undefined;
 const num = (id) => { const v = parseInt(val(id), 10); return Number.isFinite(v) ? v : undefined; };
 const chk = (id) => !!document.getElementById(id)?.checked;

 async function launch() {
 if (!current) return;
 // Title + description apply to every scan type: endpoints that take a name
 // get it in the payload, and both are PATCHed onto the new scan afterwards.
 const meta = window.ScanMeta ? window.ScanMeta.readLaunchMeta('wiz') : { name: '', description: '' };
 const name = meta.name || undefined;
 let payload = {}, endpoint = '';
 const domain = val('wiz-domain');
 try {
 // /scan/* classic modules: payload is just the target field(s).
 const simple = {
 recon: ['recon', 'domain'], subdomains: ['subdomains', 'domain'], livehosts: ['livehosts', 'domain'],
 cnames: ['cnames', 'domain'], 'dns-takeover': ['dns-takeover', 'domain'], dns: ['dns', 'domain'],
 urls: ['urls', 'domain'], js: ['js', 'domain'], 'js-endpoints': ['js-endpoints', 'domain'],
 reflection: ['reflection', 'domain'], gf: ['gf', 'domain'], tech: ['tech', 'domain'],
 backup: ['backup', 'domain'], 'mcp-discovery': ['mcp-discovery', 'domain'],
 misconfig: ['misconfig', 'domain'], firebase: ['firebase', 'domain'], zerodays: ['zerodays', 'domain'],
 };
 switch (current.id) {
 case 'discover':
 if (!val('wiz-root')) throw new Error('Root domain is required');
 endpoint = '/api/subdomains/discover';
 payload = { root: val('wiz-root'), name };
 break;
 case 'nuclei':
 if (!val('wiz-template')) throw new Error('Template is required');
 endpoint = '/api/subdomains/nuclei/run';
 payload = { template: val('wiz-template'), name, targeted: chk('wiz-nuclei-targeted') };
 break;
 case 'pipeline':
 endpoint = '/api/pipeline/root-scan';
 payload = {
 name,
 threads: num('wiz-threads'),
 max_roots: num('wiz-maxroots'),
 new_roots_only: chk('wiz-newonly'),
 collect_only: chk('wiz-collectonly'),
 template: val('wiz-template') || undefined,
 };
 break;
 case 'smarty':
 endpoint = '/api/smarty/run';
 payload = { hosts: list('wiz-hosts'), params: val('wiz-params') ? val('wiz-params').split(',').map((s) => s.trim()).filter(Boolean) : undefined, name };
 break;
 case 'ports':
 endpoint = '/api/ports/run';
 payload = { root: val('wiz-root') || undefined, name };
 break;
 case 'php2shell':
 endpoint = '/api/scan/php2shell/run';
 payload = { root: val('wiz-root') || undefined, name, php_only: chk('wiz-php-only') };
 break;
 case 'zammad':
 endpoint = '/api/zammad/run';
 payload = { hosts: list('wiz-hosts'), name };
 break;
 case 'nuclei-domain':
 if (!domain) throw new Error('Domain is required');
 endpoint = '/scan/nuclei';
 payload = { domain, mode: val('wiz-mode') || 'full' };
 break;
 case 'asr':
 if (!domain) throw new Error('Domain is required');
 endpoint = '/scan/asr';
 payload = { domain, mode: val('wiz-mode') || '2' };
 break;
 case 's3':
 if (!val('wiz-bucket')) throw new Error('Bucket name is required');
 endpoint = '/scan/s3';
 payload = { bucket: val('wiz-bucket'), region: val('wiz-region') || undefined };
 break;
 case 'github':
 if (!val('wiz-repo')) throw new Error('Repository is required');
 endpoint = '/scan/github';
 payload = { repo: val('wiz-repo') };
 break;
 case 'ffuf':
 if (!val('wiz-target')) throw new Error('Target URL is required');
 endpoint = '/scan/ffuf';
 payload = {
 target: val('wiz-target'),
 wordlist: val('wiz-wordlist') || undefined,
 threads: num('wiz-threads'),
 recursion: chk('wiz-recursion') || undefined,
 bypass_403: chk('wiz-bypass403') || undefined,
 };
 break;
 case 'domain_run':
 if (!domain) throw new Error('Domain is required');
 endpoint = '/scan/domain_run';
 payload = { domain, skip_ffuf: chk('wiz-skipffuf') };
 break;
 case 'subdomain_run':
 if (!val('wiz-subdomain')) throw new Error('Subdomain is required');
 endpoint = '/scan/subdomain_run';
 payload = { subdomain: val('wiz-subdomain'), skip_ffuf: chk('wiz-skipffuf') };
 break;
 default:
 if (simple[current.id]) {
 if (!domain) throw new Error('Domain is required');
 endpoint = '/scan/' + simple[current.id][0];
 payload = { domain };
 }
 }
 if (!endpoint) throw new Error('Unknown scan type');
 const data = await window.apiPost(endpoint, payload);
 if (data && data.scan_id && window.applyLaunchMeta) await window.applyLaunchMeta(data.scan_id, meta);
 window.showToast('success', 'Started', meta.name || data.message || data.scan_id || 'Scan started');
 closeWizard();
 setTimeout(() => { document.getElementById('nav-scans')?.click(); }, 1200);
 } catch (err) {
 window.showToast('error', 'Error', err.message);
 }
 }

 window.openLaunchWizard = openWizard;
 window.closeLaunchWizard = closeWizard;
 window.wizardBack = renderPick;
 window.wizardLaunch = launch;
})();

(() => {
 // Brand colour is identity only (top stripe + name dot). Surfaces, text and
 // controls come from the theme tokens: the old per-platform dark fills
 // (#1a2e1a, #2e1e10, …) rendered as black slabs in the light theme.
 const PLATFORM_ACCENT = { h1: '#22a861', bc: '#e67e22', ywh: '#3498db', it: '#9b59b6', bizone: '#4f6bed', immunefi: '#667eea' };
 // Theme-aware colour set for the domain list and the accounts modal.
 function platformColors(id) {
 return { accent: PLATFORM_ACCENT[id] || PLATFORM_ACCENT.immunefi, border: 'var(--border-bright)', text: 'var(--text-primary)' };
 }

 const targetsState = {
 platforms: [],
 selectedPlatform: null,
 credentials: {},
 domains: [],
 rawTargets: [],
 filtered: [],
 extractRoots: true,
 };

 // escapeSafe HTML-escapes a value for element text or a QUOTED attribute value.
 // It is NOT safe inside inline event handlers (onclick="fn('…')"): the browser
 // decodes &#39; back to ' before the JS runs, so a crafted scope target would
 // break out of the string literal. Every action button in this file therefore
 // carries its value in a data-* attribute and is wired with addEventListener /
 // a delegated listener that reads it back from element.dataset.
 function escapeSafe(s) {
 return String(s ?? '')
 .replace(/&/g, '&amp;')
 .replace(/"/g, '&quot;')
 .replace(/</g, '&lt;')
 .replace(/>/g, '&gt;')
 .replace(/'/g, '&#39;');
 }

 function renderPlatformCredFields(p) {
 if (!p.auth_fields || p.auth_fields.length === 0) return '';
 const creds = targetsState.credentials[p.id] || {};
 return p.auth_fields.map((field) => {
 const label = field.charAt(0).toUpperCase() + field.slice(1);
 const isPass = field === 'password' || field === 'token';
 return `
 <div style="margin-bottom:8px;">
 <label style="font-size:11px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;">${escapeSafe(label)}</label>
 <input type="${isPass ? 'password' : 'text'}"
 id="targets-cred-${escapeSafe(p.id)}-${escapeSafe(field)}"
 value="${escapeSafe(creds[field] || '')}"
 placeholder="${escapeSafe(field === 'token' ? 'API Token' : field === 'username' ? 'Username' : field)}"
 data-cred-platform="${escapeSafe(p.id)}" data-cred-field="${escapeSafe(field)}" class="search-input"
 style="width:100%;max-width:none;box-sizing:border-box;padding:7px 10px;font-size:12px;margin-top:4px;" />
 </div>
 `;
 }).join('');
 }

 function renderTargetsPlatforms() {
 const grid = document.getElementById('targets-platforms-grid');
 if (!grid) return;
 grid.innerHTML = '';
 for (const p of targetsState.platforms) {
 const accent = PLATFORM_ACCENT[p.id] || PLATFORM_ACCENT.immunefi;
 const isSelected = targetsState.selectedPlatform === p.id;
 const restBorder = isSelected ? 'var(--accent-primary)' : 'var(--border)';
 const card = document.createElement('div');
 card.id = `targets-platform-${p.id}`;
 card.style.cssText = `
 background:var(--bg-card);border:1px solid ${restBorder};border-top:3px solid ${accent};
 border-radius:14px;padding:18px;cursor:pointer;transition:border-color 0.18s, box-shadow 0.18s;
 display:flex;flex-direction:column;
 ${isSelected ? 'box-shadow:0 0 0 1px var(--accent-primary), var(--shadow-card);' : ''}
 `;
 const acctCount = p.account_count || 0;
 const acctSuffix = acctCount > 0 ? ` · ${acctCount} account${acctCount > 1 ? 's' : ''}` : '';
 const statusPill = p.env_configured
 ? `<span style="display:inline-flex;align-items:center;gap:5px;font-size:11px;color:var(--accent-emerald);">
 <span style="width:7px;height:7px;border-radius:50%;background:currentColor;"></span>Configured${acctSuffix}</span>`
 : `<span style="display:inline-flex;align-items:center;gap:5px;font-size:11px;color:var(--accent-amber);">
 <span style="width:7px;height:7px;border-radius:50%;background:currentColor;"></span>Needs credentials</span>`;
 const manageBtn = (p.auth_fields && p.auth_fields.length)
 ? `<button type="button" class="btn btn-ghost" data-targets-manage="1" style="width:100%;margin-top:8px;font-size:12px;">
 Manage accounts${acctCount > 0 ? ` (${acctCount})` : ''}</button>`
 : '';
 card.innerHTML = `
 <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:10px;">
 <div style="display:flex;align-items:center;gap:11px;min-width:0;">
 ${p.logo ? `<span style="font-size:28px;line-height:1;flex-shrink:0;">${escapeSafe(p.logo)}</span>` : ''}
 <div style="min-width:0;">
 <div style="display:flex;align-items:center;gap:8px;font-weight:700;font-size:15px;color:var(--text-primary);min-width:0;"><span style="flex:none;width:9px;height:9px;border-radius:50%;background:${accent};"></span><span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeSafe(p.name)}</span></div>
 <div style="margin-top:4px;">${statusPill}</div>
 </div>
 </div>
 ${isSelected ? '<span style="flex-shrink:0;font-size:9px;font-weight:800;letter-spacing:.06em;color:var(--accent-primary);border:1px solid var(--accent-primary);border-radius:20px;padding:3px 9px;">SELECTED</span>' : ''}
 </div>
 <div style="font-size:12px;color:var(--text-muted);line-height:1.55;margin-bottom:14px;">${escapeSafe(p.description)}</div>
 <div style="margin-top:auto;">
 ${renderPlatformCredFields(p)}
 ${manageBtn}
 <button type="button" class="btn${isSelected ? ' btn-primary' : ''}" data-targets-select="1" style="width:100%;margin-top:10px;justify-content:center;">
 ${isSelected ? 'Selected' : 'Select'}
 </button>
 </div>
 `;
 // Handlers close over the platform object — its values are never
 // interpolated into handler source.
 card.querySelector('[data-targets-select]')?.addEventListener('click', () => targetsSelectPlatform(p.id));
 card.querySelector('[data-targets-manage]')?.addEventListener('click', (e) => {
 e.stopPropagation();
 targetsManageAccounts(p.id);
 });
 card.querySelectorAll('input[data-cred-field]').forEach((input) => {
 input.addEventListener('input', () => targetsUpdateCred(input.dataset.credPlatform, input.dataset.credField, input.value));
 });
 card.addEventListener('mouseenter', () => {
 if (!isSelected) { card.style.borderColor = 'var(--border-strong)'; card.style.borderTopColor = accent; }
 });
 card.addEventListener('mouseleave', () => {
 if (!isSelected) { card.style.borderColor = restBorder; card.style.borderTopColor = accent; }
 });
 grid.appendChild(card);
 }
 }

 async function loadTargetsPlatforms() {
 if (window.state?.view !== 'targets') return;
 try {
 const data = await window.apiFetch('/api/scope/platforms');
 targetsState.platforms = data.platforms || [];
 renderTargetsPlatforms();
 } catch (e) {
 window.showToast('error', 'Scope Error', e.message);
 }
 // Chaos key status hint (best-effort — doesn't block the page)
 try {
 const cfg = window.state?.config || await window.apiFetch('/api/config');
 const el = document.getElementById('targets-chaos-status');
 if (el) {
 el.innerHTML = cfg.chaos_key_set
 ? '<span style="color:var(--accent-emerald)"> key configured</span>'
 : '<span style="color:var(--accent-amber)"> no CHAOS_API_KEY — set it in Settings</span>';
 }
 } catch (_) { /* ignore */ }
 }

 /* ── Chaos subdomain lookup ─────────────────────────────────────────────── */
 let chaosSubs = [];

 async function chaosFetch(prefill) {
 const input = document.getElementById('targets-chaos-domain');
 if (prefill && input) input.value = prefill;
 const domain = (prefill || (input && input.value) || '').trim();
 if (!domain) { window.showToast('warning', 'No domain', 'Enter a domain first'); return; }
 const save = document.getElementById('targets-chaos-save')?.checked ?? true;
 const btn = document.getElementById('targets-chaos-btn');
 const results = document.getElementById('targets-chaos-results');
 if (btn) { btn.textContent = 'Querying…'; btn.disabled = true; }
 if (results) results.innerHTML = '<div style="padding:14px;color:var(--text-muted)">Querying Chaos…</div>';
 try {
 const data = await window.apiPost('/api/chaos/subdomains', { domain, save });
 chaosRenderResults(data);
 window.showToast('success', 'Chaos',
 `${data.count} subdomain${data.count === 1 ? '' : 's'} for ${data.domain}${data.saved ? ` · ${data.saved} saved` : ''}`);
 } catch (e) {
 if (results) results.innerHTML = '';
 window.showToast('error', 'Chaos failed', e.message || String(e));
 } finally {
 if (btn) { btn.textContent = 'Get Subdomains'; btn.disabled = false; }
 }
 }

 function chaosRenderResults(data) {
 const el = document.getElementById('targets-chaos-results');
 if (!el) return;
 chaosSubs = data.subdomains || [];
 if (!chaosSubs.length) {
 el.innerHTML = `<div style="padding:14px;color:var(--text-muted)">Chaos has no subdomains for <code>${escapeSafe(data.domain || '')}</code>.</div>`;
 return;
 }
 el.innerHTML = `
 <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;flex-wrap:wrap;gap:8px;">
 <div style="font-size:12px;color:var(--text-muted)">
 <strong style="color:var(--text-primary)">${data.count}</strong> subdomains for <code>${escapeSafe(data.domain)}</code>
 ${data.saved ? ` · <span style="color:var(--accent-emerald)">${data.saved} saved to Subdomains DB</span>` : ''}
 ${data.save_error ? ` · <span style="color:var(--accent-red)">save failed: ${escapeSafe(data.save_error)}</span>` : ''}
 </div>
 <button type="button" class="btn btn-sm" data-chaos-copy-all="1">Copy all</button>
 </div>
 <div style="max-height:360px;overflow-y:auto;border:1px solid var(--border);border-radius:8px;">
 ${chaosSubs.map((sd, i) => `
 <div style="display:flex;align-items:center;gap:10px;padding:6px 12px;border-bottom:1px solid var(--bg-raise);font-size:12px;">
 <span style="color:var(--text-muted);width:40px;flex-shrink:0">${i + 1}</span>
 <a href="https://${escapeSafe(sd)}" target="_blank" rel="noopener" style="font-family:monospace;color:var(--accent-cyan);text-decoration:none;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeSafe(sd)}</a>
 </div>`).join('')}
 </div>`;
 el.querySelector('[data-chaos-copy-all]')?.addEventListener('click', chaosCopyAll);
 }

 async function chaosCopyAll() {
 if (!chaosSubs.length) return;
 const text = chaosSubs.join('\n');
 try {
 await window.copyToClipboard(text);
 window.showToast('success', 'Copied', `${chaosSubs.length} subdomains copied`);
 } catch (e) {
 window.showToast('error', 'Copy failed', e.message || String(e));
 }
 }

 function targetsUpdateCred(platformId, field, value) {
 if (!targetsState.credentials[platformId]) targetsState.credentials[platformId] = {};
 targetsState.credentials[platformId][field] = value;
 }

 function targetsSelectPlatform(id) {
 targetsState.selectedPlatform = id;
 renderTargetsPlatforms();
 const p = targetsState.platforms.find((x) => x.id === id);
 const fetchCard = document.getElementById('targets-fetch-card');
 if (fetchCard) {
 fetchCard.style.display = 'block';
 const titleEl = document.getElementById('targets-fetch-card-title');
 if (titleEl && p) titleEl.textContent = `Fetch from ${p.name}`;
 }
 const resultsCard = document.getElementById('targets-results-card');
 if (resultsCard) resultsCard.style.display = 'none';
 }

 async function targetsDoFetch() {
 const platformId = targetsState.selectedPlatform;
 if (!platformId) {
 window.showToast('warning', 'No platform', 'Select a platform first');
 return;
 }

 const creds = targetsState.credentials[platformId] || {};
 const btn = document.getElementById('targets-fetch-btn');
 if (btn) { btn.textContent = 'Fetching…'; btn.disabled = true; }

 try {
 const extractRoots = document.getElementById('targets-extract-roots')?.checked ?? true;
 const body = {
 platform: platformId,
 username: creds.username || '',
 token: creds.token || '',
 email: creds.email || '',
 password: creds.password || '',
 bbp_only: document.getElementById('targets-bbp-only')?.checked || false,
 pvt_only: document.getElementById('targets-pvt-only')?.checked || false,
 public_only: document.getElementById('targets-public-only')?.checked || false,
 include_oos: document.getElementById('targets-include-oos')?.checked || false,
 extract_roots: extractRoots,
 };
 const data = await window.apiPost('/api/scope/fetch', body);
 targetsState.extractRoots = extractRoots;
 targetsState.domains = data.root_domains || [];
 targetsState.rawTargets = data.raw_targets || [];
 const list = extractRoots ? targetsState.domains : targetsState.rawTargets;
 targetsState.filtered = [...list];

 const p = targetsState.platforms.find((x) => x.id === platformId);
 const header = document.getElementById('targets-result-header');
 if (header) {
 const count = extractRoots ? data.domain_count : data.target_count;
 const label = extractRoots ? 'root domains' : 'raw scope targets';
 header.textContent = `${count} ${label} from ${p?.name || platformId} (${data.programs} programs)`;
 }

 const resultsCard = document.getElementById('targets-results-card');
 if (resultsCard) resultsCard.style.display = 'block';

 targetsRenderDomainList(targetsState.filtered);
 const addAllBtn = document.getElementById('targets-add-all-btn');
 if (addAllBtn) addAllBtn.style.display = extractRoots ? 'inline-block' : 'none';
 const fetchedCount = extractRoots ? data.domain_count : data.target_count;
 const label = extractRoots ? 'root domains' : 'raw scope targets';
 window.showToast('success', 'Done', `Fetched ${fetchedCount} ${label} from ${data.programs} programs`);
 } catch (e) {
 window.showToast('error', 'Fetch failed', e.message);
 } finally {
 if (btn) { btn.textContent = 'Fetch Targets'; btn.disabled = false; }
 }
 }

 function targetsApplyFilter() {
 const q = (document.getElementById('targets-filter-input')?.value || '').toLowerCase();
 const base = targetsState.extractRoots ? targetsState.domains : targetsState.rawTargets;
 targetsState.filtered = q
 ? base.filter((d) => d.toLowerCase().includes(q))
 : [...base];
 targetsRenderDomainList(targetsState.filtered);
 }

 function targetsRenderDomainList(domains) {
 const container = document.getElementById('targets-domain-list');
 if (!container) return;
 if (!domains.length) {
 container.innerHTML = '<div style="padding:24px;text-align:center;color:var(--text-muted)">No domains found.</div>';
 return;
 }
 const colors = platformColors(targetsState.selectedPlatform);
 const extractRoots = targetsState.extractRoots;
 const colTitle = extractRoots ? 'Root Domain' : 'Raw Target';
 container.innerHTML = `
 <table style="width:100%;border-collapse:collapse;font-size:13px;">
 <thead>
 <tr style="border-bottom:1px solid var(--border);">
 <th style="text-align:left;padding:8px 12px;color:var(--text-muted);font-weight:600;">#</th>
 <th style="text-align:left;padding:8px 12px;color:var(--text-muted);font-weight:600;">${colTitle}</th>
 <th style="text-align:right;padding:8px 12px;color:var(--text-muted);font-weight:600;">Actions</th>
 </tr>
 </thead>
 <tbody>
 ${domains.map((d, i) => `
 <tr style="border-bottom:1px solid var(--bg-raise);transition:background 0.15s;"
 onmouseenter="this.style.background='var(--bg-raise)'"
 onmouseleave="this.style.background='transparent'">
 <td style="padding:9px 12px;color:var(--text-muted);width:40px">${i + 1}</td>
 <td style="padding:9px 12px;">
 <span style="color:${colors.text};font-family:monospace">${escapeSafe(d)}</span>
 </td>
 <td style="padding:9px 12px;text-align:right;">
 <div style="display:flex;gap:6px;justify-content:flex-end;">
 ${extractRoots
 ? `
 <button type="button" data-targets-action="add" data-value="${escapeSafe(d)}"
 style="padding:4px 12px;border-radius:8px;border:1px solid ${colors.border};
 background:transparent;color:${colors.text};font-size:11px;cursor:pointer;">
 + Add
 </button>
 <button type="button" data-targets-action="chaos" data-value="${escapeSafe(d)}" title="Fetch subdomains from Chaos"
 style="padding:4px 12px;border-radius:8px;border:1px solid ${colors.border};
 background:transparent;color:${colors.text};font-size:11px;cursor:pointer;">
 Chaos
 </button>
 <button type="button" data-targets-action="scan" data-value="${escapeSafe(d)}"
 style="padding:4px 12px;border-radius:8px;border:none;
 background:var(--accent-primary);color:var(--on-accent);font-size:11px;cursor:pointer;font-weight:600;">
 Run Scan
 </button>`
 : `
 <button type="button" data-targets-action="copy" data-value="${escapeSafe(d)}"
 style="padding:4px 12px;border-radius:8px;border:1px solid ${colors.border};
 background:transparent;color:${colors.text};font-size:11px;cursor:pointer;">
 Copy
 </button>`
 }
 </div>
 </td>
 </tr>
 `).join('')}
 </tbody>
 </table>
 `;
 // One delegated listener per container (assigned, so re-renders don't stack
 // handlers). data-value is decoded by the browser, so it is the exact original
 // string and never passes through a JS parser.
 container.onclick = (e) => {
 const btn = e.target.closest('button[data-targets-action]');
 if (!btn || !container.contains(btn)) return;
 const value = btn.dataset.value || '';
 switch (btn.dataset.targetsAction) {
 case 'add': targetsAddDomain(value); break;
 case 'chaos': chaosFetch(value); break;
 case 'scan': targetsLaunchScan(value); break;
 case 'copy': targetsCopyOne(value); break;
 default: break;
 }
 };
 }

 async function targetsCopyOne(value) {
 try {
 await window.copyToClipboard(value);
 window.showToast('success', 'Copied', value);
 } catch (e) {
 window.showToast('error', 'Copy failed', e.message || String(e));
 }
 }

 async function targetsAddDomain(domain) {
 try {
 await window.apiPost('/api/domains', { domain });
 window.showToast('success', 'Added', `${domain} added to Domains DB`);
 } catch (e) {
 window.showToast('error', 'Add failed', e.message);
 }
 }

 async function targetsAddAllDomains() {
 const domains = targetsState.filtered;
 if (!domains.length) return;
 const btn = document.getElementById('targets-add-all-btn');
 if (btn) { btn.textContent = 'Adding…'; btn.disabled = true; }
 try {
 const data = await window.apiPost('/api/domains/bulk', { domains });
 window.showToast('success', 'Bulk Add', `Added ${data.added} domains${data.errors?.length ? ` (${data.errors.length} errors)` : ''}`);
 } catch (e) {
 window.showToast('error', 'Bulk add failed', e.message);
 } finally {
 if (btn) { btn.textContent = '+ Add All to Domains DB'; btn.disabled = false; }
 }
 }

 // targetsLaunchScan prefills the Quick Scan Launcher (Scans page) with a full
 // domain workflow for this root domain; the user reviews the flags and launches.
 function targetsLaunchScan(domain) {
 if (typeof window.cloneScanToLauncher === 'function') {
 window.cloneScanToLauncher('domain_run', domain);
 return;
 }
 window.navigateTo('scans');
 window.showToast('info', 'Launch Scan', `Start a scan for ${domain} from the Scans page`);
 }

 async function targetsCopyAll() {
 const domains = targetsState.filtered;
 if (!domains.length) return;
 const text = domains.join('\n');

 if (navigator.clipboard && window.isSecureContext) {
 try {
 await navigator.clipboard.writeText(text);
 window.showToast('success', 'Copied', `${domains.length} domains copied to clipboard`);
 return;
 } catch (_) {}
 }

 try {
 const ta = document.createElement('textarea');
 ta.value = text;
 ta.style.cssText = 'position:fixed;left:-9999px;top:-9999px;opacity:0;';
 document.body.appendChild(ta);
 ta.focus();
 ta.select();
 const ok = document.execCommand('copy');
 document.body.removeChild(ta);
 if (ok) {
 window.showToast('success', 'Copied', `${domains.length} domains copied to clipboard`);
 } else {
 window.showToast('warning', 'Manual copy needed', 'Auto-copy failed — open the text in the toast');
 }
 } catch (e) {
 window.showToast('error', 'Copy failed', e.message);
 }
 }

 /* ── Multi-account management ──────────────────────────────────────────── */

 const AUTH_FIELDS_BY_PLATFORM = {
 h1: ['username', 'token'],
 bc: ['token'],
 it: ['token'],
 ywh: ['token', 'email', 'password'],
 };

 async function targetsManageAccounts(platformId) {
 const p = targetsState.platforms.find((x) => x.id === platformId);
 if (!p) return;
 let accts = [];
 try {
 const data = await window.apiFetch(`/api/accounts?platform=${encodeURIComponent(platformId)}`);
 accts = data.accounts || [];
 } catch (e) {
 window.showToast('error', 'Load failed', e.message);
 }
 renderAccountsModal(p, accts);
 }

 function renderAccountsModal(p, accts) {
 document.getElementById('targets-accounts-modal')?.remove();
 const colors = platformColors(p.id);
 const fields = AUTH_FIELDS_BY_PLATFORM[p.id] || ['token'];

 const rows = accts.length
 ? accts.map((a) => `
 <div style="display:flex;align-items:center;gap:10px;padding:9px 11px;border:1px solid ${colors.border};border-radius:9px;margin-bottom:8px;background:var(--bg-raise);">
 <div style="flex:1;min-width:0;">
 <div style="font-weight:600;color:${colors.text};font-size:13px;">${escapeSafe(a.label)}${a.enabled ? '' : ' <span style="color:var(--accent-amber);font-size:11px;">(disabled)</span>'}</div>
 <div style="font-size:11px;color:var(--text-muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
 ${a.username ? escapeSafe(a.username) + ' · ' : ''}${a.token_set ? 'token ' + escapeSafe(a.token_mask) : 'no token'}</div>
 </div>
 <button type="button" data-acct-action="toggle" data-acct-id="${escapeSafe(a.id)}" data-acct-enable="${a.enabled ? 'false' : 'true'}" title="${a.enabled ? 'Disable' : 'Enable'}"
 style="padding:5px 9px;border-radius:7px;border:1px solid ${colors.border};background:transparent;color:${a.enabled ? 'var(--accent-emerald)' : 'var(--accent-amber)'};font-size:11px;cursor:pointer;">${a.enabled ? 'On' : 'Off'}</button>
 <button type="button" data-acct-action="delete" data-acct-id="${escapeSafe(a.id)}" title="Delete"
 style="padding:5px 9px;border-radius:7px;border:1px solid var(--accent-red);background:transparent;color:var(--accent-red);font-size:11px;cursor:pointer;">Del</button>
 </div>`).join('')
 : `<div style="color:var(--text-muted);font-size:12px;padding:6px 0 12px;">No accounts yet — add one below. Your env-var credential (if set) is used automatically as an extra "env" account.</div>`;

 const addFields = fields.map((f) => {
 const label = f.charAt(0).toUpperCase() + f.slice(1);
 const isPass = f === 'password' || f === 'token';
 return `<input id="acct-add-${escapeSafe(p.id)}-${escapeSafe(f)}" type="${isPass ? 'password' : 'text'}" placeholder="${escapeSafe(label)}"
 style="width:100%;box-sizing:border-box;background:var(--bg-input);border:1px solid ${colors.border};border-radius:8px;padding:8px 10px;color:var(--text-primary);font-size:12px;margin-bottom:7px;outline:none;" />`;
 }).join('');

 const overlay = document.createElement('div');
 overlay.id = 'targets-accounts-modal';
 overlay.style.cssText = 'position:fixed;inset:0;z-index:10001;background:rgba(2,6,23,0.72);display:flex;align-items:center;justify-content:center;padding:24px;';
 overlay.innerHTML = `
 <div style="background:var(--bg-surface);border:1px solid ${colors.border};border-radius:14px;max-width:460px;width:100%;max-height:86vh;overflow:auto;box-shadow:0 20px 60px rgba(0,0,0,0.5);">
 <div style="display:flex;align-items:center;gap:10px;padding:15px 18px;border-bottom:1px solid ${colors.border};">
 <div style="font-weight:700;font-size:15px;color:${colors.text};flex:1;">${escapeSafe(p.name)} — accounts</div>
 <button type="button" data-acct-action="close" style="background:transparent;border:none;color:var(--text-muted);font-size:18px;cursor:pointer;">×</button>
 </div>
 <div style="padding:16px 18px;">
 ${rows}
 <div style="margin-top:14px;padding-top:14px;border-top:1px solid ${colors.border};">
 <div style="font-size:12px;font-weight:700;color:${colors.text};margin-bottom:9px;">Add account</div>
 <input id="acct-add-${escapeSafe(p.id)}-label" type="text" placeholder="Label (e.g. main, alt)"
 style="width:100%;box-sizing:border-box;background:var(--bg-input);border:1px solid ${colors.border};border-radius:8px;padding:8px 10px;color:var(--text-primary);font-size:12px;margin-bottom:7px;outline:none;" />
 ${addFields}
 <button type="button" data-acct-action="add"
 style="width:100%;margin-top:4px;padding:9px;border-radius:9px;border:none;background:var(--accent-primary);color:var(--on-accent);font-weight:600;font-size:13px;cursor:pointer;">+ Add account</button>
 </div>
 </div>
 </div>`;
 overlay.addEventListener('click', (e) => {
 if (e.target === overlay) { targetsCloseAccountsModal(); return; }
 const btn = e.target.closest('button[data-acct-action]');
 if (!btn) return;
 const id = btn.dataset.acctId;
 switch (btn.dataset.acctAction) {
 case 'toggle': targetsToggleAccount(id, btn.dataset.acctEnable === 'true', p.id); break;
 case 'delete': targetsDeleteAccount(id, p.id); break;
 case 'close': targetsCloseAccountsModal(); break;
 case 'add': targetsAddAccount(p.id); break;
 default: break;
 }
 });
 document.body.appendChild(overlay);
 }

 function targetsCloseAccountsModal() {
 document.getElementById('targets-accounts-modal')?.remove();
 }

 async function targetsAddAccount(platformId) {
 const fields = AUTH_FIELDS_BY_PLATFORM[platformId] || ['token'];
 const label = (document.getElementById(`acct-add-${platformId}-label`)?.value || '').trim();
 if (!label) { window.showToast('warning', 'Label required', 'Give the account a label'); return; }
 const body = { platform: platformId, label, enabled: true };
 for (const f of fields) {
 body[f] = (document.getElementById(`acct-add-${platformId}-${f}`)?.value || '').trim();
 }
 try {
 await window.apiPost('/api/accounts', body);
 window.showToast('success', 'Account added', `${label} saved`);
 await loadTargetsPlatforms();
 targetsManageAccounts(platformId);
 } catch (e) {
 window.showToast('error', 'Add failed', e.message);
 }
 }

 async function targetsToggleAccount(id, enabled, platformId) {
 try {
 await window.apiPost(`/api/accounts/${encodeURIComponent(id)}/toggle`, { enabled });
 await loadTargetsPlatforms();
 targetsManageAccounts(platformId);
 } catch (e) {
 window.showToast('error', 'Toggle failed', e.message);
 }
 }

 async function targetsDeleteAccount(id, platformId) {
 if (!await window.uiConfirm('Delete this account?')) return;
 try {
 await window.apiDelete(`/api/accounts/${encodeURIComponent(id)}`);
 window.showToast('success', 'Deleted', 'Account removed');
 await loadTargetsPlatforms();
 targetsManageAccounts(platformId);
 } catch (e) {
 window.showToast('error', 'Delete failed', e.message);
 }
 }

 window.TargetsPage = {
 loadTargetsPlatforms,
 renderTargetsPlatforms,
 renderPlatformCredFields,
 escapeSafe,
 targetsUpdateCred,
 targetsSelectPlatform,
 targetsDoFetch,
 targetsApplyFilter,
 targetsRenderDomainList,
 targetsAddDomain,
 targetsAddAllDomains,
 targetsLaunchScan,
 targetsCopyAll,
 targetsCopyOne,
 chaosFetch,
 chaosCopyAll,
 targetsManageAccounts,
 renderAccountsModal,
 targetsCloseAccountsModal,
 targetsAddAccount,
 targetsToggleAccount,
 targetsDeleteAccount,
 };
})();

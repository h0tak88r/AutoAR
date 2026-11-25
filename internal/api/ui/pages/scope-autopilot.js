(() => {
 // Scope autopilot panel (Programs page): new in-scope assets on H1/BC/YWH →
 // AI-planned AutoAR scans → AI review of the results on Discord. Program
 // names, assets and insights come from platforms and the model: everything is
 // escaped, and data-* values are whitelisted before they reach CSS.
 const esc = (s) =>
 window.esc ? window.esc(s) : String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
 const num = (n) => Number(n) || 0;
 const STATUS = { planned: 'queued', launched: 'scanning', finished: 'reviewing', reviewed: 'reviewed', failed: 'failed', skipped: 'skipped' };
 const PLAT = { h1: 'HackerOne', bc: 'Bugcrowd', ywh: 'YesWeHack', it: 'Intigriti' };
 let open = {};

 function isAdmin() {
 const me = window.state && window.state._me;
 return !me || me.role === 'admin';
 }
 function ago(ts) {
 if (!ts) return '—';
 const d = Date.now() / 1000 - ts;
 if (d < 3600) return Math.max(1, Math.round(d / 60)) + 'm';
 if (d < 86400) return Math.round(d / 3600) + 'h';
 return Math.round(d / 86400) + 'd';
 }

 // groupEvents folds runs into one row per (event = asset of one update).
 function groupEvents(runs) {
 const by = new Map();
 for (const r of runs || []) {
 const k = r.event_id || String(r.id);
 if (!by.has(k)) by.set(k, []);
 by.get(k).push(r);
 }
 return [...by.values()].map((rs) => rs.sort((a, b) => num(a.id) - num(b.id)));
 }

 function eventRow(rs) {
 const r0 = rs[0];
 const key = esc(r0.event_id || String(r0.id));
 const scans = rs.map((r) => {
 const st = STATUS[r.status] ? r.status : '';
 const label = r.scan_type ? `${esc(r.scan_type)}` : esc(r.reason || 'skipped');
 return `<span class="ap-scan" data-ap="${st}" title="${esc(r.reason || '')}${r.error ? ' — ' + esc(r.error) : ''}">${label} · ${esc(STATUS[st] || '—')}</span>`;
 }).join(' ');
 const insight = (rs.find((r) => r.insight) || {}).insight || '';
 const findings = Math.max(0, ...rs.map((r) => num(r.findings)));
 const isOpen = !!open[r0.event_id];
 return `<tr>
 <td style="white-space:nowrap;font-size:12px;color:var(--text-secondary)">${ago(r0.created_at)}</td>
 <td><div style="font-weight:600">${esc(r0.program_name || r0.handle)}</div><div style="font-size:11px;color:var(--text-muted)">${esc(PLAT[r0.platform] || r0.platform)}${r0.offers_bounty ? ' · bounty' : ''}</div></td>
 <td style="font-family:'JetBrains Mono',monospace;font-size:12px;word-break:break-all">${esc(r0.asset)}</td>
 <td><div class="ap-scans">${scans}</div><div style="font-size:11px;color:var(--text-muted);margin-top:3px">planned by ${esc(r0.planned_by === 'ai' ? 'AI' : 'rules')}</div></td>
 <td style="text-align:right">${findings ? `<b>${findings}</b>` : '<span style="color:var(--text-muted)">—</span>'}</td>
 <td>${insight ? `<button type="button" class="btn btn-ghost ap-more" data-ap-open="${key}" aria-expanded="${isOpen}">${isOpen ? 'Hide' : 'Insights'}</button>` : ''}</td>
 </tr>${insight && isOpen ? `<tr class="ap-insight"><td></td><td colspan="5"><pre>${esc(insight)}</pre></td></tr>` : ''}`;
 }

 function render(data) {
 const el = document.getElementById('programs-autopilot');
 if (!el || !data) return;
 const cfg = data.config || {};
 const admin = isAdmin();
 const events = groupEvents(data.runs).slice(0, 25);
 const plats = (cfg.platforms || []).map((p) => PLAT[p] || p).join(', ');
 el.innerHTML = `<div class="ap-card">
 <div class="ap-head">
 <span class="ap-title">Scope autopilot</span>
 ${admin
 ? `<button type="button" class="tri-chip fx-toggle" data-state="${cfg.enabled ? 'ok' : 'warn'}" data-ap-toggle="${cfg.enabled ? '1' : '0'}" aria-pressed="${cfg.enabled ? 'true' : 'false'}"><span class="dot"></span>${cfg.enabled ? 'On' : 'Off'}</button>`
 : `<span class="tri-chip" data-state="${cfg.enabled ? 'ok' : 'warn'}"><span class="dot"></span>${cfg.enabled ? 'On' : 'Off'}</span>`}
 <span class="ap-sub">New assets on ${esc(plats || '—')} → ${data.ai ? 'AI-planned' : 'rule-planned'} scans → AI insights on Discord · ${num(data.launched_today)}/${num(cfg.daily_max)} scans today · max ${num(cfg.max_assets_per_update)} assets per update${cfg.bounty_only ? ' · bounty programs only' : ''} · ${num(data.programs_tracked)} programs tracked</span>
 </div>
 ${events.length ? `<div class="table-wrap"><table class="table ap-table"><thead><tr><th>When</th><th>Program</th><th>New asset</th><th>Scans</th><th style="text-align:right">Findings</th><th></th></tr></thead><tbody>${events.map(eventRow).join('')}</tbody></table></div>`
 : '<div class="ap-empty">No new assets since the autopilot started. The next scope update on these platforms will show up here.</div>'}
 </div>`;
 }

 async function load() {
 if ((window.APP_EDITION || 'private') === 'public') return; // scope autopilot is a private-edition feature
 try {
 const data = await window.apiFetch('/api/scope-autopilot?limit=150');
 render(data);
 } catch (e) { /* the Programs page works without this panel */ }
 }

 async function toggle(btn) {
 const on = btn.getAttribute('data-ap-toggle') !== '1';
 btn.disabled = true;
 try {
 await window.apiPost('/api/scope-autopilot/config', { enabled: on });
 window.showToast('success', `Scope autopilot ${on ? 'on' : 'off'}`, on ? 'New in-scope assets get AI-planned scans.' : 'Scope updates are still announced; nothing is scanned automatically.');
 await load();
 } catch (e) {
 window.showToast('error', 'Not saved', e.message || String(e));
 btn.disabled = false;
 }
 }

 document.addEventListener('click', (e) => {
 const t = e.target;
 if (!t || !t.closest || !t.closest('#programs-autopilot')) return;
 const tg = t.closest('[data-ap-toggle]');
 if (tg) { toggle(tg); return; }
 const o = t.closest('[data-ap-open]');
 if (o) {
 const k = o.getAttribute('data-ap-open');
 open[k] = !open[k];
 load();
 }
 });

 window.loadScopeAutopilot = load;
 window.ScopeAutopilotPage = { render, groupEvents };
})();

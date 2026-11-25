(() => {
 const SOURCE_META = {
 h1: { name: 'HackerOne', color: '#2ecc71' },
 bc: { name: 'Bugcrowd', color: '#e67e22' },
 it: { name: 'Intigriti', color: '#9b59b6' },
 ywh: { name: 'YesWeHack', color: '#3498db' },
 as93: { name: 'External', color: '#95a5a6' },
 };

 const esc = (s) =>
 window.esc ? window.esc(s) : String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

 // Program URLs come from platforms and the public as93 aggregator: only
 // http(s) may become an href (a javascript: URL survives HTML escaping).
 function safeHref(u) {
 try {
 const parsed = new URL(String(u || ''));
 return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? parsed.href : '';
 } catch (e) {
 return '';
 }
 }

 async function refreshStatus() {
 try {
 const s = await window.apiFetch('/api/assets/catalog-status');
 const el = document.getElementById('plookup-status');
 if (el) {
 const last = s.last_sync_at ? new Date(s.last_sync_at).toLocaleString() : 'never';
 el.innerHTML =
 `Catalog: <b>${esc(s.programs || 0)}</b> programs · <b>${esc(s.domains || 0)}</b> scoped hosts · last sync: ${esc(last)}` +
 (s.sync_running ? ' · <span style="color:var(--accent-amber)">syncing…</span>' : '');
 }
 return s;
 } catch (e) {
 return null;
 }
 }

 async function loadProgramLookup() {
 await refreshStatus();
 }

 async function programLookupSearch() {
 const q = (document.getElementById('plookup-search')?.value || '').trim();
 const box = document.getElementById('plookup-results');
 if (!q || !box) return;
 box.innerHTML = '<div class="empty-state"><div class="empty-title">Searching…</div></div>';
 try {
 const data = await window.apiFetch('/api/assets/program-lookup?q=' + encodeURIComponent(q));
 renderResults(data);
 } catch (e) {
 box.innerHTML = `<div class="empty-state"><div class="empty-title" style="color:var(--accent-red)">Search failed: ${esc(e.message)}</div></div>`;
 }
 }

 const BADGE = 'flex-shrink:0;font-size:10px;font-weight:700;padding:2px 8px;border-radius:6px';

 // accountsBadge shows which of your accounts can see the program (which
 // account to submit from) — from the catalog-sync visibility data.
 function accountsBadge(r) {
 const list = Array.isArray(r.accounts) ? r.accounts.filter(Boolean) : [];
 if (!list.length) return '';
 const shown = list.slice(0, 3).map(esc).join(', ');
 const more = list.length > 3 ? ' +' + (list.length - 3) : '';
 return `<span title="Accounts that can see this program: ${esc(list.join(', '))}" style="${BADGE};background:rgba(99,102,241,.12);color:var(--accent-cyan,#67e8f9);border:1px solid #6366f155">👤 ${shown}${more}</span>`;
 }

 // scopeBadge renders the per-program verdict for a domain match: the host is
 // covered (exact entry or wildcard) in or out of scope, or the program only
 // lists a related parent host — which is NOT a scope verdict.
 function scopeBadge(r) {
 if (r.match_type !== 'domain') return '';
 if (r.match_kind === 'guess') {
 return `<span title="No catalog entry for this host or its parents; this program is named like the root domain ${esc(r.matched_domain)}. Likely the owner — confirm the host is in its scope before testing." style="${BADGE};background:rgba(241,196,15,.12);color:var(--accent-amber);border:1px dashed #f1c40f77">NAME MATCH</span>`;
 }
 if (r.match_kind === 'related' || typeof r.in_scope !== 'boolean') {
 return `<span title="The program lists a parent host or a wildcard of this exact host — check its scope wording" style="${BADGE};background:rgba(149,165,166,.15);color:var(--text-secondary);border:1px solid #95a5a655">RELATED</span>`;
 }
 return r.in_scope
 ? `<span style="${BADGE};background:rgba(46,204,113,.15);color:var(--accent-emerald);border:1px solid #2ecc7155">IN-SCOPE</span>`
 : `<span style="${BADGE};background:rgba(231,76,60,.15);color:var(--accent-red);border:1px solid #e74c3c55">OUT-OF-SCOPE</span>`;
 }

 function renderResults(data) {
 const box = document.getElementById('plookup-results');
 const results = data.results || [];
 if (!results.length) {
 box.innerHTML =
 `<div class="empty-state"><div class="empty-icon">∅</div><div class="empty-title">No paying programs found for “${esc(data.query)}”</div>` +
 `<div style="font-size:12px;color:var(--text-muted);margin-top:6px">Try a different keyword, or Sync the catalog if you haven't yet.</div></div>`;
 return;
 }
 const rows = results
 .map((r) => {
 const meta = SOURCE_META[r.source] || { name: r.source, color: '#888' };
 const sub = [
 r.match_type === 'domain' ? (r.match_kind === 'guess' ? 'named like root domain ' + esc(r.matched_domain) : 'matched: ' + esc(r.matched_domain) + (r.match_kind ? ' (' + esc(r.match_kind) + ')' : '')) : '',
 r.rewards ? esc(r.rewards) : '',
 r.safe_harbor ? 'safe-harbor: ' + esc(r.safe_harbor) : '',
 ].filter(Boolean).join(' · ');
 const href = safeHref(r.url);
 const open = href
 ? `<a href="${esc(href)}" target="_blank" rel="noopener noreferrer" class="btn btn-sm" style="flex-shrink:0">Open</a>`
 : `<span class="btn btn-sm" style="flex-shrink:0;opacity:.4;cursor:default" title="No http(s) link for this program">Open</span>`;
 return `
 <div style="display:flex;align-items:center;gap:12px;padding:12px 14px;border:1px solid var(--border);border-radius:10px;margin-bottom:8px;background:rgba(255,255,255,.02)">
 <span style="flex-shrink:0;font-size:10px;font-weight:800;color:${meta.color};border:1px solid ${meta.color}66;border-radius:6px;padding:3px 8px">${esc(meta.name)}</span>
 <div style="flex:1;min-width:0">
 <div style="font-weight:600;color:var(--text-primary);font-size:14px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.company)}</div>
 <div style="font-size:11px;color:var(--text-muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${sub}</div>
 </div>
 ${accountsBadge(r)}
 ${scopeBadge(r)}
 ${open}
 </div>`;
 })
 .join('');
 box.innerHTML =
 `<div style="font-size:12px;color:var(--text-muted);margin-bottom:10px">${results.length} paying program(s) for “${esc(data.query)}”${data.is_domain ? ' · domain search' : ''}${data.root ? ' · no catalog entry, matched by root domain ' + esc(data.root) : ''}</div>` +
 rows;
 }

 // One sync poll at a time. It stops when the sync finishes, on any status
 // error (401/network — refreshStatus() returns null), when the user leaves
 // the Program Lookup view, or after the child's max runtime.
 const POLL_MS = 3000;
 const POLL_MAX_MS = 50 * 60 * 1000; // catalog-sync child timeout is 45 min
 let syncPoll = null;

 function resetSyncButton() {
 const btn = document.getElementById('plookup-sync-btn');
 if (btn) { btn.disabled = false; btn.textContent = '⟳ Sync catalog'; }
 }

 function stopSyncPoll() {
 if (syncPoll) {
 clearInterval(syncPoll);
 syncPoll = null;
 }
 resetSyncButton();
 }

 async function programLookupSync() {
 const btn = document.getElementById('plookup-sync-btn');
 if (btn) { btn.disabled = true; btn.textContent = '⟳ Syncing…'; }
 try {
 await window.apiPost('/api/assets/program-sync', {});
 window.showToast('info', 'Sync started', 'Rebuilding the program catalog in the background…');
 stopSyncPoll();
 if (btn) { btn.disabled = true; btn.textContent = '⟳ Syncing…'; }
 const startedAt = Date.now();
 syncPoll = setInterval(async () => {
 if ((window.state && window.state.view !== 'program-lookup') || Date.now() - startedAt > POLL_MAX_MS) {
 stopSyncPoll();
 return;
 }
 const s = await refreshStatus();
 if (!s) {
 stopSyncPoll(); // status unavailable (expired session, network) — don't poll forever
 return;
 }
 if (!s.sync_running) {
 stopSyncPoll();
 const errs = Array.isArray(s.last_sync?.errors) ? s.last_sync.errors.length : 0;
 window.showToast(errs ? 'info' : 'success', 'Catalog synced',
 `${s.programs || 0} programs · ${s.domains || 0} hosts${errs ? ` · ${errs} source warning(s)` : ''}`);
 }
 }, POLL_MS);
 } catch (e) {
 resetSyncButton();
 window.showToast('error', 'Sync failed', e.message);
 }
 }

 window.loadProgramLookup = loadProgramLookup;
 window.programLookupSearch = programLookupSearch;
 window.programLookupSync = programLookupSync;
})();

(() => {
 const esc = (v) =>
 window.esc ? window.esc(v) : String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

 async function loadPortsSurface() {
 const box = document.getElementById('ports-rows');
 if (!box) return;
 const host = (document.getElementById('ports-host-filter')?.value || '').trim();
 const port = (document.getElementById('ports-port-filter')?.value || '').trim();
 const params = new URLSearchParams({ limit: '200' });
 if (host) params.set('host', host);
 if (port) params.set('port', port);
 let data;
 try {
 data = await window.apiFetch('/api/ports?' + params.toString());
 } catch (e) {
 box.innerHTML = `<tr><td colspan="5" style="color:var(--accent-red,#e74c3c)">Load failed: ${esc(e.message)}</td></tr>`;
 return;
 }
 const rows = data.ports || [];
 const countEl = document.getElementById('ports-count');
 if (countEl) countEl.textContent = String(data.total ?? 0);
 if (!rows.length) {
 box.innerHTML = '<tr><td colspan="5" style="color:var(--text-muted)">No ports match.</td></tr>';
 return;
 }
 const ago = (ts) => {
 if (!ts) return '—';
 const d = Date.now() / 1000 - ts;
 if (d < 3600) return Math.max(1, Math.round(d / 60)) + 'm ago';
 if (d < 86400) return Math.round(d / 3600) + 'h ago';
 return Math.round(d / 86400) + 'd ago';
 };
 box.innerHTML = rows.map((p) => `<tr>
 <td style="font-family:monospace;font-size:12px;color:var(--accent-cyan)">${esc(p.host)}</td>
 <td><b>${esc(p.port)}</b></td>
 <td style="font-size:12px">${esc(p.protocol)}</td>
 <td style="font-size:12px;color:var(--text-secondary)">${ago(p.first_seen)}</td>
 <td style="font-size:12px;color:var(--text-secondary)">${ago(p.last_seen)}</td>
 </tr>`).join('');
 }

 async function startPortSurfaceScan() {
 const name = await window.uiPrompt('Scan name (optional)', { okLabel: 'Start scan' });
 if (name === null) return; // cancelled
 try {
 const data = await window.apiPost('/api/ports/run', { name });
 window.showToast('success', 'Started', data.message || 'Port-surface scan started');
 setTimeout(() => { document.getElementById('nav-scans')?.click(); }, 1200);
 } catch (e) {
 window.showToast('error', 'Error', e.message);
 }
 }

 window.loadPortsSurface = loadPortsSurface;
 window.startPortSurfaceScan = startPortSurfaceScan;
})();

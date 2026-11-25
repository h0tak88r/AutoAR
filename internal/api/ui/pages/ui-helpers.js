(() => {
 function fmtDate(d) {
 if (!d) return '—';
 try {
 const dt = new Date(d);
 if (isNaN(dt)) return '—';
 return dt.toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
 } catch (_) {
 return '—';
 }
 }

 function timeAgo(d) {
 if (!d) return '—';
 try {
 const diff = Date.now() - new Date(d).getTime();
 if (isNaN(diff)) return '—';
 if (diff < 60000) return 'just now';
 if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
 if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
 return `${Math.floor(diff / 86400000)}d ago`;
 } catch (_) {
 return '—';
 }
 }

 function fmtInterval(secs) {
 if (!secs) return '—';
 if (secs < 60) return `${secs}s`;
 if (secs < 3600) return `${Math.floor(secs / 60)}m`;
 return `${Math.floor(secs / 3600)}h`;
 }

 function statusBadge(status) {
 const map = {
 running: 'badge-running',
 starting: 'badge-starting',
 paused: 'badge-starting',
 done: 'badge-done',
 completed: 'badge-done',
 failed: 'badge-failed',
 error: 'badge-failed',
 cancelled: 'badge-starting',
 };
 const cls = map[status] || 'badge-done';
 return `<span class="badge ${cls}">${window.esc(status)}</span>`;
 }

 function httpColor(code) {
 if (!code) return 'var(--text-muted)';
 if (code >= 200 && code < 300) return 'var(--accent-emerald)';
 if (code >= 300 && code < 400) return 'var(--accent-cyan)';
 if (code >= 400 && code < 500) return 'var(--accent-amber)';
 if (code >= 500) return 'var(--accent-red)';
 return 'var(--text-muted)';
 }

 function fileIcon(ext) {
 const map = {
 txt: '', log: '', json: '', zip: '', gz: '', html: '',
 pdf: '', png: '', jpg: '', jpeg: '', apk: '', ipa: '',
 db: '', sql: '', md: '',
 };
 return map[ext] || '';
 }

 function humanChangeType(t) {
 const map = {
 new_subdomain: 'New Subdomain',
 became_live: 'Host Came Online',
 became_dead: 'Host Went Down',
 content_changed: 'Content Changed',
 status_changed: 'Status Changed',
 new_js_endpoint: 'New JS Endpoint',
 new_program_asset: 'New Program Asset',
 };
 return map[t] || t;
 }

 // action (optional): { label, onclick } where onclick is an inline-handler string,
 // e.g. emptyState('', 'No domains yet', 'Add one to get started', { label: 'Run a scan', onclick: "window.navigateTo('scans')" }).
 function emptyState(icon, title, desc, action) {
 const cta = action && action.label
 ? `<button class="btn btn-primary" style="margin-top:14px"${action.onclick ? ` onclick="${action.onclick}"` : ''}>${window.esc(action.label)}</button>`
 : '';
 return `<div class="empty-state">
 <div class="empty-icon">${icon}</div>
 <div class="empty-title">${window.esc(title)}</div>
 <div class="empty-desc">${window.esc(desc)}</div>
 ${cta}
 </div>`;
 }

 function showToast(type, title, msg) {
 const container = document.getElementById('toast-container');
 // Line icons, not glyphs: the emoji strip left these as '' and every toast
 // fell through to a literal "[i]". Stroke follows the toast's type colour.
 const svg = (d) => `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">${d}</svg>`;
 const icons = {
 success: svg('<path d="M20 6 9 17l-5-5"/>'),
 error: svg('<circle cx="12" cy="12" r="9"/><path d="m15 9-6 6M9 9l6 6"/>'),
 warning: svg('<path d="M12 3 2 21h20L12 3z"/><path d="M12 10v4M12 17.5v.01"/>'),
 info: svg('<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 7.5v.01"/>'),
 };
 const el = document.createElement('div');
 el.className = `toast ${type}`;
 // Errors/warnings stay until dismissed (a 4s auto-hide can make a failed action
 // look like it succeeded); success/info auto-dismiss as before.
 const sticky = type === 'error' || type === 'warning';
 el.innerHTML = `<div class="toast-icon" aria-hidden="true">${icons[type] || icons.info}</div>
 <div class="toast-body">
 <div class="toast-title">${window.esc(title)}</div>
 ${msg ? `<div class="toast-msg">${window.esc(msg)}</div>` : ''}
 </div>
 ${sticky ? '<button class="toast-close" type="button" aria-label="Dismiss">×</button>' : ''}`;
 container.appendChild(el);
 if (sticky) {
 const close = el.querySelector('.toast-close');
 if (close) close.addEventListener('click', () => el.remove());
 } else {
 setTimeout(() => el.remove(), 4000);
 }
 }

 // uiConfirm replaces window.confirm(): an in-page dialog that resolves to
 // true/false. Native confirm() is suppressed in embedded browsers (the
 // desktop app's browser pane returns false at once, without a dialog), which
 // made every guarded action — bulk delete, AI review, scan deletion — do
 // nothing there. The first line of the message is the title, the rest the
 // body. Destructive actions (delete/remove/stop/rotate/clear/replace) start
 // focused on Cancel and show a red confirm button.
 function uiConfirm(message, opts = {}) {
 const text = String(message ?? '');
 const nl = text.indexOf('\n');
 const title = opts.title || (nl >= 0 ? text.slice(0, nl) : text);
 const body = opts.title ? text : (nl >= 0 ? text.slice(nl + 1).trim() : '');
 const danger = opts.danger ?? /\b(delete|remove|stop|rotate|clear|replace|wipe)\b/i.test(title);
 const okLabel = opts.confirmLabel || (danger ? (title.match(/^\s*(delete|remove|stop|rotate|clear|replace)/i) || ['', 'Confirm'])[1].replace(/^./, (c) => c.toUpperCase()) : 'Confirm');
 return new Promise((resolve) => {
 const opener = document.activeElement;
 const overlay = document.createElement('div');
 overlay.className = 'ui-confirm-overlay';
 overlay.innerHTML = `<div class="ui-confirm" role="alertdialog" aria-modal="true" aria-labelledby="ui-confirm-title" aria-describedby="ui-confirm-body">
 <h2 id="ui-confirm-title">${window.esc(title)}</h2>
 ${body ? `<p id="ui-confirm-body">${window.esc(body)}</p>` : ''}
 <div class="ui-confirm-actions">
 <button type="button" class="btn btn-secondary" data-ui-confirm="no">Cancel</button>
 <button type="button" class="btn ${danger ? 'btn-danger' : 'btn-primary'}" data-ui-confirm="yes">${window.esc(okLabel)}</button>
 </div>
 </div>`;
 const done = (v) => {
 document.removeEventListener('keydown', onKey, true);
 overlay.remove();
 if (opener && typeof opener.focus === 'function' && document.contains(opener)) opener.focus();
 resolve(v);
 };
 const onKey = (e) => {
 if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); done(false); return; }
 if (e.key === 'Enter' && !e.shiftKey) {
 const yes = overlay.querySelector('[data-ui-confirm="yes"]');
 if (document.activeElement === yes || !danger) { e.preventDefault(); e.stopPropagation(); done(true); }
 return;
 }
 if (e.key === 'Tab') {
 const btns = [...overlay.querySelectorAll('button')];
 const i = btns.indexOf(document.activeElement);
 e.preventDefault();
 btns[(i + (e.shiftKey ? btns.length - 1 : 1)) % btns.length].focus();
 }
 };
 overlay.addEventListener('click', (e) => {
 if (e.target === overlay) return done(false);
 const b = e.target.closest('[data-ui-confirm]');
 if (b) done(b.dataset.uiConfirm === 'yes');
 });
 document.addEventListener('keydown', onKey, true);
 document.body.appendChild(overlay);
 overlay.querySelector(danger ? '[data-ui-confirm="no"]' : '[data-ui-confirm="yes"]').focus();
 });
 }
 window.uiConfirm = uiConfirm;

 // uiPrompt is an in-page replacement for window.prompt() — which the desktop
 // app's browser pane also suppresses (returns null at once, so "Submitted"
 // with a report link silently cancelled). Resolves to the entered text, or
 // null when cancelled. opts: value, placeholder, label, okLabel, type
 // ("text" | "password" | "url"), help.
 function uiPrompt(message, opts = {}) {
 const text = String(message ?? '');
 const nl = text.indexOf('\n');
 const title = opts.title || (nl >= 0 ? text.slice(0, nl) : text);
 const body = opts.title ? text : (nl >= 0 ? text.slice(nl + 1).trim() : '');
 const type = ['password', 'url'].includes(opts.type) ? opts.type : 'text';
 return new Promise((resolve) => {
 const opener = document.activeElement;
 const overlay = document.createElement('div');
 overlay.className = 'ui-confirm-overlay';
 overlay.innerHTML = `<form class="ui-confirm" role="dialog" aria-modal="true" aria-labelledby="ui-prompt-title" novalidate>
 <h2 id="ui-prompt-title">${window.esc(title)}</h2>
 ${body ? `<p>${window.esc(body)}</p>` : ''}
 <label class="ui-prompt-field">${opts.label ? `<span>${window.esc(opts.label)}</span>` : ''}
 <input type="${type}" autocomplete="${type === 'password' ? 'new-password' : 'off'}" spellcheck="false" placeholder="${window.esc(opts.placeholder || '')}" />
 </label>
 ${opts.help ? `<p class="ui-prompt-help">${window.esc(opts.help)}</p>` : ''}
 <div class="ui-confirm-actions">
 <button type="button" class="btn btn-secondary" data-ui-prompt="no">Cancel</button>
 <button type="submit" class="btn btn-primary">${window.esc(opts.okLabel || 'Save')}</button>
 </div>
 </form>`;
 const input = overlay.querySelector('input');
 input.value = opts.value == null ? '' : String(opts.value);
 const done = (v) => {
 document.removeEventListener('keydown', onKey, true);
 overlay.remove();
 if (opener && typeof opener.focus === 'function' && document.contains(opener)) opener.focus();
 resolve(v);
 };
 const onKey = (e) => {
 if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); done(null); return; }
 if (e.key === 'Tab') {
 const els = [...overlay.querySelectorAll('input, button')];
 const i = els.indexOf(document.activeElement);
 e.preventDefault();
 els[(i + (e.shiftKey ? els.length - 1 : 1)) % els.length].focus();
 }
 };
 overlay.querySelector('form').addEventListener('submit', (e) => { e.preventDefault(); done(input.value); });
 overlay.addEventListener('click', (e) => {
 if (e.target === overlay || e.target.closest('[data-ui-prompt="no"]')) done(null);
 });
 document.addEventListener('keydown', onKey, true);
 document.body.appendChild(overlay);
 input.focus();
 if (input.select) input.select();
 });
 }
 window.uiPrompt = uiPrompt;

 function updateClock() {
 const el = document.getElementById('topbar-time');
 if (el) el.textContent = new Date().toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
 }

 window.UIHelpers = {
 fmtDate,
 timeAgo,
 fmtInterval,
 statusBadge,
 httpColor,
 fileIcon,
 humanChangeType,
 emptyState,
 showToast,
 updateClock,
 };
})();

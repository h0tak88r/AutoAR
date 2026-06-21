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
    const icons = { success: '', error: '', warning: '!', info: '[i]' };
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    // Errors/warnings stay until dismissed (a 4s auto-hide can make a failed action
    // look like it succeeded); success/info auto-dismiss as before.
    const sticky = type === 'error' || type === 'warning';
    el.innerHTML = `<div class="toast-icon">${icons[type] || '[i]'}</div>
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

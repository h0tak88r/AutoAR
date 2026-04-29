(() => {
  const KEYHACK_KEY_PATTERNS = [
    { name: 'AWS Access Key', re: /\bAKIA[0-9A-Z]{16}\b/g, sev: 'high', providerQuery: 'aws' },
    { name: 'Google API Key', re: /\bAIza[0-9A-Za-z\-_]{35}\b/g, sev: 'high', providerQuery: 'google' },
    { name: 'GitHub PAT', re: /\bghp_[A-Za-z0-9]{36,255}\b/g, sev: 'high', providerQuery: 'github' },
    { name: 'Slack Webhook', re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]+/g, sev: 'high', providerQuery: 'slack' },
    { name: 'Stripe Secret', re: /\bsk_(live|test)_[0-9a-zA-Z]{16,}\b/g, sev: 'high', providerQuery: 'stripe' },
    { name: 'JWT Token', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, sev: 'warn', providerQuery: 'jwt' },
    { name: 'Private Key Block', re: /-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----/g, sev: 'high', providerQuery: 'private key' },
    { name: 'Bearer Token', re: /\bBearer\s+[A-Za-z0-9\-._~+/]+=*/g, sev: 'warn', providerQuery: 'bearer' },
    { name: 'Slack Bot Token', re: /\bxoxb-[0-9a-zA-Z-]+/g, sev: 'high', providerQuery: 'slack' },
    { name: 'Slack User Token', re: /\bxoxp-[0-9a-zA-Z-]+/g, sev: 'high', providerQuery: 'slack' },
    { name: 'Discord Bot Token', re: /\b[A-Za-z0-9._-]{20,}\.[A-Za-z0-9._-]{4,}\.[A-Za-z0-9._-]{20,}\b/g, sev: 'high', providerQuery: 'discord' },
    { name: 'Telegram Bot Token', re: /\b[0-9]{8,10}:[A-Za-z0-9_-]{30,}\b/g, sev: 'high', providerQuery: 'telegram' },
    { name: 'OpenAI API Key', re: /\bsk-[A-Za-z0-9]{32,}\b/g, sev: 'high', providerQuery: 'openai' },
    { name: 'SendGrid API Key', re: /\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{30,}\b/g, sev: 'high', providerQuery: 'sendgrid' },
    { name: 'Twilio Auth Token', re: /\b[A-f0-9]{32}\b/g, sev: 'warn', providerQuery: 'twilio' },
    { name: 'MongoDB URI', re: /\bmongodb(\+srv)?:\/\/[^\s'"]+/g, sev: 'high', providerQuery: 'mongodb' },
    { name: 'PostgreSQL URI', re: /\bpostgres(ql)?:\/\/[^\s'"]+/g, sev: 'high', providerQuery: 'postgresql' },
    { name: 'MySQL URI', re: /\bmysql:\/\/[^\s'"]+/g, sev: 'high', providerQuery: 'mysql' },
    { name: 'Redis URL', re: /\bredis:\/\/[^\s'"]+/g, sev: 'high', providerQuery: 'redis' },
  ];

  let allTemplates = null;
  let templatesLoading = null;

  function escapeHTML(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function escAttr(s) {
    return (window.escAttr ? window.escAttr(s) : String(s || '').replace(/"/g, '&quot;'));
  }

  function detectKeyProvidersInText(raw) {
    const txt = String(raw || '');
    const out = [];
    for (const p of KEYHACK_KEY_PATTERNS) {
      p.re.lastIndex = 0;
      let m;
      while ((m = p.re.exec(txt)) !== null) {
        if (!m[0]) break;
        out.push({ name: p.name, sev: p.sev, providerQuery: p.providerQuery, match: m[0].slice(0, 160) });
        if (m.index === p.re.lastIndex) p.re.lastIndex++;
        if (out.length >= 10) break;
      }
    }
    return out;
  }

  function keyhacksTemplateMatchesProviderQuery(t, providerQuery) {
    const q = String(providerQuery || '').toLowerCase().trim();
    if (!q) return false;
    const hay = [t?.Keyname, t?.Description, t?.Notes, t?.URL, t?.CommandTemplate]
      .filter(Boolean).join(' ').toLowerCase();
    return hay.includes(q);
  }

  async function ensureKeyhacksAllTemplatesLoaded() {
    if (Array.isArray(allTemplates) && allTemplates.length) return allTemplates;
    if (templatesLoading) return templatesLoading;
    templatesLoading = window.apiFetch('/api/keyhacks')
      .then((templates) => {
        allTemplates = Array.isArray(templates) ? templates : [];
        return allTemplates;
      })
      .catch((e) => {
        allTemplates = [];
        throw e;
      })
      .finally(() => {
        templatesLoading = null;
      });
    return templatesLoading;
  }

  function commandTemplateForToken(t, token) {
    let cmd = t?.CommandTemplate || '';
    if (!cmd) return '';
    if (cmd.includes('{{KEY}}')) cmd = cmd.replaceAll('{{KEY}}', token);
    return cmd;
  }

  async function renderKeyInspectorResult(raw) {
    const out = document.getElementById('keyhacks-inspector-output');
    if (!out) return;
    const token = String(raw || '').trim();
    if (!token) {
      out.innerHTML = '<div class="empty-state"><div class="empty-title">Paste a key to inspect</div></div>';
      return;
    }

    let templates = [];
    try {
      templates = await ensureKeyhacksAllTemplatesLoaded();
    } catch (e) {
      out.innerHTML = `<div class="empty-state"><div class="empty-title" style="color:var(--accent-red)">Error loading keyhacks</div><div class="empty-subtitle">${escapeHTML(e.message)}</div></div>`;
      return;
    }
    const detections = detectKeyProvidersInText(token);
    if (!detections.length) {
      out.innerHTML = '<div class="empty-state"><div class="empty-title">No known key patterns detected</div><div class="empty-subtitle">Try searching templates by provider name.</div></div>';
      return;
    }

    const byMatch = (providerQuery) =>
      (templates || []).filter((t) => keyhacksTemplateMatchesProviderQuery(t, providerQuery)).slice(0, 3);

    const sevBadge = (sev) =>
      sev === 'high'
        ? '<span style="display:inline-flex;align-items:center;padding:2px 10px;border-radius:999px;background:rgba(248,113,113,.15);color:#f87171;font-weight:800;font-size:12px">HIGH</span>'
        : '<span style="display:inline-flex;align-items:center;padding:2px 10px;border-radius:999px;background:rgba(245,158,11,.15);color:#f59e0b;font-weight:800;font-size:12px">WARN</span>';

    const html = detections.slice(0, 3).map((d) => {
      const matched = byMatch(d.providerQuery);
      if (!matched.length) {
        return `<div class="card" style="margin:10px 0 0 0"><div class="card-header"><div class="card-title">${sevBadge(d.sev)} <span style="margin-left:8px">${escapeHTML(d.name)}</span></div></div><div class="card-body"><div style="margin-bottom:10px;color:var(--text-muted)">Matched pattern: <span style="font-family:ui-monospace,monospace">${escapeHTML(d.match)}</span></div><div class="empty-subtitle">No command template found in Keyhacks DB for this provider.</div></div></div>`;
      }
      const cmdsHtml = matched.map((t) => {
        const cmd = commandTemplateForToken(t, token);
        if (!cmd) return '';
        return `<div class="keyhack-cmd-section" style="margin-top:10px"><div class="keyhack-cmd-label">Validation command (${escapeHTML(t.Method || 'GET').toUpperCase()})</div><div class="keyhack-cmd-box"><pre class="keyhack-pre">${escapeHTML(cmd)}</pre><button class="keyhack-copy-btn" title="Copy to clipboard" data-cmd="${escAttr(cmd)}"><span style="font-size:14px">📋</span></button></div></div>`;
      }).filter(Boolean).join('');
      return `<div class="card" style="margin:10px 0 0 0"><div class="card-header"><div class="card-title">${sevBadge(d.sev)} <span style="margin-left:8px">${escapeHTML(d.name)}</span></div></div><div class="card-body"><div style="margin-bottom:10px;color:var(--text-muted)">Matched pattern: <span style="font-family:ui-monospace,monospace">${escapeHTML(d.match)}</span></div>${cmdsHtml}</div></div>`;
    }).join('');

    out.innerHTML = html;
    out.querySelectorAll('.keyhack-copy-btn').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const cmd = btn.getAttribute('data-cmd') || '';
        try { await window.copyToClipboard(cmd); window.showToast('success', 'Copied to clipboard', ''); }
        catch (e) { window.showToast('error', 'Copy failed', e?.message || String(e)); }
      });
    });
  }

  function renderKeyhacks(templates) {
    const container = document.getElementById('keyhacks-container');
    if (!container) return;
    if (!templates || templates.length === 0) {
      container.innerHTML = '<div class="empty-state"><div class="empty-icon">🔍</div><div class="empty-title">No templates found</div><div class="empty-subtitle">Try a different search query</div></div>';
      return;
    }

    const total = templates.length;
    let html = `
      <div class="card" style="margin-bottom:14px">
      <div class="card-header"><div class="card-title"><span class="card-title-icon">🔍</span>API Key Inspector — DB-Based (${total} templates)</div></div>
      <div class="card-body">
        <div style="display:flex;gap:10px;flex-wrap:wrap">
          <input class="search-input" id="keyhacks-key-input" placeholder="Paste key/token for detection..." autocomplete="off" style="flex:1;min-width:260px" />
          <button class="btn btn-primary" id="keyhacks-inspect-btn">Inspect</button>
        </div>
        <div id="keyhacks-inspector-output" style="margin-top:8px"></div>
      </div>
    </div>
    <div class="keyhacks-grid">`;

    templates.forEach((t) => {
      const method = (t.Method || 'GET').toUpperCase();
      const cmd = t.CommandTemplate || '';
      const methodClass = method === 'POST' ? 'method-post' : 'method-get';
      html += `<div class="keyhack-card"><div class="keyhack-header"><div class="keyhack-title"><span class="nav-icon" style="font-size:14px">🔑</span>${escapeHTML(t.Keyname)}</div><div class="keyhack-badge ${methodClass}">${method}</div></div><div class="keyhack-body"><div class="keyhack-desc">${escapeHTML(t.Description || 'No description available for this template.')}</div><div class="keyhack-cmd-section"><div class="keyhack-cmd-label">Validation Command Template</div><div class="keyhack-cmd-box"><pre class="keyhack-pre">${escapeHTML(cmd)}</pre><button class="keyhack-copy-btn" title="Copy to clipboard" data-cmd="${escAttr(cmd)}"><span style="font-size:14px">📋</span></button></div></div>${t.Notes ? `<div class="keyhack-notes"><div class="keyhack-notes-label">💡 Usage Notes</div><div class="keyhack-notes-text">${escapeHTML(t.Notes)}</div></div>` : ''}</div></div>`;
    });

    html += '</div>';
    container.innerHTML = html;
    const inspectBtn = document.getElementById('keyhacks-inspect-btn');
    const keyInput = document.getElementById('keyhacks-key-input');
    if (inspectBtn && keyInput) {
      inspectBtn.addEventListener('click', async () => { await renderKeyInspectorResult(keyInput.value); });
      keyInput.addEventListener('keydown', async (e) => { if (e.key === 'Enter') { e.preventDefault(); await renderKeyInspectorResult(keyInput.value); } });
    }
    container.querySelectorAll('.keyhack-copy-btn').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const cmd = btn.getAttribute('data-cmd') || '';
        try { await window.copyToClipboard(cmd); window.showToast('success', 'Copied to clipboard', ''); }
        catch (e) { window.showToast('error', 'Copy failed', e?.message || String(e)); }
      });
    });
  }

  async function loadKeyhacks(query = '') {
    const container = document.getElementById('keyhacks-container');
    if (!container) return;
    try {
      const q = String(query || '').toLowerCase().trim();
      if (!q) {
        const templates = await ensureKeyhacksAllTemplatesLoaded();
        renderKeyhacks(templates);
        return;
      }
      const data = await window.apiFetch(`/api/keyhacks/search?q=${encodeURIComponent(q)}`);
      renderKeyhacks(Array.isArray(data) ? data : []);
    } catch (e) {
      container.innerHTML = `<div class="empty-state"><div class="empty-title" style="color:var(--accent-red)">Error loading templates</div><div class="empty-subtitle">${escapeHTML(e.message)}</div></div>`;
    }
  }

  window.KeyhacksPage = { loadKeyhacks };
})();

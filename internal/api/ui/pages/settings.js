(() => {
  function escValue(v) {
    return typeof window.esc === 'function' ? window.esc(v) : String(v ?? '');
  }

  async function loadConfig() {
    try {
      window.state.config = await window.apiFetch('/api/config');
      if (window.state.view === 'settings') renderSettings();
      // Update status dot if it exists
      if (typeof window.updateStatusDot === 'function') window.updateStatusDot();
    } catch (e) {
      window.showToast('error', 'Config Error', e.message);
      throw e;
    }
  }

  function renderSettings() {
    const cfg = window.state.config;
    const el = document.getElementById('settings-container');
    if (!el || !cfg) return;

    const item = (label, value, hint = '', cls = '') => `
      <div class="settings-item">
        <div class="settings-label">
          <div class="settings-title">${label}</div>
          ${hint ? `<div class="settings-hint">${hint}</div>` : ''}
        </div>
        <div class="settings-value ${cls}">${escValue(String(value ?? '—'))}</div>
      </div>`;

    // Masked secret-token row: password input (never pre-filled), placeholder shows
    // whether a value is already saved, Save button calls the given handler.
    const tokenRow = (title, hint, inputId, saveFn, placeholder, isSet) => `
      <div class="settings-item">
        <div class="settings-label">
          <div class="settings-title">${title}</div>
          <div class="settings-hint">${hint} ${isSet ? '<span class="badge badge-done">configured</span>' : '<span class="badge badge-failed">not set</span>'}</div>
        </div>
        <div class="settings-control">
          <input type="password" id="${inputId}" value="" placeholder="${isSet ? '••••••• (saved)' : escValue(placeholder)}" class="form-control premium-input">
          <button class="btn btn-primary" onclick="${saveFn}">Save</button>
        </div>
      </div>`;

    el.innerHTML = `
      <div class="settings-container-premium">
        <div class="settings-tabs" role="tablist">
          <button class="settings-tab" data-tab="platforms" onclick="window.SettingsPage.settingsTab('platforms')">Platforms &amp; Keys</button>
          <button class="settings-tab" data-tab="ai" onclick="window.SettingsPage.settingsTab('ai')">AI Providers</button>
          <button class="settings-tab" data-tab="timeouts" onclick="window.SettingsPage.settingsTab('timeouts')">Scan Timeouts</button>
          <button class="settings-tab" data-tab="notifications" onclick="window.SettingsPage.settingsTab('notifications')">Notifications</button>
          <button class="settings-tab" data-tab="status" onclick="window.SettingsPage.settingsTab('status')">System</button>
        </div>
        <div class="settings-section" data-tab="status">
          <div class="settings-section-header"> System Status</div>
          <div class="settings-section-body">
            ${item('Version', cfg.version)}
            ${item('Deployment Mode', cfg.mode, 'Current operational profile')}
            ${item('Database Type', cfg.db_type, 'Backend persistence engine')}
            <div class="settings-item">
              <div class="settings-label">
                <div class="settings-title">Authentication</div>
                <div class="settings-hint">Dashboard API security status</div>
              </div>
              <div class="settings-value">
                <span class="badge ${cfg.auth_enabled ? 'badge-done' : 'badge-failed'}">
                  ${cfg.auth_enabled ? ' Active' : ' Public (Warning)'}
                </span>
              </div>
            </div>
          </div>
        </div>

        <div class="settings-section" data-tab="ai">
          <div class="settings-section-header"> AI Intelligence</div>
          <div class="settings-section-body">
            <div class="settings-item">
              <div class="settings-label">
                <div class="settings-title">OpenCode API Key</div>
                <div class="settings-hint">Default free provider. Get a key at <a href="https://opencode.ai/zen" target="_blank" rel="noopener">opencode.ai/zen</a>. ${cfg.opencode_key_set ? '<span class="badge badge-done">configured</span>' : '<span class="badge badge-failed">not set</span>'}</div>
              </div>
              <div class="settings-control">
                <input type="password" id="opencode-key-input"
                  value=""
                  placeholder="${cfg.opencode_key_set ? '••••••• (saved)' : 'oc-...'}"
                  class="form-control premium-input">
                <button class="btn btn-primary" onclick="window.SettingsPage.saveOpenCodeKey()">Save</button>
              </div>
            </div>
            <div class="settings-item">
              <div class="settings-label">
                <div class="settings-title">OpenCode Model</div>
                <div class="settings-hint">Override the default model. Leave blank or type <code>default</code> to use <code>deepseek-v4-flash-free</code>. See <a href="https://opencode.ai/zen/v1/models" target="_blank" rel="noopener">available models</a>.</div>
              </div>
              <div class="settings-control">
                <input type="text" id="opencode-model-input"
                  value="${escValue(cfg.opencode_model || '')}"
                  placeholder="deepseek-v4-flash-free"
                  class="form-control premium-input">
                <button class="btn btn-primary" onclick="window.SettingsPage.saveOpenCodeModel()">Save</button>
              </div>
            </div>
            <div class="settings-item">
              <div class="settings-label">
                <div class="settings-title">OpenRouter API Key</div>
                <div class="settings-hint">Optional — used when set, for premium or alternative models. ${cfg.openrouter_key_set ? '<span class="badge badge-done">configured</span>' : '<span class="badge badge-failed">not set</span>'}</div>
              </div>
              <div class="settings-control">
                <input type="password" id="or-key-input"
                  value=""
                  placeholder="${cfg.openrouter_key_set ? '••••••• (saved)' : 'sk-or-v1-…'}"
                  class="form-control premium-input">
                <button class="btn btn-primary" onclick="window.SettingsPage.saveOpenRouterKey()">Save</button>
              </div>
            </div>
            <div class="settings-item">
              <div class="settings-label">
                <div class="settings-title">OpenRouter Model</div>
                <div class="settings-hint">Override the default model. Leave blank or type <code>default</code> to use <code>z-ai/glm-4.5-air:free</code>.</div>
              </div>
              <div class="settings-control">
                <input type="text" id="openrouter-model-input"
                  value="${escValue(cfg.openrouter_model || '')}"
                  placeholder="z-ai/glm-4.5-air:free"
                  class="form-control premium-input">
                <button class="btn btn-primary" onclick="window.SettingsPage.saveOpenRouterModel()">Save</button>
              </div>
            </div>
            <div class="settings-item">
              <div class="settings-label">
                <div class="settings-title">Gemini API Key</div>
                <div class="settings-hint">Final fallback for AI analysis. ${cfg.gemini_key_set ? '<span class="badge badge-done">configured</span>' : '<span class="badge badge-failed">not set</span>'}</div>
              </div>
              <div class="settings-control">
                <input type="password" id="gemini-key-input"
                  value=""
                  placeholder="${cfg.gemini_key_set ? '••••••• (saved)' : 'AIza…'}"
                  class="form-control premium-input">
                <button class="btn btn-primary" onclick="window.SettingsPage.saveGeminiKey()">Save</button>
              </div>
            </div>
          </div>
        </div>

        <div class="settings-section" data-tab="platforms">
          <div class="settings-section-header"> Bug Bounty Platform API Keys</div>
          <div class="settings-section-description">
            Credentials for the Programs catalogue. Saved securely on the server (never
            shown back) and applied immediately — the Programs list refreshes in the
            background. Leave a field blank to keep the current value.
          </div>
          <div class="settings-section-body">
            <div class="settings-item">
              <div class="settings-label">
                <div class="settings-title">HackerOne</div>
                <div class="settings-hint">Username + API token (<a href="https://hackerone.com/settings/api_token" target="_blank" rel="noopener">get a token</a>). ${cfg.h1_token_set ? '<span class="badge badge-done">configured</span>' : '<span class="badge badge-failed">not set</span>'}</div>
              </div>
              <div class="settings-control" style="flex-direction:column;align-items:stretch;gap:6px;">
                <input type="text" id="h1-username-input" value="" placeholder="${cfg.h1_username_set ? 'username saved — type to change' : 'username'}" class="form-control premium-input">
                <div style="display:flex;gap:8px;">
                  <input type="password" id="h1-token-input" value="" placeholder="${cfg.h1_token_set ? '••••••• (saved)' : 'API token'}" class="form-control premium-input" style="flex:1;">
                  <button class="btn btn-primary" onclick="window.SettingsPage.saveH1Creds()">Save</button>
                </div>
              </div>
            </div>
            ${tokenRow('Bugcrowd', 'Value of the <code>_crowdcontrol_session_key</code> session cookie.', 'bc-token-input', 'window.SettingsPage.saveBugcrowdToken()', 'session cookie value', cfg.bc_token_set)}
            ${tokenRow('Intigriti', 'Researcher API token.', 'it-token-input', 'window.SettingsPage.saveIntigritiToken()', 'API token', cfg.it_token_set)}
            ${tokenRow('YesWeHack', 'JWT token.', 'ywh-token-input', 'window.SettingsPage.saveYWHToken()', 'JWT token', cfg.ywh_token_set)}
            <div class="settings-item">
              <div class="settings-label">
                <div class="settings-title">HackAdvisor <span style="font-size:10px;color:#f472b6;font-weight:600;">external targets</span></div>
                <div class="settings-hint">Bearer token from <a href="https://hackadvisor.io/api-docs" target="_blank" rel="noopener">hackadvisor.io/api-docs</a> — adds Immunefi, Standoff365, BI.ZONE, YesWeHack &amp; self-hosted programs. ${cfg.ha_token_set ? '<span class="badge badge-done">configured</span>' : '<span class="badge badge-failed">not set</span>'}</div>
              </div>
              <div class="settings-control" style="flex-direction:column;align-items:stretch;gap:6px;">
                <div style="display:flex;gap:8px;">
                  <input type="password" id="ha-token-input" value="" placeholder="${cfg.ha_token_set ? '••••••• (saved)' : 'ha_...'}" class="form-control premium-input" style="flex:1;">
                  <button class="btn btn-primary" onclick="window.SettingsPage.saveHackAdvisorCreds()">Save</button>
                </div>
                <label style="font-size:11px;color:var(--text-muted);display:flex;align-items:center;gap:6px;cursor:pointer;">
                  <input type="checkbox" id="ha-include-native-input" ${cfg.ha_include_native ? 'checked' : ''}> Also include its HackerOne/Bugcrowd/Intigriti listings (off = external only, avoids duplicates)
                </label>
              </div>
            </div>
            ${tokenRow('Chaos (ProjectDiscovery)', 'Subdomain-dataset API key — powers the <strong>Chaos</strong> lookup in the Targets tab. Get one at <a href="https://cloud.projectdiscovery.io" target="_blank" rel="noopener">cloud.projectdiscovery.io</a>.', 'chaos-key-input', 'window.SettingsPage.saveChaosKey()', 'chaos API key', cfg.chaos_key_set)}
          </div>
        </div>

        <div class="settings-section" data-tab="timeouts">
          <div class="settings-section-header"> Scan Phase Timeouts</div>
          <div class="settings-section-description">
            Define max duration for each scan phase. Set to <strong>0</strong> for unlimited. 
            Stored in DB, persists across redeployments.
          </div>
          <div class="settings-section-body">
            <div class="settings-timeout-grid">
              <div class="timeout-field">
                <label> Zerodays</label>
                <input id="timeout-zerodays-input" type="number" min="0" class="form-control premium-input" value="${escValue(String(cfg.timeout_zerodays ?? 600))}" />
                <span>seconds</span>
              </div>
              <div class="timeout-field">
                <label> Nuclei</label>
                <input id="timeout-nuclei-input" type="number" min="0" class="form-control premium-input" value="${escValue(String(cfg.timeout_nuclei ?? 1200))}" />
                <span>seconds</span>
              </div>
              <div class="timeout-field">
                <label> Backup / Fuzzuli</label>
                <input id="timeout-backup-input" type="number" min="0" class="form-control premium-input" value="${escValue(String(cfg.timeout_backup ?? 600))}" />
                <span>seconds</span>
              </div>
              <div class="timeout-field">
                <label> Misconfig</label>
                <input id="timeout-misconfig-input" type="number" min="0" class="form-control premium-input" value="${escValue(String(cfg.timeout_misconfig ?? 1800))}" />
                <span>seconds</span>
              </div>
              <div class="timeout-field">
                <label> Katana Crawler</label>
                <input id="timeout-katana-input" type="number" min="0" class="form-control premium-input" value="${escValue(String(cfg.timeout_katana ?? 600))}" />
                <span>seconds</span>
              </div>
              <div class="timeout-field">
                <label> Dalfox XSS</label>
                <input id="timeout-xss-input" type="number" min="0" class="form-control premium-input" value="${escValue(String(cfg.timeout_xss ?? 1200))}" />
                <span>seconds</span>
              </div>
            </div>
            <div style="margin-top: 20px; display: flex; align-items: center; gap: 15px;">
              <button class="btn btn-primary" onclick="window.SettingsPage.saveTimeoutSettings()" id="timeout-save-btn"> Save All Timeouts</button>
              <div id="timeout-save-note" style="font-size:11px; color:var(--text-muted);">Persistence verified</div>
            </div>
          </div>
        </div>

        <div class="settings-section" data-tab="notifications">
          <div class="settings-section-header"> Notifications</div>
          <div class="settings-section-body">
            <div class="settings-item">
              <div class="settings-label">
                <div class="settings-title">Monitor Webhook</div>
                <div class="settings-hint">Where monitor change alerts are sent. Discord webhook URLs work out of the box.</div>
              </div>
              <div class="settings-control">
                <input type="text" id="monitor-webhook-input" value="" placeholder="${cfg.monitor_webhook_set ? 'Configured — enter a new URL to replace it' : 'https://discord.com/api/webhooks/...'}" class="form-control premium-input">
                <button class="btn btn-primary" onclick="window.SettingsPage.saveWebhookSettings()">Save</button>
              </div>
            </div>
          </div>
        </div>

        <div class="settings-section" data-tab="status">
          <div class="settings-section-header"> Cloudflare R2 Infrastructure</div>
          <div class="settings-section-body">
            ${item('R2 Status', cfg.r2_enabled ? 'Connected' : 'Not Configured', 'Cloud artifact storage', cfg.r2_enabled ? 'ok' : 'warn')}
            ${item('Storage Bucket', cfg.r2_bucket || '—', 'R2 target bucket')}
            ${item('Public Access URL', cfg.r2_public_url || '—', 'Base URL for indexed assets')}
          </div>
        </div>

        <div class="settings-section" data-tab="status">
          <div class="settings-section-header"> API Endpoints</div>
          <div class="settings-section-body">
          ${item('API Gateway', window.location.origin + '/api', 'Base endpoint for all requests')}
            ${item('Health Check', window.location.origin + '/health', 'Service status monitor')}
          </div>
        </div>
      </div>`;

    // Restore last-active tab (default: Platforms & Keys — the most-used surface).
    settingsTab(window.state._settingsTab || 'platforms');
  }

  // Show only the sections belonging to the chosen tab; highlight the active pill.
  function settingsTab(id) {
    window.state._settingsTab = id;
    const root = document.getElementById('settings-container');
    if (!root) return;
    root.querySelectorAll('.settings-tab').forEach((b) => {
      b.classList.toggle('active', b.dataset.tab === id);
    });
    root.querySelectorAll('.settings-section[data-tab]').forEach((s) => {
      s.style.display = s.dataset.tab === id ? '' : 'none';
    });
  }

  async function saveOpenRouterKey() {
    const input = document.getElementById('or-key-input');
    if (!input) return;
    const key = input.value.trim();
    try {
      const headers = await window.buildAuthHeaders({ 'Content-Type': 'application/json' });
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers,
        body: JSON.stringify({ openrouter_key: key })
      });
      if (!res.ok) throw new Error('Failed to update server config');
      
      if (key) localStorage.setItem('autoar_or_key', key);
      else localStorage.removeItem('autoar_or_key');

      window.showToast('success', 'Saved!', 'OpenRouter key updated on server.');
      input.value = '';
      try { window.state.config = await window.apiFetch('/api/config'); renderSettings(); } catch(_) {}
    } catch (e) {
      window.showToast('error', 'Error', e.message);
    }
  }

  async function saveGeminiKey() {
    const input = document.getElementById('gemini-key-input');
    if (!input) return;
    const key = input.value.trim();
    try {
      const headers = await window.buildAuthHeaders({ 'Content-Type': 'application/json' });
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers,
        body: JSON.stringify({ gemini_key: key })
      });
      if (!res.ok) throw new Error('Failed to update server config');

      if (key) localStorage.setItem('autoar_gemini_key', key);
      else localStorage.removeItem('autoar_gemini_key');

      window.showToast('success', 'Saved!', 'Gemini key updated on server.');
      input.value = '';
      try { window.state.config = await window.apiFetch('/api/config'); renderSettings(); } catch(_) {}
    } catch (e) {
      window.showToast('error', 'Error', e.message);
    }
  }

  async function saveOpenCodeKey() {
    const input = document.getElementById('opencode-key-input');
    if (!input) return;
    const key = input.value.trim();
    if (!key) {
      window.showToast('error', 'Empty key', 'Enter an OpenCode API key before saving.');
      return;
    }
    try {
      const headers = await window.buildAuthHeaders({ 'Content-Type': 'application/json' });
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers,
        body: JSON.stringify({ opencode_key: key })
      });
      if (!res.ok) throw new Error('Failed to update server config');
      window.showToast('success', 'Saved!', 'OpenCode key updated on server.');
      input.value = '';
      try { window.state.config = await window.apiFetch('/api/config'); renderSettings(); } catch(_) {}
    } catch (e) {
      window.showToast('error', 'Error', e.message);
    }
  }

  async function saveOpenCodeModel() {
    const input = document.getElementById('opencode-model-input');
    if (!input) return;
    const model = input.value.trim();
    try {
      const headers = await window.buildAuthHeaders({ 'Content-Type': 'application/json' });
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers,
        body: JSON.stringify({ opencode_model: model })
      });
      if (!res.ok) throw new Error('Failed to update OpenCode model');
      window.showToast('success', 'Saved!', model ? `OpenCode model set to "${model}".` : 'OpenCode model reset to default.');
      try { window.state.config = await window.apiFetch('/api/config'); renderSettings(); } catch(_) {}
    } catch (e) {
      window.showToast('error', 'Error', e.message);
    }
  }

  async function saveOpenRouterModel() {
    const input = document.getElementById('openrouter-model-input');
    if (!input) return;
    const model = input.value.trim();
    try {
      const headers = await window.buildAuthHeaders({ 'Content-Type': 'application/json' });
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers,
        body: JSON.stringify({ openrouter_model: model })
      });
      if (!res.ok) throw new Error('Failed to update OpenRouter model');
      window.showToast('success', 'Saved!', model ? `OpenRouter model set to "${model}".` : 'OpenRouter model reset to default.');
      try { window.state.config = await window.apiFetch('/api/config'); renderSettings(); } catch(_) {}
    } catch (e) {
      window.showToast('error', 'Error', e.message);
    }
  }

  async function saveTimeoutSettings() {
    const zdInput  = document.getElementById('timeout-zerodays-input');
    const nuInput  = document.getElementById('timeout-nuclei-input');
    const buInput  = document.getElementById('timeout-backup-input');
    const mcInput  = document.getElementById('timeout-misconfig-input');
    const kaInput  = document.getElementById('timeout-katana-input');
    const xsInput  = document.getElementById('timeout-xss-input');
    const btn      = document.getElementById('timeout-save-btn');
    const note     = document.getElementById('timeout-save-note');
    if (!zdInput || !nuInput || !buInput || !mcInput || !kaInput || !xsInput) return;
    const zdVal = parseInt(zdInput.value, 10);
    const nuVal = parseInt(nuInput.value, 10);
    const buVal = parseInt(buInput.value, 10);
    const mcVal = parseInt(mcInput.value, 10);
    const kaVal = parseInt(kaInput.value, 10);
    const xsVal = parseInt(xsInput.value, 10);
    if ([zdVal, nuVal, buVal, mcVal, kaVal, xsVal].some(v => isNaN(v) || v < 0)) {
      window.showToast('error', 'Invalid value', 'Timeouts must be 0 or a positive integer.');
      return;
    }
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
      const headers = await window.buildAuthHeaders({ 'Content-Type': 'application/json' });
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          timeout_zerodays: zdVal,
          timeout_nuclei:   nuVal,
          timeout_backup:   buVal,
          timeout_misconfig: mcVal,
          timeout_katana:   kaVal,
          timeout_xss:      xsVal,
        })
      });
      if (!res.ok) throw new Error('Failed to update timeout settings');
      window.showToast('success', 'Saved!', `Zerodays: ${zdVal}s · Nuclei: ${nuVal}s · Backup: ${buVal}s · Misconfig: ${mcVal}s · Katana: ${kaVal}s · XSS: ${xsVal}s  (0 = unlimited)`);
      if (note) note.textContent = ` Saved to DB at ${new Date().toLocaleTimeString()} — persists across redeployments`;
      try { window.state.config = await window.apiFetch('/api/config'); } catch(_) {}
    } catch (e) {
      window.showToast('error', 'Error', e.message);
    }
    if (btn) { btn.disabled = false; btn.textContent = ' Save all timeouts'; }
  }

  async function saveWebhookSettings() {
    const input = document.getElementById('monitor-webhook-input');
    if (!input) return;
    const webhook = input.value.trim();
    // The raw webhook is no longer returned by /api/config (it's a secret), so the
    // field renders empty; an empty submit means "no change" rather than clearing it.
    if (!webhook) {
      window.showToast('info', 'No change', 'Enter a webhook URL to set or replace the current one.');
      return;
    }
    try {
      const headers = await window.buildAuthHeaders({ 'Content-Type': 'application/json' });
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers,
        body: JSON.stringify({ monitor_webhook: webhook })
      });
      if (!res.ok) throw new Error('Failed to update webhook');
      window.showToast('success', 'Saved!', 'Notification webhook updated.');
      try { window.state.config = await window.apiFetch('/api/config'); } catch(_) {}
    } catch (e) {
      window.showToast('error', 'Error', e.message);
    }
  }

  // postSettings sends a partial settings body and reloads the config on success.
  async function postSettings(payload, successMsg) {
    const headers = await window.buildAuthHeaders({ 'Content-Type': 'application/json' });
    const res = await fetch('/api/settings', { method: 'POST', headers, body: JSON.stringify(payload) });
    if (!res.ok) throw new Error('Failed to update server config');
    window.showToast('success', 'Saved!', successMsg);
    try { window.state.config = await window.apiFetch('/api/config'); renderSettings(); } catch (_) {}
  }

  // Generic single-token save (Bugcrowd / Intigriti / YesWeHack). Empty = no change.
  async function savePlatformToken(field, inputId, label) {
    const input = document.getElementById(inputId);
    if (!input) return;
    const val = input.value.trim();
    if (!val) { window.showToast('info', 'No change', `Enter a ${label} value to set or replace it.`); return; }
    try {
      await postSettings({ [field]: val }, `${label} saved. Programs will refresh shortly.`);
    } catch (e) { window.showToast('error', 'Error', e.message); }
  }

  function saveBugcrowdToken()  { return savePlatformToken('bc_token', 'bc-token-input', 'Bugcrowd token'); }
  function saveIntigritiToken() { return savePlatformToken('it_token', 'it-token-input', 'Intigriti token'); }
  function saveYWHToken()       { return savePlatformToken('ywh_token', 'ywh-token-input', 'YesWeHack token'); }
  function saveChaosKey()       { return savePlatformToken('chaos_key', 'chaos-key-input', 'Chaos API key'); }

  async function saveH1Creds() {
    const u = document.getElementById('h1-username-input');
    const t = document.getElementById('h1-token-input');
    const username = u ? u.value.trim() : '';
    const token = t ? t.value.trim() : '';
    if (!username && !token) { window.showToast('info', 'No change', 'Enter a HackerOne username and/or token.'); return; }
    // Empty = keep current (the username is no longer pre-filled, so a blank field
    // must NOT clear it — only send when the user typed something).
    const body = {};
    if (username) body.h1_username = username;
    if (token) body.h1_token = token;
    try {
      await postSettings(body, 'HackerOne credentials saved. Programs will refresh shortly.');
      if (t) t.value = '';
    } catch (e) { window.showToast('error', 'Error', e.message); }
  }

  async function saveHackAdvisorCreds() {
    const t = document.getElementById('ha-token-input');
    const n = document.getElementById('ha-include-native-input');
    const token = t ? t.value.trim() : '';
    const body = {};
    if (token) body.ha_token = token;
    if (n) body.ha_include_native = n.checked; // bool → always sent so the toggle persists
    if (!token && !n) { window.showToast('info', 'No change', 'Enter a HackAdvisor token.'); return; }
    try {
      await postSettings(body, 'HackAdvisor saved — external targets will load on the next Programs refresh.');
      if (t) t.value = '';
    } catch (e) { window.showToast('error', 'Error', e.message); }
  }

  window.SettingsPage = {
    loadConfig,
    renderSettings,
    settingsTab,
    saveOpenRouterKey,
    saveOpenCodeKey,
    saveOpenCodeModel,
    saveOpenRouterModel,
    saveGeminiKey,
    saveTimeoutSettings,
    saveWebhookSettings,
    saveH1Creds,
    saveBugcrowdToken,
    saveIntigritiToken,
    saveYWHToken,
    saveHackAdvisorCreds,
    saveChaosKey,
  };
})();

(() => {
  const { esc, buildAuthHeaders, showToast, API, apiFetch } = window;

  async function loadConfig() {
    try {
      window.state.config = await apiFetch('/api/config');
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
        <div class="settings-value ${cls}">${esc(String(value ?? '—'))}</div>
      </div>`;

    el.innerHTML = `
      <div class="settings-container-premium">
        <div class="settings-section">
          <div class="settings-section-header">🔧 System Status</div>
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
                  ${cfg.auth_enabled ? '✅ Active' : '🔓 Public (Warning)'}
                </span>
              </div>
            </div>
          </div>
        </div>

        <div class="settings-section">
          <div class="settings-section-header">🤖 AI Intelligence</div>
          <div class="settings-section-body">
            <div class="settings-item">
              <div class="settings-label">
                <div class="settings-title">OpenRouter API Key</div>
                <div class="settings-hint">Used for vulnerability validation and reporting.</div>
              </div>
              <div class="settings-control">
                <input type="password" id="or-key-input"
                  value="${esc(localStorage.getItem('autoar_or_key') || '')}"
                  placeholder="sk-or-v1-…"
                  class="form-control premium-input">
                <button class="btn btn-primary" onclick="window.SettingsPage.saveOpenRouterKey()">Save</button>
              </div>
            </div>
            <div class="settings-item">
              <div class="settings-label">
                <div class="settings-title">Gemini API Key</div>
                <div class="settings-hint">Secondary fallback for AI analysis.</div>
              </div>
              <div class="settings-control">
                <input type="password" id="gemini-key-input"
                  value="${esc(localStorage.getItem('autoar_gemini_key') || '')}"
                  placeholder="AIza…"
                  class="form-control premium-input">
                <button class="btn btn-primary" onclick="window.SettingsPage.saveGeminiKey()">Save</button>
              </div>
            </div>
          </div>
        </div>

        <div class="settings-section">
          <div class="settings-section-header">⏱ Scan Phase Timeouts</div>
          <div class="settings-section-description">
            Define max duration for each scan phase. Set to <strong>0</strong> for unlimited. 
            Stored in DB, persists across redeployments.
          </div>
          <div class="settings-section-body">
            <div class="settings-timeout-grid">
              <div class="timeout-field">
                <label>⚡ Zerodays</label>
                <input id="timeout-zerodays-input" type="number" min="0" class="form-control premium-input" value="${esc(String(cfg.timeout_zerodays ?? 600))}" />
                <span>seconds</span>
              </div>
              <div class="timeout-field">
                <label>☢️ Nuclei</label>
                <input id="timeout-nuclei-input" type="number" min="0" class="form-control premium-input" value="${esc(String(cfg.timeout_nuclei ?? 1200))}" />
                <span>seconds</span>
              </div>
              <div class="timeout-field">
                <label>💾 Backup / Fuzzuli</label>
                <input id="timeout-backup-input" type="number" min="0" class="form-control premium-input" value="${esc(String(cfg.timeout_backup ?? 600))}" />
                <span>seconds</span>
              </div>
              <div class="timeout-field">
                <label>☁️ Misconfig</label>
                <input id="timeout-misconfig-input" type="number" min="0" class="form-control premium-input" value="${esc(String(cfg.timeout_misconfig ?? 1800))}" />
                <span>seconds</span>
              </div>
            </div>
            <div style="margin-top: 20px; display: flex; align-items: center; gap: 15px;">
              <button class="btn btn-primary" onclick="window.SettingsPage.saveTimeoutSettings()" id="timeout-save-btn">💾 Save All Timeouts</button>
              <div id="timeout-save-note" style="font-size:11px; color:var(--text-muted);">Persistence verified</div>
            </div>
          </div>
        </div>

        <div class="settings-section">
          <div class="settings-section-header">🔔 Notifications</div>
          <div class="settings-section-body">
            <div class="settings-item">
              <div class="settings-label">
                <div class="settings-title">Discord Webhook</div>
                <div class="settings-hint">Where scan notifications and findings are sent.</div>
              </div>
              <div class="settings-control">
                <input type="text" id="monitor-webhook-input" value="${esc(cfg.monitor_webhook || '')}" placeholder="https://discord.com/api/webhooks/..." class="form-control premium-input">
                <button class="btn btn-primary" onclick="window.SettingsPage.saveWebhookSettings()">Save</button>
              </div>
            </div>
          </div>
        </div>

        <div class="settings-section">
          <div class="settings-section-header">☁️ Cloudflare R2 Infrastructure</div>
          <div class="settings-section-body">
            ${item('R2 Status', cfg.r2_enabled ? 'Connected' : 'Not Configured', 'Cloud artifact storage', cfg.r2_enabled ? 'ok' : 'warn')}
            ${item('Storage Bucket', cfg.r2_bucket || '—', 'R2 target bucket')}
            ${item('Public Access URL', cfg.r2_public_url || '—', 'Base URL for indexed assets')}
          </div>
        </div>

        <div class="settings-section">
          <div class="settings-section-header">📡 API Endpoints</div>
          <div class="settings-section-body">
            ${item('API Gateway', window.location.origin + '/api', 'Base endpoint for all requests')}
            ${item('Health Check', window.location.origin + '/health', 'Service status monitor')}
          </div>
        </div>
      </div>`;
  }

  async function saveOpenRouterKey() {
    const input = document.getElementById('or-key-input');
    if (!input) return;
    const key = input.value.trim();
    try {
      const headers = await buildAuthHeaders({ 'Content-Type': 'application/json' });
      const res = await fetch(`${API}/api/settings`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ openrouter_key: key })
      });
      if (!res.ok) throw new Error('Failed to update server config');
      
      if (key) localStorage.setItem('autoar_or_key', key);
      else localStorage.removeItem('autoar_or_key');
      
      window.showToast('success', 'Saved!', 'OpenRouter key updated on server.');
    } catch (e) {
      window.showToast('error', 'Error', e.message);
    }
  }

  async function saveGeminiKey() {
    const input = document.getElementById('gemini-key-input');
    if (!input) return;
    const key = input.value.trim();
    try {
      const headers = await buildAuthHeaders({ 'Content-Type': 'application/json' });
      const res = await fetch(`${API}/api/settings`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ gemini_key: key })
      });
      if (!res.ok) throw new Error('Failed to update server config');
      
      if (key) localStorage.setItem('autoar_gemini_key', key);
      else localStorage.removeItem('autoar_gemini_key');
      
      window.showToast('success', 'Saved!', 'Gemini key updated on server.');
    } catch (e) {
      window.showToast('error', 'Error', e.message);
    }
  }

  async function saveTimeoutSettings() {
    const zdInput  = document.getElementById('timeout-zerodays-input');
    const nuInput  = document.getElementById('timeout-nuclei-input');
    const buInput  = document.getElementById('timeout-backup-input');
    const mcInput  = document.getElementById('timeout-misconfig-input');
    const btn      = document.getElementById('timeout-save-btn');
    const note     = document.getElementById('timeout-save-note');
    if (!zdInput || !nuInput || !buInput || !mcInput) return;
    const zdVal = parseInt(zdInput.value, 10);
    const nuVal = parseInt(nuInput.value, 10);
    const buVal = parseInt(buInput.value, 10);
    const mcVal = parseInt(mcInput.value, 10);
    if ([zdVal, nuVal, buVal, mcVal].some(v => isNaN(v) || v < 0)) {
      window.showToast('error', 'Invalid value', 'Timeouts must be 0 or a positive integer.');
      return;
    }
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
      const headers = await buildAuthHeaders({ 'Content-Type': 'application/json' });
      const res = await fetch(`${API}/api/settings`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          timeout_zerodays: zdVal,
          timeout_nuclei:   nuVal,
          timeout_backup:   buVal,
          timeout_misconfig: mcVal,
        })
      });
      if (!res.ok) throw new Error('Failed to update timeout settings');
      window.showToast('success', 'Saved!', `Zerodays: ${zdVal}s · Nuclei: ${nuVal}s · Backup: ${buVal}s · Misconfig: ${mcVal}s  (0 = unlimited)`);
      if (note) note.textContent = `✅ Saved to DB at ${new Date().toLocaleTimeString()} — persists across redeployments`;
      try { window.state.config = await apiFetch('/api/config'); } catch(_) {}
    } catch (e) {
      window.showToast('error', 'Error', e.message);
    }
    if (btn) { btn.disabled = false; btn.textContent = '💾 Save all timeouts'; }
  }

  async function saveWebhookSettings() {
    const input = document.getElementById('monitor-webhook-input');
    if (!input) return;
    const webhook = input.value.trim();
    try {
      const headers = await buildAuthHeaders({ 'Content-Type': 'application/json' });
      const res = await fetch(`${API}/api/settings`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ monitor_webhook: webhook })
      });
      if (!res.ok) throw new Error('Failed to update webhook');
      window.showToast('success', 'Saved!', 'Notification webhook updated.');
      try { window.state.config = await apiFetch('/api/config'); } catch(_) {}
    } catch (e) {
      window.showToast('error', 'Error', e.message);
    }
  }

  window.SettingsPage = {
    loadConfig,
    renderSettings,
    saveOpenRouterKey,
    saveGeminiKey,
    saveTimeoutSettings,
    saveWebhookSettings,
  };
})();

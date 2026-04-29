(() => {
  const PLATFORM_COLORS = {
    h1: { bg: '#1a2e1a', border: '#2a5a2a', accent: '#2ecc71', text: '#2ecc71' },
    bc: { bg: '#2e1e10', border: '#5a3820', accent: '#e67e22', text: '#e67e22' },
    ywh: { bg: '#10182e', border: '#1e2e5a', accent: '#3498db', text: '#3498db' },
    it: { bg: '#1e1028', border: '#3c1e55', accent: '#9b59b6', text: '#9b59b6' },
    immunefi: { bg: '#1a1a2e', border: '#2a2a55', accent: '#667eea', text: '#667eea' },
  };

  const targetsState = {
    platforms: [],
    selectedPlatform: null,
    credentials: {},
    domains: [],
    filtered: [],
  };

  function escapeSafe(s) {
    return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
  }

  function renderPlatformCredFields(p, colors) {
    if (!p.auth_fields || p.auth_fields.length === 0) return '';
    const creds = targetsState.credentials[p.id] || {};
    return p.auth_fields.map((field) => {
      const label = field.charAt(0).toUpperCase() + field.slice(1);
      const isPass = field === 'password' || field === 'token';
      return `
      <div style="margin-bottom:8px;">
        <label style="font-size:11px;font-weight:600;color:${colors.text};text-transform:uppercase;letter-spacing:0.05em;">${label}</label>
        <input type="${isPass ? 'password' : 'text'}"
          id="targets-cred-${p.id}-${field}"
          value="${escapeSafe(creds[field] || '')}"
          placeholder="${field === 'token' ? 'API Token' : field === 'username' ? 'Username' : field}"
          oninput="targetsUpdateCred('${p.id}','${field}',this.value)"
          style="width:100%;box-sizing:border-box;background:rgba(0,0,0,0.3);border:1px solid ${colors.border};
                 border-radius:8px;padding:7px 10px;color:#fff;font-size:12px;margin-top:4px;outline:none;" />
      </div>
    `;
    }).join('');
  }

  function renderTargetsPlatforms() {
    const grid = document.getElementById('targets-platforms-grid');
    if (!grid) return;
    grid.innerHTML = '';
    for (const p of targetsState.platforms) {
      const colors = PLATFORM_COLORS[p.id] || PLATFORM_COLORS.immunefi;
      const isSelected = targetsState.selectedPlatform === p.id;
      const card = document.createElement('div');
      card.id = `targets-platform-${p.id}`;
      card.style.cssText = `
      background:${colors.bg};border:2px solid ${isSelected ? colors.accent : colors.border};
      border-radius:16px;padding:20px;cursor:pointer;transition:all 0.2s;
      ${isSelected ? `box-shadow:0 0 24px ${colors.accent}33;` : ''}
    `;
      card.innerHTML = `
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">
        <span style="font-size:28px">${p.logo}</span>
        <div>
          <div style="font-weight:700;font-size:15px;color:${colors.text}">${p.name}</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:2px">
            ${p.env_configured
    ? `<span style="color:#2ecc71">✓ Credentials configured</span>`
    : `<span style="color:#e74c3c">⚠ Credentials needed</span>`}
          </div>
        </div>
      </div>
      <div style="font-size:12px;color:var(--text-muted);line-height:1.5;margin-bottom:14px">${p.description}</div>
      ${renderPlatformCredFields(p, colors)}
      <button onclick="targetsSelectPlatform('${p.id}')"
        style="width:100%;margin-top:14px;padding:9px;border-radius:10px;border:none;
               background:${isSelected ? colors.accent : colors.border};
               color:${isSelected ? '#fff' : colors.text};font-weight:600;font-size:13px;cursor:pointer;transition:all 0.2s;">
        ${isSelected ? '✓ Selected' : 'Select'}
      </button>
    `;
      card.addEventListener('mouseenter', () => {
        if (!isSelected) card.style.borderColor = colors.accent;
      });
      card.addEventListener('mouseleave', () => {
        if (!isSelected) card.style.borderColor = colors.border;
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
        extract_roots: true,
      };
      const data = await window.apiPost('/api/scope/fetch', body);
      targetsState.domains = data.root_domains || [];
      targetsState.filtered = [...targetsState.domains];

      const p = targetsState.platforms.find((x) => x.id === platformId);
      const header = document.getElementById('targets-result-header');
      if (header) header.textContent = `${data.domain_count} root domains from ${p?.name || platformId} (${data.programs} programs)`;

      const resultsCard = document.getElementById('targets-results-card');
      if (resultsCard) resultsCard.style.display = 'block';

      targetsRenderDomainList(targetsState.filtered);
      window.showToast('success', 'Done', `Fetched ${data.domain_count} root domains from ${data.programs} programs`);
    } catch (e) {
      window.showToast('error', 'Fetch failed', e.message);
    } finally {
      if (btn) { btn.textContent = 'Fetch Targets'; btn.disabled = false; }
    }
  }

  function targetsApplyFilter() {
    const q = (document.getElementById('targets-filter-input')?.value || '').toLowerCase();
    targetsState.filtered = q
      ? targetsState.domains.filter((d) => d.toLowerCase().includes(q))
      : [...targetsState.domains];
    targetsRenderDomainList(targetsState.filtered);
  }

  function targetsRenderDomainList(domains) {
    const container = document.getElementById('targets-domain-list');
    if (!container) return;
    if (!domains.length) {
      container.innerHTML = '<div style="padding:24px;text-align:center;color:var(--text-muted)">No domains found.</div>';
      return;
    }
    const colors = PLATFORM_COLORS[targetsState.selectedPlatform] || PLATFORM_COLORS.immunefi;
    container.innerHTML = `
    <table style="width:100%;border-collapse:collapse;font-size:13px;">
      <thead>
        <tr style="border-bottom:1px solid var(--border);">
          <th style="text-align:left;padding:8px 12px;color:var(--text-muted);font-weight:600;">#</th>
          <th style="text-align:left;padding:8px 12px;color:var(--text-muted);font-weight:600;">Root Domain</th>
          <th style="text-align:right;padding:8px 12px;color:var(--text-muted);font-weight:600;">Actions</th>
        </tr>
      </thead>
      <tbody>
        ${domains.map((d, i) => `
          <tr style="border-bottom:1px solid rgba(255,255,255,0.04);transition:background 0.15s;"
              onmouseenter="this.style.background='rgba(255,255,255,0.03)'"
              onmouseleave="this.style.background='transparent'">
            <td style="padding:9px 12px;color:var(--text-muted);width:40px">${i + 1}</td>
            <td style="padding:9px 12px;">
              <span style="color:${colors.text};font-family:monospace">${escapeSafe(d)}</span>
            </td>
            <td style="padding:9px 12px;text-align:right;">
              <div style="display:flex;gap:6px;justify-content:flex-end;">
                <button onclick="targetsAddDomain('${escapeSafe(d)}')"
                  style="padding:4px 12px;border-radius:8px;border:1px solid ${colors.border};
                         background:transparent;color:${colors.text};font-size:11px;cursor:pointer;">
                  + Add
                </button>
                <button onclick="targetsLaunchScan('${escapeSafe(d)}')"
                  style="padding:4px 12px;border-radius:8px;border:none;
                         background:${colors.accent};color:#fff;font-size:11px;cursor:pointer;font-weight:600;">
                  ▶ Scan
                </button>
              </div>
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
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

  function targetsLaunchScan(domain) {
    window.navigateTo('overview');
    setTimeout(() => {
      if (typeof window.openNewScanModal === 'function') {
        window.openNewScanModal({ target: domain, scanType: 'domain_run' });
      } else {
        window.showToast('info', 'Launch Scan', `Start a scan for ${domain} from the Scans page`);
      }
    }, 300);
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
  };
})();

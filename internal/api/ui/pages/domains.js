(function() {
  const DomainsPage = {
    renderDomainGrid() {
      const container = document.getElementById('domains-container');
      if (!container) return;
      const domains = window.state.domains?.domains || [];

      if (!domains.length) {
        container.innerHTML = window.emptyState('🌐', 'No domains tracked', 'Run a scan with autoar domain run -d <domain> to start tracking.');
        return;
      }

      const searchInput = document.getElementById('domain-search');
      const query = searchInput ? searchInput.value.toLowerCase() : '';
      const filtered = query ? domains.filter(d => d.domain.toLowerCase().includes(query)) : domains;

      container.innerHTML = `
        <div class="domain-grid">
          ${filtered.map(d => `
            <div class="domain-card" style="position:relative" onclick="window.loadDomainSubdomains('${window.esc(d.domain)}')">
              <button type="button" class="btn btn-ghost" style="position:absolute;top:8px;right:8px;z-index:1;padding:4px 10px;font-size:11px;color:var(--accent-red);border-color:rgba(248,113,113,.35)" onclick='event.stopPropagation();window.deleteDomainRecord(${JSON.stringify(d.domain)})'>Delete</button>
              <div class="domain-name" style="padding-right:76px">${window.esc(d.domain)}</div>
              <div class="domain-stats">
                <div class="domain-stat">
                  <div class="domain-stat-value" style="color:var(--accent-cyan)">${d.subdomain_count}</div>
                  <div class="domain-stat-label">subdomains</div>
                </div>
                <div class="domain-stat">
                  <div class="domain-stat-value" style="color:var(--accent-emerald)">${d.live_count}</div>
                  <div class="domain-stat-label">live</div>
                </div>
                <div class="domain-stat">
                  <div class="domain-stat-value" style="color:var(--text-muted)">${d.subdomain_count - d.live_count}</div>
                  <div class="domain-stat-label">dead</div>
                </div>
              </div>
            </div>`).join('')}
        </div>`;
    },

    renderSubdomainView(domain) {
      const container = document.getElementById('domains-container');
      if (!container) return;
      const subs = window.state.subdomains || [];

      const liveCount = subs.filter(s => s.IsLive || s.is_live).length;
      const searchInput = document.getElementById('subdomain-search');
      const q = searchInput ? searchInput.value.toLowerCase() : '';
      const filtered = q ? subs.filter(s => (s.Subdomain || s.subdomain || '').toLowerCase().includes(q)) : subs;
      const allSubNames = subs.map(s => s.Subdomain || s.subdomain || '').filter(Boolean);

      container.innerHTML = `
        <div style="display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:12px;margin-bottom:8px">
          <div onclick="window.backToDomains()" class="back-btn" style="margin:0">← Back to Domains</div>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button type="button" id="copy-domain-subs-btn" class="btn btn-ghost" style="font-size:12px;padding:6px 12px">
              📋 Copy All (${allSubNames.length})
            </button>
            <button type="button" class="btn btn-ghost" style="font-size:12px;padding:6px 12px;color:var(--accent-red);border-color:rgba(248,113,113,.35)" onclick='window.deleteDomainRecord(${JSON.stringify(domain)})'>
              Delete domain…
            </button>
          </div>
        </div>
        <div class="view-header">
          <div class="view-title">${window.esc(domain)}</div>
          <div class="view-subtitle">${subs.length} subdomains — ${liveCount} live / ${subs.length - liveCount} dead</div>
        </div>
        <div class="filter-bar" style="margin-bottom:16px">
          <input class="search-input" id="subdomain-search" placeholder="Filter subdomains…"
            oninput="window.renderSubdomainView('${window.esc(domain)}')" value="${q}">
        </div>
        <div class="card">
          <div class="card-body">
            <table class="data-table">
              <thead><tr>
                <th>Subdomain</th><th>Technology</th><th>CNAME</th><th>Status</th><th>HTTP</th><th>HTTPS</th>
              </tr></thead>
              <tbody>
                ${!filtered.length
          ? `<tr><td colspan="4" style="text-align:center;padding:40px;color:var(--text-muted)">No results</td></tr>`
          : filtered.map(s => {
            const subN = s.Subdomain || s.subdomain || '';
            const live = s.IsLive || s.is_live;
            const httpS = s.HTTPStatus || s.http_status || 0;
            const httpsS = s.HTTPSStatus || s.https_status || 0;

            const techsHtml = s.techs
              ? s.techs.split(',').filter(x => x).slice(0, 4).map(t => `<span style="display:inline-block;padding:2px 6px;margin:2px;background:rgba(255,255,255,0.08);border-radius:4px;font-size:10px;white-space:nowrap">${window.esc(t.trim())}</span>`).join('')
              : '<span style="color:var(--text-muted)">—</span>';

            const cnamesHtml = s.cnames
              ? `<div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:rgba(180,180,180,0.8);word-break:break-all">${window.esc(s.cnames)}</div>`
              : '<span style="color:var(--text-muted)">—</span>';

            const httpColor = (code) => {
              if (!code) return 'var(--text-muted)';
              if (code < 300) return '#10b981';
              if (code < 400) return '#f59e0b';
              if (code < 500) return '#ef4444';
              return '#8b5cf6';
            };

            return `<tr>
                        <td><span style="font-family:'JetBrains Mono',monospace;font-size:12px">${window.esc(subN)}</span></td>
                        <td><div style="display:flex;flex-wrap:wrap;min-width:140px">${techsHtml}</div></td>
                        <td>${cnamesHtml}</td>
                        <td>${live ? `<span class="badge badge-live">● live</span>` : `<span class="badge badge-dead">dead</span>`}</td>
                        <td><span style="font-size:12px;color:${httpColor(httpS)}">${httpS || '—'}</span></td>
                        <td><span style="font-size:12px;color:${httpColor(httpsS)}">${httpsS || '—'}</span></td>
                      </tr>`;
          }).join('')}
              </tbody>
            </table>
          </div>
        </div>`;

      // Wire copy button
      const copyDomainBtn = document.getElementById('copy-domain-subs-btn');
      if (copyDomainBtn) {
        copyDomainBtn.addEventListener('click', async () => {
          try {
            await window.copyToClipboard(allSubNames.join('\n'));
            window.showToast('success', 'Copied!', `${allSubNames.length} subdomains copied to clipboard`);
          } catch (e) {
            window.showToast('error', 'Copy failed', e.message);
          }
        });
      }
    },

    renderSubdomainsPage() {
      const container = document.getElementById('subdomains-container');
      if (!container) return;
      if (window.state.loading.subdomains) {
        container.innerHTML = window.emptyState('⏳', 'Loading subdomains…', 'Please wait while paginated results are loaded.');
        return;
      }
      if (window.state.error.subdomains) {
        container.innerHTML = window.emptyState('⚠️', 'Failed to load subdomains', window.esc(window.state.error.subdomains));
        return;
      }
      const subs = window.state.allSubdomains || [];
      const total = window.state.allSubdomainsTotal || 0;
      const page = window.state.subdomainsPage || 1;
      const limit = window.state.subdomainsLimit || 30;
      const pages = Math.max(1, Math.ceil(total / limit));

      if (!subs.length && !window.state.subdomainsSearch) {
        container.innerHTML = window.emptyState('🔗', 'No subdomains tracked', 'Run a scan with autoar domain run -d <domain> to start tracking.');
        return;
      }

      const codeColor = (code) => {
        if (!code) return 'var(--text-muted)';
        if (code < 300) return '#10b981';
        if (code < 400) return '#f59e0b';
        if (code < 500) return '#ef4444';
        return '#8b5cf6';
      };

      const renderRows = (list) => list.map(s => {
        const isLive = s.is_live;
        const dom = s.domain || '';
        const subN = s.subdomain || '';
        const httpS = s.http_status || 0;
        const httpsS = s.https_status || 0;

        const liveIcon = isLive
          ? `<span style="display:inline-flex;align-items:center;gap:5px;background:rgba(16,185,129,.15);border:1px solid rgba(16,185,129,.4);border-radius:20px;padding:3px 10px;font-size:11px;color:#10b981;white-space:nowrap"><span style="width:6px;height:6px;border-radius:50%;background:#10b981;box-shadow:0 0 5px #10b981;flex-shrink:0"></span>Alive</span>`
          : `<span style="display:inline-flex;align-items:center;gap:5px;background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.3);border-radius:20px;padding:3px 10px;font-size:11px;color:#ef4444;white-space:nowrap"><span style="width:6px;height:6px;border-radius:50%;background:#ef4444;flex-shrink:0"></span>Dead</span>`;

        const httpEl = httpS ? `<code style="font-size:13px;font-weight:700;color:${codeColor(httpS)}">${httpS}</code>` : `<span style="color:var(--text-muted)">—</span>`;
        const httpsEl = httpsS ? `<code style="font-size:13px;font-weight:700;color:${codeColor(httpsS)}">${httpsS}</code>` : `<span style="color:var(--text-muted)">—</span>`;

        const techsHtml = s.techs
          ? s.techs.split(',').filter(x => x).slice(0, 5).map(t => `<span style="display:inline-block;padding:2px 6px;margin:2px;background:rgba(255,255,255,0.08);border-radius:4px;font-size:10px;white-space:nowrap">${window.esc(t.trim())}</span>`).join('')
          : '<span style="color:var(--text-muted)">—</span>';

        const cnamesHtml = s.cnames
          ? `<div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:rgba(180,180,180,0.8);word-break:break-all">${window.esc(s.cnames)}</div>`
          : '<span style="color:var(--text-muted)">—</span>';

        return `<tr class="dashboard-table-row" style="border-bottom:1px solid rgba(255,255,255,.04)">
          <td style="padding:11px 14px">${liveIcon}</td>
          <td style="padding:11px 14px"><span style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-secondary)">${window.esc(dom)}</span></td>
          <td style="padding:11px 14px;max-width:260px"><span style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan);word-break:break-all">${window.esc(subN)}</span></td>
          <td style="padding:11px 14px"><div style="display:flex;flex-wrap:wrap;min-width:140px">${techsHtml}</div></td>
          <td style="padding:11px 14px;max-width:200px">${cnamesHtml}</td>
          <td style="padding:11px 14px;text-align:center">${httpEl}</td>
          <td style="padding:11px 14px;text-align:center">${httpsEl}</td>
        </tr>`;
      }).join('');

      container.innerHTML = `
        <div style="display:flex;flex-wrap:wrap;align-items:center;justify-content:flex-start;gap:12px;margin-bottom:14px">
          <div style="background:rgba(6,182,212,.08);border:1px solid rgba(6,182,212,.25);border-radius:8px;padding:8px 16px;display:flex;align-items:center;gap:8px">
            <span style="font-size:14px;font-weight:700;color:var(--accent-cyan)">${total}</span>
            <span style="font-size:12px;color:var(--text-secondary)">Total Subdomains Match</span>
          </div>
        </div>

        <div class="card" style="margin-bottom:12px">
          <div class="card-body" style="padding:0;overflow-x:auto">
            <table class="dashboard-table" style="width:100%;border-collapse:collapse;min-width:700px">
              <thead>
                <tr style="border-bottom:1px solid rgba(255,255,255,.05);background:rgba(0,0,0,.15)">
                  <th style="padding:12px 14px;text-align:left;font-size:11px;font-weight:800;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em;width:70px">Status</th>
                  <th style="padding:12px 14px;text-align:left;font-size:11px;font-weight:800;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em;width:130px">Domain</th>
                  <th style="padding:12px 14px;text-align:left;font-size:11px;font-weight:800;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em;width:240px">Subdomain</th>
                  <th style="padding:12px 14px;text-align:left;font-size:11px;font-weight:800;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em">Technology</th>
                  <th style="padding:12px 14px;text-align:left;font-size:11px;font-weight:800;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em;width:180px">CNAME</th>
                  <th style="padding:12px 14px;text-align:center;font-size:11px;font-weight:800;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em;width:60px">HTTP</th>
                  <th style="padding:12px 14px;text-align:center;font-size:11px;font-weight:800;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em;width:60px">HTTPS</th>
                </tr>
              </thead>
              <tbody>
                ${!subs.length ? '<tr><td colspan="7" style="text-align:center;padding:40px;color:var(--text-muted)">No subdomains found</td></tr>' : renderRows(subs)}
              </tbody>
            </table>
          </div>
        </div>

        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-top:12px">
          <div style="font-size:12px;color:var(--text-muted)">Showing page ${page} of ${pages}</div>
          <div style="display:flex;gap:6px">
            <button class="btn btn-ghost" style="padding:6px 12px;font-size:12px" ${page <= 1 ? 'disabled' : ''} onclick="window.changeSubdomainsPage(${page - 1})">Previous</button>
            <button class="btn btn-ghost" style="padding:6px 12px;font-size:12px" ${page >= pages ? 'disabled' : ''} onclick="window.changeSubdomainsPage(${page + 1})">Next</button>
          </div>
        </div>`;
    },

    backToDomains() {
      window.state.selectedDomain = null;
      const fb = document.getElementById('filter-bar-domains');
      if (fb) fb.style.display = '';
      this.renderDomainGrid();
    }
  };

  window.DomainsPage = DomainsPage;
})();

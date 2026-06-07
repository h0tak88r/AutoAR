(() => {
  const PLATFORM_COLORS = {
    h1: { bg: '#1a2e1a', border: '#2a5a2a', accent: '#2ecc71', text: '#2ecc71' },
    bc: { bg: '#2e1e10', border: '#5a3820', accent: '#e67e22', text: '#e67e22' },
    it: { bg: '#1a1430', border: '#3a2a6a', accent: '#9b8cff', text: '#b3a6ff' },
  };

  const PLATFORM_LABELS = { h1: 'H1', bc: 'BC', it: 'IT' };
  const STATE_LABELS = {
    public_mode: 'Public',
    soft_launched: 'Private',
    open: 'Open',
    closed: 'Closed',
    paused: 'Paused',
    launched: 'Launched',
  };

  let programsData = [];
  let tokenHints = [];
  let loadSeq = 0;
  let scopeLoadedCount = 0;
  let cacheWarm = false;
  let cacheStale = false;
  let cacheGeneratedAt = '';
  let sortState = { key: 'name', direction: 'asc' };

  function esc(s) {
    return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function relativeAge(value) {
    if (!value) return '';
    const then = new Date(value);
    if (Number.isNaN(then.getTime())) return '';
    const diffMs = Date.now() - then.getTime();
    const future = diffMs < 0;
    const abs = Math.abs(diffMs);
    const minute = 60 * 1000;
    const hour = 60 * minute;
    const day = 24 * hour;
    const month = 30 * day;
    const year = 365 * day;
    let count = Math.max(1, Math.floor(abs / minute));
    let unit = 'm';
    if (abs >= year) {
      count = Math.floor(abs / year);
      unit = 'y';
    } else if (abs >= month) {
      count = Math.floor(abs / month);
      unit = 'mo';
    } else if (abs >= day) {
      count = Math.floor(abs / day);
      unit = 'd';
    } else if (abs >= hour) {
      count = Math.floor(abs / hour);
      unit = 'h';
    }
    return future ? `in ${count}${unit}` : `${count}${unit} ago`;
  }

  function truncateText(value, max = 86) {
    const text = String(value || '').replace(/\s+/g, ' ').trim();
    if (text.length <= max) return text;
    return `${text.slice(0, max - 1).trim()}…`;
  }

  function programKey(p) {
    return `${String(p.platform || '').toLowerCase()}:${String(p.handle || '').toLowerCase()}`;
  }

  function renderStats(hydrating = false) {
    const statsBar = document.getElementById('programs-stats-bar');
    if (!statsBar) return;
    const h1Count = programsData.filter(p => p.platform === 'h1').length;
    const bcCount = programsData.filter(p => p.platform === 'bc').length;
    const itCount = programsData.filter(p => p.platform === 'it').length;
    const scopeCount = programsData.filter(p => p.latest_target || p.scope_targets > 0 || p._scope_loaded).length;
    const scopeStatus = hydrating
      ? `<span style="color:rgba(0,212,255,0.75);">Latest: <strong>${scopeLoadedCount}/${programsData.length}</strong> checked</span>`
      : scopeCount
        ? `<span style="color:rgba(0,212,255,0.75);">Latest: <strong>${scopeCount}</strong> ready</span>`
        : '';
    // Cache freshness: when served from the warm cache, show when it was built
    // and an explicit "refresh now" that rebuilds in the background.
    let cacheStatus = '';
    if (cacheWarm && cacheGeneratedAt) {
      const age = relativeAge(cacheGeneratedAt);
      const staleNote = cacheStale ? ' · refreshing…' : '';
      cacheStatus = ` · <span style="color:rgba(255,255,255,0.4);" title="${esc(cacheGeneratedAt)}">Updated ${esc(age)}${staleNote}</span> · <a href="#" onclick="window.ProgramsPage.refreshNow();return false;" style="color:rgba(0,212,255,0.75);text-decoration:none;">Refresh now</a>`;
    }
    statsBar.innerHTML = `<span>Total: <strong>${programsData.length}</strong> bounty programs</span><span style="color:#2ecc71;">H1: <strong>${h1Count}</strong></span><span style="color:#e67e22;">BC: <strong>${bcCount}</strong></span><span style="color:#b3a6ff;">IT: <strong>${itCount}</strong></span>${scopeStatus ? ` ${scopeStatus}` : ''}${cacheStatus}` + (tokenHints.length ? ` · ${tokenHints.join(' · ')}` : '');
  }

  function sortDirectionFor(key) {
    if (sortState.key !== key) return '';
    return sortState.direction === 'asc' ? ' ^' : ' v';
  }

  function sortHeader(label, key, align = 'left') {
    return `<th style="padding:8px 12px;text-align:${align};">
      <button type="button" onclick="window.ProgramsPage.setSort('${key}')" style="appearance:none;background:transparent;border:0;padding:0;color:rgba(255,255,255,0.45);font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:0;cursor:pointer;">${label}${sortDirectionFor(key)}</button>
    </th>`;
  }

  function sortValue(p, key) {
    switch (key) {
      case 'platform': return p.platform || '';
      case 'name': return p.name || '';
      case 'state': return p.state || '';
      case 'targets': return Number(p.scope_targets || 0);
      case 'latest': {
        const ts = Date.parse(p.latest_target_updated_at || '');
        return Number.isNaN(ts) ? 0 : ts;
      }
      case 'bounty': return p.currency || '';
      case 'payments': return p.fast_payments ? 1 : 0;
      case 'safe_harbor': return p.safe_harbor ? 1 : 0;
      default: return p.name || '';
    }
  }

  function comparePrograms(a, b) {
    const av = sortValue(a, sortState.key);
    const bv = sortValue(b, sortState.key);
    const dir = sortState.direction === 'asc' ? 1 : -1;
    if (typeof av === 'number' || typeof bv === 'number') {
      if (av === bv) return String(a.name || '').localeCompare(String(b.name || ''));
      return (av - bv) * dir;
    }
    return String(av).localeCompare(String(bv), undefined, { sensitivity: 'base' }) * dir;
  }

  function setSort(key) {
    if (sortState.key === key) {
      sortState.direction = sortState.direction === 'asc' ? 'desc' : 'asc';
    } else {
      sortState = { key, direction: ['latest', 'targets', 'payments', 'safe_harbor'].includes(key) ? 'desc' : 'asc' };
    }
    renderPrograms();
  }

  function mergeScopeSummary(program, summary) {
    program.scope_targets = summary.scope_targets || 0;
    program.latest_target = summary.latest_target || '';
    program.latest_target_updated_at = summary.latest_target_updated_at || '';
    program.latest_target_brief = summary.latest_target_brief || '';
    program._scope_loaded = true;
    program._scope_loading = false;
  }

  async function hydrateScopeSummaries(seq) {
    const batchSize = 40;
    const candidates = programsData.filter(p => p.platform && p.handle);
    scopeLoadedCount = 0;
    for (let i = 0; i < candidates.length; i += batchSize) {
      if (seq !== loadSeq) return;
      const batch = candidates.slice(i, i + batchSize);
      batch.forEach(p => { p._scope_loading = true; });
      renderStats(true);
      renderPrograms();

      try {
        const res = await window.apiPost('/api/scope/program-summaries', {
          programs: batch.map(p => ({ platform: p.platform, handle: p.handle, url: p.url })),
        });
        const summaries = res.summaries || {};
        batch.forEach(p => {
          const summary = summaries[programKey(p)] || summaries[`${p.platform}:${p.handle}`];
          if (summary) mergeScopeSummary(p, summary);
          else {
            p._scope_loaded = true;
            p._scope_loading = false;
          }
        });
      } catch (e) {
        batch.forEach(p => { p._scope_loading = false; });
      }

      scopeLoadedCount = Math.min(candidates.length, i + batch.length);
      renderStats(i + batch.length < candidates.length);
      renderPrograms();
      await new Promise(resolve => setTimeout(resolve, 80));
    }
    renderStats(false);
  }

  async function loadPrograms(force = false) {
    const seq = ++loadSeq;
    const platform = document.getElementById('programs-platform-filter')?.value || 'all';
    const container = document.getElementById('programs-container');
    if (container) container.innerHTML = '<div class="empty-state"><div class="empty-icon">...</div><div class="empty-title">Loading programs…</div></div>';

    try {
      const params = new URLSearchParams({ platform, sort: 'name' });
      if (force) params.set('refresh', 'true');
      const data = await window.apiFetch('/api/scope/programs?' + params.toString());
      if (seq !== loadSeq) return;
      programsData = data.programs || [];
      cacheWarm = !!data.warm;
      cacheStale = !!data.stale;
      cacheGeneratedAt = data.generated_at || '';

      tokenHints = [];
      if (!data.has_h1_token) tokenHints.push('<span style="color:rgba(255,255,255,0.35);">H1 token not set — latest scope requires H1 auth</span>');
      if (!data.has_bc_token) tokenHints.push('<span style="color:rgba(255,255,255,0.35);">BC token not set — set BUGCROWD_TOKEN to load Bugcrowd programs</span>');
      if (!data.has_it_token) tokenHints.push('<span style="color:rgba(255,255,255,0.35);">Intigriti token not set — set INTIGRITI_TOKEN to load Intigriti programs</span>');

      if (data.scope_included) {
        // Warm cache already carries scope counts + latest targets — no per-program
        // hydration needed. The whole table renders fully populated in one shot.
        scopeLoadedCount = programsData.length;
        programsData.forEach(p => { p._scope_loaded = true; });
        renderPrograms();
        renderStats(false);
      } else {
        // Cold path: base list only — fill the scope column progressively.
        scopeLoadedCount = 0;
        renderPrograms();
        renderStats(false);
        hydrateScopeSummaries(seq);
      }
    } catch (e) {
      if (container) container.innerHTML = `<div class="empty-state"><div class="empty-icon">!</div><div class="empty-title">Failed to load</div><div class="empty-sub">${esc(e.message)}</div></div>`;
      tokenHints = [];
      renderStats(false);
    }
  }

  // refreshNow forces a server-side cache rebuild (in the background) and reloads
  // the fresh data once it has likely finished.
  function refreshNow() {
    if (window.showToast) window.showToast('info', 'Refreshing', 'Rebuilding the program cache in the background…');
    loadPrograms(true);
    setTimeout(() => { if (window.state && window.state.view === 'programs') loadPrograms(false); }, 30000);
  }

  function renderPrograms() {
    const container = document.getElementById('programs-container');
    if (!container) return;

    const query = (document.getElementById('programs-search')?.value || '').toLowerCase();
    let filtered = programsData;
    if (query) {
      filtered = programsData.filter(p =>
        (p.name || '').toLowerCase().includes(query) ||
        (p.handle || '').toLowerCase().includes(query) ||
        (p.latest_target || '').toLowerCase().includes(query) ||
        (p.latest_target_brief || '').toLowerCase().includes(query)
      );
    }
    filtered = filtered.slice().sort(comparePrograms);

    if (filtered.length === 0) {
      container.innerHTML = '<div class="empty-state"><div class="empty-icon">0</div><div class="empty-title">No programs found</div><div class="empty-sub">Try adjusting your filters or check your API credentials</div></div>';
      return;
    }

    const rows = filtered.map(p => {
      const colors = PLATFORM_COLORS[p.platform] || PLATFORM_COLORS.h1;
      const badge = PLATFORM_LABELS[p.platform] || p.platform.toUpperCase();
      const stateLabel = STATE_LABELS[p.state] || p.state || '?';
      const latestAge = relativeAge(p.latest_target_updated_at);
      const latestBrief = truncateText(p.latest_target_brief || '');
      const latestTitle = [p.latest_target, latestAge, p.latest_target_brief].filter(Boolean).join(' | ');
      const latestCell = p.latest_target
        ? `<div style="display:flex;flex-direction:column;gap:5px;min-width:0;">
            <div style="display:flex;align-items:center;gap:6px;min-width:0;flex-wrap:wrap;">
              <span style="display:inline-block;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px;padding:3px 7px;border-radius:4px;background:rgba(0,212,255,0.08);color:#9be8ff;border:1px solid rgba(0,212,255,0.18);" title="${esc(latestTitle)}">${esc(p.latest_target)}</span>
              ${latestAge ? `<span style="font-size:10px;padding:3px 6px;border-radius:4px;background:rgba(255,255,255,0.06);color:rgba(255,255,255,0.6);" title="${esc(p.latest_target_updated_at)}">${esc(latestAge)}</span>` : ''}
            </div>
            ${latestBrief ? `<div style="font-size:10px;line-height:1.35;color:rgba(255,255,255,0.45);max-width:280px;white-space:normal;">${esc(latestBrief)}</div>` : ''}
          </div>`
        : p._scope_loading
          ? '<span style="font-size:10px;padding:3px 6px;border-radius:4px;background:rgba(255,255,255,0.06);color:rgba(255,255,255,0.45);">checking...</span>'
        : '<span style="color:rgba(255,255,255,0.25);">-</span>';

      return `
      <tr class="program-row" style="border-bottom:1px solid rgba(255,255,255,0.04);transition:background 0.15s;">
        <td style="padding:10px 12px;">
          <div style="display:flex;align-items:center;gap:8px;">
            <span style="display:inline-block;padding:2px 6px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:0.05em;background:${colors.bg};color:${colors.text};border:1px solid ${colors.border};">${badge}</span>
            <span style="color:#${p.offers_bounties ? '2ecc71' : '888'};font-size:10px;" title="${p.offers_bounties ? 'Offers bounties' : 'No bounties'}">${p.offers_bounties ? '$' : '-'}</span>
          </div>
        </td>
        <td style="padding:10px 12px;">
          <a href="${esc(p.url)}" target="_blank" rel="noopener" style="color:#fff;text-decoration:none;font-weight:600;font-size:13px;" onmouseenter="this.style.textDecoration='underline'" onmouseleave="this.style.textDecoration='none'">${esc(p.name)}</a>
          <div style="font-size:10px;color:rgba(255,255,255,0.35);">${esc(p.handle)}</div>
        </td>
        <td style="padding:10px 12px;">
          <span style="font-size:11px;padding:3px 8px;border-radius:12px;background:${stateColor(p.state)};color:${stateTextColor(p.state)};font-weight:500;">${stateLabel}</span>
          ${p.submission_state && p.submission_state !== p.state ? `<span style="font-size:10px;padding:3px 8px;border-radius:12px;background:rgba(255,255,255,0.06);color:rgba(255,255,255,0.5);margin-left:4px;">${esc(p.submission_state)}</span>` : ''}
        </td>
        <td style="padding:10px 12px;text-align:center;font-size:12px;color:rgba(255,255,255,0.6);">
          ${p.scope_targets > 0 ? `<strong style="color:#fff;">${p.scope_targets}</strong>` : '<span style="color:rgba(255,255,255,0.25);">-</span>'}
        </td>
        <td style="padding:10px 12px;max-width:320px;">
          ${latestCell}
        </td>
        <td style="padding:10px 12px;text-align:center;">
          ${p.offers_bounties ? `<span style="font-size:12px;color:#2ecc71;">${esc(p.currency.toUpperCase())}</span>` : '<span style="color:rgba(255,255,255,0.2);">-</span>'}
        </td>
        <td style="padding:10px 12px;text-align:center;">
          ${p.fast_payments ? '<span style="font-size:10px;padding:2px 6px;border-radius:4px;background:rgba(46,204,113,0.15);color:#2ecc71;">Fast</span>' : '<span style="color:rgba(255,255,255,0.2);">-</span>'}
        </td>
        <td style="padding:10px 12px;text-align:center;">
          ${p.safe_harbor ? '<span style="font-size:10px;padding:2px 6px;border-radius:4px;background:rgba(52,152,219,0.15);color:#3498db;">SH</span>' : '<span style="color:rgba(255,255,255,0.2);">-</span>'}
        </td>
      </tr>`;
    }).join('');

    container.innerHTML = `
      <div style="overflow-x:auto;">
        <table style="width:100%;border-collapse:collapse;">
          <thead>
            <tr style="border-bottom:1px solid rgba(255,255,255,0.08);">
              ${sortHeader('Platform', 'platform')}
              ${sortHeader('Program', 'name')}
              ${sortHeader('State', 'state')}
              ${sortHeader('Targets', 'targets', 'center')}
              ${sortHeader('Latest In-Scope', 'latest')}
              ${sortHeader('Bounty', 'bounty', 'center')}
              ${sortHeader('Payments', 'payments', 'center')}
              ${sortHeader('Safe Harbor', 'safe_harbor', 'center')}
            </tr>
          </thead>
          <tbody>
            ${rows}
          </tbody>
        </table>
      </div>`;
  }

  function stateColor(state) {
    switch (state) {
      case 'public_mode': return 'rgba(46,204,113,0.15)';
      case 'soft_launched': return 'rgba(155,89,182,0.15)';
      case 'open': return 'rgba(46,204,113,0.15)';
      case 'launched': return 'rgba(46,204,113,0.15)';
      case 'closed': return 'rgba(231,76,60,0.15)';
      case 'paused': return 'rgba(241,196,15,0.15)';
      default: return 'rgba(255,255,255,0.06)';
    }
  }

  function stateTextColor(state) {
    switch (state) {
      case 'public_mode': return '#2ecc71';
      case 'soft_launched': return '#9b59b6';
      case 'open': return '#2ecc71';
      case 'launched': return '#2ecc71';
      case 'closed': return '#e74c3c';
      case 'paused': return '#f1c40f';
      default: return 'rgba(255,255,255,0.5)';
    }
  }

  window.ProgramsPage = { loadPrograms, renderPrograms, setSort, refreshNow };
})();

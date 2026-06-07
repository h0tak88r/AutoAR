(() => {
  const PLATFORM_COLORS = {
    h1: { bg: '#1a2e1a', border: '#2a5a2a', accent: '#2ecc71', text: '#2ecc71' },
    bc: { bg: '#2e1e10', border: '#5a3820', accent: '#e67e22', text: '#e67e22' },
  };

  const PLATFORM_LABELS = { h1: 'H1', bc: 'BC' };
  const STATE_LABELS = {
    public_mode: 'Public',
    soft_launched: 'Private',
    open: 'Open',
    closed: 'Closed',
    paused: 'Paused',
    launched: 'Launched',
  };

  let programsData = [];

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

  async function loadPrograms() {
    const platform = document.getElementById('programs-platform-filter')?.value || 'all';
    const container = document.getElementById('programs-container');
    const statsBar = document.getElementById('programs-stats-bar');
    if (container) container.innerHTML = '<div class="empty-state"><div class="empty-icon">...</div><div class="empty-title">Loading programs…</div></div>';

    try {
      const params = new URLSearchParams({ platform, sort: 'name' });
      const data = await window.apiFetch('/api/scope/programs?' + params.toString());
      programsData = data.programs || [];

      // Show token status hints
      const hints = [];
      if (!data.has_h1_token) hints.push('<span style="color:rgba(255,255,255,0.35);">H1 token not set — showing public programs only</span>');
      if (!data.has_bc_token) hints.push('<span style="color:rgba(255,255,255,0.35);">BC token not set — set BUGCROWD_TOKEN to load Bugcrowd programs</span>');

      renderPrograms();
      if (statsBar) {
        const h1Count = programsData.filter(p => p.platform === 'h1').length;
        const bcCount = programsData.filter(p => p.platform === 'bc').length;
        statsBar.innerHTML = `<span>Total: <strong>${programsData.length}</strong> programs</span><span style="color:#2ecc71;">H1: <strong>${h1Count}</strong></span><span style="color:#e67e22;">BC: <strong>${bcCount}</strong></span>` + (hints.length ? ` · ${hints.join(' · ')}` : '');
      }
    } catch (e) {
      if (container) container.innerHTML = `<div class="empty-state"><div class="empty-icon">!</div><div class="empty-title">Failed to load</div><div class="empty-sub">${esc(e.message)}</div></div>`;
      if (statsBar) statsBar.innerHTML = '';
    }
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
              <th style="padding:8px 12px;text-align:left;font-size:10px;font-weight:600;color:rgba(255,255,255,0.4);text-transform:uppercase;letter-spacing:0.05em;">Platform</th>
              <th style="padding:8px 12px;text-align:left;font-size:10px;font-weight:600;color:rgba(255,255,255,0.4);text-transform:uppercase;letter-spacing:0.05em;">Program</th>
              <th style="padding:8px 12px;text-align:left;font-size:10px;font-weight:600;color:rgba(255,255,255,0.4);text-transform:uppercase;letter-spacing:0.05em;">State</th>
              <th style="padding:8px 12px;text-align:center;font-size:10px;font-weight:600;color:rgba(255,255,255,0.4);text-transform:uppercase;letter-spacing:0.05em;">Targets</th>
              <th style="padding:8px 12px;text-align:left;font-size:10px;font-weight:600;color:rgba(255,255,255,0.4);text-transform:uppercase;letter-spacing:0.05em;">Latest In-Scope</th>
              <th style="padding:8px 12px;text-align:center;font-size:10px;font-weight:600;color:rgba(255,255,255,0.4);text-transform:uppercase;letter-spacing:0.05em;">Bounty</th>
              <th style="padding:8px 12px;text-align:center;font-size:10px;font-weight:600;color:rgba(255,255,255,0.4);text-transform:uppercase;letter-spacing:0.05em;">Payments</th>
              <th style="padding:8px 12px;text-align:center;font-size:10px;font-weight:600;color:rgba(255,255,255,0.4);text-transform:uppercase;letter-spacing:0.05em;">Safe Harbor</th>
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

  window.ProgramsPage = { loadPrograms, renderPrograms };
})();

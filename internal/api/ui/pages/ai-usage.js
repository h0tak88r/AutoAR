(() => {
  // Overview ▸ AI usage: what the AI provider has cost, from per-call token
  // metering (GET /api/ai/usage). Admin-only; the card stays hidden otherwise.
  const esc = (v) =>
    window.esc ? window.esc(v) : String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const $ = (id) => document.getElementById(id);
  const num = (v) => Number(v) || 0;

  const FEATURE_LABEL = {
    triage: 'AI Triage', agent: 'AI Agent', report: 'Report writer', validate: 'Finding validation',
    monitor: 'Monitor URL ranking', test: 'Provider test', other: 'Other',
  };

  // Spend is usually cents: keep enough digits that small numbers aren't "$0.00".
  function usd(v) {
    v = num(v);
    if (v === 0) return '$0.00';
    if (v < 0.1) return '$' + v.toFixed(4);
    if (v < 1) return '$' + v.toFixed(3);
    return '$' + v.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  }
  function compact(n) {
    n = num(n);
    if (n >= 1e9) return (n / 1e9).toFixed(1).replace(/\.0$/, '') + 'B';
    if (n >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, '') + 'M';
    if (n >= 1e3) return (n / 1e3).toFixed(1).replace(/\.0$/, '') + 'K';
    return String(n);
  }
  const tokens = (t) => num(t.prompt_tokens) + num(t.completion_tokens);
  const cacheRate = (t) => (num(t.prompt_tokens) ? Math.round((num(t.cache_hit_tokens) / num(t.prompt_tokens)) * 100) : 0);
  function shortDay(day) {
    const d = new Date(day + 'T00:00:00Z');
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', timeZone: 'UTC' });
  }

  function tile(label, value, sub, extraClass = '') {
    return `<div class="au-tile ${extraClass}"><div class="au-tile-label">${esc(label)}</div>
      <div class="au-tile-value">${value}</div><div class="au-tile-sub">${sub}</div></div>`;
  }

  function balanceTile(d) {
    const b = d.balance;
    if (!b || !Array.isArray(b.infos) || !b.infos.length) {
      const why = d.provider && d.provider.id !== 'deepseek'
        ? `${esc(d.provider.name)} has no balance API`
        : esc(d.balance_error || 'No API key configured');
      return tile('Account balance', '—', why);
    }
    // Prefer USD; DeepSeek can hold a CNY balance too.
    const i = b.infos.find((x) => x.currency === 'USD') || b.infos[0];
    const sym = i.currency === 'USD' ? '$' : '';
    const unit = i.currency === 'USD' ? '' : ` ${esc(i.currency)}`;
    const value = `${sym}${esc(i.total)}${unit}`;
    const sub = b.available
      ? `Topped up ${sym}${esc(i.topped_up)} · granted ${sym}${esc(i.granted)}`
      : '<span class="au-warn">Too low for API calls: top up</span>';
    return tile('DeepSeek balance', value, sub, b.available ? '' : 'au-tile-warn');
  }

  // ── Daily chart: one series, so bars in the accent colour, no legend; the
  // card title names it. Hover/focus shows a tooltip; a table view follows.
  // Drawn at the container's real pixel width (not a stretched viewBox) so
  // axis text keeps its size; render() redraws on resize.
  function chart(daily, metric, width) {
    const val = (d) => (metric === 'cost' ? num(d.cost_usd) : tokens(d));
    const fmt = (v) => (metric === 'cost' ? usd(v) : compact(v) + ' tok');
    const W = Math.max(320, Math.round(width || 720)), H = 168, padL = 52, padR = 8, padT = 10, padB = 24;
    const plotW = W - padL - padR, plotH = H - padT - padB;
    const maxV = Math.max(0, ...daily.map(val));
    // Clean ticks: 1/2/5 × 10^n above the max.
    const niceMax = (() => {
      if (maxV <= 0) return metric === 'cost' ? 0.01 : 10;
      const p = 10 ** Math.floor(Math.log10(maxV));
      for (const m of [1, 2, 5, 10]) if (m * p >= maxV) return m * p;
      return 10 * p;
    })();
    const ticks = [0, niceMax / 2, niceMax];
    // One decimal count for every tick, picked from the scale ($0.05 / $0.10).
    const tickFmt = (v) => {
      if (metric !== 'cost') return compact(v);
      const dp = niceMax >= 0.1 ? 2 : niceMax >= 0.01 ? 3 : 4;
      return '$' + v.toFixed(dp);
    };
    const slot = plotW / daily.length;
    const bw = Math.min(24, Math.max(2, slot - 2)); // ≤24px thick, ≥2px gap
    const y = (v) => padT + plotH - (v / niceMax) * plotH;
    const grid = ticks.map((t) => `<line x1="${padL}" x2="${W - padR}" y1="${y(t)}" y2="${y(t)}" class="au-grid"/>
      <text x="${padL - 8}" y="${y(t) + 4}" text-anchor="end" class="au-axis">${esc(tickFmt(t))}</text>`).join('');
    const bars = daily.map((d, i) => {
      const v = val(d);
      const h = v > 0 ? Math.max(2, (v / niceMax) * plotH) : 0;
      const x = padL + i * slot + (slot - bw) / 2;
      const top = padT + plotH - h;
      const r = Math.min(4, h, bw / 2);
      // 4px rounded data end, square at the baseline.
      const shape = h > 0
        ? `<path class="au-bar" d="M${x},${padT + plotH} V${top + r} Q${x},${top} ${x + r},${top} H${x + bw - r} Q${x + bw},${top} ${x + bw},${top + r} V${padT + plotH} Z"/>`
        : '';
      const tip = `${shortDay(d.day)} · ${usd(d.cost_usd)} · ${num(d.calls)} call${num(d.calls) === 1 ? '' : 's'} · ${compact(tokens(d))} tokens`;
      // Hit target = the whole day column, taller and wider than the bar.
      return `<g class="au-col" tabindex="0" data-tip="${esc(tip)}" aria-label="${esc(tip)}">
        <rect class="au-hit" x="${padL + i * slot}" y="${padT}" width="${slot}" height="${plotH}"/>${shape}</g>`;
    }).join('');
    const labelIdx = new Set([0, Math.floor(daily.length / 3), Math.floor((2 * daily.length) / 3), daily.length - 1]);
    const xlabels = daily.map((d, i) => (labelIdx.has(i)
      ? `<text x="${padL + i * slot + slot / 2}" y="${H - 6}" text-anchor="middle" class="au-axis">${esc(i === daily.length - 1 ? 'Today' : shortDay(d.day))}</text>`
      : '')).join('');
    const total = daily.reduce((s, d) => s + val(d), 0);
    return `<div class="au-chart">
      <svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img"
        aria-label="${esc(`Daily ${metric === 'cost' ? 'spend' : 'tokens'}, last ${daily.length} days, total ${fmt(total)}`)}">
        ${grid}<line x1="${padL}" x2="${W - padR}" y1="${padT + plotH}" y2="${padT + plotH}" class="au-baseline"/>${bars}${xlabels}
      </svg>
      <div class="au-tip" role="tooltip" hidden></div>
    </div>`;
  }

  function dailyTable(daily) {
    const rows = daily.slice().reverse().filter((d) => num(d.calls)).map((d) =>
      `<tr><td>${esc(d.day)}</td><td class="au-num">${num(d.calls)}</td><td class="au-num">${compact(tokens(d))}</td><td class="au-num">${usd(d.cost_usd)}</td></tr>`).join('');
    return `<details class="au-details"><summary>Daily table</summary>
      ${rows ? `<table class="au-table"><thead><tr><th>Day</th><th class="au-num">Calls</th><th class="au-num">Tokens</th><th class="au-num">Cost</th></tr></thead><tbody>${rows}</tbody></table>`
        : '<div class="au-empty-line">No calls in the last 30 days.</div>'}</details>`;
  }

  function featureTable(groups, total) {
    if (!groups.length) return '';
    const rows = groups.map((g) => {
      const share = num(total.cost_usd) ? Math.round((num(g.cost_usd) / num(total.cost_usd)) * 100) : 0;
      return `<tr>
        <td>${esc(FEATURE_LABEL[g.key] || g.key || 'Other')}</td>
        <td class="au-num">${num(g.calls)}${num(g.errors) ? ` <span class="au-err">(${num(g.errors)} failed)</span>` : ''}</td>
        <td class="au-num">${compact(g.prompt_tokens)} <span class="au-dim">${cacheRate(g)}% cached</span></td>
        <td class="au-num">${compact(g.completion_tokens)}</td>
        <td class="au-num">${usd(g.cost_usd)}</td>
        <td class="au-share"><span class="au-sharebar"><i style="--w:${share}%"></i></span><span class="au-dim">${share}%</span></td>
      </tr>`;
    }).join('');
    return `<table class="au-table au-features">
      <thead><tr><th>Feature (30 days)</th><th class="au-num">Calls</th><th class="au-num">Input</th><th class="au-num">Output</th><th class="au-num">Cost</th><th>Share</th></tr></thead>
      <tbody>${rows}</tbody></table>`;
  }

  function wireTooltip(root) {
    const box = root.querySelector('.au-chart');
    const tip = root.querySelector('.au-tip');
    if (!box || !tip) return;
    const show = (g) => {
      tip.textContent = g.dataset.tip;
      tip.hidden = false;
      const br = box.getBoundingClientRect();
      const r = g.getBoundingClientRect();
      // Keep the whole tooltip inside the chart: clamp by its real width.
      const half = tip.offsetWidth / 2 + 4;
      const left = Math.min(Math.max(r.left - br.left + r.width / 2, half), br.width - half);
      tip.style.left = left + 'px';
      g.classList.add('on');
    };
    const hide = (g) => { tip.hidden = true; g.classList.remove('on'); };
    box.querySelectorAll('.au-col').forEach((g) => {
      g.addEventListener('mouseenter', () => show(g));
      g.addEventListener('mouseleave', () => hide(g));
      g.addEventListener('focus', () => show(g));
      g.addEventListener('blur', () => hide(g));
    });
  }

  function render(d) {
    const body = $('ai-usage-body');
    const meta = $('ai-usage-meta');
    if (!body) return;
    const T = d.totals || {};
    const today = T.today || {}, d30 = T['30d'] || {}, all = T.all || {};
    const p = d.provider || {};
    const pr = d.pricing;
    if (meta) {
      const price = pr && pr.now
        ? ` · ${pr.peak_now ? 'peak' : 'off-peak'} now: $${pr.now.cache_miss} in / $${pr.now.output} out per 1M`
        : '';
      meta.textContent = `${p.name || p.id || 'No provider'} · ${p.model || '—'}${price}`;
    }
    const since = num(d.tracking_since);
    const sinceTxt = since ? new Date(since * 1000).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' }) : '';
    const unpriced = num(d30.unpriced_calls);

    const daily = d.daily || [];
    const anyCost = daily.some((x) => num(x.cost_usd) > 0);
    const anyCalls = daily.some((x) => num(x.calls) > 0);
    const metric = anyCost || !anyCalls ? 'cost' : 'tokens';

    body.innerHTML = `
      <div class="au-tiles">
        ${tile('Spent today', usd(today.cost_usd), `${num(today.calls)} call${num(today.calls) === 1 ? '' : 's'} · ${compact(tokens(today))} tokens`)}
        ${tile('Last 30 days', usd(d30.cost_usd), `${num(d30.calls)} calls · ${cacheRate(d30)}% input cached${num(d30.errors) ? ` · <span class="au-err">${num(d30.errors)} failed</span>` : ''}`)}
        ${tile('Since tracking began', usd(all.cost_usd), since ? `since ${esc(sinceTxt)} · ${compact(tokens(all))} tokens` : 'no calls recorded yet')}
        ${balanceTile(d)}
      </div>
      <div class="au-section-title">${metric === 'cost' ? 'Daily spend' : 'Daily tokens (this provider has no list price)'} · last 30 days</div>
      ${chart(daily, metric, body.clientWidth - 40)}
      ${dailyTable(daily)}
      ${featureTable(d.by_feature || [], d30)}
      <p class="au-note">
        Cost is computed per call from the provider's own token counts${pr ? ` and DeepSeek's list price (peak or off-peak at call time; prices checked ${esc(pr.checked)})` : ''}.
        ${unpriced ? `<b>${unpriced} call${unpriced === 1 ? ' has' : 's have'} no list price</b> and ${unpriced === 1 ? 'is' : 'are'} not in the totals. ` : ''}
        ${since ? `Metering started ${esc(sinceTxt)}; ` : 'Metering starts with the next AI call; '}DeepSeek's API does not expose earlier spend, see
        <a href="https://platform.deepseek.com/usage" target="_blank" rel="noopener noreferrer">platform.deepseek.com/usage</a> for history before that.
      </p>`;
    wireTooltip(body);
  }

  let last = null;
  let resizeTimer = null;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
      const card = $('ai-usage-card');
      if (last && card && !card.hidden && card.offsetParent) render(last);
    }, 150);
  });

  async function loadAIUsage() {
    const card = $('ai-usage-card');
    if (!card) return;
    const me = window.state && window.state._me;
    if (me && me.role !== 'admin') { card.hidden = true; return; }
    card.hidden = false;
    try {
      const d = await window.apiFetch('/api/ai/usage?tz=' + new Date().getTimezoneOffset());
      last = d;
      render(d);
    } catch (e) {
      if (e.status === 403) { card.hidden = true; return; }
      const body = $('ai-usage-body');
      if (body) body.innerHTML = `<div class="au-empty-line">Could not load AI usage: ${esc(e.message || e)}</div>`;
    }
  }

  window.loadAIUsage = loadAIUsage;
  window.AIUsagePage = { loadAIUsage, usd, compact, render };
})();

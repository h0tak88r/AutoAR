(() => {
  function esc(v) { return window.esc(v); }
  function escAttr(v) { return window.escAttr(v); }

  function getUnifiedTableColumns(activeKind) {
    const active = String(activeKind || '');
    const moduleTab = active.startsWith('mod:') ? active.slice(4) : (
      active === 'misconfig' ? 'misconfig'
        : active === 'nuclei' ? 'nuclei'
          : active === 'ffuf' ? 'ffuf-fuzzing'
            : (active === 'apkx' || active.startsWith('apkcat:')) ? 'apkx' : ''
    );
    switch (moduleTab) {
      case 'apkx': return ['PATH', 'CATEGORY', 'MATCHER VALUE', 'MODULE'];
      case 'nuclei': return ['TARGET', 'SEV', 'TEMPLATE', 'MATCHED AT / MATCHER'];
      case 'gf-patterns': return ['TARGET', 'PATTERN', 'VALUE', 'SOURCE'];
      case 'misconfig': return ['TARGET', 'SEV', 'SERVICE', 'FINDING'];
      case 'ffuf-fuzzing': return ['URL', 'STATUS', 'WORD', 'LENGTH'];
      default: return ['TARGET', 'SEV', 'VULNERABILITY TYPE', 'MODULE'];
    }
  }

  function renderDefaultRow(r, idx, modInfo, sevMeta) {
    const target = String(r.host || r.target || '-');
    const vulnType = String(r.title || r.finding || '—').trim();
    const typeLabel = vulnType.length > 72 ? vulnType.slice(0, 70) + '…' : vulnType;
    const href = target.startsWith('http') ? target : (target !== '-' ? `https://${target}` : '#');
    return `<tr class="findings-row" data-target="${escAttr(target)}" data-finding="${escAttr(vulnType)}" data-severity="${escAttr(r.severity)}" data-module="${escAttr(r.module || '')}" style="cursor:pointer;${idx % 2 ? 'background:rgba(255,255,255,.012)' : ''}">
    <td style="padding:7px 10px;width:36px;text-align:center"><input type="checkbox" class="finding-chk" style="width:14px;height:14px;accent-color:var(--accent-cyan);cursor:pointer" onclick="event.stopPropagation()"></td>
    <td style="padding:7px 10px;max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><a href="${esc(href)}" target="_blank" rel="noopener" onclick="event.stopPropagation()" title="${esc(target)}" style="color:var(--accent-cyan);text-decoration:none;font-family:var(--font-mono,monospace);font-size:11.5px">${esc(target)}</a></td>
    <td style="padding:7px 8px;text-align:center;white-space:nowrap"><span style="display:inline-block;background:${sevMeta.bg};border:1px solid ${sevMeta.color}44;color:${sevMeta.color};font-size:9px;font-weight:800;letter-spacing:.7px;padding:2px 7px;border-radius:4px;min-width:34px;">${esc(sevMeta.label)}</span></td>
    <td style="padding:7px 10px;max-width:0;overflow:hidden"><span title="${esc(vulnType)}" style="display:inline-block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--font-mono,monospace);font-size:11.5px;color:var(--text-primary);">${esc(typeLabel)}</span></td>
    <td style="padding:7px 10px;white-space:nowrap;max-width:0;overflow:hidden;text-overflow:ellipsis"><span style="color:${modInfo.color};font-size:11px;font-weight:500">${modInfo.icon} ${esc(modInfo.name)}</span></td>
  </tr>`;
  }

  function renderJSAnalysisRow(r, idx, modInfo, sevMeta) {
    const jsFile = String(r.source_file || r.file || '-');
    const matcher = r.matcher || r.finding_type || 'Secret';
    const matchValue = r.finding || r.value || '-';
    const typeDisplay = `[${matcher}] - [${matchValue}]`;
    const typeLabel = typeDisplay.length > 72 ? typeDisplay.slice(0, 70) + '…' : typeDisplay;
    return `<tr class="findings-row js-analysis-row" style="cursor:pointer;${idx % 2 ? 'background:rgba(255,255,255,.012)' : ''}">
    <td style="padding:7px 10px;width:36px;text-align:center"><input type="checkbox" class="finding-chk" onclick="event.stopPropagation()"></td>
    <td style="padding:7px 10px;max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><span title="${esc(jsFile)}" style="color:var(--accent-amber);font-family:var(--font-mono);font-size:11px">${esc(jsFile)}</span></td>
    <td style="padding:7px 8px;text-align:center"><span style="background:${sevMeta.bg};color:${sevMeta.color};font-size:9px;padding:2px 6px;border-radius:4px;font-weight:bold">JS</span></td>
    <td style="padding:7px 10px;max-width:0;overflow:hidden"><span title="${esc(typeDisplay)}" style="color:var(--text-primary);font-family:var(--font-mono);font-size:11.5px">${esc(typeLabel)}</span></td>
    <td style="padding:7px 10px;white-space:nowrap"><span style="color:${modInfo.color};font-size:11px">${modInfo.icon} JS Analysis</span></td>
  </tr>`;
  }

  function renderNucleiRow(r, idx, modInfo, sevMeta) {
    const raw = r.raw || {};
    const info = raw.info || r.info || {};
    const target = String(raw.matched_at || raw.host || r.host || r.target || '-');
    const templateId = String(raw.template_id || r.template_id || r.finding || '—');
    const name = String(info.name || raw.name || templateId);
    const matchedAt = String(raw.matched_at || raw.matched || r.target || '-');
    const matcherName = String(raw.matcher_name || '');
    const extractedRaw = raw.extracted_results;
    const extractedResults = Array.isArray(extractedRaw) ? extractedRaw.join(', ') : (extractedRaw || '');
    const curlCmd = String(raw.curl_command || '');
    const description = String(info.description || raw.description || '');
    const refsRaw = info.reference || raw.reference;
    const refs = Array.isArray(refsRaw) ? refsRaw.join(', ') : (refsRaw || '');
    const tagsRaw = info.tags || raw.tags;
    const tags = Array.isArray(tagsRaw) ? tagsRaw.join(', ') : (typeof tagsRaw === 'object' && tagsRaw ? Object.values(tagsRaw).join(', ') : (tagsRaw || ''));
    const rowId = `nuclei-detail-${idx}-${Math.random().toString(36).slice(2)}`;
    const MAIN_KEYS = new Set(['template_id', 'matched_at', 'matched', 'host', 'info', 'severity', 'matcher_name', 'extracted_results', 'curl_command', 'description', 'reference', 'tags', 'name', 'type']);
    const extraFields = Object.entries(raw).filter(([k, v]) => !MAIN_KEYS.has(k) && v !== null && v !== undefined).map(([k, v]) => {
      const label = k.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
      const val = (typeof v === 'object') ? JSON.stringify(v, null, 2) : String(v);
      if (!val || val === 'null' || val === '{}' || val === '[]' || val === '—' || val === '-') return '';
      const isLong = val.length > 80 || val.includes('\n');
      return `<div style="${isLong ? 'grid-column:1/-1;' : ''}margin-bottom:6px"><span style="color:var(--text-muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px">${esc(label)}</span><br>${isLong ? `<pre style="font-size:10px;color:#a0ffb0;background:rgba(0,0,0,.3);padding:6px 8px;border-radius:5px;overflow-x:auto;margin:3px 0 0;white-space:pre-wrap;word-break:break-all">${esc(val)}</pre>` : `<span style="font-family:var(--font-mono);font-size:11px;color:var(--text-primary);word-break:break-all">${esc(val)}</span>`}</div>`;
    }).filter(Boolean);
    const hasDetail = matchedAt !== '-' || matcherName || extractedResults || description || tags || refs || curlCmd || extraFields.length;
    const detailPanel = hasDetail ? `<tr id="${rowId}" style="display:none"><td colspan="5" style="padding:0;border-top:1px solid rgba(255,255,255,.07)"><div style="padding:14px 20px;background:rgba(0,0,0,.25);display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:12px 20px;border-radius:0 0 8px 8px">${matchedAt !== '-' ? `<div><span style="color:var(--text-muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px">Matched At</span><br><a href="${esc(matchedAt)}" target="_blank" style="font-family:var(--font-mono);font-size:11px;color:var(--accent-cyan);word-break:break-all">${esc(matchedAt)}</a></div>` : ''}${matcherName ? `<div><span style="color:var(--text-muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px">Matcher Name</span><br><span style="font-family:var(--font-mono);font-size:11px;color:var(--accent-amber)">${esc(matcherName)}</span></div>` : ''}${extractedResults ? `<div><span style="color:var(--text-muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px">Extracted Results</span><br><span style="font-family:var(--font-mono);font-size:11px;color:#a3e635;word-break:break-all">${esc(extractedResults)}</span></div>` : ''}${description ? `<div style="grid-column:1/-1"><span style="color:var(--text-muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px">Description</span><br><span style="font-size:11.5px;color:var(--text-primary)">${esc(description)}</span></div>` : ''}${tags ? `<div><span style="color:var(--text-muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px">Tags</span><br><span style="font-size:11px;color:var(--accent-purple)">${esc(tags)}</span></div>` : ''}${refs ? `<div style="grid-column:1/-1"><span style="color:var(--text-muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px">References</span><br><span style="font-size:11px;color:var(--text-secondary);word-break:break-all">${esc(refs)}</span></div>` : ''}${curlCmd ? `<div style="grid-column:1/-1"><span style="color:var(--text-muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px">Curl Command</span><br><pre style="font-size:10px;color:#a0ffb0;background:rgba(0,0,0,.3);padding:8px;border-radius:6px;overflow-x:auto;margin:4px 0 0;white-space:pre-wrap;word-break:break-all">${esc(curlCmd)}</pre></div>` : ''}${extraFields.join('')}</div></td></tr>` : '';
    const mainRow = `<tr class="findings-row nuclei-row" style="cursor:pointer;${idx % 2 ? 'background:rgba(255,255,255,.012)' : ''}" onclick="(function(){var d=document.getElementById('${rowId}');if(d)d.style.display=d.style.display==='none'?'table-row':'none';})()"><td style="padding:7px 10px;width:36px;text-align:center"><input type="checkbox" class="finding-chk" onclick="event.stopPropagation()"></td><td style="padding:7px 10px;max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><a href="${target.startsWith('http') ? target : `https://${target}`}" target="_blank" onclick="event.stopPropagation()" style="color:var(--accent-cyan);font-family:var(--font-mono);font-size:11.5px">${esc(target)}</a></td><td style="padding:7px 8px;text-align:center;white-space:nowrap"><span style="background:${sevMeta.bg};border:1px solid ${sevMeta.color}44;color:${sevMeta.color};font-size:9px;font-weight:800;padding:2px 7px;border-radius:4px;">${esc(sevMeta.label)}</span></td><td style="padding:7px 10px;max-width:0;overflow:hidden"><div style="color:var(--text-primary);font-weight:600;font-size:12px">${esc(name)}</div><div style="color:var(--text-muted);font-size:10px;font-family:var(--font-mono)">${esc(templateId)}</div></td><td style="padding:7px 10px;white-space:nowrap;min-width:120px"><span style="color:var(--text-secondary);font-size:11px;font-family:var(--font-mono);overflow:hidden;text-overflow:ellipsis;display:inline-block;max-width:200px" title="${esc(matchedAt)}">${esc(matchedAt.length > 40 ? `${matchedAt.slice(0, 38)}…` : matchedAt)}</span>${matcherName ? `<div style="color:var(--accent-amber);font-size:9px;margin-top:2px">${esc(matcherName)}</div>` : ''}</td></tr>`;
    return mainRow + detailPanel;
  }

  function renderGFPatternsRow(r, idx, modInfo, sevMeta) {
    const target = String(r.host || r.target || '-');
    const pattern = r.pattern || r.module || '—';
    const value = r.finding || r.value || '-';
    return `<tr class="findings-row gf-row" style="cursor:pointer;${idx % 2 ? 'background:rgba(255,255,255,.012)' : ''}">
    <td style="padding:7px 10px;width:36px;text-align:center"><input type="checkbox" class="finding-chk" onclick="event.stopPropagation()"></td>
    <td style="padding:7px 10px;max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><span style="color:var(--accent-cyan);font-family:var(--font-mono);font-size:11.5px">${esc(target)}</span></td>
    <td style="padding:7px 8px;text-align:center"><span style="background:rgba(139, 92, 246, 0.1);color:#8b5cf6;font-size:9px;padding:2px 6px;border-radius:4px;font-weight:bold">GF</span></td>
    <td style="padding:7px 10px;max-width:0;overflow:hidden"><span style="color:var(--accent-purple);font-weight:700">[${esc(pattern)}]</span><span style="color:var(--text-secondary);font-family:var(--font-mono);font-size:11px;margin-left:4px">${esc(value)}</span></td>
    <td style="padding:7px 10px;white-space:nowrap"><span style="color:#8b5cf6;font-size:11px">🎯 GF Patterns</span></td>
  </tr>`;
  }

  function renderRowForUnifiedTab(r, idx, activeKind, modInfo, sevMeta) {
    const active = String(activeKind || '');
    const moduleTab = active.startsWith('mod:') ? active.slice(4) : (active === 'misconfig' ? 'misconfig' : '');
    const isApkCategoryTab = active.startsWith('apkcat:');
    const isApkUnifiedTab = active === 'apkx' || isApkCategoryTab;
    const target = String(r.host || r.target || '-');
    let displayTarget = target;
    let href = target.startsWith('http') ? target : (target !== '-' ? `https://${target}` : '#');
    const finding = String(r.title || r.finding || '—').trim() || '—';
    const findingShort = finding.length > 88 ? `${finding.slice(0, 86)}...` : finding;
    const source = String(r.file || r.source || '—');
    let apkCategoryLabel = String(r.apk_category || '').trim();
    let apkMatcherValue = String(r.matcher_value || finding);
    if (isApkUnifiedTab) {
      const normalizeApkPath = (p) => String(p || '').replace(/^\s*[-*•]\s*/, '').trim();
      const structuredPath = normalizeApkPath(r.path || '');
      const structuredCategory = String(r.category_name || '').trim();
      const structuredContext = String(r.context || '').trim();
      if (structuredCategory) apkCategoryLabel = structuredCategory;
      if (structuredPath) { displayTarget = structuredPath; href = '#'; }
      if (!apkCategoryLabel && target && target !== '-' && target !== '—') apkCategoryLabel = target;
      let payload = finding;
      if (apkCategoryLabel && payload.toLowerCase().startsWith(`${apkCategoryLabel.toLowerCase()}:`)) payload = payload.slice(apkCategoryLabel.length + 1).trim();
      const pathMatch = payload.match(/^([^:]+):\s*(.+)$/);
      if (pathMatch && (pathMatch[1].includes('/') || pathMatch[1].includes('\\') || pathMatch[1].includes('.'))) {
        displayTarget = normalizeApkPath(pathMatch[1]); href = '#'; apkMatcherValue = pathMatch[2].trim() || payload;
      } else {
        const mPath = String(apkMatcherValue || '').match(/^([^:]+):\s*(.+)$/);
        if (mPath && (mPath[1].includes('/') || mPath[1].includes('\\') || mPath[1].includes('.'))) {
          displayTarget = normalizeApkPath(mPath[1]); apkMatcherValue = mPath[2].trim() || apkMatcherValue;
        } else { displayTarget = structuredPath || (target && target !== '—' ? target : '—'); apkMatcherValue = payload; }
        href = '#';
      }
      if (structuredContext && !apkMatcherValue.includes('Context:')) apkMatcherValue = `${apkMatcherValue} (Context: ${structuredContext})`;
    }
    if (moduleTab === 'js-analysis') {
      const jsCandidates = [String(r.source_file || ''), String(r.file || ''), String(r.target || ''), String(r.finding || '')].join(' ');
      const jsMatch = jsCandidates.match(/https?:\/\/[^\s"')]+(?:\.js|\.mjs|\.jsx)[^\s"')]*?/i);
      if (jsMatch && jsMatch[0]) { displayTarget = jsMatch[0]; href = jsMatch[0]; }
    }
    let tdTarget = '';
    const tdSev = isApkUnifiedTab ? `<td style="padding:7px 8px;text-align:center;white-space:nowrap"><span style="display:inline-block;background:rgba(34,211,238,.12);border:1px solid rgba(34,211,238,.35);color:#67e8f9;font-size:9px;font-weight:800;letter-spacing:.5px;padding:2px 7px;border-radius:4px;max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${esc(apkCategoryLabel || 'APK Analysis')}">${esc(apkCategoryLabel || 'APK Analysis')}</span></td>` : `<td style="padding:7px 8px;text-align:center;white-space:nowrap"><span style="display:inline-block;background:${sevMeta.bg};border:1px solid ${sevMeta.color}44;color:${sevMeta.color};font-size:9px;font-weight:800;letter-spacing:.7px;padding:2px 7px;border-radius:4px;min-width:34px;">${esc(sevMeta.label)}</span></td>`;
    const tdModule = `<td style="padding:7px 10px;white-space:nowrap;max-width:0;overflow:hidden;text-overflow:ellipsis"><span style="color:${modInfo.color};font-size:11px;font-weight:500">${modInfo.icon} ${esc(modInfo.name)}</span></td>`;
    let c2 = tdSev;
    let c3 = `<td style="padding:7px 10px;max-width:0;overflow:hidden"><span title="${esc(isApkUnifiedTab ? apkMatcherValue : finding)}" style="display:inline-block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--font-mono,monospace);font-size:11.5px;color:var(--text-primary);">${esc((isApkUnifiedTab ? apkMatcherValue : findingShort))}</span></td>`;
    let c4 = tdModule;
    if (moduleTab === 'nuclei') {
      const templateId = String(r.template_id || finding || '—');
      const match = String(r.matched_at || r.target || target || '—');
      c3 = `<td style="padding:7px 10px;max-width:0;overflow:hidden"><span title="${esc(templateId)}" style="font-family:var(--font-mono,monospace);font-size:11.5px;color:var(--text-primary)">${esc(templateId)}</span></td>`;
      c4 = `<td style="padding:7px 10px;max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><span title="${esc(match)}" style="font-size:11px;color:var(--text-secondary)">${esc(match)}</span></td>`;
    } else if (moduleTab === 'gf-patterns') {
      const pattern = String(r.pattern || r.finding_type || 'gf-pattern');
      const value = String(r.value || r.finding || '—');
      c2 = `<td style="padding:7px 10px;max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><span style="color:var(--accent-purple);font-size:11px;font-weight:700">${esc(pattern)}</span></td>`;
      c3 = `<td style="padding:7px 10px;max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><span title="${esc(value)}" style="font-family:var(--font-mono,monospace);font-size:11px;color:var(--text-primary)">${esc(value)}</span></td>`;
      c4 = `<td style="padding:7px 10px;max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><span style="font-size:11px;color:var(--text-muted)">${esc(source)}</span></td>`;
    } else if (moduleTab === 'js-analysis') {
      let matcher = String(r.matcher || r.finding_type || '').trim();
      let matched = String(r.value || r.match || '').trim();
      if (!matcher || !matched) {
        const m = finding.match(/^\s*\[([^\]]+)\]\s*(?:https?:\/\/\S+)?\s*->\s*(.+)\s*$/i);
        if (m) { if (!matcher) matcher = String(m[1] || '').trim(); if (!matched) matched = String(m[2] || '').trim(); }
      }
      const vulnType = matcher && matched ? `[${matcher}] ${matched}` : (matcher ? `[${matcher}]` : findingShort);
      c3 = `<td style="padding:7px 10px;max-width:0;overflow:hidden"><span title="${esc(finding)}" style="display:inline-block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--font-mono,monospace);font-size:11.5px;color:var(--text-primary);">${esc(vulnType)}</span></td>`;
      c4 = tdModule;
    } else if (moduleTab === 'misconfig') {
      const service = String(r.service || r.service_name || r.module || 'misconfig');
      c3 = `<td style="padding:7px 10px;max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><span style="font-size:11px;color:var(--accent-amber)">${esc(service)}</span></td>`;
      c4 = `<td style="padding:7px 10px;max-width:0;overflow:hidden"><span title="${esc(finding)}" style="display:inline-block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px;color:var(--text-primary)">${esc(findingShort)}</span></td>`;
    } else if (moduleTab === 'ffuf-fuzzing') {
      const raw = r.raw || {};
      const targetUrl = String(raw.matched_at || raw.url || r.target || displayTarget || '—');
      if (targetUrl && targetUrl !== '—') {
        displayTarget = targetUrl;
        href = targetUrl;
      }
      const status = String(r.status || r.status_code || raw.status_code || raw.status || '—');
      const parsedPath = (() => {
        try {
          const u = new URL(targetUrl);
          return u.pathname && u.pathname !== '/' ? u.pathname : '/';
        } catch (_) {
          return '';
        }
      })();
      const pathWord = String(r.word || raw.word || r.path || parsedPath || r.finding_type || '—');
      const length = String(r.content_length || r.length || raw.content_length || raw.length || '—');
      c2 = `<td style="padding:7px 10px;text-align:center;white-space:nowrap"><span style="font-size:11px;color:var(--accent-cyan);font-family:var(--font-mono,monospace)">${esc(status)}</span></td>`;
      c3 = `<td style="padding:7px 10px;max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><span style="font-size:11px;color:var(--accent-purple)">${esc(pathWord)}</span></td>`;
      c4 = `<td style="padding:7px 10px;max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><span style="font-size:11px;color:var(--text-primary);font-family:var(--font-mono,monospace)">${esc(length)}</span></td>`;
    }
    tdTarget = isApkUnifiedTab ? `<td style="padding:7px 10px;max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><span title="${esc(displayTarget)}" style="color:var(--accent-cyan);text-decoration:none;font-family:var(--font-mono,monospace);font-size:11.5px">${esc(displayTarget)}</span></td>` : `<td style="padding:7px 10px;max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><a href="${esc(href)}" target="_blank" rel="noopener" onclick="event.stopPropagation()" title="${esc(displayTarget)}" style="color:var(--accent-cyan);text-decoration:none;font-family:var(--font-mono,monospace);font-size:11.5px">${esc(displayTarget)}</a></td>`;
    return `<tr class="findings-row" data-target="${escAttr(displayTarget)}" data-finding="${escAttr(isApkUnifiedTab ? apkMatcherValue : finding)}" data-severity="${escAttr(isApkUnifiedTab ? (apkCategoryLabel || 'APK Analysis') : (r.severity || ''))}" data-module="${escAttr(r.module || '')}" data-href="${escAttr(href)}" style="cursor:pointer;${idx % 2 ? 'background:rgba(255,255,255,.012)' : ''}"><td style="padding:7px 10px;width:36px;text-align:center"><input type="checkbox" class="finding-chk" style="width:14px;height:14px;accent-color:var(--accent-cyan);cursor:pointer" onclick="event.stopPropagation()"></td>${tdTarget}${c2}${c3}${c4}</tr>`;
  }

  window.FindingsRowsPage = {
    getUnifiedTableColumns,
    renderRowForUnifiedTab,
    renderDefaultRow,
    renderJSAnalysisRow,
    renderNucleiRow,
    renderGFPatternsRow,
  };
})();

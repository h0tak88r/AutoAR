(function () {
'use strict';

const IPAA = window.IPAA = window.IPAA || {};
const $  = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => Array.from(el.querySelectorAll(sel));

const SEVS = ['issue', 'info', 'secure'];

const State = {
    currentResults: null,
    currentFile: null,
    viewerZip: null,
    activeSeverityFilter: new Set(SEVS),
    findingsSearch: '',
    findingsSort: 'severity',
    findingsMinConfidence: 0,
    findingsPage: 0,
    findingsPerPage: 50,
    worker: null,
    workerFailed: false,
    explorerFiles: [],
    explorerTree: null,
    currentOpenFile: null,
    currentOpenBytes: null,
};

function esc(text) {
    if (text == null) return '';
    const d = document.createElement('div');
    d.textContent = String(text);
    return d.innerHTML;
}
function escAttr(t) {
    return String(t == null ? '' : t).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function html(strings, ...values) {
    let out = '';
    strings.forEach((s, i) => {
        out += s;
        if (i < values.length) {
            const v = values[i];
            if (v == null) out += '';
            else if (typeof v === 'object' && v.__raw) out += v.html;
            else if (Array.isArray(v)) out += v.map(x => (x && x.__raw) ? x.html : esc(x)).join('');
            else out += esc(v);
        }
    });
    return { __raw: true, html: out, toString() { return out; } };
}
const raw = (s) => ({ __raw: true, html: typeof s === 'string' ? s : String(s) });

function fmtSize(b) {
    if (b == null) return '?';
    const u = ['B','KB','MB','GB'];
    let i = 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return b.toFixed(b < 10 && i > 0 ? 2 : 1) + ' ' + u[i];
}
function toast(message, type) {
    const c = document.getElementById('toastContainer') || (() => {
        const d = document.createElement('div');
        d.id = 'toastContainer'; d.className = 'toast-container';
        document.body.appendChild(d);
        return d;
    })();
    const t = document.createElement('div');
    t.className = 'toast ' + (type || 'info');
    t.setAttribute('role', 'status');
    t.textContent = message;
    c.appendChild(t);
    setTimeout(() => t.remove(), 4500);
}

function setupWorker() {
    try {
        const w = new Worker('src/analyzer.worker.js');
        w.addEventListener('error', (e) => {
            console.warn('Worker error:', e.message);
            State.workerFailed = true;
        });
        w.postMessage({ type: 'ping' });
        return w;
    } catch (e) {
        console.warn('Worker spawn failed, falling back to main thread:', e.message);
        State.workerFailed = true;
        return null;
    }
}

async function analyzeFile(file) {
    document.body.classList.add('analyzing');
    showProgress(0, 'Initializing…');
    State.currentFile = file;
    State.viewerZip = null;
    const arrayBuffer = await file.arrayBuffer();
    const fileMeta = { name: file.name, size: file.size, lastModified: file.lastModified };

    if (!State.worker) State.worker = setupWorker();

    let workerBuffer = arrayBuffer;
    if (State.worker && !State.workerFailed) {
        workerBuffer = arrayBuffer.slice(0);
    }

    return new Promise((resolve, reject) => {
        const useWorker = State.worker && !State.workerFailed;
        if (!useWorker) {
            runOnMainThread(arrayBuffer, fileMeta).then(resolve, reject);
            return;
        }
        const w = State.worker;
        const onMsg = (e) => {
            const { type, data } = e.data;
            if (type === 'progress') {
                showProgress(data.percent || 0, data.text || '…', data);
            } else if (type === 'result') {
                w.removeEventListener('message', onMsg);
                resolve(data);
            } else if (type === 'error') {
                w.removeEventListener('message', onMsg);
                reject(new Error(data.message || 'Worker error'));
            } else if (type === 'fatal') {
                console.warn('Worker fatal, falling back to main thread:', data.error);
                w.removeEventListener('message', onMsg);
                State.workerFailed = true;
                runOnMainThread(arrayBuffer, fileMeta).then(resolve, reject);
            }
        };
        w.addEventListener('message', onMsg);
        try {
            w.postMessage({ type: 'analyze', buffer: workerBuffer, fileMeta }, [workerBuffer]);
        } catch (e) {
            w.removeEventListener('message', onMsg);
            State.workerFailed = true;
            runOnMainThread(arrayBuffer, fileMeta).then(resolve, reject);
        }
    });
}

async function runOnMainThread(arrayBuffer, fileMeta) {
    if (!window.APKA || typeof window.APKA.analyzeAPK !== 'function') {
        throw new Error('Engine not loaded');
    }
    return window.APKA.analyzeAPK(arrayBuffer, fileMeta, {
        onProgress: (percent, text) => showProgress(percent || 0, text || '…'),
    });
}

async function getViewerZip() {
    if (State.viewerZip) return State.viewerZip;
    if (!State.currentFile) return null;
    if (typeof JSZip === 'undefined') return null;
    const buf = await State.currentFile.arrayBuffer();
    State.viewerZip = await JSZip.loadAsync(buf);
    return State.viewerZip;
}

function showProgress(pct, text, payload) {
    const overlay = $('#loadingOverlay');
    const fill = $('#progressFill');
    const tEl = $('#progressText');
    const lEl = $('#loadingText');
    const dEl = $('#progressDetail');
    if (overlay) overlay.classList.add('active');
    if (fill) fill.style.width = (pct || 0) + '%';
    if (tEl) tEl.textContent = text || '…';
    if (lEl) lEl.textContent = 'Analyzing APK…';
    if (dEl && payload && payload.file) {
        dEl.textContent = payload.file.split('/').pop();
    } else if (dEl) {
        dEl.textContent = '';
    }
}
function hideProgress() {
    const o = $('#loadingOverlay');
    if (o) o.classList.remove('active');
    document.body.classList.remove('analyzing');
}

async function startAnalysis(file) {
    if (!file) return;
    if (!/\.apk$/i.test(file.name) && !/\.zip$/i.test(file.name)) {
        toast('Please select a .apk or .zip file', 'error'); return;
    }
    try {
        const results = await analyzeFile(file);
        hideProgress();
        State.currentResults = results;
        renderAll(results);
        showApp();
        toast('Analysis complete · Score ' + results.securityScore, 'success');
        if (results.warnings && results.warnings.length) {
            console.warn('[APK Auditor] warnings:', results.warnings);
        }
    } catch (e) {
        hideProgress();
        console.error(e);
        toast('Analysis failed: ' + e.message, 'error');
    }
}

function showApp() {
    $('#landingContent') && ($('#landingContent').style.display = 'none');
    $('#appContainer') && $('#appContainer').classList.add('active');
    window.scrollTo({ top: 0 });
}

function showLanding() {
    $('#landingContent') && ($('#landingContent').style.display = '');
    $('#appContainer') && $('#appContainer').classList.remove('active');
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function switchTab(name) {
    $$('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
    $$('.tab').forEach(t => t.setAttribute('aria-selected', t.dataset.tab === name ? 'true' : 'false'));
    $$('.panel').forEach(p => {
        const active = p.id === 'panel-' + name;
        p.classList.toggle('active', active);
        p.hidden = !active;
    });
}

function renderAll(r) {
    renderHeader(r);
    renderOverview(r);
    renderFindings(r);
    renderManifest(r);
    renderComponents(r);
    renderCert(r);
    renderExplorer(r);
    updateBadges(r);
}

function renderHeader(r) {
    $('#appName').textContent = r.appInfo && (r.appInfo.appLabel || r.appInfo.packageName) || 'Unknown';
    $('#bundleId').textContent = (r.appInfo && r.appInfo.packageName) || '';
    const ic = $('#appIcon');
    const letter = ((r.appInfo && (r.appInfo.appLabel || r.appInfo.packageName) || '?') + '').charAt(0).toUpperCase();
    ic.innerHTML = '<span aria-hidden="true" style="font-size:24px;font-weight:700;color:#fff;">' + esc(letter) + '</span>';
}
function updateBadges(r) {
    const s = r.summary || { issue: 0, info: 0, secure: 0 };
    const total = (s.issue || 0) + (s.info || 0) + (s.secure || 0);
    const badge = $('#findingsCount');
    if (badge) {
        badge.textContent = total;
        badge.classList.toggle('zero', (s.issue || 0) === 0);
    }
}

function renderOverview(r) {
    const s = r.summary || { issue: 0, info: 0, secure: 0 };
    const issue = s.issue || 0, info = s.info || 0, secure = s.secure || 0;
    const score = r.securityScore != null ? r.securityScore : 0;
    const scoreClass = score >= 80 ? 'good' : score >= 60 ? 'ok' : score >= 40 ? 'meh' : 'bad';
    const scoreLabel = score >= 85 ? 'Excellent' : score >= 70 ? 'Good' : score >= 50 ? 'Fair' : score >= 30 ? 'Poor' : 'Critical';
    const perms = (r.permissions || []).length;
    const dperms = (r.dangerousPerms || []).length;
    const dex = (r.dexFiles || []).length;
    const trackers = (r.trackers || []).length;

    $('#overviewStats').innerHTML = html`
      <div class="stat-card score-card ${scoreClass}">
        <div class="stat-card-header"><span class="stat-card-label">Security Score</span></div>
        <div class="score-ring" style="--score:${score}" role="img" aria-label="Score ${score} of 100, ${scoreLabel}">
          <div class="score-value">${score}</div><div class="score-max">/100</div>
        </div>
        <div class="score-label">${scoreLabel}</div>
      </div>
      <div class="stat-card findings-card">
        <div class="stat-card-header"><span class="stat-card-label">Findings</span></div>
        <div class="findings-vertical">
          <button class="finding-row high"    data-jumpsev="issue"  aria-label="${issue} issues">  <span class="count">${issue}</span><span class="label">Issues</span></button>
          <button class="finding-row info"    data-jumpsev="info"   aria-label="${info} info">      <span class="count">${info}</span><span class="label">Info</span></button>
          <button class="finding-row secure"  data-jumpsev="secure" aria-label="${secure} secure"> <span class="count">${secure}</span><span class="label">Secure</span></button>
        </div>
      </div>
      <div class="stat-card"><div class="stat-card-header"><span class="stat-card-label">Permissions</span></div><div class="stat-card-value">${perms}</div><div class="stat-card-desc">${dperms} dangerous</div></div>
      <div class="stat-card"><div class="stat-card-header"><span class="stat-card-label">DEX</span></div><div class="stat-card-value">${dex}</div><div class="stat-card-desc">${(r.dexFiles || []).reduce((a,d)=>a+(d.classes||0),0)} classes</div></div>
      <div class="stat-card"><div class="stat-card-header"><span class="stat-card-label">Trackers</span></div><div class="stat-card-value">${trackers}</div><div class="stat-card-desc">SDKs</div></div>
      <div class="stat-card"><div class="stat-card-header"><span class="stat-card-label">Native libs</span></div><div class="stat-card-value">${(r.nativeLibs || []).length}</div><div class="stat-card-desc">.so files</div></div>
    `;

    $$('#overviewStats [data-jumpsev]').forEach(b => b.addEventListener('click', () => {
        State.activeSeverityFilter = new Set([b.dataset.jumpsev]);
        $$('.filter-btn[data-filter]').forEach(x => x.classList.toggle('active', x.dataset.filter === b.dataset.jumpsev));
        State.findingsPage = 0;
        renderFindings(State.currentResults);
        switchTab('findings');
    }));

    const cert = r.certInfo || r.certificate || null;
    const certCN = cert && cert.subject && (cert.subject.CN || cert.subject.O) || '';
    const items = [
        ['Package',    r.appInfo && r.appInfo.packageName],
        ['Label',      r.appInfo && r.appInfo.appLabel],
        ['Version',    r.appInfo && r.appInfo.versionName],
        ['Version Code', r.appInfo && r.appInfo.versionCode],
        ['Min SDK',    r.minSdk ? r.minSdk + (window.APKA && window.APKA.sdkToVer ? ' (' + window.APKA.sdkToVer(r.minSdk) + ')' : '') : null],
        ['Target SDK', r.targetSdk ? r.targetSdk + (window.APKA && window.APKA.sdkToVer ? ' (' + window.APKA.sdkToVer(r.targetSdk) + ')' : '') : null],
        ['Size',       r.appInfo && r.appInfo.fileSize],
        ['v2 Signature', r.hasV2Sig === undefined ? null : (r.hasV2Sig ? 'yes' : 'no')],
        ['Obfuscated', r.isObfuscated === undefined ? null : (r.isObfuscated ? 'yes' : 'no')],
        ['Cert subject', certCN],
    ];
    let infoHtml = '<div class="info-grid">';
    for (const [k, v] of items) if (v) infoHtml += html`<div class="info-item"><label>${k}</label><div class="value">${v}</div></div>`;
    if (r.appInfo && r.appInfo.sha256) infoHtml += html`<div class="info-item full"><label>SHA-256</label><div class="value hash mono">${r.appInfo.sha256}</div></div>`;
    if (r.appInfo && r.appInfo.fileName) infoHtml += html`<div class="info-item full"><label>File</label><div class="value mono">${r.appInfo.fileName}</div></div>`;
    infoHtml += '</div>';
    $('#appInfoGrid').innerHTML = infoHtml;

    const dp = r.dangerousPerms || [];
    $('#dangerousPermsList').innerHTML = dp.length === 0
        ? '<div class="no-data">No dangerous (runtime) permissions requested</div>'
        : dp.map(p => '<span class="scheme-tag">' + esc(p) + '</span>').join('');

    renderTrackers(r);
    renderUrlsPanel(r);
    renderWarningsBanner(r);
}

function renderUrlsPanel(r) {
    const el = $('#urlsList');
    if (!el) return;
    const urls = (r.urls || []).slice();
    if (urls.length === 0) {
        el.innerHTML = '<div class="no-data">No URLs found in DEX strings</div>';
        return;
    }
    const byHost = new Map();
    for (const u of urls) {
        try {
            const host = new URL(u).host;
            const arr = byHost.get(host) || [];
            arr.push(u);
            byHost.set(host, arr);
        } catch (_) {
            const arr = byHost.get('(unparseable)') || [];
            arr.push(u);
            byHost.set('(unparseable)', arr);
        }
    }
    const sorted = [...byHost.entries()].sort((a, b) => b[1].length - a[1].length).slice(0, 25);
    const totalShown = sorted.reduce((acc, [, list]) => acc + list.length, 0);
    el.innerHTML = '<div class="urls-summary">' + urls.length + ' URLs across ' + byHost.size + ' hosts. Showing top ' + sorted.length + ' hosts (' + totalShown + ' URLs).</div>' +
        '<div class="urls-list">' + sorted.map(([host, list]) => {
            const httpsCount = list.filter(u => u.indexOf('https://') === 0).length;
            const httpCount  = list.length - httpsCount;
            return '<details class="url-host"><summary><span class="url-host-name mono">' + esc(host) + '</span>' +
                '<span class="url-host-count">' + list.length + '</span>' +
                (httpCount > 0 ? '<span class="url-host-flag bad">' + httpCount + ' http</span>' : '') +
                (httpsCount > 0 ? '<span class="url-host-flag good">' + httpsCount + ' https</span>' : '') +
                '</summary>' +
                '<div class="url-list-items">' + list.slice(0, 30).map(u => '<code class="url-line mono">' + esc(u) + '</code>').join('') +
                (list.length > 30 ? '<div class="url-more">… ' + (list.length - 30) + ' more</div>' : '') +
                '</div></details>';
        }).join('') + '</div>';
}

function renderWarningsBanner(r) {
    const el = $('#warningsBanner');
    if (!el) return;
    const w = r.warnings || [];
    if (w.length === 0) { el.innerHTML = ''; el.hidden = true; return; }
    el.hidden = false;
    el.innerHTML = '<details class="warnings-card"><summary>' +
        '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>' +
        '<span>' + w.length + ' analysis warning' + (w.length === 1 ? '' : 's') + '</span>' +
        '<span class="warnings-hint">click to expand</span>' +
        '</summary><ul class="warnings-list">' + w.map(m => '<li class="mono">' + esc(m) + '</li>').join('') + '</ul></details>';
}

function renderTrackers(r) {
    const trackers = r.trackers || [];
    const el = $('#trackersList');
    if (!el) return;
    if (trackers.length === 0) { el.innerHTML = '<div class="no-data">No trackers detected</div>'; return; }
    const byCat = {};
    for (const t of trackers) { (byCat[t.category || 'other'] = byCat[t.category || 'other'] || []).push(t); }
    el.innerHTML = Object.entries(byCat).map(([cat, items]) => html`
        <div class="tracker-group">
          <div class="tracker-cat">${cat}</div>
          <div class="tracker-row">${raw(items.map(t => html`<span class="tracker-tag">${t.name}</span>`).join(''))}</div>
        </div>`).join('');
}

function findingsAfterFilters(r) {
    let all = [];
    for (const g of SEVS) {
        if (!State.activeSeverityFilter.has(g)) continue;
        for (const f of (r.groupedFindings && r.groupedFindings[g] || [])) all.push(f);
    }
    const q = State.findingsSearch.trim().toLowerCase();
    if (q) {
        all = all.filter(f =>
            (f.ruleName || '').toLowerCase().includes(q)
         || (f.description || '').toLowerCase().includes(q)
         || (f.cwe || '').toLowerCase().includes(q)
         || (f.owasp || '').toLowerCase().includes(q)
         || (f.masvs || '').toLowerCase().includes(q)
         || (f.instances || []).some(i => (i.match || '').toLowerCase().includes(q) || (i.file || '').toLowerCase().includes(q))
        );
    }
    if (State.findingsMinConfidence > 0) {
        all = all.filter(f => (f.avgConfidence != null ? f.avgConfidence : 50) >= State.findingsMinConfidence);
    }
    const sortKey = State.findingsSort;
    if (sortKey === 'severity') {
        const order = { issue: 0, info: 1, secure: 2 };
        all.sort((a, b) => (order[a.severity] - order[b.severity]) || (b.avgConfidence - a.avgConfidence));
    } else if (sortKey === 'confidence') {
        all.sort((a, b) => b.avgConfidence - a.avgConfidence);
    } else if (sortKey === 'count') {
        all.sort((a, b) => (b.instances || []).length - (a.instances || []).length);
    } else if (sortKey === 'name') {
        all.sort((a, b) => a.ruleName.localeCompare(b.ruleName));
    }
    return all;
}

function sevBadge(sev) {
    if (sev === 'issue')  return 'high';
    if (sev === 'secure') return 'secure';
    return 'info';
}

function renderFindings(r) {
    if (!r) return;
    const container = $('#findingsList');
    if (!container) return;
    const all = findingsAfterFilters(r);

    if (all.length === 0) {
        container.innerHTML = '<div class="no-data">No findings match the current filters.</div>';
        $('#findingsResultCount').textContent = '0';
        $('#findingsPager').innerHTML = '';
        return;
    }

    const start = State.findingsPage * State.findingsPerPage;
    const page = all.slice(start, start + State.findingsPerPage);
    $('#findingsResultCount').textContent = all.length + ' rules · showing ' + (start + 1) + '–' + Math.min(all.length, start + page.length);

    container.innerHTML = page.map((f, i) => {
        const idx = start + i;
        const sevCls = sevBadge(f.severity);
        const instances = (f.instances || []).slice(0, 200).map((inst, j) => {
            const file = inst.file || '';
            const line = inst.line || 0;
            const clickAttr = file ? `data-jump-file="${escAttr(file)}" data-jump-line="${parseInt(line) || 0}"` : '';
            const confBar = inst.confidence != null
                ? `<span class="confidence-badge ${inst.confidenceLabel || 'medium'}" title="Confidence ${inst.confidence}%">${inst.confidence}%</span>`
                : '';
            const entropy = inst.entropy != null ? `<span class="entropy-badge" title="Shannon entropy">H=${inst.entropy}</span>` : '';
            return html`
              <div class="instance-item">
                <div class="instance-header">
                  <span class="instance-number">#${j + 1}</span>
                  ${file ? raw(`<button class="instance-file clickable" ${clickAttr} aria-label="Open ${escAttr(file)}">${esc(file)}${line ? ':' + line : ''}</button>`) : ''}
                  ${raw(confBar)}
                  ${raw(entropy)}
                </div>
                ${inst.match ? raw('<div class="instance-match"><code>' + esc((inst.match || '').slice(0, 500)) + '</code><button class="copy-btn" data-copy="' + escAttr(inst.match || '') + '" title="Copy match" aria-label="Copy match value">⧉</button></div>') : ''}
              </div>`;
        }).join('');
        return html`
          <article class="finding-card ${sevCls}" data-severity="${f.severity}" data-finding-id="${idx}">
            <button class="finding-header" aria-expanded="false" aria-controls="finding-body-${idx}">
              <span class="severity-badge ${sevCls}">${(f.severity || 'info').toUpperCase()}</span>
              <span class="finding-title">${f.ruleName}</span>
              <span class="confidence-pill ${labelFor(f.avgConfidence)}" title="Average confidence">${f.avgConfidence || 0}%</span>
              <span class="instance-count">${(f.instances || []).length} instance${(f.instances || []).length === 1 ? '' : 's'}</span>
              <span class="finding-toggle" aria-hidden="true">▾</span>
            </button>
            <div class="finding-body" id="finding-body-${idx}" hidden>
              <div class="finding-description">${f.description || ''}</div>
              <div class="finding-meta">
                ${f.cwe   ? raw('<a class="meta-tag" target="_blank" rel="noopener" href="https://cwe.mitre.org/data/definitions/' + esc((f.cwe || '').replace(/^CWE-/, '')) + '.html">CWE: ' + esc(f.cwe) + '</a>') : ''}
                ${f.owasp ? raw('<span class="meta-tag">OWASP: ' + esc(f.owasp) + '</span>') : ''}
                ${f.masvs ? raw('<span class="meta-tag">MASVS: ' + esc(f.masvs) + '</span>') : ''}
                ${f.category ? raw('<span class="meta-tag category">' + esc(f.category) + '</span>') : ''}
              </div>
              <div class="instances-section">
                <div class="instances-header">Found in ${(f.instances || []).length} location${(f.instances || []).length === 1 ? '' : 's'}</div>
                <div class="instances-list">${raw(instances)}</div>
              </div>
            </div>
          </article>`;
    }).join('');

    $$('#findingsList .finding-header').forEach(h => h.addEventListener('click', () => {
        const expanded = h.getAttribute('aria-expanded') === 'true';
        h.setAttribute('aria-expanded', expanded ? 'false' : 'true');
        const body = h.parentElement.querySelector('.finding-body');
        if (body) body.hidden = expanded;
    }));
    $$('#findingsList [data-jump-file]').forEach(b => b.addEventListener('click', () => {
        const file = b.getAttribute('data-jump-file');
        const line = parseInt(b.getAttribute('data-jump-line') || '0', 10);
        navigateToFile(file, line);
    }));
    $$('#findingsList [data-copy]').forEach(b => b.addEventListener('click', async (e) => {
        e.stopPropagation();
        const text = b.getAttribute('data-copy');
        try {
            await navigator.clipboard.writeText(text);
            b.classList.add('copied');
            const orig = b.textContent;
            b.textContent = '✓';
            setTimeout(() => { b.classList.remove('copied'); b.textContent = orig; }, 1200);
        } catch (_) {
            toast('Copy failed, select text manually', 'error');
        }
    }));

    renderPager(all.length);
}

function labelFor(conf) {
    conf = conf || 0;
    if (conf >= 85) return 'high';
    if (conf >= 60) return 'medium';
    if (conf >= 30) return 'low';
    return 'noise';
}

function renderPager(total) {
    const pages = Math.max(1, Math.ceil(total / State.findingsPerPage));
    const cur = State.findingsPage;
    const wrap = $('#findingsPager');
    if (!wrap) return;
    if (pages <= 1) { wrap.innerHTML = ''; return; }
    wrap.innerHTML = `
      <button class="pager-btn" data-pager="first" ${cur === 0 ? 'disabled' : ''}>⏮ First</button>
      <button class="pager-btn" data-pager="prev"  ${cur === 0 ? 'disabled' : ''}>◀ Prev</button>
      <span class="pager-info">Page ${cur + 1} of ${pages}</span>
      <button class="pager-btn" data-pager="next" ${cur >= pages - 1 ? 'disabled' : ''}>Next ▶</button>
      <button class="pager-btn" data-pager="last" ${cur >= pages - 1 ? 'disabled' : ''}>Last ⏭</button>`;
    $$('#findingsPager [data-pager]').forEach(b => b.addEventListener('click', () => {
        const a = b.dataset.pager;
        if (a === 'first') State.findingsPage = 0;
        else if (a === 'prev')  State.findingsPage = Math.max(0, cur - 1);
        else if (a === 'next')  State.findingsPage = Math.min(pages - 1, cur + 1);
        else if (a === 'last')  State.findingsPage = pages - 1;
        renderFindings(State.currentResults);
    }));
}

function renderManifest(r) {
    const sum = $('#manifestSummary');
    if (sum) {
        const items = [
            ['Package',  r.appInfo && r.appInfo.packageName],
            ['Label',    r.appInfo && r.appInfo.appLabel],
            ['Version',  r.appInfo && r.appInfo.versionName],
            ['Version Code', r.appInfo && r.appInfo.versionCode],
            ['Min SDK',  r.minSdk ? r.minSdk + (window.APKA && window.APKA.sdkToVer ? ' (' + window.APKA.sdkToVer(r.minSdk) + ')' : '') : null],
            ['Target SDK', r.targetSdk ? r.targetSdk + (window.APKA && window.APKA.sdkToVer ? ' (' + window.APKA.sdkToVer(r.targetSdk) + ')' : '') : null],
            ['Main Activity', r.appInfo && r.appInfo.mainActivity],
            ['Allow Backup', r.appInfo && r.appInfo.allowBackup === undefined ? null : (r.appInfo.allowBackup ? 'true' : 'false')],
            ['Debuggable',   r.appInfo && r.appInfo.debuggable === undefined ? null : (r.appInfo.debuggable ? 'true' : 'false')],
            ['Network Security Config', r.appInfo && r.appInfo.networkSecurityConfig],
        ];
        let h = '<div class="info-grid">';
        for (const [k, v] of items) if (v !== null && v !== undefined && v !== '') h += html`<div class="info-item"><label>${k}</label><div class="value">${v}</div></div>`;
        h += '</div>';
        sum.innerHTML = h;
    }

    const perms = r.permissions || [];
    const danger = new Set(r.dangerousPerms || []);
    const pl = $('#permissionsList');
    const pc = $('#permissionsCount');
    if (pc) pc.textContent = String(perms.length);
    if (pl) {
        pl.innerHTML = perms.length === 0
            ? '<div class="no-data">No permissions declared</div>'
            : '<table class="ent-table"><thead><tr><th>Permission</th><th>Class</th></tr></thead><tbody>' +
              perms.map(p => '<tr class="' + (danger.has(p) ? 'risk-high' : '') + '"><td class="mono">' + esc(p) + '</td><td>' + (danger.has(p) ? '<span class="risk-badge high">dangerous</span>' : '<span class="risk-badge low">normal</span>') + '</td></tr>').join('') +
              '</tbody></table>';
    }

    const raw = $('#manifestRaw');
    if (raw) {
        if (r.manifestStr) {
            raw.innerHTML = '<pre class="code-viewer mono">' + esc(r.manifestStr) + '</pre>';
        } else {
            raw.innerHTML = '<div class="no-data">AndroidManifest.xml not parsed</div>';
        }
    }
}

function renderComponents(r) {
    const c = r.components || { activities: [], services: [], receivers: [], providers: [] };
    const pkg = (r.appInfo && r.appInfo.packageName) || '';
    State.componentsFilter = State.componentsFilter || 'all';
    State.componentsScope  = State.componentsScope  || 'exported';

    const all = [
        ...(c.activities || []).map(x => Object.assign({}, x, { type: x.type || 'activity' })),
        ...(c.services   || []).map(x => Object.assign({}, x, { type: x.type || 'service' })),
        ...(c.receivers  || []).map(x => Object.assign({}, x, { type: x.type || 'receiver' })),
        ...(c.providers  || []).map(x => Object.assign({}, x, { type: x.type || 'provider' })),
    ];
    const exported = all.filter(x => x.exported);
    const noPerm   = exported.filter(x => !x.permission && !x.readPermission && !x.writePermission);

    const summary = $('#componentsSummary');
    if (summary) {
        summary.innerHTML = html`
          <div class="comp-summary-grid">
            <div class="stat-card"><div class="stat-card-header"><span class="stat-card-label">Total</span></div><div class="stat-card-value">${all.length}</div><div class="stat-card-desc">${(c.activities||[]).length} act · ${(c.services||[]).length} svc · ${(c.receivers||[]).length} rcv · ${(c.providers||[]).length} prov</div></div>
            <div class="stat-card"><div class="stat-card-header"><span class="stat-card-label">Exported</span></div><div class="stat-card-value warn">${exported.length}</div><div class="stat-card-desc">reachable from other apps</div></div>
            <div class="stat-card"><div class="stat-card-header"><span class="stat-card-label">No permission</span></div><div class="stat-card-value bad">${noPerm.length}</div><div class="stat-card-desc">exposed without permission</div></div>
          </div>
        `;
    }

    const toolbar = $('#componentsToolbar');
    if (toolbar) {
        toolbar.innerHTML = `
          <div class="filter-bar" data-role="scope">
            <button class="filter-btn ${State.componentsScope === 'all' ? 'active' : ''}"      data-scope="all">All components</button>
            <button class="filter-btn ${State.componentsScope === 'exported' ? 'active' : ''}" data-scope="exported">Exported only</button>
          </div>
          <div class="filter-bar" data-role="type">
            <button class="filter-btn ${State.componentsFilter === 'all'      ? 'active' : ''}" data-type="all">All</button>
            <button class="filter-btn ${State.componentsFilter === 'activity' ? 'active' : ''}" data-type="activity">Activity</button>
            <button class="filter-btn ${State.componentsFilter === 'service'  ? 'active' : ''}" data-type="service">Service</button>
            <button class="filter-btn ${State.componentsFilter === 'receiver' ? 'active' : ''}" data-type="receiver">Receiver</button>
            <button class="filter-btn ${State.componentsFilter === 'provider' ? 'active' : ''}" data-type="provider">Provider</button>
          </div>`;
        toolbar.querySelectorAll('[data-scope]').forEach(b => b.addEventListener('click', () => {
            State.componentsScope = b.dataset.scope;
            renderComponents(State.currentResults);
        }));
        toolbar.querySelectorAll('[data-type]').forEach(b => b.addEventListener('click', () => {
            State.componentsFilter = b.dataset.type;
            renderComponents(State.currentResults);
        }));
    }

    let list = State.componentsScope === 'exported' ? exported : all;
    if (State.componentsFilter !== 'all') list = list.filter(x => x.type === State.componentsFilter);

    const container = $('#componentsList');
    if (!container) return;
    if (list.length === 0) {
        container.innerHTML = '<div class="no-data">No components match the current filters.</div>';
        return;
    }
    container.innerHTML = list.map((cmp, idx) => renderComponentCard(cmp, pkg, idx)).join('');
    container.querySelectorAll('.comp-cmd').forEach(el => el.addEventListener('click', async () => {
        try {
            await navigator.clipboard.writeText(el.dataset.cmd || el.textContent.trim());
            const orig = el.textContent;
            el.classList.add('copied');
            el.textContent = '✓ copied';
            setTimeout(() => { el.classList.remove('copied'); el.textContent = orig; }, 1200);
        } catch (_) {
            toast('Copy failed', 'error');
        }
    }));
    container.querySelectorAll('.comp-card-header').forEach(h => h.addEventListener('click', () => {
        const body = h.parentElement.querySelector('.comp-card-body');
        if (!body) return;
        const open = h.getAttribute('aria-expanded') === 'true';
        h.setAttribute('aria-expanded', open ? 'false' : 'true');
        body.hidden = open;
    }));
}

function renderComponentCard(cmp, pkg, idx) {
    const cmds = generateExploitCommands(cmp, pkg);
    const simple = (cmp.name || '').split('.').pop() || '(unnamed)';
    const badges = [];
    if (cmp.exported) badges.push('<span class="comp-badge warn">EXPORTED</span>');
    else              badges.push('<span class="comp-badge good">private</span>');
    if (cmp.exported && !cmp.permission && !cmp.readPermission && !cmp.writePermission)
        badges.push('<span class="comp-badge bad">No permission</span>');
    if (cmp.permission)      badges.push('<span class="comp-badge">perm: ' + esc(cmp.permission) + '</span>');
    if (cmp.readPermission)  badges.push('<span class="comp-badge">read: ' + esc(cmp.readPermission) + '</span>');
    if (cmp.writePermission) badges.push('<span class="comp-badge">write: ' + esc(cmp.writePermission) + '</span>');
    if (cmp.type === 'activity' && cmp.launchMode && cmp.launchMode !== 'standard')
        badges.push('<span class="comp-badge">launchMode: ' + esc(cmp.launchMode) + '</span>');
    if (cmp.type === 'provider' && cmp.grantUriPermissions)
        badges.push('<span class="comp-badge bad">grantUriPermissions</span>');
    if (cmp.type === 'provider' && cmp.authorities)
        badges.push('<span class="comp-badge">auth: ' + esc(cmp.authorities) + '</span>');

    const intents = (cmp.intentFilters || []).flatMap(f => f.actions || []).filter(a => a !== 'android.intent.action.MAIN');
    const schemes = (cmp.intentFilters || []).flatMap(f => (f.data || []).map(d => d.scheme || '')).filter(Boolean);

    let intentHtml = '';
    if (intents.length) intentHtml += '<div class="comp-intents"><span class="comp-intents-label">Actions</span> ' + intents.map(a => '<span class="meta-tag">' + esc(a.replace('android.intent.action.', '')) + '</span>').join(' ') + '</div>';
    if (schemes.length) intentHtml += '<div class="comp-intents"><span class="comp-intents-label">Schemes</span> ' + [...new Set(schemes)].map(s => '<span class="meta-tag">' + esc(s) + '://</span>').join(' ') + '</div>';

    const cmdsHtml = cmds.map(c => '<div class="comp-cmd mono" data-cmd="' + escAttr(c.cmd) + '" title="Click to copy"><span class="comp-cmd-desc">' + esc(c.desc) + '</span><span class="comp-cmd-line">' + esc(c.cmd) + '</span></div>').join('');

    return '<article class="comp-card ' + (cmp.exported ? 'exported' : 'private') + '" data-comp-id="comp-' + idx + '">' +
        '<button class="comp-card-header" aria-expanded="false" aria-controls="comp-body-' + idx + '">' +
            '<span class="comp-type-badge ' + cmp.type + '">' + cmp.type + '</span>' +
            '<span class="comp-name">' + esc(simple) + '</span>' +
            '<span class="comp-badges-inline">' + badges.join('') + '</span>' +
            '<span class="finding-toggle" aria-hidden="true">▾</span>' +
        '</button>' +
        '<div class="comp-card-body" id="comp-body-' + idx + '" hidden>' +
            '<div class="comp-fqn mono">' + esc(cmp.name) + '</div>' +
            intentHtml +
            (cmds.length ? '<details class="comp-cmds" open><summary>ADB / am test commands (' + cmds.length + ')</summary>' + cmdsHtml + '</details>' : '') +
        '</div>' +
    '</article>';
}

function generateExploitCommands(comp, packageName) {
    const cmds = [];
    if (!comp.name) return cmds;
    const fqn = comp.name.indexOf('.') >= 0 ? comp.name : (packageName ? packageName + '.' + comp.name : comp.name);
    const cn = packageName ? packageName + '/' + fqn : fqn;

    if (comp.type === 'activity') {
        cmds.push({ desc: 'Launch activity',            cmd: 'adb shell am start -n ' + cn });
        for (const f of (comp.intentFilters || [])) {
            for (const action of (f.actions || [])) {
                if (action === 'android.intent.action.MAIN') continue;
                let cmd = 'adb shell am start -n ' + cn + ' -a ' + action;
                for (const c of (f.categories || [])) cmd += ' -c ' + c;
                for (const d of (f.data || [])) {
                    if (d.scheme && d.host) {
                        const uri = d.scheme + '://' + d.host + (d.port ? ':' + d.port : '') + (d.path || d.pathPrefix || '/test');
                        cmd += ' -d "' + uri + '"';
                    } else if (d.scheme) {
                        cmd += ' -d "' + d.scheme + '://test"';
                    }
                }
                cmds.push({ desc: 'Action ' + action.replace('android.intent.action.', ''), cmd });
            }
        }
        if (comp.launchMode === 'singleTask' || comp.launchMode === 'singleInstance') {
            cmds.push({ desc: 'Task hijacking test',    cmd: 'adb shell am start -n ' + cn + ' --activity-clear-task' });
        }
    } else if (comp.type === 'service') {
        cmds.push({ desc: 'Start service',              cmd: 'adb shell am startservice -n ' + cn });
        for (const f of (comp.intentFilters || [])) {
            for (const action of (f.actions || [])) {
                cmds.push({ desc: 'Action ' + action.replace('android.intent.action.', ''), cmd: 'adb shell am startservice -n ' + cn + ' -a ' + action });
            }
        }
    } else if (comp.type === 'receiver') {
        for (const f of (comp.intentFilters || [])) {
            for (const action of (f.actions || [])) {
                const isSystem = action.indexOf('android.') === 0;
                const cmd = isSystem ? 'adb shell am broadcast -a ' + action : 'adb shell am broadcast -n ' + cn + ' -a ' + action;
                cmds.push({ desc: 'Broadcast ' + action.replace('android.intent.action.', ''), cmd });
            }
        }
        if (cmds.length === 0) cmds.push({ desc: 'Send broadcast', cmd: 'adb shell am broadcast -n ' + cn });
    } else if (comp.type === 'provider' && comp.authorities) {
        const auth = comp.authorities.split(';')[0];
        cmds.push({ desc: 'Query provider',             cmd: 'adb shell content query --uri content://' + auth + '/' });
        cmds.push({ desc: 'SQL injection probe',        cmd: 'adb shell content query --uri content://' + auth + '/ --where "1=1--"' });
        if (comp.grantUriPermissions) cmds.push({ desc: 'Read via URI grant', cmd: 'adb shell content read --uri content://' + auth + '/test' });
    }
    return cmds;
}

function renderCert(r) {
    const card = $('#certCard');
    if (card) {
        const c = r.certInfo || r.certificate || null;
        if (!c) {
            card.innerHTML = '<div class="no-data">No signing certificate found</div>';
        } else {
            const sub = c.subject || {};
            const iss = c.issuer || {};
            const val = c.validity || {};
            const debug = c.isDebug;
            const expired = c.isExpired;
            const sigAlg = c.sigAlg || '';
            const weak = ['MD5withRSA','SHA1withRSA'].indexOf(sigAlg) >= 0;
            card.innerHTML = html`
              <div class="prov-summary">
                <div class="prov-headline">
                  <span class="prov-name">${sub.CN || sub.O || '(unknown subject)'}</span>
                  ${debug ? raw('<span class="prov-dist badge-development">DEBUG</span>') : ''}
                  ${expired ? raw('<span class="prov-dist badge-ad-hoc">EXPIRED</span>') : ''}
                </div>
                <div class="info-grid">
                  <div class="info-item"><label>Subject CN</label><div class="value mono">${sub.CN || '-'}</div></div>
                  <div class="info-item"><label>Subject O</label><div class="value">${sub.O || '-'}</div></div>
                  <div class="info-item"><label>Subject OU</label><div class="value">${sub.OU || '-'}</div></div>
                  <div class="info-item"><label>Issuer CN</label><div class="value mono">${iss.CN || '-'}</div></div>
                  <div class="info-item"><label>Issuer O</label><div class="value">${iss.O || '-'}</div></div>
                  <div class="info-item"><label>Serial</label><div class="value mono">${c.serial || '-'}</div></div>
                  <div class="info-item"><label>Algorithm</label><div class="value ${weak ? 'bad' : 'good'}">${sigAlg || '-'}</div></div>
                  <div class="info-item"><label>Valid From</label><div class="value">${val.notBefore || '-'}</div></div>
                  <div class="info-item"><label>Valid Until</label><div class="value ${expired ? 'bad' : 'good'}">${val.notAfter || '-'}</div></div>
                  ${c.fingerprintSHA256 ? raw('<div class="info-item full"><label>SHA-256 Fingerprint</label><div class="value hash mono">' + esc(c.fingerprintSHA256) + '</div></div>') : ''}
                </div>
              </div>
            `;
        }
    }

    const sig = $('#sigSchemeCard');
    if (sig) {
        const hasV1 = (r.files || []).some(f => /^META-INF\/.*\.SF$/i.test(f));
        const hasV2 = !!r.hasV2Sig;
        sig.innerHTML = html`
          <div class="ats-flags">
            <span class="ats-flag ${hasV1 ? 'warn' : 'good'}">v1 (JAR): ${hasV1 ? 'present' : 'absent'}</span>
            <span class="ats-flag ${hasV2 ? 'good' : 'bad'}">v2: ${hasV2 ? 'present' : 'absent'}</span>
          </div>
          <p class="finding-description">v1 (JAR) signing alone is vulnerable to the Janus exploit on Android &lt; 7.0. APKs targeting modern devices should ship with v2 or v3 signatures.</p>
        `;
    }
}

function renderExplorer(r) {
    State.explorerFiles = r.files || [];
    State.explorerTree = r.fileTree || {};
    const treeContainer = $('#fileTree');
    treeContainer.innerHTML = buildTree(State.explorerTree, '');
    $('#totalFileCount') && ($('#totalFileCount').textContent = State.explorerFiles.length + ' files');
    populateQuickAccess(r);
    setupExplorerSearch();
    treeContainer.onclick = onTreeClick;
}

function onTreeClick(e) {
    const folderHeader = e.target.closest('.tree-folder-header');
    if (folderHeader) {
        const folder = folderHeader.parentElement;
        folder.classList.toggle('open');
        const ic = folderHeader.querySelector('.folder-icon');
        if (ic) ic.textContent = folder.classList.contains('open') ? '📂' : '📁';
        return;
    }
    const file = e.target.closest('.tree-file');
    if (file) openFile(file.dataset.path);
}

function buildTree(tree, prefix) {
    let out = '';
    const entries = Object.entries(tree).filter(([k]) => !k.startsWith('_')).sort((a, b) => {
        const aDir = a[1]._type === 'dir', bDir = b[1]._type === 'dir';
        if (aDir !== bDir) return aDir ? -1 : 1;
        return a[0].localeCompare(b[0]);
    });
    for (const [name, node] of entries) {
        if (node._type === 'dir') {
            const count = countFiles(node);
            out += '<div class="tree-folder" role="treeitem" aria-expanded="false">' +
                    '<button class="tree-folder-header" title="' + escAttr(prefix + name) + '">' +
                    '<span class="folder-chevron" aria-hidden="true">▶</span>' +
                    '<span class="folder-icon" aria-hidden="true">📁</span>' +
                    '<span class="folder-name">' + esc(name) + '</span>' +
                    '<span class="folder-count">' + count + '</span>' +
                    '</button>' +
                    '<div class="tree-folder-content">' + buildTree(node, prefix + name + '/') + '</div></div>';
        } else {
            const ext = name.split('.').pop().toLowerCase();
            const ic = fileIcon(ext, name);
            const lower = name.toLowerCase();
            const important = lower === 'androidmanifest.xml' || lower === 'classes.dex' || /^classes\d+\.dex$/.test(lower)
                            || lower === 'resources.arsc' || lower.endsWith('.rsa') || lower.endsWith('.dsa') || lower.endsWith('.ec');
            out += '<button class="tree-file' + (important ? ' important' : '') + '" data-path="' + escAttr(node._path) + '" data-ext="' + ext + '" title="' + escAttr(node._path) + '" role="treeitem">' +
                    '<span class="file-icon" aria-hidden="true">' + ic + '</span>' +
                    '<span class="file-name">' + esc(name) + '</span></button>';
        }
    }
    return out;
}

function countFiles(node) {
    let n = 0;
    for (const [k, v] of Object.entries(node)) {
        if (k.startsWith('_')) continue;
        if (v._type === 'dir') n += countFiles(v);
        else n++;
    }
    return n;
}

function fileIcon(ext, name) {
    const lower = (name || '').toLowerCase();
    if (lower === 'androidmanifest.xml') return '📋';
    if (ext === 'dex') return '⚙️';
    if (lower === 'resources.arsc') return '📦';
    const m = {
        java: '☕', kt: '🅺', smali: '🔧',
        xml: '📰', json: '📜', yaml: '📜', yml: '📜', properties: '📜',
        db: '🗄️', sqlite: '🗄️', sqlite3: '🗄️', realm: '🗄️',
        png: '🖼️', jpg: '🖼️', jpeg: '🖼️', gif: '🖼️', svg: '🖼️', webp: '🖼️', ico: '🖼️',
        js: '📒', html: '🌐', css: '🎨',
        cer: '🔐', pem: '🔐', p12: '🔐', rsa: '🔐', dsa: '🔐', ec: '🔐', mf: '📜', sf: '📜',
        so: '⚙️',
    };
    return m[ext] || '📄';
}

function populateQuickAccess(r) {
    const list = $('#quickAccessList');
    if (!list) return;
    const items = [];
    if (r.files && r.files.indexOf('AndroidManifest.xml') >= 0) {
        items.push({ path: 'AndroidManifest.xml', name: 'Manifest', icon: '📋', desc: 'AndroidManifest.xml' });
    }
    const dexFiles = (r.files || []).filter(f => /^classes\d*\.dex$/.test(f)).sort();
    for (const d of dexFiles.slice(0, 3)) {
        items.push({ path: d, name: d, icon: '⚙️', desc: 'DEX bytecode' });
    }
    if (r.files && r.files.indexOf('resources.arsc') >= 0) {
        items.push({ path: 'resources.arsc', name: 'resources.arsc', icon: '📦', desc: 'Compiled resources' });
    }
    const cert = (r.files || []).find(f => /META-INF\/.+\.(RSA|DSA|EC)$/i.test(f));
    if (cert) items.push({ path: cert, name: 'Cert', icon: '🔐', desc: 'Signing certificate' });
    list.innerHTML = items.length === 0
        ? '<span class="qa-empty">No key files found</span>'
        : items.map(f => html`
            <button class="quick-access-item" data-path="${f.path}" title="${f.path}">
              <span class="qa-icon" aria-hidden="true">${f.icon}</span>
              <div class="qa-text"><span class="qa-name">${f.name}</span><span class="qa-desc">${f.desc}</span></div>
            </button>`).join('');
    list.querySelectorAll('.quick-access-item').forEach(b => b.addEventListener('click', () => openFile(b.dataset.path)));
}

function setupExplorerSearch() {
    const input = $('#fileSearchInput');
    const results = $('#fileSearchResults');
    const hint = $('#explorerSearchHint');
    if (!input || !results) return;

    State.explorerSearchMode = State.explorerSearchMode || 'name';
    const placeholders = {
        name:    'Search file names…',
        content: 'Search inside parsed files (manifest, configs, smali)',
        strings: 'Search DEX string pool…',
    };
    const updatePlaceholder = () => { input.placeholder = placeholders[State.explorerSearchMode] || 'Search…'; };
    updatePlaceholder();

    $$('.explorer-search-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            $$('.explorer-search-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            State.explorerSearchMode = tab.dataset.searchMode;
            updatePlaceholder();
            if (input.value.trim()) doSearch();
            else { results.innerHTML = ''; if (hint) hint.textContent = ''; }
        });
    });

    const doSearch = () => {
        const q = input.value.trim();
        if (q.length < 2) { results.innerHTML = ''; if (hint) hint.textContent = ''; return; }
        const mode = State.explorerSearchMode;
        if (mode === 'name')         renderNameMatches(q);
        else if (mode === 'content') renderContentMatches(q);
        else if (mode === 'strings') renderStringMatches(q);
    };

    let t;
    input.oninput = () => {
        clearTimeout(t);
        t = setTimeout(doSearch, State.explorerSearchMode === 'name' ? 60 : 180);
    };

    function renderNameMatches(q) {
        const lq = q.toLowerCase();
        const matches = State.explorerFiles.filter(f => f.toLowerCase().includes(lq)).slice(0, 80);
        if (hint) hint.textContent = matches.length + ' file' + (matches.length === 1 ? '' : 's');
        if (matches.length === 0) {
            results.innerHTML = '<div class="search-result-item muted">No file name matches.</div>';
            return;
        }
        results.innerHTML = matches.map(f => '<button class="search-result-item" data-path="' + escAttr(f) + '"><span class="match-name">' + esc(f.split('/').pop()) + '</span><span class="match-path">' + esc(f) + '</span></button>').join('');
        results.querySelectorAll('[data-path]').forEach(b => b.addEventListener('click', () => openFile(b.dataset.path)));
    }

    function renderContentMatches(q) {
        const r = State.currentResults || {};
        const fc = r.fileContents || {};
        const lq = q.toLowerCase();
        const hits = [];
        for (const path of Object.keys(fc)) {
            const content = fc[path];
            if (typeof content !== 'string') continue;
            const lower = content.toLowerCase();
            let idx = lower.indexOf(lq);
            if (idx < 0) continue;
            let count = 0;
            const previews = [];
            while (idx >= 0 && count < 3) {
                const start = Math.max(0, idx - 30);
                const end   = Math.min(content.length, idx + q.length + 30);
                previews.push({ snippet: content.slice(start, end), pos: idx });
                idx = lower.indexOf(lq, idx + q.length);
                count++;
            }
            const total = (lower.match(new RegExp(escRegex(lq), 'g')) || []).length;
            hits.push({ path, previews, total });
            if (hits.length >= 50) break;
        }
        if (hint) hint.textContent = hits.length + ' file' + (hits.length === 1 ? '' : 's') + ' with matches';
        if (hits.length === 0) {
            results.innerHTML = '<div class="search-result-item muted">No content matches. Only parsed text files are searched (manifest, configs, decoded resources).</div>';
            return;
        }
        results.innerHTML = hits.map(h => {
            const prev = h.previews.map(p => {
                const start = Math.max(0, p.pos - 30);
                const offset = p.pos - start;
                const snippet = p.snippet;
                const before = snippet.slice(0, offset);
                const match  = snippet.slice(offset, offset + q.length);
                const after  = snippet.slice(offset + q.length);
                return '<div class="content-preview mono">' + esc(before) + '<mark>' + esc(match) + '</mark>' + esc(after) + '</div>';
            }).join('');
            return '<button class="search-result-item content-result" data-path="' + escAttr(h.path) + '">' +
                '<span class="match-name">' + esc(h.path.split('/').pop()) + '<span class="match-count">' + h.total + ' hit' + (h.total === 1 ? '' : 's') + '</span></span>' +
                '<span class="match-path">' + esc(h.path) + '</span>' +
                prev +
            '</button>';
        }).join('');
        results.querySelectorAll('[data-path]').forEach(b => b.addEventListener('click', () => openFile(b.dataset.path)));
    }

    function renderStringMatches(q) {
        const r = State.currentResults || {};
        const all = r.strings || [];
        const lq = q.toLowerCase();
        const hits = [];
        for (let i = 0; i < all.length && hits.length < 500; i++) {
            if (all[i] && all[i].toLowerCase().indexOf(lq) >= 0) hits.push(all[i]);
        }
        if (hint) hint.textContent = hits.length + ' string' + (hits.length === 1 ? '' : 's') + ' from DEX pool';
        if (hits.length === 0) {
            results.innerHTML = '<div class="search-result-item muted">No DEX strings match.</div>';
            return;
        }
        results.innerHTML = hits.slice(0, 200).map(s => {
            const lower = s.toLowerCase();
            const idx = lower.indexOf(lq);
            const before = s.slice(0, idx);
            const match  = s.slice(idx, idx + q.length);
            const after  = s.slice(idx + q.length);
            return '<div class="search-result-item string-result"><span class="match-name mono">' + esc(before) + '<mark>' + esc(match) + '</mark>' + esc(after) + '</span></div>';
        }).join('') + (hits.length > 200 ? '<div class="search-result-item muted">… ' + (hits.length - 200) + ' more</div>' : '');
    }
}

function escRegex(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function openFile(path) {
    if (!path) return;
    State.currentOpenFile = path;
    State.currentOpenBytes = null;
    $('#currentFilePath').textContent = path;
    const dl = $('#downloadFileBtn'); if (dl) dl.disabled = true;
    const viewer = $('#fileViewer');
    viewer.innerHTML = '<div class="loading-file">Loading…</div>';
    try {
        const r = State.currentResults || {};
        if (path === 'AndroidManifest.xml' && r.manifestStr) {
            viewer.innerHTML = '<pre class="code-viewer mono">' + esc(r.manifestStr) + '</pre>';
            const data = new TextEncoder().encode(r.manifestStr);
            State.currentOpenBytes = data;
            if (dl) dl.disabled = false;
            return;
        }
        if (path === 'resources.arsc' && r.fileContents && r.fileContents['resources.arsc']) {
            viewer.innerHTML = '<pre class="code-viewer mono">' + esc(r.fileContents['resources.arsc']) + '</pre>';
            State.currentOpenBytes = new TextEncoder().encode(r.fileContents['resources.arsc']);
            if (dl) dl.disabled = false;
            return;
        }
        const zip = await getViewerZip();
        if (!zip) {
            viewer.innerHTML = '<div class="no-data">Drop the APK again to enable the inline viewer (analysis results remain loaded).</div>';
            return;
        }
        const entry = zip.file(path);
        if (!entry) {
            viewer.innerHTML = '<div class="no-data">File not found in archive: ' + esc(path) + '</div>';
            return;
        }
        const data = await entry.async('arraybuffer');
        State.currentOpenBytes = new Uint8Array(data);
        if (dl) dl.disabled = false;
        renderFile(viewer, path, data);
    } catch (e) {
        viewer.innerHTML = '<div class="no-data">' + esc(e.message || 'Unable to read file') + '</div>';
    }
}

function downloadCurrentFile() {
    if (!State.currentOpenBytes || !State.currentOpenFile) return;
    const blob = new Blob([State.currentOpenBytes]);
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = State.currentOpenFile.split('/').pop();
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(a.href); }, 800);
}

function renderFile(viewer, path, arrayBuffer) {
    const bytes = new Uint8Array(arrayBuffer);
    const ext = path.split('.').pop().toLowerCase();
    const lower = path.toLowerCase();

    if (lower === 'androidmanifest.xml' || ext === 'arsc' || ext === 'dex') {
        openBinaryViewer(viewer, path, bytes);
        return;
    }
    if (['png','jpg','jpeg','gif','webp','svg','ico'].indexOf(ext) >= 0) {
        const mime = ext === 'jpg' ? 'image/jpeg' : (ext === 'svg' ? 'image/svg+xml' : ('image/' + ext));
        const blob = new Blob([bytes], { type: mime });
        const url = URL.createObjectURL(blob);
        viewer.innerHTML = '<div class="image-viewer">' +
            '<div class="image-info">' +
            '<span class="info-badge">' + ext.toUpperCase() + '</span>' +
            '<span class="info-badge">' + fmtSize(bytes.length) + '</span>' +
            '</div>' +
            '<div class="image-container"><img src="' + url + '" alt="' + escAttr(path) + '" loading="lazy"></div>' +
            '</div>';
        return;
    }

    if (looksText(bytes)) {
        const text = new TextDecoder('utf-8').decode(bytes);
        viewer.innerHTML = '<pre class="code-viewer mono">' + esc(text) + '</pre>';
        return;
    }
    openBinaryViewer(viewer, path, bytes);
}

function looksText(bytes) {
    const sample = Math.min(bytes.length, 1000);
    let printable = 0;
    for (let i = 0; i < sample; i++) {
        const b = bytes[i];
        if (b === 9 || b === 10 || b === 13) { printable++; continue; }
        if (b >= 32 && b <= 126) { printable++; continue; }
        if (b === 0) return false;
    }
    return printable / sample > 0.95;
}

const HEX_PAGE_BYTES = 4096;

function openBinaryViewer(viewer, path, bytes) {
    const totalPages = Math.max(1, Math.ceil(bytes.length / HEX_PAGE_BYTES));
    let off = 0;
    const render = () => {
        const cur = Math.floor(off / HEX_PAGE_BYTES);
        viewer.innerHTML = '<div class="binary-viewer">' +
            '<div class="binary-toolbar">' +
                '<div class="binary-info"><span class="info-badge">Binary</span><span class="info-badge">' + fmtSize(bytes.length) + '</span></div>' +
            '</div>' +
            '<div class="hex-controls">' +
                '<button class="hex-nav" data-action="first" ' + (cur === 0 ? 'disabled' : '') + '>⏮</button>' +
                '<button class="hex-nav" data-action="prev"  ' + (cur === 0 ? 'disabled' : '') + '>◀</button>' +
                '<span class="hex-page-info">Page ' + (cur + 1) + ' / ' + totalPages + ' · offset 0x' + off.toString(16) + '</span>' +
                '<button class="hex-nav" data-action="next" ' + (cur >= totalPages - 1 ? 'disabled' : '') + '>▶</button>' +
                '<button class="hex-nav" data-action="last" ' + (cur >= totalPages - 1 ? 'disabled' : '') + '>⏭</button>' +
            '</div>' +
            '<div class="binary-body">' + renderHexLines(bytes, off) + '</div>' +
        '</div>';
        viewer.querySelectorAll('.hex-nav').forEach(b => b.addEventListener('click', () => {
            const action = b.dataset.action;
            const cur2 = Math.floor(off / HEX_PAGE_BYTES);
            if (action === 'first') off = 0;
            else if (action === 'prev')  off = Math.max(0, (cur2 - 1) * HEX_PAGE_BYTES);
            else if (action === 'next')  off = Math.min((totalPages - 1) * HEX_PAGE_BYTES, (cur2 + 1) * HEX_PAGE_BYTES);
            else if (action === 'last')  off = (totalPages - 1) * HEX_PAGE_BYTES;
            render();
        }));
    };
    render();
}

function renderHexLines(bytes, offset) {
    const start = offset;
    const end = Math.min(bytes.length, start + HEX_PAGE_BYTES);
    let out = '<div class="hex-table-header"><span>Offset</span><span>Hex</span><span>ASCII</span></div><div class="hex-dump">';
    for (let i = start; i < end; i += 16) {
        let hexCol = '';
        let asciiCol = '';
        for (let j = 0; j < 16; j++) {
            const o = i + j;
            const b = bytes[o];
            if (b === undefined) { hexCol += '   '; asciiCol += ' '; continue; }
            const hex = b.toString(16).padStart(2, '0');
            const ch = (b >= 32 && b < 127) ? String.fromCharCode(b) : '.';
            hexCol += hex + ' ';
            asciiCol += esc(ch);
        }
        out += '<div class="hex-line" data-off="' + i + '"><span class="hex-offset mono">' + i.toString(16).padStart(8, '0') + '</span><span class="hex-bytes mono">' + hexCol + '</span><span class="hex-ascii mono">' + asciiCol + '</span></div>';
    }
    out += '</div>';
    return out;
}

function navigateToFile(file, line) {
    if (!file) return;
    switchTab('explorer');
    openFile(file).then(() => {
        if (line > 0) setTimeout(() => {
            const target = $('.code-viewer');
            if (target) {
                const els = target.querySelectorAll('div');
                if (els[line - 1]) els[line - 1].scrollIntoView({ block: 'center' });
            }
        }, 200);
    });
}

function setupTabs() {
    const TAB_NAMES = ['overview', 'findings', 'manifest', 'components', 'cert', 'explorer'];
    $$('.tab').forEach((t) => {
        t.addEventListener('click', () => switchTab(t.dataset.tab));
        t.addEventListener('keydown', (e) => {
            const tabs = $$('.tab');
            const idx = tabs.indexOf(t);
            let next = -1;
            if (e.key === 'ArrowRight') next = (idx + 1) % tabs.length;
            else if (e.key === 'ArrowLeft')  next = (idx - 1 + tabs.length) % tabs.length;
            else if (e.key === 'Home')       next = 0;
            else if (e.key === 'End')        next = tabs.length - 1;
            if (next >= 0) {
                e.preventDefault();
                tabs[next].focus();
                switchTab(tabs[next].dataset.tab);
            }
        });
    });
    document.addEventListener('keydown', (e) => {
        const ae = document.activeElement;
        const inField = ae && (ae.tagName === 'INPUT' || ae.tagName === 'TEXTAREA' || ae.tagName === 'SELECT' || ae.isContentEditable);
        if (e.key === '/' && !inField) {
            const search = $('#findingsSearchInput');
            if ($('#panel-findings') && $('#panel-findings').classList.contains('active') && search) {
                e.preventDefault(); search.focus();
            }
        }
        if (e.key === 'Escape') {
            const dd = $('#exportDropdown');
            if (dd && !dd.hidden) { dd.hidden = true; $('#exportMenuBtn').setAttribute('aria-expanded', 'false'); return; }
            $$('#findingsList .finding-body').forEach(b => b.hidden = true);
            $$('#findingsList .finding-header').forEach(h => h.setAttribute('aria-expanded', 'false'));
        }
        if (e.key >= '1' && e.key <= '6' && (e.altKey || e.metaKey)) {
            e.preventDefault();
            switchTab(TAB_NAMES[parseInt(e.key, 10) - 1]);
        }
    });
}

function setupFindingsFilters() {
    $$('.filter-btn[data-filter]').forEach(b => b.addEventListener('click', () => {
        $$('.filter-btn[data-filter]').forEach(x => x.classList.remove('active'));
        b.classList.add('active');
        const f = b.dataset.filter;
        State.activeSeverityFilter = f === 'all' ? new Set(SEVS) : new Set([f]);
        State.findingsPage = 0;
        renderFindings(State.currentResults);
    }));
    $('#findingsSearchInput') && $('#findingsSearchInput').addEventListener('input', (e) => {
        State.findingsSearch = e.target.value;
        State.findingsPage = 0;
        renderFindings(State.currentResults);
    });
    $('#findingsSort') && $('#findingsSort').addEventListener('change', (e) => {
        State.findingsSort = e.target.value;
        renderFindings(State.currentResults);
    });
    const conf = $('#findingsMinConfidence');
    const confLabel = $('#findingsMinConfidenceLabel');
    conf && conf.addEventListener('input', () => {
        State.findingsMinConfidence = parseInt(conf.value, 10) || 0;
        if (confLabel) confLabel.textContent = '≥ ' + State.findingsMinConfidence + '%';
        State.findingsPage = 0;
        renderFindings(State.currentResults);
    });
    $('#expandAllBtn') && $('#expandAllBtn').addEventListener('click', () => {
        $$('#findingsList .finding-header').forEach(h => h.setAttribute('aria-expanded', 'true'));
        $$('#findingsList .finding-body').forEach(b => b.hidden = false);
    });
    $('#collapseAllBtn') && $('#collapseAllBtn').addEventListener('click', () => {
        $$('#findingsList .finding-header').forEach(h => h.setAttribute('aria-expanded', 'false'));
        $$('#findingsList .finding-body').forEach(b => b.hidden = true);
    });
}

function setupExport() {
    const btn = $('#exportMenuBtn');
    const dd  = $('#exportDropdown');
    if (!btn || !dd) return;
    btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const open = !dd.hidden;
        dd.hidden = open;
        btn.setAttribute('aria-expanded', String(!open));
    });
    document.addEventListener('click', () => {
        dd.hidden = true;
        btn.setAttribute('aria-expanded', 'false');
    });
    dd.addEventListener('click', (e) => e.stopPropagation());
    dd.querySelectorAll('[data-export]').forEach(b => b.addEventListener('click', () => {
        const kind = b.dataset.export;
        if (!State.currentResults) return;
        try {
            if (kind === 'pdf') {
                if (!IPAA.PDF) throw new Error('PDF module not loaded');
                IPAA.PDF.exportPDF(State.currentResults);
                toast('PDF report generated', 'success');
            } else {
                IPAA.Export.exportFile(kind, State.currentResults);
                toast('Exported ' + kind.toUpperCase(), 'success');
            }
        }
        catch (e) { toast('Export failed: ' + e.message, 'error'); }
        dd.hidden = true;
        btn.setAttribute('aria-expanded', 'false');
    }));
}

function setupTheme() {
    const THEMES = ['dark', 'light'];
    const stored = localStorage.getItem('theme');
    const queryTheme = new URLSearchParams(location.search).get('theme');
    document.documentElement.dataset.theme = (queryTheme && THEMES.indexOf(queryTheme) >= 0) ? queryTheme
        : stored || (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
    $('#themeToggle') && $('#themeToggle').addEventListener('click', () => {
        const cur = document.documentElement.dataset.theme || 'dark';
        const idx = THEMES.indexOf(cur);
        const next = THEMES[(idx + 1) % THEMES.length];
        document.documentElement.dataset.theme = next;
        localStorage.setItem('theme', next);
    });
}

function setupDragDrop() {
    const dropZone = $('#dropZone');
    const input    = $('#fileInput');
    if (dropZone) {
        dropZone.addEventListener('click', () => input.click());
        dropZone.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
        dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('drag-over'); });
        dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault(); dropZone.classList.remove('drag-over');
            const f = e.dataTransfer.files[0];
            if (f) startAnalysis(f);
        });
    }
    if (input) input.addEventListener('change', () => {
        const f = input.files[0];
        if (f) startAnalysis(f);
        input.value = '';
    });
    window.addEventListener('dragover', (e) => e.preventDefault());
    window.addEventListener('drop', (e) => {
        e.preventDefault();
        const f = e.dataTransfer.files[0];
        if (f && !document.body.classList.contains('analyzing')) startAnalysis(f);
    });
}

function setupGlobalErrors() {
    window.addEventListener('error', (e) => {
        if (e.error && e.error.message) {
            console.error('[APK Auditor] error:', e.error);
            if (document.body.classList.contains('analyzing')) {
                hideProgress();
                toast('Analysis failed, ' + (e.error.message || 'unknown error'), 'error');
            }
        }
    });
    window.addEventListener('unhandledrejection', (e) => {
        console.error('[APK Auditor] unhandled promise:', e.reason);
        if (document.body.classList.contains('analyzing')) {
            hideProgress();
            toast('Analysis failed, ' + ((e.reason && e.reason.message) || 'unknown error'), 'error');
        }
    });
}

function setupCursorSpot() {
    const hero = document.querySelector('.hero');
    const spot = document.getElementById('cursorSpot');
    if (!hero || !spot) return;
    let rafId = 0;
    let targetX = 0, targetY = 0;
    let curX = 0, curY = 0;
    hero.addEventListener('pointermove', (e) => {
        const rect = hero.getBoundingClientRect();
        targetX = e.clientX - rect.left;
        targetY = e.clientY - rect.top;
        if (!rafId) {
            const tick = () => {
                curX += (targetX - curX) * 0.18;
                curY += (targetY - curY) * 0.18;
                spot.style.left = curX + 'px';
                spot.style.top  = curY + 'px';
                if (Math.abs(targetX - curX) > 0.5 || Math.abs(targetY - curY) > 0.5) {
                    rafId = requestAnimationFrame(tick);
                } else {
                    rafId = 0;
                }
            };
            rafId = requestAnimationFrame(tick);
        }
    });
}

const PREVIEW_SAMPLES = [
    { sev: 'ISSUE',   sevClass: 'preview-sev-high', title: 'Hardcoded API Key',
      meta: ['CWE-798', 'OWASP M9', 'MASVS STORAGE-14'],
      file: 'classes.dex · com/example/Config.java:14', conf: '95%', match: 'AKIA' + 'IOSFODNN7' + 'EXAMPLE' },
    { sev: 'ISSUE',   sevClass: 'preview-sev-high', title: 'Debug Certificate',
      meta: ['CWE-321', 'OWASP M9', 'MASVS CODE-1'],
      file: 'META-INF/CERT.RSA', conf: '99%', match: 'CN=Android Debug, O=Android, C=US' },
    { sev: 'ISSUE',   sevClass: 'preview-sev-high', title: 'Cleartext HTTP Allowed',
      meta: ['CWE-319', 'OWASP M3', 'MASVS NETWORK-1'],
      file: 'res/xml/network_security_config.xml', conf: '90%', match: 'cleartextTrafficPermitted="true"' },
    { sev: 'ISSUE',   sevClass: 'preview-sev-high', title: 'Stripe Secret Key',
      meta: ['CWE-798', 'OWASP M9', 'MASVS STORAGE-14'],
      file: 'assets/config.json:12', conf: '95%', match: 'sk_' + 'live_' + '4eC39HqLyjWDarjtT1zdp7dc' },
    { sev: 'ISSUE',   sevClass: 'preview-sev-warning', title: 'Exported Activity Without Permission',
      meta: ['CWE-926', 'OWASP M1', 'MASVS PLATFORM-1'],
      file: 'AndroidManifest.xml', conf: '80%', match: 'android:exported="true" without android:permission' },
];

function setupPreviewRotator() {
    const card = document.getElementById('previewCard');
    if (!card) return;
    let idx = 0;
    const apply = () => {
        const s = PREVIEW_SAMPLES[idx];
        const sevEl   = card.querySelector('[data-field="sev"]');
        const titleEl = card.querySelector('[data-field="title"]');
        const confEl  = card.querySelector('[data-field="conf"]');
        const metaEl  = card.querySelector('[data-field="meta"]');
        const fileEl  = card.querySelector('[data-field="file"]');
        const matchEl = card.querySelector('[data-field="match"]');
        if (sevEl) { sevEl.textContent = s.sev; sevEl.className = 'preview-sev ' + s.sevClass; }
        if (titleEl) titleEl.textContent = s.title;
        if (confEl)  confEl.textContent  = s.conf;
        if (metaEl)  metaEl.innerHTML    = s.meta.map(t => '<span class="preview-tag">' + esc(t) + '</span>').join('');
        if (fileEl)  fileEl.textContent  = s.file;
        if (matchEl) matchEl.textContent = s.match;
        card.style.borderLeftColor = s.sevClass === 'preview-sev-warning' ? 'var(--orange)' : 'var(--red)';
    };
    setInterval(() => {
        card.classList.add('swapping');
        setTimeout(() => {
            idx = (idx + 1) % PREVIEW_SAMPLES.length;
            apply();
            card.classList.remove('swapping');
        }, 400);
    }, 3600);
}

function init() {
    setupGlobalErrors();
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.getRegistrations().then(regs => regs.forEach(r => r.unregister())).catch(() => {});
        if (window.caches) caches.keys().then(ks => ks.forEach(k => caches.delete(k))).catch(() => {});
    }
    setupTheme();
    setupTabs();
    setupFindingsFilters();
    setupExport();
    setupDragDrop();
    setupCursorSpot();
    setupPreviewRotator();
    $('#newScanBtn') && $('#newScanBtn').addEventListener('click', () => $('#fileInput').click());
    $('#heroCta') && $('#heroCta').addEventListener('click', () => $('#fileInput').click());
    $('#downloadFileBtn') && $('#downloadFileBtn').addEventListener('click', downloadCurrentFile);
    document.querySelectorAll('a.logo, .logo[href]').forEach(el => {
        el.addEventListener('click', (e) => {
            e.preventDefault();
            showLanding();
        });
    });
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();

})();

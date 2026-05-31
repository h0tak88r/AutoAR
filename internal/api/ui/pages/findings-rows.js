/**
 * findings-rows.js
 * ──────────────────────────────────────────────────────────────────────────────
 * Generic findings-table renderer.
 *
 * All module-specific logic now lives in module-registry.js.
 * This file only knows about cells and rows — it is module-agnostic.
 * ──────────────────────────────────────────────────────────────────────────────
 */
(() => {
  'use strict';

  const esc     = v  => (typeof window.esc     === 'function' ? window.esc(v)     : String(v ?? ''));
  const escAttr = v  => (typeof window.escAttr === 'function' ? window.escAttr(v) : String(v ?? ''));
  const reg     = () => window.ModuleRegistry; // lazy ref — registry loads before this file

  /* ── HTTP status colour (reused from result-tables) ──────────────────────── */
  function httpStatusColor(code) {
    const n = Number(code);
    if (n >= 200 && n < 300) return 'var(--accent-emerald)';
    if (n >= 300 && n < 400) return 'var(--accent-cyan)';
    if (n >= 400 && n < 500) return 'var(--accent-amber)';
    if (n >= 500)             return 'var(--accent-red)';
    return 'var(--text-muted)';
  }

  /* ══════════════════════════════════════════════════════════════════════════
     CELL RENDERERS
     Each renderer(value, col) → <td>...</td> HTML string.
     `col` is the column definition from the registry.
  ══════════════════════════════════════════════════════════════════════════ */

  const W = col =>
    col.w    ? `width:${col.w};flex-shrink:0;` :
    col.flex ? `flex:${col.flex};min-width:0;`  : '';
  const ALIGN = col => col.align ? `text-align:${col.align};` : '';
  const BASE   = 'padding:8px 12px;vertical-align:middle;overflow:hidden;';
  const TRUNC  = 'text-overflow:ellipsis;white-space:nowrap;';
  const MONO   = "font-family:'JetBrains Mono',monospace;font-size:11.5px;";

  const CELL = {

    /* clickable URL — cyan by default */
    'link'(v, col) {
      const { href, label, color } = typeof v === 'object' ? v : { href: '#', label: String(v ?? '') };
      const display = label.length > 65 ? label.slice(0, 63) + '…' : label;
      const c = color || 'var(--accent-cyan)';
      return `<td style="${BASE}${W(col)}${TRUNC}${ALIGN(col)}">
        <a href="${esc(href)}" target="_blank" rel="noopener"
           onclick="event.stopPropagation()" title="${esc(label)}"
           style="${MONO}color:${c};text-decoration:none">${esc(display)}</a></td>`;
    },

    /* amber-coloured link variant (JS files) */
    'link-amber'(v, col) {
      return CELL['link']({ ...(typeof v === 'object' ? v : { href:'#', label: String(v??'') }), color: '#f59e0b' }, col);
    },

    /* severity badge */
    'sev-badge'(v, col) {
      const m = typeof v === 'object' ? v : reg().sevMeta(v);
      return `<td style="${BASE}${W(col)}${ALIGN(col)}">
        <span style="display:inline-block;background:${m.bg};border:1px solid ${m.color}44;
                     color:${m.color};font-size:9px;font-weight:800;letter-spacing:.7px;
                     padding:2px 8px;border-radius:4px;min-width:36px">${esc(m.label)}</span></td>`;
    },

    /* HTTP status code with colour */
    'http-status'(v, col) {
      const c = httpStatusColor(v);
      return `<td style="${BASE}${W(col)}${ALIGN(col)}">
        <span style="${MONO}color:${c};font-weight:700">${esc(String(v))}</span></td>`;
    },

    /* two stacked lines: primary (bold) + secondary (muted) */
    'two-line'(v, col) {
      const { primary, secondary } = typeof v === 'object' ? v : { primary: String(v ?? ''), secondary: '' };
      const p = primary.length > 60 ? primary.slice(0, 58) + '…' : primary;
      return `<td style="${BASE}${W(col)}${ALIGN(col)}">
        <div style="${TRUNC}font-size:12px;font-weight:600;color:var(--text-primary)" title="${esc(primary)}">${esc(p)}</div>
        ${secondary ? `<div style="${TRUNC}${MONO}font-size:10px;color:var(--text-muted)">${esc(secondary)}</div>` : ''}
      </td>`;
    },

    /* two stacked lines, both monospaced */
    'two-line-mono'(v, col) {
      const { primary, secondary } = typeof v === 'object' ? v : { primary: String(v ?? ''), secondary: '' };
      const p = primary.length > 60 ? primary.slice(0, 58) + '…' : primary;
      return `<td style="${BASE}${W(col)}${ALIGN(col)}">
        <div style="${TRUNC}${MONO}font-size:11.5px;color:var(--text-secondary)" title="${esc(primary)}">${esc(p)}</div>
        ${secondary ? `<div style="${TRUNC}${MONO}font-size:10px;color:var(--accent-amber)">${esc(secondary)}</div>` : ''}
      </td>`;
    },

    /* plain monospace */
    'mono'(v, col) {
      const t = String(v ?? '');
      const d = t.length > 60 ? t.slice(0, 58) + '…' : t;
      return `<td style="${BASE}${W(col)}${TRUNC}${ALIGN(col)}">
        <span style="${MONO}color:var(--text-primary)" title="${esc(t)}">${esc(d)}</span></td>`;
    },

    /* muted monospace */
    'mono-muted'(v, col) {
      return `<td style="${BASE}${W(col)}${TRUNC}${ALIGN(col)}">
        <span style="${MONO}color:var(--text-muted)">${esc(String(v ?? ''))}</span></td>`;
    },

    /* amber monospace */
    'mono-amber'(v, col) {
      const t = String(v ?? '');
      return `<td style="${BASE}${W(col)}${TRUNC}${ALIGN(col)}">
        <span style="${MONO}font-size:11px;color:var(--accent-amber)">${esc(t)}</span></td>`;
    },

    /* truncated mono */
    'mono-trunc'(v, col) { return CELL['mono'](v, col); },

    /* muted truncated plain text */
    'muted-trunc'(v, col) {
      const t = String(v ?? '');
      return `<td style="${BASE}${W(col)}${TRUNC}${ALIGN(col)}">
        <span style="font-size:11px;color:var(--text-muted)" title="${esc(t)}">${esc(t)}</span></td>`;
    },

    /* truncated plain text (no mono) */
    'trunc'(v, col) {
      const t = String(v ?? '');
      const d = t.length > 80 ? t.slice(0, 78) + '…' : t;
      return `<td style="${BASE}${W(col)}${TRUNC}${ALIGN(col)}">
        <span style="font-size:11.5px;color:var(--text-primary)" title="${esc(t)}">${esc(d)}</span></td>`;
    },

    /* bold primary text (non-link) */
    'bold-text'(v, col) {
      const t = String(v ?? '');
      return `<td style="${BASE}${W(col)}${TRUNC}${ALIGN(col)}">
        <span style="${MONO}font-size:11.5px;font-weight:600;color:var(--text-primary)" title="${esc(t)}">${esc(t)}</span></td>`;
    },

    /* coloured pill badge */
    'badge-pill'(v, col) {
      const { label, color } = typeof v === 'object' ? v : { label: String(v ?? ''), color: '#a78bfa' };
      return `<td style="${BASE}${W(col)}${ALIGN(col)}">
        <span style="background:${color}1a;border:1px solid ${color}55;color:${color};
                     font-size:10px;font-weight:700;padding:2px 8px;border-radius:12px;
                     white-space:nowrap">${esc(label)}</span></td>`;
    },

    /* small label badge (e.g. "JS") with custom bg/color */
    'label-badge'(v, col) {
      const { label, bg, color } = typeof v === 'object' ? v : { label: String(v??''), bg:'rgba(255,255,255,.06)', color:'#94a3b8' };
      return `<td style="${BASE}${W(col)}${ALIGN(col)}">
        <span style="background:${bg};color:${color};font-size:9px;font-weight:800;
                     padding:2px 7px;border-radius:4px">${esc(label)}</span></td>`;
    },

    /* boolean verified badge */
    'bool-badge'(v, col) {
      const ok = v === true || v === 'true';
      const [label, color] = ok ? [' yes', '#22c55e'] : ['X no', '#94a3b8'];
      return `<td style="${BASE}${W(col)}${ALIGN(col)}">
        <span style="${MONO}font-size:10px;font-weight:700;color:${color}">${label}</span></td>`;
    },

    /* link if href present, monospace text otherwise */
    'link-or-mono'(v, col) {
      const { href, label, isLink } = typeof v === 'object' ? v : { href:'#', label: String(v??''), isLink:false };
      const d = label.length > 60 ? label.slice(0, 58) + '…' : label;
      const inner = isLink
        ? `<a href="${esc(href)}" target="_blank" rel="noopener" onclick="event.stopPropagation()"
              style="${MONO}font-size:11px;color:var(--accent-cyan);text-decoration:none"
              title="${esc(label)}">${esc(d)}</a>`
        : `<span style="${MONO}font-size:11px;color:var(--text-secondary)" title="${esc(label)}">${esc(d)}</span>`;
      return `<td style="${BASE}${W(col)}${TRUNC}${ALIGN(col)}">${inner}</td>`;
    },

    /* module icon + name badge */
    'mod-badge'(v, col) {
      const m = v || {};
      return `<td style="${BASE}${W(col)}${TRUNC}${ALIGN(col)}">
        <span style="font-size:11px;font-weight:500;color:${esc(m.color||'#94a3b8')}">
          ${esc(m.icon||'')} ${esc(m.name||'')}</span></td>`;
    },
  };

  /* fallback for unknown render types */
  function renderCell(type, value, col) {
    const fn = CELL[type];
    if (fn) return fn(value, col);
    return `<td style="${BASE}${W(col)}">${esc(String(value ?? ''))}</td>`;
  }

  /* ══════════════════════════════════════════════════════════════════════════
     DETAIL PANEL
     Expandable row shown when user clicks a Nuclei (or other) finding row.
  ══════════════════════════════════════════════════════════════════════════ */

  function renderDetailPanel(fields, colCount, rowId) {
    if (!fields || !fields.length) return '';
    const cells = fields.map(f => {
      const style = f.full ? 'grid-column:1/-1;' : '';
      let val;
      if (f.code) {
        val = `<pre style="font-size:10px;color:#a0ffb0;background:rgba(0,0,0,.3);
                           padding:8px;border-radius:6px;overflow-x:auto;
                           white-space:pre-wrap;word-break:break-all;margin:4px 0 0"
                >${esc(f.value)}</pre>`;
      } else if (f.isLink && f.value.startsWith('http')) {
        val = `<a href="${esc(f.value)}" target="_blank"
                  style="${MONO}font-size:11px;color:var(--accent-cyan)">${esc(f.value)}</a>`;
      } else {
        val = `<span style="${MONO}font-size:11px;color:var(--text-primary);word-break:break-all">${esc(f.value)}</span>`;
      }
      return `<div style="${style}margin-bottom:6px">
        <span style="color:var(--text-muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px">${esc(f.label)}</span><br>${val}
      </div>`;
    }).join('');

    return `<tr id="${escAttr(rowId)}" style="display:none">
      <td colspan="${colCount}" style="padding:0;border-top:1px solid rgba(255,255,255,.07)">
        <div style="padding:14px 20px;background:rgba(0,0,0,.22);
                    display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));
                    gap:12px 20px">${cells}</div>
      </td>
    </tr>`;
  }

  /* ══════════════════════════════════════════════════════════════════════════
     ROW BUILDER — the single entry point used by scan-detail / result-tables
  ══════════════════════════════════════════════════════════════════════════ */

  /**
   * Build one <tr> (+ optional hidden detail <tr>) for a single finding.
   *
   * @param {object} finding    - raw finding object from the API
   * @param {number} idx        - row index (for zebra stripe)
   * @param {string} activeKind - module tab key (e.g. 'nuclei', 'ffuf', 'mod:gf')
   * @param {object} modInfo    - { icon, name, color } from getModuleDisplayInfo()
   * @returns {string} HTML string (one or two <tr> elements)
   */
  function buildFindingRow(finding, idx, activeKind, modInfo) {
    const schema    = reg().get(activeKind);
    const cols      = schema.columns;
    const data      = schema.extract(finding, modInfo);
    const colCount  = cols.length + 1; // +1 for checkbox col

    /* detail fields (may be empty) */
    const detailFields = reg().detail(activeKind, finding);
    const hasDetail    = detailFields.length > 0;
    const rowId        = hasDetail ? `dr-${idx}-${Math.random().toString(36).slice(2, 7)}` : '';

    /* zebra stripe */
    const zebra = idx % 2 ? 'background:rgba(255,255,255,.012)' : '';

    /* click handler — only toggle detail if it exists */
    const clickHandler = hasDetail
      ? `onclick="(function(){var d=document.getElementById('${rowId}');if(d)d.style.display=d.style.display==='none'?'table-row':'none';})()"  style="cursor:pointer;${zebra}"`
      : `style="cursor:pointer;${zebra}"`;

    /* checkbox cell */
    const cbCell = `<td style="padding:8px 10px;width:34px;text-align:center;vertical-align:middle">
      <input type="checkbox" class="finding-chk"
             style="width:14px;height:14px;accent-color:var(--accent-cyan);cursor:pointer"
             onclick="event.stopPropagation()"></td>`;

    /* data cells */
    const dataCells = cols.map(col => renderCell(col.type, data[col.id], col)).join('');

    /* data attrs for client-side filtering */
    const target   = String(finding.host || finding.target || '');
    const severity = String(finding.severity || '');
    const module_  = String(finding.module   || '');
    const findingT = String(finding.title    || finding.finding || '');

    const mainRow = `<tr class="findings-row"
      data-target="${escAttr(target)}"
      data-finding="${escAttr(findingT)}"
      data-severity="${escAttr(severity)}"
      data-module="${escAttr(module_)}"
      ${clickHandler}>${cbCell}${dataCells}</tr>`;

    return mainRow + (hasDetail ? renderDetailPanel(detailFields, colCount, rowId) : '');
  }

  /* ── column header builder ─────────────────────────────────────────────── */

  function getColumns(activeKind) {
    return reg().columns(activeKind).map(c => c.label);
  }

  /* ══════════════════════════════════════════════════════════════════════════
     PUBLIC API  (same shape as the old FindingsRowsPage so call-sites need
     zero changes — they just get better output)
  ══════════════════════════════════════════════════════════════════════════ */

  window.FindingsRowsPage = {
    /**
     * Return column label strings for the given activeKind.
     * Used by result-tables.js to build <thead>.
     */
    getUnifiedTableColumns: getColumns,

    /**
     * Build one findings row HTML string.
     * Drop-in replacement for the old renderRowForUnifiedTab.
     */
    renderRowForUnifiedTab(r, idx, activeKind, modInfo /*, sevMeta — no longer needed */) {
      return buildFindingRow(r, idx, activeKind, modInfo);
    },

    /* kept for backward-compat: individual renderers callers may still use */
    renderDefaultRow(r, idx, modInfo)     { return buildFindingRow(r, idx, 'default',  modInfo); },
    renderNucleiRow(r, idx, modInfo)      { return buildFindingRow(r, idx, 'nuclei',   modInfo); },
    renderJSAnalysisRow(r, idx, modInfo)  { return buildFindingRow(r, idx, 'js',       modInfo); },
    renderGFPatternsRow(r, idx, modInfo)  { return buildFindingRow(r, idx, 'gf',       modInfo); },
  };

})();

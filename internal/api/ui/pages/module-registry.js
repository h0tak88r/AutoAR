/**
 * module-registry.js
 * ──────────────────────────────────────────────────────────────────────────────
 * Central registry for all scan-result module schemas.
 *
 * HOW IT WORKS
 * ────────────
 * 1. Every module has one entry in MODULE_REGISTRY.
 * 2. Each entry declares:
 *      columns  – what columns to show (label, width, cell-style)
 *      extract  – pure function (finding, modInfo) → plain object with one
 *                 key per column.  Keys must match column `id` values.
 *      detail   – optional fn (finding) → [ {label, value, opts} ]
 *                 Returning non-empty causes an expand-on-click detail panel.
 * 3. The generic renderer in findings-rows.js reads these and produces HTML.
 *    No more per-module switch/case there.
 *
 * HOW TO ADD A NEW MODULE
 * ────────────────────────
 * Just add one entry here.  Zero changes needed elsewhere.
 * ──────────────────────────────────────────────────────────────────────────────
 */

(() => {
  'use strict';

  /* ── tiny helpers (no deps) ─────────────────────────────────────────────── */

  /** Return first non-empty value from obj[key1], obj[key2], … */
  function pick(obj, ...keys) {
    for (const k of keys) {
      const v = obj == null ? undefined : obj[k];
      if (v !== null && v !== undefined && v !== '') return v;
    }
    return '';
  }

  function s(v) { return String(v ?? '').trim(); }

  function arr(v) {
    if (Array.isArray(v)) return v.join(', ');
    if (typeof v === 'object' && v) return Object.values(v).join(', ');
    return s(v);
  }

  /* ── severity colour map ────────────────────────────────────────────────── */

  const SEV = {
    critical: { bg: 'rgba(248,113,113,.15)', color: '#f87171',  label: 'CRIT' },
    high:     { bg: 'rgba(251,146,60,.15)',  color: '#fb923c',  label: 'HIGH' },
    medium:   { bg: 'rgba(251,191,36,.15)',  color: '#fbbf24',  label: 'MED'  },
    low:      { bg: 'rgba(74,222,128,.15)',  color: '#4ade80',  label: 'LOW'  },
    info:     { bg: 'rgba(6,182,212,.12)',   color: '#22d3ee',  label: 'INFO' },
    unknown:  { bg: 'rgba(255,255,255,.06)', color: '#94a3b8',  label: '—'    },
  };

  function sevMeta(raw) {
    return SEV[s(raw).toLowerCase()] || SEV.unknown;
  }

  /* ── module key resolution ──────────────────────────────────────────────── */

  const KEY_ALIASES = {
    'nuclei': 'nuclei', 'mod:nuclei': 'nuclei',
    'ffuf': 'ffuf', 'ffuf-fuzzing': 'ffuf', 'mod:ffuf': 'ffuf',
    'gf-patterns': 'gf', 'mod:gf': 'gf',
    'js-analysis': 'js', 'mod:js': 'js', 'js': 'js',
    'misconfig': 'misconfig', 'mod:misconfig': 'misconfig',
    'github-scan': 'github', 'mod:github': 'github',
    'apkx': 'apkx', 'mod:apkx': 'apkx',
  };

  function resolveKey(activeKind) {
    const k = s(activeKind);
    if (KEY_ALIASES[k]) return KEY_ALIASES[k];
    if (k.startsWith('apkcat:')) return 'apkx';
    if (k.startsWith('mod:')) return k.slice(4); // fall-through to default if unknown
    return 'default';
  }

  /* ── MODULE_REGISTRY ────────────────────────────────────────────────────── */

  const MODULE_REGISTRY = {

    /* ── Nuclei ─────────────────────────────────────────────────────────── */
    nuclei: {
      columns: [
        { id: 'target',   label: 'TARGET',      flex: '2', type: 'link'     },
        { id: 'sev',      label: 'SEV',          w: '68px', type: 'sev-badge', align: 'center' },
        { id: 'template', label: 'TEMPLATE',     flex: '2', type: 'two-line' },
        { id: 'matched',  label: 'MATCHED AT',   flex: '2', type: 'two-line-mono' },
      ],
      extract(r) {
        const raw  = r.raw  || {};
        const info = raw.info || r.info || {};
        const target   = s(raw.matched_at || raw.host || r.host || r.target || '-');
        const tmplId   = s(raw.template_id || r.template_id || r.finding || '—');
        return {
          target:   { href: toHref(target), label: target },
          sev:      sevMeta(r.severity),
          template: { primary: s(info.name || tmplId), secondary: tmplId },
          matched:  { primary: s(raw.matched_at || r.target || '-'), secondary: s(raw.matcher_name || '') },
        };
      },
      detail(r) {
        const raw  = r.raw  || {};
        const info = raw.info || r.info || {};
        return buildFields([
          ['Matched At',        s(raw.matched_at),           { isLink: true }],
          ['Matcher Name',      s(raw.matcher_name)],
          ['Extracted Results', arr(raw.extracted_results)],
          ['Description',       s(info.description),          { full: true }],
          ['Tags',              arr(info.tags)],
          ['References',        arr(info.reference),          { full: true }],
          ['Curl Command',      s(raw.curl_command),          { full: true, code: true }],
        ]);
      },
    },

    /* ── FFUF ───────────────────────────────────────────────────────────── */
    ffuf: {
      columns: [
        { id: 'url',    label: 'URL',    flex: '3', type: 'link'        },
        { id: 'status', label: 'STATUS', w: '76px', type: 'http-status', align: 'center' },
        { id: 'word',   label: 'WORD',   flex: '1', type: 'mono'        },
        { id: 'length', label: 'LENGTH', w: '80px', type: 'mono-muted', align: 'right'  },
      ],
      extract(r) {
        const raw = r.raw || {};

        // ── Structured row (JSON from ffuf) ──────────────────────────────
        // raw has status_code / url / word / content_length
        if (raw.url || raw.matched_at || raw.status_code != null) {
          const url = s(raw.matched_at || raw.url || r.target || '—');
          return {
            url:    { href: toHref(url), label: url },
            status: s(raw.status_code || raw.status || r.status || r.status_code || '—'),
            word:   s(raw.word || raw.input?.FUZZ || r.word || r.path || '—'),
            length: s(raw.content_length || raw.length || r.content_length || '—'),
          };
        }

        // ── Text-format row ───────────────────────────────────────────────
        // FFUF stdout line format: "[200] url (Size: 114, Lines: 1, Words: 2)"
        // stored verbatim in r.target or r.finding
        const line = s(r.target || r.finding || '');

        // Extract status code [NNN]
        const statusMatch = line.match(/^\[(\d{3})\]/);
        const status = statusMatch ? statusMatch[1] : '—';

        // Extract URL — the bare URL after the status code, before " (Size"
        const urlMatch = line.match(/^\[\d{3}\]\s+(https?:\/\/[^\s(]+)/);
        let url = urlMatch ? urlMatch[1] : line;
        // Strip trailing " (Size: ...)"
        url = url.replace(/\s*\(Size:.*$/, '').trim();

        // Extract content-length from "(Size: NNN"
        const sizeMatch = line.match(/Size:\s*(\d+)/);
        const length = sizeMatch ? sizeMatch[1] : s(r.content_length || r.length || '—');

        // Derive word: always extract from the URL path — never use r.word/r.finding
        // which may contain the full formatted line for old scans.
        let word = '—';
        if (url && url !== '—' && url.startsWith('http')) {
          try {
            const u = new URL(url);
            const seg = u.pathname.split('/').filter(Boolean).pop();
            if (seg) word = '/' + seg;
            else if (u.pathname && u.pathname !== '/') word = u.pathname;
            else word = '/';
          } catch (_) { word = url; }
        } else if (url && url !== '—') {
          word = url;
        }

        return {
          url:    { href: toHref(url), label: url },
          status,
          word,
          length,
        };
      },
    },

    /* ── GF Patterns ────────────────────────────────────────────────────── */
    gf: {
      columns: [
        { id: 'target',  label: 'TARGET',  flex: '2', type: 'link'       },
        { id: 'pattern', label: 'PATTERN', flex: '1', type: 'badge-pill'  },
        { id: 'value',   label: 'VALUE',   flex: '3', type: 'mono-trunc'  },
        { id: 'source',  label: 'SOURCE',  flex: '1', type: 'muted-trunc' },
      ],
      extract(r) {
        const target = s(r.host || r.target || '-');
        return {
          target:  { href: toHref(target), label: target },
          pattern: { label: s(r.pattern || r.module || r.finding_type || '—'), color: '#a78bfa' },
          value:   s(r.value || r.finding || '-'),
          source:  s(r.file || r.source || '—'),
        };
      },
    },

    /* ── JS Analysis ────────────────────────────────────────────────────── */
    js: {
      columns: [
        { id: 'file',    label: 'JS FILE', flex: '2', type: 'link-amber'  },
        { id: 'type',    label: 'TYPE',    w: '58px', type: 'label-badge', align: 'center' },
        { id: 'finding', label: 'FINDING', flex: '3', type: 'mono-trunc'  },
        { id: 'module',  label: 'MODULE',  flex: '1', type: 'mod-badge'   },
      ],
      extract(r, modInfo) {
        const file    = s(r.source_file || r.file || r.target || '-');
        const matcher = s(r.matcher || r.finding_type || '');
        const value   = s(r.finding || r.value || '-');
        return {
          file:    { href: toHref(file), label: file, color: '#f59e0b' },
          type:    { label: 'JS', bg: 'rgba(245,158,11,.12)', color: '#fbbf24' },
          finding: matcher ? `[${matcher}] ${value}` : value,
          module:  modInfo,
        };
      },
    },

    /* ── Misconfig ──────────────────────────────────────────────────────── */
    misconfig: {
      columns: [
        { id: 'target',  label: 'TARGET',  flex: '2', type: 'link'      },
        { id: 'sev',     label: 'SEV',     w: '68px', type: 'sev-badge', align: 'center' },
        { id: 'service', label: 'SERVICE', flex: '1', type: 'mono-amber' },
        { id: 'finding', label: 'FINDING', flex: '3', type: 'trunc'     },
      ],
      extract(r) {
        const target = s(r.host || r.target || '-');
        return {
          target:  { href: toHref(target), label: target },
          sev:     sevMeta(r.severity),
          service: s(r.service || r.service_name || r.module || 'misconfig'),
          finding: s(r.title || r.finding || '—'),
        };
      },
    },

    /* ── GitHub Scan (TruffleHog) ───────────────────────────────────────── */
    github: {
      columns: [
        { id: 'detector', label: 'DETECTOR',  flex: '2', type: 'bold-text'   },
        { id: 'sev',      label: 'SEV',       w: '68px', type: 'sev-badge',   align: 'center' },
        { id: 'verified', label: 'VERIFIED',  w: '90px', type: 'bool-badge',  align: 'center' },
        { id: 'source',   label: 'SOURCE',    flex: '2', type: 'link-or-mono' },
      ],
      extract(r) {
        const raw  = r.raw || {};
        const data = raw.SourceMetadata?.Data || raw.source_metadata?.data || {};
        const git  = data.Git  || data.git  || {};
        const fs   = data.Filesystem || data.filesystem || {};
        const link = s(data.link || data.Link || git.link || git.Link || '');
        const file = s(data.file || data.File || git.file || git.File || fs.file || fs.File || '');
        const line = s(data.line || data.Line || git.line || git.Line || '');
        const detector  = s(pick(raw, 'DetectorName', 'detector_name') || r.finding || 'Unknown');
        const redacted  = s(pick(raw, 'Redacted', 'redacted'));
        const verified  = String(pick(raw, 'Verified', 'verified')).toLowerCase() === 'true';
        const srcParts  = [file && line ? `${file}:${line}` : file, link].filter(Boolean);
        const srcLabel  = srcParts.join(' · ') || s(r.target) || '—';
        return {
          detector: redacted ? `${detector}  (${redacted})` : detector,
          sev:      sevMeta(r.severity),
          verified: verified,
          source:   { href: link || '#', label: srcLabel, isLink: !!link },
        };
      },
    },

    /* ── APK Analysis ───────────────────────────────────────────────────── */
    apkx: {
      columns: [
        { id: 'path',     label: 'PATH',          flex: '2', type: 'mono-trunc'  },
        { id: 'category', label: 'CATEGORY',      flex: '1', type: 'badge-pill'  },
        { id: 'value',    label: 'MATCHER VALUE',  flex: '3', type: 'mono-trunc'  },
        { id: 'module',   label: 'MODULE',         flex: '1', type: 'mod-badge'   },
      ],
      extract(r, modInfo) {
        const normPath = p => s(p).replace(/^\s*[-*•]\s*/, '');
        return {
          path:     normPath(r.path || r.target || '—'),
          category: { label: s(r.category_name || r.apk_category || 'APK'), color: '#67e8f9' },
          value:    s(r.matcher_value || r.context || r.finding || '—'),
          module:   modInfo,
        };
      },
    },

    /* ── Default (fallback for any unknown module) ──────────────────────── */
    default: {
      columns: [
        { id: 'target',  label: 'TARGET',           flex: '2', type: 'link'      },
        { id: 'sev',     label: 'SEV',              w: '68px', type: 'sev-badge', align: 'center' },
        { id: 'finding', label: 'VULNERABILITY TYPE',flex: '3', type: 'mono-trunc'},
        { id: 'module',  label: 'MODULE',           flex: '1', type: 'mod-badge'  },
      ],
      extract(r, modInfo) {
        const target = s(r.host || r.target || '-');
        return {
          target:  { href: toHref(target), label: target },
          sev:     sevMeta(r.severity),
          finding: s(r.title || r.finding || '—'),
          module:  modInfo,
        };
      },
    },

  }; // end MODULE_REGISTRY

  /* ── shared helpers ─────────────────────────────────────────────────────── */

  function toHref(v) {
    const u = s(v);
    return u.startsWith('http') ? u : (u && u !== '-' && u !== '—') ? `https://${u}` : '#';
  }

  /** Build a detail-panel field list from [ [label, value, opts?] ] triples. */
  function buildFields(triples) {
    return triples
      .map(([label, value, opts = {}]) => ({ label, value: s(value), ...opts }))
      .filter(f => f.value);
  }

  /* ── public API ─────────────────────────────────────────────────────────── */

  window.ModuleRegistry = {
    /**
     * Return the schema for a given activeKind string.
     * Always returns at least the `default` schema.
     */
    get(activeKind) {
      const key = resolveKey(activeKind);
      return MODULE_REGISTRY[key] || MODULE_REGISTRY.default;
    },

    /** Return column labels for a given activeKind (used to build <thead>). */
    columns(activeKind) {
      return this.get(activeKind).columns;
    },

    /** Normalise a finding object into a flat { colId → displayValue } map. */
    extract(activeKind, finding, modInfo) {
      return this.get(activeKind).extract(finding, modInfo);
    },

    /** Return detail panel fields for a finding (empty array = no detail). */
    detail(activeKind, finding) {
      const schema = this.get(activeKind);
      return schema.detail ? schema.detail(finding) : [];
    },

    sevMeta,
    toHref,
    buildFields,
  };

})();

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
    // JS modules — three distinct modules:
    'js-analysis': 'js', 'mod:js': 'js', 'js': 'js',           // secrets/vuln findings
    'js-endpoints': 'js-endpoints', 'mod:js-endpoints': 'js-endpoints', // API paths extracted from JS
    'katana-crawler': 'katana', 'mod:katana': 'katana',
    'reflection': 'reflection', 'mod:reflection': 'reflection',
    'xss-detection': 'xss-detection', 'mod:xss-detection': 'xss-detection',
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
        { id: 'status', label: 'STATUS', w: '72px', type: 'http-status', align: 'center' },
        { id: 'path',   label: 'PATH',   flex: '2', type: 'mono'        },
        { id: 'size',   label: 'SIZE',   w: '72px', type: 'mono-muted', align: 'right'  },
        { id: 'lines',  label: 'LINES',  w: '64px', type: 'mono-muted', align: 'right'  },
        { id: 'words',  label: 'WORDS',  w: '64px', type: 'mono-muted', align: 'right'  },
      ],
      extract(r) {
        const raw = r.raw || {};

        // ── Structured row (JSON from ffuf) ──────────────────────────────
        // raw has status_code / url / word / content_length
        if (raw.url || raw.matched_at || raw.status_code != null) {
          const url = s(raw.matched_at || raw.url || r.target || '—');
          return {
            url:    { href: toHref(url), label: url },
            status: s(raw.status_code || raw.status || '—'),
            path:   s(raw.word || raw.path || raw.input?.FUZZ || r.path || '—'),
            size:   s(raw.content_length  ?? raw.length ?? '—'),
            lines:  s(raw.content_lines   ?? '—'),
            words:  s(raw.content_words   ?? '—'),
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

        // Parse metrics from "(Size: N, Lines: N, Words: N)"
        const sizeM  = line.match(/Size:\s*(\d+)/);
        const linesM = line.match(/Lines:\s*(\d+)/);
        const wordsM = line.match(/Words:\s*(\d+)/);
        const size  = sizeM  ? sizeM[1]  : s(r.content_length || '—');
        const lines = linesM ? linesM[1] : '—';
        const words = wordsM ? wordsM[1] : '—';

        // Derive path from URL — always from URL, never from r.word/r.finding
        let path = '—';
        if (url && url.startsWith('http')) {
          try {
            const u = new URL(url);
            path = u.pathname || '/';
          } catch (_) { path = url; }
        } else if (url && url !== '—') {
          path = url;
        }

        return {
          url:    { href: toHref(url), label: url },
          status,
          path,
          size,
          lines,
          words,
        };
      },
    },

    /* ── GF Patterns ────────────────────────────────────────────────────── */
    gf: {
      columns: [
        { id: 'target',  label: 'TARGET',  flex: '2', type: 'link'       },
        { id: 'sev',     label: 'SEV',     w: '68px', type: 'sev-badge',  align: 'center' },
        { id: 'pattern', label: 'PATTERN', flex: '1', type: 'badge-pill'  },
        { id: 'value',   label: 'MATCHED URL', flex: '3', type: 'mono-trunc' },
      ],
      extract(r) {
        const raw = r.raw || {};
        const target = s(r.host || r.target || '-');

        // Resolve pattern name: prefer explicit raw.pattern → raw.template_id → r.finding → filename
        let patternName = s(raw.pattern || raw.template_id || '');
        if (!patternName && r.file) {
          patternName = r.file.replace(/\.txt$/i, '').replace(/^gf-/i, '').replace(/-results$/i, '');
        }
        if (!patternName) patternName = s(r.finding || r.module || '—');
        // Strip leading "gf-" prefix for display (gf-ssrf → ssrf)
        const displayName = patternName.replace(/^gf-/i, '');

        // Pattern → colour mapping
        const patternColors = {
          ssrf: '#f87171', rce: '#f87171', lfi: '#f87171', sqli: '#f87171', ssti: '#f87171',
          xss: '#fb923c', redirect: '#fbbf24', idor: '#fbbf24', iparams: '#fbbf24', debug_logic: '#fbbf24',
          iext: '#4ade80', 'img-traversal': '#4ade80', isubs: '#22d3ee', jsvar: '#22d3ee',
        };
        const color = patternColors[displayName.toLowerCase()] || '#a78bfa';

        // VALUE column: the actual matched URL (stored in target/host after backend parsing)
        const value = s(r.target || r.host || '-');

        return {
          target:  { href: toHref(target), label: target },
          sev:     sevMeta(r.severity),
          pattern: { label: displayName || patternName, color },
          value,
        };
      },
      detail(r) {
        const raw = r.raw || {};
        const patternName = s(raw.pattern || raw.template_id || r.finding || '');
        return buildFields([
          ['Pattern',     patternName.replace(/^gf-/i, '')],
          ['Full ID',     patternName],
          ['Matched URL', s(r.target || r.host || ''), { isLink: true }],
          ['Severity',    s(r.severity)],
          ['Source File', s(r.file || raw.module || '')],
        ]);
      },
    },


    /* ── JS Endpoints (API paths extracted from JS files) ───────────────── */
    'js-endpoints': {
      columns: [
        { id: 'endpoint', label: 'ENDPOINT',    flex: '3', type: 'link'       },
        { id: 'source',   label: 'SOURCE FILE', flex: '2', type: 'mono-muted' },
      ],
      extract(r) {
        const raw      = r.raw || {};
        const endpoint = s(raw.endpoint || r.target || r.finding || '-');
        const source   = s(r.file || raw.module || '');
        return {
          endpoint: { href: toHref(endpoint), label: endpoint },
          source,
        };
      },
      detail(r) {
        const raw = r.raw || {};
        return buildFields([
          ['Endpoint',   s(raw.endpoint || r.target || ''), { isLink: true }],
          ['Source JS',  s(r.file || '')],
          ['Module',     'JS Endpoints'],
        ]);
      },
    },

    /* ── Katana Crawler (JS-aware web crawler results) ───────────────────── */
    katana: {
      columns: [
        { id: 'url',    label: 'CRAWLED URL', flex: '4', type: 'link'       },
        { id: 'domain', label: 'DOMAIN',      flex: '1', type: 'mono-muted' },
      ],
      extract(r) {
        const raw = r.raw || {};
        const url = s(raw.url || r.target || r.finding || '-');
        let domain = '';
        try { domain = new URL(url).hostname; } catch (_) {}
        return {
          url:    { href: toHref(url), label: url },
          domain,
        };
      },
      detail(r) {
        const raw = r.raw || {};
        const url = s(raw.url || r.target || r.finding || '');
        return buildFields([
          ['URL',    url, { isLink: true }],
          ['Module', 'Katana Crawler'],
        ]);
      },
    },

    /* ── XSS Detection (Dalfox confirmed — from kxss {<}/{>} candidates) ───── */
    'xss-detection': {
      columns: [
        { id: 'target',    label: 'TARGET',      flex: '3', type: 'link'      },
        { id: 'sev',       label: 'SEV',          w: '68px', type: 'sev-badge', align: 'center' },
        { id: 'vulnType',  label: 'TYPE',         flex: '1', type: 'badge-pill' },
        { id: 'parameter', label: 'PARAMETER',   flex: '1', type: 'mono-muted' },
        { id: 'payload',   label: 'PAYLOAD',      flex: '2', type: 'mono-trunc' },
      ],
      extract(r) {
        const raw      = r.raw || {};
        const target   = s(raw['matched-at'] || r.target || r.host || '-');
        const vulnType = s(raw['template-id'] || r.finding || 'XSS');
        const param    = s(raw.parameter || raw.param || r.parameter || '');
        const payload  = s(raw.payload || r.payload || '');
        return {
          target:    { href: toHref(target), label: target },
          sev:       sevMeta(r.severity || raw.severity || 'high'),
          vulnType:  { label: vulnType, color: '#f87171' },
          parameter: param,
          payload,
        };
      },
      detail(r) {
        const raw = r.raw || {};
        return buildFields([
          ['Target',    s(raw['matched-at'] || r.target || ''), { isLink: true }],
          ['Type',      s(raw['template-id'] || r.finding || '')],
          ['Parameter', s(raw.parameter || raw.param || '')],
          ['Payload',   s(raw.payload || '')],
          ['Severity',  s(r.severity || raw.severity || 'high')],
          ['Module',    'XSS Detection (Dalfox)'],
        ]);
      },
    },

    /* ── JS Analysis (secrets in JS files) ───────────────────────────────── */
    js: {
      columns: [
        { id: 'file',       label: 'JS FILE',     flex: '2', type: 'link-amber'  },
        { id: 'sev',        label: 'SEV',         w: '68px', type: 'sev-badge',  align: 'center' },
        { id: 'secretType', label: 'SECRET TYPE', flex: '1', type: 'badge-pill'  },
        { id: 'secret',     label: 'SECRET VALUE', flex: '3', type: 'mono-trunc' },
      ],
      extract(r) {
        const raw = r.raw || {};
        // JS file URL (the source .js file where the secret was found)
        const file = s(r.target || raw.matched_at || r.source_file || '-');

        // Secret type: read from raw.secret_type → parse from finding bracket → template-id → fallback
        let secretType = s(raw.secret_type || raw.secretType || '');
        if (!secretType) {
          // Parse from "[secretType] url -> value" format stored in finding
          const m = s(r.finding || '').match(/^\[([^\]]+)\]/);
          if (m) secretType = m[1];
        }
        if (!secretType) {
          // Strip "JS Secret Exposure (" prefix from template_id
          secretType = s(raw.template_id || r.finding || '—')
            .replace(/^JS Secret Exposure\s*\(?\s*/i, '')
            .replace(/\)$/, '');
        }

        // Secret value: read from raw.secret → parse after "->" in finding
        let secretVal = s(raw.secret || '');
        if (!secretVal) {
          const finding = s(r.finding || '');
          const arrowIdx = finding.indexOf('->');
          if (arrowIdx !== -1) secretVal = finding.slice(arrowIdx + 2).trim();
        }
        if (!secretVal) secretVal = '—';

        // Colour by severity of secret type
        const highTypes = new Set(['api_key', 'apikey', 'apikey_patterns', 'private_key', 'aws_access_key_id', 'aws_secret', 'password', 'passwd', 'client_secret', 'client_id_secret']);
        const medTypes  = new Set(['access_token', 'auth_token', 'bearer_token', 'jwt', 'session', 'refresh_token']);
        const tl = secretType.toLowerCase().replace(/\s+/g, '_');
        const color = highTypes.has(tl) ? '#f87171' : medTypes.has(tl) ? '#fb923c' : '#a78bfa';

        return {
          file:       { href: toHref(file), label: file, color: '#f59e0b' },
          sev:        sevMeta(r.severity || 'high'),
          secretType: { label: secretType || 'unknown', color },
          secret:     secretVal,
        };
      },
      detail(r) {
        const raw = r.raw || {};
        const file     = s(r.target || raw.matched_at || r.source_file || '');
        const finding  = s(r.finding || '');
        const secret   = s(raw.secret || '');
        const secType  = s(raw.secret_type || raw.secretType || '');
        const tmplId   = s(raw.template_id || '');
        return buildFields([
          ['JS File',     file,    { isLink: true }],
          ['Secret Type', secType || tmplId],
          ['Secret Value', secret || (() => {
            const ai = finding.indexOf('->');
            return ai !== -1 ? finding.slice(ai + 2).trim() : '';
          })(), { code: true }],
          ['Severity',    s(r.severity)],
          ['Raw Finding', finding, { full: true }],
        ]);
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

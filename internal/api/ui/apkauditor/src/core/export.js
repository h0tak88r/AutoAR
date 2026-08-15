(function (root) {
'use strict';

function flatFindings(results) {
    const out = [];
    const groups = [
        ...(results.groupedFindings && results.groupedFindings.issue || []),
        ...(results.groupedFindings && results.groupedFindings.secure || []),
        ...(results.groupedFindings && results.groupedFindings.info || []),
    ];
    for (const g of groups) {
        if (g.instances && g.instances.length > 0) {
            for (const inst of g.instances) {
                out.push({
                    ruleId: g.ruleId, ruleName: g.ruleName, severity: g.severity,
                    description: g.description, cwe: g.cwe, owasp: g.owasp, masvs: g.masvs,
                    category: g.category, occurrences: g.count, avgConfidence: g.avgConfidence,
                    confidence: inst.confidence, confidenceLabel: inst.confidenceLabel, entropy: inst.entropy,
                    file: inst.file, line: inst.line, match: inst.match,
                });
            }
        } else {
            out.push({
                ruleId: g.ruleId, ruleName: g.ruleName, severity: g.severity,
                description: g.description, cwe: g.cwe, owasp: g.owasp, masvs: g.masvs,
                category: g.category, occurrences: g.count, avgConfidence: g.avgConfidence,
            });
        }
    }
    return out;
}

function toJSON(results) {
    const json = {
        tool: { name: 'APK Auditor', version: '3.0' },
        generatedAt: new Date().toISOString(),
        app: results.appInfo,
        packageName: results.appInfo && results.appInfo.packageName,
        minSdk: results.minSdk,
        targetSdk: results.targetSdk,
        permissions: results.permissions,
        dangerousPermissions: results.dangerousPerms,
        components: results.components,
        certificate: results.certInfo,
        hasV2Signature: results.hasV2Sig,
        isObfuscated: results.isObfuscated,
        dexFiles: results.dexFiles,
        nativeLibraries: results.nativeLibs,
        trackers: results.trackers,
        urls: (results.urls || []).slice(0, 500),
        summary: results.summary,
        securityScore: results.securityScore,
        findings: flatFindings(results),
        warnings: results.warnings || [],
    };
    return JSON.stringify(json, null, 2);
}

// Values come from decompiled APK content, which is attacker-controlled. Excel and
// Sheets execute a cell starting with = + - @ (or a leading tab/CR) as a formula, so
// those are prefixed with an apostrophe before quoting.
function csvEscape(v) {
    if (v == null) return '';
    let s = String(v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    if (/[",\n\r]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
    return s;
}

const CSV_COLUMNS = [
    ['package_name',     (f, ai) => ai.packageName],
    ['app_label',        (f, ai) => ai.appLabel],
    ['version_name',     (f, ai) => ai.versionName],
    ['version_code',     (f, ai) => ai.versionCode],
    ['file_name',        (f, ai) => ai.fileName],
    ['sha256',           (f, ai) => ai.sha256],
    ['severity',         (f) => f.severity],
    ['confidence',       (f) => f.confidence],
    ['confidence_label', (f) => f.confidenceLabel],
    ['avg_confidence',   (f) => f.avgConfidence],
    ['entropy',          (f) => f.entropy],
    ['occurrences',      (f) => f.occurrences],
    ['rule_id',          (f) => f.ruleId],
    ['rule_name',        (f) => f.ruleName],
    ['category',         (f) => f.category],
    ['cwe',              (f) => f.cwe],
    ['owasp',            (f) => f.owasp],
    ['masvs',            (f) => f.masvs],
    ['file',             (f) => f.file],
    ['line',             (f) => f.line],
    ['match',            (f) => (f.match || '').slice(0, 2000)],
    ['description',      (f) => f.description],
];

function toCSV(results) {
    const ai = results.appInfo || {};
    const rows = [CSV_COLUMNS.map(c => c[0])];
    for (const f of flatFindings(results)) {
        rows.push(CSV_COLUMNS.map(c => {
            const v = c[1](f, ai);
            return v == null ? '' : v;
        }));
    }
    return rows.map(r => r.map(csvEscape).join(',')).join('\n');
}

function sevToLevel(s) {
    if (s === 'issue') return 'error';
    if (s === 'secure') return 'note';
    return 'note';
}

function toSARIF(results) {
    const rules = new Map();
    const sarifResults = [];
    for (const f of flatFindings(results)) {
        if (!rules.has(f.ruleId)) {
            rules.set(f.ruleId, {
                id: f.ruleId,
                name: f.ruleName,
                shortDescription: { text: f.ruleName },
                fullDescription: { text: f.description || f.ruleName },
                helpUri: f.cwe ? 'https://cwe.mitre.org/data/definitions/' + (f.cwe.replace(/^CWE-/, '')) + '.html' : undefined,
                defaultConfiguration: { level: sevToLevel(f.severity) },
                properties: { severity: f.severity, cwe: f.cwe, owasp: f.owasp, masvs: f.masvs, category: f.category },
            });
        }
        const physical = { artifactLocation: { uri: f.file || '' }, region: f.line ? { startLine: f.line } : undefined };
        sarifResults.push({
            ruleId: f.ruleId,
            level: sevToLevel(f.severity),
            message: { text: f.description || f.ruleName },
            locations: f.file ? [{ physicalLocation: physical }] : [],
            properties: { confidence: f.confidence, entropy: f.entropy, match: (f.match || '').slice(0, 200) },
        });
    }
    return JSON.stringify({
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [{
            tool: { driver: { name: 'APK Auditor', version: '3.0', informationUri: 'https://apkauditor.com', rules: [...rules.values()] } },
            artifacts: [{
                location: { uri: results.appInfo && results.appInfo.fileName },
                hashes: (results.appInfo && results.appInfo.sha256) ? { 'sha-256': results.appInfo.sha256 } : undefined,
            }],
            results: sarifResults,
            properties: { securityScore: results.securityScore, summary: results.summary, app: results.appInfo, packageName: results.appInfo && results.appInfo.packageName },
        }],
    }, null, 2);
}

function download(text, filename, mime) {
    const blob = new Blob([text], { type: mime || 'application/octet-stream' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(a.href); }, 1000);
}

function exportFile(kind, results, filenameBase) {
    const ai = results.appInfo || {};
    const base = filenameBase || (ai.packageName || (ai.fileName || 'apk').replace(/\.apk$/i, ''));
    const safeBase = base.replace(/[^a-zA-Z0-9._-]/g, '_');
    if (kind === 'json')  return download(toJSON(results),  safeBase + '_report.json',  'application/json');
    if (kind === 'csv')   return download(toCSV(results),   safeBase + '_findings.csv', 'text/csv');
    if (kind === 'sarif') return download(toSARIF(results), safeBase + '_findings.sarif', 'application/json');
    throw new Error('Unknown export kind: ' + kind);
}

const api = { toJSON, toCSV, toSARIF, exportFile, flatFindings };
if (typeof module !== 'undefined' && module.exports) module.exports = api;
else { root.IPAA = root.IPAA || {}; root.IPAA.Export = api; }

})(typeof self !== 'undefined' ? self : this);

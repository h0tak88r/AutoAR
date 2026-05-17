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
                    category: g.category,
                    confidence: inst.confidence, confidenceLabel: inst.confidenceLabel, entropy: inst.entropy,
                    file: inst.file, line: inst.line, match: inst.match,
                });
            }
        } else {
            out.push({
                ruleId: g.ruleId, ruleName: g.ruleName, severity: g.severity,
                description: g.description, cwe: g.cwe, owasp: g.owasp, masvs: g.masvs,
                category: g.category,
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

function csvEscape(v) {
    if (v == null) return '';
    const s = String(v);
    if (/[",\n\r]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
    return s;
}

function toCSV(results) {
    const rows = [['severity', 'confidence', 'rule_id', 'rule_name', 'category', 'cwe', 'owasp', 'masvs', 'file', 'line', 'match', 'description']];
    for (const f of flatFindings(results)) {
        rows.push([
            f.severity, f.confidence != null ? f.confidence : '', f.ruleId, f.ruleName, f.category || '',
            f.cwe || '', f.owasp || '', f.masvs || '',
            f.file || '', f.line != null ? f.line : '',
            (f.match || '').slice(0, 500),
            (f.description || '').slice(0, 500),
        ]);
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

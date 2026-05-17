(function (root) {
'use strict';

function shannonEntropy(str) {
    if (!str || str.length === 0) return 0;
    const freq = new Map();
    for (let i = 0; i < str.length; i++) {
        const c = str[i];
        freq.set(c, (freq.get(c) || 0) + 1);
    }
    let h = 0;
    const len = str.length;
    for (const count of freq.values()) {
        const p = count / len;
        h -= p * Math.log2(p);
    }
    return h;
}

const COMMON_WORDS_LOWER = new Set([
    'placeholder', 'example', 'lorem', 'ipsum', 'test', 'testing', 'demo', 'sample',
    'password', 'passw0rd', 'changeme', 'default', 'admin', 'username', 'guest',
    'unknown', 'null', 'undefined', 'foobar', 'foo', 'bar', 'true', 'false',
    'yes', 'no', 'enabled', 'disabled', 'required', 'optional', 'localhost',
    'apikey', 'token', 'secret', 'key', 'auth', 'authorization', 'bearer',
    'username', 'email', 'phone', 'name', 'value', 'data', 'string',
]);

function looksLikePlaceholder(str) {
    const s = str.toLowerCase();
    if (s.length < 4) return true;
    if (/^x+$/.test(s) || /^[*]+$/.test(s) || /^[.]+$/.test(s)) return true;
    if (/^(test|demo|example|sample|placeholder|todo)[_-]?/.test(s)) return true;
    if (/your[_-]?(api|secret|token|key|password)/.test(s)) return true;
    if (/<[a-z]+>/.test(s)) return true;
    if (/\$\{[a-z]+\}/i.test(s)) return true;
    if (COMMON_WORDS_LOWER.has(s)) return true;
    return false;
}

function isHighEntropySecret(value, opts) {
    const o = opts || {};
    const minEntropy = o.minEntropy ?? 4.0;
    const minBase64Entropy = o.minBase64Entropy ?? 4.5;
    const minHexEntropy = o.minHexEntropy ?? 3.0;
    const minLength = o.minLength ?? 16;

    if (!value || value.length < minLength) return { match: false, reason: 'too-short' };
    if (looksLikePlaceholder(value)) return { match: false, reason: 'placeholder' };
    const repeated = /^(.)\1+$/.test(value);
    if (repeated) return { match: false, reason: 'repeated-char' };

    const entropy = shannonEntropy(value);
    const isHex = /^[0-9a-fA-F]+$/.test(value);
    const isBase64 = /^[A-Za-z0-9+/=_-]+$/.test(value);
    let kind = 'generic';
    let threshold = minEntropy;
    if (isHex) { kind = 'hex'; threshold = minHexEntropy; }
    else if (isBase64) { kind = 'base64'; threshold = minBase64Entropy; }

    return {
        match: entropy >= threshold,
        entropy: +entropy.toFixed(2),
        threshold,
        kind,
    };
}

const SECRET_DETECTORS = [
    {
        id: 'aws_access_key_id',
        name: 'AWS Access Key ID',
        pattern: /\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b/g,
        severity: 'high',
        confidence: 95,
        cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14',
        description: 'AWS access key ID found. Rotate immediately and remove from binary.',
    },
    {
        id: 'aws_secret_access_key',
        name: 'AWS Secret Access Key',
        pattern: /\b((?:[A-Za-z0-9+/]{40}))\b/g,
        check: (m) => {
            const ctx = m.context || '';
            return /aws[_-]?secret|secret[_-]?access[_-]?key/i.test(ctx) && shannonEntropy(m.value) >= 4.5;
        },
        severity: 'high', confidence: 80,
        cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14',
        description: 'AWS secret access key candidate (40-char base64 near AWS context).',
    },
    {
        id: 'google_api_key',
        name: 'Google API Key',
        pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
        severity: 'high', confidence: 90,
        cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14',
        description: 'Google API key in code. Restrict by referrer/bundle and rotate.',
    },
    {
        id: 'google_oauth_token',
        name: 'Google OAuth Access Token',
        pattern: /\bya29\.[0-9A-Za-z\-_]+\b/g,
        severity: 'high', confidence: 90,
        cwe: 'CWE-798', owasp: 'M9',
        description: 'Google OAuth access token detected.',
    },
    {
        id: 'firebase_url',
        name: 'Firebase Database URL',
        pattern: /\bhttps?:\/\/[a-zA-Z0-9-]+\.(?:firebaseio\.com|firebasedatabase\.app)[^\s"'<>]*/gi,
        severity: 'warning', confidence: 85,
        cwe: 'CWE-200', owasp: 'M1', masvs: 'STORAGE-12',
        description: 'Firebase database URL found. Verify security rules.',
    },
    {
        id: 'github_token',
        name: 'GitHub Personal Access Token',
        pattern: /\b(gh[pousr]_[A-Za-z0-9]{36,255})\b/g,
        severity: 'high', confidence: 95,
        cwe: 'CWE-798', owasp: 'M9',
        description: 'GitHub PAT found. Revoke and rotate.',
    },
    {
        id: 'slack_token',
        name: 'Slack Token',
        pattern: /\b(xox[abprs]-[A-Za-z0-9-]{10,})\b/g,
        severity: 'high', confidence: 90,
        cwe: 'CWE-798', owasp: 'M9',
        description: 'Slack token found.',
    },
    {
        id: 'slack_webhook',
        name: 'Slack Webhook URL',
        pattern: /\bhttps:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+\b/g,
        severity: 'high', confidence: 95,
        cwe: 'CWE-200', owasp: 'M1',
        description: 'Slack webhook URL embedded.',
    },
    {
        id: 'stripe_secret',
        name: 'Stripe Secret Key',
        pattern: /\b(sk_(?:test|live)_[0-9A-Za-z]{16,99})\b/g,
        severity: 'high', confidence: 95,
        cwe: 'CWE-798', owasp: 'M9',
        description: 'Stripe secret/restricted key. Never ship secret keys to clients.',
    },
    {
        id: 'stripe_publishable',
        name: 'Stripe Publishable Key',
        pattern: /\b(pk_(?:test|live)_[0-9A-Za-z]{16,99})\b/g,
        severity: 'info', confidence: 95,
        cwe: '', owasp: '',
        description: 'Stripe publishable key (safe to expose, but tag for tracking).',
    },
    {
        id: 'twilio_sid',
        name: 'Twilio Account SID',
        pattern: /\b(AC[a-f0-9]{32})\b/g,
        severity: 'warning', confidence: 80,
        cwe: 'CWE-200', owasp: 'M9',
        description: 'Twilio account SID (low risk alone but tag for rotation review).',
    },
    {
        id: 'twilio_auth_token',
        name: 'Twilio Auth Token',
        pattern: /\b([a-f0-9]{32})\b/g,
        check: (m) => /twilio.{0,20}(auth|token)/i.test(m.context || ''),
        severity: 'high', confidence: 70,
        cwe: 'CWE-798', owasp: 'M9',
        description: 'Twilio auth token candidate.',
    },
    {
        id: 'sendgrid_api',
        name: 'SendGrid API Key',
        pattern: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g,
        severity: 'high', confidence: 95,
        cwe: 'CWE-798', owasp: 'M9',
        description: 'SendGrid API key.',
    },
    {
        id: 'mailgun_api',
        name: 'Mailgun API Key',
        pattern: /\b(key-[a-f0-9]{32})\b/g,
        severity: 'high', confidence: 90,
        cwe: 'CWE-798', owasp: 'M9',
        description: 'Mailgun API key.',
    },
    {
        id: 'square_token',
        name: 'Square Access Token',
        pattern: /\b(sq0(?:atp|csp)-[A-Za-z0-9_-]{22,43})\b/g,
        severity: 'high', confidence: 90,
        cwe: 'CWE-798',
        description: 'Square access token.',
    },
    {
        id: 'paypal_token',
        name: 'PayPal/Braintree Token',
        pattern: /\baccess_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[a-f0-9]{32}\b/gi,
        severity: 'high', confidence: 95,
        cwe: 'CWE-798',
        description: 'PayPal/Braintree access token.',
    },
    {
        id: 'private_key_pem',
        name: 'Private Key (PEM)',
        pattern: /-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED|ANY)?\s*PRIVATE KEY-----/g,
        severity: 'high', confidence: 99,
        cwe: 'CWE-321', owasp: 'M9',
        description: 'PEM-encoded private key embedded in the bundle.',
    },
    {
        id: 'pkcs12_marker',
        name: 'PKCS12 / .p12 / .pfx Reference',
        pattern: /\b(?:\.p12|\.pfx|PKCS12)\b/g,
        severity: 'warning', confidence: 60,
        cwe: 'CWE-321',
        description: 'PKCS#12 reference (may indicate embedded cert+key). Verify the .p12 is protected.',
    },
    {
        id: 'jwt_token',
        name: 'JWT Token',
        pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
        severity: 'warning', confidence: 80,
        cwe: 'CWE-798',
        description: 'JWT token detected in code or strings. Verify it is not a long-lived secret.',
    },
    {
        id: 'generic_bearer',
        name: 'Bearer Token Header',
        pattern: /Authorization\s*:\s*Bearer\s+([A-Za-z0-9._\-]{20,})/g,
        severity: 'high', confidence: 75,
        cwe: 'CWE-798',
        description: 'Hardcoded Bearer authorization header.',
    },
    {
        id: 'basic_auth_url',
        name: 'Basic Auth in URL',
        pattern: /\b(?:https?|ftp):\/\/[^\s:@\/]+:[^\s@\/]+@[^\s'"]+/g,
        severity: 'high', confidence: 90,
        cwe: 'CWE-522',
        description: 'URL contains embedded credentials (user:pass@host).',
    },
    {
        id: 'high_entropy_assigned_secret',
        name: 'High-Entropy Hardcoded Secret',
        pattern: /(?:secret|api[_-]?key|api[_-]?secret|access[_-]?token|client[_-]?secret|auth[_-]?token|private[_-]?key|encryption[_-]?key)\s*[:=]\s*["']([A-Za-z0-9+/=_\-.]{16,})["']/gi,
        check: (m) => {
            const r = isHighEntropySecret(m.value, { minEntropy: 4.0, minBase64Entropy: 4.3 });
            return r.match;
        },
        severity: 'high', confidence: 70,
        cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14',
        description: 'A high-entropy string is assigned to a "secret"-like key.',
    },
];

function detectSecrets(text, opts) {
    const o = opts || {};
    const findings = [];
    for (const det of SECRET_DETECTORS) {
        det.pattern.lastIndex = 0;
        let m;
        while ((m = det.pattern.exec(text)) !== null) {
            const value = m[1] || m[0];
            const matchStr = m[0];
            const ctxStart = Math.max(0, m.index - 64);
            const ctxEnd = Math.min(text.length, m.index + matchStr.length + 64);
            const context = text.slice(ctxStart, ctxEnd);
            if (det.check && !det.check({ value, context, match: matchStr })) {
                if (m.index === det.pattern.lastIndex) det.pattern.lastIndex++;
                continue;
            }
            const entropy = shannonEntropy(value);
            findings.push({
                ruleId: det.id,
                ruleName: det.name,
                severity: det.severity,
                confidence: det.confidence,
                description: det.description,
                cwe: det.cwe, owasp: det.owasp, masvs: det.masvs,
                match: matchStr,
                value,
                entropy: +entropy.toFixed(2),
                index: m.index,
            });
            if (m.index === det.pattern.lastIndex) det.pattern.lastIndex++;
        }
    }
    return findings;
}

function dedupeFindings(findings) {
    const seen = new Map();
    const out = [];
    for (const f of findings) {
        const key = [
            f.ruleId,
            f.file || '',
            f.line ?? '',
            (f.match || '').slice(0, 200),
            f.binaryOffset || '',
        ].join('||');
        if (seen.has(key)) {
            seen.get(key).occurrences++;
            continue;
        }
        const entry = { ...f, occurrences: 1 };
        seen.set(key, entry);
        out.push(entry);
    }
    return out;
}

function computeConfidence(finding, opts) {
    if (typeof finding.confidence === 'number') return finding.confidence;
    let conf = 50;
    if (finding.entropy != null) {
        if (finding.entropy >= 5.0) conf += 30;
        else if (finding.entropy >= 4.5) conf += 20;
        else if (finding.entropy >= 4.0) conf += 10;
        else if (finding.entropy < 3.0) conf -= 20;
    }
    if (finding.file && /test|fixture|mock|example|sample/i.test(finding.file)) conf -= 25;
    if (finding.match && looksLikePlaceholder(finding.match)) conf = Math.min(conf, 15);
    return Math.max(0, Math.min(100, conf));
}

function confidenceLabel(c) {
    if (c >= 85) return 'high';
    if (c >= 60) return 'medium';
    if (c >= 30) return 'low';
    return 'noise';
}

const api = {
    shannonEntropy,
    looksLikePlaceholder,
    isHighEntropySecret,
    detectSecrets,
    dedupeFindings,
    computeConfidence,
    confidenceLabel,
    SECRET_DETECTORS,
};

if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
} else {
    root.IPAA = root.IPAA || {};
    root.IPAA.Entropy = api;
}

})(typeof self !== 'undefined' ? self : this);

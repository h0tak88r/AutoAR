self.IPAA = self.IPAA || {};
try {
    importScripts(
        '../lib/jszip.min.js',
        'core/entropy.js',
        'core/engine.js'
    );
} catch (e) {
    self.postMessage({ type: 'fatal', data: { error: 'Worker importScripts failed: ' + e.message } });
}

const STRIP_KEYS = new Set(['buf', 'data', '_data', 'dexParsed', 'manifest', 'smaliTree']);

self.onmessage = async (e) => {
    const msg = e.data;
    if (!msg || !msg.type) return;
    if (msg.type === 'analyze') {
        try {
            const result = await self.APKA.analyzeAPK(msg.buffer, msg.fileMeta, {
                onProgress: (percent, text) => self.postMessage({ type: 'progress', data: { percent, text } })
            });
            self.postMessage({ type: 'result', data: sanitize(result) });
        } catch (err) {
            self.postMessage({ type: 'error', data: { message: err && err.message || String(err) } });
        }
    } else if (msg.type === 'ping') {
        self.postMessage({ type: 'pong', data: { ok: true } });
    }
};

function sanitize(obj) {
    const seen = new WeakSet();
    function walk(v) {
        if (v == null || typeof v !== 'object') return v;
        if (seen.has(v)) return undefined;
        if (v instanceof ArrayBuffer || ArrayBuffer.isView(v)) return undefined;
        seen.add(v);
        if (Array.isArray(v)) return v.map(walk);
        const out = {};
        for (const k of Object.keys(v)) {
            if (STRIP_KEYS.has(k)) continue;
            out[k] = walk(v[k]);
        }
        return out;
    }
    return walk(obj);
}

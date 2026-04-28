/** @preserve @license MIT */
'use strict';

const state = {
    analysisResults: null,
    zipContent: null,
    dexParsed: [],
    findings: { issue: [], secure: [] },
    groupedFindings: { issue: [], secure: [] },
    fileContents: new Map(),
    smaliTree: {},

    currentViewMode: 'java',
    currentViewClass: null,
    currentViewFqn: null,
    currentViewDexIdx: null,
    javaCache: new Map(),
    explorerView: 'apk',
    regexSearch: false
};

const esc = s => { if (!s && s !== 0) return ''; return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); };
const formatSize = b => b < 1024 ? b + ' B' : b < 1048576 ? (b / 1024).toFixed(1) + ' KB' : (b / 1048576).toFixed(2) + ' MB';
const sleep = ms => new Promise(r => setTimeout(r, ms));
const yield_ = () => sleep(0);

async function sha256hex(buf) {
    const h = await crypto.subtle.digest('SHA-256', buf);
    return Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2, '0')).join('');
}
async function md5hex(buf) {
    const b = new Uint8Array(buf);
    let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    const s = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
    const K = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391];
    const len = b.length, bitLen = len * 8;
    const padLen = len + 1 + ((56 - (len + 1) % 64 + 64) % 64) + 8;
    const pad = new Uint8Array(padLen);
    pad.set(b); pad[len] = 0x80;
    const dv = new DataView(pad.buffer);
    dv.setUint32(padLen - 8, bitLen >>> 0, true); dv.setUint32(padLen - 4, Math.floor(bitLen / 0x100000000), true);
    for (let i = 0; i < padLen; i += 64) {
        const M = []; for (let j = 0; j < 16; j++)M[j] = dv.getUint32(i + j * 4, true);
        let A = a0, B = b0, C = c0, D = d0;
        for (let j = 0; j < 64; j++) {
            let F, g;
            if (j < 16) { F = (B & C) | ((~B) & D); g = j; }
            else if (j < 32) { F = (D & B) | ((~D) & C); g = (5 * j + 1) % 16; }
            else if (j < 48) { F = B ^ C ^ D; g = (3 * j + 5) % 16; }
            else { F = C ^ (B | (~D)); g = (7 * j) % 16; }
            F = (F + A + K[j] + M[g]) >>> 0; A = D; D = C; C = B; B = (B + ((F << s[j]) | (F >>> (32 - s[j])))) >>> 0;
        }
        a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
    }
    const hex = v => [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff].map(x => x.toString(16).padStart(2, '0')).join('');
    return hex(a0) + hex(b0) + hex(c0) + hex(d0);
}
function sdkToVer(s) {
    const M = { 14: '4.0', 15: '4.0.3', 16: '4.1', 17: '4.2', 18: '4.3', 19: '4.4', 21: '5.0', 22: '5.1', 23: '6.0', 24: '7.0', 25: '7.1', 26: '8.0', 27: '8.1', 28: '9', 29: '10', 30: '11', 31: '12', 32: '12L', 33: '13', 34: '14', 35: '15' };
    return M[s] || String(s);
}

class AXMLParser {
    constructor(buffer) {
        const ab = buffer instanceof ArrayBuffer ? buffer : buffer.buffer;
        this.v = new DataView(ab);
        this.b = new Uint8Array(ab);
        this.strings = [];
        this.stack = [];
        this.root = null;
        this.cur = null;
    }
    u16(o) { return this.v.getUint16(o, true); }
    u32(o) { return this.v.getUint32(o, true); }

    parseStringPool(off) {
        const headerSize = this.u16(off + 2) || 28;
        const cnt = this.u32(off + 8);
        const flags = this.u32(off + 16);
        const strStart = this.u32(off + 20);
        const isU8 = !!(flags & 0x100);
        const base = off + strStart;
        const dec = new TextDecoder('utf-8', { fatal: false });
        const dec16 = new TextDecoder('utf-16le', { fatal: false });
        for (let i = 0; i < cnt; i++) {
            const tableOff = off + headerSize + i * 4;
            if (tableOff + 4 > this.b.length) break;
            const so = base + this.u32(tableOff);
            if (so >= this.b.length) { this.strings.push(''); continue; }
            try {
                if (isU8) {
                    let p = so;
                    let len = this.b[p++];
                    if (len & 0x80) len = ((len & 0x7F) << 8) | this.b[p++];
                    let len2 = this.b[p++];
                    if (len2 & 0x80) len2 = ((len2 & 0x7F) << 8) | this.b[p++];
                    const end = p + len2;
                    this.strings.push(dec.decode(this.b.slice(p, Math.min(end, this.b.length))));
                } else {
                    let p = so;
                    let len = this.u16(p); p += 2;
                    if (len & 0x8000) { len = ((len & 0x7FFF) << 16) | this.u16(p); p += 2; }
                    const bytes = len * 2;
                    this.strings.push(dec16.decode(this.b.slice(p, Math.min(p + bytes, this.b.length))));
                }
            } catch (e) { this.strings.push(''); }
        }
    }
    parseStartNs(off) { }
    parseStartElem(off) {
        if (off + 36 > this.b.length) return;
        const nameIdx = this.u32(off + 20);
        const attrStart = this.u16(off + 24);
        const attrSize = Math.max(this.u16(off + 26), 20);
        const attrCnt = this.u16(off + 28);
        const elem = { tag: this.strings[nameIdx] || '', attribs: {}, children: [] };
        const attrsBase = off + 16 + attrStart;
        for (let i = 0; i < attrCnt; i++) {
            const ao = attrsBase + i * attrSize;
            if (ao + 20 > this.b.length) break;
            const nm = this.u32(ao + 4);
            const rs = this.u32(ao + 8);
            const dt = ao + 15 < this.b.length ? this.b[ao + 15] : 0;
            const dv = this.u32(ao + 16);
            const key = this.strings[nm] || '';
            if (!key) continue;
            let val;
            switch (dt) {
                case 0x03: val = (rs !== 0xFFFFFFFF && rs < this.strings.length) ? (this.strings[rs] ?? '') : ''; break;
                case 0x10: val = dv | 0; break;
                case 0x11: val = '0x' + (dv >>> 0).toString(16); break;
                case 0x12: val = dv !== 0; break;
                default: val = (rs !== 0xFFFFFFFF && rs < this.strings.length) ? (this.strings[rs] ?? dv) : dv;
            }
            elem.attribs[key] = val;
        }
        if (this.cur) { this.stack.push(this.cur); this.cur.children.push(elem); }
        else { this.root = elem; }
        this.cur = elem;
    }
    parseEndElem() { if (this.stack.length) this.cur = this.stack.pop(); }

    parse() {
        try {
            if (this.b.length < 8) return null;
            if (this.u16(0) !== 0x0003) return null;
            let pos = 8;
            let iterations = 0;
            while (pos < this.b.length - 8 && iterations++ < 200000) {
                if (pos + 8 > this.b.length) break;
                const ct = this.u16(pos);
                const cs = this.u32(pos + 4);
                if (!cs || cs > this.b.length || pos + cs > this.b.length) break;
                if (ct === 0x0001) this.parseStringPool(pos);
                else if (ct === 0x0100) this.parseStartNs(pos);
                else if (ct === 0x0102) this.parseStartElem(pos);
                else if (ct === 0x0103) this.parseEndElem();
                pos += cs;
            }
        } catch (e) { }
        return this.root;
    }
}

function parseArsc(buffer) {
    try {
        const ab = buffer instanceof ArrayBuffer ? buffer : buffer.buffer;
        const v = new DataView(ab);
        const b = new Uint8Array(ab);
        if (b.length < 40) return null;
        const u16 = o => v.getUint16(o, true);
        const u32 = o => v.getUint32(o, true);

        if (u16(0) !== 0x0002) return null;

        const poolOff = 12;
        if (u16(poolOff) !== 0x0001) return null;

        const poolHeaderSize = u16(poolOff + 2) || 28;
        const cnt = Math.min(u32(poolOff + 8), 60000);
        const flags = u32(poolOff + 16);
        const strStart = u32(poolOff + 20);
        const isU8 = !!(flags & 0x100);
        const base = poolOff + strStart;
        const dec = new TextDecoder('utf-8', { fatal: false });
        const dec16 = new TextDecoder('utf-16le', { fatal: false });

        const strings = [];
        for (let i = 0; i < cnt; i++) {
            const tableOff = poolOff + poolHeaderSize + i * 4;
            if (tableOff + 4 > b.length) break;
            const so = base + u32(tableOff);
            if (so >= b.length || so < base) { strings.push(''); continue; }
            try {
                if (isU8) {
                    let p = so;
                    let len = b[p++];
                    if (len & 0x80) len = ((len & 0x7F) << 8) | b[p++];
                    let len2 = b[p++];
                    if (len2 & 0x80) len2 = ((len2 & 0x7F) << 8) | b[p++];
                    strings.push(dec.decode(b.slice(p, Math.min(p + len2, b.length))));
                } else {
                    let p = so;
                    let len = u16(p); p += 2;
                    if (len & 0x8000) { len = ((len & 0x7FFF) << 16) | u16(p); p += 2; }
                    strings.push(dec16.decode(b.slice(p, Math.min(p + len * 2, b.length))));
                }
            } catch (e) { strings.push(''); }
        }

        const allStrings = strings.filter(s => s.length > 0 && s.length < 1000);
        return { strings: allStrings, allStrings };
    } catch (e) { return null; }
}

function renderArsc(arscData) {
    if (!arscData || !arscData.strings.length) return 'Could not parse resources.arsc';
    return `resources.arsc -${arscData.strings.length} strings\n\n` +
        arscData.strings.filter(s => s.trim()).join('\n');
}

class DEXParser {
    constructor(buf) {
        const ab = buf instanceof ArrayBuffer ? buf : buf.buffer;
        this.v = new DataView(ab);
        this.b = new Uint8Array(ab);
    }
    u16(o) { return this.v.getUint16(o, true); }
    u32(o) { return this.v.getUint32(o, true); }
    uleb(p) {
        let r = 0, s = 0, x, itr = 0;
        do { if (p >= this.b.length || itr++ > 6) return { v: 0, p }; x = this.b[p++]; r |= (x & 0x7F) << s; s += 7; } while (x & 0x80);
        return { v: r, p };
    }

    parse() {
        try {
            if (this.b.length < 112) return null;
            const magic = new TextDecoder().decode(this.b.slice(0, 4));
            if (magic !== 'dex\n') return null;
            const H = {
                strSize: this.u32(56), strOff: this.u32(60),
                typSize: this.u32(64), typOff: this.u32(68),
                protoSize: this.u32(72), protoOff: this.u32(76),
                fldSize: this.u32(80), fldOff: this.u32(84),
                mthSize: this.u32(88), mthOff: this.u32(92),
                clsSize: this.u32(96), clsOff: this.u32(100)
            };
            if (H.strSize > 2000000 || H.typSize > 1000000 || H.mthSize > 1000000 || H.clsSize > 500000) return null;
            const strings = this._strings(H);
            const types = this._types(H, strings);
            const protos = this._protos(H, strings, types);
            const fields = this._fields(H, strings, types);
            const methods = this._methods(H, strings, types, protos);
            const classes = this._classes(H, strings, types, methods, fields);
            return { strings, types, fields, methods, classes };
        } catch (e) { return null; }
    }

    _strings(H) {
        const dec = new TextDecoder('utf-8', { fatal: false });
        const out = [];
        const limit = Math.min(H.strSize, 50000);
        for (let i = 0; i < limit; i++) {
            const tableOff = H.strOff + i * 4;
            if (tableOff + 4 > this.b.length) break;
            const dataOff = this.u32(tableOff);
            if (dataOff >= this.b.length) { out.push(''); continue; }
            let p = dataOff, r = 0, shift = 0, x, itr = 0;
            do { if (p >= this.b.length || itr++ > 5) break; x = this.b[p++]; r |= (x & 0x7F) << shift; shift += 7; } while (x & 0x80);
            if (r > 4096) { out.push(''); continue; }
            let end = p, maxEnd = Math.min(p + 8192, this.b.length);
            while (end < maxEnd && this.b[end] !== 0) end++;
            out.push(dec.decode(this.b.slice(p, end)));
        }
        return out;
    }

    _types(H, strs) {
        const o = [];
        const limit = Math.min(H.typSize, 50000);
        for (let i = 0; i < limit; i++) {
            const off = H.typOff + i * 4;
            if (off + 4 > this.b.length) break;
            const idx = this.u32(off);
            o.push(idx < strs.length ? strs[idx] : '');
        }
        return o;
    }

    _protos(H, strs, types) {
        const o = [];
        const limit = Math.min(H.protoSize, 50000);
        for (let i = 0; i < limit; i++) {
            const x = H.protoOff + i * 12;
            if (x + 12 > this.b.length) break;
            const retIdx = this.u32(x + 4);
            const paramsOff = this.u32(x + 8);
            const ret = retIdx < types.length ? types[retIdx] : 'V';
            const params = [];
            if (paramsOff && paramsOff + 4 <= this.b.length) {
                const pCnt = Math.min(this.u32(paramsOff), 20);
                for (let j = 0; j < pCnt; j++) {
                    const po = paramsOff + 4 + j * 2;
                    if (po + 2 > this.b.length) break;
                    const ti = this.u16(po);
                    params.push(ti < types.length ? types[ti] : '');
                }
            }
            o.push({ ret, params });
        }
        return o;
    }

    _fields(H, strs, types) {
        const o = [];
        const limit = Math.min(H.fldSize, 100000);
        for (let i = 0; i < limit; i++) {
            const x = H.fldOff + i * 8;
            if (x + 8 > this.b.length) break;
            const ci = this.u16(x), ti = this.u16(x + 2), ni = this.u32(x + 4);
            o.push({
                cls: ci < types.length ? types[ci] : '',
                type: ti < types.length ? types[ti] : '',
                name: ni < strs.length ? strs[ni] : ''
            });
        }
        return o;
    }

    _methods(H, strs, types, protos) {
        const o = [];
        const limit = Math.min(H.mthSize, 100000);
        for (let i = 0; i < limit; i++) {
            const x = H.mthOff + i * 8;
            if (x + 8 > this.b.length) break;
            const ci = this.u16(x), pi = this.u16(x + 2), ni = this.u32(x + 4);
            const proto = pi < protos.length ? protos[pi] : null;
            o.push({
                cls: ci < types.length ? types[ci] : '',
                name: ni < strs.length ? strs[ni] : '',
                returnType: proto ? proto.ret : 'V',
                paramTypes: proto ? proto.params : []
            });
        }
        return o;
    }

    _classes(H, strs, types, methods, fields) {
        const o = [];
        const limit = Math.min(H.clsSize, 20000);
        for (let i = 0; i < limit; i++) {
            const x = H.clsOff + i * 32;
            if (x + 32 > this.b.length) break;
            const ci = this.u32(x), flags = this.u32(x + 4), si = this.u32(x + 8);
            const ifaceOff = this.u32(x + 12);
            const src = this.u32(x + 16), dataOff = this.u32(x + 24);
            const cls = {
                name: ci < types.length ? types[ci] : '',
                superName: si !== 0xFFFFFFFF && si < types.length ? types[si] : '',
                srcFile: src !== 0xFFFFFFFF && src < strs.length ? strs[src] : '',
                flags,
                interfaces: [],
                methods: [],
                fields: []
            };
            if (ifaceOff && ifaceOff + 4 <= this.b.length) {
                const cnt = Math.min(this.u32(ifaceOff), 10);
                for (let j = 0; j < cnt; j++) {
                    const po = ifaceOff + 4 + j * 2;
                    if (po + 2 > this.b.length) break;
                    const ti = this.u16(po);
                    if (ti < types.length) cls.interfaces.push(types[ti]);
                }
            }
            if (dataOff && dataOff < this.b.length) {
                try {
                    const cd = this._classData(dataOff, methods, fields);
                    cls.methods = cd.methods;
                    cls.fields = cd.fields;
                } catch (e) { }
            }
            o.push(cls);
        }
        return o;
    }

    _classData(off, allM, allF) {
        let p = off;
        const r = () => { const { v, p: np } = this.uleb(p); p = np; return v; };
        const sf = r(), ins = r(), dm = r(), vm = r();
        if (sf + ins > 10000 || dm + vm > 10000) return { fields: [], methods: [] };
        const fields = []; let fIdx = 0;
        for (let i = 0; i < sf + ins; i++) {
            const d = r(), af = r(); fIdx += d;
            if (fIdx < allF.length) fields.push({ ...allF[fIdx], flags: af, isStatic: i < sf });
        }
        const methods = []; let mIdx = 0;
        for (let i = 0; i < dm + vm; i++) {
            const d = r(), af = r(), co = r(); mIdx += d;
            if (mIdx < allM.length) methods.push({ ...allM[mIdx], af, co, isDirect: i < dm });
        }
        return { fields, methods };
    }
}

class CertParser {
    constructor(buf) {
        this.b = new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer);
        this.p = 0;
    }
    rb() { return this.p < this.b.length ? this.b[this.p++] : 0; }
    rl() {
        let n = this.rb();
        if (!(n & 0x80)) return n;
        const k = n & 0x7F;
        if (k > 4) return 0;
        let l = 0;
        for (let i = 0; i < k; i++) l = (l << 8) | this.rb();
        return l;
    }
    tlv() {
        if (this.p >= this.b.length) return null;
        const tag = this.rb();
        const len = this.rl();
        if (len < 0 || this.p + len > this.b.length) return null;
        const s = this.p;
        this.p += len;
        return { tag, len, s, e: this.p, d: this.b.slice(s, this.p) };
    }
    oid(d) {
        if (!d || !d.length) return '';
        let o = Math.floor(d[0] / 40) + '.' + (d[0] % 40);
        let v = 0;
        for (let i = 1; i < d.length; i++) {
            v = (v << 7) | (d[i] & 0x7F);
            if (!(d[i] & 0x80)) { o += '.' + v; v = 0; }
        }
        const M = {
            '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU',
            '1.2.840.113549.1.1.4': 'MD5withRSA', '1.2.840.113549.1.1.5': 'SHA1withRSA',
            '1.2.840.113549.1.1.11': 'SHA256withRSA', '1.2.840.113549.1.1.12': 'SHA384withRSA',
            '1.2.840.10045.4.3.2': 'SHA256withECDSA', '1.2.840.10045.4.3.3': 'SHA384withECDSA'
        };
        return M[o] || o;
    }
    parseName(d) {
        const cp = new CertParser(d), out = {};
        let itr = 0;
        while (cp.p < d.length && itr++ < 20) {
            const set = cp.tlv(); if (!set) break;
            const sp = new CertParser(set.d), seq = sp.tlv(); if (!seq) continue;
            const ap = new CertParser(seq.d), ot = ap.tlv(), vt = ap.tlv();
            if (!ot || !vt) continue;
            const k = this.oid(ot.d);
            try { out[k] = new TextDecoder('utf-8', { fatal: false }).decode(vt.d); } catch (e) { }
        }
        return out;
    }
    parseTime(tag, d) {
        try {
            const s = new TextDecoder().decode(d);
            if (tag === 0x17) { const yr = parseInt(s.slice(0, 2)); return `${yr >= 50 ? '19' : '20'}${s.slice(0, 2)}-${s.slice(2, 4)}-${s.slice(4, 6)}`; }
            return `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}`;
        } catch (e) { return '?'; }
    }
    findCert() {
        try {
            const top = this.tlv(); if (!top || top.tag !== 0x30) return null;
            const p = new CertParser(top.d);
            const ot = p.tlv(); if (!ot) return null;
            if (ot.tag !== 0x06) return this._x509direct();
            const ctx = p.tlv(); if (!ctx) return null;
            const sp = new CertParser(ctx.d), sd = sp.tlv(); if (!sd) return null;
            const ip = new CertParser(sd.d); ip.tlv(); ip.tlv(); ip.tlv();
            const cc = ip.tlv(); if (!cc) return null;
            const xp = new CertParser(cc.d), xs = xp.tlv();
            return xs ? this._x509(xs.d) : null;
        } catch (e) { return null; }
    }
    _x509direct() { this.p = 0; try { const s = this.tlv(); return s && s.tag === 0x30 ? this._x509(s.d) : null; } catch (e) { return null; } }
    _x509(d) {
        try {
            const tp = new CertParser(d), tbs = tp.tlv(); if (!tbs || tbs.tag !== 0x30) return null;
            const sa = tp.tlv();
            const res = { subject: {}, issuer: {}, validity: {}, sigAlg: '', serial: '', isDebug: false, isExpired: false };
            if (sa && sa.tag === 0x30) { const ap = new CertParser(sa.d), ot = ap.tlv(); if (ot && ot.tag === 0x06) res.sigAlg = this.oid(ot.d); }
            const ip = new CertParser(tbs.d); let cur = ip.tlv();
            if (cur && (cur.tag & 0xE0) === 0xA0) cur = ip.tlv();
            res.serial = Array.from(cur?.d || []).slice(0, 20).map(b => b.toString(16).padStart(2, '0')).join(':');
            ip.tlv();
            const iss = ip.tlv(); if (iss) res.issuer = this.parseName(iss.d);
            const val = ip.tlv();
            if (val) { const vp = new CertParser(val.d), nb = vp.tlv(), na = vp.tlv(); if (nb) res.validity.notBefore = this.parseTime(nb.tag, nb.d); if (na) res.validity.notAfter = this.parseTime(na.tag, na.d); }
            const sub = ip.tlv(); if (sub) res.subject = this.parseName(sub.d);
            const cn = res.subject.CN || '', org = res.subject.O || '';
            res.isDebug = cn.includes('Android Debug') || org === 'Android' || cn === 'Unknown';
            if (res.validity.notAfter) res.isExpired = new Date(res.validity.notAfter) < new Date();
            return res;
        } catch (e) { return null; }
    }
}

const ANDROID_RULES = [
    {
        id: 'world_readable', name: 'SharedPreferences World Readable', severity: 'issue',
        patterns: [/MODE_WORLD_READABLE/g, /openFileOutput\([^,]{1,80},\s*1\)/g],
        description: 'World-readable files can be read by any installed app on the device.', cwe: 'CWE-276', owasp: 'M2', masvs: 'STORAGE-2'
    },
    {
        id: 'world_writable', name: 'SharedPreferences World Writable', severity: 'issue',
        patterns: [/MODE_WORLD_WRITEABLE/g, /openFileOutput\([^,]{1,80},\s*2\)/g],
        description: 'World-writable files can be modified by any installed app on the device.', cwe: 'CWE-276', owasp: 'M2', masvs: 'STORAGE-2'
    },
    {
        id: 'external_storage', name: 'External Storage Write', severity: 'issue',
        patterns: [/getExternalStorageDirectory/g, /getExternalFilesDir/g, /Environment\.getExternal/g],
        description: 'External storage is world-readable. Never write sensitive data to external storage.', cwe: 'CWE-312', owasp: 'M2', masvs: 'STORAGE-2'
    },
    {
        id: 'sqlite_raw', name: 'SQLite Raw Query', severity: 'issue',
        patterns: [/rawQuery\s*\(/g, /execSQL\s*\(/g],
        description: 'Raw SQL queries without parameterization are vulnerable to injection attacks.', cwe: 'CWE-89', owasp: 'M7', masvs: 'PLATFORM-2'
    },
    {
        id: 'sqlite_plain', name: 'SQLite Unencrypted Database', severity: 'issue',
        patterns: [/SQLiteOpenHelper/g, /SQLiteDatabase/g, /openOrCreateDatabase/g],
        description: 'SQLite databases are stored unencrypted. Use encrypted storage for sensitive data.', cwe: 'CWE-312', owasp: 'M2', masvs: 'STORAGE-14'
    },
    {
        id: 'sqlcipher', name: 'SQLCipher Encrypted Database', severity: 'secure',
        patterns: [/SQLCipher/g, /net\.sqlcipher/g],
        description: 'SQLCipher is used for encrypted SQLite storage -a good security practice.', cwe: '', owasp: '', masvs: 'STORAGE-14'
    },
    {
        id: 'weak_md5', name: 'Weak Hash Algorithm (MD5)', severity: 'issue',
        patterns: [/MessageDigest\.getInstance\(["']MD5["']/gi, /DigestUtils\.md5/gi, /"MD5"/g],
        description: 'MD5 is cryptographically broken. Collisions can be generated trivially. Use SHA-256.', cwe: 'CWE-327', owasp: 'M5', masvs: 'CRYPTO-4'
    },
    {
        id: 'weak_sha1', name: 'Weak Hash Algorithm (SHA-1)', severity: 'issue',
        patterns: [/MessageDigest\.getInstance\(["']SHA-?1["']/gi, /DigestUtils\.sha1/gi],
        description: 'SHA-1 is deprecated due to practical collision attacks. Migrate to SHA-256.', cwe: 'CWE-327', owasp: 'M5', masvs: 'CRYPTO-4'
    },
    {
        id: 'weak_des', name: 'Weak Cipher (DES/3DES)', severity: 'issue',
        patterns: [/Cipher\.getInstance\(["']DES/gi, /DESKeySpec/g, /"DESede"/g],
        description: 'DES and Triple-DES are obsolete. Use AES-256-GCM for symmetric encryption.', cwe: 'CWE-327', owasp: 'M5', masvs: 'CRYPTO-3'
    },
    {
        id: 'ecb_mode', name: 'ECB Mode Encryption', severity: 'issue',
        patterns: [/\/ECB\//g, /AES\/ECB/g, /Cipher\.getInstance\(["']AES["']\)/gi],
        description: 'ECB mode reveals patterns in encrypted data. Use AES/GCM/NoPadding instead.', cwe: 'CWE-327', owasp: 'M5', masvs: 'CRYPTO-3'
    },
    {
        id: 'insecure_random', name: 'Insecure Random Generator', severity: 'issue',
        patterns: [/new\s+Random\s*\(/g, /java\.util\.Random/g, /Math\.random\s*\(/g],
        description: 'java.util.Random is predictable. Use java.security.SecureRandom for cryptographic operations.', cwe: 'CWE-330', owasp: 'M5', masvs: 'CRYPTO-6'
    },
    {
        id: 'null_cipher', name: 'NullCipher Usage', severity: 'issue',
        patterns: [/NullCipher/g],
        description: 'NullCipher performs no actual encryption. Data is stored/transmitted in plaintext.', cwe: 'CWE-327', owasp: 'M5', masvs: 'CRYPTO-3'
    },
    {
        id: 'hardcoded_iv', name: 'Hardcoded Initialization Vector', severity: 'issue',
        patterns: [/IvParameterSpec\s*\(\s*new\s+byte\s*\[\s*\]\s*\{/g, /new\s+IvParameterSpec\s*\(["']/g],
        description: 'A static IV makes encryption deterministic and compromises ciphertext confidentiality.', cwe: 'CWE-329', owasp: 'M5', masvs: 'CRYPTO-3'
    },
    {
        id: 'hardcoded_key', name: 'Hardcoded Encryption Key', severity: 'issue',
        patterns: [/SecretKeySpec\s*\(\s*["'][^"']{1,100}["']/g],
        description: 'Hardcoded keys can be extracted by anyone who reverse-engineers the APK.', cwe: 'CWE-321', owasp: 'M5', masvs: 'CRYPTO-1'
    },
    {
        id: 'http_url', name: 'Insecure HTTP URL', severity: 'issue',
        patterns: [/http:\/\/(?!localhost|127\.|10\.|192\.168)[a-zA-Z][a-zA-Z0-9._-]{3,}/g],
        description: 'Cleartext HTTP traffic can be intercepted. All endpoints should use HTTPS.', cwe: 'CWE-319', owasp: 'M3', masvs: 'NETWORK-1'
    },
    {
        id: 'ssl_disabled', name: 'SSL Validation Disabled', severity: 'issue',
        patterns: [/ALLOW_ALL_HOSTNAME_VERIFIER/g, /getInsecure\s*\(/g, /TrustAllX509/gi, /setHostnameVerifier\s*\(\s*ALLOW_ALL/g],
        description: 'Disabling SSL validation allows attackers to intercept encrypted connections.', cwe: 'CWE-295', owasp: 'M3', masvs: 'NETWORK-4'
    },
    {
        id: 'trust_all', name: 'Trust All SSL Certificates', severity: 'issue',
        patterns: [/checkServerTrusted/g, /X509TrustManager/g, /TrustAllCerts/g],
        description: 'Accepting all certificates makes the app vulnerable to man-in-the-middle attacks.', cwe: 'CWE-295', owasp: 'M3', masvs: 'NETWORK-4'
    },
    {
        id: 'cert_pinning', name: 'Certificate Pinning Implemented', severity: 'secure',
        patterns: [/CertificatePinner/g, /pin-sha256/gi, /PublicKeyPinning/g],
        description: 'Certificate pinning is in place to prevent certificate substitution attacks.', cwe: '', owasp: '', masvs: 'NETWORK-4'
    },
    {
        id: 'ssl_error_override', name: 'WebView SSL Error Override', severity: 'issue',
        patterns: [/onReceivedSslError/g],
        description: 'Overriding onReceivedSslError without rejection allows connections with invalid certificates.', cwe: 'CWE-295', owasp: 'M3', masvs: 'NETWORK-4'
    },
    {
        id: 'webview_js', name: 'WebView JavaScript Enabled', severity: 'issue',
        patterns: [/setJavaScriptEnabled\s*\(\s*true/g, /javaScriptEnabled\s*=\s*true/g],
        description: 'Enabling JavaScript in WebView is a prerequisite for cross-site scripting attacks.', cwe: 'CWE-79', owasp: 'M7', masvs: 'PLATFORM-6'
    },
    {
        id: 'webview_addjs', name: 'WebView addJavascriptInterface', severity: 'issue',
        patterns: [/addJavascriptInterface\s*\(/g, /@JavascriptInterface/g],
        description: 'Exposes Java methods to JavaScript -enables remote code execution on Android < 4.2.', cwe: 'CWE-749', owasp: 'M7', masvs: 'PLATFORM-6'
    },
    {
        id: 'webview_file', name: 'WebView File Access Enabled', severity: 'issue',
        patterns: [/setAllowFileAccess\s*\(\s*true/g, /setAllowFileAccessFromFileURLs\s*\(\s*true/g, /setAllowUniversalAccessFromFileURLs\s*\(\s*true/g],
        description: 'WebView file access allows malicious scripts to read arbitrary files via file:// URIs.', cwe: 'CWE-200', owasp: 'M7', masvs: 'PLATFORM-6'
    },
    {
        id: 'webview_savepass', name: 'WebView Password Saving', severity: 'issue',
        patterns: [/setSavePassword\s*\(\s*true/g],
        description: 'Saved WebView passwords can be recovered from device storage.', cwe: 'CWE-256', owasp: 'M2', masvs: 'STORAGE-14'
    },
    {
        id: 'runtime_exec', name: 'Runtime Command Execution', severity: 'issue',
        patterns: [/Runtime\.getRuntime\(\)\.exec\s*\(/g, /ProcessBuilder\s*\(/g],
        description: 'Dynamic process execution with user-controlled input enables OS command injection.', cwe: 'CWE-78', owasp: 'M7', masvs: 'CODE-6'
    },
    {
        id: 'implicit_intent', name: 'Implicit Intent', severity: 'issue',
        patterns: [/new\s+Intent\s*\(\s*["']android\./g, /sendBroadcast\s*\(\s*new\s+Intent/g],
        description: 'Implicit intents can be intercepted or redirected by other installed applications.', cwe: 'CWE-925', owasp: 'M1', masvs: 'PLATFORM-1'
    },
    {
        id: 'sticky_broadcast', name: 'Sticky Broadcast', severity: 'issue',
        patterns: [/sendStickyBroadcast/g, /sendStickyOrderedBroadcast/g],
        description: 'Sticky broadcasts are deprecated (API 21) and accessible to any app.', cwe: 'CWE-200', owasp: 'M1', masvs: 'PLATFORM-2'
    },
    {
        id: 'pending_mutable', name: 'Mutable PendingIntent', severity: 'issue',
        patterns: [/FLAG_MUTABLE/g],
        description: 'Mutable PendingIntents can be hijacked. Use FLAG_IMMUTABLE on Android 12+.', cwe: 'CWE-927', owasp: 'M1', masvs: 'PLATFORM-1'
    },
    {
        id: 'hardcoded_pw', name: 'Hardcoded Password/Secret', severity: 'issue',
        patterns: [/password\s*=\s*["'][^"'\n]{3,80}["']/gi, /secret\s*=\s*["'][^"'\n]{4,80}["']/gi, /api[_-]?key\s*=\s*["'][^"'\n]{8,80}["']/gi],
        description: 'Hardcoded credentials embedded in APKs are trivially recoverable via static analysis.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'hardcoded_token', name: 'Hardcoded Token/Bearer', severity: 'issue',
        patterns: [/Bearer\s+[A-Za-z0-9\-_]{20,}/g, /authorization\s*[:=]\s*["'][^"'\n]{20,80}["']/gi],
        description: 'Authentication tokens must be fetched dynamically, not embedded in the binary.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'aws_key', name: 'AWS Credentials Exposed', severity: 'issue',
        patterns: [/AKIA[0-9A-Z]{16}/g],
        description: 'AWS access key found. Rotate credentials immediately in AWS IAM console.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'google_key', name: 'Google API Key Exposed', severity: 'issue',
        patterns: [/AIza[0-9A-Za-z\-_]{35}/g],
        description: 'Google API key embedded in the APK. Restrict key scope in Google Cloud Console.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'firebase_url', name: 'Firebase Database URL', severity: 'issue',
        patterns: [/[a-zA-Z0-9\-]+\.firebaseio\.com/gi, /[a-zA-Z0-9\-]+\.firebasedatabase\.app/gi],
        description: 'Firebase database URL found. Verify that security rules block unauthorized access.', cwe: 'CWE-200', owasp: 'M1', masvs: 'STORAGE-12'
    },
    {
        id: 'aws_s3', name: 'AWS S3 Bucket URL', severity: 'issue',
        patterns: [/[a-z0-9\-]+\.s3[.\-][a-z0-9\-]+\.amazonaws\.com/gi],
        description: 'S3 bucket URL detected. Verify the bucket policy does not permit public access.', cwe: 'CWE-200', owasp: 'M1', masvs: 'STORAGE-12'
    },
    {
        id: 'localhost_url', name: 'Debug/Localhost URL', severity: 'issue',
        patterns: [/https?:\/\/localhost[\/:]/gi, /https?:\/\/127\.0\.0\.1[\/:]/g],
        description: 'Development/debug endpoints found in the release binary. Remove before shipping.', cwe: 'CWE-489', owasp: 'M1', masvs: 'CODE-4'
    },
    {
        id: 'jwt_hardcoded', name: 'Hardcoded JWT Token', severity: 'issue',
        patterns: [/eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}/g],
        description: 'A signed JWT was found embedded in the binary -tokens must not be hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'private_key', name: 'Private Key Material', severity: 'issue',
        patterns: [/-----BEGIN (?:RSA )?PRIVATE KEY-----/g, /-----BEGIN EC PRIVATE KEY-----/g],
        description: 'Private key material embedded in the APK allows complete impersonation.', cwe: 'CWE-321', owasp: 'M9', masvs: 'CRYPTO-1'
    },
    {
        id: 'android_keystore', name: 'Android Keystore Used', severity: 'secure',
        patterns: [/AndroidKeyStore/g, /KeyStore\.getInstance\(["']AndroidKeyStore["']/g],
        description: 'Android Keystore provides hardware-backed cryptographic key storage.', cwe: '', owasp: '', masvs: 'STORAGE-1'
    },
    {
        id: 'biometric', name: 'Biometric Authentication', severity: 'issue',
        patterns: [/BiometricPrompt/g, /FingerprintManager/g, /BiometricManager/g],
        description: 'Biometric authentication (fingerprint/face) is implemented.', cwe: '', owasp: '', masvs: 'AUTH-8'
    },
    {
        id: 'root_detect', name: 'Root Detection', severity: 'secure',
        patterns: [/RootBeer/g, /isRooted/g, /isDeviceRooted/g, /\/system\/xbin\/su/g],
        description: 'Root detection is implemented to identify compromised devices.', cwe: '', owasp: '', masvs: 'RESILIENCE-1'
    },
    {
        id: 'emulator_detect', name: 'Emulator Detection', severity: 'secure',
        patterns: [/isEmulator/g, /Build\.FINGERPRINT.*generic/gi, /Build\.MODEL.*Emulator/gi],
        description: 'Emulator detection for runtime environment integrity checks.', cwe: '', owasp: '', masvs: 'RESILIENCE-3'
    },
    {
        id: 'antidebug', name: 'Anti-Debug Protection', severity: 'secure',
        patterns: [/isDebuggerConnected/g, /android\.os\.Debug\.isDebuggerConnected/g],
        description: 'Anti-debugging protection is implemented to resist dynamic analysis.', cwe: '', owasp: '', masvs: 'RESILIENCE-2'
    },
    {
        id: 'integrity_check', name: 'App Integrity Check', severity: 'secure',
        patterns: [/SafetyNet/g, /PlayIntegrity/g],
        description: 'Play Integrity or SafetyNet attestation verifies app has not been tampered with.', cwe: '', owasp: '', masvs: 'RESILIENCE-4'
    },
    {
        id: 'native_jni', name: 'Native JNI Code', severity: 'issue',
        patterns: [/System\.loadLibrary\s*\(/g, /System\.load\s*\(/g],
        description: 'Native code is loaded. JNI bridges may introduce memory-safety vulnerabilities.', cwe: 'CWE-120', owasp: 'M7', masvs: 'CODE-6'
    },
    {
        id: 'unsafe_native', name: 'Unsafe Native Functions', severity: 'issue',
        patterns: [/memcpy\s*\(/g, /strcpy\s*\(/g, /sprintf\s*\(/g, /gets\s*\(/g],
        description: 'Unsafe C standard library functions found. These can cause buffer overflows.', cwe: 'CWE-120', owasp: 'M7', masvs: 'CODE-6'
    },
    {
        id: 'github_token', name: 'GitHub Token Exposed', severity: 'issue',
        patterns: [/ghp_[A-Za-z0-9_]{36}/g, /gho_[A-Za-z0-9_]{36}/g, /ghs_[A-Za-z0-9_]{36}/g, /github_pat_[A-Za-z0-9_]{22,}/g],
        description: 'GitHub personal access token found. Revoke it immediately in GitHub Settings > Tokens.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'stripe_secret', name: 'Stripe Secret Key Exposed', severity: 'issue',
        patterns: [/sk_live_[A-Za-z0-9]{24,}/g, /sk_test_[A-Za-z0-9]{24,}/g, /rk_live_[A-Za-z0-9]{24,}/g],
        description: 'Stripe secret key found in APK. This allows full access to the payment account.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'slack_webhook', name: 'Slack Webhook URL', severity: 'issue',
        patterns: [/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g],
        description: 'Slack webhook URL exposed. Anyone can post messages to this channel.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'sendgrid_key', name: 'SendGrid API Key Exposed', severity: 'issue',
        patterns: [/SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g],
        description: 'SendGrid API key found. Attacker can send emails from your domain.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'mailgun_key', name: 'Mailgun API Key', severity: 'issue',
        patterns: [/key-[0-9a-zA-Z]{32}/g],
        description: 'Mailgun API key detected in the application.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'api_key_xml', name: 'API Key in XML Resource', severity: 'issue',
        patterns: [/google_maps_key/gi, /google_api_key/gi, /api_key.*>[A-Za-z0-9_\-]{20,}/g, /maps_api_key/gi, /facebook_app_id.*>[0-9]{10,}/g],
        description: 'API key found in XML resources (strings.xml / config). These are trivially extractable.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'cleartext_nsc', name: 'Cleartext Traffic in Network Security Config', severity: 'issue',
        patterns: [/cleartextTrafficPermitted\s*=\s*["']true/gi],
        description: 'Network security config explicitly allows cleartext HTTP traffic to specific domains.', cwe: 'CWE-319', owasp: 'M3', masvs: 'NETWORK-1'
    },
    {
        id: 'deeplink_handler', name: 'Custom URL Scheme Handler', severity: 'issue',
        patterns: [/android:scheme=["'][a-zA-Z][a-zA-Z0-9+.\-]*["']/g],
        description: 'Custom URL scheme registered. Verify deep link inputs are validated to prevent injection.', cwe: 'CWE-939', owasp: 'M1', masvs: 'PLATFORM-3'
    },
    {
        id: 'intent_extra_unvalidated', name: 'Unvalidated Intent Extras', severity: 'issue',
        patterns: [/getStringExtra\s*\(/g, /getIntExtra\s*\(/g, /getSerializableExtra\s*\(/g, /getParcelableExtra\s*\(/g],
        description: 'Intent extras are read without validation. Exported components receiving these may be exploitable.', cwe: 'CWE-20', owasp: 'M1', masvs: 'PLATFORM-2'
    },
    {
        id: 'shared_prefs_plain', name: 'SharedPreferences for Sensitive Data', severity: 'issue',
        patterns: [/getSharedPreferences\s*\([^)]*(?:password|token|secret|key|credential)/gi],
        description: 'SharedPreferences used to store potentially sensitive data. Use EncryptedSharedPreferences instead.', cwe: 'CWE-312', owasp: 'M2', masvs: 'STORAGE-2'
    },
    {
        id: 'tapjacking', name: 'Tapjacking Vulnerability', severity: 'issue',
        patterns: [/filterTouchesWhenObscured\s*=\s*["']?false/gi],
        description: 'Touch filtering disabled. The app may be vulnerable to tapjacking overlay attacks.', cwe: 'CWE-1021', owasp: 'M1', masvs: 'PLATFORM-9'
    },
    {
        id: 'file_mode_private', name: 'Insecure File Creation Mode', severity: 'issue',
        patterns: [/openFileOutput\s*\([^)]*,\s*(?:1|2|3)\s*\)/g, /MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE/g],
        description: 'Files created with world-readable/writable mode can be accessed by any app on the device.', cwe: 'CWE-276', owasp: 'M2', masvs: 'STORAGE-2'
    },
    {
        id: 'temp_file', name: 'Insecure Temp File Creation', severity: 'issue',
        patterns: [/File\.createTempFile\s*\(/g, /\.createTempFile\s*\(/g],
        description: 'Temp files may persist on disk with predictable names. Ensure cleanup and proper permissions.', cwe: 'CWE-377', owasp: 'M2', masvs: 'STORAGE-2'
    },
    {
        id: 'webview_content_access', name: 'WebView Content Provider Access', severity: 'issue',
        patterns: [/setAllowContentAccess\s*\(\s*true/g],
        description: 'WebView can access content:// URIs -may allow reading arbitrary app data via content providers.', cwe: 'CWE-200', owasp: 'M7', masvs: 'PLATFORM-6'
    },
    {
        id: 'content_provider_sql', name: 'Content Provider SQL Injection', severity: 'issue',
        patterns: [/query\s*\([^)]*\+[^)]*selection/gi, /rawQuery\s*\([^)]*\+/g],
        description: 'SQL query concatenates user input. Use parameterized queries (selectionArgs) to prevent SQL injection.', cwe: 'CWE-89', owasp: 'M7', masvs: 'PLATFORM-2'
    },
    {
        id: 'ordered_broadcast', name: 'Ordered Broadcast Without Permission', severity: 'issue',
        patterns: [/sendOrderedBroadcast\s*\([^,]+,\s*null/g],
        description: 'Ordered broadcast sent with null permission -any app can receive and modify the result.', cwe: 'CWE-925', owasp: 'M1', masvs: 'PLATFORM-4'
    },
    {
        id: 'clipboard_copy', name: 'Sensitive Data Copied to Clipboard', severity: 'issue',
        patterns: [/setPrimaryClip\s*\(/g],
        description: 'Data copied to clipboard is accessible to all apps. On Android < 12, background apps can read clipboard silently.', cwe: 'CWE-200', owasp: 'M2', masvs: 'STORAGE-10'
    },
    {
        id: 'insecure_deser', name: 'Insecure Deserialization', severity: 'issue',
        patterns: [/ObjectInputStream\s*\(/g, /readObject\s*\(\s*\)/g, /\.readUnshared\s*\(/g],
        description: 'Java deserialization of untrusted data can lead to remote code execution via gadget chains.', cwe: 'CWE-502', owasp: 'M7', masvs: 'PLATFORM-8'
    },
    {
        id: 'fileprovider_root', name: 'FileProvider Exposes Root Path', severity: 'issue',
        patterns: [/root-path\s*name/g, /external-path\s*name/g],
        description: 'FileProvider configuration may expose root or external paths. Verify only intended directories are shared.', cwe: 'CWE-200', owasp: 'M2', masvs: 'STORAGE-12'
    },
    {
        id: 'hardcoded_ip', name: 'Hardcoded IP Address', severity: 'issue',
        patterns: [/["'](?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)["']/g],
        description: 'Hardcoded IP address found. Use hostnames to allow certificate validation and DNS-based security.', cwe: 'CWE-798', owasp: 'M3', masvs: 'NETWORK-1'
    },
    {
        id: 'implicit_chooser', name: 'Implicit Intent Without Chooser', severity: 'issue',
        patterns: [/startActivity\s*\(\s*new\s+Intent\s*\(\s*Intent\./g],
        description: 'Implicit intent sent without Intent.createChooser(). A malicious app can register as handler to intercept data.', cwe: 'CWE-925', owasp: 'M1', masvs: 'PLATFORM-4'
    },
    {
        id: 'log_sensitive', name: 'Sensitive Data in Logs', severity: 'issue',
        patterns: [/Log\.[dievw]\s*\([^)]*(?:password|passwd|token|secret|pin|otp|credential|auth_token|session_id|access_key)/gi],
        description: 'Sensitive data (passwords, tokens, PINs) written to Android logs. Logs are readable by any app with READ_LOGS or via ADB.', cwe: 'CWE-532', owasp: 'M2', masvs: 'STORAGE-3'
    },
    {
        id: 'sms_send', name: 'SMS Sending Capability', severity: 'issue',
        patterns: [/SmsManager\.getDefault\(\)\.send/g, /sendTextMessage\s*\(/g, /sendMultipartTextMessage\s*\(/g],
        description: 'App sends SMS programmatically. If triggered by untrusted input, this enables premium SMS fraud.', cwe: 'CWE-927', owasp: 'M1', masvs: 'PLATFORM-4'
    },
    {
        id: 'webview_inject', name: 'WebView URL from External Input', severity: 'issue',
        patterns: [/\.loadUrl\s*\(\s*(?:url|uri|link|data|intent|getIntent)/gi, /\.loadData\s*\(\s*(?:html|content|data|getIntent)/gi],
        description: 'WebView loads content from a variable that may originate from untrusted input (intent, deep link). Attacker can inject javascript: URIs for XSS or file: URIs to steal data.', cwe: 'CWE-79', owasp: 'M7', masvs: 'PLATFORM-6'
    },
    {
        id: 'deeplink_data_unsafe', name: 'Deep Link Data Used Without Validation', severity: 'issue',
        patterns: [/getIntent\(\)\.getData\(\)\.get(?:Host|Path|Query|Fragment|Scheme)/g, /getIntent\(\)\.getData\(\)\.toString/g],
        description: 'URI data from deep link intent read without validation. Can enable open redirect, SSRF, or account takeover if used in navigation or API calls.', cwe: 'CWE-601', owasp: 'M1', masvs: 'PLATFORM-3'
    },
    {
        id: 'dynamic_receiver', name: 'Dynamic Broadcast Receiver (Potentially Exported)', severity: 'issue',
        patterns: [/registerReceiver\s*\([^)]*(?:new\s+IntentFilter|filter)/g],
        description: 'Dynamically registered BroadcastReceiver. On Android 14+, receivers must specify RECEIVER_NOT_EXPORTED or RECEIVER_EXPORTED flag. Missing flag defaults to exported.', cwe: 'CWE-926', owasp: 'M1', masvs: 'PLATFORM-4'
    },
    {
        id: 'classloader_rce', name: 'Dynamic Class Loading (Code Execution Risk)', severity: 'issue',
        patterns: [/new\s+DexClassLoader\s*\(/g, /new\s+PathClassLoader\s*\(/g, /new\s+URLClassLoader\s*\(/g, /InMemoryDexClassLoader/g],
        description: 'Classes loaded dynamically from external paths. If the loaded code path is attacker-controllable, this leads to arbitrary code execution.', cwe: 'CWE-94', owasp: 'M7', masvs: 'RESILIENCE-9'
    },
    {
        id: 'reflect_invoke', name: 'Reflective Method Invocation', severity: 'issue',
        patterns: [/\.invoke\s*\(\s*[^)]*getMethod/g, /getDeclaredMethod\s*\([^)]*\)\.invoke/g],
        description: 'Method invoked via reflection. If the class/method name comes from untrusted input, this can execute arbitrary code.', cwe: 'CWE-470', owasp: 'M7', masvs: 'CODE-6'
    },
    {
        id: 'provider_openfile', name: 'Content Provider openFile (Path Traversal Risk)', severity: 'issue',
        patterns: [/openFile\s*\([^)]*Uri[^)]*\)/g],
        description: 'Content Provider implements openFile(). Without proper path canonicalization, "../" in URIs can read arbitrary files from the app sandbox.', cwe: 'CWE-22', owasp: 'M2', masvs: 'PLATFORM-2'
    },
    {
        id: 'pending_implicit_full', name: 'Mutable PendingIntent with Empty Intent', severity: 'issue',
        patterns: [/PendingIntent\.get(?:Activity|Service|Broadcast)\s*\([^)]*new\s+Intent\s*\(\s*\)/g, /PendingIntent\.get(?:Activity|Service|Broadcast)\s*\([^)]*FLAG_MUTABLE/g],
        description: 'PendingIntent created with mutable flag or empty base intent. Attacker app can fill in the intent to hijack the operation and steal data.', cwe: 'CWE-927', owasp: 'M1', masvs: 'PLATFORM-1'
    },
    {
        id: 'prefs_sensitive_store', name: 'Credentials Stored in SharedPreferences', severity: 'issue',
        patterns: [/\.edit\(\)\.put(?:String|Int|Boolean)\s*\([^)]*(?:password|token|secret|pin|session|auth_key|access_token|refresh_token)/gi],
        description: 'Sensitive credentials written to SharedPreferences (plain XML on disk). Use EncryptedSharedPreferences or Android Keystore.', cwe: 'CWE-312', owasp: 'M2', masvs: 'STORAGE-2'
    },
    {
        id: 'fragment_inject', name: 'Fragment Injection via Intent Extras', severity: 'issue',
        patterns: [/getStringExtra\s*\(\s*["']:android:show_fragment["']/g, /PreferenceActivity/g],
        description: 'Exported activity extending PreferenceActivity is vulnerable to fragment injection. Attacker can load arbitrary fragments including non-exported ones.', cwe: 'CWE-470', owasp: 'M1', masvs: 'PLATFORM-2'
    },
    {
        id: 'intent_redir', name: 'Intent Redirection (Access Non-Exported Components)', severity: 'issue',
        patterns: [/startActivity\s*\(\s*\(?Intent\)?\s*get(?:Parcelable|Serializable)Extra/g, /startActivity\s*\([^)]*getParcelableExtra\s*\(/g, /startService\s*\([^)]*getParcelableExtra/g],
        description: 'Activity/Service started from an Intent received via extras. Attacker can craft an intent pointing to non-exported components, bypassing access controls.', cwe: 'CWE-926', owasp: 'M1', masvs: 'PLATFORM-1'
    },
    {
        id: 'provider_query_exposed', name: 'Content Provider Query Without Permission Check', severity: 'issue',
        patterns: [/\.query\s*\(\s*uri/gi, /getContentResolver\(\)\.query/g],
        description: 'Content resolver query executed. If the target provider is exported without permissions, any app can read its data (contacts, messages, app data).', cwe: 'CWE-200', owasp: 'M2', masvs: 'PLATFORM-2'
    },
    {
        id: 'math_random_security', name: 'Math.random() for Security Token', severity: 'issue',
        patterns: [/Math\.random\s*\(\s*\).*(?:token|key|nonce|salt|iv|seed|otp|code|pin)/gi, /Random\s*\(\s*\).*(?:token|key|nonce|otp|pin)/gi],
        description: 'Predictable random generator used to create security tokens. Use SecureRandom for all cryptographic and authentication-related randomness.', cwe: 'CWE-330', owasp: 'M5', masvs: 'CRYPTO-6'
    },
    {
        id: 'rsa_no_padding', name: 'RSA Without Padding', severity: 'issue',
        patterns: [/Cipher\.getInstance\s*\(\s*["']RSA[^"']*\/NoPadding/gi],
        description: 'RSA used without OAEP padding. Textbook RSA is vulnerable to chosen-ciphertext attacks. Use RSA/ECB/OAEPWithSHA-256AndMGF1Padding.', cwe: 'CWE-780', owasp: 'M5', masvs: 'CRYPTO-3'
    },
    {
        id: 'cbc_padding', name: 'CBC with PKCS Padding (Padding Oracle)', severity: 'issue',
        patterns: [/Cipher\.getInstance\s*\(\s*["'][^"']*\/CBC\/PKCS5Padding/gi, /Cipher\.getInstance\s*\(\s*["'][^"']*\/CBC\/PKCS7Padding/gi],
        description: 'CBC mode with PKCS5/PKCS7 padding is vulnerable to padding oracle attacks. Use AES/GCM/NoPadding for authenticated encryption.', cwe: 'CWE-649', owasp: 'M5', masvs: 'CRYPTO-3'
    },
    {
        id: 'weak_rc4', name: 'Weak Cipher (RC4/Blowfish)', severity: 'issue',
        patterns: [/Cipher\.getInstance\s*\(\s*["'](?:RC2|RC4|ARCFOUR|Blowfish)/gi],
        description: 'RC4/Blowfish are deprecated ciphers with known weaknesses. Use AES-256-GCM instead.', cwe: 'CWE-327', owasp: 'M5', masvs: 'CRYPTO-3'
    },
    {
        id: 'weak_md4', name: 'Weak Hash (MD4)', severity: 'issue',
        patterns: [/MessageDigest\.getInstance\s*\(\s*["']MD4/gi],
        description: 'MD4 is completely broken. Collisions can be found in milliseconds. Use SHA-256 or SHA-3.', cwe: 'CWE-327', owasp: 'M5', masvs: 'CRYPTO-4'
    },
    {
        id: 'webview_debug', name: 'WebView Debugging Enabled', severity: 'issue',
        patterns: [/setWebContentsDebuggingEnabled\s*\(\s*true/g],
        description: 'WebView remote debugging is enabled. Attacker on same network can inspect WebView contents via chrome://inspect. Disable in production.', cwe: 'CWE-489', owasp: 'M1', masvs: 'RESILIENCE-2'
    },
    {
        id: 'no_screenshot_protect', name: 'No Screenshot Protection (FLAG_SECURE)', severity: 'issue',
        patterns: [/FLAG_SECURE/g],
        description: 'FLAG_SECURE is used to prevent screenshots and recent-app thumbnails from leaking sensitive UI content.', cwe: 'CWE-200', owasp: 'M2', masvs: 'STORAGE-9'
    },
    {
        id: 'hidden_ui', name: 'Hidden UI Elements (Data Leak)', severity: 'issue',
        patterns: [/setVisibility\s*\(\s*View\.GONE\s*\)/g, /setVisibility\s*\(\s*View\.INVISIBLE\s*\)/g],
        description: 'UI elements hidden with GONE/INVISIBLE may still hold sensitive data in memory. Attacker can reveal them via layout inspection.', cwe: 'CWE-200', owasp: 'M2', masvs: 'STORAGE-7'
    },
    {
        id: 'jackson_deser', name: 'Jackson Default Typing (Deserialization)', severity: 'issue',
        patterns: [/enableDefaultTyping\s*\(/g, /activateDefaultTyping\s*\(/g],
        description: 'Jackson ObjectMapper with default typing enabled allows arbitrary class instantiation from JSON input, leading to RCE.', cwe: 'CWE-502', owasp: 'M7', masvs: 'PLATFORM-8'
    },
    {
        id: 'download_mgr', name: 'Download Manager Usage', severity: 'issue',
        patterns: [/getSystemService\s*\(\s*[^)]*DOWNLOAD_SERVICE/g, /DownloadManager\.Request\s*\(/g],
        description: 'DownloadManager saves files to public storage by default. Downloaded files can be read or tampered with by other apps.', cwe: 'CWE-276', owasp: 'M2', masvs: 'STORAGE-2'
    },
    {
        id: 'clipboard_listen', name: 'Clipboard Listener', severity: 'issue',
        patterns: [/OnPrimaryClipChangedListener/g, /addPrimaryClipChangedListener/g],
        description: 'App listens to clipboard changes. Can capture passwords, OTPs, and sensitive data copied by the user from other apps.', cwe: 'CWE-200', owasp: 'M2', masvs: 'STORAGE-10'
    },
    {
        id: 'debug_build', name: 'Debug Build Flag Enabled', severity: 'issue',
        patterns: [/BuildConfig\.DEBUG\s*==\s*true/g, /BuildConfig\.DEBUG\s*\)/g],
        description: 'Code checks or relies on BuildConfig.DEBUG. If debug flag is left true in release builds, debug code paths remain active.', cwe: 'CWE-489', owasp: 'M9', masvs: 'CODE-5'
    },
    {
        id: 'world_readwrite', name: 'World Read+Write File Mode', severity: 'issue',
        patterns: [/openFileOutput\s*\([^)]*,\s*3\s*\)/g],
        description: 'File created with mode 3 (world-readable + world-writable). Any app on the device can read and modify this file.', cwe: 'CWE-276', owasp: 'M2', masvs: 'STORAGE-2'
    },
    {
        id: 'frida_detect', name: 'Frida Detection', severity: 'issue',
        patterns: [/fridaserver/gi, /27047/g, /LIBFRIDA/g, /frida-agent/gi],
        description: 'Anti-tampering check for Frida instrumentation framework. Presence suggests the app has runtime protection.', cwe: '', owasp: '', masvs: 'RESILIENCE-4'
    },
    {
        id: 'webview_sdcard', name: 'WebView Loads from External Storage', severity: 'issue',
        patterns: [/loadUrl\s*\([^)]*getExternalStorageDirectory/g, /loadUrl\s*\([^)]*getExternalFilesDir/g],
        description: 'WebView loads HTML from external storage. Any app with storage permission can replace the HTML with malicious content.', cwe: 'CWE-749', owasp: 'M7', masvs: 'PLATFORM-6'
    },
    {
        id: 'slack_token', name: 'Slack Token', severity: 'issue',
        patterns: [/xox[baprs]-[0-9a-zA-Z]{10,48}/g],
        description: 'Slack API token found. Allows reading messages, posting, and accessing workspace data.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'fb_access_token', name: 'Facebook Access Token', severity: 'issue',
        patterns: [/EAACEdEose0cBA[0-9A-Za-z]+/g],
        description: 'Facebook access token found. Grants access to user profile, posts, and connected apps.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'gcp_oauth_token', name: 'Google OAuth Access Token', severity: 'issue',
        patterns: [/ya29\.[0-9A-Za-z\-_]+/g],
        description: 'Google OAuth access token embedded in code. These tokens grant API access to Google services.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'gcp_oauth_client', name: 'Google OAuth Client ID', severity: 'issue',
        patterns: [/[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g],
        description: 'Google OAuth client ID found. Combined with a secret, this enables impersonating the app for OAuth flows.', cwe: 'CWE-200', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'gcp_service_account', name: 'GCP Service Account Key', severity: 'issue',
        patterns: [/"type"\s*:\s*"service_account"/g],
        description: 'Google Cloud service account key file detected. Full access to GCP resources tied to this account.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'password_in_url', name: 'Credentials in URL', severity: 'issue',
        patterns: [/[a-zA-Z]{3,10}:\/\/[^\s:@]{3,20}:[^\s:@]{3,20}@.{1,100}/g],
        description: 'URL contains embedded username:password. These are logged in browser history, server logs, and proxy logs.', cwe: 'CWE-522', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'square_token', name: 'Square Payment Token', severity: 'issue',
        patterns: [/sq0atp-[0-9A-Za-z\-_]{22}/g, /sq0csp-[0-9A-Za-z\-_]{43}/g],
        description: 'Square payment API token found. Allows processing transactions on the merchant account.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'telegram_bot', name: 'Telegram Bot Token', severity: 'issue',
        patterns: [/[0-9]{5,10}:AA[0-9A-Za-z\-_]{33}/g],
        description: 'Telegram bot API token. Allows sending messages, reading updates, and controlling the bot.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'aws_secret', name: 'AWS Secret Access Key', severity: 'issue',
        patterns: [/(?:aws|AWS).*['"][0-9a-zA-Z\/+]{40}['"]/g],
        description: 'AWS secret access key found near an AWS context string. Full programmatic access to AWS resources.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'mailchimp_key', name: 'MailChimp API Key', severity: 'issue',
        patterns: [/[0-9a-f]{32}-us[0-9]{1,2}/g],
        description: 'MailChimp API key found. Allows managing email campaigns and subscriber lists.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'paypal_token', name: 'PayPal/Braintree Token', severity: 'issue',
        patterns: [/access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g],
        description: 'PayPal/Braintree production access token. Enables payment processing on the merchant account.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'pgp_private', name: 'PGP Private Key', severity: 'issue',
        patterns: [/-----BEGIN PGP PRIVATE KEY BLOCK-----/g],
        description: 'PGP private key block found in the app. Allows decrypting messages and forging signatures.', cwe: 'CWE-321', owasp: 'M9', masvs: 'CRYPTO-1'
    },
    {
        id: 'ssh_private', name: 'SSH/DSA Private Key', severity: 'issue',
        patterns: [/-----BEGIN DSA PRIVATE KEY-----/g, /-----BEGIN OPENSSH PRIVATE KEY-----/g],
        description: 'SSH private key embedded in the app. Allows authenticating to servers as the key owner.', cwe: 'CWE-321', owasp: 'M9', masvs: 'CRYPTO-1'
    },
    ,
    {
        id: 'apx_aws_s3_bucket', name: "aws_s3_bucket", severity: 'issue',
        patterns: [new RegExp("s3[_-]?bucket(=|=|:|:)", 'gi')],
        description: 'Detected sensitive pattern: aws_s3_bucket. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_s3_endpoint', name: "aws_s3_endpoint", severity: 'issue',
        patterns: [new RegExp("s3[_-]?endpoint(=|=|:|:)", 'gi')],
        description: 'Detected sensitive pattern: aws_s3_endpoint. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_s3_url', name: "aws_s3_url", severity: 'issue',
        patterns: [new RegExp("s3[_-]?url(=|=|:|:)", 'gi')],
        description: 'Detected sensitive pattern: aws_s3_url. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_s3_website', name: "aws_s3_website", severity: 'issue',
        patterns: [new RegExp("s3[_-]?website(=|=|:|:)", 'gi')],
        description: 'Detected sensitive pattern: aws_s3_website. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_mws_key', name: "aws_mws_key", severity: 'issue',
        patterns: [new RegExp("aws[_-]?mws[_-]?key(=|=|:|:)", 'gi')],
        description: 'Detected sensitive pattern: aws_mws_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_intercom_api_key', name: "Intercom API Key", severity: 'issue',
        patterns: [new RegExp("Intercom\\.initialize\\([\"|']?\\w+[\"|']?,\\s?[\"|']?\\w+[\"|']?,\\s?[\"|']?\\w+[\"|']?\\)", 'gi')],
        description: 'Detected sensitive pattern: Intercom API Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_singular_config', name: "Singular Config", severity: 'issue',
        patterns: [new RegExp("SingularConfig\\([\"|']?[\\w._]+[\"|']?,\\s?[\"|']?[\\w._]+[\"|']?\\)", 'gi')],
        description: 'Detected sensitive pattern: Singular Config. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_adjust_config', name: "Adjust Config", severity: 'issue',
        patterns: [new RegExp("(AdjustConfig\\([\"|']?[\\w]+[\"|']?,\\s?[\"|']?[\\w]+[\"|']?(?:,\\s?[\"|']?[\\w]+[\"|']?)?\\)|([aA]djust)?[C|c]onfig\\.setAppSecret\\(.*\\))", 'gi')],
        description: 'Detected sensitive pattern: Adjust Config. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bitmovin_api_key', name: "Bitmovin API Key", severity: 'issue',
        patterns: [new RegExp("BITMOVIN_API_KEY\\s?=\\s?['|\"]?.*['|\"]?", 'gi')],
        description: 'Detected sensitive pattern: Bitmovin API Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_default_api_key', name: "Default API Key", severity: 'issue',
        patterns: [new RegExp("DEFAULT_API_KEY\\s?=\\s?['|\"]?.*['|\"]?", 'gi')],
        description: 'Detected sensitive pattern: Default API Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_salesforce_marketingcloud_token', name: "Salesforce MarketingCloud Token", severity: 'issue',
        patterns: [new RegExp("setAccessToken\\(\\w+\\.MC_ACCESS_TOKEN\\)", 'gi')],
        description: 'Detected sensitive pattern: Salesforce MarketingCloud Token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_appdynamics_key', name: "AppDynamics Key", severity: 'issue',
        patterns: [new RegExp("AgentConfiguration\\.builder\\(\\)(\\s*)?([\\.\\w\\(\\)\\s]+)\\.withAppKey\\(.*?\\)", 'gi')],
        description: 'Detected sensitive pattern: AppDynamics Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_appcenter_secret', name: "AppCenter Secret", severity: 'issue',
        patterns: [new RegExp("AppCenter\\.(configure|start)\\(.*\\)", 'gi')],
        description: 'Detected sensitive pattern: AppCenter Secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sentry_dsn', name: "Sentry DSN", severity: 'issue',
        patterns: [new RegExp("https?://(\\\\w+)(:\\\\w+)?@sentry\\.io/[0-9]+", 'gi')],
        description: 'Detected sensitive pattern: Sentry DSN. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_authorization_basic', name: "Authorization Basic", severity: 'issue',
        patterns: [new RegExp("basic\\s[a-zA-Z0-9_\\-:\\.=]+", 'gi')],
        description: 'Detected sensitive pattern: Authorization Basic. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_authorization_bearer', name: "Authorization Bearer", severity: 'issue',
        patterns: [new RegExp("bearer\\s[a-zA-Z0-9_\\-:\\.=]+", 'gi')],
        description: 'Detected sensitive pattern: Authorization Bearer. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_basic_auth_credentials', name: "Basic Auth Credentials", severity: 'issue',
        patterns: [new RegExp("[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\\.[a-zA-Z]+", 'gi')],
        description: 'Detected sensitive pattern: Basic Auth Credentials. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloudinary_basic_auth', name: "Cloudinary Basic Auth", severity: 'issue',
        patterns: [new RegExp("cloudinary:\\/\\/[0-9]{15}:[0-9A-Za-z]+@[a-z]+", 'gi')],
        description: 'Detected sensitive pattern: Cloudinary Basic Auth. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_discord_bot_token', name: "Discord BOT Token", severity: 'issue',
        patterns: [new RegExp("((?:N|M|O)[a-zA-Z0-9]{23}\\.[a-zA-Z0-9-_]{6}\\.[a-zA-Z0-9-_]{27})$", 'gi')],
        description: 'Detected sensitive pattern: Discord BOT Token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_facebook_clientid', name: "Facebook ClientID", severity: 'issue',
        patterns: [new RegExp("[fF][aA][cC][eE][bB][oO][oO][kK](.{0,20})?[''\"][0-9]{13,17}", 'gi')],
        description: 'Detected sensitive pattern: Facebook ClientID. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_firebase', name: "Firebase", severity: 'issue',
        patterns: [new RegExp("[a-z0-9.-]+\\.firebaseio\\.com", 'gi')],
        description: 'Detected sensitive pattern: Firebase. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_api_key', name: "Generic API Key", severity: 'issue',
        patterns: [new RegExp("[aA][pP][iI][_]?[kK][eE][yY].*[''|\"][0-9a-zA-Z]{32,45}[''|\"]", 'gi')],
        description: 'Detected sensitive pattern: Generic API Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_secret', name: "Generic Secret", severity: 'issue',
        patterns: [new RegExp("[sS][eE][cC][rR][eE][tT].*[''|\"][0-9a-zA-Z]{32,45}[''|\"]", 'gi')],
        description: 'Detected sensitive pattern: Generic Secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github', name: "GitHub", severity: 'issue',
        patterns: [new RegExp("[gG][iI][tT][hH][uU][bB].*[''|\"][0-9a-zA-Z]{35,40}[''|\"]", 'gi')],
        description: 'Detected sensitive pattern: GitHub. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github_access_token', name: "GitHub Access Token", severity: 'issue',
        patterns: [new RegExp("([a-zA-Z0-9_-]*:[a-zA-Z0-9_-]+@github.com*)$", 'gi')],
        description: 'Detected sensitive pattern: GitHub Access Token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_google_cloud_platform_oauth', name: "Google Cloud Platform OAuth", severity: 'issue',
        patterns: [new RegExp("[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com", 'gi')],
        description: 'Detected sensitive pattern: Google Cloud Platform OAuth. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_heroku_api_key', name: "Heroku API Key", severity: 'issue',
        patterns: [new RegExp("[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", 'gi')],
        description: 'Detected sensitive pattern: Heroku API Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ip_address', name: "IP Address", severity: 'issue',
        patterns: [new RegExp("(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])", 'gi')],
        description: 'Detected sensitive pattern: IP Address. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_json_web_token', name: "JSON Web Token", severity: 'issue',
        patterns: [new RegExp("(eyJ[a-zA-Z0-9-]{10,}.eyJ[a-zA-Z0-9-]{10,}.[a-zA-Z0-9-]{10,})", 'gi')],
        description: 'Detected sensitive pattern: JSON Web Token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mac_address', name: "Mac Address", severity: 'issue',
        patterns: [new RegExp("(([0-9A-Fa-f]{2}[:]){5}[0-9A-Fa-f]{2}|([0-9A-Fa-f]{2}[-]){5}[0-9A-Fa-f]{2}|([0-9A-Fa-f]{4}[\\.]){2}[0-9A-Fa-f]{4})$", 'gi')],
        description: 'Detected sensitive pattern: Mac Address. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mailto', name: "Mailto", severity: 'issue',
        patterns: [new RegExp("mailto:[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9.-]+", 'gi')],
        description: 'Detected sensitive pattern: Mailto. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_arn', name: "AWS ARN", severity: 'issue',
        patterns: [new RegExp("arn:aws:[a-z0-9\\-]+:[a-z]{2}-[a-z]+-[0-9]+:[0-9]+:.+", 'gi')],
        description: 'Detected sensitive pattern: AWS ARN. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_access_key_id_value', name: "AWS Access Key ID Value", severity: 'issue',
        patterns: [new RegExp("(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", 'gi')],
        description: 'Detected sensitive pattern: AWS Access Key ID Value. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_secret_access_key_value', name: "AWS Secret Access Key Value", severity: 'issue',
        patterns: [new RegExp("aws_secret_access_key", 'gi')],
        description: 'Detected sensitive pattern: AWS Secret Access Key Value. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_urls', name: "URLs", severity: 'issue',
        patterns: [new RegExp("https?://[\\w\\.-]+(?:\\.[\\w\\.-]+)+[\\w\\-\\._~:/?#\\[\\]@!\\$&'\\(\\)\\*\\+,;=.]+", 'gi')],
        description: 'Detected sensitive pattern: URLs. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_api_gateway', name: "AWS API Gateway", severity: 'issue',
        patterns: [new RegExp("[0-9a-z]+.execute-api.[0-9a-z._-]+.amazonaws.com", 'gi')],
        description: 'Detected sensitive pattern: AWS API Gateway. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_api_key', name: "AWS API Key", severity: 'issue',
        patterns: [new RegExp("AKIA[0-9A-Z]{16}", 'gi')],
        description: 'Detected sensitive pattern: AWS API Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_appsync_graphql_key', name: "AWS AppSync GraphQL Key", severity: 'issue',
        patterns: [new RegExp("da2-[a-z0-9]{26}", 'gi')],
        description: 'Detected sensitive pattern: AWS AppSync GraphQL Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_ec2_external', name: "AWS EC2 External", severity: 'issue',
        patterns: [new RegExp("ec2-[0-9a-z._-]+.compute(-1)?.amazonaws.com", 'gi')],
        description: 'Detected sensitive pattern: AWS EC2 External. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_ec2_internal', name: "AWS EC2 Internal", severity: 'issue',
        patterns: [new RegExp("[0-9a-z._-]+.compute(-1)?.internal", 'gi')],
        description: 'Detected sensitive pattern: AWS EC2 Internal. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_elb', name: "AWS ELB", severity: 'issue',
        patterns: [new RegExp("[0-9a-z._-]+.elb.amazonaws.com", 'gi')],
        description: 'Detected sensitive pattern: AWS ELB. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_elasticcache', name: "AWS ElasticCache", severity: 'issue',
        patterns: [new RegExp("[0-9a-z._-]+.cache.amazonaws.com", 'gi')],
        description: 'Detected sensitive pattern: AWS ElasticCache. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_mws_id', name: "AWS MWS ID", severity: 'issue',
        patterns: [new RegExp("mzn\\\\.mws\\\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", 'gi')],
        description: 'Detected sensitive pattern: AWS MWS ID. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_rds', name: "AWS RDS", severity: 'issue',
        patterns: [new RegExp("[0-9a-z._-]+.rds.amazonaws.com", 'gi')],
        description: 'Detected sensitive pattern: AWS RDS. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_client_id', name: "AWS client ID", severity: 'issue',
        patterns: [new RegExp("(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", 'gi')],
        description: 'Detected sensitive pattern: AWS client ID. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_cred_file_info', name: "AWS cred file info", severity: 'issue',
        patterns: [new RegExp("(aws_access_key_id|aws_secret_access_key)", 'gi')],
        description: 'Detected sensitive pattern: AWS cred file info. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_abbysale', name: "Abbysale", severity: 'issue',
        patterns: [new RegExp("(?:abbysale).{0,40}\\b([a-z0-9A-Z]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Abbysale. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_abstract', name: "Abstract", severity: 'issue',
        patterns: [new RegExp("(?:abstract).{0,40}\\b([0-9a-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Abstract. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_abuseipdb', name: "Abuseipdb", severity: 'issue',
        patterns: [new RegExp("(?:abuseipdb).{0,40}\\b([a-z0-9]{80})\\b", 'gi')],
        description: 'Detected sensitive pattern: Abuseipdb. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_accuweather', name: "Accuweather", severity: 'issue',
        patterns: [new RegExp("(?:accuweather).{0,40}([a-z0-9A-Z\\%]{35})\\b", 'gi')],
        description: 'Detected sensitive pattern: Accuweather. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_adafruitio', name: "Adafruitio", severity: 'issue',
        patterns: [new RegExp("\\b(aio\\_[a-zA-Z0-9]{28})\\b", 'gi')],
        description: 'Detected sensitive pattern: Adafruitio. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_adobeio_1', name: "Adobeio - 1", severity: 'issue',
        patterns: [new RegExp("(?:adobe).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Adobeio - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_adzuna_1', name: "Adzuna - 1", severity: 'issue',
        patterns: [new RegExp("(?:adzuna).{0,40}\\b([a-z0-9]{8})\\b", 'gi')],
        description: 'Detected sensitive pattern: Adzuna - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_adzuna_2', name: "Adzuna - 2", severity: 'issue',
        patterns: [new RegExp("(?:adzuna).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Adzuna - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aeroworkflow_1', name: "Aeroworkflow - 1", severity: 'issue',
        patterns: [new RegExp("(?:aeroworkflow).{0,40}\\b([0-9]{1,})\\b", 'gi')],
        description: 'Detected sensitive pattern: Aeroworkflow - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aeroworkflow_2', name: "Aeroworkflow - 2", severity: 'issue',
        patterns: [new RegExp("(?:aeroworkflow).{0,40}\\b([a-zA-Z0-9^!]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Aeroworkflow - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_agora', name: "Agora", severity: 'issue',
        patterns: [new RegExp("(?:agora).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Agora. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_airbrakeprojectkey_1', name: "Airbrakeprojectkey - 1", severity: 'issue',
        patterns: [new RegExp("(?:airbrake).{0,40}\\b([0-9]{6})\\b", 'gi')],
        description: 'Detected sensitive pattern: Airbrakeprojectkey - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_airbrakeprojectkey_2', name: "Airbrakeprojectkey - 2", severity: 'issue',
        patterns: [new RegExp("(?:airbrake).{0,40}\\b([a-zA-Z-0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Airbrakeprojectkey - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_airbrakeuserkey', name: "Airbrakeuserkey", severity: 'issue',
        patterns: [new RegExp("(?:airbrake).{0,40}\\b([a-zA-Z-0-9]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Airbrakeuserkey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_airship', name: "Airship", severity: 'issue',
        patterns: [new RegExp("(?:airship).{0,40}\\b([0-9Aa-zA-Z]{91})\\b", 'gi')],
        description: 'Detected sensitive pattern: Airship. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_airvisual', name: "Airvisual", severity: 'issue',
        patterns: [new RegExp("(?:airvisual).{0,40}\\b([a-z0-9-]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Airvisual. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_alconost', name: "Alconost", severity: 'issue',
        patterns: [new RegExp("(?:alconost).{0,40}\\b([0-9Aa-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Alconost. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_alegra_1', name: "Alegra - 1", severity: 'issue',
        patterns: [new RegExp("(?:alegra).{0,40}\\b([a-z0-9-]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Alegra - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_alegra_2', name: "Alegra - 2", severity: 'issue',
        patterns: [new RegExp("(?:alegra).{0,40}\\b([a-zA-Z0-9.-@]{25,30})\\b", 'gi')],
        description: 'Detected sensitive pattern: Alegra - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aletheiaapi', name: "Aletheiaapi", severity: 'issue',
        patterns: [new RegExp("(?:aletheiaapi).{0,40}\\b([A-Z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Aletheiaapi. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_algoliaadminkey_1', name: "Algoliaadminkey - 1", severity: 'issue',
        patterns: [new RegExp("(?:algolia).{0,40}\\b([A-Z0-9]{10})\\b", 'gi')],
        description: 'Detected sensitive pattern: Algoliaadminkey - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_algoliaadminkey_2', name: "Algoliaadminkey - 2", severity: 'issue',
        patterns: [new RegExp("(?:algolia).{0,40}\\b([a-zA-Z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Algoliaadminkey - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_alibaba_2', name: "Alibaba - 2", severity: 'issue',
        patterns: [new RegExp("\\b(LTAI[a-zA-Z0-9]{17,21})[\\\"' ;\\s]*", 'gi')],
        description: 'Detected sensitive pattern: Alibaba - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_alienvault', name: "Alienvault", severity: 'issue',
        patterns: [new RegExp("(?:alienvault).{0,40}\\b([a-z0-9]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Alienvault. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_allsports', name: "Allsports", severity: 'issue',
        patterns: [new RegExp("(?:allsports).{0,40}\\b([0-9a-z]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Allsports. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_amadeus_1', name: "Amadeus - 1", severity: 'issue',
        patterns: [new RegExp("(?:amadeus).{0,40}\\b([0-9A-Za-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Amadeus - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_amadeus_2', name: "Amadeus - 2", severity: 'issue',
        patterns: [new RegExp("(?:amadeus).{0,40}\\b([0-9A-Za-z]{16})\\b", 'gi')],
        description: 'Detected sensitive pattern: Amadeus - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_amazon_sns_topic', name: "Amazon SNS Topic", severity: 'issue',
        patterns: [new RegExp("arn:aws:sns:[a-z0-9\\-]+:[0-9]+:[A-Za-z0-9\\-_]+", 'gi')],
        description: 'Detected sensitive pattern: Amazon SNS Topic. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ambee', name: "Ambee", severity: 'issue',
        patterns: [new RegExp("(?:ambee).{0,40}\\b([0-9a-f]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Ambee. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_amplitudeapikey', name: "Amplitudeapikey", severity: 'issue',
        patterns: [new RegExp("(?:amplitude).{0,40}\\b([a-f0-9]{32})", 'gi')],
        description: 'Detected sensitive pattern: Amplitudeapikey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_apacta', name: "Apacta", severity: 'issue',
        patterns: [new RegExp("(?:apacta).{0,40}\\b([a-z0-9-]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Apacta. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_api2cart', name: "Api2cart", severity: 'issue',
        patterns: [new RegExp("(?:api2cart).{0,40}\\b([0-9a-f]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Api2cart. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_apideck_1', name: "Apideck - 1", severity: 'issue',
        patterns: [new RegExp("\\b(sk_live_[a-z0-9A-Z-]{93})\\b", 'gi')],
        description: 'Detected sensitive pattern: Apideck - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_apideck_2', name: "Apideck - 2", severity: 'issue',
        patterns: [new RegExp("(?:apideck).{0,40}\\b([a-z0-9A-Z]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Apideck - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_apiflash_1', name: "Apiflash - 1", severity: 'issue',
        patterns: [new RegExp("(?:apiflash).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Apiflash - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_apiflash_2', name: "Apiflash - 2", severity: 'issue',
        patterns: [new RegExp("(?:apiflash).{0,40}\\b([a-zA-Z0-9\\S]{21,30})\\b", 'gi')],
        description: 'Detected sensitive pattern: Apiflash - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_apifonica', name: "Apifonica", severity: 'issue',
        patterns: [new RegExp("(?:apifonica).{0,40}\\b([0-9a-z]{11}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Apifonica. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_apify', name: "Apify", severity: 'issue',
        patterns: [new RegExp("\\b(apify\\_api\\_[a-zA-Z-0-9]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Apify. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_apimatic_1', name: "Apimatic - 1", severity: 'issue',
        patterns: [new RegExp("(?:apimatic).{0,40}\\b([a-z0-9-\\S]{8,32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Apimatic - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_apimatic_2', name: "Apimatic - 2", severity: 'issue',
        patterns: [new RegExp("(?:apimatic).{0,40}\\b([a-zA-Z0-9]{3,20}@[a-zA-Z0-9]{2,12}.[a-zA-Z0-9]{2,5})\\b", 'gi')],
        description: 'Detected sensitive pattern: Apimatic - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_apiscience', name: "Apiscience", severity: 'issue',
        patterns: [new RegExp("(?:apiscience).{0,40}\\b([a-bA-Z0-9\\S]{22})\\b", 'gi')],
        description: 'Detected sensitive pattern: Apiscience. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_apollo', name: "Apollo", severity: 'issue',
        patterns: [new RegExp("(?:apollo).{0,40}\\b([a-zA-Z0-9]{22})\\b", 'gi')],
        description: 'Detected sensitive pattern: Apollo. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_appcues_1', name: "Appcues - 1", severity: 'issue',
        patterns: [new RegExp("(?:appcues).{0,40}\\b([0-9]{5})\\b", 'gi')],
        description: 'Detected sensitive pattern: Appcues - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_appcues_2', name: "Appcues - 2", severity: 'issue',
        patterns: [new RegExp("(?:appcues).{0,40}\\b([a-z0-9-]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Appcues - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_appcues_3', name: "Appcues - 3", severity: 'issue',
        patterns: [new RegExp("(?:appcues).{0,40}\\b([a-z0-9-]{39})\\b", 'gi')],
        description: 'Detected sensitive pattern: Appcues - 3. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_appfollow', name: "Appfollow", severity: 'issue',
        patterns: [new RegExp("(?:appfollow).{0,40}\\b([0-9A-Za-z]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Appfollow. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_appsynergy', name: "Appsynergy", severity: 'issue',
        patterns: [new RegExp("(?:appsynergy).{0,40}\\b([a-z0-9]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Appsynergy. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_apptivo_1', name: "Apptivo - 1", severity: 'issue',
        patterns: [new RegExp("(?:apptivo).{0,40}\\b([a-z0-9-]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Apptivo - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_apptivo_2', name: "Apptivo - 2", severity: 'issue',
        patterns: [new RegExp("(?:apptivo).{0,40}\\b([a-zA-Z0-9-]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Apptivo - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_artifactory_2', name: "Artifactory - 2", severity: 'issue',
        patterns: [new RegExp("\\b([A-Za-z0-9](?:[A-Za-z0-9\\-]{0,61}[A-Za-z0-9])\\.jfrog\\.io)", 'gi')],
        description: 'Detected sensitive pattern: Artifactory - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_artifactory_api_token', name: "Artifactory API Token", severity: 'issue',
        patterns: [new RegExp("(?:\\s|=|:|\"|^)AKC[a-zA-Z0-9]{10,}", 'gi')],
        description: 'Detected sensitive pattern: Artifactory API Token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_artifactory_password', name: "Artifactory Password", severity: 'issue',
        patterns: [new RegExp("(?:\\s|=|:|\"|^)AP[\\dABCDEF][a-zA-Z0-9]{8,}", 'gi')],
        description: 'Detected sensitive pattern: Artifactory Password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_artsy_1', name: "Artsy - 1", severity: 'issue',
        patterns: [new RegExp("(?:artsy).{0,40}\\b([0-9a-zA-Z]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Artsy - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_artsy_2', name: "Artsy - 2", severity: 'issue',
        patterns: [new RegExp("(?:artsy).{0,40}\\b([0-9a-zA-Z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Artsy - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_asanaoauth', name: "Asanaoauth", severity: 'issue',
        patterns: [new RegExp("(?:asana).{0,40}\\b([a-z\\/:0-9]{51})\\b", 'gi')],
        description: 'Detected sensitive pattern: Asanaoauth. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_asanapersonalaccesstoken', name: "Asanapersonalaccesstoken", severity: 'issue',
        patterns: [new RegExp("(?:asana).{0,40}\\b([0-9]{1,}\\/[0-9]{16,}:[A-Za-z0-9]{32,})\\b", 'gi')],
        description: 'Detected sensitive pattern: Asanapersonalaccesstoken. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_assemblyai', name: "Assemblyai", severity: 'issue',
        patterns: [new RegExp("(?:assemblyai).{0,40}\\b([0-9a-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Assemblyai. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_asymmetric_private_key', name: "Asymmetric Private Key", severity: 'issue',
        patterns: [new RegExp("-----BEGIN ((EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY( BLOCK)?-----", 'gi')],
        description: 'Detected sensitive pattern: Asymmetric Private Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_audd', name: "Audd", severity: 'issue',
        patterns: [new RegExp("(?:audd).{0,40}\\b([a-z0-9-]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Audd. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_auth0managementapitoken', name: "Auth0managementapitoken", severity: 'issue',
        patterns: [new RegExp("(?:auth0).{0,40}\\b(ey[a-zA-Z0-9._-]+)\\b", 'gi')],
        description: 'Detected sensitive pattern: Auth0managementapitoken. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_auth0oauth_1', name: "Auth0oauth - 1", severity: 'issue',
        patterns: [new RegExp("(?:auth0).{0,40}\\b([a-zA-Z0-9_-]{32,60})\\b", 'gi')],
        description: 'Detected sensitive pattern: Auth0oauth - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_autodesk_1', name: "Autodesk - 1", severity: 'issue',
        patterns: [new RegExp("(?:autodesk).{0,40}\\b([0-9A-Za-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Autodesk - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_autodesk_2', name: "Autodesk - 2", severity: 'issue',
        patterns: [new RegExp("(?:autodesk).{0,40}\\b([0-9A-Za-z]{16})\\b", 'gi')],
        description: 'Detected sensitive pattern: Autodesk - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_autoklose', name: "Autoklose", severity: 'issue',
        patterns: [new RegExp("(?:autoklose).{0,40}\\b([a-zA-Z0-9-]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Autoklose. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_autopilot', name: "Autopilot", severity: 'issue',
        patterns: [new RegExp("(?:autopilot).{0,40}\\b([0-9a-f]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Autopilot. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_avazapersonalaccesstoken', name: "Avazapersonalaccesstoken", severity: 'issue',
        patterns: [new RegExp("(?:avaza).{0,40}\\b([0-9]+-[0-9a-f]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Avazapersonalaccesstoken. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aviationstack', name: "Aviationstack", severity: 'issue',
        patterns: [new RegExp("(?:aviationstack).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Aviationstack. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_1', name: "Aws - 1", severity: 'issue',
        patterns: [new RegExp("\\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\\b", 'gi')],
        description: 'Detected sensitive pattern: Aws - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_axonaut', name: "Axonaut", severity: 'issue',
        patterns: [new RegExp("(?:axonaut).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Axonaut. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aylien_1', name: "Aylien - 1", severity: 'issue',
        patterns: [new RegExp("(?:aylien).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Aylien - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aylien_2', name: "Aylien - 2", severity: 'issue',
        patterns: [new RegExp("(?:aylien).{0,40}\\b([a-z0-9]{8})\\b", 'gi')],
        description: 'Detected sensitive pattern: Aylien - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ayrshare', name: "Ayrshare", severity: 'issue',
        patterns: [new RegExp("(?:ayrshare).{0,40}\\b([A-Z]{7}-[A-Z0-9]{7}-[A-Z0-9]{7}-[A-Z0-9]{7})\\b", 'gi')],
        description: 'Detected sensitive pattern: Ayrshare. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bannerbear', name: "Bannerbear", severity: 'issue',
        patterns: [new RegExp("(?:bannerbear).{0,40}\\b([0-9a-zA-Z]{22}tt)\\b", 'gi')],
        description: 'Detected sensitive pattern: Bannerbear. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_baremetrics', name: "Baremetrics", severity: 'issue',
        patterns: [new RegExp("(?:baremetrics).{0,40}\\b([a-zA-Z0-9_]{25})\\b", 'gi')],
        description: 'Detected sensitive pattern: Baremetrics. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_baseapiio', name: "Baseapiio", severity: 'issue',
        patterns: [new RegExp("(?:baseapi|base-api).{0,40}\\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Baseapiio. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_beamer', name: "Beamer", severity: 'issue',
        patterns: [new RegExp("(?:beamer).{0,40}\\b([a-zA-Z0-9_+/]{45}=)", 'gi')],
        description: 'Detected sensitive pattern: Beamer. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bearer_token', name: "Bearer token", severity: 'issue',
        patterns: [new RegExp("(bearer).+", 'gi')],
        description: 'Detected sensitive pattern: Bearer token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_beebole', name: "Beebole", severity: 'issue',
        patterns: [new RegExp("(?:beebole).{0,40}\\b([0-9a-z]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Beebole. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_besttime', name: "Besttime", severity: 'issue',
        patterns: [new RegExp("(?:besttime).{0,40}\\b([0-9A-Za-z_]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Besttime. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_billomat_1', name: "Billomat - 1", severity: 'issue',
        patterns: [new RegExp("(?:billomat).{0,40}\\b([0-9a-z]{1,})\\b", 'gi')],
        description: 'Detected sensitive pattern: Billomat - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_billomat_2', name: "Billomat - 2", severity: 'issue',
        patterns: [new RegExp("(?:billomat).{0,40}\\b([0-9a-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Billomat - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bitbar', name: "Bitbar", severity: 'issue',
        patterns: [new RegExp("(?:bitbar).{0,40}\\b([0-9a-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Bitbar. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bitcoinaverage', name: "Bitcoinaverage", severity: 'issue',
        patterns: [new RegExp("(?:bitcoinaverage).{0,40}\\b([a-zA-Z0-9]{43})\\b", 'gi')],
        description: 'Detected sensitive pattern: Bitcoinaverage. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bitfinex', name: "Bitfinex", severity: 'issue',
        patterns: [new RegExp("(?:bitfinex).{0,40}\\b([A-Za-z0-9_-]{43})\\b", 'gi')],
        description: 'Detected sensitive pattern: Bitfinex. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bitly_secret_key', name: "Bitly Secret Key", severity: 'issue',
        patterns: [new RegExp("R_[0-9a-f]{32}", 'gi')],
        description: 'Detected sensitive pattern: Bitly Secret Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bitlyaccesstoken', name: "Bitlyaccesstoken", severity: 'issue',
        patterns: [new RegExp("(?:bitly).{0,40}\\b([a-zA-Z-0-9]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Bitlyaccesstoken. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bitmex_1', name: "Bitmex - 1", severity: 'issue',
        patterns: [new RegExp("(?:bitmex).{0,40}([ \\r\\n]{1}[0-9a-zA-Z\\-\\_]{24}[ \\r\\n]{1})", 'gi')],
        description: 'Detected sensitive pattern: Bitmex - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bitmex_2', name: "Bitmex - 2", severity: 'issue',
        patterns: [new RegExp("(?:bitmex).{0,40}([ \\r\\n]{1}[0-9a-zA-Z\\-\\_]{48}[ \\r\\n]{1})", 'gi')],
        description: 'Detected sensitive pattern: Bitmex - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_blablabus', name: "Blablabus", severity: 'issue',
        patterns: [new RegExp("(?:blablabus).{0,40}\\b([0-9A-Za-z]{22})\\b", 'gi')],
        description: 'Detected sensitive pattern: Blablabus. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_blazemeter', name: "Blazemeter", severity: 'issue',
        patterns: [new RegExp("(?:blazemeter|runscope).{0,40}\\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Blazemeter. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_blitapp', name: "Blitapp", severity: 'issue',
        patterns: [new RegExp("(?:blitapp).{0,40}\\b([a-zA-Z0-9_-]{39})\\b", 'gi')],
        description: 'Detected sensitive pattern: Blitapp. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_blogger', name: "Blogger", severity: 'issue',
        patterns: [new RegExp("(?:blogger).{0,40}\\b([0-9A-Za-z-]{39})\\b", 'gi')],
        description: 'Detected sensitive pattern: Blogger. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bombbomb', name: "Bombbomb", severity: 'issue',
        patterns: [new RegExp("(?:bombbomb).{0,40}\\b([a-zA-Z0-9-._]{704})\\b", 'gi')],
        description: 'Detected sensitive pattern: Bombbomb. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_boostnote', name: "Boostnote", severity: 'issue',
        patterns: [new RegExp("(?:boostnote).{0,40}\\b([0-9a-f]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Boostnote. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_borgbase', name: "Borgbase", severity: 'issue',
        patterns: [new RegExp("(?:borgbase).{0,40}\\b([a-zA-Z0-9/_.-]{148,152})\\b", 'gi')],
        description: 'Detected sensitive pattern: Borgbase. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_braintree_api_key', name: "Braintree API Key", severity: 'issue',
        patterns: [new RegExp("access_token$production$[0-9a-z]{16}$[0-9a-f]{32}", 'gi')],
        description: 'Detected sensitive pattern: Braintree API Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_brandfetch', name: "Brandfetch", severity: 'issue',
        patterns: [new RegExp("(?:brandfetch).{0,40}\\b([0-9A-Za-z]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Brandfetch. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_browshot', name: "Browshot", severity: 'issue',
        patterns: [new RegExp("(?:browshot).{0,40}\\b([a-zA-Z-0-9]{28})\\b", 'gi')],
        description: 'Detected sensitive pattern: Browshot. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_buddyns', name: "Buddyns", severity: 'issue',
        patterns: [new RegExp("(?:buddyns).{0,40}\\b([0-9a-z]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Buddyns. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bugherd', name: "Bugherd", severity: 'issue',
        patterns: [new RegExp("(?:bugherd).{0,40}\\b([0-9a-z]{22})\\b", 'gi')],
        description: 'Detected sensitive pattern: Bugherd. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bugsnag', name: "Bugsnag", severity: 'issue',
        patterns: [new RegExp("(?:bugsnag).{0,40}\\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Bugsnag. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_buildkite', name: "Buildkite", severity: 'issue',
        patterns: [new RegExp("(?:buildkite).{0,40}\\b([a-z0-9]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Buildkite. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bulbul', name: "Bulbul", severity: 'issue',
        patterns: [new RegExp("(?:bulbul).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Bulbul. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_buttercms', name: "Buttercms", severity: 'issue',
        patterns: [new RegExp("(?:buttercms).{0,40}\\b([a-z0-9]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Buttercms. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_caflou', name: "Caflou", severity: 'issue',
        patterns: [new RegExp("(?:caflou).{0,40}\\b([a-bA-Z0-9\\S]{155})\\b", 'gi')],
        description: 'Detected sensitive pattern: Caflou. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_calendarific', name: "Calendarific", severity: 'issue',
        patterns: [new RegExp("(?:calendarific).{0,40}\\b([a-z0-9]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Calendarific. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_calendlyapikey', name: "Calendlyapikey", severity: 'issue',
        patterns: [new RegExp("(?:calendly).{0,40}\\b([a-zA-Z-0-9]{20}.[a-zA-Z-0-9]{171}.[a-zA-Z-0-9_]{43})\\b", 'gi')],
        description: 'Detected sensitive pattern: Calendlyapikey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_calorieninja', name: "Calorieninja", severity: 'issue',
        patterns: [new RegExp("(?:calorieninja).{0,40}\\b([0-9A-Za-z]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Calorieninja. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_campayn', name: "Campayn", severity: 'issue',
        patterns: [new RegExp("(?:campayn).{0,40}\\b([a-z0-9]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Campayn. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cannyio', name: "Cannyio", severity: 'issue',
        patterns: [new RegExp("(?:canny).{0,40}\\b([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[0-9]{4}-[a-z0-9]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Cannyio. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_capsulecrm', name: "Capsulecrm", severity: 'issue',
        patterns: [new RegExp("(?:capsulecrm).{0,40}\\b([a-zA-Z0-9-._+=]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Capsulecrm. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_captaindata_1', name: "Captaindata - 1", severity: 'issue',
        patterns: [new RegExp("(?:captaindata).{0,40}\\b([0-9a-f]{8}\\-[0-9a-f]{4}\\-[0-9a-f]{4}\\-[0-9a-f]{4}\\-[0-9a-f]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Captaindata - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_captaindata_2', name: "Captaindata - 2", severity: 'issue',
        patterns: [new RegExp("(?:captaindata).{0,40}\\b([0-9a-f]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Captaindata - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_carboninterface', name: "Carboninterface", severity: 'issue',
        patterns: [new RegExp("(?:carboninterface).{0,40}\\b([a-zA-Z0-9]{21})\\b", 'gi')],
        description: 'Detected sensitive pattern: Carboninterface. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cashboard_1', name: "Cashboard - 1", severity: 'issue',
        patterns: [new RegExp("(?:cashboard).{0,40}\\b([0-9A-Z]{3}-[0-9A-Z]{3}-[0-9A-Z]{3}-[0-9A-Z]{3})\\b", 'gi')],
        description: 'Detected sensitive pattern: Cashboard - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cashboard_2', name: "Cashboard - 2", severity: 'issue',
        patterns: [new RegExp("(?:cashboard).{0,40}\\b([0-9a-z]{1,})\\b", 'gi')],
        description: 'Detected sensitive pattern: Cashboard - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_caspio_1', name: "Caspio - 1", severity: 'issue',
        patterns: [new RegExp("(?:caspio).{0,40}\\b([a-z0-9]{8})\\b", 'gi')],
        description: 'Detected sensitive pattern: Caspio - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_caspio_2', name: "Caspio - 2", severity: 'issue',
        patterns: [new RegExp("(?:caspio).{0,40}\\b([a-z0-9]{50})\\b", 'gi')],
        description: 'Detected sensitive pattern: Caspio - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_censys_1', name: "Censys - 1", severity: 'issue',
        patterns: [new RegExp("(?:censys).{0,40}\\b([a-zA-Z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Censys - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_censys_2', name: "Censys - 2", severity: 'issue',
        patterns: [new RegExp("(?:censys).{0,40}\\b([a-z0-9-]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Censys - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_centralstationcrm', name: "Centralstationcrm", severity: 'issue',
        patterns: [new RegExp("(?:centralstation).{0,40}\\b([a-z0-9]{30})\\b", 'gi')],
        description: 'Detected sensitive pattern: Centralstationcrm. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cexio_1', name: "Cexio - 1", severity: 'issue',
        patterns: [new RegExp("(?:cexio|cex.io).{0,40}\\b([a-z]{2}[0-9]{9})\\b", 'gi')],
        description: 'Detected sensitive pattern: Cexio - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cexio_2', name: "Cexio - 2", severity: 'issue',
        patterns: [new RegExp("(?:cexio|cex.io).{0,40}\\b([0-9A-Za-z]{24,27})\\b", 'gi')],
        description: 'Detected sensitive pattern: Cexio - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_chatbot', name: "Chatbot", severity: 'issue',
        patterns: [new RegExp("(?:chatbot).{0,40}\\b([a-zA-Z0-9_]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Chatbot. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_chatfule', name: "Chatfule", severity: 'issue',
        patterns: [new RegExp("(?:chatfuel).{0,40}\\b([a-zA-Z0-9]{128})\\b", 'gi')],
        description: 'Detected sensitive pattern: Chatfule. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_checio', name: "Checio", severity: 'issue',
        patterns: [new RegExp("(?:checio).{0,40}\\b(pk_[a-z0-9]{45})\\b", 'gi')],
        description: 'Detected sensitive pattern: Checio. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_checklyhq', name: "Checklyhq", severity: 'issue',
        patterns: [new RegExp("(?:checklyhq).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Checklyhq. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_checkout_1', name: "Checkout - 1", severity: 'issue',
        patterns: [new RegExp("(?:checkout).{0,40}\\b((sk_|sk_test_)[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Checkout - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_checkout_2', name: "Checkout - 2", severity: 'issue',
        patterns: [new RegExp("(?:checkout).{0,40}\\b(cus_[0-9a-zA-Z]{26})\\b", 'gi')],
        description: 'Detected sensitive pattern: Checkout - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_checkvist_1', name: "Checkvist - 1", severity: 'issue',
        patterns: [new RegExp("(?:checkvist).{0,40}\\b([\\w\\.-]+@[\\w-]+\\.[\\w\\.-]{2,5})\\b", 'gi')],
        description: 'Detected sensitive pattern: Checkvist - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_checkvist_2', name: "Checkvist - 2", severity: 'issue',
        patterns: [new RegExp("(?:checkvist).{0,40}\\b([0-9a-zA-Z]{14})\\b", 'gi')],
        description: 'Detected sensitive pattern: Checkvist - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cicero', name: "Cicero", severity: 'issue',
        patterns: [new RegExp("(?:cicero).{0,40}\\b([0-9a-z]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Cicero. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_circleci', name: "Circleci", severity: 'issue',
        patterns: [new RegExp("(?:circle).{0,40}([a-fA-F0-9]{40})", 'gi')],
        description: 'Detected sensitive pattern: Circleci. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_clearbit', name: "Clearbit", severity: 'issue',
        patterns: [new RegExp("(?:clearbit).{0,40}\\b([0-9a-z_]{35})\\b", 'gi')],
        description: 'Detected sensitive pattern: Clearbit. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_clickhelp_1', name: "Clickhelp - 1", severity: 'issue',
        patterns: [new RegExp("\\b([0-9A-Za-z]{3,20}.try.clickhelp.co)\\b", 'gi')],
        description: 'Detected sensitive pattern: Clickhelp - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_clickhelp_2', name: "Clickhelp - 2", severity: 'issue',
        patterns: [new RegExp("(?:clickhelp).{0,40}\\b([0-9A-Za-z]{24})\\b", 'gi')],
        description: 'Detected sensitive pattern: Clickhelp - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_clicksendsms_2', name: "Clicksendsms - 2", severity: 'issue',
        patterns: [new RegExp("(?:sms).{0,40}\\b([a-zA-Z0-9]{3,20}@[a-zA-Z0-9]{2,12}.[a-zA-Z0-9]{2,5})\\b", 'gi')],
        description: 'Detected sensitive pattern: Clicksendsms - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_clickuppersonaltoken', name: "Clickuppersonaltoken", severity: 'issue',
        patterns: [new RegExp("(?:clickup).{0,40}\\b(pk_[0-9]{8}_[0-9A-Z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Clickuppersonaltoken. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cliengo', name: "Cliengo", severity: 'issue',
        patterns: [new RegExp("(?:cliengo).{0,40}\\b([0-9a-f]{8}\\-[0-9a-f]{4}\\-[0-9a-f]{4}\\-[0-9a-f]{4}\\-[0-9a-f]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Cliengo. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_clinchpad', name: "Clinchpad", severity: 'issue',
        patterns: [new RegExp("(?:clinchpad).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Clinchpad. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_clockify', name: "Clockify", severity: 'issue',
        patterns: [new RegExp("(?:clockify).{0,40}\\b([a-zA-Z0-9]{48})\\b", 'gi')],
        description: 'Detected sensitive pattern: Clockify. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_clockworksms_1', name: "Clockworksms - 1", severity: 'issue',
        patterns: [new RegExp("(?:clockwork|textanywhere).{0,40}\\b([0-9a-zA-Z]{24})\\b", 'gi')],
        description: 'Detected sensitive pattern: Clockworksms - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_clockworksms_2', name: "Clockworksms - 2", severity: 'issue',
        patterns: [new RegExp("(?:clockwork|textanywhere).{0,40}\\b([0-9]{5})\\b", 'gi')],
        description: 'Detected sensitive pattern: Clockworksms - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_closecrm', name: "Closecrm", severity: 'issue',
        patterns: [new RegExp("\\b(api_[a-z0-9A-Z.]{45})\\b", 'gi')],
        description: 'Detected sensitive pattern: Closecrm. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloudelements_1', name: "Cloudelements - 1", severity: 'issue',
        patterns: [new RegExp("(?:cloudelements).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Cloudelements - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloudelements_2', name: "Cloudelements - 2", severity: 'issue',
        patterns: [new RegExp("(?:cloudelements).{0,40}\\b([a-zA-Z0-9]{43})\\b", 'gi')],
        description: 'Detected sensitive pattern: Cloudelements - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloudflareapitoken', name: "Cloudflareapitoken", severity: 'issue',
        patterns: [new RegExp("(?:cloudflare).{0,40}\\b([A-Za-z0-9_-]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Cloudflareapitoken. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloudflarecakey', name: "Cloudflarecakey", severity: 'issue',
        patterns: [new RegExp("(?:cloudflare).{0,40}\\b(v[A-Za-z0-9._-]{173,})\\b", 'gi')],
        description: 'Detected sensitive pattern: Cloudflarecakey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloudimage', name: "Cloudimage", severity: 'issue',
        patterns: [new RegExp("(?:cloudimage).{0,40}\\b([a-z0-9_]{30})\\b", 'gi')],
        description: 'Detected sensitive pattern: Cloudimage. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloudinary_credentials', name: "Cloudinary Credentials", severity: 'issue',
        patterns: [new RegExp("cloudinary://[0-9]+:[A-Za-z0-9\\-_\\.]+@[A-Za-z0-9\\-_\\.]+", 'gi')],
        description: 'Detected sensitive pattern: Cloudinary Credentials. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloudmersive', name: "Cloudmersive", severity: 'issue',
        patterns: [new RegExp("(?:cloudmersive).{0,40}\\b([a-z0-9-]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Cloudmersive. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloudplan', name: "Cloudplan", severity: 'issue',
        patterns: [new RegExp("(?:cloudplan).{0,40}\\b([A-Z0-9-]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Cloudplan. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloverly', name: "Cloverly", severity: 'issue',
        patterns: [new RegExp("(?:cloverly).{0,40}\\b([a-z0-9:_]{28})\\b", 'gi')],
        description: 'Detected sensitive pattern: Cloverly. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloze_1', name: "Cloze - 1", severity: 'issue',
        patterns: [new RegExp("(?:cloze).{0,40}\\b([0-9a-f]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Cloze - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloze_2', name: "Cloze - 2", severity: 'issue',
        patterns: [new RegExp("(?:cloze).{0,40}\\b([\\w\\.-]+@[\\w-]+\\.[\\w\\.-]{2,5})\\b", 'gi')],
        description: 'Detected sensitive pattern: Cloze - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_clustdoc', name: "Clustdoc", severity: 'issue',
        patterns: [new RegExp("(?:clustdoc).{0,40}\\b([0-9a-zA-Z]{60})\\b", 'gi')],
        description: 'Detected sensitive pattern: Clustdoc. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_codacy', name: "Codacy", severity: 'issue',
        patterns: [new RegExp("(?:codacy).{0,40}\\b([0-9A-Za-z]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Codacy. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_coinapi', name: "Coinapi", severity: 'issue',
        patterns: [new RegExp("(?:coinapi).{0,40}\\b([A-Z0-9-]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Coinapi. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_coinbase', name: "Coinbase", severity: 'issue',
        patterns: [new RegExp("(?:coinbase).{0,40}\\b([a-zA-Z-0-9]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Coinbase. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_coinlayer', name: "Coinlayer", severity: 'issue',
        patterns: [new RegExp("(?:coinlayer).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Coinlayer. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_coinlib', name: "Coinlib", severity: 'issue',
        patterns: [new RegExp("(?:coinlib).{0,40}\\b([a-z0-9]{16})\\b", 'gi')],
        description: 'Detected sensitive pattern: Coinlib. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_column', name: "Column", severity: 'issue',
        patterns: [new RegExp("(?:column).{0,40}\\b((?:test|live)_[a-zA-Z0-9]{27})\\b", 'gi')],
        description: 'Detected sensitive pattern: Column. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_commercejs', name: "Commercejs", severity: 'issue',
        patterns: [new RegExp("(?:commercejs).{0,40}\\b([a-z0-9_]{48})\\b", 'gi')],
        description: 'Detected sensitive pattern: Commercejs. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_commodities', name: "Commodities", severity: 'issue',
        patterns: [new RegExp("(?:commodities).{0,40}\\b([a-zA-Z0-9]{60})\\b", 'gi')],
        description: 'Detected sensitive pattern: Commodities. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_companyhub_1', name: "Companyhub - 1", severity: 'issue',
        patterns: [new RegExp("(?:companyhub).{0,40}\\b([0-9a-zA-Z]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Companyhub - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_companyhub_2', name: "Companyhub - 2", severity: 'issue',
        patterns: [new RegExp("(?:companyhub).{0,40}\\b([a-zA-Z0-9$%^=-]{4,32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Companyhub - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_confluent_1', name: "Confluent - 1", severity: 'issue',
        patterns: [new RegExp("(?:confluent).{0,40}\\b([a-zA-Z-0-9]{16})\\b", 'gi')],
        description: 'Detected sensitive pattern: Confluent - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_confluent_2', name: "Confluent - 2", severity: 'issue',
        patterns: [new RegExp("(?:confluent).{0,40}\\b([a-zA-Z-0-9]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Confluent - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_convertkit', name: "Convertkit", severity: 'issue',
        patterns: [new RegExp("(?:convertkit).{0,40}\\b([a-z0-9A-Z_]{22})\\b", 'gi')],
        description: 'Detected sensitive pattern: Convertkit. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_convier', name: "Convier", severity: 'issue',
        patterns: [new RegExp("(?:convier).{0,40}\\b([0-9]{2}\\|[a-zA-Z0-9]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Convier. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_copper_2', name: "Copper - 2", severity: 'issue',
        patterns: [new RegExp("(?:copper).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Copper - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_countrylayer', name: "Countrylayer", severity: 'issue',
        patterns: [new RegExp("(?:countrylayer).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Countrylayer. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_courier', name: "Courier", severity: 'issue',
        patterns: [new RegExp("(?:courier).{0,40}\\b(pk\\_[a-zA-Z0-9]{1,}\\_[a-zA-Z0-9]{28})\\b", 'gi')],
        description: 'Detected sensitive pattern: Courier. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_coveralls', name: "Coveralls", severity: 'issue',
        patterns: [new RegExp("(?:coveralls).{0,40}\\b([a-zA-Z0-9-]{37})\\b", 'gi')],
        description: 'Detected sensitive pattern: Coveralls. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_crowdin', name: "Crowdin", severity: 'issue',
        patterns: [new RegExp("(?:crowdin).{0,40}\\b([0-9A-Za-z]{80})\\b", 'gi')],
        description: 'Detected sensitive pattern: Crowdin. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cryptocompare', name: "Cryptocompare", severity: 'issue',
        patterns: [new RegExp("(?:cryptocompare).{0,40}\\b([a-z-0-9]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Cryptocompare. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_currencycloud_1', name: "Currencycloud - 1", severity: 'issue',
        patterns: [new RegExp("(?:currencycloud).{0,40}\\b([0-9a-z]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Currencycloud - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_currencyfreaks', name: "Currencyfreaks", severity: 'issue',
        patterns: [new RegExp("(?:currencyfreaks).{0,40}\\b([0-9a-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Currencyfreaks. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_currencylayer', name: "Currencylayer", severity: 'issue',
        patterns: [new RegExp("(?:currencylayer).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Currencylayer. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_currencyscoop', name: "Currencyscoop", severity: 'issue',
        patterns: [new RegExp("(?:currencyscoop).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Currencyscoop. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_currentsapi', name: "Currentsapi", severity: 'issue',
        patterns: [new RegExp("(?:currentsapi).{0,40}\\b([a-zA-Z0-9\\S]{48})\\b", 'gi')],
        description: 'Detected sensitive pattern: Currentsapi. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_customerguru_1', name: "Customerguru - 1", severity: 'issue',
        patterns: [new RegExp("(?:guru).{0,40}\\b([a-z0-9A-Z]{50})\\b", 'gi')],
        description: 'Detected sensitive pattern: Customerguru - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_customerguru_2', name: "Customerguru - 2", severity: 'issue',
        patterns: [new RegExp("(?:guru).{0,40}\\b([a-z0-9A-Z]{30})\\b", 'gi')],
        description: 'Detected sensitive pattern: Customerguru - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_customerio', name: "Customerio", severity: 'issue',
        patterns: [new RegExp("(?:customer).{0,40}\\b([a-z0-9A-Z]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Customerio. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_d7network', name: "D7network", severity: 'issue',
        patterns: [new RegExp("(?:d7network).{0,40}\\b([a-zA-Z0-9\\W\\S]{23}\\=)", 'gi')],
        description: 'Detected sensitive pattern: D7network. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_dailyco', name: "Dailyco", severity: 'issue',
        patterns: [new RegExp("(?:daily).{0,40}\\b([0-9a-f]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Dailyco. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_dandelion', name: "Dandelion", severity: 'issue',
        patterns: [new RegExp("(?:dandelion).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Dandelion. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_databricks', name: "Databricks", severity: 'issue',
        patterns: [new RegExp("dapi[a-f0-9]{32}\\b", 'gi')],
        description: 'Detected sensitive pattern: Databricks. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_datadogtoken_1', name: "Datadogtoken - 1", severity: 'issue',
        patterns: [new RegExp("(?:datadog).{0,40}\\b([a-zA-Z-0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Datadogtoken - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_datadogtoken_2', name: "Datadogtoken - 2", severity: 'issue',
        patterns: [new RegExp("(?:datadog).{0,40}\\b([a-zA-Z-0-9]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Datadogtoken - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_datafire', name: "Datafire", severity: 'issue',
        patterns: [new RegExp("(?:datafire).{0,40}\\b([a-z0-9\\S]{175,190})\\b", 'gi')],
        description: 'Detected sensitive pattern: Datafire. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_datagov', name: "Datagov", severity: 'issue',
        patterns: [new RegExp("(?:data.gov).{0,40}\\b([a-zA-Z0-9]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Datagov. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_debounce', name: "Debounce", severity: 'issue',
        patterns: [new RegExp("(?:debounce).{0,40}\\b([a-zA-Z0-9]{13})\\b", 'gi')],
        description: 'Detected sensitive pattern: Debounce. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_deepai', name: "Deepai", severity: 'issue',
        patterns: [new RegExp("(?:deepai).{0,40}\\b([a-z0-9-]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Deepai. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_deepgram', name: "Deepgram", severity: 'issue',
        patterns: [new RegExp("(?:deepgram).{0,40}\\b([0-9a-z]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Deepgram. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_delighted', name: "Delighted", severity: 'issue',
        patterns: [new RegExp("(?:delighted).{0,40}\\b([a-z0-9A-Z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Delighted. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_deputy_1', name: "Deputy - 1", severity: 'issue',
        patterns: [new RegExp("\\b([0-9a-z]{1,}.as.deputy.com)\\b", 'gi')],
        description: 'Detected sensitive pattern: Deputy - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_deputy_2', name: "Deputy - 2", severity: 'issue',
        patterns: [new RegExp("(?:deputy).{0,40}\\b([0-9a-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Deputy - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_detectlanguage', name: "Detectlanguage", severity: 'issue',
        patterns: [new RegExp("(?:detectlanguage).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Detectlanguage. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_dfuse', name: "Dfuse", severity: 'issue',
        patterns: [new RegExp("\\b(web\\_[0-9a-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Dfuse. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_diffbot', name: "Diffbot", severity: 'issue',
        patterns: [new RegExp("(?:diffbot).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Diffbot. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_digitaloceantoken', name: "Digitaloceantoken", severity: 'issue',
        patterns: [new RegExp("(?:digitalocean).{0,40}\\b([A-Za-z0-9_-]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Digitaloceantoken. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_discord_webhook', name: "Discord Webhook", severity: 'issue',
        patterns: [new RegExp("https://discordapp\\.com/api/webhooks/[0-9]+/[A-Za-z0-9\\-]+", 'gi')],
        description: 'Detected sensitive pattern: Discord Webhook. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_discordbottoken_1', name: "Discordbottoken - 1", severity: 'issue',
        patterns: [new RegExp("(?:discord).{0,40}\\b([A-Za-z0-9_-]{24}\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{27})\\b", 'gi')],
        description: 'Detected sensitive pattern: Discordbottoken - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_discordbottoken_2', name: "Discordbottoken - 2", severity: 'issue',
        patterns: [new RegExp("(?:discord).{0,40}\\b([0-9]{17})\\b", 'gi')],
        description: 'Detected sensitive pattern: Discordbottoken - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_discordwebhook', name: "Discordwebhook", severity: 'issue',
        patterns: [new RegExp("(https:\\/\\/discord.com\\/api\\/webhooks\\/[0-9]{18}\\/[0-9a-zA-Z-]{68})", 'gi')],
        description: 'Detected sensitive pattern: Discordwebhook. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ditto', name: "Ditto", severity: 'issue',
        patterns: [new RegExp("(?:ditto).{0,40}\\b([a-z0-9]{8}\\-[a-z0-9]{4}\\-[a-z0-9]{4}\\-[a-z0-9]{4}\\-[a-z0-9]{12}\\.[a-z0-9]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Ditto. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_dnscheck_1', name: "Dnscheck - 1", severity: 'issue',
        patterns: [new RegExp("(?:dnscheck).{0,40}\\b([a-z0-9A-Z-]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Dnscheck - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_dnscheck_2', name: "Dnscheck - 2", severity: 'issue',
        patterns: [new RegExp("(?:dnscheck).{0,40}\\b([a-z0-9A-Z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Dnscheck - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_documo', name: "Documo", severity: 'issue',
        patterns: [new RegExp("\\b(ey[a-zA-Z0-9]{34}.ey[a-zA-Z0-9]{154}.[a-zA-Z0-9_-]{43})\\b", 'gi')],
        description: 'Detected sensitive pattern: Documo. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_doppler', name: "Doppler", severity: 'issue',
        patterns: [new RegExp("\\b(dp\\.pt\\.[a-zA-Z0-9]{43})\\b", 'gi')],
        description: 'Detected sensitive pattern: Doppler. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_dotmailer_1', name: "Dotmailer - 1", severity: 'issue',
        patterns: [new RegExp("(?:dotmailer).{0,40}\\b(apiuser-[a-z0-9]{12}@apiconnector.com)\\b", 'gi')],
        description: 'Detected sensitive pattern: Dotmailer - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_dotmailer_2', name: "Dotmailer - 2", severity: 'issue',
        patterns: [new RegExp("(?:dotmailer).{0,40}\\b([a-zA-Z0-9\\S]{8,24})\\b", 'gi')],
        description: 'Detected sensitive pattern: Dotmailer - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_dovico', name: "Dovico", severity: 'issue',
        patterns: [new RegExp("(?:dovico).{0,40}\\b([0-9a-z]{32}\\.[0-9a-z]{1,}\\b)", 'gi')],
        description: 'Detected sensitive pattern: Dovico. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_dronahq', name: "Dronahq", severity: 'issue',
        patterns: [new RegExp("(?:dronahq).{0,40}\\b([a-z0-9]{50})\\b", 'gi')],
        description: 'Detected sensitive pattern: Dronahq. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_droneci', name: "Droneci", severity: 'issue',
        patterns: [new RegExp("(?:droneci).{0,40}\\b([a-zA-Z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Droneci. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_dropbox', name: "Dropbox", severity: 'issue',
        patterns: [new RegExp("\\b(sl\\.[A-Za-z0-9\\-\\_]{130,140})\\b", 'gi')],
        description: 'Detected sensitive pattern: Dropbox. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_dwolla', name: "Dwolla", severity: 'issue',
        patterns: [new RegExp("(?:dwolla).{0,40}\\b([a-zA-Z-0-9]{50})\\b", 'gi')],
        description: 'Detected sensitive pattern: Dwolla. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_dynalist', name: "Dynalist", severity: 'issue',
        patterns: [new RegExp("(?:dynalist).{0,40}\\b([a-zA-Z0-9-_]{128})\\b", 'gi')],
        description: 'Detected sensitive pattern: Dynalist. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_dynatrace_token', name: "Dynatrace token", severity: 'issue',
        patterns: [new RegExp("dt0[a-zA-Z]{1}[0-9]{2}\\.[A-Z0-9]{24}\\.[A-Z0-9]{64}", 'gi')],
        description: 'Detected sensitive pattern: Dynatrace token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_dyspatch', name: "Dyspatch", severity: 'issue',
        patterns: [new RegExp("(?:dyspatch).{0,40}\\b([A-Z0-9]{52})\\b", 'gi')],
        description: 'Detected sensitive pattern: Dyspatch. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ec', name: "EC", severity: 'issue',
        patterns: [new RegExp("-----BEGIN EC PRIVATE KEY-----", 'gi')],
        description: 'Detected sensitive pattern: EC. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_eagleeyenetworks_1', name: "Eagleeyenetworks - 1", severity: 'issue',
        patterns: [new RegExp("(?:eagleeyenetworks).{0,40}\\b([a-zA-Z0-9]{3,20}@[a-zA-Z0-9]{2,12}.[a-zA-Z0-9]{2,5})\\b", 'gi')],
        description: 'Detected sensitive pattern: Eagleeyenetworks - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_eagleeyenetworks_2', name: "Eagleeyenetworks - 2", severity: 'issue',
        patterns: [new RegExp("(?:eagleeyenetworks).{0,40}\\b([a-zA-Z0-9]{15})\\b", 'gi')],
        description: 'Detected sensitive pattern: Eagleeyenetworks - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_easyinsight_1', name: "Easyinsight - 1", severity: 'issue',
        patterns: [new RegExp("(?:easyinsight|easy-insight).{0,40}\\b([a-zA-Z0-9]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Easyinsight - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_easyinsight_2', name: "Easyinsight - 2", severity: 'issue',
        patterns: [new RegExp("(?:easyinsight|easy-insight).{0,40}\\b([0-9Aa-zA-Z]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Easyinsight - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_edamam_1', name: "Edamam - 1", severity: 'issue',
        patterns: [new RegExp("(?:edamam).{0,40}\\b([0-9a-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Edamam - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_edamam_2', name: "Edamam - 2", severity: 'issue',
        patterns: [new RegExp("(?:edamam).{0,40}\\b([0-9a-z]{8})\\b", 'gi')],
        description: 'Detected sensitive pattern: Edamam - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_edenai', name: "Edenai", severity: 'issue',
        patterns: [new RegExp("(?:edenai).{0,40}\\b([a-zA-Z0-9]{36}.[a-zA-Z0-9]{92}.[a-zA-Z0-9_]{43})\\b", 'gi')],
        description: 'Detected sensitive pattern: Edenai. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_eightxeight_1', name: "Eightxeight - 1", severity: 'issue',
        patterns: [new RegExp("(?:8x8).{0,40}\\b([a-zA-Z0-9_]{18,30})\\b", 'gi')],
        description: 'Detected sensitive pattern: Eightxeight - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_eightxeight_2', name: "Eightxeight - 2", severity: 'issue',
        patterns: [new RegExp("(?:8x8).{0,40}\\b([a-zA-Z0-9]{43})\\b", 'gi')],
        description: 'Detected sensitive pattern: Eightxeight - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_elasticemail', name: "Elasticemail", severity: 'issue',
        patterns: [new RegExp("(?:elastic).{0,40}\\b([A-Za-z0-9_-]{96})\\b", 'gi')],
        description: 'Detected sensitive pattern: Elasticemail. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_enablex_1', name: "Enablex - 1", severity: 'issue',
        patterns: [new RegExp("(?:enablex).{0,40}\\b([a-zA-Z0-9]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Enablex - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_enablex_2', name: "Enablex - 2", severity: 'issue',
        patterns: [new RegExp("(?:enablex).{0,40}\\b([a-z0-9]{24})\\b", 'gi')],
        description: 'Detected sensitive pattern: Enablex - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_enigma', name: "Enigma", severity: 'issue',
        patterns: [new RegExp("(?:enigma).{0,40}\\b([a-zA-Z0-9]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Enigma. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ethplorer', name: "Ethplorer", severity: 'issue',
        patterns: [new RegExp("(?:ethplorer).{0,40}\\b([a-z0-9A-Z-]{22})\\b", 'gi')],
        description: 'Detected sensitive pattern: Ethplorer. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_etsyapikey', name: "Etsyapikey", severity: 'issue',
        patterns: [new RegExp("(?:etsy).{0,40}\\b([a-zA-Z-0-9]{24})\\b", 'gi')],
        description: 'Detected sensitive pattern: Etsyapikey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_everhour', name: "Everhour", severity: 'issue',
        patterns: [new RegExp("(?:everhour).{0,40}\\b([0-9Aa-f]{4}-[0-9a-f]{4}-[0-9a-f]{6}-[0-9a-f]{6}-[0-9a-f]{8})\\b", 'gi')],
        description: 'Detected sensitive pattern: Everhour. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_exchangerateapi', name: "Exchangerateapi", severity: 'issue',
        patterns: [new RegExp("(?:exchangerate).{0,40}\\b([a-z0-9]{24})\\b", 'gi')],
        description: 'Detected sensitive pattern: Exchangerateapi. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_exchangeratesapi', name: "Exchangeratesapi", severity: 'issue',
        patterns: [new RegExp("(?:exchangerates).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Exchangeratesapi. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_fcm_server_key', name: "FCM Server Key", severity: 'issue',
        patterns: [new RegExp("AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}", 'gi')],
        description: 'Detected sensitive pattern: FCM Server Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_fcm_server_key', name: "FCM_server_key", severity: 'issue',
        patterns: [new RegExp("(AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140})", 'gi')],
        description: 'Detected sensitive pattern: FCM_server_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_facebook_access_token', name: "Facebook Access Token", severity: 'issue',
        patterns: [new RegExp("EAACEdEose0cBA[0-9A-Za-z]+", 'gi')],
        description: 'Detected sensitive pattern: Facebook Access Token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_facebook_oauth', name: "Facebook OAuth", severity: 'issue',
        patterns: [new RegExp("[fF][aA][cC][eE][bB][oO][oO][kK].*[''|\"][0-9a-f]{32}[''|\"]", 'gi')],
        description: 'Detected sensitive pattern: Facebook OAuth. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_facebookoauth', name: "Facebookoauth", severity: 'issue',
        patterns: [new RegExp("(?:facebook).{0,40}\\b([A-Za-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Facebookoauth. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_faceplusplus', name: "Faceplusplus", severity: 'issue',
        patterns: [new RegExp("(?:faceplusplus).{0,40}\\b([0-9a-zA-Z_-]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Faceplusplus. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_fakejson', name: "Fakejson", severity: 'issue',
        patterns: [new RegExp("(?:fakejson).{0,40}\\b([a-zA-Z0-9]{22})\\b", 'gi')],
        description: 'Detected sensitive pattern: Fakejson. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_fastforex', name: "Fastforex", severity: 'issue',
        patterns: [new RegExp("(?:fastforex).{0,40}\\b([a-z0-9-]{28})\\b", 'gi')],
        description: 'Detected sensitive pattern: Fastforex. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_fastlypersonaltoken', name: "Fastlypersonaltoken", severity: 'issue',
        patterns: [new RegExp("(?:fastly).{0,40}\\b([A-Za-z0-9_-]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Fastlypersonaltoken. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_feedier', name: "Feedier", severity: 'issue',
        patterns: [new RegExp("(?:feedier).{0,40}\\b([a-z0-9A-Z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Feedier. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_fetchrss', name: "Fetchrss", severity: 'issue',
        patterns: [new RegExp("(?:fetchrss).{0,40}\\b([0-9A-Za-z.]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Fetchrss. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_figmapersonalaccesstoken', name: "Figmapersonalaccesstoken", severity: 'issue',
        patterns: [new RegExp("(?:figma).{0,40}\\b([0-9]{6}-[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Figmapersonalaccesstoken. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_fileio', name: "Fileio", severity: 'issue',
        patterns: [new RegExp("(?:fileio).{0,40}\\b([A-Z0-9.-]{39})\\b", 'gi')],
        description: 'Detected sensitive pattern: Fileio. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_finage', name: "Finage", severity: 'issue',
        patterns: [new RegExp("\\b(API_KEY[0-9A-Z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Finage. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_financialmodelingprep', name: "Financialmodelingprep", severity: 'issue',
        patterns: [new RegExp("(?:financialmodelingprep).{0,40}\\b([a-zA-Z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Financialmodelingprep. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_findl', name: "Findl", severity: 'issue',
        patterns: [new RegExp("(?:findl).{0,40}\\b([a-z0-9]{8}\\-[a-z0-9]{4}\\-[a-z0-9]{4}\\-[a-z0-9]{4}\\-[a-z0-9]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Findl. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_finnhub', name: "Finnhub", severity: 'issue',
        patterns: [new RegExp("(?:finnhub).{0,40}\\b([0-9a-z]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Finnhub. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_firebase_database_detect_1', name: "Firebase Database Detect - 1", severity: 'issue',
        patterns: [new RegExp("[a-z0-9.-]+\\.firebaseio\\.com", 'gi')],
        description: 'Detected sensitive pattern: Firebase Database Detect - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_firebase_database_detect_2', name: "Firebase Database Detect - 2", severity: 'issue',
        patterns: [new RegExp("[a-z0-9.-]+\\.firebaseapp\\.com", 'gi')],
        description: 'Detected sensitive pattern: Firebase Database Detect - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_fixerio', name: "Fixerio", severity: 'issue',
        patterns: [new RegExp("(?:fixer).{0,40}\\b([A-Za-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Fixerio. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_flatio', name: "Flatio", severity: 'issue',
        patterns: [new RegExp("(?:flat).{0,40}\\b([0-9a-z]{128})\\b", 'gi')],
        description: 'Detected sensitive pattern: Flatio. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_fleetbase', name: "Fleetbase", severity: 'issue',
        patterns: [new RegExp("\\b(flb_live_[0-9a-zA-Z]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Fleetbase. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_flickr', name: "Flickr", severity: 'issue',
        patterns: [new RegExp("(?:flickr).{0,40}\\b([0-9a-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Flickr. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_flightapi', name: "Flightapi", severity: 'issue',
        patterns: [new RegExp("(?:flightapi).{0,40}\\b([a-z0-9]{24})\\b", 'gi')],
        description: 'Detected sensitive pattern: Flightapi. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_flightstats_1', name: "Flightstats - 1", severity: 'issue',
        patterns: [new RegExp("(?:flightstats).{0,40}\\b([0-9a-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Flightstats - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_flightstats_2', name: "Flightstats - 2", severity: 'issue',
        patterns: [new RegExp("(?:flightstats).{0,40}\\b([0-9a-z]{8})\\b", 'gi')],
        description: 'Detected sensitive pattern: Flightstats - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_float', name: "Float", severity: 'issue',
        patterns: [new RegExp("(?:float).{0,40}\\b([a-zA-Z0-9-._+=]{59,60})\\b", 'gi')],
        description: 'Detected sensitive pattern: Float. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_flowflu_2', name: "Flowflu - 2", severity: 'issue',
        patterns: [new RegExp("(?:flowflu).{0,40}\\b([a-zA-Z0-9]{51})\\b", 'gi')],
        description: 'Detected sensitive pattern: Flowflu - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_flutterwave', name: "Flutterwave", severity: 'issue',
        patterns: [new RegExp("\\b(FLWSECK-[0-9a-z]{32}-X)\\b", 'gi')],
        description: 'Detected sensitive pattern: Flutterwave. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_fmfw_1', name: "Fmfw - 1", severity: 'issue',
        patterns: [new RegExp("(?:fmfw).{0,40}\\b([a-zA-Z0-9-]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Fmfw - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_fmfw_2', name: "Fmfw - 2", severity: 'issue',
        patterns: [new RegExp("(?:fmfw).{0,40}\\b([a-zA-Z0-9_-]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Fmfw - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_formbucket', name: "Formbucket", severity: 'issue',
        patterns: [new RegExp("(?:formbucket).{0,40}\\b([0-9A-Za-z]{1,}.[0-9A-Za-z]{1,}\\.[0-9A-Z-a-z\\-_]{1,})", 'gi')],
        description: 'Detected sensitive pattern: Formbucket. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_formio', name: "Formio", severity: 'issue',
        patterns: [new RegExp("(?:formio).{0,40}\\b(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\\.eyJhdWQiOiJhcGkubGl2ZXN0b3JtLmNvIiwianRpIjoi[0-9A-Z-a-z]{134}\\.[0-9A-Za-z\\-\\_]{43}[\\r\\n]{1})", 'gi')],
        description: 'Detected sensitive pattern: Formio. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_foursquare', name: "Foursquare", severity: 'issue',
        patterns: [new RegExp("(?:foursquare).{0,40}\\b([0-9A-Z]{48})\\b", 'gi')],
        description: 'Detected sensitive pattern: Foursquare. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_frameio', name: "Frameio", severity: 'issue',
        patterns: [new RegExp("\\b(fio-u-[0-9a-zA-Z_-]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Frameio. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_freshbooks_1', name: "Freshbooks - 1", severity: 'issue',
        patterns: [new RegExp("(?:freshbooks).{0,40}\\b([0-9a-z]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Freshbooks - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_freshbooks_2', name: "Freshbooks - 2", severity: 'issue',
        patterns: [new RegExp("(?:freshbooks).{0,40}\\b(https://www.[0-9A-Za-z_-]{1,}.com)\\b", 'gi')],
        description: 'Detected sensitive pattern: Freshbooks - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_freshdesk_1', name: "Freshdesk - 1", severity: 'issue',
        patterns: [new RegExp("(?:freshdesk).{0,40}\\b([0-9A-Za-z]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Freshdesk - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_freshdesk_2', name: "Freshdesk - 2", severity: 'issue',
        patterns: [new RegExp("\\b([0-9a-z-]{1,}.freshdesk.com)\\b", 'gi')],
        description: 'Detected sensitive pattern: Freshdesk - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_front', name: "Front", severity: 'issue',
        patterns: [new RegExp("(?:front).{0,40}\\b([0-9a-zA-Z]{36}.[0-9a-zA-Z\\.\\-\\_]{188,244})\\b", 'gi')],
        description: 'Detected sensitive pattern: Front. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_fulcrum', name: "Fulcrum", severity: 'issue',
        patterns: [new RegExp("(?:fulcrum).{0,40}\\b([a-z0-9]{80})\\b", 'gi')],
        description: 'Detected sensitive pattern: Fulcrum. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_fullstory', name: "Fullstory", severity: 'issue',
        patterns: [new RegExp("(?:fullstory).{0,40}\\b([a-zA-Z-0-9/+]{88})\\b", 'gi')],
        description: 'Detected sensitive pattern: Fullstory. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_fusebill', name: "Fusebill", severity: 'issue',
        patterns: [new RegExp("(?:fusebill).{0,40}\\b([a-zA-Z0-9]{88})\\b", 'gi')],
        description: 'Detected sensitive pattern: Fusebill. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_fxmarket', name: "Fxmarket", severity: 'issue',
        patterns: [new RegExp("(?:fxmarket).{0,40}\\b([0-9Aa-zA-Z-_=]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Fxmarket. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gcp', name: "Gcp", severity: 'issue',
        patterns: [new RegExp("\\{[^{]+auth_provider_x509_cert_url[^}]+\\}", 'gi')],
        description: 'Detected sensitive pattern: Gcp. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_geckoboard', name: "Geckoboard", severity: 'issue',
        patterns: [new RegExp("(?:geckoboard).{0,40}\\b([a-zA-Z0-9]{44})\\b", 'gi')],
        description: 'Detected sensitive pattern: Geckoboard. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1376', name: "Generic - 1376", severity: 'issue',
        patterns: [new RegExp("jdbc:mysql(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1376. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1688', name: "Generic - 1688", severity: 'issue',
        patterns: [new RegExp("TOKEN[\\\\-|_|A-Z0-9]*(\\'|\\\")?(:|=)(\\'|\\\")?[\\\\-|_|A-Z0-9]{10}", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1688. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1689', name: "Generic - 1689", severity: 'issue',
        patterns: [new RegExp("API[\\\\-|_|A-Z0-9]*(\\'|\\\")?(:|=)(\\'|\\\")?[\\\\-|_|A-Z0-9]{10}", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1689. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1691', name: "Generic - 1691", severity: 'issue',
        patterns: [new RegExp("SECRET[\\\\-|_|A-Z0-9]*(\\'|\\\")?(:|=)(\\'|\\\")?[\\\\-|_|A-Z0-9]{10}", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1691. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1692', name: "Generic - 1692", severity: 'issue',
        patterns: [new RegExp("AUTHORIZATION[\\\\-|_|A-Z0-9]*(\\'|\\\")?(:|=)(\\'|\\\")?[\\\\-|_|A-Z0-9]{10}", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1692. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1693', name: "Generic - 1693", severity: 'issue',
        patterns: [new RegExp("PASSWORD[\\\\-|_|A-Z0-9]*(\\'|\\\")?(:|=)(\\'|\\\")?[\\\\-|_|A-Z0-9]{10}", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1693. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1695', name: "Generic - 1695", severity: 'issue',
        patterns: [new RegExp("(A|a)(P|p)(Ii)[\\-|_|A-Za-z0-9]*(\\''|\")?( )*(:|=)( )*(\\''|\")?[0-9A-Za-z\\-_]+(\\''|\")?", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1695. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1700', name: "Generic - 1700", severity: 'issue',
        patterns: [new RegExp("BEGIN OPENSSH PRIVATE KEY", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1700. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1701', name: "Generic - 1701", severity: 'issue',
        patterns: [new RegExp("BEGIN PRIVATE KEY", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1701. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1702', name: "Generic - 1702", severity: 'issue',
        patterns: [new RegExp("BEGIN RSA PRIVATE KEY", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1702. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1703', name: "Generic - 1703", severity: 'issue',
        patterns: [new RegExp("BEGIN DSA PRIVATE KEY", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1703. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1704', name: "Generic - 1704", severity: 'issue',
        patterns: [new RegExp("BEGIN EC PRIVATE KEY", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1704. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1705', name: "Generic - 1705", severity: 'issue',
        patterns: [new RegExp("BEGIN PGP PRIVATE KEY BLOCK", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1705. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1707', name: "Generic - 1707", severity: 'issue',
        patterns: [new RegExp("[a-z0-9.-]+\\.s3-[a-z0-9-]\\.amazonaws\\.com", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1707. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1708', name: "Generic - 1708", severity: 'issue',
        patterns: [new RegExp("[a-z0-9.-]+\\.s3-website[.-](eu|ap|us|ca|sa|cn)", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1708. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1710', name: "Generic - 1710", severity: 'issue',
        patterns: [new RegExp("algolia_api_key", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1710. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1711', name: "Generic - 1711", severity: 'issue',
        patterns: [new RegExp("asana_access_token", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1711. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1713', name: "Generic - 1713", severity: 'issue',
        patterns: [new RegExp("azure_tenant", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1713. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1714', name: "Generic - 1714", severity: 'issue',
        patterns: [new RegExp("bitly_access_token", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1714. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1715', name: "Generic - 1715", severity: 'issue',
        patterns: [new RegExp("branchio_secret", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1715. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1716', name: "Generic - 1716", severity: 'issue',
        patterns: [new RegExp("browserstack_access_key", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1716. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1717', name: "Generic - 1717", severity: 'issue',
        patterns: [new RegExp("buildkite_access_token", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1717. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1718', name: "Generic - 1718", severity: 'issue',
        patterns: [new RegExp("comcast_access_token", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1718. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1719', name: "Generic - 1719", severity: 'issue',
        patterns: [new RegExp("datadog_api_key", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1719. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1720', name: "Generic - 1720", severity: 'issue',
        patterns: [new RegExp("deviantart_secret", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1720. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1721', name: "Generic - 1721", severity: 'issue',
        patterns: [new RegExp("deviantart_access_token", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1721. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1722', name: "Generic - 1722", severity: 'issue',
        patterns: [new RegExp("dropbox_api_token", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1722. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1723', name: "Generic - 1723", severity: 'issue',
        patterns: [new RegExp("facebook_appsecret", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1723. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1724', name: "Generic - 1724", severity: 'issue',
        patterns: [new RegExp("facebook_access_token", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1724. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1725', name: "Generic - 1725", severity: 'issue',
        patterns: [new RegExp("firebase_custom_token", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1725. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1726', name: "Generic - 1726", severity: 'issue',
        patterns: [new RegExp("firebase_id_token", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1726. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1727', name: "Generic - 1727", severity: 'issue',
        patterns: [new RegExp("github_client", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1727. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1728', name: "Generic - 1728", severity: 'issue',
        patterns: [new RegExp("github_ssh_key", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1728. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1730', name: "Generic - 1730", severity: 'issue',
        patterns: [new RegExp("gitlab_private_token", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1730. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1731', name: "Generic - 1731", severity: 'issue',
        patterns: [new RegExp("google_cm", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1731. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1732', name: "Generic - 1732", severity: 'issue',
        patterns: [new RegExp("google_maps_key", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1732. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1733', name: "Generic - 1733", severity: 'issue',
        patterns: [new RegExp("heroku_api_key", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1733. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1734', name: "Generic - 1734", severity: 'issue',
        patterns: [new RegExp("instagram_access_token", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1734. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1735', name: "Generic - 1735", severity: 'issue',
        patterns: [new RegExp("mailchimp_api_key", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1735. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1736', name: "Generic - 1736", severity: 'issue',
        patterns: [new RegExp("mailgun_api_key", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1736. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1737', name: "Generic - 1737", severity: 'issue',
        patterns: [new RegExp("mailjet", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1737. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1738', name: "Generic - 1738", severity: 'issue',
        patterns: [new RegExp("mapbox_access_token", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1738. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1739', name: "Generic - 1739", severity: 'issue',
        patterns: [new RegExp("pagerduty_api_token", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1739. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1740', name: "Generic - 1740", severity: 'issue',
        patterns: [new RegExp("paypal_key_sb", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1740. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1741', name: "Generic - 1741", severity: 'issue',
        patterns: [new RegExp("paypal_key_live", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1741. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1742', name: "Generic - 1742", severity: 'issue',
        patterns: [new RegExp("paypal_token_sb", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1742. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1743', name: "Generic - 1743", severity: 'issue',
        patterns: [new RegExp("paypal_token_live", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1743. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1744', name: "Generic - 1744", severity: 'issue',
        patterns: [new RegExp("pendo_integration_key", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1744. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1745', name: "Generic - 1745", severity: 'issue',
        patterns: [new RegExp("salesforce_access_token", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1745. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1746', name: "Generic - 1746", severity: 'issue',
        patterns: [new RegExp("saucelabs_ukey", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1746. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1747', name: "Generic - 1747", severity: 'issue',
        patterns: [new RegExp("sendgrid_api_key", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1747. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1748', name: "Generic - 1748", severity: 'issue',
        patterns: [new RegExp("slack_api_token", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1748. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1749', name: "Generic - 1749", severity: 'issue',
        patterns: [new RegExp("slack_webhook", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1749. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1750', name: "Generic - 1750", severity: 'issue',
        patterns: [new RegExp("square_secret", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1750. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1751', name: "Generic - 1751", severity: 'issue',
        patterns: [new RegExp("square_auth_token", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1751. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1752', name: "Generic - 1752", severity: 'issue',
        patterns: [new RegExp("travisci_api_token", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1752. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1753', name: "Generic - 1753", severity: 'issue',
        patterns: [new RegExp("twilio_sid_token", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1753. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1754', name: "Generic - 1754", severity: 'issue',
        patterns: [new RegExp("twitter_api_secret", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1754. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1755', name: "Generic - 1755", severity: 'issue',
        patterns: [new RegExp("twitter_bearer_token", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1755. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1756', name: "Generic - 1756", severity: 'issue',
        patterns: [new RegExp("spotify_access_token", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1756. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1757', name: "Generic - 1757", severity: 'issue',
        patterns: [new RegExp("stripe_key_live", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1757. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1758', name: "Generic - 1758", severity: 'issue',
        patterns: [new RegExp("wakatime_api_key", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1758. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1759', name: "Generic - 1759", severity: 'issue',
        patterns: [new RegExp("wompi_auth_bearer_sb", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1759. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1760', name: "Generic - 1760", severity: 'issue',
        patterns: [new RegExp("wompi_auth_bearer_live", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1760. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1761', name: "Generic - 1761", severity: 'issue',
        patterns: [new RegExp("wpengine_api_key", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1761. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1762', name: "Generic - 1762", severity: 'issue',
        patterns: [new RegExp("zapier_webhook", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1762. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1763', name: "Generic - 1763", severity: 'issue',
        patterns: [new RegExp("zendesk_access_token", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1763. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1764', name: "Generic - 1764", severity: 'issue',
        patterns: [new RegExp("ssh-rsa", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1764. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sift_key', name: "Sift Key", severity: 'issue',
        patterns: [new RegExp("\\.with(?:AccountId|BeaconKey)\\([\"|'].*[\"|']\\)", 'gi')],
        description: 'Detected sensitive pattern: Sift Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_1765', name: "Generic - 1765", severity: 'issue',
        patterns: [new RegExp("s3-[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9._-]+", 'gi')],
        description: 'Detected sensitive pattern: Generic - 1765. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_generic_webhook_secret', name: "Generic webhook secret", severity: 'issue',
        patterns: [new RegExp("(webhook).+(secret|token|key).+", 'gi')],
        description: 'Detected sensitive pattern: Generic webhook secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gengo', name: "Gengo", severity: 'issue',
        patterns: [new RegExp("(?:gengo).{0,40}([ ]{0,1}[0-9a-zA-Z\\[\\]\\-\\(\\)\\{\\}|_^@$=~]{64}[ \\r\\n]{1})", 'gi')],
        description: 'Detected sensitive pattern: Gengo. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_geoapify', name: "Geoapify", severity: 'issue',
        patterns: [new RegExp("(?:geoapify).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Geoapify. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_geocode', name: "Geocode", severity: 'issue',
        patterns: [new RegExp("(?:geocode).{0,40}\\b([a-z0-9]{28})\\b", 'gi')],
        description: 'Detected sensitive pattern: Geocode. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_geocodify', name: "Geocodify", severity: 'issue',
        patterns: [new RegExp("(?:geocodify).{0,40}\\b([0-9a-z]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Geocodify. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_geocodio_2', name: "Geocodio - 2", severity: 'issue',
        patterns: [new RegExp("(?:geocod).{0,40}\\b([a-z0-9]{39})\\b", 'gi')],
        description: 'Detected sensitive pattern: Geocodio - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_geoipifi', name: "Geoipifi", severity: 'issue',
        patterns: [new RegExp("(?:ipifi).{0,40}\\b([a-z0-9A-Z_]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Geoipifi. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_getemail', name: "Getemail", severity: 'issue',
        patterns: [new RegExp("(?:getemail).{0,40}\\b([a-zA-Z0-9-]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Getemail. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_getemails_1', name: "Getemails - 1", severity: 'issue',
        patterns: [new RegExp("(?:getemails).{0,40}\\b([a-z0-9-]{26})\\b", 'gi')],
        description: 'Detected sensitive pattern: Getemails - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_getemails_2', name: "Getemails - 2", severity: 'issue',
        patterns: [new RegExp("(?:getemails).{0,40}\\b([a-z0-9-]{18})\\b", 'gi')],
        description: 'Detected sensitive pattern: Getemails - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_getgeoapi', name: "Getgeoapi", severity: 'issue',
        patterns: [new RegExp("(?:getgeoapi).{0,40}\\b([0-9a-z]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Getgeoapi. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_getgist', name: "Getgist", severity: 'issue',
        patterns: [new RegExp("(?:getgist).{0,40}\\b([a-z0-9A-Z+=]{68})", 'gi')],
        description: 'Detected sensitive pattern: Getgist. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_getsandbox_1', name: "Getsandbox - 1", severity: 'issue',
        patterns: [new RegExp("(?:getsandbox).{0,40}\\b([a-z0-9-]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Getsandbox - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_getsandbox_2', name: "Getsandbox - 2", severity: 'issue',
        patterns: [new RegExp("(?:getsandbox).{0,40}\\b([a-z0-9-]{15,30})\\b", 'gi')],
        description: 'Detected sensitive pattern: Getsandbox - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github_2', name: "Github - 2", severity: 'issue',
        patterns: [new RegExp("\\b((?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,255}\\b)", 'gi')],
        description: 'Detected sensitive pattern: Github - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github_app_token', name: "Github App Token", severity: 'issue',
        patterns: [new RegExp("(ghu|ghs)_[0-9a-zA-Z]{36}", 'gi')],
        description: 'Detected sensitive pattern: Github App Token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github_oauth_access_token', name: "Github OAuth Access Token", severity: 'issue',
        patterns: [new RegExp("gho_[0-9a-zA-Z]{36}", 'gi')],
        description: 'Detected sensitive pattern: Github OAuth Access Token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github_personal_access_token', name: "Github Personal Access Token", severity: 'issue',
        patterns: [new RegExp("ghp_[0-9a-zA-Z]{36}", 'gi')],
        description: 'Detected sensitive pattern: Github Personal Access Token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github_refresh_token', name: "Github Refresh Token", severity: 'issue',
        patterns: [new RegExp("ghr_[0-9a-zA-Z]{76}", 'gi')],
        description: 'Detected sensitive pattern: Github Refresh Token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github_old', name: "Github_old", severity: 'issue',
        patterns: [new RegExp("(?:github)[^\\.].{0,40}[ =:'\"]+([a-f0-9]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Github_old. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_githubapp_1', name: "Githubapp - 1", severity: 'issue',
        patterns: [new RegExp("(?:github).{0,40}\\b([0-9]{6})\\b", 'gi')],
        description: 'Detected sensitive pattern: Githubapp - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gitlab', name: "Gitlab", severity: 'issue',
        patterns: [new RegExp("(?:gitlab).{0,40}\\b([a-zA-Z0-9\\-=_]{20,22})\\b", 'gi')],
        description: 'Detected sensitive pattern: Gitlab. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gitlabv2', name: "Gitlabv2", severity: 'issue',
        patterns: [new RegExp("\\b(glpat-[a-zA-Z0-9\\-=_]{20,22})\\b", 'gi')],
        description: 'Detected sensitive pattern: Gitlabv2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gitter', name: "Gitter", severity: 'issue',
        patterns: [new RegExp("(?:gitter).{0,40}\\b([a-z0-9-]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Gitter. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_glassnode', name: "Glassnode", severity: 'issue',
        patterns: [new RegExp("(?:glassnode).{0,40}\\b([0-9A-Za-z]{27})\\b", 'gi')],
        description: 'Detected sensitive pattern: Glassnode. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gocanvas_1', name: "Gocanvas - 1", severity: 'issue',
        patterns: [new RegExp("(?:gocanvas).{0,40}\\b([0-9A-Za-z/+]{43}=[ \\r\\n]{1})", 'gi')],
        description: 'Detected sensitive pattern: Gocanvas - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gocanvas_2', name: "Gocanvas - 2", severity: 'issue',
        patterns: [new RegExp("(?:gocanvas).{0,40}\\b([\\w\\.-]+@[\\w-]+\\.[\\w\\.-]{2,5})\\b", 'gi')],
        description: 'Detected sensitive pattern: Gocanvas - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gocardless', name: "Gocardless", severity: 'issue',
        patterns: [new RegExp("\\b(live_[0-9A-Za-z\\_\\-]{40}[ \"'\\r\\n]{1})", 'gi')],
        description: 'Detected sensitive pattern: Gocardless. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_goodday', name: "Goodday", severity: 'issue',
        patterns: [new RegExp("(?:goodday).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Goodday. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_google_gcp_service_account', name: "Google (GCP) Service Account", severity: 'issue',
        patterns: [new RegExp("\"type\": \"service_account\"", 'gi')],
        description: 'Detected sensitive pattern: Google (GCP) Service Account. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_google_api_key', name: "Google API Key", severity: 'issue',
        patterns: [new RegExp("AIza[0-9a-z-_]{35}", 'gi')],
        description: 'Detected sensitive pattern: Google API Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_google_calendar_uri', name: "Google Calendar URI", severity: 'issue',
        patterns: [new RegExp("https://www\\.google\\.com/calendar/embed\\?src=[A-Za-z0-9%@&;=\\-_\\./]+", 'gi')],
        description: 'Detected sensitive pattern: Google Calendar URI. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_google_oauth_access_token', name: "Google OAuth Access Token", severity: 'issue',
        patterns: [new RegExp("ya29\\.[0-9A-Za-z\\-_]+", 'gi')],
        description: 'Detected sensitive pattern: Google OAuth Access Token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_graphcms_1', name: "Graphcms - 1", severity: 'issue',
        patterns: [new RegExp("(?:graph).{0,40}\\b([a-z0-9]{25})\\b", 'gi')],
        description: 'Detected sensitive pattern: Graphcms - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_graphcms_2', name: "Graphcms - 2", severity: 'issue',
        patterns: [new RegExp("\\b(ey[a-zA-Z0-9]{73}.ey[a-zA-Z0-9]{365}.[a-zA-Z0-9_-]{683})\\b", 'gi')],
        description: 'Detected sensitive pattern: Graphcms - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_graphhopper', name: "Graphhopper", severity: 'issue',
        patterns: [new RegExp("(?:graphhopper).{0,40}\\b([a-z0-9-]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Graphhopper. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_groovehq', name: "Groovehq", severity: 'issue',
        patterns: [new RegExp("(?:groove).{0,40}\\b([a-z0-9A-Z]{64})", 'gi')],
        description: 'Detected sensitive pattern: Groovehq. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_guru_1', name: "Guru - 1", severity: 'issue',
        patterns: [new RegExp("(?:guru).{0,40}\\b([a-zA-Z0-9]{3,20}@[a-zA-Z0-9]{2,12}.[a-zA-Z0-9]{2,5})\\b", 'gi')],
        description: 'Detected sensitive pattern: Guru - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_guru_2', name: "Guru - 2", severity: 'issue',
        patterns: [new RegExp("(?:guru).{0,40}\\b([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Guru - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gyazo', name: "Gyazo", severity: 'issue',
        patterns: [new RegExp("(?:gyazo).{0,40}\\b([0-9A-Za-z-]{43})\\b", 'gi')],
        description: 'Detected sensitive pattern: Gyazo. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_happi', name: "Happi", severity: 'issue',
        patterns: [new RegExp("(?:happi).{0,40}\\b([a-zA-Z0-9]{56})", 'gi')],
        description: 'Detected sensitive pattern: Happi. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_happyscribe', name: "Happyscribe", severity: 'issue',
        patterns: [new RegExp("(?:happyscribe).{0,40}\\b([0-9a-zA-Z]{24})\\b", 'gi')],
        description: 'Detected sensitive pattern: Happyscribe. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_harvest_1', name: "Harvest - 1", severity: 'issue',
        patterns: [new RegExp("(?:harvest).{0,40}\\b([a-z0-9A-Z._]{97})\\b", 'gi')],
        description: 'Detected sensitive pattern: Harvest - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_harvest_2', name: "Harvest - 2", severity: 'issue',
        patterns: [new RegExp("(?:harvest).{0,40}\\b([0-9]{4,9})\\b", 'gi')],
        description: 'Detected sensitive pattern: Harvest - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_hellosign', name: "Hellosign", severity: 'issue',
        patterns: [new RegExp("(?:hellosign).{0,40}\\b([a-zA-Z-0-9/+]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Hellosign. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_helpcrunch', name: "Helpcrunch", severity: 'issue',
        patterns: [new RegExp("(?:helpcrunch).{0,40}\\b([a-zA-Z-0-9+/=]{328})", 'gi')],
        description: 'Detected sensitive pattern: Helpcrunch. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_helpscout', name: "Helpscout", severity: 'issue',
        patterns: [new RegExp("(?:helpscout).{0,40}\\b([A-Za-z0-9]{56})\\b", 'gi')],
        description: 'Detected sensitive pattern: Helpscout. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_hereapi', name: "Hereapi", severity: 'issue',
        patterns: [new RegExp("(?:hereapi).{0,40}\\b([a-zA-Z0-9\\S]{43})\\b", 'gi')],
        description: 'Detected sensitive pattern: Hereapi. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_heroku', name: "Heroku", severity: 'issue',
        patterns: [new RegExp("(?:heroku).{0,40}\\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Heroku. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_hive_1', name: "Hive - 1", severity: 'issue',
        patterns: [new RegExp("(?:hive).{0,40}\\b([0-9a-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Hive - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_hive_2', name: "Hive - 2", severity: 'issue',
        patterns: [new RegExp("(?:hive).{0,40}\\b([0-9A-Za-z]{17})\\b", 'gi')],
        description: 'Detected sensitive pattern: Hive - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_hiveage', name: "Hiveage", severity: 'issue',
        patterns: [new RegExp("(?:hiveage).{0,40}\\b([0-9A-Za-z\\_\\-]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Hiveage. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_holidayapi', name: "Holidayapi", severity: 'issue',
        patterns: [new RegExp("(?:holidayapi).{0,40}\\b([a-z0-9-]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Holidayapi. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_host', name: "Host", severity: 'issue',
        patterns: [new RegExp("(?:host).{0,40}\\b([a-z0-9]{14})\\b", 'gi')],
        description: 'Detected sensitive pattern: Host. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_html2pdf', name: "Html2pdf", severity: 'issue',
        patterns: [new RegExp("(?:html2pdf).{0,40}\\b([a-zA-Z0-9]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Html2pdf. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_hubspotapikey', name: "Hubspotapikey", severity: 'issue',
        patterns: [new RegExp("(?:hubspot).{0,40}\\b([A-Za-z0-9]{8}\\-[A-Za-z0-9]{4}\\-[A-Za-z0-9]{4}\\-[A-Za-z0-9]{4}\\-[A-Za-z0-9]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Hubspotapikey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_humanity', name: "Humanity", severity: 'issue',
        patterns: [new RegExp("(?:humanity).{0,40}\\b([0-9a-z]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Humanity. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_hunter', name: "Hunter", severity: 'issue',
        patterns: [new RegExp("(?:hunter).{0,40}\\b([a-z0-9_-]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Hunter. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_hypertrack_1', name: "Hypertrack - 1", severity: 'issue',
        patterns: [new RegExp("(?:hypertrack).{0,40}\\b([0-9a-zA-Z\\_\\-]{54})\\b", 'gi')],
        description: 'Detected sensitive pattern: Hypertrack - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_hypertrack_2', name: "Hypertrack - 2", severity: 'issue',
        patterns: [new RegExp("(?:hypertrack).{0,40}\\b([0-9a-zA-Z\\_\\-]{27})\\b", 'gi')],
        description: 'Detected sensitive pattern: Hypertrack - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ibmclouduserkey', name: "Ibmclouduserkey", severity: 'issue',
        patterns: [new RegExp("(?:ibm).{0,40}\\b([A-Za-z0-9_-]{44})\\b", 'gi')],
        description: 'Detected sensitive pattern: Ibmclouduserkey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_iconfinder', name: "Iconfinder", severity: 'issue',
        patterns: [new RegExp("(?:iconfinder).{0,40}\\b([a-zA-Z0-9]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Iconfinder. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_iexcloud', name: "Iexcloud", severity: 'issue',
        patterns: [new RegExp("(?:iexcloud).{0,40}\\b([a-z0-9_]{35})\\b", 'gi')],
        description: 'Detected sensitive pattern: Iexcloud. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_imagekit', name: "Imagekit", severity: 'issue',
        patterns: [new RegExp("(?:imagekit).{0,40}\\b([a-zA-Z0-9_=]{36})", 'gi')],
        description: 'Detected sensitive pattern: Imagekit. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_imagga', name: "Imagga", severity: 'issue',
        patterns: [new RegExp("(?:imagga).{0,40}\\b([a-z0-9A-Z=]{72})", 'gi')],
        description: 'Detected sensitive pattern: Imagga. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_impala', name: "Impala", severity: 'issue',
        patterns: [new RegExp("(?:impala).{0,40}\\b([0-9A-Za-z_]{46})\\b", 'gi')],
        description: 'Detected sensitive pattern: Impala. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_insightly', name: "Insightly", severity: 'issue',
        patterns: [new RegExp("(?:insightly).{0,40}\\b([a-z0-9-]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Insightly. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_integromat', name: "Integromat", severity: 'issue',
        patterns: [new RegExp("(?:integromat).{0,40}\\b([a-z0-9-]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Integromat. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_intercom', name: "Intercom", severity: 'issue',
        patterns: [new RegExp("(?:intercom).{0,40}\\b([a-zA-Z0-9\\W\\S]{59}\\=)", 'gi')],
        description: 'Detected sensitive pattern: Intercom. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_intrinio', name: "Intrinio", severity: 'issue',
        patterns: [new RegExp("(?:intrinio).{0,40}\\b([a-zA-Z0-9]{44})\\b", 'gi')],
        description: 'Detected sensitive pattern: Intrinio. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_invoiceocean_1', name: "Invoiceocean - 1", severity: 'issue',
        patterns: [new RegExp("(?:invoiceocean).{0,40}\\b([0-9A-Za-z]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Invoiceocean - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_invoiceocean_2', name: "Invoiceocean - 2", severity: 'issue',
        patterns: [new RegExp("\\b([0-9a-z]{1,}.invoiceocean.com)\\b", 'gi')],
        description: 'Detected sensitive pattern: Invoiceocean - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ipapi', name: "Ipapi", severity: 'issue',
        patterns: [new RegExp("(?:ipapi).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Ipapi. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ipgeolocation', name: "Ipgeolocation", severity: 'issue',
        patterns: [new RegExp("(?:ipgeolocation).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Ipgeolocation. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ipify', name: "Ipify", severity: 'issue',
        patterns: [new RegExp("(?:ipify).{0,40}\\b([a-zA-Z0-9_-]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Ipify. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ipinfodb', name: "Ipinfodb", severity: 'issue',
        patterns: [new RegExp("(?:ipinfodb).{0,40}\\b([a-z0-9]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Ipinfodb. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ipquality', name: "Ipquality", severity: 'issue',
        patterns: [new RegExp("(?:ipquality).{0,40}\\b([0-9a-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Ipquality. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ipstack', name: "Ipstack", severity: 'issue',
        patterns: [new RegExp("(?:ipstack).{0,40}\\b([a-fA-f0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Ipstack. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_jdbc_connection_string', name: "JDBC Connection String", severity: 'issue',
        patterns: [new RegExp("jdbc:[a-z:]+://[A-Za-z0-9\\.\\-_:;=/@?,&]+", 'gi')],
        description: 'Detected sensitive pattern: JDBC Connection String. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_jiratoken_1', name: "Jiratoken - 1", severity: 'issue',
        patterns: [new RegExp("(?:jira).{0,40}\\b([a-zA-Z-0-9]{24})\\b", 'gi')],
        description: 'Detected sensitive pattern: Jiratoken - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_jiratoken_2', name: "Jiratoken - 2", severity: 'issue',
        patterns: [new RegExp("(?:jira).{0,40}\\b([a-zA-Z-0-9]{5,24}\\@[a-zA-Z-0-9]{3,16}\\.com)\\b", 'gi')],
        description: 'Detected sensitive pattern: Jiratoken - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_jiratoken_3', name: "Jiratoken - 3", severity: 'issue',
        patterns: [new RegExp("(?:jira).{0,40}\\b([a-zA-Z-0-9]{5,24}\\.[a-zA-Z-0-9]{3,16}\\.[a-zA-Z-0-9]{3,16})\\b", 'gi')],
        description: 'Detected sensitive pattern: Jiratoken - 3. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_jotform', name: "Jotform", severity: 'issue',
        patterns: [new RegExp("(?:jotform).{0,40}\\b([0-9Aa-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Jotform. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_jumpcloud', name: "Jumpcloud", severity: 'issue',
        patterns: [new RegExp("(?:jumpcloud).{0,40}\\b([a-zA-Z0-9]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Jumpcloud. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_juro', name: "Juro", severity: 'issue',
        patterns: [new RegExp("(?:juro).{0,40}\\b([a-zA-Z0-9]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Juro. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_kanban_1', name: "Kanban - 1", severity: 'issue',
        patterns: [new RegExp("(?:kanban).{0,40}\\b([0-9A-Z]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Kanban - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_kanban_2', name: "Kanban - 2", severity: 'issue',
        patterns: [new RegExp("\\b([0-9a-z]{1,}.kanbantool.com)\\b", 'gi')],
        description: 'Detected sensitive pattern: Kanban - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_karmacrm', name: "Karmacrm", severity: 'issue',
        patterns: [new RegExp("(?:karma).{0,40}\\b([a-zA-Z0-9]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Karmacrm. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_keenio_1', name: "Keenio - 1", severity: 'issue',
        patterns: [new RegExp("(?:keen).{0,40}\\b([0-9a-z]{24})\\b", 'gi')],
        description: 'Detected sensitive pattern: Keenio - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_keenio_2', name: "Keenio - 2", severity: 'issue',
        patterns: [new RegExp("(?:keen).{0,40}\\b([0-9A-Z]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Keenio - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_kickbox', name: "Kickbox", severity: 'issue',
        patterns: [new RegExp("(?:kickbox).{0,40}\\b([a-zA-Z0-9_]+[a-zA-Z0-9]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Kickbox. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_klipfolio', name: "Klipfolio", severity: 'issue',
        patterns: [new RegExp("(?:klipfolio).{0,40}\\b([0-9a-f]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Klipfolio. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_kontent', name: "Kontent", severity: 'issue',
        patterns: [new RegExp("(?:kontent).{0,40}\\b([a-z0-9-]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Kontent. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_kraken_1', name: "Kraken - 1", severity: 'issue',
        patterns: [new RegExp("(?:kraken).{0,40}\\b([0-9A-Za-z\\/\\+=]{56}[ \"'\\r\\n]{1})", 'gi')],
        description: 'Detected sensitive pattern: Kraken - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_kraken_2', name: "Kraken - 2", severity: 'issue',
        patterns: [new RegExp("(?:kraken).{0,40}\\b([0-9A-Za-z\\/\\+=]{86,88}[ \"'\\r\\n]{1})", 'gi')],
        description: 'Detected sensitive pattern: Kraken - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_kucoin_1', name: "Kucoin - 1", severity: 'issue',
        patterns: [new RegExp("(?:kucoin).{0,40}([ \\r\\n]{1}[!-~]{7,32}[ \\r\\n]{1})", 'gi')],
        description: 'Detected sensitive pattern: Kucoin - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_kucoin_2', name: "Kucoin - 2", severity: 'issue',
        patterns: [new RegExp("(?:kucoin).{0,40}\\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Kucoin - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_kucoin_3', name: "Kucoin - 3", severity: 'issue',
        patterns: [new RegExp("(?:kucoin).{0,40}\\b([0-9a-f]{24})\\b", 'gi')],
        description: 'Detected sensitive pattern: Kucoin - 3. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_kylas', name: "Kylas", severity: 'issue',
        patterns: [new RegExp("(?:kylas).{0,40}\\b([a-z0-9-]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Kylas. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_languagelayer', name: "Languagelayer", severity: 'issue',
        patterns: [new RegExp("(?:languagelayer).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Languagelayer. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_lastfm', name: "Lastfm", severity: 'issue',
        patterns: [new RegExp("(?:lastfm).{0,40}\\b([0-9a-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Lastfm. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_launchdarkly', name: "Launchdarkly", severity: 'issue',
        patterns: [new RegExp("(?:launchdarkly).{0,40}\\b([a-z0-9-]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Launchdarkly. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_leadfeeder', name: "Leadfeeder", severity: 'issue',
        patterns: [new RegExp("(?:leadfeeder).{0,40}\\b([a-zA-Z0-9-]{43})\\b", 'gi')],
        description: 'Detected sensitive pattern: Leadfeeder. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_lendflow', name: "Lendflow", severity: 'issue',
        patterns: [new RegExp("(?:lendflow).{0,40}\\b([a-zA-Z0-9]{36}\\.[a-zA-Z0-9]{235}\\.[a-zA-Z0-9]{32}\\-[a-zA-Z0-9]{47}\\-[a-zA-Z0-9_]{162}\\-[a-zA-Z0-9]{42}\\-[a-zA-Z0-9_]{40}\\-[a-zA-Z0-9_]{66}\\-[a-zA-Z0-9_]{59}\\-[a-zA-Z0-9]{7}\\-[a-zA-Z0-9_]{220})\\b", 'gi')],
        description: 'Detected sensitive pattern: Lendflow. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_lessannoyingcrm', name: "Lessannoyingcrm", severity: 'issue',
        patterns: [new RegExp("(?:less).{0,40}\\b([a-zA-Z0-9-]{57})\\b", 'gi')],
        description: 'Detected sensitive pattern: Lessannoyingcrm. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_lexigram', name: "Lexigram", severity: 'issue',
        patterns: [new RegExp("(?:lexigram).{0,40}\\b([a-zA-Z0-9\\S]{301})\\b", 'gi')],
        description: 'Detected sensitive pattern: Lexigram. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_linearapi', name: "Linearapi", severity: 'issue',
        patterns: [new RegExp("\\b(lin_api_[0-9A-Za-z]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Linearapi. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_linemessaging', name: "Linemessaging", severity: 'issue',
        patterns: [new RegExp("(?:line).{0,40}\\b([A-Za-z0-9+/]{171,172})\\b", 'gi')],
        description: 'Detected sensitive pattern: Linemessaging. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_linenotify', name: "Linenotify", severity: 'issue',
        patterns: [new RegExp("(?:linenotify).{0,40}\\b([0-9A-Za-z]{43})\\b", 'gi')],
        description: 'Detected sensitive pattern: Linenotify. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_linkpreview', name: "Linkpreview", severity: 'issue',
        patterns: [new RegExp("(?:linkpreview).{0,40}\\b([a-zA-Z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Linkpreview. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_liveagent', name: "Liveagent", severity: 'issue',
        patterns: [new RegExp("(?:liveagent).{0,40}\\b([a-zA-Z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Liveagent. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_livestorm', name: "Livestorm", severity: 'issue',
        patterns: [new RegExp("(?:livestorm).{0,40}\\b(eyJhbGciOiJIUzI1NiJ9\\.eyJhdWQiOiJhcGkubGl2ZXN0b3JtLmNvIiwianRpIjoi[0-9A-Z-a-z]{134}\\.[0-9A-Za-z\\-\\_]{43}[\\r\\n]{1})", 'gi')],
        description: 'Detected sensitive pattern: Livestorm. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_locationiq', name: "Locationiq", severity: 'issue',
        patterns: [new RegExp("\\b(pk\\.[a-zA-Z-0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Locationiq. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_loginradius', name: "Loginradius", severity: 'issue',
        patterns: [new RegExp("(?:loginradius).{0,40}\\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Loginradius. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_lokalisetoken', name: "Lokalisetoken", severity: 'issue',
        patterns: [new RegExp("(?:lokalise).{0,40}\\b([a-z0-9]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Lokalisetoken. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_loyverse', name: "Loyverse", severity: 'issue',
        patterns: [new RegExp("(?:loyverse).{0,40}\\b([0-9-a-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Loyverse. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_luno_1', name: "Luno - 1", severity: 'issue',
        patterns: [new RegExp("(?:luno).{0,40}\\b([a-z0-9]{13})\\b", 'gi')],
        description: 'Detected sensitive pattern: Luno - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_luno_2', name: "Luno - 2", severity: 'issue',
        patterns: [new RegExp("(?:luno).{0,40}\\b([a-zA-Z0-9_-]{43})\\b", 'gi')],
        description: 'Detected sensitive pattern: Luno - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_m3o', name: "M3o", severity: 'issue',
        patterns: [new RegExp("(?:m3o).{0,40}\\b([0-9A-Za-z]{48})\\b", 'gi')],
        description: 'Detected sensitive pattern: M3o. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_macaddress', name: "Macaddress", severity: 'issue',
        patterns: [new RegExp("(?:macaddress).{0,40}\\b([a-zA-Z0-9_]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Macaddress. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_madkudu', name: "Madkudu", severity: 'issue',
        patterns: [new RegExp("(?:madkudu).{0,40}\\b([0-9a-f]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Madkudu. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_magnetic', name: "Magnetic", severity: 'issue',
        patterns: [new RegExp("(?:magnetic).{0,40}\\b([0-9Aa-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Magnetic. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mailchimp_api_key', name: "MailChimp API Key", severity: 'issue',
        patterns: [new RegExp("[0-9a-f]{32}-us[0-9]{1,2}", 'gi')],
        description: 'Detected sensitive pattern: MailChimp API Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mailboxlayer', name: "Mailboxlayer", severity: 'issue',
        patterns: [new RegExp("(?:mailboxlayer).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Mailboxlayer. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mailerlite', name: "Mailerlite", severity: 'issue',
        patterns: [new RegExp("(?:mailerlite).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Mailerlite. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mailgun_2', name: "Mailgun - 2", severity: 'issue',
        patterns: [new RegExp("(?:mailgun).{0,40}\\b([a-zA-Z-0-9]{72})\\b", 'gi')],
        description: 'Detected sensitive pattern: Mailgun - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mailgun_api_key_1', name: "Mailgun API Key - 1", severity: 'issue',
        patterns: [new RegExp("key-[0-9a-zA-Z]{32}", 'gi')],
        description: 'Detected sensitive pattern: Mailgun API Key - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mailgun_api_key_2', name: "Mailgun API key - 2", severity: 'issue',
        patterns: [new RegExp("(mailgun|mg)[0-9a-z]{32}", 'gi')],
        description: 'Detected sensitive pattern: Mailgun API key - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mailjetbasicauth', name: "Mailjetbasicauth", severity: 'issue',
        patterns: [new RegExp("(?:mailjet).{0,40}\\b([A-Za-z0-9]{87}\\=)", 'gi')],
        description: 'Detected sensitive pattern: Mailjetbasicauth. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mailjetsms', name: "Mailjetsms", severity: 'issue',
        patterns: [new RegExp("(?:mailjet).{0,40}\\b([A-Za-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Mailjetsms. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mailmodo', name: "Mailmodo", severity: 'issue',
        patterns: [new RegExp("(?:mailmodo).{0,40}\\b([A-Z0-9]{7}-[A-Z0-9]{7}-[A-Z0-9]{7}-[A-Z0-9]{7})\\b", 'gi')],
        description: 'Detected sensitive pattern: Mailmodo. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mailsac', name: "Mailsac", severity: 'issue',
        patterns: [new RegExp("(?:mailsac).{0,40}\\b(k_[0-9A-Za-z]{36,})\\b", 'gi')],
        description: 'Detected sensitive pattern: Mailsac. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mandrill', name: "Mandrill", severity: 'issue',
        patterns: [new RegExp("(?:mandrill).{0,40}\\b([A-Za-z0-9_-]{22})\\b", 'gi')],
        description: 'Detected sensitive pattern: Mandrill. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_manifest', name: "Manifest", severity: 'issue',
        patterns: [new RegExp("(?:manifest).{0,40}\\b([a-zA-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Manifest. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mapbox_2', name: "Mapbox - 2", severity: 'issue',
        patterns: [new RegExp("\\b(sk\\.[a-zA-Z-0-9\\.]{80,240})\\b", 'gi')],
        description: 'Detected sensitive pattern: Mapbox - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mapquest', name: "Mapquest", severity: 'issue',
        patterns: [new RegExp("(?:mapquest).{0,40}\\b([0-9A-Za-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Mapquest. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_marketstack', name: "Marketstack", severity: 'issue',
        patterns: [new RegExp("(?:marketstack).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Marketstack. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mattermostpersonaltoken_1', name: "Mattermostpersonaltoken - 1", severity: 'issue',
        patterns: [new RegExp("(?:mattermost).{0,40}\\b([A-Za-z0-9-_]{1,}.cloud.mattermost.com)\\b", 'gi')],
        description: 'Detected sensitive pattern: Mattermostpersonaltoken - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mattermostpersonaltoken_2', name: "Mattermostpersonaltoken - 2", severity: 'issue',
        patterns: [new RegExp("(?:mattermost).{0,40}\\b([a-z0-9]{26})\\b", 'gi')],
        description: 'Detected sensitive pattern: Mattermostpersonaltoken - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mavenlink', name: "Mavenlink", severity: 'issue',
        patterns: [new RegExp("(?:mavenlink).{0,40}\\b([0-9a-z]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Mavenlink. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_maxmindlicense_1', name: "Maxmindlicense - 1", severity: 'issue',
        patterns: [new RegExp("(?:maxmind|geoip).{0,40}\\b([0-9A-Za-z]{16})\\b", 'gi')],
        description: 'Detected sensitive pattern: Maxmindlicense - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_maxmindlicense_2', name: "Maxmindlicense - 2", severity: 'issue',
        patterns: [new RegExp("(?:maxmind|geoip).{0,40}\\b([0-9]{2,7})\\b", 'gi')],
        description: 'Detected sensitive pattern: Maxmindlicense - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_meaningcloud', name: "Meaningcloud", severity: 'issue',
        patterns: [new RegExp("(?:meaningcloud).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Meaningcloud. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mediastack', name: "Mediastack", severity: 'issue',
        patterns: [new RegExp("(?:mediastack).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Mediastack. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_meistertask', name: "Meistertask", severity: 'issue',
        patterns: [new RegExp("(?:meistertask).{0,40}\\b([a-zA-Z0-9]{43})\\b", 'gi')],
        description: 'Detected sensitive pattern: Meistertask. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mesibo', name: "Mesibo", severity: 'issue',
        patterns: [new RegExp("(?:mesibo).{0,40}\\b([0-9A-Za-z]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Mesibo. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_messagebird', name: "Messagebird", severity: 'issue',
        patterns: [new RegExp("(?:messagebird).{0,40}\\b([A-Za-z0-9_-]{25})\\b", 'gi')],
        description: 'Detected sensitive pattern: Messagebird. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_metaapi_1', name: "Metaapi - 1", severity: 'issue',
        patterns: [new RegExp("(?:metaapi|meta-api).{0,40}\\b([0-9a-f]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Metaapi - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_metaapi_2', name: "Metaapi - 2", severity: 'issue',
        patterns: [new RegExp("(?:metaapi|meta-api).{0,40}\\b([0-9a-f]{24})\\b", 'gi')],
        description: 'Detected sensitive pattern: Metaapi - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_metrilo', name: "Metrilo", severity: 'issue',
        patterns: [new RegExp("(?:metrilo).{0,40}\\b([a-z0-9]{16})\\b", 'gi')],
        description: 'Detected sensitive pattern: Metrilo. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_microsoft_teams_webhook', name: "Microsoft Teams Webhook", severity: 'issue',
        patterns: [new RegExp("https://outlook\\.office\\.com/webhook/[A-Za-z0-9\\-@]+/IncomingWebhook/[A-Za-z0-9\\-]+/[A-Za-z0-9\\-]+", 'gi')],
        description: 'Detected sensitive pattern: Microsoft Teams Webhook. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_microsoftteamswebhook', name: "Microsoftteamswebhook", severity: 'issue',
        patterns: [new RegExp("(https:\\/\\/[a-zA-Z-0-9]+\\.webhook\\.office\\.com\\/webhookb2\\/[a-zA-Z-0-9]{8}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{12}\\@[a-zA-Z-0-9]{8}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{12}\\/IncomingWebhook\\/[a-zA-Z-0-9]{32}\\/[a-zA-Z-0-9]{8}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{12})", 'gi')],
        description: 'Detected sensitive pattern: Microsoftteamswebhook. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_midise', name: "Midise", severity: 'issue',
        patterns: [new RegExp("midi-662b69edd2[a-zA-Z0-9]{54}", 'gi')],
        description: 'Detected sensitive pattern: Midise. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mindmeister', name: "Mindmeister", severity: 'issue',
        patterns: [new RegExp("(?:mindmeister).{0,40}\\b([a-zA-Z0-9]{43})\\b", 'gi')],
        description: 'Detected sensitive pattern: Mindmeister. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mite_1', name: "Mite - 1", severity: 'issue',
        patterns: [new RegExp("(?:mite).{0,40}\\b([0-9a-z]{16})\\b", 'gi')],
        description: 'Detected sensitive pattern: Mite - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mite_2', name: "Mite - 2", severity: 'issue',
        patterns: [new RegExp("\\b([0-9a-z-]{1,}.mite.yo.lk)\\b", 'gi')],
        description: 'Detected sensitive pattern: Mite - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mixmax', name: "Mixmax", severity: 'issue',
        patterns: [new RegExp("(?:mixmax).{0,40}\\b([a-zA-Z0-9_-]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Mixmax. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mixpanel_1', name: "Mixpanel - 1", severity: 'issue',
        patterns: [new RegExp("(?:mixpanel).{0,40}\\b([a-zA-Z0-9.-]{30,40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Mixpanel - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mixpanel_2', name: "Mixpanel - 2", severity: 'issue',
        patterns: [new RegExp("(?:mixpanel).{0,40}\\b([a-zA-Z0-9-]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Mixpanel - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_moderation', name: "Moderation", severity: 'issue',
        patterns: [new RegExp("(?:moderation).{0,40}\\b([a-zA-Z0-9]{36}\\.[a-zA-Z0-9]{115}\\.[a-zA-Z0-9_]{43})\\b", 'gi')],
        description: 'Detected sensitive pattern: Moderation. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_monday', name: "Monday", severity: 'issue',
        patterns: [new RegExp("(?:monday).{0,40}\\b(ey[a-zA-Z0-9_.]{210,225})\\b", 'gi')],
        description: 'Detected sensitive pattern: Monday. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_moonclerck', name: "Moonclerck", severity: 'issue',
        patterns: [new RegExp("(?:moonclerck).{0,40}\\b([0-9a-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Moonclerck. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_moonclerk', name: "Moonclerk", severity: 'issue',
        patterns: [new RegExp("(?:moonclerk).{0,40}\\b([0-9a-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Moonclerk. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_moosend', name: "Moosend", severity: 'issue',
        patterns: [new RegExp("(?:moosend).{0,40}\\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Moosend. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mrticktock_1', name: "Mrticktock - 1", severity: 'issue',
        patterns: [new RegExp("(?:mrticktock).{0,40}\\b([a-zA-Z0-9!=@#$%()_^]{1,50})", 'gi')],
        description: 'Detected sensitive pattern: Mrticktock - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_myfreshworks_2', name: "Myfreshworks - 2", severity: 'issue',
        patterns: [new RegExp("(?:freshworks).{0,40}\\b([a-z0-9A-Z-]{22})\\b", 'gi')],
        description: 'Detected sensitive pattern: Myfreshworks - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_myintervals', name: "Myintervals", severity: 'issue',
        patterns: [new RegExp("(?:myintervals).{0,40}\\b([0-9a-z]{11})\\b", 'gi')],
        description: 'Detected sensitive pattern: Myintervals. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_nasdaqdatalink', name: "Nasdaqdatalink", severity: 'issue',
        patterns: [new RegExp("(?:nasdaq).{0,40}\\b([a-zA-Z0-9_-]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Nasdaqdatalink. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_nethunt_1', name: "Nethunt - 1", severity: 'issue',
        patterns: [new RegExp("(?:nethunt).{0,40}\\b([a-zA-Z0-9.-@]{25,30})\\b", 'gi')],
        description: 'Detected sensitive pattern: Nethunt - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_nethunt_2', name: "Nethunt - 2", severity: 'issue',
        patterns: [new RegExp("(?:nethunt).{0,40}\\b([a-z0-9-\\S]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Nethunt - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_netlify', name: "Netlify", severity: 'issue',
        patterns: [new RegExp("(?:netlify).{0,40}\\b([A-Za-z0-9_-]{43,45})\\b", 'gi')],
        description: 'Detected sensitive pattern: Netlify. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_neutrinoapi_1', name: "Neutrinoapi - 1", severity: 'issue',
        patterns: [new RegExp("(?:neutrinoapi).{0,40}\\b([a-zA-Z0-9]{48})\\b", 'gi')],
        description: 'Detected sensitive pattern: Neutrinoapi - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_neutrinoapi_2', name: "Neutrinoapi - 2", severity: 'issue',
        patterns: [new RegExp("(?:neutrinoapi).{0,40}\\b([a-zA-Z0-9]{6,24})\\b", 'gi')],
        description: 'Detected sensitive pattern: Neutrinoapi - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_newrelic_admin_api_key', name: "Newrelic Admin API Key", severity: 'issue',
        patterns: [new RegExp("NRAA-[a-f0-9]{27}", 'gi')],
        description: 'Detected sensitive pattern: Newrelic Admin API Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_newrelic_insights_api_key', name: "Newrelic Insights API Key", severity: 'issue',
        patterns: [new RegExp("NRI(?:I|Q)-[A-Za-z0-9\\-_]{32}", 'gi')],
        description: 'Detected sensitive pattern: Newrelic Insights API Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_newrelic_rest_api_key', name: "Newrelic REST API Key", severity: 'issue',
        patterns: [new RegExp("NRRA-[a-f0-9]{42}", 'gi')],
        description: 'Detected sensitive pattern: Newrelic REST API Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_newrelic_synthetics_location_key', name: "Newrelic Synthetics Location Key", severity: 'issue',
        patterns: [new RegExp("NRSP-[a-z]{2}[0-9]{2}[a-f0-9]{31}", 'gi')],
        description: 'Detected sensitive pattern: Newrelic Synthetics Location Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_newrelicpersonalapikey', name: "Newrelicpersonalapikey", severity: 'issue',
        patterns: [new RegExp("(?:newrelic).{0,40}\\b([A-Za-z0-9_\\.]{4}-[A-Za-z0-9_\\.]{42})\\b", 'gi')],
        description: 'Detected sensitive pattern: Newrelicpersonalapikey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_newsapi', name: "Newsapi", severity: 'issue',
        patterns: [new RegExp("(?:newsapi).{0,40}\\b([a-z0-9]{32})", 'gi')],
        description: 'Detected sensitive pattern: Newsapi. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_newscatcher', name: "Newscatcher", severity: 'issue',
        patterns: [new RegExp("(?:newscatcher).{0,40}\\b([0-9A-Za-z_]{43})\\b", 'gi')],
        description: 'Detected sensitive pattern: Newscatcher. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_nexmoapikey_1', name: "Nexmoapikey - 1", severity: 'issue',
        patterns: [new RegExp("(?:nexmo).{0,40}\\b([A-Za-z0-9_-]{8})\\b", 'gi')],
        description: 'Detected sensitive pattern: Nexmoapikey - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_nexmoapikey_2', name: "Nexmoapikey - 2", severity: 'issue',
        patterns: [new RegExp("(?:nexmo).{0,40}\\b([A-Za-z0-9_-]{16})\\b", 'gi')],
        description: 'Detected sensitive pattern: Nexmoapikey - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_nftport', name: "Nftport", severity: 'issue',
        patterns: [new RegExp("(?:nftport).{0,40}\\b([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Nftport. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_nicereply', name: "Nicereply", severity: 'issue',
        patterns: [new RegExp("(?:nicereply).{0,40}\\b([0-9a-f]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Nicereply. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_nimble', name: "Nimble", severity: 'issue',
        patterns: [new RegExp("(?:nimble).{0,40}\\b([a-zA-Z0-9]{30})\\b", 'gi')],
        description: 'Detected sensitive pattern: Nimble. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_nitro', name: "Nitro", severity: 'issue',
        patterns: [new RegExp("(?:nitro).{0,40}\\b([0-9a-f]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Nitro. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_noticeable', name: "Noticeable", severity: 'issue',
        patterns: [new RegExp("(?:noticeable).{0,40}\\b([0-9a-zA-Z]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Noticeable. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_notion', name: "Notion", severity: 'issue',
        patterns: [new RegExp("\\b(secret_[A-Za-z0-9]{43})\\b", 'gi')],
        description: 'Detected sensitive pattern: Notion. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_nozbeteams', name: "Nozbeteams", severity: 'issue',
        patterns: [new RegExp("(?:nozbe|nozbeteams).{0,40}\\b([0-9A-Za-z]{16}_[0-9A-Za-z\\-_]{64}[ \\r\\n]{1})", 'gi')],
        description: 'Detected sensitive pattern: Nozbeteams. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_numverify', name: "Numverify", severity: 'issue',
        patterns: [new RegExp("(?:numverify).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Numverify. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_nutritionix_1', name: "Nutritionix - 1", severity: 'issue',
        patterns: [new RegExp("(?:nutritionix).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Nutritionix - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_nutritionix_2', name: "Nutritionix - 2", severity: 'issue',
        patterns: [new RegExp("(?:nutritionix).{0,40}\\b([a-z0-9]{8})\\b", 'gi')],
        description: 'Detected sensitive pattern: Nutritionix - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_nylas', name: "Nylas", severity: 'issue',
        patterns: [new RegExp("(?:nylas).{0,40}\\b([0-9A-Za-z]{30})\\b", 'gi')],
        description: 'Detected sensitive pattern: Nylas. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_nytimes', name: "Nytimes", severity: 'issue',
        patterns: [new RegExp("(?:nytimes).{0,40}\\b([a-z0-9A-Z-]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Nytimes. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_oanda', name: "Oanda", severity: 'issue',
        patterns: [new RegExp("(?:oanda).{0,40}\\b([a-zA-Z0-9]{24})\\b", 'gi')],
        description: 'Detected sensitive pattern: Oanda. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_omnisend', name: "Omnisend", severity: 'issue',
        patterns: [new RegExp("(?:omnisend).{0,40}\\b([a-z0-9A-Z-]{75})\\b", 'gi')],
        description: 'Detected sensitive pattern: Omnisend. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_onedesk_1', name: "Onedesk - 1", severity: 'issue',
        patterns: [new RegExp("(?:onedesk).{0,40}\\b([a-zA-Z0-9!=@#$%^]{8,64})", 'gi')],
        description: 'Detected sensitive pattern: Onedesk - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_onelogin_2', name: "Onelogin - 2", severity: 'issue',
        patterns: [new RegExp("secret[a-zA-Z0-9_' \"=]{0,20}([a-z0-9]{64})", 'gi')],
        description: 'Detected sensitive pattern: Onelogin - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_onepagecrm_1', name: "Onepagecrm - 1", severity: 'issue',
        patterns: [new RegExp("(?:onepagecrm).{0,40}\\b([a-zA-Z0-9=]{44})", 'gi')],
        description: 'Detected sensitive pattern: Onepagecrm - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_onepagecrm_2', name: "Onepagecrm - 2", severity: 'issue',
        patterns: [new RegExp("(?:onepagecrm).{0,40}\\b([a-z0-9]{24})\\b", 'gi')],
        description: 'Detected sensitive pattern: Onepagecrm - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_onwaterio', name: "Onwaterio", severity: 'issue',
        patterns: [new RegExp("(?:onwater).{0,40}\\b([a-zA-Z0-9_-]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Onwaterio. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_oopspam', name: "Oopspam", severity: 'issue',
        patterns: [new RegExp("(?:oopspam).{0,40}\\b([a-zA-Z0-9]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Oopspam. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_opencagedata', name: "Opencagedata", severity: 'issue',
        patterns: [new RegExp("(?:opencagedata).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Opencagedata. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_opengraphr', name: "Opengraphr", severity: 'issue',
        patterns: [new RegExp("(?:opengraphr).{0,40}\\b([0-9Aa-zA-Z]{80})\\b", 'gi')],
        description: 'Detected sensitive pattern: Opengraphr. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_openuv', name: "Openuv", severity: 'issue',
        patterns: [new RegExp("(?:openuv).{0,40}\\b([0-9a-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Openuv. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_openweather', name: "Openweather", severity: 'issue',
        patterns: [new RegExp("(?:openweather).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Openweather. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_optimizely', name: "Optimizely", severity: 'issue',
        patterns: [new RegExp("(?:optimizely).{0,40}\\b([0-9A-Za-z-:]{54})\\b", 'gi')],
        description: 'Detected sensitive pattern: Optimizely. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_owlbot', name: "Owlbot", severity: 'issue',
        patterns: [new RegExp("(?:owlbot).{0,40}\\b([a-z0-9]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Owlbot. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_pgp_private_key_block', name: "PGP private key block", severity: 'issue',
        patterns: [new RegExp("-----BEGIN PGP PRIVATE KEY BLOCK-----", 'gi')],
        description: 'Detected sensitive pattern: PGP private key block. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_pagerdutyapikey', name: "Pagerdutyapikey", severity: 'issue',
        patterns: [new RegExp("(?:pagerduty).{0,40}\\b([a-z]{1}\\+[a-zA-Z]{9}\\-[a-z]{2}\\-[a-z0-9]{5})\\b", 'gi')],
        description: 'Detected sensitive pattern: Pagerdutyapikey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_pandadoc', name: "Pandadoc", severity: 'issue',
        patterns: [new RegExp("(?:pandadoc).{0,40}\\b([a-zA-Z0-9]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Pandadoc. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_pandascore', name: "Pandascore", severity: 'issue',
        patterns: [new RegExp("(?:pandascore).{0,40}([ \\r\\n]{0,1}[0-9A-Za-z\\-\\_]{51}[ \\r\\n]{1})", 'gi')],
        description: 'Detected sensitive pattern: Pandascore. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_paralleldots', name: "Paralleldots", severity: 'issue',
        patterns: [new RegExp("(?:paralleldots).{0,40}\\b([0-9A-Za-z]{43})\\b", 'gi')],
        description: 'Detected sensitive pattern: Paralleldots. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_partnerstack', name: "Partnerstack", severity: 'issue',
        patterns: [new RegExp("(?:partnerstack).{0,40}\\b([0-9A-Za-z]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Partnerstack. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_passbase', name: "Passbase", severity: 'issue',
        patterns: [new RegExp("(?:passbase).{0,40}\\b([a-zA-Z0-9]{128})\\b", 'gi')],
        description: 'Detected sensitive pattern: Passbase. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_password_in_url', name: "Password in URL", severity: 'issue',
        patterns: [new RegExp("[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"''\\s]", 'gi')],
        description: 'Detected sensitive pattern: Password in URL. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_pastebin', name: "Pastebin", severity: 'issue',
        patterns: [new RegExp("(?:pastebin).{0,40}\\b([a-zA-Z0-9_]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Pastebin. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_paypal_braintree_access_token', name: "PayPal Braintree access token", severity: 'issue',
        patterns: [new RegExp("access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}", 'gi')],
        description: 'Detected sensitive pattern: PayPal Braintree access token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_paymoapp', name: "Paymoapp", severity: 'issue',
        patterns: [new RegExp("(?:paymoapp).{0,40}\\b([a-zA-Z0-9]{44})\\b", 'gi')],
        description: 'Detected sensitive pattern: Paymoapp. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_paymongo', name: "Paymongo", severity: 'issue',
        patterns: [new RegExp("(?:paymongo).{0,40}\\b([a-zA-Z0-9_]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Paymongo. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_paypaloauth_1', name: "Paypaloauth - 1", severity: 'issue',
        patterns: [new RegExp("\\b([A-Za-z0-9_\\.]{7}-[A-Za-z0-9_\\.]{72})\\b", 'gi')],
        description: 'Detected sensitive pattern: Paypaloauth - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_paypaloauth_2', name: "Paypaloauth - 2", severity: 'issue',
        patterns: [new RegExp("\\b([A-Za-z0-9_\\.]{69}-[A-Za-z0-9_\\.]{10})\\b", 'gi')],
        description: 'Detected sensitive pattern: Paypaloauth - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_paystack', name: "Paystack", severity: 'issue',
        patterns: [new RegExp("\\b(sk\\_[a-z]{1,}\\_[A-Za-z0-9]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Paystack. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_pdflayer', name: "Pdflayer", severity: 'issue',
        patterns: [new RegExp("(?:pdflayer).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Pdflayer. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_pdfshift', name: "Pdfshift", severity: 'issue',
        patterns: [new RegExp("(?:pdfshift).{0,40}\\b([0-9a-f]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Pdfshift. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_peopledatalabs', name: "Peopledatalabs", severity: 'issue',
        patterns: [new RegExp("(?:peopledatalabs).{0,40}\\b([a-z0-9]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Peopledatalabs. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_pepipost', name: "Pepipost", severity: 'issue',
        patterns: [new RegExp("(?:pepipost|netcore).{0,40}\\b([a-zA-Z-0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Pepipost. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_picatic_api_key', name: "Picatic API key", severity: 'issue',
        patterns: [new RegExp("sk_live_[0-9a-z]{32}", 'gi')],
        description: 'Detected sensitive pattern: Picatic API key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_pipedream', name: "Pipedream", severity: 'issue',
        patterns: [new RegExp("(?:pipedream).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Pipedream. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_pipedrive', name: "Pipedrive", severity: 'issue',
        patterns: [new RegExp("(?:pipedrive).{0,40}\\b([a-zA-Z0-9]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Pipedrive. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_pivotaltracker', name: "Pivotaltracker", severity: 'issue',
        patterns: [new RegExp("(?:pivotal).{0,40}([a-z0-9]{32})", 'gi')],
        description: 'Detected sensitive pattern: Pivotaltracker. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_pixabay', name: "Pixabay", severity: 'issue',
        patterns: [new RegExp("(?:pixabay).{0,40}\\b([a-z0-9-]{34})\\b", 'gi')],
        description: 'Detected sensitive pattern: Pixabay. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_plaidkey_1', name: "Plaidkey - 1", severity: 'issue',
        patterns: [new RegExp("(?:plaid).{0,40}\\b([a-z0-9]{24})\\b", 'gi')],
        description: 'Detected sensitive pattern: Plaidkey - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_plaidkey_2', name: "Plaidkey - 2", severity: 'issue',
        patterns: [new RegExp("(?:plaid).{0,40}\\b([a-z0-9]{30})\\b", 'gi')],
        description: 'Detected sensitive pattern: Plaidkey - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_planviewleankit_1', name: "Planviewleankit - 1", severity: 'issue',
        patterns: [new RegExp("(?:planviewleankit|planview).{0,40}\\b([0-9a-f]{128})\\b", 'gi')],
        description: 'Detected sensitive pattern: Planviewleankit - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_planviewleankit_2', name: "Planviewleankit - 2", severity: 'issue',
        patterns: [new RegExp("(?:planviewleankit|planview).{0,40}(?:subdomain).\\b([a-zA-Z][a-zA-Z0-9.-]{1,23}[a-zA-Z0-9])\\b", 'gi')],
        description: 'Detected sensitive pattern: Planviewleankit - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_planyo', name: "Planyo", severity: 'issue',
        patterns: [new RegExp("(?:planyo).{0,40}\\b([0-9a-z]{62})\\b", 'gi')],
        description: 'Detected sensitive pattern: Planyo. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_plivo_1', name: "Plivo - 1", severity: 'issue',
        patterns: [new RegExp("(?:plivo).{0,40}\\b([A-Za-z0-9_-]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Plivo - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_plivo_2', name: "Plivo - 2", severity: 'issue',
        patterns: [new RegExp("(?:plivo).{0,40}\\b([A-Z]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Plivo - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_poloniex_1', name: "Poloniex - 1", severity: 'issue',
        patterns: [new RegExp("(?:poloniex).{0,40}\\b([0-9a-f]{128})\\b", 'gi')],
        description: 'Detected sensitive pattern: Poloniex - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_poloniex_2', name: "Poloniex - 2", severity: 'issue',
        patterns: [new RegExp("(?:poloniex).{0,40}\\b([0-9A-Z]{8}-[0-9A-Z]{8}-[0-9A-Z]{8}-[0-9A-Z]{8})\\b", 'gi')],
        description: 'Detected sensitive pattern: Poloniex - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_polygon', name: "Polygon", severity: 'issue',
        patterns: [new RegExp("(?:polygon).{0,40}\\b([a-z0-9A-Z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Polygon. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_positionstack', name: "Positionstack", severity: 'issue',
        patterns: [new RegExp("(?:positionstack).{0,40}\\b([a-zA-Z0-9_]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Positionstack. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_postageapp', name: "Postageapp", severity: 'issue',
        patterns: [new RegExp("(?:postageapp).{0,40}\\b([0-9A-Za-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Postageapp. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_posthog', name: "Posthog", severity: 'issue',
        patterns: [new RegExp("\\b(phc_[a-zA-Z0-9_]{43})\\b", 'gi')],
        description: 'Detected sensitive pattern: Posthog. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_postman', name: "Postman", severity: 'issue',
        patterns: [new RegExp("\\b(PMAK-[a-zA-Z-0-9]{59})\\b", 'gi')],
        description: 'Detected sensitive pattern: Postman. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_postmark', name: "Postmark", severity: 'issue',
        patterns: [new RegExp("(?:postmark).{0,40}\\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Postmark. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_powrbot', name: "Powrbot", severity: 'issue',
        patterns: [new RegExp("(?:powrbot).{0,40}\\b([a-z0-9A-Z]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Powrbot. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_privatekey', name: "Privatekey", severity: 'issue',
        patterns: [new RegExp("'-----\\s*?BEGIN[ A-Z0-9_-]*?PRIVATE KEY\\s*?-----[\\s\\S]*?----\\s*?END[ A-Z0-9_-]*?", 'gi')],
        description: 'Detected sensitive pattern: Privatekey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_prospectcrm', name: "Prospectcrm", severity: 'issue',
        patterns: [new RegExp("(?:prospect).{0,40}\\b([a-z0-9-]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Prospectcrm. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_prospectio', name: "Prospectio", severity: 'issue',
        patterns: [new RegExp("(?:prospect).{0,40}\\b([a-z0-9A-Z-]{50})\\b", 'gi')],
        description: 'Detected sensitive pattern: Prospectio. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_protocolsio', name: "Protocolsio", severity: 'issue',
        patterns: [new RegExp("(?:protocols).{0,40}\\b([a-z0-9]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Protocolsio. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_proxycrawl', name: "Proxycrawl", severity: 'issue',
        patterns: [new RegExp("(?:proxycrawl).{0,40}\\b([a-zA-Z0-9_]{22})\\b", 'gi')],
        description: 'Detected sensitive pattern: Proxycrawl. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_pubnubpublishkey_1', name: "Pubnubpublishkey - 1", severity: 'issue',
        patterns: [new RegExp("\\b(sub-c-[0-9a-z]{8}-[a-z]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Pubnubpublishkey - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_pubnubpublishkey_2', name: "Pubnubpublishkey - 2", severity: 'issue',
        patterns: [new RegExp("\\b(pub-c-[0-9a-z]{8}-[0-9a-z]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Pubnubpublishkey - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_purestake', name: "Purestake", severity: 'issue',
        patterns: [new RegExp("(?:purestake).{0,40}\\b([a-zA-Z0-9]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Purestake. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_pushbulletapikey', name: "Pushbulletapikey", severity: 'issue',
        patterns: [new RegExp("(?:pushbullet).{0,40}\\b([A-Za-z0-9_\\.]{34})\\b", 'gi')],
        description: 'Detected sensitive pattern: Pushbulletapikey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_pusherchannelkey_1', name: "Pusherchannelkey - 1", severity: 'issue',
        patterns: [new RegExp("(?:key).{0,40}\\b([a-z0-9]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Pusherchannelkey - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_pusherchannelkey_2', name: "Pusherchannelkey - 2", severity: 'issue',
        patterns: [new RegExp("(?:pusher).{0,40}\\b([a-z0-9]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Pusherchannelkey - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_pusherchannelkey_3', name: "Pusherchannelkey - 3", severity: 'issue',
        patterns: [new RegExp("(?:pusher).{0,40}\\b([0-9]{7})\\b", 'gi')],
        description: 'Detected sensitive pattern: Pusherchannelkey - 3. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_pypi_upload_token', name: "PyPI upload token", severity: 'issue',
        patterns: [new RegExp("pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,1000}", 'gi')],
        description: 'Detected sensitive pattern: PyPI upload token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_qualaroo', name: "Qualaroo", severity: 'issue',
        patterns: [new RegExp("(?:qualaroo).{0,40}\\b([a-z0-9A-Z=]{64})", 'gi')],
        description: 'Detected sensitive pattern: Qualaroo. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_qubole', name: "Qubole", severity: 'issue',
        patterns: [new RegExp("(?:qubole).{0,40}\\b([0-9a-z]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Qubole. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_quickmetrics', name: "Quickmetrics", severity: 'issue',
        patterns: [new RegExp("(?:quickmetrics).{0,40}\\b([a-zA-Z0-9_-]{22})\\b", 'gi')],
        description: 'Detected sensitive pattern: Quickmetrics. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_redis_url', name: "REDIS_URL", severity: 'issue',
        patterns: [new RegExp("(REDIS_URL).+", 'gi')],
        description: 'Detected sensitive pattern: REDIS_URL. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_rkcs8', name: "RKCS8", severity: 'issue',
        patterns: [new RegExp("-----BEGIN PRIVATE KEY-----", 'gi')],
        description: 'Detected sensitive pattern: RKCS8. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_rsa_private_key', name: "RSA private key", severity: 'issue',
        patterns: [new RegExp("-----BEGIN RSA PRIVATE KEY-----", 'gi')],
        description: 'Detected sensitive pattern: RSA private key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_rapidapi', name: "Rapidapi", severity: 'issue',
        patterns: [new RegExp("(?:rapidapi).{0,40}\\b([A-Za-z0-9_-]{50})\\b", 'gi')],
        description: 'Detected sensitive pattern: Rapidapi. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_raven', name: "Raven", severity: 'issue',
        patterns: [new RegExp("(?:raven).{0,40}\\b([A-Z0-9-]{16})\\b", 'gi')],
        description: 'Detected sensitive pattern: Raven. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_rawg', name: "Rawg", severity: 'issue',
        patterns: [new RegExp("(?:rawg).{0,40}\\b([0-9Aa-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Rawg. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_razorpay_1', name: "Razorpay - 1", severity: 'issue',
        patterns: [new RegExp("\\brzp_\\w{2,6}_\\w{10,20}\\b", 'gi')],
        description: 'Detected sensitive pattern: Razorpay - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_readme', name: "Readme", severity: 'issue',
        patterns: [new RegExp("(?:readme).{0,40}\\b([a-zA-Z0-9_]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Readme. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_reallysimplesystems', name: "Reallysimplesystems", severity: 'issue',
        patterns: [new RegExp("\\b(ey[a-zA-Z0-9-._]{153}.ey[a-zA-Z0-9-._]{916,1000})\\b", 'gi')],
        description: 'Detected sensitive pattern: Reallysimplesystems. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_rebrandly', name: "Rebrandly", severity: 'issue',
        patterns: [new RegExp("(?:rebrandly).{0,40}\\b([a-zA-Z0-9_]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Rebrandly. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_refiner', name: "Refiner", severity: 'issue',
        patterns: [new RegExp("(?:refiner).{0,40}\\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Refiner. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_repairshopr_1', name: "Repairshopr - 1", severity: 'issue',
        patterns: [new RegExp("(?:repairshopr).{0,40}\\b([a-zA-Z0-9_.!+$#^*]{3,32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Repairshopr - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_repairshopr_2', name: "Repairshopr - 2", severity: 'issue',
        patterns: [new RegExp("(?:repairshopr).{0,40}\\b([a-zA-Z0-9-]{51})\\b", 'gi')],
        description: 'Detected sensitive pattern: Repairshopr - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_restpack', name: "Restpack", severity: 'issue',
        patterns: [new RegExp("(?:restpack).{0,40}\\b([a-zA-Z0-9]{48})\\b", 'gi')],
        description: 'Detected sensitive pattern: Restpack. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_restpackhtmltopdfapi', name: "Restpackhtmltopdfapi", severity: 'issue',
        patterns: [new RegExp("(?:restpack).{0,40}\\b([0-9A-Za-z]{48})\\b", 'gi')],
        description: 'Detected sensitive pattern: Restpackhtmltopdfapi. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_rev_1', name: "Rev - 1", severity: 'issue',
        patterns: [new RegExp("(?:rev).{0,40}\\b([0-9a-zA-Z\\/\\+]{27}\\=[ \\r\\n]{1})", 'gi')],
        description: 'Detected sensitive pattern: Rev - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_rev_2', name: "Rev - 2", severity: 'issue',
        patterns: [new RegExp("(?:rev).{0,40}\\b([0-9a-zA-Z\\-]{27}[ \\r\\n]{1})", 'gi')],
        description: 'Detected sensitive pattern: Rev - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_revampcrm_1', name: "Revampcrm - 1", severity: 'issue',
        patterns: [new RegExp("(?:revamp).{0,40}\\b([a-zA-Z0-9]{40}\\b)", 'gi')],
        description: 'Detected sensitive pattern: Revampcrm - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_revampcrm_2', name: "Revampcrm - 2", severity: 'issue',
        patterns: [new RegExp("(?:revamp).{0,40}\\b([a-zA-Z0-9.-@]{25,30})\\b", 'gi')],
        description: 'Detected sensitive pattern: Revampcrm - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ringcentral_1', name: "Ringcentral - 1", severity: 'issue',
        patterns: [new RegExp("(?:ringcentral).{0,40}\\b(https://www.[0-9A-Za-z_-]{1,}.com)\\b", 'gi')],
        description: 'Detected sensitive pattern: Ringcentral - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ringcentral_2', name: "Ringcentral - 2", severity: 'issue',
        patterns: [new RegExp("(?:ringcentral).{0,40}\\b([0-9A-Za-z_-]{22})\\b", 'gi')],
        description: 'Detected sensitive pattern: Ringcentral - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ritekit', name: "Ritekit", severity: 'issue',
        patterns: [new RegExp("(?:ritekit).{0,40}\\b([0-9a-f]{44})\\b", 'gi')],
        description: 'Detected sensitive pattern: Ritekit. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_roaring', name: "Roaring", severity: 'issue',
        patterns: [new RegExp("(?:roaring).{0,40}\\b([0-9A-Za-z_-]{28})\\b", 'gi')],
        description: 'Detected sensitive pattern: Roaring. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_rocketreach', name: "Rocketreach", severity: 'issue',
        patterns: [new RegExp("(?:rocketreach).{0,40}\\b([a-z0-9-]{39})\\b", 'gi')],
        description: 'Detected sensitive pattern: Rocketreach. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_roninapp_1', name: "Roninapp - 1", severity: 'issue',
        patterns: [new RegExp("(?:ronin).{0,40}\\b([0-9Aa-zA-Z]{3,32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Roninapp - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_roninapp_2', name: "Roninapp - 2", severity: 'issue',
        patterns: [new RegExp("(?:ronin).{0,40}\\b([0-9a-zA-Z]{26})\\b", 'gi')],
        description: 'Detected sensitive pattern: Roninapp - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_route4me', name: "Route4me", severity: 'issue',
        patterns: [new RegExp("(?:route4me).{0,40}\\b([0-9A-Z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Route4me. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_rownd_1', name: "Rownd - 1", severity: 'issue',
        patterns: [new RegExp("(?:rownd).{0,40}\\b([a-z0-9]{8}\\-[a-z0-9]{4}\\-[a-z0-9]{4}\\-[a-z0-9]{4}\\-[a-z0-9]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Rownd - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_rownd_2', name: "Rownd - 2", severity: 'issue',
        patterns: [new RegExp("(?:rownd).{0,40}\\b([a-z0-9]{48})\\b", 'gi')],
        description: 'Detected sensitive pattern: Rownd - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_rownd_3', name: "Rownd - 3", severity: 'issue',
        patterns: [new RegExp("(?:rownd).{0,40}\\b([0-9]{18})\\b", 'gi')],
        description: 'Detected sensitive pattern: Rownd - 3. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_rubygems', name: "Rubygems", severity: 'issue',
        patterns: [new RegExp("\\b(rubygems_[a-zA0-9]{48})\\b", 'gi')],
        description: 'Detected sensitive pattern: Rubygems. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_runrunit_1', name: "Runrunit - 1", severity: 'issue',
        patterns: [new RegExp("(?:runrunit).{0,40}\\b([0-9a-f]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Runrunit - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_runrunit_2', name: "Runrunit - 2", severity: 'issue',
        patterns: [new RegExp("(?:runrunit).{0,40}\\b([0-9A-Za-z]{18,20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Runrunit - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ssh', name: "SSH", severity: 'issue',
        patterns: [new RegExp("-----BEGIN OPENSSH PRIVATE KEY-----", 'gi')],
        description: 'Detected sensitive pattern: SSH. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ssh_dsa_private_key', name: "SSH (DSA) private key", severity: 'issue',
        patterns: [new RegExp("-----BEGIN DSA PRIVATE KEY-----", 'gi')],
        description: 'Detected sensitive pattern: SSH (DSA) private key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_salesblink', name: "Salesblink", severity: 'issue',
        patterns: [new RegExp("(?:salesblink).{0,40}\\b([a-zA-Z]{16})\\b", 'gi')],
        description: 'Detected sensitive pattern: Salesblink. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_salescookie', name: "Salescookie", severity: 'issue',
        patterns: [new RegExp("(?:salescookie).{0,40}\\b([a-zA-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Salescookie. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_salesflare', name: "Salesflare", severity: 'issue',
        patterns: [new RegExp("(?:salesflare).{0,40}\\b([a-zA-Z0-9_]{45})\\b", 'gi')],
        description: 'Detected sensitive pattern: Salesflare. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_satismeterprojectkey_1', name: "Satismeterprojectkey - 1", severity: 'issue',
        patterns: [new RegExp("(?:satismeter).{0,40}\\b([a-zA-Z0-9]{4,20}@[a-zA-Z0-9]{2,12}.[a-zA-Z0-9]{2,12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Satismeterprojectkey - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_satismeterprojectkey_2', name: "Satismeterprojectkey - 2", severity: 'issue',
        patterns: [new RegExp("(?:satismeter).{0,40}\\b([a-zA-Z0-9]{24})\\b", 'gi')],
        description: 'Detected sensitive pattern: Satismeterprojectkey - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_satismeterprojectkey_3', name: "Satismeterprojectkey - 3", severity: 'issue',
        patterns: [new RegExp("(?:satismeter).{0,40}\\b([a-zA-Z0-9!=@#$%^]{6,32})", 'gi')],
        description: 'Detected sensitive pattern: Satismeterprojectkey - 3. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_satismeterwritekey', name: "Satismeterwritekey", severity: 'issue',
        patterns: [new RegExp("(?:satismeter).{0,40}\\b([a-z0-9A-Z]{16})\\b", 'gi')],
        description: 'Detected sensitive pattern: Satismeterwritekey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_saucelabs_1', name: "Saucelabs - 1", severity: 'issue',
        patterns: [new RegExp("\\b(oauth\\-[a-z0-9]{8,}\\-[a-z0-9]{5})\\b", 'gi')],
        description: 'Detected sensitive pattern: Saucelabs - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_saucelabs_2', name: "Saucelabs - 2", severity: 'issue',
        patterns: [new RegExp("(?:saucelabs).{0,40}\\b([a-z0-9]{8}\\-[a-z0-9]{4}\\-[a-z0-9]{4}\\-[a-z0-9]{4}\\-[a-z0-9]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Saucelabs - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_scalewaykey', name: "Scalewaykey", severity: 'issue',
        patterns: [new RegExp("(?:scaleway).{0,40}\\b([0-9a-z]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[0-9a-z]{4}-[0-9a-z]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Scalewaykey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_scrapeowl', name: "Scrapeowl", severity: 'issue',
        patterns: [new RegExp("(?:scrapeowl).{0,40}\\b([0-9a-z]{30})\\b", 'gi')],
        description: 'Detected sensitive pattern: Scrapeowl. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_scraperapi', name: "Scraperapi", severity: 'issue',
        patterns: [new RegExp("(?:scraperapi).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Scraperapi. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_scraperbox', name: "Scraperbox", severity: 'issue',
        patterns: [new RegExp("(?:scraperbox).{0,40}\\b([A-Z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Scraperbox. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_scrapersite', name: "Scrapersite", severity: 'issue',
        patterns: [new RegExp("(?:scrapersite).{0,40}\\b([a-zA-Z0-9]{45})\\b", 'gi')],
        description: 'Detected sensitive pattern: Scrapersite. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_scrapestack', name: "Scrapestack", severity: 'issue',
        patterns: [new RegExp("(?:scrapestack).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Scrapestack. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_scrapfly', name: "Scrapfly", severity: 'issue',
        patterns: [new RegExp("(?:scrapfly).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Scrapfly. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_scrapingant', name: "Scrapingant", severity: 'issue',
        patterns: [new RegExp("(?:scrapingant).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Scrapingant. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_scrapingbee', name: "Scrapingbee", severity: 'issue',
        patterns: [new RegExp("(?:scrapingbee).{0,40}\\b([A-Z0-9]{80})\\b", 'gi')],
        description: 'Detected sensitive pattern: Scrapingbee. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_screenshotapi', name: "Screenshotapi", severity: 'issue',
        patterns: [new RegExp("(?:screenshotapi).{0,40}\\b([0-9A-Z]{7}\\-[0-9A-Z]{7}\\-[0-9A-Z]{7}\\-[0-9A-Z]{7})\\b", 'gi')],
        description: 'Detected sensitive pattern: Screenshotapi. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_screenshotlayer', name: "Screenshotlayer", severity: 'issue',
        patterns: [new RegExp("(?:screenshotlayer).{0,40}\\b([a-zA-Z0-9_]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Screenshotlayer. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_securitytrails', name: "Securitytrails", severity: 'issue',
        patterns: [new RegExp("(?:securitytrails).{0,40}\\b([a-zA-Z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Securitytrails. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_segmentapikey', name: "Segmentapikey", severity: 'issue',
        patterns: [new RegExp("(?:segment).{0,40}\\b([A-Za-z0-9_\\-a-zA-Z]{43}\\.[A-Za-z0-9_\\-a-zA-Z]{43})\\b", 'gi')],
        description: 'Detected sensitive pattern: Segmentapikey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_selectpdf', name: "Selectpdf", severity: 'issue',
        patterns: [new RegExp("(?:selectpdf).{0,40}\\b([a-z0-9-]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Selectpdf. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_semaphore', name: "Semaphore", severity: 'issue',
        patterns: [new RegExp("(?:semaphore).{0,40}\\b([0-9a-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Semaphore. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sendgrid_api_key', name: "SendGrid API Key", severity: 'issue',
        patterns: [new RegExp("SG\\.[\\w_]{16,32}\\.[\\w_]{16,64}", 'gi')],
        description: 'Detected sensitive pattern: SendGrid API Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sendbird_1', name: "Sendbird - 1", severity: 'issue',
        patterns: [new RegExp("(?:sendbird).{0,40}\\b([0-9a-f]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Sendbird - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sendbird_2', name: "Sendbird - 2", severity: 'issue',
        patterns: [new RegExp("(?:sendbird).{0,40}\\b([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Sendbird - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sendbirdorganizationapi', name: "Sendbirdorganizationapi", severity: 'issue',
        patterns: [new RegExp("(?:sendbird).{0,40}\\b([0-9a-f]{24})\\b", 'gi')],
        description: 'Detected sensitive pattern: Sendbirdorganizationapi. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sendgrid', name: "Sendgrid", severity: 'issue',
        patterns: [new RegExp("(?:sendgrid).{0,40}(SG\\.[\\w\\-_]{20,24}\\.[\\w\\-_]{39,50})\\b", 'gi')],
        description: 'Detected sensitive pattern: Sendgrid. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sendinbluev2', name: "Sendinbluev2", severity: 'issue',
        patterns: [new RegExp("\\b(xkeysib\\-[A-Za-z0-9_-]{81})\\b", 'gi')],
        description: 'Detected sensitive pattern: Sendinbluev2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sentiment_1', name: "Sentiment - 1", severity: 'issue',
        patterns: [new RegExp("(?:sentiment).{0,40}\\b([0-9]{17})\\b", 'gi')],
        description: 'Detected sensitive pattern: Sentiment - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sentiment_2', name: "Sentiment - 2", severity: 'issue',
        patterns: [new RegExp("(?:sentiment).{0,40}\\b([a-zA-Z0-9]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Sentiment - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sentrytoken', name: "Sentrytoken", severity: 'issue',
        patterns: [new RegExp("(?:sentry).{0,40}\\b([a-f0-9]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Sentrytoken. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_serphouse', name: "Serphouse", severity: 'issue',
        patterns: [new RegExp("(?:serphouse).{0,40}\\b([0-9A-Za-z]{60})\\b", 'gi')],
        description: 'Detected sensitive pattern: Serphouse. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_serpstack', name: "Serpstack", severity: 'issue',
        patterns: [new RegExp("(?:serpstack).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Serpstack. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sheety_1', name: "Sheety - 1", severity: 'issue',
        patterns: [new RegExp("(?:sheety).{0,40}\\b([0-9a-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Sheety - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sheety_2', name: "Sheety - 2", severity: 'issue',
        patterns: [new RegExp("(?:sheety).{0,40}\\b([0-9a-z]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Sheety - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sherpadesk', name: "Sherpadesk", severity: 'issue',
        patterns: [new RegExp("(?:sherpadesk).{0,40}\\b([0-9a-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Sherpadesk. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_shipday', name: "Shipday", severity: 'issue',
        patterns: [new RegExp("(?:shipday).{0,40}\\b([a-zA-Z0-9.]{11}[a-zA-Z0-9]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Shipday. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_shodankey', name: "Shodankey", severity: 'issue',
        patterns: [new RegExp("(?:shodan).{0,40}\\b([a-zA-Z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Shodankey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_shopify_access_token', name: "Shopify access token", severity: 'issue',
        patterns: [new RegExp("shpat_[a-fA-F0-9]{32}", 'gi')],
        description: 'Detected sensitive pattern: Shopify access token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_shopify_custom_app_access_token', name: "Shopify custom app access token", severity: 'issue',
        patterns: [new RegExp("shpca_[a-fA-F0-9]{32}", 'gi')],
        description: 'Detected sensitive pattern: Shopify custom app access token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_shopify_private_app_access_token', name: "Shopify private app access token", severity: 'issue',
        patterns: [new RegExp("shppa_[a-fA-F0-9]{32}", 'gi')],
        description: 'Detected sensitive pattern: Shopify private app access token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_shopify_shared_secret', name: "Shopify shared secret", severity: 'issue',
        patterns: [new RegExp("shpss_[a-fA-F0-9]{32}", 'gi')],
        description: 'Detected sensitive pattern: Shopify shared secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_shoppable_service_auth', name: "Shoppable Service Auth", severity: 'issue',
        patterns: [new RegExp("data-shoppable-auth-token.+", 'gi')],
        description: 'Detected sensitive pattern: Shoppable Service Auth. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_shortcut', name: "Shortcut", severity: 'issue',
        patterns: [new RegExp("(?:shortcut).{0,40}\\b([0-9a-f-]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Shortcut. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_shotstack', name: "Shotstack", severity: 'issue',
        patterns: [new RegExp("(?:shotstack).{0,40}\\b([a-zA-Z0-9]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Shotstack. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_shutterstock_1', name: "Shutterstock - 1", severity: 'issue',
        patterns: [new RegExp("(?:shutterstock).{0,40}\\b([0-9a-zA-Z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Shutterstock - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_shutterstock_2', name: "Shutterstock - 2", severity: 'issue',
        patterns: [new RegExp("(?:shutterstock).{0,40}\\b([0-9a-zA-Z]{16})\\b", 'gi')],
        description: 'Detected sensitive pattern: Shutterstock - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_shutterstockoauth', name: "Shutterstockoauth", severity: 'issue',
        patterns: [new RegExp("(?:shutterstock).{0,40}\\b(v2/[0-9A-Za-z]{388})\\b", 'gi')],
        description: 'Detected sensitive pattern: Shutterstockoauth. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_signalwire_1', name: "Signalwire - 1", severity: 'issue',
        patterns: [new RegExp("\\b([0-9a-z-]{3,64}.signalwire.com)\\b", 'gi')],
        description: 'Detected sensitive pattern: Signalwire - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_signalwire_2', name: "Signalwire - 2", severity: 'issue',
        patterns: [new RegExp("(?:signalwire).{0,40}\\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Signalwire - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_signalwire_3', name: "Signalwire - 3", severity: 'issue',
        patterns: [new RegExp("(?:signalwire).{0,40}\\b([0-9A-Za-z]{50})\\b", 'gi')],
        description: 'Detected sensitive pattern: Signalwire - 3. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_signaturit', name: "Signaturit", severity: 'issue',
        patterns: [new RegExp("(?:signaturit).{0,40}\\b([0-9A-Za-z]{86})\\b", 'gi')],
        description: 'Detected sensitive pattern: Signaturit. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_signupgenius', name: "Signupgenius", severity: 'issue',
        patterns: [new RegExp("(?:signupgenius).{0,40}\\b([0-9A-Za-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Signupgenius. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sigopt', name: "Sigopt", severity: 'issue',
        patterns: [new RegExp("(?:sigopt).{0,40}\\b([A-Z0-9]{48})\\b", 'gi')],
        description: 'Detected sensitive pattern: Sigopt. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_simplesat', name: "Simplesat", severity: 'issue',
        patterns: [new RegExp("(?:simplesat).{0,40}\\b([a-z0-9]{40})", 'gi')],
        description: 'Detected sensitive pattern: Simplesat. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_simplynoted', name: "Simplynoted", severity: 'issue',
        patterns: [new RegExp("(?:simplynoted).{0,40}\\b([a-zA-Z0-9\\S]{340,360})\\b", 'gi')],
        description: 'Detected sensitive pattern: Simplynoted. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_simvoly', name: "Simvoly", severity: 'issue',
        patterns: [new RegExp("(?:simvoly).{0,40}\\b([a-z0-9]{33})\\b", 'gi')],
        description: 'Detected sensitive pattern: Simvoly. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sinchmessage', name: "Sinchmessage", severity: 'issue',
        patterns: [new RegExp("(?:sinch).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Sinchmessage. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sirv_1', name: "Sirv - 1", severity: 'issue',
        patterns: [new RegExp("(?:sirv).{0,40}\\b([a-zA-Z0-9\\S]{88})", 'gi')],
        description: 'Detected sensitive pattern: Sirv - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sirv_2', name: "Sirv - 2", severity: 'issue',
        patterns: [new RegExp("(?:sirv).{0,40}\\b([a-zA-Z0-9]{26})\\b", 'gi')],
        description: 'Detected sensitive pattern: Sirv - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_siteleaf', name: "Siteleaf", severity: 'issue',
        patterns: [new RegExp("(?:siteleaf).{0,40}\\b([0-9Aa-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Siteleaf. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_skrappio', name: "Skrappio", severity: 'issue',
        patterns: [new RegExp("(?:skrapp).{0,40}\\b([a-z0-9A-Z]{42})\\b", 'gi')],
        description: 'Detected sensitive pattern: Skrappio. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_skybiometry', name: "Skybiometry", severity: 'issue',
        patterns: [new RegExp("(?:skybiometry).{0,40}\\b([0-9a-z]{25,26})\\b", 'gi')],
        description: 'Detected sensitive pattern: Skybiometry. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_slack', name: "Slack", severity: 'issue',
        patterns: [new RegExp("xox[baprs]-[0-9a-zA-Z]{10,48}", 'gi')],
        description: 'Detected sensitive pattern: Slack. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_slack_token', name: "Slack Token", severity: 'issue',
        patterns: [new RegExp("(xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})", 'gi')],
        description: 'Detected sensitive pattern: Slack Token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_slack_user_token', name: "Slack User token", severity: 'issue',
        patterns: [new RegExp("xoxp-[0-9A-Za-z\\-]{72}", 'gi')],
        description: 'Detected sensitive pattern: Slack User token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_slack_webhook', name: "Slack Webhook", severity: 'issue',
        patterns: [new RegExp("https://hooks.slack.com/services/T[a-zA-Z0-9_]{8,10}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{23,24}", 'gi')],
        description: 'Detected sensitive pattern: Slack Webhook. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_slack_access_token', name: "Slack access token", severity: 'issue',
        patterns: [new RegExp("xoxb-[0-9A-Za-z\\-]{51}", 'gi')],
        description: 'Detected sensitive pattern: Slack access token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_slackwebhook', name: "Slackwebhook", severity: 'issue',
        patterns: [new RegExp("(https:\\/\\/hooks.slack.com\\/services\\/[A-Za-z0-9+\\/]{44,46})", 'gi')],
        description: 'Detected sensitive pattern: Slackwebhook. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_smartsheets', name: "Smartsheets", severity: 'issue',
        patterns: [new RegExp("(?:smartsheets).{0,40}\\b([a-zA-Z0-9]{37})\\b", 'gi')],
        description: 'Detected sensitive pattern: Smartsheets. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_smartystreets_1', name: "Smartystreets - 1", severity: 'issue',
        patterns: [new RegExp("(?:smartystreets).{0,40}\\b([a-zA-Z0-9]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Smartystreets - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_smartystreets_2', name: "Smartystreets - 2", severity: 'issue',
        patterns: [new RegExp("(?:smartystreets).{0,40}\\b([a-z0-9-]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Smartystreets - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_smooch_1', name: "Smooch - 1", severity: 'issue',
        patterns: [new RegExp("(?:smooch).{0,40}\\b(act_[0-9a-z]{24})\\b", 'gi')],
        description: 'Detected sensitive pattern: Smooch - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_smooch_2', name: "Smooch - 2", severity: 'issue',
        patterns: [new RegExp("(?:smooch).{0,40}\\b([0-9a-zA-Z_-]{86})\\b", 'gi')],
        description: 'Detected sensitive pattern: Smooch - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_snipcart', name: "Snipcart", severity: 'issue',
        patterns: [new RegExp("(?:snipcart).{0,40}\\b([0-9A-Za-z_]{75})\\b", 'gi')],
        description: 'Detected sensitive pattern: Snipcart. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_snykkey', name: "Snykkey", severity: 'issue',
        patterns: [new RegExp("(?:snyk).{0,40}\\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Snykkey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sonarqube_token', name: "SonarQube Token", severity: 'issue',
        patterns: [new RegExp("sonar.{0,50}(?:\"|'|`)?[0-9a-f]{40}(?:\"|'|`)?", 'gi')],
        description: 'Detected sensitive pattern: SonarQube Token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_splunkobservabilitytoken', name: "Splunkobservabilitytoken", severity: 'issue',
        patterns: [new RegExp("(?:splunk).{0,40}\\b([a-z0-9A-Z]{22})\\b", 'gi')],
        description: 'Detected sensitive pattern: Splunkobservabilitytoken. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_spoonacular', name: "Spoonacular", severity: 'issue',
        patterns: [new RegExp("(?:spoonacular).{0,40}\\b([0-9a-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Spoonacular. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sportsmonk', name: "Sportsmonk", severity: 'issue',
        patterns: [new RegExp("(?:sportsmonk).{0,40}\\b([0-9a-zA-Z]{60})\\b", 'gi')],
        description: 'Detected sensitive pattern: Sportsmonk. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_square', name: "Square", severity: 'issue',
        patterns: [new RegExp("(?:square).{0,40}(EAAA[a-zA-Z0-9\\-\\+\\=]{60})", 'gi')],
        description: 'Detected sensitive pattern: Square. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_square_api_key', name: "Square API Key", severity: 'issue',
        patterns: [new RegExp("sq0(atp|csp)-[0-9a-z-_]{22,43}", 'gi')],
        description: 'Detected sensitive pattern: Square API Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_square_oauth_secret', name: "Square OAuth Secret", severity: 'issue',
        patterns: [new RegExp("sq0csp-[0-9A-Za-z\\-_]{43}", 'gi')],
        description: 'Detected sensitive pattern: Square OAuth Secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_square_access_token', name: "Square access token", severity: 'issue',
        patterns: [new RegExp("sq0atp-[0-9A-Za-z\\-_]{22}", 'gi')],
        description: 'Detected sensitive pattern: Square access token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_squareapp_1', name: "Squareapp - 1", severity: 'issue',
        patterns: [new RegExp("[\\w\\-]*sq0i[a-z]{2}-[0-9A-Za-z\\-_]{22,43}", 'gi')],
        description: 'Detected sensitive pattern: Squareapp - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_squareapp_2', name: "Squareapp - 2", severity: 'issue',
        patterns: [new RegExp("[\\w\\-]*sq0c[a-z]{2}-[0-9A-Za-z\\-_]{40,50}", 'gi')],
        description: 'Detected sensitive pattern: Squareapp - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_squarespace', name: "Squarespace", severity: 'issue',
        patterns: [new RegExp("(?:squarespace).{0,40}\\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Squarespace. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_squareup', name: "Squareup", severity: 'issue',
        patterns: [new RegExp("\\b(sq0idp-[0-9A-Za-z]{22})\\b", 'gi')],
        description: 'Detected sensitive pattern: Squareup. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sslmate', name: "Sslmate", severity: 'issue',
        patterns: [new RegExp("(?:sslmate).{0,40}\\b([a-zA-Z0-9]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Sslmate. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_stitchdata', name: "Stitchdata", severity: 'issue',
        patterns: [new RegExp("(?:stitchdata).{0,40}\\b([0-9a-z_]{35})\\b", 'gi')],
        description: 'Detected sensitive pattern: Stitchdata. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_stockdata', name: "Stockdata", severity: 'issue',
        patterns: [new RegExp("(?:stockdata).{0,40}\\b([0-9A-Za-z]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Stockdata. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_storecove', name: "Storecove", severity: 'issue',
        patterns: [new RegExp("(?:storecove).{0,40}\\b([a-zA-Z0-9_-]{43})\\b", 'gi')],
        description: 'Detected sensitive pattern: Storecove. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_stormglass', name: "Stormglass", severity: 'issue',
        patterns: [new RegExp("(?:stormglass).{0,40}\\b([0-9Aa-z-]{73})\\b", 'gi')],
        description: 'Detected sensitive pattern: Stormglass. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_storyblok', name: "Storyblok", severity: 'issue',
        patterns: [new RegExp("(?:storyblok).{0,40}\\b([0-9A-Za-z]{22}t{2})\\b", 'gi')],
        description: 'Detected sensitive pattern: Storyblok. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_storychief', name: "Storychief", severity: 'issue',
        patterns: [new RegExp("(?:storychief).{0,40}\\b([a-zA-Z0-9_\\-.]{940,1000})", 'gi')],
        description: 'Detected sensitive pattern: Storychief. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_strava_1', name: "Strava - 1", severity: 'issue',
        patterns: [new RegExp("(?:strava).{0,40}\\b([0-9]{5})\\b", 'gi')],
        description: 'Detected sensitive pattern: Strava - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_strava_2', name: "Strava - 2", severity: 'issue',
        patterns: [new RegExp("(?:strava).{0,40}\\b([0-9a-z]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Strava - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_streak', name: "Streak", severity: 'issue',
        patterns: [new RegExp("(?:streak).{0,40}\\b([0-9Aa-f]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Streak. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_stripe', name: "Stripe", severity: 'issue',
        patterns: [new RegExp("[rs]k_live_[a-zA-Z0-9]{20,30}", 'gi')],
        description: 'Detected sensitive pattern: Stripe. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_stripe_api_key_1', name: "Stripe API Key - 1", severity: 'issue',
        patterns: [new RegExp("sk_live_[0-9a-zA-Z]{24}", 'gi')],
        description: 'Detected sensitive pattern: Stripe API Key - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_stripe_api_key_2', name: "Stripe API key - 2", severity: 'issue',
        patterns: [new RegExp("stripe[sr]k_live_[0-9a-zA-Z]{24}", 'gi')],
        description: 'Detected sensitive pattern: Stripe API key - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_stripe_api_key_3', name: "Stripe API key - 3", severity: 'issue',
        patterns: [new RegExp("stripe[sk|rk]_live_[0-9a-zA-Z]{24}", 'gi')],
        description: 'Detected sensitive pattern: Stripe API key - 3. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_stripe_public_live_key', name: "Stripe Public Live Key", severity: 'issue',
        patterns: [new RegExp("pk_live_[0-9a-z]{24}", 'gi')],
        description: 'Detected sensitive pattern: Stripe Public Live Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_stripe_public_test_key', name: "Stripe Public Test Key", severity: 'issue',
        patterns: [new RegExp("pk_test_[0-9a-z]{24}", 'gi')],
        description: 'Detected sensitive pattern: Stripe Public Test Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_stripe_restriced_key', name: "Stripe Restriced Key", severity: 'issue',
        patterns: [new RegExp("rk_(?:live|test)_[0-9a-zA-Z]{24}", 'gi')],
        description: 'Detected sensitive pattern: Stripe Restriced Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_stripe_restricted_api_key', name: "Stripe Restricted API Key", severity: 'issue',
        patterns: [new RegExp("rk_live_[0-9a-zA-Z]{24}", 'gi')],
        description: 'Detected sensitive pattern: Stripe Restricted API Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_stripe_secret_key', name: "Stripe Secret Key", severity: 'issue',
        patterns: [new RegExp("sk_(?:live|test)_[0-9a-zA-Z]{24}", 'gi')],
        description: 'Detected sensitive pattern: Stripe Secret Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_stripe_secret_live_key', name: "Stripe Secret Live Key", severity: 'issue',
        patterns: [new RegExp("(sk|rk)_live_[0-9a-z]{24}", 'gi')],
        description: 'Detected sensitive pattern: Stripe Secret Live Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_stripe_secret_test_key', name: "Stripe Secret Test Key", severity: 'issue',
        patterns: [new RegExp("(sk|rk)_test_[0-9a-z]{24}", 'gi')],
        description: 'Detected sensitive pattern: Stripe Secret Test Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_stytch_1', name: "Stytch - 1", severity: 'issue',
        patterns: [new RegExp("(?:stytch).{0,40}\\b([a-zA-Z0-9-_]{47}=)", 'gi')],
        description: 'Detected sensitive pattern: Stytch - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_stytch_2', name: "Stytch - 2", severity: 'issue',
        patterns: [new RegExp("(?:stytch).{0,40}\\b([a-z0-9-]{49})\\b", 'gi')],
        description: 'Detected sensitive pattern: Stytch - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sugester_1', name: "Sugester - 1", severity: 'issue',
        patterns: [new RegExp("(?:sugester).{0,40}\\b([a-zA-Z0-9_.!+$#^*%]{3,32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Sugester - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sugester_2', name: "Sugester - 2", severity: 'issue',
        patterns: [new RegExp("(?:sugester).{0,40}\\b([a-zA-Z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Sugester - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sumologickey_1', name: "Sumologickey - 1", severity: 'issue',
        patterns: [new RegExp("(?:sumo).{0,40}\\b([A-Za-z0-9]{14})\\b", 'gi')],
        description: 'Detected sensitive pattern: Sumologickey - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sumologickey_2', name: "Sumologickey - 2", severity: 'issue',
        patterns: [new RegExp("(?:sumo).{0,40}\\b([A-Za-z0-9]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Sumologickey - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_supernotesapi', name: "Supernotesapi", severity: 'issue',
        patterns: [new RegExp("(?:supernotes).{0,40}([ \\r\\n]{0,1}[0-9A-Za-z\\-_]{43}[ \\r\\n]{1})", 'gi')],
        description: 'Detected sensitive pattern: Supernotesapi. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_surveyanyplace_1', name: "Surveyanyplace - 1", severity: 'issue',
        patterns: [new RegExp("(?:survey).{0,40}\\b([a-z0-9A-Z-]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Surveyanyplace - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_surveyanyplace_2', name: "Surveyanyplace - 2", severity: 'issue',
        patterns: [new RegExp("(?:survey).{0,40}\\b([a-z0-9A-Z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Surveyanyplace - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_surveybot', name: "Surveybot", severity: 'issue',
        patterns: [new RegExp("(?:surveybot).{0,40}\\b([A-Za-z0-9-]{80})\\b", 'gi')],
        description: 'Detected sensitive pattern: Surveybot. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_surveysparrow', name: "Surveysparrow", severity: 'issue',
        patterns: [new RegExp("(?:surveysparrow).{0,40}\\b([a-zA-Z0-9-_]{88})\\b", 'gi')],
        description: 'Detected sensitive pattern: Surveysparrow. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_survicate', name: "Survicate", severity: 'issue',
        patterns: [new RegExp("(?:survicate).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Survicate. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_swell_1', name: "Swell - 1", severity: 'issue',
        patterns: [new RegExp("(?:swell).{0,40}\\b([a-zA-Z0-9]{6,24})\\b", 'gi')],
        description: 'Detected sensitive pattern: Swell - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_swell_2', name: "Swell - 2", severity: 'issue',
        patterns: [new RegExp("(?:swell).{0,40}\\b([a-zA-Z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Swell - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_swiftype', name: "Swiftype", severity: 'issue',
        patterns: [new RegExp("(?:swiftype).{0,40}\\b([a-zA-z-0-9]{6}\\_[a-zA-z-0-9]{6}\\-[a-zA-z-0-9]{6})\\b", 'gi')],
        description: 'Detected sensitive pattern: Swiftype. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_tallyfy', name: "Tallyfy", severity: 'issue',
        patterns: [new RegExp("(?:tallyfy).{0,40}\\b([0-9A-Za-z]{36}\\.[0-9A-Za-z]{264}\\.[0-9A-Za-z\\-\\_]{683})\\b", 'gi')],
        description: 'Detected sensitive pattern: Tallyfy. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_tatumio', name: "Tatumio", severity: 'issue',
        patterns: [new RegExp("(?:tatum).{0,40}\\b([0-9a-z-]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Tatumio. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_taxjar', name: "Taxjar", severity: 'issue',
        patterns: [new RegExp("(?:taxjar).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Taxjar. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_teamgate_1', name: "Teamgate - 1", severity: 'issue',
        patterns: [new RegExp("(?:teamgate).{0,40}\\b([a-z0-9]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Teamgate - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_teamgate_2', name: "Teamgate - 2", severity: 'issue',
        patterns: [new RegExp("(?:teamgate).{0,40}\\b([a-zA-Z0-9]{80})\\b", 'gi')],
        description: 'Detected sensitive pattern: Teamgate - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_teamworkcrm', name: "Teamworkcrm", severity: 'issue',
        patterns: [new RegExp("(?:teamwork|teamworkcrm).{0,40}\\b(tkn\\.v1_[0-9A-Za-z]{71}=[ \\r\\n]{1})", 'gi')],
        description: 'Detected sensitive pattern: Teamworkcrm. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_teamworkdesk', name: "Teamworkdesk", severity: 'issue',
        patterns: [new RegExp("(?:teamwork|teamworkdesk).{0,40}\\b(tkn\\.v1_[0-9A-Za-z]{71}=[ \\r\\n]{1})", 'gi')],
        description: 'Detected sensitive pattern: Teamworkdesk. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_teamworkspaces', name: "Teamworkspaces", severity: 'issue',
        patterns: [new RegExp("(?:teamwork|teamworkspaces).{0,40}\\b(tkn\\.v1_[0-9A-Za-z]{71}=[ \\r\\n]{1})", 'gi')],
        description: 'Detected sensitive pattern: Teamworkspaces. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_technicalanalysisapi', name: "Technicalanalysisapi", severity: 'issue',
        patterns: [new RegExp("(?:technicalanalysisapi).{0,40}\\b([A-Z0-9]{48})\\b", 'gi')],
        description: 'Detected sensitive pattern: Technicalanalysisapi. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_telegram_bot_api_key', name: "Telegram Bot API Key", severity: 'issue',
        patterns: [new RegExp("[0-9]+:AA[0-9A-Za-z\\-_]{33}", 'gi')],
        description: 'Detected sensitive pattern: Telegram Bot API Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_telegram_secret', name: "Telegram Secret", severity: 'issue',
        patterns: [new RegExp("d{5,}:A[0-9a-z_-]{34,34}", 'gi')],
        description: 'Detected sensitive pattern: Telegram Secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_telegrambottoken', name: "Telegrambottoken", severity: 'issue',
        patterns: [new RegExp("(?:telegram).{0,40}\\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\\b", 'gi')],
        description: 'Detected sensitive pattern: Telegrambottoken. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_telnyx', name: "Telnyx", severity: 'issue',
        patterns: [new RegExp("(?:telnyx).{0,40}\\b(KEY[0-9A-Za-z_-]{55})\\b", 'gi')],
        description: 'Detected sensitive pattern: Telnyx. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_terraformcloudpersonaltoken', name: "Terraformcloudpersonaltoken", severity: 'issue',
        patterns: [new RegExp("\\b([A-Za-z0-9]{14}.atlasv1.[A-Za-z0-9]{67})\\b", 'gi')],
        description: 'Detected sensitive pattern: Terraformcloudpersonaltoken. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_text2data', name: "Text2data", severity: 'issue',
        patterns: [new RegExp("(?:text2data).{0,40}\\b([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Text2data. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_textmagic_1', name: "Textmagic - 1", severity: 'issue',
        patterns: [new RegExp("(?:textmagic).{0,40}\\b([0-9A-Za-z]{30})\\b", 'gi')],
        description: 'Detected sensitive pattern: Textmagic - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_textmagic_2', name: "Textmagic - 2", severity: 'issue',
        patterns: [new RegExp("(?:textmagic).{0,40}\\b([0-9A-Za-z]{1,25})\\b", 'gi')],
        description: 'Detected sensitive pattern: Textmagic - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_theoddsapi', name: "Theoddsapi", severity: 'issue',
        patterns: [new RegExp("(?:theoddsapi|the-odds-api).{0,40}\\b([0-9a-f]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Theoddsapi. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_thinkific_1', name: "Thinkific - 1", severity: 'issue',
        patterns: [new RegExp("(?:thinkific).{0,40}\\b([0-9a-f]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Thinkific - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_thinkific_2', name: "Thinkific - 2", severity: 'issue',
        patterns: [new RegExp("(?:thinkific).{0,40}\\b([0-9A-Za-z]{4,40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Thinkific - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_thousandeyes_1', name: "Thousandeyes - 1", severity: 'issue',
        patterns: [new RegExp("(?:thousandeyes).{0,40}\\b([a-zA-Z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Thousandeyes - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_thousandeyes_2', name: "Thousandeyes - 2", severity: 'issue',
        patterns: [new RegExp("(?:thousandeyes).{0,40}\\b([a-zA-Z0-9]{3,20}@[a-zA-Z0-9]{2,12}.[a-zA-Z0-9]{2,5})\\b", 'gi')],
        description: 'Detected sensitive pattern: Thousandeyes - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ticketmaster', name: "Ticketmaster", severity: 'issue',
        patterns: [new RegExp("(?:ticketmaster).{0,40}\\b([a-zA-Z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Ticketmaster. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_tiingo', name: "Tiingo", severity: 'issue',
        patterns: [new RegExp("(?:tiingo).{0,40}\\b([0-9a-z]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Tiingo. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_timezoneapi', name: "Timezoneapi", severity: 'issue',
        patterns: [new RegExp("(?:timezoneapi).{0,40}\\b([a-zA-Z0-9]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Timezoneapi. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_tly', name: "Tly", severity: 'issue',
        patterns: [new RegExp("(?:tly).{0,40}\\b([0-9A-Za-z]{60})\\b", 'gi')],
        description: 'Detected sensitive pattern: Tly. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_tmetric', name: "Tmetric", severity: 'issue',
        patterns: [new RegExp("(?:tmetric).{0,40}\\b([0-9A-Z]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Tmetric. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_todoist', name: "Todoist", severity: 'issue',
        patterns: [new RegExp("(?:todoist).{0,40}\\b([0-9a-z]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Todoist. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_toggltrack', name: "Toggltrack", severity: 'issue',
        patterns: [new RegExp("(?:toggl).{0,40}\\b([0-9Aa-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Toggltrack. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_tomorrowio', name: "Tomorrowio", severity: 'issue',
        patterns: [new RegExp("(?:tomorrow).{0,40}\\b([a-zA-Z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Tomorrowio. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_tomtom', name: "Tomtom", severity: 'issue',
        patterns: [new RegExp("(?:tomtom).{0,40}\\b([0-9Aa-zA-Z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Tomtom. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_tradier', name: "Tradier", severity: 'issue',
        patterns: [new RegExp("(?:tradier).{0,40}\\b([a-zA-Z0-9]{28})\\b", 'gi')],
        description: 'Detected sensitive pattern: Tradier. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_travelpayouts', name: "Travelpayouts", severity: 'issue',
        patterns: [new RegExp("(?:travelpayouts).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Travelpayouts. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_travisci', name: "Travisci", severity: 'issue',
        patterns: [new RegExp("(?:travis).{0,40}\\b([a-zA-Z0-9A-Z_]{22})\\b", 'gi')],
        description: 'Detected sensitive pattern: Travisci. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_trello_url', name: "Trello URL", severity: 'issue',
        patterns: [new RegExp("https://trello.com/b/[0-9a-z]/[0-9a-z_-]+", 'gi')],
        description: 'Detected sensitive pattern: Trello URL. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_trelloapikey_2', name: "Trelloapikey - 2", severity: 'issue',
        patterns: [new RegExp("(?:trello).{0,40}\\b([a-zA-Z-0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Trelloapikey - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_twelvedata', name: "Twelvedata", severity: 'issue',
        patterns: [new RegExp("(?:twelvedata).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Twelvedata. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_twilio_1', name: "Twilio - 1", severity: 'issue',
        patterns: [new RegExp("\\bAC[0-9a-f]{32}\\b", 'gi')],
        description: 'Detected sensitive pattern: Twilio - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_twilio_api_key', name: "Twilio API Key", severity: 'issue',
        patterns: [new RegExp("SK[0-9a-fA-F]{32}", 'gi')],
        description: 'Detected sensitive pattern: Twilio API Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_twitter_access_token', name: "Twitter Access Token", severity: 'issue',
        patterns: [new RegExp("[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}", 'gi')],
        description: 'Detected sensitive pattern: Twitter Access Token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_twitter_client_id', name: "Twitter Client ID", severity: 'issue',
        patterns: [new RegExp("twitter[0-9a-z]{18,25}", 'gi')],
        description: 'Detected sensitive pattern: Twitter Client ID. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_twitter_oauth', name: "Twitter OAuth", severity: 'issue',
        patterns: [new RegExp("[tT][wW][iI][tT][tT][eE][rR].*[''|\"][0-9a-zA-Z]{35,44}[''|\"]", 'gi')],
        description: 'Detected sensitive pattern: Twitter OAuth. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_twitter_secret_key', name: "Twitter Secret Key", severity: 'issue',
        patterns: [new RegExp("twitter[0-9a-z]{35,44}", 'gi')],
        description: 'Detected sensitive pattern: Twitter Secret Key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_tyntec', name: "Tyntec", severity: 'issue',
        patterns: [new RegExp("(?:tyntec).{0,40}\\b([a-zA-Z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Tyntec. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_typeform', name: "Typeform", severity: 'issue',
        patterns: [new RegExp("(?:typeform).{0,40}\\b([0-9A-Za-z]{44})\\b", 'gi')],
        description: 'Detected sensitive pattern: Typeform. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ubidots', name: "Ubidots", severity: 'issue',
        patterns: [new RegExp("\\b(BBFF-[0-9a-zA-Z]{30})\\b", 'gi')],
        description: 'Detected sensitive pattern: Ubidots. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_unifyid', name: "Unifyid", severity: 'issue',
        patterns: [new RegExp("(?:unify).{0,40}\\b([0-9A-Za-z_=-]{44})", 'gi')],
        description: 'Detected sensitive pattern: Unifyid. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_unplugg', name: "Unplugg", severity: 'issue',
        patterns: [new RegExp("(?:unplu).{0,40}\\b([a-z0-9]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Unplugg. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_unsplash', name: "Unsplash", severity: 'issue',
        patterns: [new RegExp("(?:unsplash).{0,40}\\b([0-9A-Za-z_]{43})\\b", 'gi')],
        description: 'Detected sensitive pattern: Unsplash. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_upcdatabase', name: "Upcdatabase", severity: 'issue',
        patterns: [new RegExp("(?:upcdatabase).{0,40}\\b([A-Z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Upcdatabase. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_uplead', name: "Uplead", severity: 'issue',
        patterns: [new RegExp("(?:uplead).{0,40}\\b([a-z0-9-]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Uplead. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_uploadcare', name: "Uploadcare", severity: 'issue',
        patterns: [new RegExp("(?:uploadcare).{0,40}\\b([a-z0-9]{20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Uploadcare. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_upwave', name: "Upwave", severity: 'issue',
        patterns: [new RegExp("(?:upwave).{0,40}\\b([0-9a-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Upwave. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_uri', name: "Uri", severity: 'issue',
        patterns: [new RegExp("\\b[a-zA-Z]{1,10}:?\\/\\/[-.%\\w{}]{1,50}:([-.%\\S]{3,50})@[-.%\\w\\/:]+\\b", 'gi')],
        description: 'Detected sensitive pattern: Uri. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_urlscan', name: "Urlscan", severity: 'issue',
        patterns: [new RegExp("(?:urlscan).{0,40}\\b([a-z0-9-]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Urlscan. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_userstack', name: "Userstack", severity: 'issue',
        patterns: [new RegExp("(?:userstack).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Userstack. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_vatlayer', name: "Vatlayer", severity: 'issue',
        patterns: [new RegExp("(?:vatlayer).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Vatlayer. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_vercel', name: "Vercel", severity: 'issue',
        patterns: [new RegExp("(?:vercel).{0,40}\\b([a-zA-Z0-9]{24})\\b", 'gi')],
        description: 'Detected sensitive pattern: Vercel. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_verifier_1', name: "Verifier - 1", severity: 'issue',
        patterns: [new RegExp("(?:verifier).{0,40}\\b([a-zA-Z-0-9-]{5,16}\\@[a-zA-Z-0-9]{4,16}\\.[a-zA-Z-0-9]{3,6})\\b", 'gi')],
        description: 'Detected sensitive pattern: Verifier - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_verifier_2', name: "Verifier - 2", severity: 'issue',
        patterns: [new RegExp("(?:verifier).{0,40}\\b([a-z0-9]{96})\\b", 'gi')],
        description: 'Detected sensitive pattern: Verifier - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_verimail', name: "Verimail", severity: 'issue',
        patterns: [new RegExp("(?:verimail).{0,40}\\b([A-Z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Verimail. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_veriphone', name: "Veriphone", severity: 'issue',
        patterns: [new RegExp("(?:veriphone).{0,40}\\b([0-9A-Z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Veriphone. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_versioneye', name: "Versioneye", severity: 'issue',
        patterns: [new RegExp("(?:versioneye).{0,40}\\b([a-zA-Z0-9-]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Versioneye. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_viewneo', name: "Viewneo", severity: 'issue',
        patterns: [new RegExp("(?:viewneo).{0,40}\\b([a-z0-9A-Z]{120,300}.[a-z0-9A-Z]{150,300}.[a-z0-9A-Z-_]{600,800})", 'gi')],
        description: 'Detected sensitive pattern: Viewneo. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_virustotal', name: "Virustotal", severity: 'issue',
        patterns: [new RegExp("(?:virustotal).{0,40}\\b([a-f0-9]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Virustotal. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_visualcrossing', name: "Visualcrossing", severity: 'issue',
        patterns: [new RegExp("(?:visualcrossing).{0,40}\\b([0-9A-Z]{25})\\b", 'gi')],
        description: 'Detected sensitive pattern: Visualcrossing. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_voicegain', name: "Voicegain", severity: 'issue',
        patterns: [new RegExp("(?:voicegain).{0,40}\\b(ey[0-9a-zA-Z_-]{34}.ey[0-9a-zA-Z_-]{108}.[0-9a-zA-Z_-]{43})\\b", 'gi')],
        description: 'Detected sensitive pattern: Voicegain. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_vouchery_1', name: "Vouchery - 1", severity: 'issue',
        patterns: [new RegExp("(?:vouchery).{0,40}\\b([a-z0-9-]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Vouchery - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_vouchery_2', name: "Vouchery - 2", severity: 'issue',
        patterns: [new RegExp("(?:vouchery).{0,40}\\b([a-zA-Z0-9-\\S]{2,20})\\b", 'gi')],
        description: 'Detected sensitive pattern: Vouchery - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_vpnapi', name: "Vpnapi", severity: 'issue',
        patterns: [new RegExp("(?:vpnapi).{0,40}\\b([a-z0-9A-Z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Vpnapi. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_vultrapikey', name: "Vultrapikey", severity: 'issue',
        patterns: [new RegExp("(?:vultr).{0,40} \\b([A-Z0-9]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Vultrapikey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_vyte', name: "Vyte", severity: 'issue',
        patterns: [new RegExp("(?:vyte).{0,40}\\b([0-9a-z]{50})\\b", 'gi')],
        description: 'Detected sensitive pattern: Vyte. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_walkscore', name: "Walkscore", severity: 'issue',
        patterns: [new RegExp("(?:walkscore).{0,40}\\b([0-9a-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Walkscore. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_weatherbit', name: "Weatherbit", severity: 'issue',
        patterns: [new RegExp("(?:weatherbit).{0,40}\\b([0-9a-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Weatherbit. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_weatherstack', name: "Weatherstack", severity: 'issue',
        patterns: [new RegExp("(?:weatherstack).{0,40}\\b([0-9a-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Weatherstack. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_webex_1', name: "Webex - 1", severity: 'issue',
        patterns: [new RegExp("(?:error).{0,40}(redirect_uri_mismatch)", 'gi')],
        description: 'Detected sensitive pattern: Webex - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_webex_2', name: "Webex - 2", severity: 'issue',
        patterns: [new RegExp("(?:webex).{0,40}\\b([A-Za-z0-9_-]{65})\\b", 'gi')],
        description: 'Detected sensitive pattern: Webex - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_webex_3', name: "Webex - 3", severity: 'issue',
        patterns: [new RegExp("(?:webex).{0,40}\\b([A-Za-z0-9_-]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Webex - 3. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_webflow', name: "Webflow", severity: 'issue',
        patterns: [new RegExp("(?:webflow).{0,40}\\b([a-zA0-9]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Webflow. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_webscraper', name: "Webscraper", severity: 'issue',
        patterns: [new RegExp("(?:webscraper).{0,40}\\b([a-zA-Z0-9]{60})\\b", 'gi')],
        description: 'Detected sensitive pattern: Webscraper. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_webscraping', name: "Webscraping", severity: 'issue',
        patterns: [new RegExp("(?:webscraping).{0,40}\\b([0-9A-Za-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Webscraping. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_wepay_2', name: "Wepay - 2", severity: 'issue',
        patterns: [new RegExp("(?:wepay).{0,40}\\b([a-zA-Z0-9_?]{62})\\b", 'gi')],
        description: 'Detected sensitive pattern: Wepay - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_whoxy', name: "Whoxy", severity: 'issue',
        patterns: [new RegExp("(?:whoxy).{0,40}\\b([0-9a-z]{33})\\b", 'gi')],
        description: 'Detected sensitive pattern: Whoxy. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_worksnaps', name: "Worksnaps", severity: 'issue',
        patterns: [new RegExp("(?:worksnaps).{0,40}\\b([0-9A-Za-z]{40})\\b", 'gi')],
        description: 'Detected sensitive pattern: Worksnaps. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_workstack', name: "Workstack", severity: 'issue',
        patterns: [new RegExp("(?:workstack).{0,40}\\b([0-9Aa-zA-Z]{60})\\b", 'gi')],
        description: 'Detected sensitive pattern: Workstack. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_worldcoinindex', name: "Worldcoinindex", severity: 'issue',
        patterns: [new RegExp("(?:worldcoinindex).{0,40}\\b([a-zA-Z0-9]{35})\\b", 'gi')],
        description: 'Detected sensitive pattern: Worldcoinindex. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_worldweather', name: "Worldweather", severity: 'issue',
        patterns: [new RegExp("(?:worldweather).{0,40}\\b([0-9a-z]{31})\\b", 'gi')],
        description: 'Detected sensitive pattern: Worldweather. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_wrike', name: "Wrike", severity: 'issue',
        patterns: [new RegExp("(?:wrike).{0,40}\\b(ey[a-zA-Z0-9-._]{333})\\b", 'gi')],
        description: 'Detected sensitive pattern: Wrike. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_yandex', name: "Yandex", severity: 'issue',
        patterns: [new RegExp("(?:yandex).{0,40}\\b([a-z0-9A-Z.]{83})\\b", 'gi')],
        description: 'Detected sensitive pattern: Yandex. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_youneedabudget', name: "Youneedabudget", severity: 'issue',
        patterns: [new RegExp("(?:youneedabudget).{0,40}\\b([0-9a-f]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Youneedabudget. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_yousign', name: "Yousign", severity: 'issue',
        patterns: [new RegExp("(?:yousign).{0,40}\\b([0-9a-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Yousign. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_youtubeapikey_1', name: "Youtubeapikey - 1", severity: 'issue',
        patterns: [new RegExp("(?:youtube).{0,40}\\b([a-zA-Z-0-9_]{39})\\b", 'gi')],
        description: 'Detected sensitive pattern: Youtubeapikey - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_zapier_webhook', name: "Zapier Webhook", severity: 'issue',
        patterns: [new RegExp("https://(?:www.)?hooks\\.zapier\\.com/hooks/catch/[A-Za-z0-9]+/[A-Za-z0-9]+/", 'gi')],
        description: 'Detected sensitive pattern: Zapier Webhook. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_zapierwebhook', name: "Zapierwebhook", severity: 'issue',
        patterns: [new RegExp("(https:\\/\\/hooks.zapier.com\\/hooks\\/catch\\/[A-Za-z0-9\\/]{16})", 'gi')],
        description: 'Detected sensitive pattern: Zapierwebhook. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_zendeskapi_3', name: "Zendeskapi - 3", severity: 'issue',
        patterns: [new RegExp("(?:zendesk).{0,40}([A-Za-z0-9_-]{40})", 'gi')],
        description: 'Detected sensitive pattern: Zendeskapi - 3. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_zenkitapi', name: "Zenkitapi", severity: 'issue',
        patterns: [new RegExp("(?:zenkit).{0,40}\\b([0-9a-z]{8}\\-[0-9A-Za-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Zenkitapi. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_zenscrape', name: "Zenscrape", severity: 'issue',
        patterns: [new RegExp("(?:zenscrape).{0,40}\\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b", 'gi')],
        description: 'Detected sensitive pattern: Zenscrape. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_zenserp', name: "Zenserp", severity: 'issue',
        patterns: [new RegExp("(?:zenserp).{0,40}\\b([0-9a-z-]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Zenserp. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_zeplin', name: "Zeplin", severity: 'issue',
        patterns: [new RegExp("(?:zeplin).{0,40}\\b([a-zA-Z0-9-.]{350,400})\\b", 'gi')],
        description: 'Detected sensitive pattern: Zeplin. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_zerobounce', name: "Zerobounce", severity: 'issue',
        patterns: [new RegExp("(?:zerobounce).{0,40}\\b([a-z0-9]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Zerobounce. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_zipapi_1', name: "Zipapi - 1", severity: 'issue',
        patterns: [new RegExp("(?:zipapi).{0,40}\\b([a-zA-Z0-9!=@#$%^]{7,})", 'gi')],
        description: 'Detected sensitive pattern: Zipapi - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_zipapi_3', name: "Zipapi - 3", severity: 'issue',
        patterns: [new RegExp("(?:zipapi).{0,40}\\b([0-9a-z]{32})\\b", 'gi')],
        description: 'Detected sensitive pattern: Zipapi - 3. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_zipcodeapi', name: "Zipcodeapi", severity: 'issue',
        patterns: [new RegExp("(?:zipcodeapi).{0,40}\\b([a-zA-Z0-9]{64})\\b", 'gi')],
        description: 'Detected sensitive pattern: Zipcodeapi. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_zoho_webhook', name: "Zoho Webhook", severity: 'issue',
        patterns: [new RegExp("https://creator\\.zoho\\.com/api/[A-Za-z0-9/\\-_\\.]+\\?authtoken=[A-Za-z0-9]+", 'gi')],
        description: 'Detected sensitive pattern: Zoho Webhook. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_zonkafeedback', name: "Zonkafeedback", severity: 'issue',
        patterns: [new RegExp("(?:zonka).{0,40}\\b([A-Za-z0-9]{36})\\b", 'gi')],
        description: 'Detected sensitive pattern: Zonkafeedback. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_access_key_secret', name: "access_key_secret", severity: 'issue',
        patterns: [new RegExp("access[_-]?key[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: access_key_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_access_secret', name: "access_secret", severity: 'issue',
        patterns: [new RegExp("access[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: access_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_access_token', name: "access_token", severity: 'issue',
        patterns: [new RegExp("access[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: access_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_account_sid', name: "account_sid", severity: 'issue',
        patterns: [new RegExp("account[_-]?sid(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: account_sid. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_admin_email', name: "admin_email", severity: 'issue',
        patterns: [new RegExp("admin[_-]?email(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: admin_email. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_adzerk_api_key', name: "adzerk_api_key", severity: 'issue',
        patterns: [new RegExp("adzerk[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: adzerk_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_algolia_admin_key_1', name: "algolia_admin_key_1", severity: 'issue',
        patterns: [new RegExp("algolia[_-]?admin[_-]?key[_-]?1(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: algolia_admin_key_1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_algolia_admin_key_2', name: "algolia_admin_key_2", severity: 'issue',
        patterns: [new RegExp("algolia[_-]?admin[_-]?key[_-]?2(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: algolia_admin_key_2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_algolia_admin_key_mcm', name: "algolia_admin_key_mcm", severity: 'issue',
        patterns: [new RegExp("algolia[_-]?admin[_-]?key[_-]?mcm(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: algolia_admin_key_mcm. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_algolia_api_key', name: "algolia_api_key", severity: 'issue',
        patterns: [new RegExp("algolia[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: algolia_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_algolia_api_key_mcm', name: "algolia_api_key_mcm", severity: 'issue',
        patterns: [new RegExp("algolia[_-]?api[_-]?key[_-]?mcm(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: algolia_api_key_mcm. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_algolia_api_key_search', name: "algolia_api_key_search", severity: 'issue',
        patterns: [new RegExp("algolia[_-]?api[_-]?key[_-]?search(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: algolia_api_key_search. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_algolia_search_api_key', name: "algolia_search_api_key", severity: 'issue',
        patterns: [new RegExp("algolia[_-]?search[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: algolia_search_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_algolia_search_key', name: "algolia_search_key", severity: 'issue',
        patterns: [new RegExp("algolia[_-]?search[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: algolia_search_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_algolia_search_key_1', name: "algolia_search_key_1", severity: 'issue',
        patterns: [new RegExp("algolia[_-]?search[_-]?key[_-]?1(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: algolia_search_key_1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_alias_pass', name: "alias_pass", severity: 'issue',
        patterns: [new RegExp("alias[_-]?pass(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: alias_pass. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_alicloud_access_key', name: "alicloud_access_key", severity: 'issue',
        patterns: [new RegExp("alicloud[_-]?access[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: alicloud_access_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_alicloud_secret_key', name: "alicloud_secret_key", severity: 'issue',
        patterns: [new RegExp("alicloud[_-]?secret[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: alicloud_secret_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_amazon_bucket_name', name: "amazon_bucket_name", severity: 'issue',
        patterns: [new RegExp("amazon[_-]?bucket[_-]?name(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: amazon_bucket_name. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_amazon_secret_access_key', name: "amazon_secret_access_key", severity: 'issue',
        patterns: [new RegExp("amazon[_-]?secret[_-]?access[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: amazon_secret_access_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_anaconda_token', name: "anaconda_token", severity: 'issue',
        patterns: [new RegExp("anaconda[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: anaconda_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_android_docs_deploy_token', name: "android_docs_deploy_token", severity: 'issue',
        patterns: [new RegExp("android[_-]?docs[_-]?deploy[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: android_docs_deploy_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ansible_vault_password', name: "ansible_vault_password", severity: 'issue',
        patterns: [new RegExp("ansible[_-]?vault[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ansible_vault_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aos_key', name: "aos_key", severity: 'issue',
        patterns: [new RegExp("aos[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: aos_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aos_sec', name: "aos_sec", severity: 'issue',
        patterns: [new RegExp("aos[_-]?sec(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: aos_sec. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_api_key', name: "api_key", severity: 'issue',
        patterns: [new RegExp("api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_api_key_secret', name: "api_key_secret", severity: 'issue',
        patterns: [new RegExp("api[_-]?key[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: api_key_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_api_key_sid', name: "api_key_sid", severity: 'issue',
        patterns: [new RegExp("api[_-]?key[_-]?sid(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: api_key_sid. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_api_secret', name: "api_secret", severity: 'issue',
        patterns: [new RegExp("api[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: api_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_apiary_api_key', name: "apiary_api_key", severity: 'issue',
        patterns: [new RegExp("apiary[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: apiary_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_apigw_access_token', name: "apigw_access_token", severity: 'issue',
        patterns: [new RegExp("apigw[_-]?access[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: apigw_access_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_apikey_patterns', name: "apikey_patterns", severity: 'issue',
        patterns: [new RegExp("apikey[:](?:['\"]?[a-zA-Z0-9-_|]+['\"]?)", 'gi')],
        description: 'Detected sensitive pattern: apikey_patterns. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_app_bucket_perm', name: "app_bucket_perm", severity: 'issue',
        patterns: [new RegExp("app[_-]?bucket[_-]?perm(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: app_bucket_perm. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_app_report_token_key', name: "app_report_token_key", severity: 'issue',
        patterns: [new RegExp("app[_-]?report[_-]?token[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: app_report_token_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_app_secrete', name: "app_secrete", severity: 'issue',
        patterns: [new RegExp("app[_-]?secrete(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: app_secrete. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_app_token', name: "app_token", severity: 'issue',
        patterns: [new RegExp("app[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: app_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_appclientsecret', name: "appclientsecret", severity: 'issue',
        patterns: [new RegExp("appclientsecret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: appclientsecret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_apple_id_password', name: "apple_id_password", severity: 'issue',
        patterns: [new RegExp("apple[_-]?id[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: apple_id_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_argos_token', name: "argos_token", severity: 'issue',
        patterns: [new RegExp("argos[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: argos_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_artifactory', name: "artifactory", severity: 'issue',
        patterns: [new RegExp("(artifactory.{0,50}(\"|')?[a-zA-Z0-9=]{112}(\"|')?)", 'gi')],
        description: 'Detected sensitive pattern: artifactory. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_artifactory_key', name: "artifactory_key", severity: 'issue',
        patterns: [new RegExp("artifactory[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: artifactory_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_artifacts_aws_access_key_id', name: "artifacts_aws_access_key_id", severity: 'issue',
        patterns: [new RegExp("artifacts[_-]?aws[_-]?access[_-]?key[_-]?id(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: artifacts_aws_access_key_id. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_artifacts_aws_secret_access_key', name: "artifacts_aws_secret_access_key", severity: 'issue',
        patterns: [new RegExp("artifacts[_-]?aws[_-]?secret[_-]?access[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: artifacts_aws_secret_access_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_artifacts_bucket', name: "artifacts_bucket", severity: 'issue',
        patterns: [new RegExp("artifacts[_-]?bucket(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: artifacts_bucket. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_artifacts_key', name: "artifacts_key", severity: 'issue',
        patterns: [new RegExp("artifacts[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: artifacts_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_artifacts_secret', name: "artifacts_secret", severity: 'issue',
        patterns: [new RegExp("artifacts[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: artifacts_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_assistant_iam_apikey', name: "assistant_iam_apikey", severity: 'issue',
        patterns: [new RegExp("assistant[_-]?iam[_-]?apikey(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: assistant_iam_apikey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_auth0_api_clientsecret', name: "auth0_api_clientsecret", severity: 'issue',
        patterns: [new RegExp("auth0[_-]?api[_-]?clientsecret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: auth0_api_clientsecret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_auth0_client_secret', name: "auth0_client_secret", severity: 'issue',
        patterns: [new RegExp("auth0[_-]?client[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: auth0_client_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_auth_token', name: "auth_token", severity: 'issue',
        patterns: [new RegExp("auth[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: auth_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_author_email_addr', name: "author_email_addr", severity: 'issue',
        patterns: [new RegExp("author[_-]?email[_-]?addr(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: author_email_addr. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_author_npm_api_key', name: "author_npm_api_key", severity: 'issue',
        patterns: [new RegExp("author[_-]?npm[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: author_npm_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_access', name: "aws_access", severity: 'issue',
        patterns: [new RegExp("aws[_-]?access(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: aws_access. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_access_key', name: "aws_access_key", severity: 'issue',
        patterns: [new RegExp("aws[_-]?access[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: aws_access_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_access_key_id_1', name: "aws_access_key_id - 1", severity: 'issue',
        patterns: [new RegExp("aws[_-]?access[_-]?key[_-]?id(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: aws_access_key_id - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_config_accesskeyid', name: "aws_config_accesskeyid", severity: 'issue',
        patterns: [new RegExp("aws[_-]?config[_-]?accesskeyid(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: aws_config_accesskeyid. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_config_secretaccesskey', name: "aws_config_secretaccesskey", severity: 'issue',
        patterns: [new RegExp("aws[_-]?config[_-]?secretaccesskey(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: aws_config_secretaccesskey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_key', name: "aws_key", severity: 'issue',
        patterns: [new RegExp("aws[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: aws_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_patterns', name: "aws_patterns", severity: 'issue',
        patterns: [new RegExp("(?:accesskeyid|secretaccesskey|aws_access_key_id|aws_secret_access_key)", 'gi')],
        description: 'Detected sensitive pattern: aws_patterns. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_secret', name: "aws_secret", severity: 'issue',
        patterns: [new RegExp("aws[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: aws_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_secret_access_key', name: "aws_secret_access_key", severity: 'issue',
        patterns: [new RegExp("aws[_-]?secret[_-]?access[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: aws_secret_access_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_secret_key', name: "aws_secret_key", severity: 'issue',
        patterns: [new RegExp("aws[_-]?secret[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: aws_secret_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_secrets', name: "aws_secrets", severity: 'issue',
        patterns: [new RegExp("aws[_-]?secrets(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: aws_secrets. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_ses_access_key_id', name: "aws_ses_access_key_id", severity: 'issue',
        patterns: [new RegExp("aws[_-]?ses[_-]?access[_-]?key[_-]?id(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: aws_ses_access_key_id. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_aws_ses_secret_access_key', name: "aws_ses_secret_access_key", severity: 'issue',
        patterns: [new RegExp("aws[_-]?ses[_-]?secret[_-]?access[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: aws_ses_secret_access_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_awsaccesskeyid', name: "awsaccesskeyid", severity: 'issue',
        patterns: [new RegExp("awsaccesskeyid(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: awsaccesskeyid. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_awscn_access_key_id', name: "awscn_access_key_id", severity: 'issue',
        patterns: [new RegExp("awscn[_-]?access[_-]?key[_-]?id(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: awscn_access_key_id. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_awscn_secret_access_key', name: "awscn_secret_access_key", severity: 'issue',
        patterns: [new RegExp("awscn[_-]?secret[_-]?access[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: awscn_secret_access_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_awssecretkey', name: "awssecretkey", severity: 'issue',
        patterns: [new RegExp("awssecretkey(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: awssecretkey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_b2_app_key', name: "b2_app_key", severity: 'issue',
        patterns: [new RegExp("b2[_-]?app[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: b2_app_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_b2_bucket', name: "b2_bucket", severity: 'issue',
        patterns: [new RegExp("b2[_-]?bucket(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: b2_bucket. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bintray_api_key', name: "bintray_api_key", severity: 'issue',
        patterns: [new RegExp("bintray[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: bintray_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bintray_apikey', name: "bintray_apikey", severity: 'issue',
        patterns: [new RegExp("bintray[_-]?apikey(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: bintray_apikey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bintray_gpg_password', name: "bintray_gpg_password", severity: 'issue',
        patterns: [new RegExp("bintray[_-]?gpg[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: bintray_gpg_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bintray_key', name: "bintray_key", severity: 'issue',
        patterns: [new RegExp("bintray[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: bintray_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bintray_token', name: "bintray_token", severity: 'issue',
        patterns: [new RegExp("bintray[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: bintray_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bintraykey', name: "bintraykey", severity: 'issue',
        patterns: [new RegExp("bintraykey(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: bintraykey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bluemix_api_key', name: "bluemix_api_key", severity: 'issue',
        patterns: [new RegExp("bluemix[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: bluemix_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bluemix_auth', name: "bluemix_auth", severity: 'issue',
        patterns: [new RegExp("bluemix[_-]?auth(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: bluemix_auth. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bluemix_pass', name: "bluemix_pass", severity: 'issue',
        patterns: [new RegExp("bluemix[_-]?pass(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: bluemix_pass. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bluemix_pass_prod', name: "bluemix_pass_prod", severity: 'issue',
        patterns: [new RegExp("bluemix[_-]?pass[_-]?prod(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: bluemix_pass_prod. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bluemix_password', name: "bluemix_password", severity: 'issue',
        patterns: [new RegExp("bluemix[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: bluemix_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bluemix_pwd', name: "bluemix_pwd", severity: 'issue',
        patterns: [new RegExp("bluemix[_-]?pwd(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: bluemix_pwd. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bluemix_username', name: "bluemix_username", severity: 'issue',
        patterns: [new RegExp("bluemix[_-]?username(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: bluemix_username. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_brackets_repo_oauth_token', name: "brackets_repo_oauth_token", severity: 'issue',
        patterns: [new RegExp("brackets[_-]?repo[_-]?oauth[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: brackets_repo_oauth_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_browser_stack_access_key', name: "browser_stack_access_key", severity: 'issue',
        patterns: [new RegExp("browser[_-]?stack[_-]?access[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: browser_stack_access_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_browserstack_access_key', name: "browserstack_access_key", severity: 'issue',
        patterns: [new RegExp("browserstack[_-]?access[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: browserstack_access_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bucketeer_aws_access_key_id', name: "bucketeer_aws_access_key_id", severity: 'issue',
        patterns: [new RegExp("bucketeer[_-]?aws[_-]?access[_-]?key[_-]?id(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: bucketeer_aws_access_key_id. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bucketeer_aws_secret_access_key', name: "bucketeer_aws_secret_access_key", severity: 'issue',
        patterns: [new RegExp("bucketeer[_-]?aws[_-]?secret[_-]?access[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: bucketeer_aws_secret_access_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_built_branch_deploy_key', name: "built_branch_deploy_key", severity: 'issue',
        patterns: [new RegExp("built[_-]?branch[_-]?deploy[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: built_branch_deploy_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bundlesize_github_token', name: "bundlesize_github_token", severity: 'issue',
        patterns: [new RegExp("bundlesize[_-]?github[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: bundlesize_github_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bx_password', name: "bx_password", severity: 'issue',
        patterns: [new RegExp("bx[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: bx_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_bx_username', name: "bx_username", severity: 'issue',
        patterns: [new RegExp("bx[_-]?username(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: bx_username. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cache_s3_secret_key', name: "cache_s3_secret_key", severity: 'issue',
        patterns: [new RegExp("cache[_-]?s3[_-]?secret[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cache_s3_secret_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cargo_token', name: "cargo_token", severity: 'issue',
        patterns: [new RegExp("cargo[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cargo_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cattle_access_key', name: "cattle_access_key", severity: 'issue',
        patterns: [new RegExp("cattle[_-]?access[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cattle_access_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cattle_agent_instance_auth', name: "cattle_agent_instance_auth", severity: 'issue',
        patterns: [new RegExp("cattle[_-]?agent[_-]?instance[_-]?auth(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cattle_agent_instance_auth. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cattle_secret_key', name: "cattle_secret_key", severity: 'issue',
        patterns: [new RegExp("cattle[_-]?secret[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cattle_secret_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_censys_secret', name: "censys_secret", severity: 'issue',
        patterns: [new RegExp("censys[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: censys_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_certificate_password', name: "certificate_password", severity: 'issue',
        patterns: [new RegExp("certificate[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: certificate_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cf_password', name: "cf_password", severity: 'issue',
        patterns: [new RegExp("cf[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cf_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cheverny_token', name: "cheverny_token", severity: 'issue',
        patterns: [new RegExp("cheverny[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cheverny_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_chrome_client_secret', name: "chrome_client_secret", severity: 'issue',
        patterns: [new RegExp("chrome[_-]?client[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: chrome_client_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_chrome_refresh_token', name: "chrome_refresh_token", severity: 'issue',
        patterns: [new RegExp("chrome[_-]?refresh[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: chrome_refresh_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ci_deploy_password', name: "ci_deploy_password", severity: 'issue',
        patterns: [new RegExp("ci[_-]?deploy[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ci_deploy_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ci_project_url', name: "ci_project_url", severity: 'issue',
        patterns: [new RegExp("ci[_-]?project[_-]?url(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ci_project_url. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ci_registry_user', name: "ci_registry_user", severity: 'issue',
        patterns: [new RegExp("ci[_-]?registry[_-]?user(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ci_registry_user. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ci_server_name', name: "ci_server_name", severity: 'issue',
        patterns: [new RegExp("ci[_-]?server[_-]?name(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ci_server_name. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ci_user_token', name: "ci_user_token", severity: 'issue',
        patterns: [new RegExp("ci[_-]?user[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ci_user_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_claimr_database', name: "claimr_database", severity: 'issue',
        patterns: [new RegExp("claimr[_-]?database(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: claimr_database. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_claimr_db', name: "claimr_db", severity: 'issue',
        patterns: [new RegExp("claimr[_-]?db(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: claimr_db. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_claimr_superuser', name: "claimr_superuser", severity: 'issue',
        patterns: [new RegExp("claimr[_-]?superuser(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: claimr_superuser. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_claimr_token', name: "claimr_token", severity: 'issue',
        patterns: [new RegExp("claimr[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: claimr_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cli_e2e_cma_token', name: "cli_e2e_cma_token", severity: 'issue',
        patterns: [new RegExp("cli[_-]?e2e[_-]?cma[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cli_e2e_cma_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_client_secret', name: "client_secret", severity: 'issue',
        patterns: [new RegExp("client[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: client_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_clojars_password', name: "clojars_password", severity: 'issue',
        patterns: [new RegExp("clojars[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: clojars_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloud_api_key', name: "cloud_api_key", severity: 'issue',
        patterns: [new RegExp("cloud[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cloud_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloudant_archived_database', name: "cloudant_archived_database", severity: 'issue',
        patterns: [new RegExp("cloudant[_-]?archived[_-]?database(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cloudant_archived_database. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloudant_audited_database', name: "cloudant_audited_database", severity: 'issue',
        patterns: [new RegExp("cloudant[_-]?audited[_-]?database(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cloudant_audited_database. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloudant_database', name: "cloudant_database", severity: 'issue',
        patterns: [new RegExp("cloudant[_-]?database(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cloudant_database. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloudant_instance', name: "cloudant_instance", severity: 'issue',
        patterns: [new RegExp("cloudant[_-]?instance(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cloudant_instance. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloudant_order_database', name: "cloudant_order_database", severity: 'issue',
        patterns: [new RegExp("cloudant[_-]?order[_-]?database(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cloudant_order_database. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloudant_parsed_database', name: "cloudant_parsed_database", severity: 'issue',
        patterns: [new RegExp("cloudant[_-]?parsed[_-]?database(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cloudant_parsed_database. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloudant_password', name: "cloudant_password", severity: 'issue',
        patterns: [new RegExp("cloudant[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cloudant_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloudant_processed_database', name: "cloudant_processed_database", severity: 'issue',
        patterns: [new RegExp("cloudant[_-]?processed[_-]?database(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cloudant_processed_database. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloudant_service_database', name: "cloudant_service_database", severity: 'issue',
        patterns: [new RegExp("cloudant[_-]?service[_-]?database(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cloudant_service_database. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloudflare_api_key', name: "cloudflare_api_key", severity: 'issue',
        patterns: [new RegExp("cloudflare[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cloudflare_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloudflare_auth_email', name: "cloudflare_auth_email", severity: 'issue',
        patterns: [new RegExp("cloudflare[_-]?auth[_-]?email(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cloudflare_auth_email. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloudflare_auth_key', name: "cloudflare_auth_key", severity: 'issue',
        patterns: [new RegExp("cloudflare[_-]?auth[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cloudflare_auth_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloudflare_email', name: "cloudflare_email", severity: 'issue',
        patterns: [new RegExp("cloudflare[_-]?email(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cloudflare_email. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloudinary_url', name: "cloudinary_url", severity: 'issue',
        patterns: [new RegExp("cloudinary[_-]?url(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cloudinary_url. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cloudinary_url_staging', name: "cloudinary_url_staging", severity: 'issue',
        patterns: [new RegExp("cloudinary[_-]?url[_-]?staging(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cloudinary_url_staging. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_clu_repo_url', name: "clu_repo_url", severity: 'issue',
        patterns: [new RegExp("clu[_-]?repo[_-]?url(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: clu_repo_url. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_clu_ssh_private_key_base64', name: "clu_ssh_private_key_base64", severity: 'issue',
        patterns: [new RegExp("clu[_-]?ssh[_-]?private[_-]?key[_-]?base64(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: clu_ssh_private_key_base64. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cn_access_key_id', name: "cn_access_key_id", severity: 'issue',
        patterns: [new RegExp("cn[_-]?access[_-]?key[_-]?id(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cn_access_key_id. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cn_secret_access_key', name: "cn_secret_access_key", severity: 'issue',
        patterns: [new RegExp("cn[_-]?secret[_-]?access[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cn_secret_access_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cocoapods_trunk_email', name: "cocoapods_trunk_email", severity: 'issue',
        patterns: [new RegExp("cocoapods[_-]?trunk[_-]?email(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cocoapods_trunk_email. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cocoapods_trunk_token', name: "cocoapods_trunk_token", severity: 'issue',
        patterns: [new RegExp("cocoapods[_-]?trunk[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cocoapods_trunk_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_codacy_project_token', name: "codacy_project_token", severity: 'issue',
        patterns: [new RegExp("codacy[_-]?project[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: codacy_project_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_codeclimate', name: "codeclimate", severity: 'issue',
        patterns: [new RegExp("(codeclima.{0,50}(\"|')?[0-9a-f]{64}(\"|')?)", 'gi')],
        description: 'Detected sensitive pattern: codeclimate. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_codeclimate_repo_token', name: "codeclimate_repo_token", severity: 'issue',
        patterns: [new RegExp("codeclimate[_-]?repo[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: codeclimate_repo_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_codecov_token', name: "codecov_token", severity: 'issue',
        patterns: [new RegExp("codecov[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: codecov_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_coding_token', name: "coding_token", severity: 'issue',
        patterns: [new RegExp("coding[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: coding_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_conekta_apikey', name: "conekta_apikey", severity: 'issue',
        patterns: [new RegExp("conekta[_-]?apikey(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: conekta_apikey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_consumer_key', name: "consumer_key", severity: 'issue',
        patterns: [new RegExp("consumer[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: consumer_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_consumerkey', name: "consumerkey", severity: 'issue',
        patterns: [new RegExp("consumerkey(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: consumerkey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_contentful_access_token', name: "contentful_access_token", severity: 'issue',
        patterns: [new RegExp("contentful[_-]?access[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: contentful_access_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_contentful_cma_test_token', name: "contentful_cma_test_token", severity: 'issue',
        patterns: [new RegExp("contentful[_-]?cma[_-]?test[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: contentful_cma_test_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_contentful_integration_management_token', name: "contentful_integration_management_token", severity: 'issue',
        patterns: [new RegExp("contentful[_-]?integration[_-]?management[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: contentful_integration_management_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_contentful_php_management_test_token', name: "contentful_php_management_test_token", severity: 'issue',
        patterns: [new RegExp("contentful[_-]?php[_-]?management[_-]?test[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: contentful_php_management_test_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_contentful_test_org_cma_token', name: "contentful_test_org_cma_token", severity: 'issue',
        patterns: [new RegExp("contentful[_-]?test[_-]?org[_-]?cma[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: contentful_test_org_cma_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_contentful_v2_access_token', name: "contentful_v2_access_token", severity: 'issue',
        patterns: [new RegExp("contentful[_-]?v2[_-]?access[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: contentful_v2_access_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_conversation_password', name: "conversation_password", severity: 'issue',
        patterns: [new RegExp("conversation[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: conversation_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_conversation_username', name: "conversation_username", severity: 'issue',
        patterns: [new RegExp("conversation[_-]?username(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: conversation_username. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cos_secrets', name: "cos_secrets", severity: 'issue',
        patterns: [new RegExp("cos[_-]?secrets(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cos_secrets. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_coveralls_api_token', name: "coveralls_api_token", severity: 'issue',
        patterns: [new RegExp("coveralls[_-]?api[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: coveralls_api_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_coveralls_repo_token', name: "coveralls_repo_token", severity: 'issue',
        patterns: [new RegExp("coveralls[_-]?repo[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: coveralls_repo_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_coveralls_token', name: "coveralls_token", severity: 'issue',
        patterns: [new RegExp("coveralls[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: coveralls_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_coverity_scan_token', name: "coverity_scan_token", severity: 'issue',
        patterns: [new RegExp("coverity[_-]?scan[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: coverity_scan_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_cypress_record_key', name: "cypress_record_key", severity: 'issue',
        patterns: [new RegExp("cypress[_-]?record[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: cypress_record_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_danger_github_api_token', name: "danger_github_api_token", severity: 'issue',
        patterns: [new RegExp("danger[_-]?github[_-]?api[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: danger_github_api_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_database_host', name: "database_host", severity: 'issue',
        patterns: [new RegExp("database[_-]?host(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: database_host. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_database_name', name: "database_name", severity: 'issue',
        patterns: [new RegExp("database[_-]?name(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: database_name. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_database_password', name: "database_password", severity: 'issue',
        patterns: [new RegExp("database[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: database_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_database_port', name: "database_port", severity: 'issue',
        patterns: [new RegExp("database[_-]?port(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: database_port. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_database_user', name: "database_user", severity: 'issue',
        patterns: [new RegExp("database[_-]?user(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: database_user. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_database_username', name: "database_username", severity: 'issue',
        patterns: [new RegExp("database[_-]?username(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: database_username. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_datadog_api_key', name: "datadog_api_key", severity: 'issue',
        patterns: [new RegExp("datadog[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: datadog_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_datadog_app_key', name: "datadog_app_key", severity: 'issue',
        patterns: [new RegExp("datadog[_-]?app[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: datadog_app_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_db_connection', name: "db_connection", severity: 'issue',
        patterns: [new RegExp("db[_-]?connection(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: db_connection. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_db_database', name: "db_database", severity: 'issue',
        patterns: [new RegExp("db[_-]?database(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: db_database. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_db_host', name: "db_host", severity: 'issue',
        patterns: [new RegExp("db[_-]?host(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: db_host. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_db_password', name: "db_password", severity: 'issue',
        patterns: [new RegExp("db[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: db_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_db_pw', name: "db_pw", severity: 'issue',
        patterns: [new RegExp("db[_-]?pw(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: db_pw. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_db_user', name: "db_user", severity: 'issue',
        patterns: [new RegExp("db[_-]?user(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: db_user. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_db_username', name: "db_username", severity: 'issue',
        patterns: [new RegExp("db[_-]?username(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: db_username. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ddg_test_email', name: "ddg_test_email", severity: 'issue',
        patterns: [new RegExp("ddg[_-]?test[_-]?email(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ddg_test_email. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ddg_test_email_pw', name: "ddg_test_email_pw", severity: 'issue',
        patterns: [new RegExp("ddg[_-]?test[_-]?email[_-]?pw(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ddg_test_email_pw. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ddgc_github_token', name: "ddgc_github_token", severity: 'issue',
        patterns: [new RegExp("ddgc[_-]?github[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ddgc_github_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_deploy_password', name: "deploy_password", severity: 'issue',
        patterns: [new RegExp("deploy[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: deploy_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_deploy_secure', name: "deploy_secure", severity: 'issue',
        patterns: [new RegExp("deploy[_-]?secure(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: deploy_secure. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_deploy_token', name: "deploy_token", severity: 'issue',
        patterns: [new RegExp("deploy[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: deploy_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_deploy_user', name: "deploy_user", severity: 'issue',
        patterns: [new RegExp("deploy[_-]?user(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: deploy_user. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_dgpg_passphrase', name: "dgpg_passphrase", severity: 'issue',
        patterns: [new RegExp("dgpg[_-]?passphrase(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: dgpg_passphrase. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_digitalocean_access_token', name: "digitalocean_access_token", severity: 'issue',
        patterns: [new RegExp("digitalocean[_-]?access[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: digitalocean_access_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_digitalocean_ssh_key_body', name: "digitalocean_ssh_key_body", severity: 'issue',
        patterns: [new RegExp("digitalocean[_-]?ssh[_-]?key[_-]?body(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: digitalocean_ssh_key_body. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_digitalocean_ssh_key_ids', name: "digitalocean_ssh_key_ids", severity: 'issue',
        patterns: [new RegExp("digitalocean[_-]?ssh[_-]?key[_-]?ids(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: digitalocean_ssh_key_ids. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_docker_hub_password', name: "docker_hub_password", severity: 'issue',
        patterns: [new RegExp("docker[_-]?hub[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: docker_hub_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_docker_key', name: "docker_key", severity: 'issue',
        patterns: [new RegExp("docker[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: docker_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_docker_pass', name: "docker_pass", severity: 'issue',
        patterns: [new RegExp("docker[_-]?pass(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: docker_pass. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_docker_passwd', name: "docker_passwd", severity: 'issue',
        patterns: [new RegExp("docker[_-]?passwd(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: docker_passwd. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_docker_password', name: "docker_password", severity: 'issue',
        patterns: [new RegExp("docker[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: docker_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_docker_postgres_url', name: "docker_postgres_url", severity: 'issue',
        patterns: [new RegExp("docker[_-]?postgres[_-]?url(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: docker_postgres_url. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_docker_token', name: "docker_token", severity: 'issue',
        patterns: [new RegExp("docker[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: docker_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_dockerhub_password', name: "dockerhub_password", severity: 'issue',
        patterns: [new RegExp("dockerhub[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: dockerhub_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_dockerhubpassword', name: "dockerhubpassword", severity: 'issue',
        patterns: [new RegExp("dockerhubpassword(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: dockerhubpassword. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_doordash_auth_token', name: "doordash_auth_token", severity: 'issue',
        patterns: [new RegExp("doordash[_-]?auth[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: doordash_auth_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_dropbox_oauth_bearer', name: "dropbox_oauth_bearer", severity: 'issue',
        patterns: [new RegExp("dropbox[_-]?oauth[_-]?bearer(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: dropbox_oauth_bearer. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_droplet_travis_password', name: "droplet_travis_password", severity: 'issue',
        patterns: [new RegExp("droplet[_-]?travis[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: droplet_travis_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_dsonar_login', name: "dsonar_login", severity: 'issue',
        patterns: [new RegExp("dsonar[_-]?login(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: dsonar_login. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_dsonar_projectkey', name: "dsonar_projectkey", severity: 'issue',
        patterns: [new RegExp("dsonar[_-]?projectkey(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: dsonar_projectkey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_elastic_cloud_auth', name: "elastic_cloud_auth", severity: 'issue',
        patterns: [new RegExp("elastic[_-]?cloud[_-]?auth(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: elastic_cloud_auth. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_elasticsearch_password', name: "elasticsearch_password", severity: 'issue',
        patterns: [new RegExp("elasticsearch[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: elasticsearch_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_encryption_password', name: "encryption_password", severity: 'issue',
        patterns: [new RegExp("encryption[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: encryption_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_end_user_password', name: "end_user_password", severity: 'issue',
        patterns: [new RegExp("end[_-]?user[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: end_user_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_env_github_oauth_token', name: "env_github_oauth_token", severity: 'issue',
        patterns: [new RegExp("env[_-]?github[_-]?oauth[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: env_github_oauth_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_env_heroku_api_key', name: "env_heroku_api_key", severity: 'issue',
        patterns: [new RegExp("env[_-]?heroku[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: env_heroku_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_env_key', name: "env_key", severity: 'issue',
        patterns: [new RegExp("env[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: env_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_env_secret', name: "env_secret", severity: 'issue',
        patterns: [new RegExp("env[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: env_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_env_secret_access_key', name: "env_secret_access_key", severity: 'issue',
        patterns: [new RegExp("env[_-]?secret[_-]?access[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: env_secret_access_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_env_sonatype_password', name: "env_sonatype_password", severity: 'issue',
        patterns: [new RegExp("env[_-]?sonatype[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: env_sonatype_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_eureka_awssecretkey', name: "eureka_awssecretkey", severity: 'issue',
        patterns: [new RegExp("eureka[_-]?awssecretkey(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: eureka_awssecretkey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_exp_password', name: "exp_password", severity: 'issue',
        patterns: [new RegExp("exp[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: exp_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_facebook_access_token', name: "facebook_access_token", severity: 'issue',
        patterns: [new RegExp("(EAACEdEose0cBA[0-9A-Za-z]+)", 'gi')],
        description: 'Detected sensitive pattern: facebook_access_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_facebook_oauth', name: "facebook_oauth", severity: 'issue',
        patterns: [new RegExp("[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*[''|\"][0-9a-f]{32}[''|\"]", 'gi')],
        description: 'Detected sensitive pattern: facebook_oauth. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_file_password', name: "file_password", severity: 'issue',
        patterns: [new RegExp("file[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: file_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_firebase_api_json', name: "firebase_api_json", severity: 'issue',
        patterns: [new RegExp("firebase[_-]?api[_-]?json(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: firebase_api_json. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_firebase_api_token', name: "firebase_api_token", severity: 'issue',
        patterns: [new RegExp("firebase[_-]?api[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: firebase_api_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_firebase_key', name: "firebase_key", severity: 'issue',
        patterns: [new RegExp("firebase[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: firebase_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_firebase_project_develop', name: "firebase_project_develop", severity: 'issue',
        patterns: [new RegExp("firebase[_-]?project[_-]?develop(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: firebase_project_develop. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_firebase_token', name: "firebase_token", severity: 'issue',
        patterns: [new RegExp("firebase[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: firebase_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_firefox_secret', name: "firefox_secret", severity: 'issue',
        patterns: [new RegExp("firefox[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: firefox_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_flask_secret_key', name: "flask_secret_key", severity: 'issue',
        patterns: [new RegExp("flask[_-]?secret[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: flask_secret_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_flickr_api_key', name: "flickr_api_key", severity: 'issue',
        patterns: [new RegExp("flickr[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: flickr_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_flickr_api_secret', name: "flickr_api_secret", severity: 'issue',
        patterns: [new RegExp("flickr[_-]?api[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: flickr_api_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_fossa_api_key', name: "fossa_api_key", severity: 'issue',
        patterns: [new RegExp("fossa[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: fossa_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ftp_host', name: "ftp_host", severity: 'issue',
        patterns: [new RegExp("ftp[_-]?host(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ftp_host. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ftp_login', name: "ftp_login", severity: 'issue',
        patterns: [new RegExp("ftp[_-]?login(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ftp_login. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ftp_password', name: "ftp_password", severity: 'issue',
        patterns: [new RegExp("ftp[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ftp_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ftp_pw', name: "ftp_pw", severity: 'issue',
        patterns: [new RegExp("ftp[_-]?pw(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ftp_pw. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ftp_user', name: "ftp_user", severity: 'issue',
        patterns: [new RegExp("ftp[_-]?user(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ftp_user. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ftp_username', name: "ftp_username", severity: 'issue',
        patterns: [new RegExp("ftp[_-]?username(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ftp_username. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gcloud_bucket', name: "gcloud_bucket", severity: 'issue',
        patterns: [new RegExp("gcloud[_-]?bucket(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gcloud_bucket. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gcloud_project', name: "gcloud_project", severity: 'issue',
        patterns: [new RegExp("gcloud[_-]?project(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gcloud_project. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gcloud_service_key', name: "gcloud_service_key", severity: 'issue',
        patterns: [new RegExp("gcloud[_-]?service[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gcloud_service_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gcr_password', name: "gcr_password", severity: 'issue',
        patterns: [new RegExp("gcr[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gcr_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gcs_bucket', name: "gcs_bucket", severity: 'issue',
        patterns: [new RegExp("gcs[_-]?bucket(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gcs_bucket. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gh_api_key', name: "gh_api_key", severity: 'issue',
        patterns: [new RegExp("gh[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gh_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gh_email', name: "gh_email", severity: 'issue',
        patterns: [new RegExp("gh[_-]?email(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gh_email. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gh_next_oauth_client_secret', name: "gh_next_oauth_client_secret", severity: 'issue',
        patterns: [new RegExp("gh[_-]?next[_-]?oauth[_-]?client[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gh_next_oauth_client_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gh_next_unstable_oauth_client_id', name: "gh_next_unstable_oauth_client_id", severity: 'issue',
        patterns: [new RegExp("gh[_-]?next[_-]?unstable[_-]?oauth[_-]?client[_-]?id(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gh_next_unstable_oauth_client_id. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gh_next_unstable_oauth_client_secret', name: "gh_next_unstable_oauth_client_secret", severity: 'issue',
        patterns: [new RegExp("gh[_-]?next[_-]?unstable[_-]?oauth[_-]?client[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gh_next_unstable_oauth_client_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gh_oauth_client_secret', name: "gh_oauth_client_secret", severity: 'issue',
        patterns: [new RegExp("gh[_-]?oauth[_-]?client[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gh_oauth_client_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gh_oauth_token', name: "gh_oauth_token", severity: 'issue',
        patterns: [new RegExp("gh[_-]?oauth[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gh_oauth_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gh_repo_token', name: "gh_repo_token", severity: 'issue',
        patterns: [new RegExp("gh[_-]?repo[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gh_repo_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gh_token', name: "gh_token", severity: 'issue',
        patterns: [new RegExp("gh[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gh_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gh_unstable_oauth_client_secret', name: "gh_unstable_oauth_client_secret", severity: 'issue',
        patterns: [new RegExp("gh[_-]?unstable[_-]?oauth[_-]?client[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gh_unstable_oauth_client_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ghb_token', name: "ghb_token", severity: 'issue',
        patterns: [new RegExp("ghb[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ghb_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ghost_api_key', name: "ghost_api_key", severity: 'issue',
        patterns: [new RegExp("ghost[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ghost_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_git_author_email', name: "git_author_email", severity: 'issue',
        patterns: [new RegExp("git[_-]?author[_-]?email(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: git_author_email. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_git_author_name', name: "git_author_name", severity: 'issue',
        patterns: [new RegExp("git[_-]?author[_-]?name(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: git_author_name. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_git_committer_email', name: "git_committer_email", severity: 'issue',
        patterns: [new RegExp("git[_-]?committer[_-]?email(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: git_committer_email. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_git_committer_name', name: "git_committer_name", severity: 'issue',
        patterns: [new RegExp("git[_-]?committer[_-]?name(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: git_committer_name. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_git_email', name: "git_email", severity: 'issue',
        patterns: [new RegExp("git[_-]?email(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: git_email. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_git_name', name: "git_name", severity: 'issue',
        patterns: [new RegExp("git[_-]?name(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: git_name. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_git_token', name: "git_token", severity: 'issue',
        patterns: [new RegExp("git[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: git_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github_access_token_1', name: "github_access_token - 1", severity: 'issue',
        patterns: [new RegExp("github[_-]?access[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: github_access_token - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github_access_token_2', name: "github_access_token - 2", severity: 'issue',
        patterns: [new RegExp("[a-zA-Z0-9_-]*:[a-zA-Z0-9_-]+@github.com*", 'gi')],
        description: 'Detected sensitive pattern: github_access_token - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github_api_key', name: "github_api_key", severity: 'issue',
        patterns: [new RegExp("github[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: github_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github_api_token', name: "github_api_token", severity: 'issue',
        patterns: [new RegExp("github[_-]?api[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: github_api_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github_auth', name: "github_auth", severity: 'issue',
        patterns: [new RegExp("github[_-]?auth(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: github_auth. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github_auth_token', name: "github_auth_token", severity: 'issue',
        patterns: [new RegExp("github[_-]?auth[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: github_auth_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github_client_secret', name: "github_client_secret", severity: 'issue',
        patterns: [new RegExp("github[_-]?client[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: github_client_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github_deploy_hb_doc_pass', name: "github_deploy_hb_doc_pass", severity: 'issue',
        patterns: [new RegExp("github[_-]?deploy[_-]?hb[_-]?doc[_-]?pass(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: github_deploy_hb_doc_pass. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github_deployment_token', name: "github_deployment_token", severity: 'issue',
        patterns: [new RegExp("github[_-]?deployment[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: github_deployment_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github_hunter_token', name: "github_hunter_token", severity: 'issue',
        patterns: [new RegExp("github[_-]?hunter[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: github_hunter_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github_hunter_username', name: "github_hunter_username", severity: 'issue',
        patterns: [new RegExp("github[_-]?hunter[_-]?username(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: github_hunter_username. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github_key', name: "github_key", severity: 'issue',
        patterns: [new RegExp("github[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: github_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github_oauth', name: "github_oauth", severity: 'issue',
        patterns: [new RegExp("github[_-]?oauth(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: github_oauth. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github_oauth_token', name: "github_oauth_token", severity: 'issue',
        patterns: [new RegExp("github[_-]?oauth[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: github_oauth_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github_password', name: "github_password", severity: 'issue',
        patterns: [new RegExp("github[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: github_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github_pwd', name: "github_pwd", severity: 'issue',
        patterns: [new RegExp("github[_-]?pwd(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: github_pwd. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github_release_token', name: "github_release_token", severity: 'issue',
        patterns: [new RegExp("github[_-]?release[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: github_release_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github_repo', name: "github_repo", severity: 'issue',
        patterns: [new RegExp("github[_-]?repo(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: github_repo. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github_token', name: "github_token", severity: 'issue',
        patterns: [new RegExp("github[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: github_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_github_tokens', name: "github_tokens", severity: 'issue',
        patterns: [new RegExp("github[_-]?tokens(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: github_tokens. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gitlab_user_email', name: "gitlab_user_email", severity: 'issue',
        patterns: [new RegExp("gitlab[_-]?user[_-]?email(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gitlab_user_email. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gogs_password', name: "gogs_password", severity: 'issue',
        patterns: [new RegExp("gogs[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gogs_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_google_account_type', name: "google_account_type", severity: 'issue',
        patterns: [new RegExp("google[_-]?account[_-]?type(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: google_account_type. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_google_client_email', name: "google_client_email", severity: 'issue',
        patterns: [new RegExp("google[_-]?client[_-]?email(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: google_client_email. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_google_client_id', name: "google_client_id", severity: 'issue',
        patterns: [new RegExp("google[_-]?client[_-]?id(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: google_client_id. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_google_client_secret', name: "google_client_secret", severity: 'issue',
        patterns: [new RegExp("google[_-]?client[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: google_client_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_google_maps_api_key', name: "google_maps_api_key", severity: 'issue',
        patterns: [new RegExp("google[_-]?maps[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: google_maps_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_google_oauth', name: "google_oauth", severity: 'issue',
        patterns: [new RegExp("(ya29.[0-9A-Za-z-_]+)", 'gi')],
        description: 'Detected sensitive pattern: google_oauth. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_google_patterns', name: "google_patterns", severity: 'issue',
        patterns: [new RegExp("(?:google_client_id|google_client_secret|google_client_token)", 'gi')],
        description: 'Detected sensitive pattern: google_patterns. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_google_private_key', name: "google_private_key", severity: 'issue',
        patterns: [new RegExp("google[_-]?private[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: google_private_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_google_url', name: "google_url", severity: 'issue',
        patterns: [new RegExp("([0-9]{12}-[a-z0-9]{32}.apps.googleusercontent.com)", 'gi')],
        description: 'Detected sensitive pattern: google_url. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gpg_key_name', name: "gpg_key_name", severity: 'issue',
        patterns: [new RegExp("gpg[_-]?key[_-]?name(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gpg_key_name. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gpg_keyname', name: "gpg_keyname", severity: 'issue',
        patterns: [new RegExp("gpg[_-]?keyname(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gpg_keyname. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gpg_ownertrust', name: "gpg_ownertrust", severity: 'issue',
        patterns: [new RegExp("gpg[_-]?ownertrust(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gpg_ownertrust. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gpg_passphrase', name: "gpg_passphrase", severity: 'issue',
        patterns: [new RegExp("gpg[_-]?passphrase(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gpg_passphrase. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gpg_private_key', name: "gpg_private_key", severity: 'issue',
        patterns: [new RegExp("gpg[_-]?private[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gpg_private_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gpg_secret_keys', name: "gpg_secret_keys", severity: 'issue',
        patterns: [new RegExp("gpg[_-]?secret[_-]?keys(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gpg_secret_keys. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gradle_publish_key', name: "gradle_publish_key", severity: 'issue',
        patterns: [new RegExp("gradle[_-]?publish[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gradle_publish_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gradle_publish_secret', name: "gradle_publish_secret", severity: 'issue',
        patterns: [new RegExp("gradle[_-]?publish[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gradle_publish_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gradle_signing_key_id', name: "gradle_signing_key_id", severity: 'issue',
        patterns: [new RegExp("gradle[_-]?signing[_-]?key[_-]?id(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gradle_signing_key_id. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gradle_signing_password', name: "gradle_signing_password", severity: 'issue',
        patterns: [new RegExp("gradle[_-]?signing[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gradle_signing_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_gren_github_token', name: "gren_github_token", severity: 'issue',
        patterns: [new RegExp("gren[_-]?github[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: gren_github_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_grgit_user', name: "grgit_user", severity: 'issue',
        patterns: [new RegExp("grgit[_-]?user(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: grgit_user. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_hab_auth_token', name: "hab_auth_token", severity: 'issue',
        patterns: [new RegExp("hab[_-]?auth[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: hab_auth_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_hab_key', name: "hab_key", severity: 'issue',
        patterns: [new RegExp("hab[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: hab_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_hb_codesign_gpg_pass', name: "hb_codesign_gpg_pass", severity: 'issue',
        patterns: [new RegExp("hb[_-]?codesign[_-]?gpg[_-]?pass(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: hb_codesign_gpg_pass. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_hb_codesign_key_pass', name: "hb_codesign_key_pass", severity: 'issue',
        patterns: [new RegExp("hb[_-]?codesign[_-]?key[_-]?pass(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: hb_codesign_key_pass. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_heroku_api_key', name: "heroku_api_key", severity: 'issue',
        patterns: [new RegExp("heroku[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: heroku_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_heroku_api_key_api_key', name: "heroku_api_key_api_key", severity: 'issue',
        patterns: [new RegExp("([h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})", 'gi')],
        description: 'Detected sensitive pattern: heroku_api_key_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_heroku_email', name: "heroku_email", severity: 'issue',
        patterns: [new RegExp("heroku[_-]?email(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: heroku_email. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_heroku_token', name: "heroku_token", severity: 'issue',
        patterns: [new RegExp("heroku[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: heroku_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_hockeyapp', name: "hockeyapp", severity: 'issue',
        patterns: [new RegExp("hockey.{0,50}(\"|')?[0-9a-f]{32}(\"|')?", 'gi')],
        description: 'Detected sensitive pattern: hockeyapp. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_hockeyapp_token', name: "hockeyapp_token", severity: 'issue',
        patterns: [new RegExp("hockeyapp[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: hockeyapp_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_homebrew_github_api_token', name: "homebrew_github_api_token", severity: 'issue',
        patterns: [new RegExp("homebrew[_-]?github[_-]?api[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: homebrew_github_api_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_hub_dxia2_password', name: "hub_dxia2_password", severity: 'issue',
        patterns: [new RegExp("hub[_-]?dxia2[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: hub_dxia2_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ij_repo_password', name: "ij_repo_password", severity: 'issue',
        patterns: [new RegExp("ij[_-]?repo[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ij_repo_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ij_repo_username', name: "ij_repo_username", severity: 'issue',
        patterns: [new RegExp("ij[_-]?repo[_-]?username(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ij_repo_username. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_index_name', name: "index_name", severity: 'issue',
        patterns: [new RegExp("index[_-]?name(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: index_name. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_integration_test_api_key', name: "integration_test_api_key", severity: 'issue',
        patterns: [new RegExp("integration[_-]?test[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: integration_test_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_integration_test_appid', name: "integration_test_appid", severity: 'issue',
        patterns: [new RegExp("integration[_-]?test[_-]?appid(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: integration_test_appid. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_internal_secrets', name: "internal_secrets", severity: 'issue',
        patterns: [new RegExp("internal[_-]?secrets(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: internal_secrets. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ios_docs_deploy_token', name: "ios_docs_deploy_token", severity: 'issue',
        patterns: [new RegExp("ios[_-]?docs[_-]?deploy[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ios_docs_deploy_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_itest_gh_token', name: "itest_gh_token", severity: 'issue',
        patterns: [new RegExp("itest[_-]?gh[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: itest_gh_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_jdbc', name: "jdbc", severity: 'issue',
        patterns: [new RegExp("mysql: jdbc:mysql(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: jdbc. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_jdbc_databaseurl', name: "jdbc_databaseurl", severity: 'issue',
        patterns: [new RegExp("jdbc[_-]?databaseurl(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: jdbc_databaseurl. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_jdbc_host', name: "jdbc_host", severity: 'issue',
        patterns: [new RegExp("jdbc[_-]?host(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: jdbc_host. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_jwt_secret', name: "jwt_secret", severity: 'issue',
        patterns: [new RegExp("jwt[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: jwt_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_kafka_admin_url', name: "kafka_admin_url", severity: 'issue',
        patterns: [new RegExp("kafka[_-]?admin[_-]?url(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: kafka_admin_url. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_kafka_instance_name', name: "kafka_instance_name", severity: 'issue',
        patterns: [new RegExp("kafka[_-]?instance[_-]?name(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: kafka_instance_name. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_kafka_rest_url', name: "kafka_rest_url", severity: 'issue',
        patterns: [new RegExp("kafka[_-]?rest[_-]?url(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: kafka_rest_url. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_keystore_pass', name: "keystore_pass", severity: 'issue',
        patterns: [new RegExp("keystore[_-]?pass(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: keystore_pass. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_kovan_private_key', name: "kovan_private_key", severity: 'issue',
        patterns: [new RegExp("kovan[_-]?private[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: kovan_private_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_kubecfg_s3_path', name: "kubecfg_s3_path", severity: 'issue',
        patterns: [new RegExp("kubecfg[_-]?s3[_-]?path(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: kubecfg_s3_path. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_kubeconfig', name: "kubeconfig", severity: 'issue',
        patterns: [new RegExp("kubeconfig(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: kubeconfig. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_kxoltsn3vogdop92m', name: "kxoltsn3vogdop92m", severity: 'issue',
        patterns: [new RegExp("kxoltsn3vogdop92m(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: kxoltsn3vogdop92m. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_leanplum_key', name: "leanplum_key", severity: 'issue',
        patterns: [new RegExp("leanplum[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: leanplum_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_lektor_deploy_password', name: "lektor_deploy_password", severity: 'issue',
        patterns: [new RegExp("lektor[_-]?deploy[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: lektor_deploy_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_lektor_deploy_username', name: "lektor_deploy_username", severity: 'issue',
        patterns: [new RegExp("lektor[_-]?deploy[_-]?username(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: lektor_deploy_username. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_lighthouse_api_key', name: "lighthouse_api_key", severity: 'issue',
        patterns: [new RegExp("lighthouse[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: lighthouse_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_linux_signing_key', name: "linux_signing_key", severity: 'issue',
        patterns: [new RegExp("linux[_-]?signing[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: linux_signing_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ll_publish_url', name: "ll_publish_url", severity: 'issue',
        patterns: [new RegExp("ll[_-]?publish[_-]?url(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ll_publish_url. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ll_shared_key', name: "ll_shared_key", severity: 'issue',
        patterns: [new RegExp("ll[_-]?shared[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ll_shared_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_looker_test_runner_client_secret', name: "looker_test_runner_client_secret", severity: 'issue',
        patterns: [new RegExp("looker[_-]?test[_-]?runner[_-]?client[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: looker_test_runner_client_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_lottie_happo_api_key', name: "lottie_happo_api_key", severity: 'issue',
        patterns: [new RegExp("lottie[_-]?happo[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: lottie_happo_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_lottie_happo_secret_key', name: "lottie_happo_secret_key", severity: 'issue',
        patterns: [new RegExp("lottie[_-]?happo[_-]?secret[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: lottie_happo_secret_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_lottie_s3_secret_key', name: "lottie_s3_secret_key", severity: 'issue',
        patterns: [new RegExp("lottie[_-]?s3[_-]?secret[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: lottie_s3_secret_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_lottie_upload_cert_key_password', name: "lottie_upload_cert_key_password", severity: 'issue',
        patterns: [new RegExp("lottie[_-]?upload[_-]?cert[_-]?key[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: lottie_upload_cert_key_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_lottie_upload_cert_key_store_password', name: "lottie_upload_cert_key_store_password", severity: 'issue',
        patterns: [new RegExp("lottie[_-]?upload[_-]?cert[_-]?key[_-]?store[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: lottie_upload_cert_key_store_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_magento_auth_password', name: "magento_auth_password", severity: 'issue',
        patterns: [new RegExp("magento[_-]?auth[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: magento_auth_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_magento_auth_username', name: "magento_auth_username", severity: 'issue',
        patterns: [new RegExp("magento[_-]?auth[_-]?username (=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: magento_auth_username. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_magento_password', name: "magento_password", severity: 'issue',
        patterns: [new RegExp("magento[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: magento_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mail_password', name: "mail_password", severity: 'issue',
        patterns: [new RegExp("mail[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mail_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mailchimp', name: "mailchimp", severity: 'issue',
        patterns: [new RegExp("(W(?:[a-f0-9]{32}(-us[0-9]{1,2}))a-zA-Z0-9)", 'gi')],
        description: 'Detected sensitive pattern: mailchimp. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mailchimp_api_key', name: "mailchimp_api_key", severity: 'issue',
        patterns: [new RegExp("mailchimp[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mailchimp_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mailchimp_key', name: "mailchimp_key", severity: 'issue',
        patterns: [new RegExp("mailchimp[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mailchimp_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mailer_password', name: "mailer_password", severity: 'issue',
        patterns: [new RegExp("mailer[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mailer_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mailgun', name: "mailgun", severity: 'issue',
        patterns: [new RegExp("(key-[0-9a-f]{32})", 'gi')],
        description: 'Detected sensitive pattern: mailgun. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mailgun_api_key', name: "mailgun_api_key", severity: 'issue',
        patterns: [new RegExp("mailgun[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mailgun_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mailgun_apikey', name: "mailgun_apikey", severity: 'issue',
        patterns: [new RegExp("mailgun[_-]?apikey(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mailgun_apikey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mailgun_password', name: "mailgun_password", severity: 'issue',
        patterns: [new RegExp("mailgun[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mailgun_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mailgun_priv_key', name: "mailgun_priv_key", severity: 'issue',
        patterns: [new RegExp("mailgun[_-]?priv[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mailgun_priv_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mailgun_pub_apikey', name: "mailgun_pub_apikey", severity: 'issue',
        patterns: [new RegExp("mailgun[_-]?pub[_-]?apikey(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mailgun_pub_apikey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mailgun_pub_key', name: "mailgun_pub_key", severity: 'issue',
        patterns: [new RegExp("mailgun[_-]?pub[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mailgun_pub_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mailgun_secret_api_key', name: "mailgun_secret_api_key", severity: 'issue',
        patterns: [new RegExp("mailgun[_-]?secret[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mailgun_secret_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_manage_key', name: "manage_key", severity: 'issue',
        patterns: [new RegExp("manage[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: manage_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_manage_secret', name: "manage_secret", severity: 'issue',
        patterns: [new RegExp("manage[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: manage_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_management_token', name: "management_token", severity: 'issue',
        patterns: [new RegExp("management[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: management_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_managementapiaccesstoken', name: "managementapiaccesstoken", severity: 'issue',
        patterns: [new RegExp("managementapiaccesstoken(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: managementapiaccesstoken. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mandrill_api_key', name: "mandrill_api_key", severity: 'issue',
        patterns: [new RegExp("mandrill[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mandrill_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_manifest_app_token', name: "manifest_app_token", severity: 'issue',
        patterns: [new RegExp("manifest[_-]?app[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: manifest_app_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_manifest_app_url', name: "manifest_app_url", severity: 'issue',
        patterns: [new RegExp("manifest[_-]?app[_-]?url(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: manifest_app_url. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mapbox_access_token', name: "mapbox_access_token", severity: 'issue',
        patterns: [new RegExp("mapbox[_-]?access[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mapbox_access_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mapbox_api_token', name: "mapbox_api_token", severity: 'issue',
        patterns: [new RegExp("mapbox[_-]?api[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mapbox_api_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mapbox_aws_access_key_id', name: "mapbox_aws_access_key_id", severity: 'issue',
        patterns: [new RegExp("mapbox[_-]?aws[_-]?access[_-]?key[_-]?id(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mapbox_aws_access_key_id. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mapbox_aws_secret_access_key', name: "mapbox_aws_secret_access_key", severity: 'issue',
        patterns: [new RegExp("mapbox[_-]?aws[_-]?secret[_-]?access[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mapbox_aws_secret_access_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mapboxaccesstoken', name: "mapboxaccesstoken", severity: 'issue',
        patterns: [new RegExp("mapboxaccesstoken(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mapboxaccesstoken. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_master_password', name: "master_password", severity: 'issue',
        patterns: [new RegExp("(master_password).+", 'gi')],
        description: 'Detected sensitive pattern: master_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mg_api_key', name: "mg_api_key", severity: 'issue',
        patterns: [new RegExp("mg[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mg_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mg_public_api_key', name: "mg_public_api_key", severity: 'issue',
        patterns: [new RegExp("mg[_-]?public[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mg_public_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mh_apikey', name: "mh_apikey", severity: 'issue',
        patterns: [new RegExp("mh[_-]?apikey(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mh_apikey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mh_password', name: "mh_password", severity: 'issue',
        patterns: [new RegExp("mh[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mh_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mile_zero_key', name: "mile_zero_key", severity: 'issue',
        patterns: [new RegExp("mile[_-]?zero[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mile_zero_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_minio_access_key', name: "minio_access_key", severity: 'issue',
        patterns: [new RegExp("minio[_-]?access[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: minio_access_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_minio_secret_key', name: "minio_secret_key", severity: 'issue',
        patterns: [new RegExp("minio[_-]?secret[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: minio_secret_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_multi_bob_sid', name: "multi_bob_sid", severity: 'issue',
        patterns: [new RegExp("multi[_-]?bob[_-]?sid(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: multi_bob_sid. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_multi_connect_sid', name: "multi_connect_sid", severity: 'issue',
        patterns: [new RegExp("multi[_-]?connect[_-]?sid(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: multi_connect_sid. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_multi_disconnect_sid', name: "multi_disconnect_sid", severity: 'issue',
        patterns: [new RegExp("multi[_-]?disconnect[_-]?sid(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: multi_disconnect_sid. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_multi_workflow_sid', name: "multi_workflow_sid", severity: 'issue',
        patterns: [new RegExp("multi[_-]?workflow[_-]?sid(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: multi_workflow_sid. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_multi_workspace_sid', name: "multi_workspace_sid", severity: 'issue',
        patterns: [new RegExp("multi[_-]?workspace[_-]?sid(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: multi_workspace_sid. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_my_secret_env', name: "my_secret_env", severity: 'issue',
        patterns: [new RegExp("my[_-]?secret[_-]?env(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: my_secret_env. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mysql_database', name: "mysql_database", severity: 'issue',
        patterns: [new RegExp("mysql[_-]?database(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mysql_database. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mysql_hostname', name: "mysql_hostname", severity: 'issue',
        patterns: [new RegExp("mysql[_-]?hostname(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mysql_hostname. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mysql_password', name: "mysql_password", severity: 'issue',
        patterns: [new RegExp("mysql[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mysql_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mysql_root_password', name: "mysql_root_password", severity: 'issue',
        patterns: [new RegExp("mysql[_-]?root[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mysql_root_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mysql_user', name: "mysql_user", severity: 'issue',
        patterns: [new RegExp("mysql[_-]?user(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mysql_user. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mysql_username', name: "mysql_username", severity: 'issue',
        patterns: [new RegExp("mysql[_-]?username(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mysql_username. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mysqlmasteruser', name: "mysqlmasteruser", severity: 'issue',
        patterns: [new RegExp("mysqlmasteruser(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mysqlmasteruser. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_mysqlsecret', name: "mysqlsecret", severity: 'issue',
        patterns: [new RegExp("mysqlsecret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: mysqlsecret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_nativeevents', name: "nativeevents", severity: 'issue',
        patterns: [new RegExp("nativeevents(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: nativeevents. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_netlify_api_key', name: "netlify_api_key", severity: 'issue',
        patterns: [new RegExp("netlify[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: netlify_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_new_relic_beta_token', name: "new_relic_beta_token", severity: 'issue',
        patterns: [new RegExp("new[_-]?relic[_-]?beta[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: new_relic_beta_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_nexus_password', name: "nexus_password", severity: 'issue',
        patterns: [new RegExp("nexus[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: nexus_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_nexuspassword', name: "nexuspassword", severity: 'issue',
        patterns: [new RegExp("nexuspassword(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: nexuspassword. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ngrok_auth_token', name: "ngrok_auth_token", severity: 'issue',
        patterns: [new RegExp("ngrok[_-]?auth[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ngrok_auth_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ngrok_token', name: "ngrok_token", severity: 'issue',
        patterns: [new RegExp("ngrok[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ngrok_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_node_env', name: "node_env", severity: 'issue',
        patterns: [new RegExp("node[_-]?env(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: node_env. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_node_pre_gyp_accesskeyid', name: "node_pre_gyp_accesskeyid", severity: 'issue',
        patterns: [new RegExp("node[_-]?pre[_-]?gyp[_-]?accesskeyid(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: node_pre_gyp_accesskeyid. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_node_pre_gyp_github_token', name: "node_pre_gyp_github_token", severity: 'issue',
        patterns: [new RegExp("node[_-]?pre[_-]?gyp[_-]?github[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: node_pre_gyp_github_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_node_pre_gyp_secretaccesskey', name: "node_pre_gyp_secretaccesskey", severity: 'issue',
        patterns: [new RegExp("node[_-]?pre[_-]?gyp[_-]?secretaccesskey(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: node_pre_gyp_secretaccesskey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_non_token', name: "non_token", severity: 'issue',
        patterns: [new RegExp("non[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: non_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_now_token', name: "now_token", severity: 'issue',
        patterns: [new RegExp("now[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: now_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_npm_api_key', name: "npm_api_key", severity: 'issue',
        patterns: [new RegExp("npm[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: npm_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_npm_api_token', name: "npm_api_token", severity: 'issue',
        patterns: [new RegExp("npm[_-]?api[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: npm_api_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_npm_auth_token', name: "npm_auth_token", severity: 'issue',
        patterns: [new RegExp("npm[_-]?auth[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: npm_auth_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_npm_email', name: "npm_email", severity: 'issue',
        patterns: [new RegExp("npm[_-]?email(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: npm_email. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_npm_password', name: "npm_password", severity: 'issue',
        patterns: [new RegExp("npm[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: npm_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_npm_secret_key', name: "npm_secret_key", severity: 'issue',
        patterns: [new RegExp("npm[_-]?secret[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: npm_secret_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_npm_token_1', name: "npm_token - 1", severity: 'issue',
        patterns: [new RegExp("npm[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: npm_token - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_nuget_api_key_1', name: "nuget_api_key - 1", severity: 'issue',
        patterns: [new RegExp("(oy2[a-z0-9]{43})", 'gi')],
        description: 'Detected sensitive pattern: nuget_api_key - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_nuget_api_key_2', name: "nuget_api_key - 2", severity: 'issue',
        patterns: [new RegExp("nuget[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: nuget_api_key - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_numbers_service_pass', name: "numbers_service_pass", severity: 'issue',
        patterns: [new RegExp("numbers[_-]?service[_-]?pass(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: numbers_service_pass. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_oauth_token', name: "oauth_token", severity: 'issue',
        patterns: [new RegExp("oauth[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: oauth_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_object_storage_password', name: "object_storage_password", severity: 'issue',
        patterns: [new RegExp("object[_-]?storage[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: object_storage_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_object_storage_region_name', name: "object_storage_region_name", severity: 'issue',
        patterns: [new RegExp("object[_-]?storage[_-]?region[_-]?name(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: object_storage_region_name. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_object_store_bucket', name: "object_store_bucket", severity: 'issue',
        patterns: [new RegExp("object[_-]?store[_-]?bucket(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: object_store_bucket. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_object_store_creds', name: "object_store_creds", severity: 'issue',
        patterns: [new RegExp("object[_-]?store[_-]?creds(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: object_store_creds. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_oc_pass', name: "oc_pass", severity: 'issue',
        patterns: [new RegExp("oc[_-]?pass(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: oc_pass. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_octest_app_password', name: "octest_app_password", severity: 'issue',
        patterns: [new RegExp("octest[_-]?app[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: octest_app_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_octest_app_username', name: "octest_app_username", severity: 'issue',
        patterns: [new RegExp("octest[_-]?app[_-]?username(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: octest_app_username. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_octest_password', name: "octest_password", severity: 'issue',
        patterns: [new RegExp("octest[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: octest_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ofta_key', name: "ofta_key", severity: 'issue',
        patterns: [new RegExp("ofta[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ofta_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ofta_region', name: "ofta_region", severity: 'issue',
        patterns: [new RegExp("ofta[_-]?region(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ofta_region. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ofta_secret', name: "ofta_secret", severity: 'issue',
        patterns: [new RegExp("ofta[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ofta_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_okta_client_token', name: "okta_client_token", severity: 'issue',
        patterns: [new RegExp("okta[_-]?client[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: okta_client_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_okta_oauth2_client_secret', name: "okta_oauth2_client_secret", severity: 'issue',
        patterns: [new RegExp("okta[_-]?oauth2[_-]?client[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: okta_oauth2_client_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_okta_oauth2_clientsecret', name: "okta_oauth2_clientsecret", severity: 'issue',
        patterns: [new RegExp("okta[_-]?oauth2[_-]?clientsecret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: okta_oauth2_clientsecret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_omise_key', name: "omise_key", severity: 'issue',
        patterns: [new RegExp("omise[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: omise_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_omise_pkey', name: "omise_pkey", severity: 'issue',
        patterns: [new RegExp("omise[_-]?pkey(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: omise_pkey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_omise_pubkey', name: "omise_pubkey", severity: 'issue',
        patterns: [new RegExp("omise[_-]?pubkey(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: omise_pubkey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_omise_skey', name: "omise_skey", severity: 'issue',
        patterns: [new RegExp("omise[_-]?skey(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: omise_skey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_onesignal_api_key', name: "onesignal_api_key", severity: 'issue',
        patterns: [new RegExp("onesignal[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: onesignal_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_onesignal_user_auth_key', name: "onesignal_user_auth_key", severity: 'issue',
        patterns: [new RegExp("onesignal[_-]?user[_-]?auth[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: onesignal_user_auth_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_open_whisk_key', name: "open_whisk_key", severity: 'issue',
        patterns: [new RegExp("open[_-]?whisk[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: open_whisk_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_openwhisk_key', name: "openwhisk_key", severity: 'issue',
        patterns: [new RegExp("openwhisk[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: openwhisk_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_os_auth_url', name: "os_auth_url", severity: 'issue',
        patterns: [new RegExp("os[_-]?auth[_-]?url(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: os_auth_url. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_os_password', name: "os_password", severity: 'issue',
        patterns: [new RegExp("os[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: os_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ossrh_jira_password', name: "ossrh_jira_password", severity: 'issue',
        patterns: [new RegExp("ossrh[_-]?jira[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ossrh_jira_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ossrh_pass', name: "ossrh_pass", severity: 'issue',
        patterns: [new RegExp("ossrh[_-]?pass(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ossrh_pass. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ossrh_password', name: "ossrh_password", severity: 'issue',
        patterns: [new RegExp("ossrh[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ossrh_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ossrh_secret', name: "ossrh_secret", severity: 'issue',
        patterns: [new RegExp("ossrh[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ossrh_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ossrh_username', name: "ossrh_username", severity: 'issue',
        patterns: [new RegExp("ossrh[_-]?username(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ossrh_username. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_outlook_team', name: "outlook_team", severity: 'issue',
        patterns: [new RegExp("(https://outlook.office.com/webhook/[0-9a-f-]{36}@)", 'gi')],
        description: 'Detected sensitive pattern: outlook_team. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_packagecloud_token', name: "packagecloud_token", severity: 'issue',
        patterns: [new RegExp("packagecloud[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: packagecloud_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_pagerduty_apikey', name: "pagerduty_apikey", severity: 'issue',
        patterns: [new RegExp("pagerduty[_-]?apikey(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: pagerduty_apikey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_parse_js_key', name: "parse_js_key", severity: 'issue',
        patterns: [new RegExp("parse[_-]?js[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: parse_js_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_passwordtravis', name: "passwordtravis", severity: 'issue',
        patterns: [new RegExp("passwordtravis(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: passwordtravis. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_paypal_braintree_access_token', name: "paypal_braintree_access_token", severity: 'issue',
        patterns: [new RegExp("(access_token$production$[0-9a-z]{16}$[0-9a-f]{32})", 'gi')],
        description: 'Detected sensitive pattern: paypal_braintree_access_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_paypal_client_secret', name: "paypal_client_secret", severity: 'issue',
        patterns: [new RegExp("paypal[_-]?client[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: paypal_client_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_percy_project', name: "percy_project", severity: 'issue',
        patterns: [new RegExp("percy[_-]?project(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: percy_project. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_percy_token', name: "percy_token", severity: 'issue',
        patterns: [new RegExp("percy[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: percy_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_personal_key', name: "personal_key", severity: 'issue',
        patterns: [new RegExp("personal[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: personal_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_personal_secret', name: "personal_secret", severity: 'issue',
        patterns: [new RegExp("personal[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: personal_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_pg_database', name: "pg_database", severity: 'issue',
        patterns: [new RegExp("pg[_-]?database(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: pg_database. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_pg_host', name: "pg_host", severity: 'issue',
        patterns: [new RegExp("pg[_-]?host(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: pg_host. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_places_api_key', name: "places_api_key", severity: 'issue',
        patterns: [new RegExp("places[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: places_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_places_apikey', name: "places_apikey", severity: 'issue',
        patterns: [new RegExp("places[_-]?apikey(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: places_apikey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_plotly_apikey', name: "plotly_apikey", severity: 'issue',
        patterns: [new RegExp("plotly[_-]?apikey(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: plotly_apikey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_plugin_password', name: "plugin_password", severity: 'issue',
        patterns: [new RegExp("plugin[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: plugin_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_postgres_env_postgres_db', name: "postgres_env_postgres_db", severity: 'issue',
        patterns: [new RegExp("postgres[_-]?env[_-]?postgres[_-]?db(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: postgres_env_postgres_db. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_postgres_env_postgres_password', name: "postgres_env_postgres_password", severity: 'issue',
        patterns: [new RegExp("postgres[_-]?env[_-]?postgres[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: postgres_env_postgres_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_postgresql_db', name: "postgresql_db", severity: 'issue',
        patterns: [new RegExp("postgresql[_-]?db(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: postgresql_db. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_postgresql_pass', name: "postgresql_pass", severity: 'issue',
        patterns: [new RegExp("postgresql[_-]?pass(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: postgresql_pass. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_prebuild_auth', name: "prebuild_auth", severity: 'issue',
        patterns: [new RegExp("prebuild[_-]?auth(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: prebuild_auth. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_preferred_username', name: "preferred_username", severity: 'issue',
        patterns: [new RegExp("preferred[_-]?username(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: preferred_username. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_pring_mail_username', name: "pring_mail_username", severity: 'issue',
        patterns: [new RegExp("pring[_-]?mail[_-]?username(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: pring_mail_username. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_private_key', name: "private_key", severity: 'issue',
        patterns: [new RegExp("-----(?:(?:BEGIN|END) )(?:(?:EC|PGP|DSA|RSA|OPENSSH).)?PRIVATE.KEY(.BLOCK)?-----", 'gi')],
        description: 'Detected sensitive pattern: private_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_private_signing_password', name: "private_signing_password", severity: 'issue',
        patterns: [new RegExp("private[_-]?signing[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: private_signing_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_prod_access_key_id', name: "prod_access_key_id", severity: 'issue',
        patterns: [new RegExp("prod[_-]?access[_-]?key[_-]?id(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: prod_access_key_id. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_prod_password', name: "prod_password", severity: 'issue',
        patterns: [new RegExp("prod[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: prod_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_prod_secret_key', name: "prod_secret_key", severity: 'issue',
        patterns: [new RegExp("prod[_-]?secret[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: prod_secret_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_project_config', name: "project_config", severity: 'issue',
        patterns: [new RegExp("project[_-]?config(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: project_config. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_publish_access', name: "publish_access", severity: 'issue',
        patterns: [new RegExp("publish[_-]?access(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: publish_access. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_publish_key', name: "publish_key", severity: 'issue',
        patterns: [new RegExp("publish[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: publish_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_publish_secret', name: "publish_secret", severity: 'issue',
        patterns: [new RegExp("publish[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: publish_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_pushover_token', name: "pushover_token", severity: 'issue',
        patterns: [new RegExp("pushover[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: pushover_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_pypi_passowrd', name: "pypi_passowrd", severity: 'issue',
        patterns: [new RegExp("pypi[_-]?passowrd(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: pypi_passowrd. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_qiita_token', name: "qiita_token", severity: 'issue',
        patterns: [new RegExp("qiita[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: qiita_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_quip_token', name: "quip_token", severity: 'issue',
        patterns: [new RegExp("quip[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: quip_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_rabbitmq_password', name: "rabbitmq_password", severity: 'issue',
        patterns: [new RegExp("rabbitmq[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: rabbitmq_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_randrmusicapiaccesstoken', name: "randrmusicapiaccesstoken", severity: 'issue',
        patterns: [new RegExp("randrmusicapiaccesstoken(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: randrmusicapiaccesstoken. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_redis_stunnel_urls', name: "redis_stunnel_urls", severity: 'issue',
        patterns: [new RegExp("redis[_-]?stunnel[_-]?urls(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: redis_stunnel_urls. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_rediscloud_url', name: "rediscloud_url", severity: 'issue',
        patterns: [new RegExp("rediscloud[_-]?url(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: rediscloud_url. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_refresh_token', name: "refresh_token", severity: 'issue',
        patterns: [new RegExp("refresh[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: refresh_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_registry_pass', name: "registry_pass", severity: 'issue',
        patterns: [new RegExp("registry[_-]?pass(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: registry_pass. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_registry_secure', name: "registry_secure", severity: 'issue',
        patterns: [new RegExp("registry[_-]?secure(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: registry_secure. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_release_gh_token', name: "release_gh_token", severity: 'issue',
        patterns: [new RegExp("release[_-]?gh[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: release_gh_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_release_token', name: "release_token", severity: 'issue',
        patterns: [new RegExp("release[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: release_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_reporting_webdav_pwd', name: "reporting_webdav_pwd", severity: 'issue',
        patterns: [new RegExp("reporting[_-]?webdav[_-]?pwd(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: reporting_webdav_pwd. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_reporting_webdav_url', name: "reporting_webdav_url", severity: 'issue',
        patterns: [new RegExp("reporting[_-]?webdav[_-]?url(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: reporting_webdav_url. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_repotoken', name: "repotoken", severity: 'issue',
        patterns: [new RegExp("repotoken(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: repotoken. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_rest_api_key', name: "rest_api_key", severity: 'issue',
        patterns: [new RegExp("rest[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: rest_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_rinkeby_private_key', name: "rinkeby_private_key", severity: 'issue',
        patterns: [new RegExp("rinkeby[_-]?private[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: rinkeby_private_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ropsten_private_key', name: "ropsten_private_key", severity: 'issue',
        patterns: [new RegExp("ropsten[_-]?private[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ropsten_private_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_route53_access_key_id', name: "route53_access_key_id", severity: 'issue',
        patterns: [new RegExp("route53[_-]?access[_-]?key[_-]?id(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: route53_access_key_id. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_rtd_key_pass', name: "rtd_key_pass", severity: 'issue',
        patterns: [new RegExp("rtd[_-]?key[_-]?pass(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: rtd_key_pass. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_rtd_store_pass', name: "rtd_store_pass", severity: 'issue',
        patterns: [new RegExp("rtd[_-]?store[_-]?pass(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: rtd_store_pass. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_rubygems_auth_token', name: "rubygems_auth_token", severity: 'issue',
        patterns: [new RegExp("rubygems[_-]?auth[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: rubygems_auth_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_s3_access_key', name: "s3_access_key", severity: 'issue',
        patterns: [new RegExp("s3[_-]?access[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: s3_access_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_s3_access_key_id', name: "s3_access_key_id", severity: 'issue',
        patterns: [new RegExp("s3[_-]?access[_-]?key[_-]?id(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: s3_access_key_id. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_s3_bucket_name_app_logs', name: "s3_bucket_name_app_logs", severity: 'issue',
        patterns: [new RegExp("s3[_-]?bucket[_-]?name[_-]?app[_-]?logs(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: s3_bucket_name_app_logs. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_s3_bucket_name_assets', name: "s3_bucket_name_assets", severity: 'issue',
        patterns: [new RegExp("s3[_-]?bucket[_-]?name[_-]?assets(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: s3_bucket_name_assets. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_s3_external_3_amazonaws_com', name: "s3_external_3_amazonaws_com", severity: 'issue',
        patterns: [new RegExp("s3[_-]?external[_-]?3[_-]?amazonaws[_-]?com(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: s3_external_3_amazonaws_com. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_s3_key', name: "s3_key", severity: 'issue',
        patterns: [new RegExp("s3[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: s3_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_s3_key_app_logs', name: "s3_key_app_logs", severity: 'issue',
        patterns: [new RegExp("s3[_-]?key[_-]?app[_-]?logs(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: s3_key_app_logs. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_s3_key_assets', name: "s3_key_assets", severity: 'issue',
        patterns: [new RegExp("s3[_-]?key[_-]?assets(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: s3_key_assets. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_s3_secret_app_logs', name: "s3_secret_app_logs", severity: 'issue',
        patterns: [new RegExp("s3[_-]?secret[_-]?app[_-]?logs(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: s3_secret_app_logs. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_s3_secret_assets', name: "s3_secret_assets", severity: 'issue',
        patterns: [new RegExp("s3[_-]?secret[_-]?assets(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: s3_secret_assets. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_s3_secret_key', name: "s3_secret_key", severity: 'issue',
        patterns: [new RegExp("s3[_-]?secret[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: s3_secret_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_s3_user_secret', name: "s3_user_secret", severity: 'issue',
        patterns: [new RegExp("s3[_-]?user[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: s3_user_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sacloud_access_token', name: "sacloud_access_token", severity: 'issue',
        patterns: [new RegExp("sacloud[_-]?access[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sacloud_access_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sacloud_access_token_secret', name: "sacloud_access_token_secret", severity: 'issue',
        patterns: [new RegExp("sacloud[_-]?access[_-]?token[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sacloud_access_token_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sacloud_api', name: "sacloud_api", severity: 'issue',
        patterns: [new RegExp("sacloud[_-]?api(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sacloud_api. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_salesforce_bulk_test_password', name: "salesforce_bulk_test_password", severity: 'issue',
        patterns: [new RegExp("salesforce[_-]?bulk[_-]?test[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: salesforce_bulk_test_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_salesforce_bulk_test_security_token', name: "salesforce_bulk_test_security_token", severity: 'issue',
        patterns: [new RegExp("salesforce[_-]?bulk[_-]?test[_-]?security[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: salesforce_bulk_test_security_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sandbox_access_token', name: "sandbox_access_token", severity: 'issue',
        patterns: [new RegExp("sandbox[_-]?access[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sandbox_access_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sandbox_aws_access_key_id', name: "sandbox_aws_access_key_id", severity: 'issue',
        patterns: [new RegExp("sandbox[_-]?aws[_-]?access[_-]?key[_-]?id(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sandbox_aws_access_key_id. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sandbox_aws_secret_access_key', name: "sandbox_aws_secret_access_key", severity: 'issue',
        patterns: [new RegExp("sandbox[_-]?aws[_-]?secret[_-]?access[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sandbox_aws_secret_access_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sauce_access_key', name: "sauce_access_key", severity: 'issue',
        patterns: [new RegExp("sauce[_-]?access[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sauce_access_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sauce_token', name: "sauce_token", severity: 'issue',
        patterns: [new RegExp("(sauce.{0,50}(\"|')?[0-9a-f-]{36}(\"|')?)", 'gi')],
        description: 'Detected sensitive pattern: sauce_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_scrutinizer_token', name: "scrutinizer_token", severity: 'issue',
        patterns: [new RegExp("scrutinizer[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: scrutinizer_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sdr_token', name: "sdr_token", severity: 'issue',
        patterns: [new RegExp("sdr[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sdr_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_secret_0', name: "secret_0", severity: 'issue',
        patterns: [new RegExp("secret[_-]?0(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: secret_0. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_secret_1', name: "secret_1", severity: 'issue',
        patterns: [new RegExp("secret[_-]?1(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: secret_1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_secret_10', name: "secret_10", severity: 'issue',
        patterns: [new RegExp("secret[_-]?10(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: secret_10. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_secret_11', name: "secret_11", severity: 'issue',
        patterns: [new RegExp("secret[_-]?11(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: secret_11. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_secret_2', name: "secret_2", severity: 'issue',
        patterns: [new RegExp("secret[_-]?2(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: secret_2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_secret_3', name: "secret_3", severity: 'issue',
        patterns: [new RegExp("secret[_-]?3(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: secret_3. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_secret_4', name: "secret_4", severity: 'issue',
        patterns: [new RegExp("secret[_-]?4(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: secret_4. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_secret_5', name: "secret_5", severity: 'issue',
        patterns: [new RegExp("secret[_-]?5(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: secret_5. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_secret_6', name: "secret_6", severity: 'issue',
        patterns: [new RegExp("secret[_-]?6(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: secret_6. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_secret_7', name: "secret_7", severity: 'issue',
        patterns: [new RegExp("secret[_-]?7(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: secret_7. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_secret_8', name: "secret_8", severity: 'issue',
        patterns: [new RegExp("secret[_-]?8(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: secret_8. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_secret_9', name: "secret_9", severity: 'issue',
        patterns: [new RegExp("secret[_-]?9(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: secret_9. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_secret_key_base', name: "secret_key_base", severity: 'issue',
        patterns: [new RegExp("secret[_-]?key[_-]?base(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: secret_key_base. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_secretaccesskey', name: "secretaccesskey", severity: 'issue',
        patterns: [new RegExp("secretaccesskey(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: secretaccesskey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_secretkey', name: "secretkey", severity: 'issue',
        patterns: [new RegExp("secretkey(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: secretkey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_segment_api_key', name: "segment_api_key", severity: 'issue',
        patterns: [new RegExp("segment[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: segment_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_selion_log_level_dev', name: "selion_log_level_dev", severity: 'issue',
        patterns: [new RegExp("selion[_-]?log[_-]?level[_-]?dev(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: selion_log_level_dev. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_selion_selenium_host', name: "selion_selenium_host", severity: 'issue',
        patterns: [new RegExp("selion[_-]?selenium[_-]?host(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: selion_selenium_host. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sendgrid_2', name: "sendgrid - 2", severity: 'issue',
        patterns: [new RegExp("sendgrid(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sendgrid - 2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sendgrid_api_key_1', name: "sendgrid_api_key - 1", severity: 'issue',
        patterns: [new RegExp("sendgrid[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sendgrid_api_key - 1. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sendgrid_key', name: "sendgrid_key", severity: 'issue',
        patterns: [new RegExp("sendgrid[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sendgrid_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sendgrid_password', name: "sendgrid_password", severity: 'issue',
        patterns: [new RegExp("sendgrid[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sendgrid_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sendgrid_user', name: "sendgrid_user", severity: 'issue',
        patterns: [new RegExp("sendgrid[_-]?user(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sendgrid_user. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sendgrid_username', name: "sendgrid_username", severity: 'issue',
        patterns: [new RegExp("sendgrid[_-]?username(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sendgrid_username. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sendwithus_key', name: "sendwithus_key", severity: 'issue',
        patterns: [new RegExp("sendwithus[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sendwithus_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sentry_auth_token', name: "sentry_auth_token", severity: 'issue',
        patterns: [new RegExp("sentry[_-]?auth[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sentry_auth_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sentry_default_org', name: "sentry_default_org", severity: 'issue',
        patterns: [new RegExp("sentry[_-]?default[_-]?org(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sentry_default_org. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sentry_endpoint', name: "sentry_endpoint", severity: 'issue',
        patterns: [new RegExp("sentry[_-]?endpoint(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sentry_endpoint. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sentry_key', name: "sentry_key", severity: 'issue',
        patterns: [new RegExp("sentry[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sentry_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_service_account_secret', name: "service_account_secret", severity: 'issue',
        patterns: [new RegExp("service[_-]?account[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: service_account_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ses_access_key', name: "ses_access_key", severity: 'issue',
        patterns: [new RegExp("ses[_-]?access[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ses_access_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ses_secret_key', name: "ses_secret_key", severity: 'issue',
        patterns: [new RegExp("ses[_-]?secret[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ses_secret_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_setdstaccesskey', name: "setdstaccesskey", severity: 'issue',
        patterns: [new RegExp("setdstaccesskey(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: setdstaccesskey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_setdstsecretkey', name: "setdstsecretkey", severity: 'issue',
        patterns: [new RegExp("setdstsecretkey(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: setdstsecretkey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_setsecretkey', name: "setsecretkey", severity: 'issue',
        patterns: [new RegExp("setsecretkey(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: setsecretkey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_signing_key', name: "signing_key", severity: 'issue',
        patterns: [new RegExp("signing[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: signing_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_signing_key_password', name: "signing_key_password", severity: 'issue',
        patterns: [new RegExp("signing[_-]?key[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: signing_key_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_signing_key_secret', name: "signing_key_secret", severity: 'issue',
        patterns: [new RegExp("signing[_-]?key[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: signing_key_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_signing_key_sid', name: "signing_key_sid", severity: 'issue',
        patterns: [new RegExp("signing[_-]?key[_-]?sid(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: signing_key_sid. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_slack_webhook_url', name: "slack_webhook_url", severity: 'issue',
        patterns: [new RegExp("(hooks.slack.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[a-zA-Z0-9]{1,})", 'gi')],
        description: 'Detected sensitive pattern: slack_webhook_url. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_slash_developer_space', name: "slash_developer_space", severity: 'issue',
        patterns: [new RegExp("slash[_-]?developer[_-]?space(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: slash_developer_space. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_slash_developer_space_key', name: "slash_developer_space_key", severity: 'issue',
        patterns: [new RegExp("slash[_-]?developer[_-]?space[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: slash_developer_space_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_slate_user_email', name: "slate_user_email", severity: 'issue',
        patterns: [new RegExp("slate[_-]?user[_-]?email(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: slate_user_email. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_snoowrap_client_secret', name: "snoowrap_client_secret", severity: 'issue',
        patterns: [new RegExp("snoowrap[_-]?client[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: snoowrap_client_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_snoowrap_password', name: "snoowrap_password", severity: 'issue',
        patterns: [new RegExp("snoowrap[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: snoowrap_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_snoowrap_refresh_token', name: "snoowrap_refresh_token", severity: 'issue',
        patterns: [new RegExp("snoowrap[_-]?refresh[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: snoowrap_refresh_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_snyk_api_token', name: "snyk_api_token", severity: 'issue',
        patterns: [new RegExp("snyk[_-]?api[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: snyk_api_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_snyk_token', name: "snyk_token", severity: 'issue',
        patterns: [new RegExp("snyk[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: snyk_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_socrata_app_token', name: "socrata_app_token", severity: 'issue',
        patterns: [new RegExp("socrata[_-]?app[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: socrata_app_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_socrata_password', name: "socrata_password", severity: 'issue',
        patterns: [new RegExp("socrata[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: socrata_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sonar_organization_key', name: "sonar_organization_key", severity: 'issue',
        patterns: [new RegExp("sonar[_-]?organization[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sonar_organization_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sonar_project_key', name: "sonar_project_key", severity: 'issue',
        patterns: [new RegExp("sonar[_-]?project[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sonar_project_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sonar_token', name: "sonar_token", severity: 'issue',
        patterns: [new RegExp("sonar[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sonar_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sonarqube_docs_api_key', name: "sonarqube_docs_api_key", severity: 'issue',
        patterns: [new RegExp("(sonar.{0,50}(\"|')?[0-9a-f]{40}(\"|')?)", 'gi')],
        description: 'Detected sensitive pattern: sonarqube_docs_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sonatype_gpg_key_name', name: "sonatype_gpg_key_name", severity: 'issue',
        patterns: [new RegExp("sonatype[_-]?gpg[_-]?key[_-]?name(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sonatype_gpg_key_name. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sonatype_gpg_passphrase', name: "sonatype_gpg_passphrase", severity: 'issue',
        patterns: [new RegExp("sonatype[_-]?gpg[_-]?passphrase(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sonatype_gpg_passphrase. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sonatype_nexus_password', name: "sonatype_nexus_password", severity: 'issue',
        patterns: [new RegExp("sonatype[_-]?nexus[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sonatype_nexus_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sonatype_pass', name: "sonatype_pass", severity: 'issue',
        patterns: [new RegExp("sonatype[_-]?pass(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sonatype_pass. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sonatype_password', name: "sonatype_password", severity: 'issue',
        patterns: [new RegExp("sonatype[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sonatype_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sonatype_token_password', name: "sonatype_token_password", severity: 'issue',
        patterns: [new RegExp("sonatype[_-]?token[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sonatype_token_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sonatype_token_user', name: "sonatype_token_user", severity: 'issue',
        patterns: [new RegExp("sonatype[_-]?token[_-]?user(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sonatype_token_user. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sonatypepassword', name: "sonatypepassword", severity: 'issue',
        patterns: [new RegExp("sonatypepassword(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sonatypepassword. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_soundcloud_client_secret', name: "soundcloud_client_secret", severity: 'issue',
        patterns: [new RegExp("soundcloud[_-]?client[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: soundcloud_client_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_soundcloud_password', name: "soundcloud_password", severity: 'issue',
        patterns: [new RegExp("soundcloud[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: soundcloud_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_spaces_access_key_id', name: "spaces_access_key_id", severity: 'issue',
        patterns: [new RegExp("spaces[_-]?access[_-]?key[_-]?id(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: spaces_access_key_id. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_spaces_secret_access_key', name: "spaces_secret_access_key", severity: 'issue',
        patterns: [new RegExp("spaces[_-]?secret[_-]?access[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: spaces_secret_access_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_spotify_api_access_token', name: "spotify_api_access_token", severity: 'issue',
        patterns: [new RegExp("spotify[_-]?api[_-]?access[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: spotify_api_access_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_spotify_api_client_secret', name: "spotify_api_client_secret", severity: 'issue',
        patterns: [new RegExp("spotify[_-]?api[_-]?client[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: spotify_api_client_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_spring_mail_password', name: "spring_mail_password", severity: 'issue',
        patterns: [new RegExp("spring[_-]?mail[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: spring_mail_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sqsaccesskey', name: "sqsaccesskey", severity: 'issue',
        patterns: [new RegExp("sqsaccesskey(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sqsaccesskey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sqssecretkey', name: "sqssecretkey", severity: 'issue',
        patterns: [new RegExp("sqssecretkey(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sqssecretkey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_square_app_secret', name: "square_app_secret", severity: 'issue',
        patterns: [new RegExp("(sq0[a-z]{3}-[0-9A-Za-z-_]{20,50})", 'gi')],
        description: 'Detected sensitive pattern: square_app_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_square_reader_sdk_repository_password', name: "square_reader_sdk_repository_password", severity: 'issue',
        patterns: [new RegExp("square[_-]?reader[_-]?sdk[_-]?repository[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: square_reader_sdk_repository_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_srcclr_api_token', name: "srcclr_api_token", severity: 'issue',
        patterns: [new RegExp("srcclr[_-]?api[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: srcclr_api_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ssh_password', name: "ssh_password", severity: 'issue',
        patterns: [new RegExp("(sshpass -p.*['|\"])", 'gi')],
        description: 'Detected sensitive pattern: ssh_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_sshpass', name: "sshpass", severity: 'issue',
        patterns: [new RegExp("sshpass(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: sshpass. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_ssmtp_config', name: "ssmtp_config", severity: 'issue',
        patterns: [new RegExp("ssmtp[_-]?config(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: ssmtp_config. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_staging_base_url_runscope', name: "staging_base_url_runscope", severity: 'issue',
        patterns: [new RegExp("staging[_-]?base[_-]?url[_-]?runscope(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: staging_base_url_runscope. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_star_test_aws_access_key_id', name: "star_test_aws_access_key_id", severity: 'issue',
        patterns: [new RegExp("star[_-]?test[_-]?aws[_-]?access[_-]?key[_-]?id(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: star_test_aws_access_key_id. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_star_test_bucket', name: "star_test_bucket", severity: 'issue',
        patterns: [new RegExp("star[_-]?test[_-]?bucket(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: star_test_bucket. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_star_test_location', name: "star_test_location", severity: 'issue',
        patterns: [new RegExp("star[_-]?test[_-]?location(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: star_test_location. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_star_test_secret_access_key', name: "star_test_secret_access_key", severity: 'issue',
        patterns: [new RegExp("star[_-]?test[_-]?secret[_-]?access[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: star_test_secret_access_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_starship_account_sid', name: "starship_account_sid", severity: 'issue',
        patterns: [new RegExp("starship[_-]?account[_-]?sid(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: starship_account_sid. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_starship_auth_token', name: "starship_auth_token", severity: 'issue',
        patterns: [new RegExp("starship[_-]?auth[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: starship_auth_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_stormpath_api_key_id', name: "stormpath_api_key_id", severity: 'issue',
        patterns: [new RegExp("stormpath[_-]?api[_-]?key[_-]?id(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: stormpath_api_key_id. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_stormpath_api_key_secret', name: "stormpath_api_key_secret", severity: 'issue',
        patterns: [new RegExp("stormpath[_-]?api[_-]?key[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: stormpath_api_key_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_strip_publishable_key', name: "strip_publishable_key", severity: 'issue',
        patterns: [new RegExp("strip[_-]?publishable[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: strip_publishable_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_strip_secret_key', name: "strip_secret_key", severity: 'issue',
        patterns: [new RegExp("strip[_-]?secret[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: strip_secret_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_stripe_private', name: "stripe_private", severity: 'issue',
        patterns: [new RegExp("stripe[_-]?private(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: stripe_private. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_stripe_public', name: "stripe_public", severity: 'issue',
        patterns: [new RegExp("stripe[_-]?public(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: stripe_public. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_stripe_restricted_api', name: "stripe_restricted_api", severity: 'issue',
        patterns: [new RegExp("(rk_live_[0-9a-zA-Z]{24,34})", 'gi')],
        description: 'Detected sensitive pattern: stripe_restricted_api. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_stripe_standard_api', name: "stripe_standard_api", severity: 'issue',
        patterns: [new RegExp("(sk_live_[0-9a-zA-Z]{24,34})", 'gi')],
        description: 'Detected sensitive pattern: stripe_standard_api. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_surge_login', name: "surge_login", severity: 'issue',
        patterns: [new RegExp("surge[_-]?login(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: surge_login. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_surge_token', name: "surge_token", severity: 'issue',
        patterns: [new RegExp("surge[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: surge_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_svn_pass', name: "svn_pass", severity: 'issue',
        patterns: [new RegExp("svn[_-]?pass(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: svn_pass. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_tesco_api_key', name: "tesco_api_key", severity: 'issue',
        patterns: [new RegExp("tesco[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: tesco_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_test_github_token', name: "test_github_token", severity: 'issue',
        patterns: [new RegExp("test[_-]?github[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: test_github_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_test_test', name: "test_test", severity: 'issue',
        patterns: [new RegExp("test[_-]?test(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: test_test. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_tester_keys_password', name: "tester_keys_password", severity: 'issue',
        patterns: [new RegExp("tester[_-]?keys[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: tester_keys_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_thera_oss_access_key', name: "thera_oss_access_key", severity: 'issue',
        patterns: [new RegExp("thera[_-]?oss[_-]?access[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: thera_oss_access_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_token_core_java', name: "token_core_java", severity: 'issue',
        patterns: [new RegExp("token[_-]?core[_-]?java(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: token_core_java. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_travis_access_token', name: "travis_access_token", severity: 'issue',
        patterns: [new RegExp("travis[_-]?access[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: travis_access_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_travis_api_token', name: "travis_api_token", severity: 'issue',
        patterns: [new RegExp("travis[_-]?api[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: travis_api_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_travis_branch', name: "travis_branch", severity: 'issue',
        patterns: [new RegExp("travis[_-]?branch(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: travis_branch. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_travis_com_token', name: "travis_com_token", severity: 'issue',
        patterns: [new RegExp("travis[_-]?com[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: travis_com_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_travis_e2e_token', name: "travis_e2e_token", severity: 'issue',
        patterns: [new RegExp("travis[_-]?e2e[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: travis_e2e_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_travis_gh_token', name: "travis_gh_token", severity: 'issue',
        patterns: [new RegExp("travis[_-]?gh[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: travis_gh_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_travis_pull_request', name: "travis_pull_request", severity: 'issue',
        patterns: [new RegExp("travis[_-]?pull[_-]?request(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: travis_pull_request. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_travis_secure_env_vars', name: "travis_secure_env_vars", severity: 'issue',
        patterns: [new RegExp("travis[_-]?secure[_-]?env[_-]?vars(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: travis_secure_env_vars. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_travis_token', name: "travis_token", severity: 'issue',
        patterns: [new RegExp("travis[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: travis_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_trex_client_token', name: "trex_client_token", severity: 'issue',
        patterns: [new RegExp("trex[_-]?client[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: trex_client_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_trex_okta_client_token', name: "trex_okta_client_token", severity: 'issue',
        patterns: [new RegExp("trex[_-]?okta[_-]?client[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: trex_okta_client_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_twilio_api_key', name: "twilio_api_key", severity: 'issue',
        patterns: [new RegExp("twilio[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: twilio_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_twilio_api_secret', name: "twilio_api_secret", severity: 'issue',
        patterns: [new RegExp("twilio[_-]?api[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: twilio_api_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_twilio_chat_account_api_service', name: "twilio_chat_account_api_service", severity: 'issue',
        patterns: [new RegExp("twilio[_-]?chat[_-]?account[_-]?api[_-]?service(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: twilio_chat_account_api_service. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_twilio_configuration_sid', name: "twilio_configuration_sid", severity: 'issue',
        patterns: [new RegExp("twilio[_-]?configuration[_-]?sid(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: twilio_configuration_sid. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_twilio_sid', name: "twilio_sid", severity: 'issue',
        patterns: [new RegExp("twilio[_-]?sid(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: twilio_sid. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_twilio_token', name: "twilio_token", severity: 'issue',
        patterns: [new RegExp("twilio[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: twilio_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_twine_password', name: "twine_password", severity: 'issue',
        patterns: [new RegExp("twine[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: twine_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_twitter_consumer_key', name: "twitter_consumer_key", severity: 'issue',
        patterns: [new RegExp("twitter[_-]?consumer[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: twitter_consumer_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_twitter_consumer_secret', name: "twitter_consumer_secret", severity: 'issue',
        patterns: [new RegExp("twitter[_-]?consumer[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: twitter_consumer_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_twitteroauthaccesssecret', name: "twitteroauthaccesssecret", severity: 'issue',
        patterns: [new RegExp("twitteroauthaccesssecret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: twitteroauthaccesssecret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_twitteroauthaccesstoken', name: "twitteroauthaccesstoken", severity: 'issue',
        patterns: [new RegExp("twitteroauthaccesstoken(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: twitteroauthaccesstoken. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_unity_password', name: "unity_password", severity: 'issue',
        patterns: [new RegExp("unity[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: unity_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_unity_serial', name: "unity_serial", severity: 'issue',
        patterns: [new RegExp("unity[_-]?serial(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: unity_serial. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_urban_key', name: "urban_key", severity: 'issue',
        patterns: [new RegExp("urban[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: urban_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_urban_master_secret', name: "urban_master_secret", severity: 'issue',
        patterns: [new RegExp("urban[_-]?master[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: urban_master_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_urban_secret', name: "urban_secret", severity: 'issue',
        patterns: [new RegExp("urban[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: urban_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_us_east_1_elb_amazonaws_com', name: "us_east_1_elb_amazonaws_com", severity: 'issue',
        patterns: [new RegExp("us[_-]?east[_-]?1[_-]?elb[_-]?amazonaws[_-]?com(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: us_east_1_elb_amazonaws_com. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_use_ssh', name: "use_ssh", severity: 'issue',
        patterns: [new RegExp("use[_-]?ssh(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: use_ssh. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_user_assets_access_key_id', name: "user_assets_access_key_id", severity: 'issue',
        patterns: [new RegExp("user[_-]?assets[_-]?access[_-]?key[_-]?id(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: user_assets_access_key_id. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_user_assets_secret_access_key', name: "user_assets_secret_access_key", severity: 'issue',
        patterns: [new RegExp("user[_-]?assets[_-]?secret[_-]?access[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: user_assets_secret_access_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_usertravis', name: "usertravis", severity: 'issue',
        patterns: [new RegExp("usertravis(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: usertravis. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_v_sfdc_client_secret', name: "v_sfdc_client_secret", severity: 'issue',
        patterns: [new RegExp("v[_-]?sfdc[_-]?client[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: v_sfdc_client_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_v_sfdc_password', name: "v_sfdc_password", severity: 'issue',
        patterns: [new RegExp("v[_-]?sfdc[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: v_sfdc_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_vip_github_build_repo_deploy_key', name: "vip_github_build_repo_deploy_key", severity: 'issue',
        patterns: [new RegExp("vip[_-]?github[_-]?build[_-]?repo[_-]?deploy[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: vip_github_build_repo_deploy_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_vip_github_deploy_key', name: "vip_github_deploy_key", severity: 'issue',
        patterns: [new RegExp("vip[_-]?github[_-]?deploy[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: vip_github_deploy_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_vip_github_deploy_key_pass', name: "vip_github_deploy_key_pass", severity: 'issue',
        patterns: [new RegExp("vip[_-]?github[_-]?deploy[_-]?key[_-]?pass(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: vip_github_deploy_key_pass. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_virustotal_apikey', name: "virustotal_apikey", severity: 'issue',
        patterns: [new RegExp("virustotal[_-]?apikey(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: virustotal_apikey. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_visual_recognition_api_key', name: "visual_recognition_api_key", severity: 'issue',
        patterns: [new RegExp("visual[_-]?recognition[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: visual_recognition_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_vscetoken', name: "vscetoken", severity: 'issue',
        patterns: [new RegExp("vscetoken(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: vscetoken. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_wakatime_api_key', name: "wakatime_api_key", severity: 'issue',
        patterns: [new RegExp("wakatime[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: wakatime_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_watson_conversation_password', name: "watson_conversation_password", severity: 'issue',
        patterns: [new RegExp("watson[_-]?conversation[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: watson_conversation_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_watson_device_password', name: "watson_device_password", severity: 'issue',
        patterns: [new RegExp("watson[_-]?device[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: watson_device_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_watson_password', name: "watson_password", severity: 'issue',
        patterns: [new RegExp("watson[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: watson_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_widget_basic_password', name: "widget_basic_password", severity: 'issue',
        patterns: [new RegExp("widget[_-]?basic[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: widget_basic_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_widget_basic_password_2', name: "widget_basic_password_2", severity: 'issue',
        patterns: [new RegExp("widget[_-]?basic[_-]?password[_-]?2(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: widget_basic_password_2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_widget_basic_password_3', name: "widget_basic_password_3", severity: 'issue',
        patterns: [new RegExp("widget[_-]?basic[_-]?password[_-]?3(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: widget_basic_password_3. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_widget_basic_password_4', name: "widget_basic_password_4", severity: 'issue',
        patterns: [new RegExp("widget[_-]?basic[_-]?password[_-]?4(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: widget_basic_password_4. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_widget_basic_password_5', name: "widget_basic_password_5", severity: 'issue',
        patterns: [new RegExp("widget[_-]?basic[_-]?password[_-]?5(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: widget_basic_password_5. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_widget_fb_password', name: "widget_fb_password", severity: 'issue',
        patterns: [new RegExp("widget[_-]?fb[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: widget_fb_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_widget_fb_password_2', name: "widget_fb_password_2", severity: 'issue',
        patterns: [new RegExp("widget[_-]?fb[_-]?password[_-]?2(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: widget_fb_password_2. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_widget_fb_password_3', name: "widget_fb_password_3", severity: 'issue',
        patterns: [new RegExp("widget[_-]?fb[_-]?password[_-]?3(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: widget_fb_password_3. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_widget_test_server', name: "widget_test_server", severity: 'issue',
        patterns: [new RegExp("widget[_-]?test[_-]?server(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: widget_test_server. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_wincert_password', name: "wincert_password", severity: 'issue',
        patterns: [new RegExp("wincert[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: wincert_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_wordpress_db_password', name: "wordpress_db_password", severity: 'issue',
        patterns: [new RegExp("wordpress[_-]?db[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: wordpress_db_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_wordpress_db_user', name: "wordpress_db_user", severity: 'issue',
        patterns: [new RegExp("wordpress[_-]?db[_-]?user(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: wordpress_db_user. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_wpjm_phpunit_google_geocode_api_key', name: "wpjm_phpunit_google_geocode_api_key", severity: 'issue',
        patterns: [new RegExp("wpjm[_-]?phpunit[_-]?google[_-]?geocode[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: wpjm_phpunit_google_geocode_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_wporg_password', name: "wporg_password", severity: 'issue',
        patterns: [new RegExp("wporg[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: wporg_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_wpt_db_password', name: "wpt_db_password", severity: 'issue',
        patterns: [new RegExp("wpt[_-]?db[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: wpt_db_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_wpt_db_user', name: "wpt_db_user", severity: 'issue',
        patterns: [new RegExp("wpt[_-]?db[_-]?user(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: wpt_db_user. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_wpt_prepare_dir', name: "wpt_prepare_dir", severity: 'issue',
        patterns: [new RegExp("wpt[_-]?prepare[_-]?dir(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: wpt_prepare_dir. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_wpt_report_api_key', name: "wpt_report_api_key", severity: 'issue',
        patterns: [new RegExp("wpt[_-]?report[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: wpt_report_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_wpt_ssh_connect', name: "wpt_ssh_connect", severity: 'issue',
        patterns: [new RegExp("wpt[_-]?ssh[_-]?connect(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: wpt_ssh_connect. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_wpt_ssh_private_key_base64', name: "wpt_ssh_private_key_base64", severity: 'issue',
        patterns: [new RegExp("wpt[_-]?ssh[_-]?private[_-]?key[_-]?base64(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: wpt_ssh_private_key_base64. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_www_googleapis_com', name: "www_googleapis_com", severity: 'issue',
        patterns: [new RegExp("www[_-]?googleapis[_-]?com(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: www_googleapis_com. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_yangshun_gh_password', name: "yangshun_gh_password", severity: 'issue',
        patterns: [new RegExp("yangshun[_-]?gh[_-]?password(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: yangshun_gh_password. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_yangshun_gh_token', name: "yangshun_gh_token", severity: 'issue',
        patterns: [new RegExp("yangshun[_-]?gh[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: yangshun_gh_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_yt_account_client_secret', name: "yt_account_client_secret", severity: 'issue',
        patterns: [new RegExp("yt[_-]?account[_-]?client[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: yt_account_client_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_yt_account_refresh_token', name: "yt_account_refresh_token", severity: 'issue',
        patterns: [new RegExp("yt[_-]?account[_-]?refresh[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: yt_account_refresh_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_yt_api_key', name: "yt_api_key", severity: 'issue',
        patterns: [new RegExp("yt[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: yt_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_yt_client_secret', name: "yt_client_secret", severity: 'issue',
        patterns: [new RegExp("yt[_-]?client[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: yt_client_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_yt_partner_client_secret', name: "yt_partner_client_secret", severity: 'issue',
        patterns: [new RegExp("yt[_-]?partner[_-]?client[_-]?secret(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: yt_partner_client_secret. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_yt_partner_refresh_token', name: "yt_partner_refresh_token", severity: 'issue',
        patterns: [new RegExp("yt[_-]?partner[_-]?refresh[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: yt_partner_refresh_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_yt_server_api_key', name: "yt_server_api_key", severity: 'issue',
        patterns: [new RegExp("yt[_-]?server[_-]?api[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: yt_server_api_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_', name: "zendesk_travis_github", severity: 'issue',
        patterns: [new RegExp("zendesk[_-]?travis[_-]?github(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: zendesk_travis_github. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_zensonatypepassword', name: "zensonatypepassword", severity: 'issue',
        patterns: [new RegExp("zensonatypepassword(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: zensonatypepassword. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_zhuliang_gh_token', name: "zhuliang_gh_token", severity: 'issue',
        patterns: [new RegExp("zhuliang[_-]?gh[_-]?token(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: zhuliang_gh_token. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_zopim_account_key', name: "zopim_account_key", severity: 'issue',
        patterns: [new RegExp("zopim[_-]?account[_-]?key(=| =|:| :)", 'gi')],
        description: 'Detected sensitive pattern: zopim_account_key. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_insecurestorage', name: "InsecureStorage", severity: 'issue',
        patterns: [new RegExp("(SharedPreferences\\.getSharedPreferences\\(|getSharedPreferences\\(|MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE|SQLiteDatabase\\.openDatabase\\(|SQLiteOpenHelper|CREATE TABLE|INSERT INTO)", 'gi')],
        description: 'Detected sensitive pattern: InsecureStorage. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_certificatepinning', name: "CertificatePinning", severity: 'issue',
        patterns: [new RegExp("(CertificatePinner|TrustManager|X509TrustManager|OkHttpClient\\.Builder\\(\\)\\.certificatePinner|SSLSocketFactory|TrustManagerFactory)", 'gi')],
        description: 'Detected sensitive pattern: CertificatePinning. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'apx_debugmode', name: "DebugMode", severity: 'issue',
        patterns: [new RegExp("android:debuggable=\"true\"", 'gi')],
        description: 'Detected sensitive pattern: DebugMode. Ensure no secrets are hardcoded.', cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    }
];

function findAll(node, tag) {
    if (!node) return [];
    const o = [];
    if (node.tag === tag) o.push(node);
    (node.children || []).forEach(c => o.push(...findAll(c, tag)));
    return o;
}
function findFirst(node, tag) {
    if (!node) return null;
    if (node.tag === tag) return node;
    for (const c of (node.children || [])) { const f = findFirst(c, tag); if (f) return f; }
    return null;
}
function xmlToStr(node, depth = 0) {
    if (!node) return '';
    const pad = '  '.repeat(depth);
    const attrs = Object.entries(node.attribs || {}).map(([k, v]) => ` ${k}="${esc(String(v))}"`).join('');
    if (!node.children || !node.children.length) return `${pad}<${node.tag}${attrs}/>`;
    return `${pad}<${node.tag}${attrs}>\n${node.children.map(c => xmlToStr(c, depth + 1)).join('\n')}\n${pad}</${node.tag}>`;
}

const DANGEROUS_PERMS = new Set(['READ_CONTACTS', 'WRITE_CONTACTS', 'GET_ACCOUNTS', 'READ_CALL_LOG', 'WRITE_CALL_LOG', 'PROCESS_OUTGOING_CALLS', 'READ_CALENDAR', 'WRITE_CALENDAR', 'CAMERA', 'RECORD_AUDIO', 'READ_SMS', 'RECEIVE_SMS', 'SEND_SMS', 'READ_PHONE_STATE', 'READ_PHONE_NUMBERS', 'CALL_PHONE', 'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 'ACCESS_BACKGROUND_LOCATION', 'BODY_SENSORS', 'ACTIVITY_RECOGNITION', 'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'BLUETOOTH_CONNECT', 'BLUETOOTH_SCAN', 'BLUETOOTH_ADVERTISE', 'READ_MEDIA_IMAGES', 'READ_MEDIA_VIDEO', 'READ_MEDIA_AUDIO']);

function analyzeManifest(manifest) {
    if (!manifest) return [];
    const findings = [];
    const app = findFirst(manifest, 'application');
    if (!app) return findings;
    const A = app.attribs || {};
    const f = (id, name, sev, desc, cwe, owasp, masvs, match) =>
        findings.push({ ruleId: id, ruleName: name, severity: sev, description: desc, cwe, owasp, masvs, file: 'AndroidManifest.xml', line: null, match });

    if (A.debuggable === true || A.debuggable === 'true')
        f('debuggable', 'Application Debuggable', 'issue', 'android:debuggable=true permits attaching a debugger and dumping memory at runtime.', 'CWE-489', 'M9', 'CODE-5', 'android:debuggable="true"');
    if (A.allowBackup === true || A.allowBackup === 'true')
        f('allow_backup', 'ADB Backup Enabled', 'issue', 'android:allowBackup=true enables ADB backup which can extract the full app data directory.', 'CWE-312', 'M2', 'STORAGE-8', 'android:allowBackup="true"');
    if (A.usesCleartextTraffic === true || A.usesCleartextTraffic === 'true')
        f('cleartext', 'Cleartext Traffic Allowed', 'issue', 'android:usesCleartextTraffic=true allows unencrypted HTTP.', 'CWE-319', 'M3', 'NETWORK-1', 'android:usesCleartextTraffic="true"');
    if (!A.networkSecurityConfig)
        f('no_nsc', 'No Network Security Config', 'issue', 'No network_security_config.xml found. App may allow cleartext on older Android.', 'CWE-319', 'M3', 'NETWORK-1', 'networkSecurityConfig attribute missing');

    findAll(app, 'activity').forEach(act => {
        const a = act.attribs || {};
        const n = a.name || '';
        const short = n.split('.').pop();
        if ((a.exported === true || a.exported === 'true') && !a.permission)
            f('exported_activity', 'Exported Activity Without Permission', 'issue', `Activity "${n}" is exported and can be launched by any application without restrictions.`, 'CWE-926', 'M1', 'PLATFORM-1', `<activity> ${short} [exported, no permission]`);
        if (a.taskAffinity !== undefined && a.taskAffinity !== '')
            f('task_affinity', 'Non-empty taskAffinity (Task Hijacking)', 'issue', `Activity "${n}" sets a custom taskAffinity, may enable task hijacking.`, 'CWE-926', 'M1', 'PLATFORM-3', `<activity> ${short} [taskAffinity="${a.taskAffinity}"]`);
    });
    findAll(app, 'service').forEach(svc => {
        const a = svc.attribs || {};
        const n = a.name || '';
        const short = n.split('.').pop();
        if ((a.exported === true || a.exported === 'true') && !a.permission)
            f('exported_service', 'Exported Service Without Permission', 'issue', `Service "${n}" is exported and startable by any application.`, 'CWE-926', 'M1', 'PLATFORM-1', `<service> ${short} [exported, no permission]`);
    });
    findAll(app, 'receiver').forEach(rcv => {
        const a = rcv.attribs || {};
        const n = a.name || '';
        const short = n.split('.').pop();
        if ((a.exported === true || a.exported === 'true') && !a.permission)
            f('exported_receiver', 'Exported Broadcast Receiver (No Permission)', 'issue', `Receiver "${n}" is exported without permission, any app can trigger it.`, 'CWE-926', 'M1', 'PLATFORM-1', `<receiver> ${short} [exported, no permission]`);
        const hasFilter = (rcv.children || []).some(c => c.tag === 'intent-filter');
        if (hasFilter && a.exported !== false && a.exported !== 'false' && !a.permission)
            f('receiver_auto_exported', 'Broadcast Receiver Auto-Exported via Intent Filter', 'issue', `Receiver "${n}" has intent-filter without android:exported="false", implicitly exported.`, 'CWE-926', 'M1', 'PLATFORM-1', `<receiver> ${short} [intent-filter, auto-exported]`);
    });
    findAll(app, 'provider').forEach(prov => {
        const a = prov.attribs || {};
        const n = a.name || '';
        const short = n.split('.').pop();
        if (a.exported === true || a.exported === 'true') {
            const sev = 'issue';
            f('exported_provider', 'Exported Content Provider' + (a.permission ? '' : ' (No Permission)'), sev, `Provider "${n}" is exported${a.permission ? ` (requires ${a.permission})` : ', any app can query it'}.`, 'CWE-926', 'M1', 'PLATFORM-2', `<provider> ${short} [exported${a.permission ? ', perm: ' + a.permission : ', no permission'}]`);
        }
        if (a.grantUriPermissions === true || a.grantUriPermissions === 'true')
            f('grant_uri', 'Content Provider grantUriPermissions', 'issue', `Provider "${n}" grants arbitrary URI permissions.`, 'CWE-732', 'M1', 'PLATFORM-2', `<provider> ${short} [grantUriPermissions=true]`);
    });

    findAll(app, 'activity').forEach(act => {
        const a = act.attribs || {};
        const n = a.name || '';
        const short = n.split('.').pop();
        const filters = findAll(act, 'intent-filter');
        for (const filter of filters) {
            for (const d of findAll(filter, 'data')) {
                const scheme = d.attribs?.scheme;
                if (scheme && !['http', 'https'].includes(scheme))
                    f('deeplink_scheme', `Custom URL Scheme: ${scheme}://`, 'issue', `Activity "${n}" handles "${scheme}://" scheme. Validate deep link input.`, 'CWE-939', 'M1', 'PLATFORM-3', `<activity> ${short} [scheme="${scheme}://"]`);
            }
        }
        const lm = String(a.launchMode || '');
        const isHijackLM = (lm === 'singleTask' || lm === 'singleInstance' || lm === '2' || lm === '3');
        if (isHijackLM)
            f('task_hijack', `Vulnerable launchMode (${lm})`, 'issue', `Activity "${n}" uses launchMode="${lm}". If combined with taskAffinity or exported=true, it is vulnerable to Task Hijacking (StrandHogg).`, 'CWE-926', 'M1', 'PLATFORM-3', `<activity> ${short} [launchMode="${lm}"]`);
        if (a.allowTaskReparenting === true || a.allowTaskReparenting === 'true')
            f('task_reparenting', 'allowTaskReparenting Enabled', 'issue', `Activity "${n}" has allowTaskReparenting="true", which can be abused for task hijacking.`, 'CWE-926', 'M1', 'PLATFORM-3', `<activity> ${short} [allowTaskReparenting="true"]`);
    });

    findAll(manifest, 'permission').forEach(perm => {
        const a = perm.attribs || {};
        const n = a.name || '';
        if (a.protectionLevel === 'normal' || a.protectionLevel === '0')
            f('custom_perm_normal', 'Custom Permission with Normal Protection', 'issue', `Permission "${n}" has protectionLevel=normal, any app can request it.`, 'CWE-732', 'M1', 'PLATFORM-1', `<permission> ${n.split('.').pop()} [protectionLevel=normal]`);
    });

    const sdk = findFirst(manifest, 'uses-sdk');
    if (sdk) {
        const min = parseInt(sdk.attribs?.minSdkVersion) || 0;
        const tgt = parseInt(sdk.attribs?.targetSdkVersion) || 0;
        if (min > 0 && min < 21) f('min_sdk', `Low minSdkVersion (API ${min})`, 'issue', `minSdkVersion=${min} (Android ${sdkToVer(min)}) includes versions with known vulns. Raise to 21+.`, 'CWE-1104', 'M8', 'RESILIENCE-8', `minSdkVersion=${min} (Android ${sdkToVer(min)})`);
        if (min > 0 && min < 24) f('min_sdk_nougat', `minSdkVersion below Android 7`, 'issue', `minSdkVersion=${min} supports devices without network security config enforcement.`, 'CWE-1104', 'M8', 'RESILIENCE-8', `minSdkVersion=${min}, no NSC enforcement below API 24`);
        if (tgt > 0 && tgt < 30) f('target_sdk', `Low targetSdkVersion (API ${tgt})`, 'issue', `targetSdkVersion=${tgt} (Android ${sdkToVer(tgt)}) misses scoped storage, permission updates. Target 33+.`, 'CWE-1104', 'M8', 'RESILIENCE-8', `targetSdkVersion=${tgt} (Android ${sdkToVer(tgt)})`);
        if (tgt > 0 && tgt < 33) f('target_sdk_13', `targetSdkVersion below Android 13`, 'issue', `targetSdkVersion=${tgt} missing notification permissions, photo picker. Target 33+.`, 'CWE-1104', 'M8', 'RESILIENCE-8', `targetSdkVersion=${tgt}`);
    }

    const perms = findAll(manifest, 'uses-permission').map(p => (p.attribs?.name || '').replace('android.permission.', ''));
    const dp = perms.filter(p => DANGEROUS_PERMS.has(p));
    if (dp.length)
        f('dangerous_perms', `${dp.length} Dangerous Permission(s)`, 'issue', `Dangerous permissions: ${dp.slice(0, 8).join(', ')}${dp.length > 8 ? '...' : ''}.`, 'CWE-250', 'M8', 'PLATFORM-1', dp.join(', '));
    return findings;
}

function extractManifestInfo(R) {
    const M = R.manifest;
    R.appInfo.packageName = M.attribs?.package || '';
    const sdk = findFirst(M, 'uses-sdk');
    if (sdk) {
        R.minSdk = parseInt(sdk.attribs?.minSdkVersion) || null;
        R.targetSdk = parseInt(sdk.attribs?.targetSdkVersion) || null;
        R.appInfo.minSdk = R.minSdk;
        R.appInfo.targetSdk = R.targetSdk;
    }
    const allPerms = findAll(M, 'uses-permission');
    R.permissions = allPerms.map(p => (p.attribs?.name || '').replace('android.permission.', ''));
    R.dangerousPerms = R.permissions.filter(p => DANGEROUS_PERMS.has(p));
    const app = findFirst(M, 'application');
    if (app) {
        const mk = (el, tag) => findAll(el, tag).map(e => ({
            name: e.attribs?.name || '',
            exported: e.attribs?.exported,
            permission: e.attribs?.permission || '',
            hasIntentFilter: (e.children || []).some(c => c.tag === 'intent-filter')
        }));
        R.components = {
            activities: mk(app, 'activity'),
            services: mk(app, 'service'),
            receivers: mk(app, 'receiver'),
            providers: findAll(app, 'provider').map(e => ({
                name: e.attribs?.name || '',
                exported: e.attribs?.exported,
                authority: e.attribs?.authorities || '',
                permission: e.attribs?.permission || ''
            }))
        };
    }
}

function analyzeContent(content, filePath, rules) {
    const findings = [];
    const safe = content.length > 2000000 ? content.slice(0, 2000000) : content;
    for (const rule of rules) {
        for (const pat of rule.patterns) {
            try {
                pat.lastIndex = 0;
                let m, count = 0;
                while ((m = pat.exec(safe)) !== null && count++ < 20) {
                    const ln = (safe.substring(0, m.index).match(/\n/g) || []).length + 1;
                    findings.push({
                        ruleId: rule.id, ruleName: rule.name, severity: rule.severity,
                        description: rule.description, cwe: rule.cwe, owasp: rule.owasp, masvs: rule.masvs,
                        file: filePath, line: ln, match: m[0].slice(0, 120)
                    });
                    if (m.index === pat.lastIndex) pat.lastIndex++;
                }
            } catch (e) { }
        }
    }
    return findings;
}

const TRACKER_SIGS = [
    ['Firebase', ['com/google/firebase', 'FirebaseApp', 'firebase.google.com']],
    ['Google Analytics', ['com/google/android/gms/analytics', 'GoogleAnalytics']],
    ['Google Ads (AdMob)', ['com/google/android/gms/ads', 'MobileAds', 'AdRequest']],
    ['Facebook SDK', ['com/facebook/analytics', 'FacebookSdk', 'AppEventsLogger']],
    ['Facebook Ads', ['com/facebook/ads', 'AudienceNetworkAds']],
    ['Crashlytics', ['com/google/firebase/crashlytics', 'io/fabric/sdk', 'Crashlytics.init']],
    ['Sentry', ['io/sentry', 'SentryClient', 'sentry.io']],
    ['Mixpanel', ['com/mixpanel/android', 'MixpanelAPI']],
    ['Amplitude', ['com/amplitude/android', 'Amplitude.getInstance']],
    ['AppsFlyer', ['com/appsflyer', 'AppsFlyerLib']],
    ['Adjust', ['com/adjust/sdk', 'AdjustConfig']],
    ['Branch.io', ['io/branch/referral', 'Branch.getInstance']],
    ['Braze', ['com/braze', 'com/appboy']],
    ['OneSignal', ['com/onesignal', 'OneSignal.init']],
    ['Intercom', ['io/intercom/android']],
    ['Zendesk', ['zendesk/android', 'zendesk.support']],
    ['New Relic', ['com/newrelic/agent']],
    ['Datadog', ['com/datadog/android']],
    ['Segment', ['com/segment/analytics', 'Analytics.with']],
    ['Stripe', ['com/stripe/android', 'Stripe(']],
    ['PayPal', ['com/paypal/android', 'PayPalService']],
    ['Braintree', ['com/braintreepayments']],
    ['Leanplum', ['com/leanplum']],
    ['MoPub', ['com/mopub/mobileads']],
    ['IronSource', ['com/ironsource']],
    ['AppLovin', ['com/applovin']],
    ['Unity Ads', ['com/unity3d/ads']],
    ['Vungle', ['com/vungle']],
    ['Chartboost', ['com/chartboost/sdk']],
    ['Flurry', ['com/flurry/android']],
    ['CleverTap', ['com/clevertap/android']],
    ['OkHttp', ['okhttp3', 'OkHttpClient']],
    ['Retrofit', ['retrofit2', 'Retrofit.Builder']],
    ['Glide', ['com/bumptech/glide']],
    ['Picasso', ['com/squareup/picasso']],
    ['Room Database', ['androidx/room', 'RoomDatabase']],
    ['Kotlin Coroutines', ['kotlinx/coroutines']],
    ['RxJava', ['io/reactivex', 'rx/Observable']],
    ['Dagger/Hilt', ['dagger/hilt', 'com/google/dagger']],
];
function detectTrackers(strings, files) {
    const combined = strings.slice(0, 30000).join('\n') + '\n' + files.join('\n');
    return [...new Set(TRACKER_SIGS.filter(([, sigs]) => sigs.some(s => combined.includes(s))).map(([name]) => name))];
}

function buildSmaliTree(classes, tree, dexIdx) {
    const limited = classes.slice(0, 5000);
    for (const cls of limited) {
        const raw = cls.name.replace(/^L/, '').replace(/;$/, '');
        const name = raw.replace(/\//g, '.');
        const parts = name.split('.');
        let cur = tree;
        for (let i = 0; i < parts.length - 1; i++) {
            const p = parts[i];
            if (!cur[p]) cur[p] = { _type: 'pkg', _ch: {} };
            cur = cur[p]._ch;
        }
        cur[parts[parts.length - 1]] = { _type: 'class', _cls: cls, _fqn: name, _dexIdx: dexIdx || 0 };
    }
}

async function analyzeAPK(file) {
    const R = {
        appInfo: { fileName: file.name, fileSize: formatSize(file.size) },
        manifest: null, manifestStr: '', permissions: [], dangerousPerms: [],
        components: { activities: [], services: [], receivers: [], providers: [] },
        certInfo: null, findings: [], files: [], fileTree: {},
        dexFiles: [], trackers: [], nativeLibs: [],
        specialFiles: { dex: [], databases: [], configs: [] },
        strings: [], urls: [], minSdk: null, targetSdk: null, isObfuscated: false
    };
    state.findings = { issue: [], secure: [] };
    state.groupedFindings = { issue: [], secure: [] };
    state.fileContents.clear();
    state.dexParsed = [];
    state.smaliTree = {};
    state.currentViewMode = 'java';
    state.currentViewClass = null;
    state.currentViewFqn = null;
    state.currentViewDexIdx = null;
    state.javaCache = new Map();
    state.explorerView = 'apk';
    state.arscData = null;
    state.inspectorData = null;

    showLoading('Loading APK...');
    updateProgress(5, 'Reading file...');
    await yield_();

    const ab = await file.arrayBuffer();

    updateProgress(10, 'Computing hash...');
    await yield_();
    R.appInfo.sha256 = await sha256hex(ab);
    R.appInfo.md5 = await md5hex(ab);

    updateProgress(14, 'Extracting APK...');
    await yield_();
    const zip = await JSZip.loadAsync(ab);
    state.zipContent = zip;

    updateProgress(18, 'Building file tree...');
    await yield_();
    for (const [path, entry] of Object.entries(zip.files)) {
        if (entry.dir) continue;
        R.files.push(path);
        const ext = path.split('.').pop().toLowerCase();
        if (ext === 'dex') R.specialFiles.dex.push(path);
        if (ext === 'so') R.nativeLibs.push(path);
        if (['db', 'sqlite', 'sqlite3'].includes(ext)) R.specialFiles.databases.push(path);
        if (['json', 'xml', 'properties'].includes(ext) && !path.startsWith('META-INF')) R.specialFiles.configs.push(path);
        const parts = path.split('/');
        let cur = R.fileTree;
        for (let i = 0; i < parts.length; i++) {
            const p = parts[i];
            if (i === parts.length - 1) {
                const sz = entry._data?.uncompressedSize || entry.options?.uncompressedSize || 0;
                cur[p] = { _type: 'file', _path: path, _size: sz };
            } else {
                if (!cur[p]) cur[p] = { _type: 'dir' };
                cur = cur[p];
            }
        }
    }

    updateProgress(24, 'Parsing AndroidManifest.xml...');
    await yield_();
    const mf = zip.file('AndroidManifest.xml');
    if (mf) {
        try {
            const mb = await mf.async('arraybuffer');
            const parser = new AXMLParser(mb);
            R.manifest = parser.parse();
            if (R.manifest) {
                R.manifestStr = '<?xml version="1.0" encoding="utf-8"?>\n' + xmlToStr(R.manifest);
                state.fileContents.set('AndroidManifest.xml', R.manifestStr);
                extractManifestInfo(R);
                R.findings.push(...analyzeManifest(R.manifest));
            }
        } catch (e) { }
    }

    updateProgress(32, 'Analyzing certificate...');
    await yield_();
    for (const path of Object.keys(zip.files)) {
        if (/META-INF\/.+\.(RSA|DSA|EC)$/i.test(path)) {
            try {
                const cb = await zip.file(path).async('arraybuffer');
                const cp = new CertParser(cb);
                R.certInfo = cp.findCert();
                if (R.certInfo) {
                    if (R.certInfo.isDebug) R.findings.push({ ruleId: 'debug_cert', ruleName: 'Debug Certificate Used', severity: 'issue', description: 'APK signed with Android debug key. Debug builds must not be distributed.', cwe: 'CWE-321', owasp: 'M9', masvs: 'CODE-1', file: path, line: null, match: `Debug cert: CN=${R.certInfo.subject?.CN || '?'}` });
                    if (R.certInfo.isExpired) R.findings.push({ ruleId: 'expired_cert', ruleName: 'Expired Signing Certificate', severity: 'issue', description: 'Signing certificate has expired.', cwe: 'CWE-298', owasp: 'M3', masvs: 'CODE-1', file: path, line: null, match: `Expired: ${R.certInfo.validity?.notAfter || '?'}` });
                    if (['MD5withRSA', 'SHA1withRSA'].includes(R.certInfo.sigAlg)) R.findings.push({ ruleId: 'weak_sig', ruleName: `Weak Signature: ${R.certInfo.sigAlg}`, severity: 'issue', description: `${R.certInfo.sigAlg} is weak. Use SHA256withRSA or SHA256withECDSA.`, cwe: 'CWE-327', owasp: 'M5', masvs: 'CODE-1', file: path, line: null, match: `Algorithm: ${R.certInfo.sigAlg}` });
                }
                break;
            } catch (e) { }
        }
    }

    {
        const hasV1 = R.files.some(f => /^META-INF\/.*\.SF$/i.test(f));
        let hasV2 = false;
        try {
            const raw = new Uint8Array(ab);
            const searchStart = Math.max(0, raw.length - 4096);
            const magic = [0x41, 0x50, 0x4B, 0x20, 0x53, 0x69, 0x67];
            for (let i = searchStart; i < raw.length - 7; i++) {
                if (raw[i] === magic[0] && raw[i + 1] === magic[1] && raw[i + 2] === magic[2] &&
                    raw[i + 3] === magic[3] && raw[i + 4] === magic[4] && raw[i + 5] === magic[5] && raw[i + 6] === magic[6]) {
                    hasV2 = true; break;
                }
            }
        } catch (e) { }

        if (hasV1 && !hasV2) {
            R.findings.push({
                ruleId: 'v1_only_sig', ruleName: 'v1 (JAR) Signature Only', severity: 'issue',
                description: 'Only v1 signing found. Vulnerable to Janus (CVE-2017-13156) on Android < 7. Enable v2/v3.',
                cwe: 'CWE-345', owasp: 'M8', masvs: 'CODE-1', file: 'META-INF/', line: null,
                match: 'JAR signature only, no APK Signing Block v2/v3'
            });
        }
        R.hasV2Sig = hasV2;
    }

    updateProgress(40, 'Parsing DEX files...');
    await yield_();
    const allDexStrings = [];
    for (const dp of R.specialFiles.dex) {
        try {
            updateProgress(40, `Parsing ${dp}...`);
            await yield_();
            const db = await zip.file(dp).async('arraybuffer');
            const parser = new DEXParser(db);
            const parsed = parser.parse();
            if (parsed) {
                state.dexParsed.push({ name: dp, buf: db, ...parsed });
                allDexStrings.push(...parsed.strings);
                buildSmaliTree(parsed.classes, state.smaliTree, state.dexParsed.length - 1);
                R.dexFiles.push({ name: dp, classes: parsed.classes.length, methods: parsed.methods.length, strings: parsed.strings.length });
            }
        } catch (e) { }
    }

    updateProgress(44, 'Parsing resources.arsc...');
    await yield_();
    const arscFile = zip.file('resources.arsc');
    if (arscFile) {
        try {
            const arscBuf = await arscFile.async('arraybuffer');
            const arscData = parseArsc(arscBuf);
            if (arscData) {
                state.arscData = arscData;
                state.fileContents.set('resources.arsc', renderArsc(arscData));
                const arscContent = arscData.allStrings.join('\n');
                R.findings.push(...analyzeContent(arscContent, 'resources.arsc', ANDROID_RULES));
            }
        } catch (e) { }
    }

    const allClasses = state.dexParsed.flatMap(d => d.classes);
    if (allClasses.length > 10) {
        const short = allClasses.filter(c => { const s = c.name.replace(/.*\//, '').replace(/;/, ''); return s.length <= 2; }).length;
        R.isObfuscated = (short / allClasses.length) > 0.4;
    }
    if (R.isObfuscated) R.findings.push({ ruleId: 'obfuscated', ruleName: 'Code Obfuscation Active', severity: 'secure', description: 'ProGuard/R8 obfuscation detected from class name analysis.', cwe: '', owasp: '', masvs: 'RESILIENCE-9', file: 'classes.dex', line: null, match: 'Short class names >40% of total' });

    updateProgress(56, 'Scanning decompiled classes...');
    await yield_();
    let classesScanned = 0;
    for (const dex of state.dexParsed) {
        for (const cls of (dex.classes || [])) {
            if (classesScanned++ > 10000) break;
            const fqn = (cls.name || '').replace(/^L/, '').replace(/;$/, '').replace(/\//g, '.');
            if (!fqn || fqn.length < 3) continue;
            try {
                const javaCode = generateJavaView(cls, dex.buf, dex.strings, dex.types, dex.methods, dex.fields || []);
                state.javaCache.set(fqn, javaCode);
                const classFindings = analyzeContent(javaCode, fqn + '.java', ANDROID_RULES);
                R.findings.push(...classFindings);
            } catch (e) { }
            if (classesScanned % 100 === 0) {
                updateProgress(56 + Math.min(10, classesScanned / 200), `Scanning ${classesScanned} classes...`);
                await yield_();
            }
        }
    }
    R.strings = allDexStrings.filter(s => s.length > 3 && s.length < 300);
    R.urls = R.strings.filter(s => /^https?:\/\//.test(s));

    updateProgress(68, 'Scanning resource files...');
    await yield_();
    const textExts = new Set(['xml', 'json', 'properties', 'yaml', 'js', 'html']);
    const priorityFiles = R.files.filter(f =>
        /^res\/values.*\.xml$/i.test(f) ||
        /^res\/xml\/.*\.xml$/i.test(f) ||
        /^assets\/.*\.(json|xml|properties)$/i.test(f)
    );
    const otherTextFiles = R.files.filter(f =>
        !f.startsWith('META-INF/') &&
        !priorityFiles.includes(f) &&
        textExts.has(f.split('.').pop().toLowerCase())
    );
    const textFiles = [...priorityFiles, ...otherTextFiles].slice(0, 500);
    for (const path of textFiles) {
        try {
            const ext = path.split('.').pop().toLowerCase();
            let c;
            if (ext === 'xml') {
                const ab = await zip.file(path).async('arraybuffer');
                const bytes = new Uint8Array(ab);
                if (bytes.length > 4 && bytes[0] === 0x03 && bytes[1] === 0x00) {
                    try {
                        const parser = new AXMLParser(ab);
                        const parsed = parser.parse();
                        if (parsed) c = '<?xml version="1.0" encoding="utf-8"?>\n' + xmlToStr(parsed);
                    } catch (pe) { }
                }
                if (!c) c = new TextDecoder('utf-8', { fatal: false }).decode(ab);
            } else {
                c = await zip.file(path).async('string');
            }
            state.fileContents.set(path, c);
            R.findings.push(...analyzeContent(c, path, ANDROID_RULES));
        } catch (e) { }
    }
    await yield_();

    updateProgress(82, 'Detecting trackers...');
    await yield_();
    R.trackers = detectTrackers(allDexStrings, R.files);

    updateProgress(92, 'Compiling results...');
    await yield_();
    const ruleGroups = new Map();
    for (const f of R.findings) {
        if (ruleGroups.has(f.ruleId)) {
            const g = ruleGroups.get(f.ruleId);
            g.count++;
            if (g.matches.length < 500 && f.match) {
                g.matches.push({ match: f.match, file: f.file, line: f.line });
            }
        } else {
            ruleGroups.set(f.ruleId, {
                ...f,
                count: 1,
                matches: f.match ? [{ match: f.match, file: f.file, line: f.line }] : []
            });
        }
    }
    for (const [, g] of ruleGroups) {
        const s = g.severity === 'secure' ? 'secure' : 'issue';
        state.groupedFindings[s].push(g);
    }
    state.analysisResults = R;
    updateProgress(100, 'Complete!');
    return R;
}

function dexTypeToJava(t) {
    if (!t) return 'Object';
    const PRIM = { 'V': 'void', 'Z': 'boolean', 'B': 'byte', 'S': 'short', 'C': 'char', 'I': 'int', 'J': 'long', 'F': 'float', 'D': 'double' };
    if (PRIM[t]) return PRIM[t];
    if (t.startsWith('[')) return dexTypeToJava(t.slice(1)) + '[]';
    if (t.startsWith('L')) {
        const inner = t.slice(1, t.endsWith(';') ? -1 : undefined);
        return inner.split('/').pop() || inner;
    }
    return t;
}

function generateJavaView(cls, buf, allStrings, allTypes, allMethods, allFields) {
    const ACC = [
        [0x0001, 'public'], [0x0002, 'private'], [0x0004, 'protected'],
        [0x0008, 'static'], [0x0010, 'final'], [0x0400, 'abstract'],
        [0x1000, 'synthetic']
    ];
    const mods = f => ACC.filter(([bit]) => f & bit).map(([, n]) => n).join(' ');

    const isIface = (cls.flags & 0x0200) !== 0;
    const isEnum = (cls.flags & 0x4000) !== 0;
    const isAbst = (cls.flags & 0x0400) !== 0;

    const fqn = (cls.name || '').replace(/^L/, '').replace(/;$/, '').replace(/\//g, '.');
    const dot = fqn.lastIndexOf('.');
    const pkg = dot > 0 ? fqn.slice(0, dot) : '';
    const simpleName = dot > 0 ? fqn.slice(dot + 1) : fqn;
    const superSimple = dexTypeToJava(cls.superName);

    let out = '// decompiled output - not compilable\n';
    if (pkg) out += `package ${pkg};\n\n`;
    if (cls.srcFile) out += `// Source: ${cls.srcFile}\n`;

    const accessMods = mods(cls.flags & ~0x0200 & ~0x4000 & ~0x0400);
    const kwExtra = isAbst && !isIface ? 'abstract ' : '';
    const kw = isEnum ? 'enum' : isIface ? 'interface' : 'class';
    out += `${accessMods}${accessMods ? ' ' : ''}${kwExtra}${kw} ${simpleName}`;
    if (!isIface && !isEnum && superSimple && superSimple !== 'Object') {
        out += ` extends ${superSimple}`;
    }
    const ifaces = (cls.interfaces || []).map(t => dexTypeToJava(t)).filter(Boolean);
    if (ifaces.length) {
        out += ` ${isIface ? 'extends' : 'implements'} ${ifaces.join(', ')}`;
    }
    out += ' {\n';

    const staticFields = (cls.fields || []).filter(f => f.isStatic).slice(0, 60);
    const instanceFields = (cls.fields || []).filter(f => !f.isStatic).slice(0, 60);
    if (staticFields.length) {
        out += '\n    // ── Static fields\n';
        for (const f of staticFields)
            out += `    ${mods(f.flags)} ${dexTypeToJava(f.type)} ${f.name};\n`;
    }
    if (instanceFields.length) {
        out += '\n    // ── Instance fields\n';
        for (const f of instanceFields)
            out += `    ${mods(f.flags)} ${dexTypeToJava(f.type)} ${f.name};\n`;
    }

    const methodList = (cls.methods || []).slice(0, 120);
    const directMethods = methodList.filter(m => m.isDirect);
    const virtualMethods = methodList.filter(m => !m.isDirect);

    const hasBuf = buf && (buf instanceof ArrayBuffer ? buf.byteLength > 0 : buf.buffer?.byteLength > 0);
    const dexBuf = hasBuf ? buf : null;
    const dexV = dexBuf ? new DataView(dexBuf instanceof ArrayBuffer ? dexBuf : dexBuf.buffer) : null;

    const renderMethod = (m) => {
        const ret = dexTypeToJava(m.returnType || 'V');
        const params = (m.paramTypes || []).map((t, i) => `${dexTypeToJava(t)} arg${i}`).join(', ');
        const mmods = mods(m.af || 0);
        const isCtor = m.name === '<init>' || m.name === '<clinit>';
        const isStaticMethod = (m.af & 0x0008) !== 0;
        const retStr = isCtor ? '' : ret + ' ';
        const nameStr = isCtor ? simpleName : (m.name || '?');
        out += `\n    ${mmods}${mmods ? ' ' : ''}${retStr}${nameStr}(${params}) {\n`;

        if (m.co && dexBuf) {
            const declaredParams = (m.paramTypes || []).length;
            const totalParams = isStaticMethod ? declaredParams : declaredParams + 1;
            let regCount = 0;
            try { regCount = dexV.getUint16(m.co, true); } catch (e) { regCount = totalParams; }
            out += decompileToJava(dexBuf, m.co, allStrings || [], allTypes || [], allMethods || [], allFields || [], regCount, totalParams, isStaticMethod);
        } else {
            out += `        // abstract / native\n`;
        }
        out += '    }\n';
    };

    if (directMethods.length) {
        out += '\n    // ── Constructors / static methods\n';
        directMethods.forEach(renderMethod);
    }
    if (virtualMethods.length) {
        out += '\n    // ── Virtual methods\n';
        virtualMethods.forEach(renderMethod);
    }

    out += '\n}\n';
    return out;
}

function smaliFlags(f) {
    const p = [];
    if (f & 0x0001) p.push('public');
    if (f & 0x0002) p.push('private');
    if (f & 0x0004) p.push('protected');
    if (f & 0x0008) p.push('static');
    if (f & 0x0010) p.push('final');
    if (f & 0x0040) p.push('bridge');
    if (f & 0x0080) p.push('varargs');
    if (f & 0x0100) p.push('native');
    if (f & 0x0200) p.push('interface');
    if (f & 0x0400) p.push('abstract');
    if (f & 0x1000) p.push('synthetic');
    if (f & 0x4000) p.push('enum');
    if (f & 0x10000) p.push('constructor');
    return p.join(' ');
}

function disassembleCode(buf, co, strings, types, methods, fields) {
    try {
        if (!co || !buf) return '    # abstract / native';
        const ab = buf instanceof ArrayBuffer ? buf : buf.buffer;
        const v = new DataView(ab);
        const b = new Uint8Array(ab);
        if (co + 16 > b.length) return '    # invalid code_off';
        const u16 = o => v.getUint16(o, true);
        const i16 = o => v.getInt16(o, true);
        const u32 = o => v.getUint32(o, true);
        const regs = u16(co);
        const insn_count = Math.min(u32(co + 12), 2000);
        const base = co + 16;
        if (base + insn_count * 2 > b.length) return `    .registers ${regs}\n    # truncated`;
        const iw = i => u16(base + i * 2);
        const sw = i => i16(base + i * 2);
        const mref = i => {
            if (i >= methods.length) return `method@${i}`;
            const m = methods[i];
            return `${m.cls}->${m.name}(${(m.paramTypes || []).join('')})${m.returnType || 'V'}`;
        };
        const fref = i => {
            if (i >= fields.length) return `field@${i}`;
            const f = fields[i];
            return `${f.cls}->${f.name}:${f.type}`;
        };
        const tref = i => i < types.length ? types[i] : `type@${i}`;
        const sref = i => {
            if (i >= strings.length) return `string@${i}`;
            return `"${strings[i].replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r').slice(0, 120)}"`;
        };
        const lbl = t => `:L${(t < 0 ? 'm' : '') + (Math.abs(t)).toString(16).padStart(4, '0')}`;

        const branchTargetPCs = new Set();
        {
            let _pc = 0, _itr = 0;
            while (_pc < insn_count && _itr++ < 6000) {
                const _w0 = iw(_pc); const _op = _w0 & 0xFF;
                const _A = (_w0 >> 8) & 0xFF;
                let _sz = 1;
                if (_op >= 0x02 && _op <= 0x03) _sz = _op === 0x02 ? 2 : 3;
                else if (_op >= 0x05 && _op <= 0x06) _sz = _op === 0x05 ? 2 : 3;
                else if (_op >= 0x08 && _op <= 0x09) _sz = _op === 0x08 ? 2 : 3;
                else if (_op >= 0x13 && _op <= 0x15) _sz = 2;
                else if (_op === 0x14) _sz = 3;
                else if (_op >= 0x16 && _op <= 0x17) _sz = _op === 0x16 ? 2 : 3;
                else if (_op === 0x18) _sz = 5;
                else if (_op === 0x19) _sz = 2;
                else if (_op === 0x1a) _sz = 2;
                else if (_op === 0x1b) _sz = 3;
                else if (_op === 0x1c) _sz = 2;
                else if (_op === 0x1f || _op === 0x20) _sz = 2;
                else if (_op === 0x22 || _op === 0x23) _sz = 2;
                else if (_op === 0x24 || _op === 0x25) _sz = 3;
                else if (_op === 0x26) _sz = 3;
                else if (_op === 0x28) { const o8 = (_A >= 128 ? _A - 256 : _A); branchTargetPCs.add(_pc + o8); }
                else if (_op === 0x29) { _sz = 2; branchTargetPCs.add(_pc + sw(_pc + 1)); }
                else if (_op === 0x2a) { _sz = 3; branchTargetPCs.add(_pc + ((iw(_pc + 2) << 16) | iw(_pc + 1))); }
                else if (_op === 0x2b || _op === 0x2c) _sz = 2;
                else if (_op >= 0x2d && _op <= 0x31) _sz = 2;
                else if (_op >= 0x32 && _op <= 0x37) { _sz = 2; branchTargetPCs.add(_pc + sw(_pc + 1)); }
                else if (_op >= 0x38 && _op <= 0x3d) { _sz = 2; branchTargetPCs.add(_pc + sw(_pc + 1)); }
                else if ((_op >= 0x44 && _op <= 0x51) || (_op >= 0x52 && _op <= 0x6d)) _sz = 2;
                else if ((_op >= 0x6e && _op <= 0x72) || (_op >= 0x74 && _op <= 0x78)) _sz = 3;
                else if (_op >= 0x90 && _op <= 0xaf) _sz = 2;
                else if (_op >= 0xd0 && _op <= 0xe2) _sz = 2;
                _pc += _sz;
            }
        }

        const tries_size = u16(co + 6);
        const tryInfo = [];
        if (tries_size > 0) {
            let triesOff = base + insn_count * 2;
            if (triesOff % 4 !== 0) triesOff += 2;
            for (let t = 0; t < Math.min(tries_size, 20); t++) {
                const off = triesOff + t * 8;
                if (off + 8 <= b.length) {
                    const startAddr = u32(off);
                    const insnCount = u16(off + 4);
                    const handlerOff = u16(off + 6);
                    tryInfo.push({ start: startAddr, count: insnCount, handler: handlerOff });
                }
            }
        }

        const out = [`    .registers ${regs}`];
        for (const t of tryInfo) {
            out.push(`    .catch all {:L${t.start.toString(16).padStart(4, '0')} .. :L${(t.start + t.count).toString(16).padStart(4, '0')}} :handler_${t.handler.toString(16)}`);
        }
        out.push('');

        let pc = 0, itr = 0;
        while (pc < insn_count && itr++ < 6000) {
            if (branchTargetPCs.has(pc)) {
                out.push(`\n    ${lbl(pc)}`);
            }
            const w0 = iw(pc);
            const op = w0 & 0xFF;
            const A = (w0 >> 8) & 0xFF;
            const a = (w0 >> 8) & 0xF;
            const bN = (w0 >> 12) & 0xF;
            let s = '', sz = 1;
            switch (op) {
                case 0x00: s = 'nop'; break;
                case 0x01: s = `move v${a}, v${bN}`; break;
                case 0x02: sz = 2; s = `move/from16 v${A}, v${iw(pc + 1)}`; break;
                case 0x03: sz = 3; s = `move/16 v${iw(pc + 1)}, v${iw(pc + 2)}`; break;
                case 0x04: s = `move-wide v${a}, v${bN}`; break;
                case 0x05: sz = 2; s = `move-wide/from16 v${A}, v${iw(pc + 1)}`; break;
                case 0x06: sz = 3; s = `move-wide/16 v${iw(pc + 1)}, v${iw(pc + 2)}`; break;
                case 0x07: s = `move-object v${a}, v${bN}`; break;
                case 0x08: sz = 2; s = `move-object/from16 v${A}, v${iw(pc + 1)}`; break;
                case 0x09: sz = 3; s = `move-object/16 v${iw(pc + 1)}, v${iw(pc + 2)}`; break;
                case 0x0a: s = `move-result v${A}`; break;
                case 0x0b: s = `move-result-wide v${A}`; break;
                case 0x0c: s = `move-result-object v${A}`; break;
                case 0x0d: s = `move-exception v${A}`; break;
                case 0x0e: s = 'return-void'; break;
                case 0x0f: s = `return v${A}`; break;
                case 0x10: s = `return-wide v${A}`; break;
                case 0x11: s = `return-object v${A}`; break;
                case 0x12: { const lit = (bN & 8) ? bN - 16 : bN; s = `const/4 v${a}, #${lit}`; break; }
                case 0x13: sz = 2; s = `const/16 v${A}, #${sw(pc + 1)}`; break;
                case 0x14: sz = 3; s = `const v${A}, #${(iw(pc + 2) << 16) | iw(pc + 1)}`; break;
                case 0x15: sz = 2; s = `const/high16 v${A}, #0x${iw(pc + 1).toString(16)}0000`; break;
                case 0x16: sz = 2; s = `const-wide/16 v${A}, #${sw(pc + 1)}`; break;
                case 0x17: sz = 3; s = `const-wide/32 v${A}, #${(iw(pc + 2) << 16) | iw(pc + 1)}`; break;
                case 0x18: sz = 5; s = `const-wide v${A}, #wide`; break;
                case 0x19: sz = 2; s = `const-wide/high16 v${A}, #0x${iw(pc + 1).toString(16)}000000000000`; break;
                case 0x1a: sz = 2; s = `const-string v${A}, ${sref(iw(pc + 1))}`; break;
                case 0x1b: sz = 3; s = `const-string/jumbo v${A}, ${sref((iw(pc + 2) << 16) | iw(pc + 1))}`; break;
                case 0x1c: sz = 2; s = `const-class v${A}, ${tref(iw(pc + 1))}`; break;
                case 0x1d: s = `monitor-enter v${A}`; break;
                case 0x1e: s = `monitor-exit v${A}`; break;
                case 0x1f: sz = 2; s = `check-cast v${A}, ${tref(iw(pc + 1))}`; break;
                case 0x20: sz = 2; s = `instance-of v${a}, v${bN}, ${tref(iw(pc + 1))}`; break;
                case 0x21: s = `array-length v${a}, v${bN}`; break;
                case 0x22: sz = 2; s = `new-instance v${A}, ${tref(iw(pc + 1))}`; break;
                case 0x23: sz = 2; s = `new-array v${a}, v${bN}, ${tref(iw(pc + 1))}`; break;
                case 0x24: { sz = 3; const cnt = (w0 >> 12) & 0xF; s = `filled-new-array {${cnt > 0 ? '...' : ''}}, ${tref(iw(pc + 1))}`; break; }
                case 0x25: sz = 3; s = `filled-new-array/range {v${iw(pc + 2)} .. v${iw(pc + 2) + A - 1}}, ${tref(iw(pc + 1))}`; break;
                case 0x26: { sz = 3; const off = (iw(pc + 2) << 16) | iw(pc + 1); s = `fill-array-data v${A}, ${lbl(pc + off)}`; break; }
                case 0x27: s = `throw v${A}`; break;
                case 0x28: { const o8 = (A >= 128 ? A - 256 : A); s = `goto ${lbl(pc + o8)}`; break; }
                case 0x29: { sz = 2; s = `goto/16 ${lbl(pc + sw(pc + 1))}`; break; }
                case 0x2a: { sz = 3; const o = (iw(pc + 2) << 16) | iw(pc + 1); s = `goto/32 ${lbl(pc + o)}`; break; }
                case 0x2b: { sz = 2; s = `packed-switch v${A}, ${lbl(pc + sw(pc + 1))}`; break; }
                case 0x2c: { sz = 2; s = `sparse-switch v${A}, ${lbl(pc + sw(pc + 1))}`; break; }
                case 0x2d: { sz = 2; const w1 = iw(pc + 1); s = `cmpl-float v${A}, v${w1 & 0xFF}, v${(w1 >> 8) & 0xFF}`; break; }
                case 0x2e: { sz = 2; const w1 = iw(pc + 1); s = `cmpg-float v${A}, v${w1 & 0xFF}, v${(w1 >> 8) & 0xFF}`; break; }
                case 0x2f: { sz = 2; const w1 = iw(pc + 1); s = `cmpl-double v${A}, v${w1 & 0xFF}, v${(w1 >> 8) & 0xFF}`; break; }
                case 0x30: { sz = 2; const w1 = iw(pc + 1); s = `cmpg-double v${A}, v${w1 & 0xFF}, v${(w1 >> 8) & 0xFF}`; break; }
                case 0x31: { sz = 2; const w1 = iw(pc + 1); s = `cmp-long v${A}, v${w1 & 0xFF}, v${(w1 >> 8) & 0xFF}`; break; }
                case 0x32: { sz = 2; s = `if-eq v${a}, v${bN}, ${lbl(pc + sw(pc + 1))}`; break; }
                case 0x33: { sz = 2; s = `if-ne v${a}, v${bN}, ${lbl(pc + sw(pc + 1))}`; break; }
                case 0x34: { sz = 2; s = `if-lt v${a}, v${bN}, ${lbl(pc + sw(pc + 1))}`; break; }
                case 0x35: { sz = 2; s = `if-ge v${a}, v${bN}, ${lbl(pc + sw(pc + 1))}`; break; }
                case 0x36: { sz = 2; s = `if-gt v${a}, v${bN}, ${lbl(pc + sw(pc + 1))}`; break; }
                case 0x37: { sz = 2; s = `if-le v${a}, v${bN}, ${lbl(pc + sw(pc + 1))}`; break; }
                case 0x38: { sz = 2; s = `if-eqz v${A}, ${lbl(pc + sw(pc + 1))}`; break; }
                case 0x39: { sz = 2; s = `if-nez v${A}, ${lbl(pc + sw(pc + 1))}`; break; }
                case 0x3a: { sz = 2; s = `if-ltz v${A}, ${lbl(pc + sw(pc + 1))}`; break; }
                case 0x3b: { sz = 2; s = `if-gez v${A}, ${lbl(pc + sw(pc + 1))}`; break; }
                case 0x3c: { sz = 2; s = `if-gtz v${A}, ${lbl(pc + sw(pc + 1))}`; break; }
                case 0x3d: { sz = 2; s = `if-lez v${A}, ${lbl(pc + sw(pc + 1))}`; break; }
                case 0x44: case 0x45: case 0x46: case 0x47: case 0x48: case 0x49: case 0x4a: {
                    const NS = ['aget', 'aget-wide', 'aget-object', 'aget-boolean', 'aget-byte', 'aget-char', 'aget-short'];
                    sz = 2; const w1 = iw(pc + 1); s = `${NS[op - 0x44]} v${A}, v${w1 & 0xFF}, v${(w1 >> 8) & 0xFF}`; break;
                }
                case 0x4b: case 0x4c: case 0x4d: case 0x4e: case 0x4f: case 0x50: case 0x51: {
                    const NS = ['aput', 'aput-wide', 'aput-object', 'aput-boolean', 'aput-byte', 'aput-char', 'aput-short'];
                    sz = 2; const w1 = iw(pc + 1); s = `${NS[op - 0x4b]} v${A}, v${w1 & 0xFF}, v${(w1 >> 8) & 0xFF}`; break;
                }
                case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57: case 0x58: {
                    const NS = ['iget', 'iget-wide', 'iget-object', 'iget-boolean', 'iget-byte', 'iget-char', 'iget-short'];
                    sz = 2; s = `${NS[op - 0x52]} v${a}, v${bN}, ${fref(iw(pc + 1))}`; break;
                }
                case 0x59: case 0x5a: case 0x5b: case 0x5c: case 0x5d: case 0x5e: case 0x5f: {
                    const NS = ['iput', 'iput-wide', 'iput-object', 'iput-boolean', 'iput-byte', 'iput-char', 'iput-short'];
                    sz = 2; s = `${NS[op - 0x59]} v${a}, v${bN}, ${fref(iw(pc + 1))}`; break;
                }
                case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65: case 0x66: {
                    const NS = ['sget', 'sget-wide', 'sget-object', 'sget-boolean', 'sget-byte', 'sget-char', 'sget-short'];
                    sz = 2; s = `${NS[op - 0x60]} v${A}, ${fref(iw(pc + 1))}`; break;
                }
                case 0x67: case 0x68: case 0x69: case 0x6a: case 0x6b: case 0x6c: case 0x6d: {
                    const NS = ['sput', 'sput-wide', 'sput-object', 'sput-boolean', 'sput-byte', 'sput-char', 'sput-short'];
                    sz = 2; s = `${NS[op - 0x67]} v${A}, ${fref(iw(pc + 1))}`; break;
                }
                case 0x6e: case 0x6f: case 0x70: case 0x71: case 0x72: {
                    const NS = ['invoke-virtual', 'invoke-super', 'invoke-direct', 'invoke-static', 'invoke-interface'];
                    sz = 3; const w1 = iw(pc + 1), w2 = iw(pc + 2);
                    const cnt = (w0 >> 12) & 0xF, ref = w1;
                    const regsArr = [w2 & 0xF, (w2 >> 4) & 0xF, (w2 >> 8) & 0xF, (w2 >> 12) & 0xF, (w0 >> 8) & 0xF].slice(0, cnt).map(r => `v${r}`).join(', ');
                    s = `${NS[op - 0x6e]} {${regsArr}}, ${mref(ref)}`; break;
                }
                case 0x74: case 0x75: case 0x76: case 0x77: case 0x78: {
                    const NS = ['invoke-virtual/range', 'invoke-super/range', 'invoke-direct/range', 'invoke-static/range', 'invoke-interface/range'];
                    sz = 3; const w1 = iw(pc + 1), w2 = iw(pc + 2);
                    s = `${NS[op - 0x74]} {v${w2} .. v${w2 + A - 1}}, ${mref(w1)}`; break;
                }
                case 0x7b: s = `neg-int v${a}, v${bN}`; break;
                case 0x7c: s = `not-int v${a}, v${bN}`; break;
                case 0x7d: s = `neg-long v${a}, v${bN}`; break;
                case 0x7e: s = `not-long v${a}, v${bN}`; break;
                case 0x7f: s = `neg-float v${a}, v${bN}`; break;
                case 0x80: s = `neg-double v${a}, v${bN}`; break;
                case 0x81: s = `int-to-long v${a}, v${bN}`; break;
                case 0x82: s = `int-to-float v${a}, v${bN}`; break;
                case 0x83: s = `int-to-double v${a}, v${bN}`; break;
                case 0x84: s = `long-to-int v${a}, v${bN}`; break;
                case 0x85: s = `long-to-float v${a}, v${bN}`; break;
                case 0x86: s = `long-to-double v${a}, v${bN}`; break;
                case 0x87: s = `float-to-int v${a}, v${bN}`; break;
                case 0x88: s = `float-to-long v${a}, v${bN}`; break;
                case 0x89: s = `float-to-double v${a}, v${bN}`; break;
                case 0x8a: s = `double-to-int v${a}, v${bN}`; break;
                case 0x8b: s = `double-to-long v${a}, v${bN}`; break;
                case 0x8c: s = `double-to-float v${a}, v${bN}`; break;
                case 0x8d: s = `int-to-byte v${a}, v${bN}`; break;
                case 0x8e: s = `int-to-char v${a}, v${bN}`; break;
                case 0x8f: s = `int-to-short v${a}, v${bN}`; break;
                case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95:
                case 0x96: case 0x97: case 0x98: case 0x99: case 0x9a: case 0x9b:
                case 0x9c: case 0x9d: case 0x9e: case 0x9f: case 0xa0: case 0xa1:
                case 0xa2: case 0xa3: case 0xa4: case 0xa5: case 0xa6: case 0xa7:
                case 0xa8: case 0xa9: case 0xaa: case 0xab: case 0xac: case 0xad:
                case 0xae: case 0xaf: {
                    const NS = ['add-int', 'sub-int', 'mul-int', 'div-int', 'rem-int', 'and-int', 'or-int', 'xor-int', 'shl-int', 'shr-int', 'ushr-int', 'add-long', 'sub-long', 'mul-long', 'div-long', 'rem-long', 'and-long', 'or-long', 'xor-long', 'shl-long', 'shr-long', 'ushr-long', 'add-float', 'sub-float', 'mul-float', 'div-float', 'rem-float', 'add-double', 'sub-double', 'mul-double', 'div-double', 'rem-double'];
                    sz = 2; const w1 = iw(pc + 1); s = `${NS[op - 0x90] || 'op'} v${A}, v${w1 & 0xFF}, v${(w1 >> 8) & 0xFF}`; break;
                }
                case 0xb0: case 0xb1: case 0xb2: case 0xb3: case 0xb4: case 0xb5:
                case 0xb6: case 0xb7: case 0xb8: case 0xb9: case 0xba: case 0xbb:
                case 0xbc: case 0xbd: case 0xbe: case 0xbf: case 0xc0: case 0xc1:
                case 0xc2: case 0xc3: case 0xc4: case 0xc5: case 0xc6: case 0xc7:
                case 0xc8: case 0xc9: case 0xca: case 0xcb: case 0xcc: case 0xcd:
                case 0xce: case 0xcf: {
                    const NS = ['add-int', 'sub-int', 'mul-int', 'div-int', 'rem-int', 'and-int', 'or-int', 'xor-int', 'shl-int', 'shr-int', 'ushr-int', 'add-long', 'sub-long', 'mul-long', 'div-long', 'rem-long', 'and-long', 'or-long', 'xor-long', 'shl-long', 'shr-long', 'ushr-long', 'add-float', 'sub-float', 'mul-float', 'div-float', 'rem-float', 'add-double', 'sub-double', 'mul-double', 'div-double', 'rem-double'];
                    s = `${NS[op - 0xb0] || 'op'}/2addr v${a}, v${bN}`; break;
                }
                case 0xd0: case 0xd1: case 0xd2: case 0xd3: case 0xd4: case 0xd5: case 0xd6: case 0xd7: {
                    const NS = ['add-int', 'rsub-int', 'mul-int', 'div-int', 'rem-int', 'and-int', 'or-int', 'xor-int'];
                    sz = 2; s = `${NS[op - 0xd0] || 'op'}/lit16 v${a}, v${bN}, #${sw(pc + 1)}`; break;
                }
                case 0xd8: case 0xd9: case 0xda: case 0xdb: case 0xdc: case 0xdd:
                case 0xde: case 0xdf: case 0xe0: case 0xe1: case 0xe2: {
                    const NS = ['add-int', 'rsub-int', 'mul-int', 'div-int', 'rem-int', 'and-int', 'or-int', 'xor-int', 'shl-int', 'shr-int', 'ushr-int'];
                    sz = 2; const w1 = iw(pc + 1); const l8 = (w1 >> 8) & 0xFF; const sl8 = l8 >= 128 ? l8 - 256 : l8;
                    s = `${NS[op - 0xd8] || 'op'}/lit8 v${A}, v${w1 & 0xFF}, #${sl8}`; break;
                }
                default:
                    s = `# 0x${op.toString(16).padStart(2, '0')} (unknown)`;
                    break;
            }
            out.push(`    ${s}`);
            pc += sz;
        }
        if (pc < insn_count) out.push(`    # ... ${insn_count - pc} more instructions (capped)`);
        return out.join('\n');
    } catch (e) { return `    # disassembly error: ${e.message}`; }
}

function decompileToJava(buf, co, strings, types, methods, fields, totalRegs, paramCount, isStatic) {
    try {
        if (!co || !buf) return '        // abstract / native\n';
        const ab = buf instanceof ArrayBuffer ? buf : buf.buffer;
        const v = new DataView(ab);
        const b = new Uint8Array(ab);
        if (co + 16 > b.length) return '        // invalid bytecode offset\n';
        const u16 = o => v.getUint16(o, true);
        const i16 = o => v.getInt16(o, true);
        const u32 = o => v.getUint32(o, true);
        const regCount = u16(co);
        const insn_count = u32(co + 12);
        const base = co + 16;
        if (base + insn_count * 2 > b.length) return '        // truncated bytecode\n';
        if (insn_count > 500) return `        // Method too large for browser decompilation (${insn_count} instructions)\n`;
        const iw = i => u16(base + i * 2);
        const sw = i => i16(base + i * 2);

        const resolveMethod = i => {
            if (i >= methods.length) return { cls: '?', name: '?', params: [], ret: 'V' };
            const m = methods[i];
            return { cls: m.cls || '', name: m.name || '?', params: m.paramTypes || [], ret: m.returnType || 'V' };
        };
        const resolveField = i => {
            if (i >= fields.length) return { cls: '?', name: '?', type: '?' };
            const f = fields[i];
            return { cls: f.cls || '', name: f.name || '?', type: f.type || '?' };
        };
        const typeRef = i => i < types.length ? dexTypeToJava(types[i]) : `type_${i}`;
        const strRef = i => {
            if (i >= strings.length) return `"string_${i}"`;
            return `"${strings[i].replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r').slice(0, 200)}"`;
        };

        const ir = [];
        let pc = 0, itr = 0;
        while (pc < insn_count && itr++ < 4000) {
            const w0 = iw(pc);
            const op = w0 & 0xFF;
            const A = (w0 >> 8) & 0xFF;
            const a = (w0 >> 8) & 0xF;
            const bN = (w0 >> 12) & 0xF;
            const insn = { pc, op, sz: 1 };
            switch (op) {
                case 0x00: insn.type = 'nop'; break;
                case 0x01: insn.type = 'move'; insn.dst = a; insn.src = bN; break;
                case 0x02: insn.sz = 2; insn.type = 'move'; insn.dst = A; insn.src = iw(pc + 1); break;
                case 0x03: insn.sz = 3; insn.type = 'move'; insn.dst = iw(pc + 1); insn.src = iw(pc + 2); break;
                case 0x04: insn.type = 'move'; insn.dst = a; insn.src = bN; break;
                case 0x05: insn.sz = 2; insn.type = 'move'; insn.dst = A; insn.src = iw(pc + 1); break;
                case 0x06: insn.sz = 3; insn.type = 'move'; insn.dst = iw(pc + 1); insn.src = iw(pc + 2); break;
                case 0x07: insn.type = 'move'; insn.dst = a; insn.src = bN; break;
                case 0x08: insn.sz = 2; insn.type = 'move'; insn.dst = A; insn.src = iw(pc + 1); break;
                case 0x09: insn.sz = 3; insn.type = 'move'; insn.dst = iw(pc + 1); insn.src = iw(pc + 2); break;
                case 0x0a: insn.type = 'move_result'; insn.dst = A; break;
                case 0x0b: insn.type = 'move_result'; insn.dst = A; break;
                case 0x0c: insn.type = 'move_result'; insn.dst = A; break;
                case 0x0d: insn.type = 'move_exception'; insn.dst = A; break;
                case 0x0e: insn.type = 'return_void'; break;
                case 0x0f: insn.type = 'return'; insn.src = A; break;
                case 0x10: insn.type = 'return'; insn.src = A; break;
                case 0x11: insn.type = 'return'; insn.src = A; break;
                case 0x12: { const lit = (bN & 8) ? bN - 16 : bN; insn.type = 'const'; insn.dst = a; insn.literal = lit; break; }
                case 0x13: insn.sz = 2; insn.type = 'const'; insn.dst = A; insn.literal = sw(pc + 1); break;
                case 0x14: insn.sz = 3; insn.type = 'const'; insn.dst = A; insn.literal = (iw(pc + 2) << 16) | iw(pc + 1); break;
                case 0x15: insn.sz = 2; insn.type = 'const'; insn.dst = A; insn.literal = iw(pc + 1) << 16; break;
                case 0x16: insn.sz = 2; insn.type = 'const_wide'; insn.dst = A; insn.literal = sw(pc + 1); break;
                case 0x17: insn.sz = 3; insn.type = 'const_wide'; insn.dst = A; insn.literal = (iw(pc + 2) << 16) | iw(pc + 1); break;
                case 0x18: insn.sz = 5; insn.type = 'const_wide'; insn.dst = A; insn.literal = 0; break;
                case 0x19: insn.sz = 2; insn.type = 'const_wide'; insn.dst = A; insn.literal = 0; break;
                case 0x1a: insn.sz = 2; insn.type = 'const_string'; insn.dst = A; insn.stringIdx = iw(pc + 1); break;
                case 0x1b: insn.sz = 3; insn.type = 'const_string'; insn.dst = A; insn.stringIdx = (iw(pc + 2) << 16) | iw(pc + 1); break;
                case 0x1c: insn.sz = 2; insn.type = 'const_class'; insn.dst = A; insn.typeIdx = iw(pc + 1); break;
                case 0x1d: insn.type = 'monitor_enter'; insn.src = A; break;
                case 0x1e: insn.type = 'monitor_exit'; insn.src = A; break;
                case 0x1f: insn.sz = 2; insn.type = 'check_cast'; insn.dst = A; insn.typeIdx = iw(pc + 1); break;
                case 0x20: insn.sz = 2; insn.type = 'instance_of'; insn.dst = a; insn.src = bN; insn.typeIdx = iw(pc + 1); break;
                case 0x21: insn.type = 'array_length'; insn.dst = a; insn.src = bN; break;
                case 0x22: insn.sz = 2; insn.type = 'new_instance'; insn.dst = A; insn.typeIdx = iw(pc + 1); break;
                case 0x23: insn.sz = 2; insn.type = 'new_array'; insn.dst = a; insn.src = bN; insn.typeIdx = iw(pc + 1); break;
                case 0x24: {
                    insn.sz = 3; const cnt = (w0 >> 12) & 0xF; const w2 = iw(pc + 2);
                    insn.type = 'filled_new_array'; insn.typeIdx = iw(pc + 1);
                    insn.args = [w2 & 0xF, (w2 >> 4) & 0xF, (w2 >> 8) & 0xF, (w2 >> 12) & 0xF, A].slice(0, cnt); break;
                }
                case 0x25: {
                    insn.sz = 3; insn.type = 'filled_new_array_range'; insn.typeIdx = iw(pc + 1);
                    const start = iw(pc + 2); insn.args = []; for (let r = 0; r < A; r++) insn.args.push(start + r); break;
                }
                case 0x26: insn.sz = 3; insn.type = 'fill_array_data'; insn.dst = A; break;
                case 0x27: insn.type = 'throw'; insn.src = A; break;
                case 0x28: { const o8 = (A >= 128 ? A - 256 : A); insn.type = 'goto'; insn.target = pc + o8; break; }
                case 0x29: insn.sz = 2; insn.type = 'goto'; insn.target = pc + sw(pc + 1); break;
                case 0x2a: insn.sz = 3; insn.type = 'goto'; insn.target = pc + ((iw(pc + 2) << 16) | iw(pc + 1)); break;
                case 0x2b: insn.sz = 2; insn.type = 'switch'; insn.src = A; break;
                case 0x2c: insn.sz = 2; insn.type = 'switch'; insn.src = A; break;
                case 0x2d: case 0x2e: case 0x2f: case 0x30: case 0x31: {
                    insn.sz = 2; const w1 = iw(pc + 1);
                    insn.type = 'cmp'; insn.dst = A; insn.srcA = w1 & 0xFF; insn.srcB = (w1 >> 8) & 0xFF; break;
                }
                case 0x32: case 0x33: case 0x34: case 0x35: case 0x36: case 0x37: {
                    insn.sz = 2; insn.type = 'if';
                    const CMP = ['==', '!=', '<', '>=', '>', '<='];
                    insn.cmp = CMP[op - 0x32]; insn.srcA = a; insn.srcB = bN; insn.target = pc + sw(pc + 1); break;
                }
                case 0x38: case 0x39: case 0x3a: case 0x3b: case 0x3c: case 0x3d: {
                    insn.sz = 2; insn.type = 'ifz';
                    const CMP = ['==', '!=', '<', '>=', '>', '<='];
                    insn.cmp = CMP[op - 0x38]; insn.src = A; insn.target = pc + sw(pc + 1); break;
                }
                case 0x44: case 0x45: case 0x46: case 0x47: case 0x48: case 0x49: case 0x4a: {
                    insn.sz = 2; const w1 = iw(pc + 1);
                    insn.type = 'aget'; insn.dst = A; insn.arr = w1 & 0xFF; insn.idx = (w1 >> 8) & 0xFF; break;
                }
                case 0x4b: case 0x4c: case 0x4d: case 0x4e: case 0x4f: case 0x50: case 0x51: {
                    insn.sz = 2; const w1 = iw(pc + 1);
                    insn.type = 'aput'; insn.src = A; insn.arr = w1 & 0xFF; insn.idx = (w1 >> 8) & 0xFF; break;
                }
                case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57: case 0x58: {
                    insn.sz = 2; insn.type = 'iget'; insn.dst = a; insn.obj = bN; insn.fieldIdx = iw(pc + 1); break;
                }
                case 0x59: case 0x5a: case 0x5b: case 0x5c: case 0x5d: case 0x5e: case 0x5f: {
                    insn.sz = 2; insn.type = 'iput'; insn.src = a; insn.obj = bN; insn.fieldIdx = iw(pc + 1); break;
                }
                case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65: case 0x66: {
                    insn.sz = 2; insn.type = 'sget'; insn.dst = A; insn.fieldIdx = iw(pc + 1); break;
                }
                case 0x67: case 0x68: case 0x69: case 0x6a: case 0x6b: case 0x6c: case 0x6d: {
                    insn.sz = 2; insn.type = 'sput'; insn.src = A; insn.fieldIdx = iw(pc + 1); break;
                }
                case 0x6e: case 0x6f: case 0x70: case 0x71: case 0x72: {
                    insn.sz = 3; const w1 = iw(pc + 1); const w2 = iw(pc + 2);
                    const cnt = (w0 >> 12) & 0xF;
                    const KINDS = ['virtual', 'super', 'direct', 'static', 'interface'];
                    insn.type = 'invoke'; insn.kind = KINDS[op - 0x6e]; insn.methodIdx = w1;
                    insn.args = [w2 & 0xF, (w2 >> 4) & 0xF, (w2 >> 8) & 0xF, (w2 >> 12) & 0xF, (w0 >> 8) & 0xF].slice(0, cnt);
                    break;
                }
                case 0x74: case 0x75: case 0x76: case 0x77: case 0x78: {
                    insn.sz = 3; const w1 = iw(pc + 1); const w2 = iw(pc + 2);
                    const KINDS = ['virtual', 'super', 'direct', 'static', 'interface'];
                    insn.type = 'invoke'; insn.kind = KINDS[op - 0x74]; insn.methodIdx = w1;
                    insn.args = []; for (let r = 0; r < A; r++) insn.args.push(w2 + r);
                    break;
                }
                case 0x7b: insn.type = 'unary'; insn.dst = a; insn.src = bN; insn.uop = '-'; break;
                case 0x7c: insn.type = 'unary'; insn.dst = a; insn.src = bN; insn.uop = '~'; break;
                case 0x7d: insn.type = 'unary'; insn.dst = a; insn.src = bN; insn.uop = '-'; break;
                case 0x7e: insn.type = 'unary'; insn.dst = a; insn.src = bN; insn.uop = '~'; break;
                case 0x7f: insn.type = 'unary'; insn.dst = a; insn.src = bN; insn.uop = '-'; break;
                case 0x80: insn.type = 'unary'; insn.dst = a; insn.src = bN; insn.uop = '-'; break;
                case 0x81: case 0x82: case 0x83: case 0x84: case 0x85: case 0x86:
                case 0x87: case 0x88: case 0x89: case 0x8a: case 0x8b: case 0x8c: {
                    const CASTS = ['(long)', '(float)', '(double)', '(int)', '(float)', '(double)',
                        '(int)', '(long)', '(double)', '(int)', '(long)', '(float)'];
                    insn.type = 'cast'; insn.dst = a; insn.src = bN; insn.castTo = CASTS[op - 0x81]; break;
                }
                case 0x8d: insn.type = 'cast'; insn.dst = a; insn.src = bN; insn.castTo = '(byte)'; break;
                case 0x8e: insn.type = 'cast'; insn.dst = a; insn.src = bN; insn.castTo = '(char)'; break;
                case 0x8f: insn.type = 'cast'; insn.dst = a; insn.src = bN; insn.castTo = '(short)'; break;
                case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95:
                case 0x96: case 0x97: case 0x98: case 0x99: case 0x9a: case 0x9b:
                case 0x9c: case 0x9d: case 0x9e: case 0x9f: case 0xa0: case 0xa1:
                case 0xa2: case 0xa3: case 0xa4: case 0xa5: case 0xa6: case 0xa7:
                case 0xa8: case 0xa9: case 0xaa: case 0xab: case 0xac: case 0xad:
                case 0xae: case 0xaf: {
                    const OPS = ['+', '-', '*', '/', '%', '&', '|', '^', '<<', '>>', '>>>',
                        '+', '-', '*', '/', '%', '&', '|', '^', '<<', '>>', '>>>',
                        '+', '-', '*', '/', '%',
                        '+', '-', '*', '/', '%'];
                    insn.sz = 2; const w1 = iw(pc + 1);
                    insn.type = 'binop'; insn.dst = A; insn.srcA = w1 & 0xFF; insn.srcB = (w1 >> 8) & 0xFF;
                    insn.bop = OPS[op - 0x90] || '+'; break;
                }
                case 0xb0: case 0xb1: case 0xb2: case 0xb3: case 0xb4: case 0xb5:
                case 0xb6: case 0xb7: case 0xb8: case 0xb9: case 0xba: case 0xbb:
                case 0xbc: case 0xbd: case 0xbe: case 0xbf: case 0xc0: case 0xc1:
                case 0xc2: case 0xc3: case 0xc4: case 0xc5: case 0xc6: case 0xc7:
                case 0xc8: case 0xc9: case 0xca: case 0xcb: case 0xcc: case 0xcd:
                case 0xce: case 0xcf: {
                    const OPS = ['+', '-', '*', '/', '%', '&', '|', '^', '<<', '>>', '>>>',
                        '+', '-', '*', '/', '%', '&', '|', '^', '<<', '>>', '>>>',
                        '+', '-', '*', '/', '%',
                        '+', '-', '*', '/', '%'];
                    insn.type = 'binop2addr'; insn.dst = a; insn.srcB = bN;
                    insn.bop = OPS[op - 0xb0] || '+'; break;
                }
                case 0xd0: case 0xd1: case 0xd2: case 0xd3: case 0xd4: case 0xd5: case 0xd6: case 0xd7: {
                    const OPS = ['+', '-', '*', '/', '%', '&', '|', '^'];
                    insn.sz = 2; insn.type = 'binop_lit'; insn.dst = a; insn.src = bN; insn.literal = sw(pc + 1);
                    insn.bop = OPS[op - 0xd0] || '+'; break;
                }
                case 0xd8: case 0xd9: case 0xda: case 0xdb: case 0xdc: case 0xdd:
                case 0xde: case 0xdf: case 0xe0: case 0xe1: case 0xe2: {
                    const OPS = ['+', '-', '*', '/', '%', '&', '|', '^', '<<', '>>', '>>>'];
                    insn.sz = 2; const w1 = iw(pc + 1);
                    const l8 = (w1 >> 8) & 0xFF; const sl8 = l8 >= 128 ? l8 - 256 : l8;
                    insn.type = 'binop_lit'; insn.dst = A; insn.src = w1 & 0xFF; insn.literal = sl8;
                    insn.bop = OPS[op - 0xd8] || '+'; break;
                }
                default:
                    insn.type = 'unknown'; insn.raw = op; break;
            }
            ir.push(insn);
            pc += insn.sz;
        }

        const R = new Map();
        const firstParam = regCount - paramCount;
        let paramIdx = 0;
        if (!isStatic) {
            R.set(firstParam, { expr: 'this', type: 'self', assignIdx: -1, useCount: 99 });
            paramIdx = 1;
        }
        for (let p = paramIdx; p < paramCount; p++) {
            R.set(firstParam + p, { expr: `arg${p - (isStatic ? 0 : 1)}`, type: 'param', assignIdx: -1, useCount: 99 });
        }

        const reg = n => {
            const r = R.get(n);
            if (r) { r.useCount++; return r.expr; }
            return `v${n}`;
        };
        const setReg = (n, expr, type, idx) => {
            R.set(n, { expr, type: type || 'unknown', assignIdx: idx, useCount: 0 });
        };

        const newInstanceMap = new Map();
        const constructorInits = new Set();
        for (let i = 0; i < ir.length; i++) {
            if (ir[i].type === 'new_instance') {
                newInstanceMap.set(ir[i].dst, { typeIdx: ir[i].typeIdx, irIdx: i });
            }
            if (ir[i].type === 'invoke' && ir[i].kind === 'direct') {
                const m = resolveMethod(ir[i].methodIdx);
                if (m.name === '<init>' && ir[i].args.length > 0) {
                    const objReg = ir[i].args[0];
                    if (newInstanceMap.has(objReg)) {
                        ir[i]._constructorFor = objReg;
                        ir[i]._constructorType = newInstanceMap.get(objReg).typeIdx;
                        ir[i]._newInstanceIdx = newInstanceMap.get(objReg).irIdx;
                        constructorInits.add(i);
                    }
                }
            }
        }

        const branchTargets = new Map();
        for (let i = 0; i < ir.length; i++) {
            const ins = ir[i];
            if (ins.type === 'if' || ins.type === 'ifz') {
                if (ins.target > ins.pc) {
                    branchTargets.set(ins.target, 'if_close');
                } else {
                    branchTargets.set(ins.target, 'while_start');
                }
            }
            if (ins.type === 'goto' && ins.target < ins.pc) {
                branchTargets.set(ins.target, 'loop_start');
            }
        }

        const pcToIdx = new Map();
        for (let i = 0; i < ir.length; i++) pcToIdx.set(ir[i].pc, i);

        const peekMoveResult = (idx) => {
            if (idx + 1 < ir.length && ir[idx + 1].type === 'move_result') return ir[idx + 1].dst;
            return -1;
        };

        const lines = [];
        const I = n => '        ' + '    '.repeat(n);
        let indent = 0;
        const skipSet = new Set();
        for (const [, info] of newInstanceMap) {
            for (const ci of constructorInits) {
                if (ir[ci]._newInstanceIdx === info.irIdx) skipSet.add(info.irIdx);
            }
        }

        for (let i = 0; i < ir.length; i++) {
            const ins = ir[i];
            if (skipSet.has(i)) continue;

            const bt = branchTargets.get(ins.pc);
            if (bt === 'if_close') {
                if (indent > 0) indent--;
                lines.push(I(indent) + '}');
            }
            if (bt === 'while_start' || bt === 'loop_start') {
                lines.push(I(indent) + 'while (true) {');
                indent++;
            }

            switch (ins.type) {
                case 'nop': break;

                case 'move':
                    setReg(ins.dst, reg(ins.src), 'moved', i);
                    break;

                case 'move_result':
                    if (!skipSet.has(i)) {
                        setReg(ins.dst, '/* move-result */', 'unknown', i);
                    }
                    break;

                case 'move_exception':
                    setReg(ins.dst, 'ex', 'exception', i);
                    lines.push(I(indent) + `// catch exception → v${ins.dst}`);
                    break;

                case 'return_void':
                    lines.push(I(indent) + 'return;');
                    break;

                case 'return':
                    lines.push(I(indent) + `return ${reg(ins.src)};`);
                    break;

                case 'const':
                    setReg(ins.dst, ins.literal === 0 ? '0' : String(ins.literal), 'int', i);
                    break;

                case 'const_wide':
                    setReg(ins.dst, ins.literal === 0 ? '0L' : ins.literal + 'L', 'long', i);
                    break;

                case 'const_string':
                    setReg(ins.dst, strRef(ins.stringIdx), 'String', i);
                    break;

                case 'const_class':
                    setReg(ins.dst, typeRef(ins.typeIdx) + '.class', 'Class', i);
                    break;

                case 'monitor_enter':
                    lines.push(I(indent) + `synchronized (${reg(ins.src)}) {`);
                    indent++;
                    break;

                case 'monitor_exit':
                    if (indent > 0) indent--;
                    lines.push(I(indent) + '}');
                    break;

                case 'check_cast': {
                    const t = typeRef(ins.typeIdx);
                    const prev = R.get(ins.dst);
                    if (prev) {
                        setReg(ins.dst, `(${t}) ${prev.expr}`, t, i);
                    } else {
                        setReg(ins.dst, `(${t}) v${ins.dst}`, t, i);
                    }
                    break;
                }

                case 'instance_of': {
                    const t = typeRef(ins.typeIdx);
                    setReg(ins.dst, `${reg(ins.src)} instanceof ${t}`, 'boolean', i);
                    break;
                }

                case 'array_length':
                    setReg(ins.dst, `${reg(ins.src)}.length`, 'int', i);
                    break;

                case 'new_instance':
                    setReg(ins.dst, `new ${typeRef(ins.typeIdx)}()`, typeRef(ins.typeIdx), i);
                    break;

                case 'new_array': {
                    const t = typeRef(ins.typeIdx);
                    setReg(ins.dst, `new ${t.replace('[]', '')}[${reg(ins.src)}]`, t, i);
                    break;
                }

                case 'filled_new_array': case 'filled_new_array_range': {
                    const t = typeRef(ins.typeIdx);
                    const vals = (ins.args || []).map(r => reg(r)).join(', ');
                    const mr = peekMoveResult(i);
                    if (mr >= 0) {
                        setReg(mr, `new ${t} {${vals}}`, t, i);
                        skipSet.add(i + 1);
                    } else {
                        lines.push(I(indent) + `new ${t} {${vals}};`);
                    }
                    break;
                }

                case 'fill_array_data':
                    lines.push(I(indent) + `// fill-array-data v${ins.dst}`);
                    break;

                case 'throw':
                    lines.push(I(indent) + `throw ${reg(ins.src)};`);
                    break;

                case 'goto': {
                    if (ins.target < ins.pc) {
                        if (indent > 0) {
                            indent--;
                            lines.push(I(indent) + '}');
                        } else {
                            lines.push(I(indent) + `continue;`);
                        }
                    } else {
                        lines.push(I(indent) + `break;`);
                    }
                    break;
                }

                case 'switch':
                    lines.push(I(indent) + `switch (${reg(ins.src)}) { /* switch table */ }`);
                    break;

                case 'cmp':
                    setReg(ins.dst, `compare(${reg(ins.srcA)}, ${reg(ins.srcB)})`, 'int', i);
                    break;

                case 'if': {
                    const INV = { '==': '!=', '!=': '==', '<': '>=', '>=': '<', '>': '<=', '<=': '>' };
                    if (ins.target > ins.pc) {
                        const cond = INV[ins.cmp] || ins.cmp;
                        lines.push(I(indent) + `if (${reg(ins.srcA)} ${cond} ${reg(ins.srcB)}) {`);
                        indent++;
                    } else {
                        lines.push(I(indent) + `if (${reg(ins.srcA)} ${ins.cmp} ${reg(ins.srcB)}) break;`);
                    }
                    break;
                }

                case 'ifz': {
                    const INV = { '==': '!=', '!=': '==', '<': '>=', '>=': '<', '>': '<=', '<=': '>' };
                    const val = reg(ins.src);
                    const zeroExpr = (cmp) => {
                        if (cmp === '!=' || cmp === '==') return `${val} ${cmp} null`;
                        return `${val} ${cmp} 0`;
                    };
                    if (ins.target > ins.pc) {
                        const cond = INV[ins.cmp] || ins.cmp;
                        lines.push(I(indent) + `if (${zeroExpr(cond)}) {`);
                        indent++;
                    } else {
                        lines.push(I(indent) + `if (${zeroExpr(ins.cmp)}) break;`);
                    }
                    break;
                }

                case 'aget':
                    setReg(ins.dst, `${reg(ins.arr)}[${reg(ins.idx)}]`, 'element', i);
                    break;

                case 'aput':
                    lines.push(I(indent) + `${reg(ins.arr)}[${reg(ins.idx)}] = ${reg(ins.src)};`);
                    break;

                case 'iget': {
                    const f = resolveField(ins.fieldIdx);
                    const objExpr = reg(ins.obj);
                    setReg(ins.dst, `${objExpr}.${f.name}`, dexTypeToJava(f.type), i);
                    break;
                }

                case 'iput': {
                    const f = resolveField(ins.fieldIdx);
                    const objExpr = reg(ins.obj);
                    lines.push(I(indent) + `${objExpr}.${f.name} = ${reg(ins.src)};`);
                    break;
                }

                case 'sget': {
                    const f = resolveField(ins.fieldIdx);
                    const clsName = dexTypeToJava(f.cls);
                    setReg(ins.dst, `${clsName}.${f.name}`, dexTypeToJava(f.type), i);
                    break;
                }

                case 'sput': {
                    const f = resolveField(ins.fieldIdx);
                    const clsName = dexTypeToJava(f.cls);
                    lines.push(I(indent) + `${clsName}.${f.name} = ${reg(ins.src)};`);
                    break;
                }

                case 'invoke': {
                    const m = resolveMethod(ins.methodIdx);
                    const isInit = m.name === '<init>';
                    const isStaticCall = ins.kind === 'static';

                    if (constructorInits.has(i) && isInit) {
                        const objReg = ins.args[0];
                        const t = typeRef(ins._constructorType);
                        const argExprs = ins.args.slice(1).map(r => reg(r)).join(', ');
                        setReg(objReg, `new ${t}(${argExprs})`, t, i);
                        lines.push(I(indent) + `${t} v${objReg} = new ${t}(${argExprs});`);
                        break;
                    }

                    let callExpr;
                    if (isStaticCall) {
                        const clsName = dexTypeToJava(m.cls);
                        const argExprs = ins.args.map(r => reg(r)).join(', ');
                        callExpr = `${clsName}.${m.name}(${argExprs})`;
                    } else if (isInit) {
                        const objExpr = ins.args.length > 0 ? reg(ins.args[0]) : 'this';
                        const argExprs = ins.args.slice(1).map(r => reg(r)).join(', ');
                        if (objExpr === 'this') {
                            callExpr = `super(${argExprs})`;
                        } else {
                            callExpr = `${objExpr}.<init>(${argExprs})`;
                        }
                    } else {
                        const objExpr = ins.args.length > 0 ? reg(ins.args[0]) : '?';
                        const argExprs = ins.args.slice(1).map(r => reg(r)).join(', ');
                        callExpr = `${objExpr}.${m.name}(${argExprs})`;
                    }

                    const mr = peekMoveResult(i);
                    if (mr >= 0) {
                        setReg(mr, callExpr, dexTypeToJava(m.ret), i);
                        skipSet.add(i + 1);
                        if (m.ret !== 'V') {
                            lines.push(I(indent) + `${dexTypeToJava(m.ret)} v${mr} = ${callExpr};`);
                        } else {
                            lines.push(I(indent) + `${callExpr};`);
                        }
                    } else {
                        lines.push(I(indent) + `${callExpr};`);
                    }
                    break;
                }

                case 'unary':
                    setReg(ins.dst, `${ins.uop}${reg(ins.src)}`, 'numeric', i);
                    lines.push(I(indent) + `v${ins.dst} = ${ins.uop}${reg(ins.src)};`);
                    break;

                case 'cast':
                    setReg(ins.dst, `${ins.castTo} ${reg(ins.src)}`, ins.castTo.replace(/[()]/g, ''), i);
                    break;

                case 'binop': {
                    const expr = `${reg(ins.srcA)} ${ins.bop} ${reg(ins.srcB)}`;
                    setReg(ins.dst, expr, 'numeric', i);
                    lines.push(I(indent) + `v${ins.dst} = ${expr};`);
                    break;
                }

                case 'binop2addr': {
                    const expr = `${reg(ins.dst)} ${ins.bop} ${reg(ins.srcB)}`;
                    lines.push(I(indent) + `v${ins.dst} = ${expr};`);
                    setReg(ins.dst, `v${ins.dst}`, 'numeric', i);
                    break;
                }

                case 'binop_lit': {
                    const expr = `${reg(ins.src)} ${ins.bop} ${ins.literal}`;
                    setReg(ins.dst, expr, 'numeric', i);
                    lines.push(I(indent) + `v${ins.dst} = ${expr};`);
                    break;
                }

                case 'unknown':
                    lines.push(I(indent) + `// unknown opcode 0x${ins.raw.toString(16)}`);
                    break;

                default: break;
            }
        }

        while (indent > 0) { indent--; lines.push(I(indent) + '}'); }

        return lines.length > 0 ? lines.join('\n') + '\n' : '        // empty method\n';
    } catch (e) {
        return `        // decompilation error: ${e.message}\n`;
    }
}

function generateSmaliView(cls, buf, allStrings, allTypes, allMethods, allFields) {
    const L = [];
    L.push(`.class ${smaliFlags(cls.flags)} ${cls.name || ''}`);
    if (cls.superName) L.push(`.super ${cls.superName}`);
    if (cls.srcFile) L.push(`.source "${cls.srcFile}"`);
    for (const iface of (cls.interfaces || [])) L.push(`.implements ${iface}`);
    L.push('');
    const sF = (cls.fields || []).filter(f => f.isStatic);
    const iF = (cls.fields || []).filter(f => !f.isStatic);
    if (sF.length) {
        L.push('# ─── Static Fields ─────────────────────────────────');
        for (const f of sF) L.push(`.field ${smaliFlags(f.flags)} ${f.name}:${f.type}`);
        L.push('');
    }
    if (iF.length) {
        L.push('# ─── Instance Fields ───────────────────────────────');
        for (const f of iF) L.push(`.field ${smaliFlags(f.flags)} ${f.name}:${f.type}`);
        L.push('');
    }
    for (const m of (cls.methods || []).slice(0, 80)) {
        const params = (m.paramTypes || []).join('');
        const ret = m.returnType || 'V';
        L.push(`.method ${smaliFlags(m.af || 0)} ${m.name}(${params})${ret}`);
        L.push(disassembleCode(buf, m.co, allStrings, allTypes, allMethods, allFields));
        L.push('.end method');
        L.push('');
    }
    return L.join('\n');
}

function highlightXML(xml) {
    return xml.split('\n').map((line, idx) => {
        let s = esc(line);
        s = s.replace(/(&lt;\?)([\w]+)([\s\S]*?)(\?&gt;)/g, '<span class="xp">$1</span><span class="xt">$2</span>$3<span class="xp">$4</span>');
        s = s.replace(/(&lt;!--)([\s\S]*?)(--&gt;)/g, '<span class="xc">$1$2$3</span>');
        s = s.replace(/(&lt;\/)([\w:.-]+)(&gt;)/g, '<span class="xp">$1</span><span class="xt">$2</span><span class="xp">$3</span>');
        s = s.replace(/(&lt;)([\w:.-]+)/g, '<span class="xp">$1</span><span class="xt">$2</span>');
        s = s.replace(/(\/?&gt;)/g, '<span class="xp">$1</span>');
        s = s.replace(/\b([\w]+):([\w-]+)(=)(&quot;)([^<]*)(&quot;)/g,
            '<span class="xn">$1:</span><span class="xa">$2</span><span class="xp">=$4</span><span class="xv">$5</span><span class="xp">$6</span>');
        s = s.replace(/\b([\w-]+)(=)(&quot;)([^<]*)(&quot;)/g,
            '<span class="xa">$1</span><span class="xp">=$3</span><span class="xv">$4</span><span class="xp">$5</span>');
        return `<div class="cl"><span class="ln">${idx + 1}</span><span class="lc">${s}</span></div>`;
    }).join('');
}

function highlightJava(raw) {
    const KW = /\b(package|import|class|interface|enum|extends|implements|new|return|if|else|while|for|do|try|catch|finally|throw|throws|super|this|null|true|false|instanceof)\b/g;
    const MOD = /\b(public|private|protected|static|final|abstract|synchronized|native|transient|volatile|strictfp)\b/g;
    const PRIM = /\b(void|boolean|byte|short|char|int|long|float|double)\b/g;
    return raw.split('\n').map((line, idx) => {
        let s = esc(line);
        const ci = s.indexOf('//');
        let code = ci >= 0 ? s.slice(0, ci) : s;
        const cmt = ci >= 0 ? `<span class="sc">${s.slice(ci)}</span>` : '';
        code = code.replace(/(&quot;(?:[^&]|&amp;|&lt;|&gt;)*?&quot;|&#39;(?:[^&]|&amp;)*?&#39;)/g, '<span class="ss">$1</span>');
        code = code.replace(KW, '<span class="sk">$1</span>');
        code = code.replace(MOD, '<span class="sm">$1</span>');
        code = code.replace(PRIM, '<span class="sm">$1</span>');
        code = code.replace(/\b([A-Z][A-Za-z0-9_$]*(?:\[\])?)\b/g, '<span class="st">$1</span>');
        code = code.replace(/(@[\w]+)/g, '<span class="sl">$1</span>');
        code = code.replace(/(0x[0-9A-Fa-f]+|\b\d+[LlFfDd]?\b)/g, '<span class="sn">$1</span>');
        return `<div class="cl"><span class="ln">${idx + 1}</span><span class="lc">${code}${cmt}</span></div>`;
    }).join('');
}

function highlightSmali(raw) {
    return raw.split('\n').map((line, idx) => {
        let s = esc(line);
        const ci = s.indexOf('#');
        let code = ci >= 0 ? s.slice(0, ci) : s;
        const cmt = ci >= 0 ? `<span class="sc">${s.slice(ci)}</span>` : '';
        code = code.replace(/^(\s*)(\.[\w-]+)/g, '$1<span class="sk">$2</span>');
        code = code.replace(/\b(public|private|protected|static|final|abstract|interface|enum|synthetic|constructor|bridge|native|transient|volatile|varargs)\b/g, '<span class="sm">$1</span>');
        code = code.replace(/(:[\w$]+)/g, '<span class="sl">$1</span>');
        code = code.replace(/(L[a-zA-Z_$][a-zA-Z0-9_$\/]*;)/g, '<span class="st">$1</span>');
        code = code.replace(/(&quot;(?:[^&]|&amp;|&lt;|&gt;)*?&quot;)/g, '<span class="ss">$1</span>');
        code = code.replace(/\b([vp]\d{1,2})\b/g, '<span class="sr">$1</span>');
        code = code.replace(/(0x[0-9a-fA-F]+)/g, '<span class="sn">$1</span>');
        code = code.replace(/(?<![a-zA-Z_$])(\d+)(?![a-zA-Z_$])/g, '<span class="sn">$1</span>');
        return `<div class="cl"><span class="ln">${idx + 1}</span><span class="lc">${code}${cmt}</span></div>`;
    }).join('');
}

function renderManifestTab(R) {
    const el = document.getElementById('manifestViewer');
    if (!el) return;
    if (!R || !R.manifestStr) {
        el.innerHTML = '<div style="padding:32px;text-align:center;color:var(--text-muted);font-size:14px">AndroidManifest.xml could not be parsed from this APK</div>';
        return;
    }
    el.innerHTML = `<div class="cwl">${highlightXML(R.manifestStr)}</div>`;
}

function copyManifest() {
    const R = state.analysisResults;
    if (!R || !R.manifestStr) { showToast('No manifest available', 'error'); return; }
    navigator.clipboard.writeText(R.manifestStr).then(() => showToast('Manifest copied!', 'success')).catch(() => showToast('Copy failed', 'error'));
}

function downloadManifestFile() {
    const R = state.analysisResults;
    if (!R || !R.manifestStr) { showToast('No manifest available', 'error'); return; }
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([R.manifestStr], { type: 'text/xml' }));
    a.download = 'AndroidManifest.xml'; a.click();
}

function ir(k, v) { return `<div class="info-row"><span class="info-key">${esc(k)}</span><span class="info-val">${v}</span></div>`; }

function renderOverviewTab(R) {
    const g = state.groupedFindings;

    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    set('infoPkg', R.appInfo.packageName || R.appInfo.fileName);
    set('infoVer', R.appInfo.versionName || R.appInfo.versionCode || '—');
    set('infoMin', R.minSdk ? `API ${R.minSdk} (Android ${sdkToVer(R.minSdk)})` : '—');
    set('infoTarget', R.targetSdk ? `API ${R.targetSdk} (Android ${sdkToVer(R.targetSdk)})` : '—');

    const ci = R.certInfo;
    document.getElementById('appInfoGrid').innerHTML = `<div class="info-grid">
        ${ir('Package', R.appInfo.packageName || R.appInfo.fileName)}
        ${ir('File', R.appInfo.fileName)}
        ${ir('Size', R.appInfo.fileSize)}
        ${ir('MD5', `<span style="font-family:monospace;font-size:11px;word-break:break-all">${R.appInfo.md5 || '—'}</span>`)}
        ${ir('SHA-256', `<span style="font-family:monospace;font-size:11px;word-break:break-all">${R.appInfo.sha256 || '—'}</span>`)}
        ${ir('Min SDK', R.minSdk ? `API ${R.minSdk} (Android ${sdkToVer(R.minSdk)})` : '—')}
        ${ir('Target SDK', R.targetSdk ? `API ${R.targetSdk} (Android ${sdkToVer(R.targetSdk)})` : '—')}
        ${ir('DEX Files', R.dexFiles.length || R.specialFiles.dex.length)}
        ${ir('Native Libs', R.nativeLibs.length)}
        ${ir('Obfuscated', R.isObfuscated ? '<span style="color:var(--green)">Yes</span>' : '<span style="color:var(--orange)">No</span>')}
        ${ci ? ir('Cert Subject', Object.entries(ci.subject).map(([k, v]) => `${k}=${esc(v)}`).join(', ') || '—') : ''}
        ${ci ? ir('Cert Algorithm', `<span style="color:${['MD5withRSA', 'SHA1withRSA'].includes(ci.sigAlg) ? 'var(--red)' : 'var(--green)'}">${esc(ci.sigAlg) || '—'}</span>`) : ''}
        ${ci ? ir('Cert Validity', `${ci.validity?.notBefore || '?'} → ${ci.validity?.notAfter || '?'}${ci.isExpired ? ' <span style="color:var(--red)">(EXPIRED)</span>' : ''}`) : ''}
        ${ci ? ir('Debug Cert', ci.isDebug ? '<span style="color:var(--red)">Yes -debug signed!</span>' : '<span style="color:var(--green)">No</span>') : ''}
    </div>`;

    const pEl = document.getElementById('permissionsList');
    pEl.innerHTML = R.permissions.length ? R.permissions.map(p => {
        const d = DANGEROUS_PERMS.has(p);
        return `<div class="perm-item ${d ? 'danger' : 'normal'}"><span class="perm-icon" style="color:${d ? 'var(--red)' : 'var(--orange)'}">${d ? '&#9679;' : '&#9675;'}</span><div><div class="perm-name">${esc(p)}</div><div class="perm-full">android.permission.${esc(p)}</div></div>${d ? '<span class="badge-danger">Dangerous</span>' : ''}</div>`;
    }).join('') : '<div class="no-data">No permissions declared</div>';

    const cEl = document.getElementById('componentsList');
    const cmp = R.components;
    const mkComp = (arr, type) => arr.map(c => {
        const exp = c.exported === true || c.exported === 'true';
        return `<div class="comp-item ${exp ? 'exported' : ''}"><span class="comp-type">${type}</span><span class="comp-name">${esc(c.name.split('.').pop())}</span>${exp && !c.permission ? '<span class="badge-danger">Exported</span>' : exp ? '<span class="badge-warn">Exported</span>' : ''}</div>`;
    }).join('');
    cEl.innerHTML = mkComp(cmp.activities, 'Activity') + mkComp(cmp.services, 'Service') + mkComp(cmp.receivers, 'Receiver') + mkComp(cmp.providers, 'Provider') || '<div class="no-data">No components found</div>';

    document.getElementById('trackersList').innerHTML = R.trackers.length
        ? R.trackers.map(t => `<div class="tracker-item"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:13px;height:13px;opacity:.5;flex-shrink:0"><circle cx="12" cy="12" r="10"/></svg>${esc(t)}</div>`).join('')
        : '<div class="no-data">No known third-party SDKs detected</div>';
}

function renderFindingsTab(filterSev = 'all', query = '') {
    state._currentFindingsFilter = filterSev;
    if (query !== undefined && query !== null) state._currentFindingsQuery = query.toLowerCase();
    const q = state._currentFindingsQuery || '';
    
    let all = [...state.groupedFindings.issue];
    
    if (filterSev !== 'all') {
        all = all.filter(f => {
            const s = (f.severity === 'issue' || f.severity === 'medium') ? 'medium' : f.severity;
            return s === filterSev;
        });
    }
    
    if (q) {
        all = all.filter(f => 
            f.ruleName.toLowerCase().includes(q) || 
            f.description.toLowerCase().includes(q) ||
            (f.cwe && f.cwe.toLowerCase().includes(q))
        );
    }

    const renderMatch = m => {
        const file = m.file || '';
        return `<div class="finding-match-item"><code>${esc((m.match || '').slice(0, 150))}</code><span class="match-loc finding-goto" data-file="${esc(file)}" data-line="${m.line || ''}">${esc(file)}${m.line ? ':' + m.line : ''}</span></div>`;
    };

    const counts = {
        critical: state.groupedFindings.issue.filter(f => f.severity === 'critical').length,
        medium: state.groupedFindings.issue.filter(f => f.severity === 'issue' || f.severity === 'medium').length,
        info: state.groupedFindings.issue.filter(f => f.severity === 'info').length
    };

    const filterBar = `
        <div class="filter-bar" style="padding: 0 0 16px 0; border-bottom: 1px solid var(--border-subtle); margin-bottom: 16px">
            <button class="filter-btn ${filterSev === 'all' ? 'active' : ''}" onclick="renderFindingsTab('all')">All (${state.groupedFindings.issue.length})</button>
            <button class="filter-btn ${filterSev === 'critical' ? 'active' : ''}" onclick="renderFindingsTab('critical')" style="border-left: 3px solid #ef4444">Critical (${counts.critical})</button>
            <button class="filter-btn ${filterSev === 'medium' ? 'active' : ''}" onclick="renderFindingsTab('medium')" style="border-left: 3px solid #f59e0b">Medium (${counts.medium})</button>
            <button class="filter-btn ${filterSev === 'info' ? 'active' : ''}" onclick="renderFindingsTab('info')" style="border-left: 3px solid #06b6d4">Info (${counts.info})</button>
        </div>
    `;

    document.getElementById('findingsList').innerHTML = filterBar + (all.map((f, idx) => {
        const countBadge = f.count > 1 ? `<span class="finding-count-badge">${f.count} instances</span>` : '';
        const sev = (f.severity === 'issue' || f.severity === 'medium') ? 'warning' :
            (f.severity === 'critical') ? 'high' : (f.severity === 'info' ? 'info' : f.severity);
        const sevText = (f.severity === 'issue') ? 'MEDIUM' : f.severity.toUpperCase();

        let matchesHtml = (f.matches || []).map(renderMatch).join('');

        return `
            <div class="finding-container-compact">
                <div class="finding-row-compact ${sev}" onclick="this.classList.toggle('active'); document.getElementById('details_${idx}').classList.toggle('active')">
                    <div class="sev-mini ${sev}">${sevText}</div>
                    <div class="finding-title-compact">${esc(f.ruleName)}</div>
                    <div class="finding-meta-compact">
                        ${countBadge}
                        <span class="finding-chevron">▼</span>
                    </div>
                </div>
                <div id="details_${idx}" class="finding-details-compact">
                    <p class="finding-desc" style="margin-bottom:16px; font-size:13px; opacity:0.8; line-height:1.6">${esc(f.description)}</p>
                    <div class="finding-matches">${matchesHtml}</div>
                    <div class="finding-tags" style="margin-top:12px">
                        ${f.cwe ? `<span class="tag">${esc(f.cwe)}</span>` : ''}${f.owasp ? `<span class="tag">OWASP M${esc(f.owasp.replace('M', ''))}</span>` : ''}${f.masvs ? `<span class="tag">MASVS-${esc(f.masvs)}</span>` : ''}
                    </div>
                </div>
            </div>
        `;
    }).join('') || '<div class="no-data">No findings matching filter</div>');
    const fl = document.getElementById('findingsList');
    const handler = e => {
        const btn = e.target.closest('.finding-expand-btn');
        if (btn) {
            const el = document.getElementById(btn.dataset.target);
            if (!el) return;
            const hidden = el.style.display === 'none';
            el.style.display = hidden ? '' : 'none';
            btn.textContent = hidden ? 'Hide instances' : 'Show all ' + btn.dataset.total + ' instances';
            return;
        }
        const loc = e.target.closest('.finding-goto');
        if (loc) {
            navigateToFile(loc.dataset.file, loc.dataset.line);
        }
    };
    fl.removeEventListener('click', fl._expandHandler);
    fl._expandHandler = handler;
    fl.addEventListener('click', handler);
}

function filterFindings(q) {
    renderFindingsTab(state._currentFindingsFilter || 'all', q);
}

function renderSmaliTab(R) {
    const total = state.dexParsed.reduce((s, d) => s + d.classes.length, 0);
    const totalM = state.dexParsed.reduce((s, d) => s + d.methods.length, 0);
    document.getElementById('smaliInfo').innerHTML = `<div class="dex-stats">
        ${R.dexFiles.map(d => `<div class="dex-stat-card"><div class="dex-name">${esc(d.name)}</div><div class="dex-nums"><span>${d.classes} classes</span><span>${d.methods} methods</span><span>${d.strings} strings</span></div></div>`).join('')}
        <div class="dex-stat-card total"><div class="dex-name">Totals</div><div class="dex-nums"><span>${total} classes</span><span>${totalM} methods</span><span>${R.strings.length} strings</span></div></div>
    </div>`;
    const treeEl = document.getElementById('smaliTree');
    if (!R.dexFiles.length) {
        treeEl.innerHTML = '<div style="padding:16px;text-align:center;color:var(--text-muted);font-size:12px">No DEX files found</div>';
    } else {
        renderSmaliTree(treeEl, state.smaliTree);
    }
    renderSmaliStrings(R);
}

function renderSmaliTree(el, tree) {
    el.innerHTML = '';
    const pkgs = Object.keys(tree).filter(k => tree[k]._type === 'pkg').sort();
    const clss = Object.keys(tree).filter(k => tree[k]._type === 'class').sort();
    for (const pkg of pkgs) {
        const node = tree[pkg];
        const det = document.createElement('details');
        det.innerHTML = `<summary class="jadx-pkg"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:11px;height:11px;opacity:.45;flex-shrink:0"><path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2z"/></svg>${esc(pkg)}</summary>`;
        const inner = document.createElement('div'); inner.className = 'jadx-children';
        renderSmaliTree(inner, node._ch);
        det.appendChild(inner); el.appendChild(det);
    }
    for (const cls of clss) {
        const node = tree[cls];
        const isIface = (node._cls.flags & 0x0200) !== 0;
        const isAbst = (node._cls.flags & 0x0400) !== 0;
        const icon = isIface ? '&#11041;' : isAbst ? '&#9672;' : '&#9670;';
        const col = isIface ? 'var(--cyan)' : isAbst ? 'var(--orange)' : 'var(--accent-primary)';
        const btn = document.createElement('div');
        btn.className = 'jadx-cls';
        btn.dataset.fqn = node._fqn;
        btn.innerHTML = `<span style="color:${col};font-size:9px;flex-shrink:0">${icon}</span><span>${esc(cls)}</span>`;
        btn.onclick = () => showSmaliClass(node._cls, node._fqn, node._dexIdx);
        el.appendChild(btn);
    }
}

function filterSmaliTree(q) {
    const el = document.getElementById('smaliTree');
    if (!q) { renderSmaliTree(el, state.smaliTree); return; }
    el.innerHTML = '';
    const lq = q.toLowerCase();
    const results = [];
    function walk(tree) {
        for (const [, node] of Object.entries(tree)) {
            if (node._type === 'class') { if (node._fqn.toLowerCase().includes(lq)) results.push(node); }
            else if (node._type === 'pkg') walk(node._ch);
        }
    }
    walk(state.smaliTree);
    if (!results.length) { el.innerHTML = '<div style="padding:12px 16px;color:var(--text-muted);font-size:12px">No results</div>'; return; }
    results.slice(0, 200).forEach(node => {
        const isIface = (node._cls.flags & 0x0200) !== 0;
        const isAbst = (node._cls.flags & 0x0400) !== 0;
        const icon = isIface ? '&#11041;' : isAbst ? '&#9672;' : '&#9670;';
        const col = isIface ? 'var(--cyan)' : isAbst ? 'var(--orange)' : 'var(--accent-primary)';
        const btn = document.createElement('div');
        btn.className = 'jadx-cls'; btn.dataset.fqn = node._fqn;
        btn.innerHTML = `<span style="color:${col};font-size:9px;flex-shrink:0">${icon}</span><span style="font-size:11px">${esc(node._fqn)}</span>`;
        btn.onclick = () => showSmaliClass(node._cls, node._fqn, node._dexIdx);
        el.appendChild(btn);
    });
}

function renderSmaliStrings(R) {
    const interesting = R.strings.filter(s => s.length > 6 && !/^[LQ\[]/.test(s) && !/^</.test(s)).slice(0, 500);
    const urls = R.urls.slice(0, 100);
    document.getElementById('smaliStrings').innerHTML = `
    <div class="strings-tabs">
        <button class="stab active" onclick="showStringsTab(this,'stab-interesting')">Interesting (${interesting.length})</button>
        <button class="stab" onclick="showStringsTab(this,'stab-urls')">URLs (${urls.length})</button>
        <button class="stab" onclick="showStringsTab(this,'stab-all')">All Strings (${Math.min(R.strings.length, 1000)})</button>
    </div>
    <div id="stab-interesting" class="strings-list active">${interesting.map(s => `<div class="str-item">${esc(s)}</div>`).join('') || '<div class="no-data">No interesting strings</div>'}</div>
    <div id="stab-urls" class="strings-list">${urls.map(s => `<div class="str-item url">${esc(s)}</div>`).join('') || '<div class="no-data">No URLs found</div>'}</div>
    <div id="stab-all" class="strings-list">${R.strings.slice(0, 1000).map(s => `<div class="str-item">${esc(s)}</div>`).join('')}</div>`;
}

function showStringsTab(btn, id) {
    document.querySelectorAll('.stab').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.strings-list').forEach(l => l.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(id)?.classList.add('active');
}

function showSmaliClass(cls, fqn, dexIdx) {
    state.currentViewClass = cls;
    state.currentViewFqn = fqn;
    state.currentViewDexIdx = dexIdx ?? 0;

    const simple = fqn.split('.').pop();
    const mCnt = (cls.methods || []).length, fCnt = (cls.fields || []).length;

    document.getElementById('jadxFilePath').textContent = fqn;
    document.getElementById('jadxFileMeta').textContent =
        `${mCnt} method${mCnt !== 1 ? 's' : ''} · ${fCnt} field${fCnt !== 1 ? 's' : ''}`;

    const toggle = document.getElementById('jadxViewToggle');
    if (toggle) toggle.style.display = 'flex';

    const jumpSel = document.getElementById('methodJump');
    if (jumpSel) {
        jumpSel.innerHTML = '<option value="">Jump to method...</option>';
        for (const m of (cls.methods || []).slice(0, 120)) {
            const name = m.name === '<init>' ? simple + ' (constructor)' : (m.name === '<clinit>' ? 'static {}' : m.name);
            jumpSel.innerHTML += `<option value="${esc(m.name)}">${esc(name)}</option>`;
        }
        jumpSel.style.display = 'inline-block';
    }

    renderCodeView();
    document.querySelectorAll('.jadx-cls').forEach(el => el.classList.toggle('active', el.dataset.fqn === fqn));
}

function switchCodeView(mode) {
    state.currentViewMode = mode;
    document.querySelectorAll('.jadx-toggle-btn').forEach(b =>
        b.classList.toggle('active', b.dataset.view === mode));
    renderCodeView();
}

function renderCodeView() {
    const cls = state.currentViewClass;
    if (!cls) return;
    const fqn = state.currentViewFqn;
    const simple = (fqn || '').split('.').pop();
    const dex = state.dexParsed[state.currentViewDexIdx ?? 0];
    const mode = state.currentViewMode;

    const ext = mode === 'java' ? '.java' : '.smali';
    document.getElementById('jadxFileName').textContent = simple + ext;

    document.querySelectorAll('.jadx-toggle-btn').forEach(b =>
        b.classList.toggle('active', b.dataset.view === mode));

    let code, highlighted;
    if (mode === 'java') {
        if (state.javaCache.has(fqn)) {
            code = state.javaCache.get(fqn);
        } else {
            code = dex
                ? generateJavaView(cls, dex.buf, dex.strings, dex.types, dex.methods, dex.fields || [])
                : generateJavaView(cls, null, [], [], [], []);
            state.javaCache.set(fqn, code);
        }
        highlighted = highlightJava(code);
    } else {
        code = dex
            ? generateSmaliView(cls, dex.buf, dex.strings, dex.types, dex.methods, dex.fields || [])
            : generateSmaliView(cls, null, [], [], [], []);
        highlighted = highlightSmali(code);
    }

    document.getElementById('jadxCode').innerHTML = `<div class="cwl">${highlighted}</div>`;
    if (typeof _activeSearchQuery === 'string' && _activeSearchQuery.length > 0) setTimeout(() => applyCodeSearch(_activeSearchQuery), 50);
}

function jumpToMethod(methodName) {
    if (!methodName) return;
    const codeEl = document.getElementById('jadxCode');
    if (!codeEl) return;
    const lines = codeEl.querySelectorAll('.cl');
    for (const line of lines) {
        const text = line.textContent || '';
        if (text.includes(methodName + '(') || text.includes(methodName + ' (')) {
            line.scrollIntoView({ behavior: 'smooth', block: 'center' });
            line.style.background = 'rgba(129,140,248,.2)';
            setTimeout(() => { line.style.background = ''; }, 2000);
            break;
        }
    }
}

function switchExplorerView(mode, btn) {
    state.explorerView = mode;
    if (btn) {
        btn.parentElement.querySelectorAll('.stab').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
    }
    const isAPK = mode === 'apk';
    const isClass = mode === 'java' || mode === 'smali';

    const fileTree = document.getElementById('fileTree');
    const fileTreeHeader = document.getElementById('fileTreeHeader');
    const javaTree = document.getElementById('javaSourceTree');
    const smaliTree = document.getElementById('smaliSourceTree');
    const classSearch = document.getElementById('classSearchWrap');
    const smaliTreeEl = document.getElementById('smaliTree');
    const typeFilter = document.getElementById('fileTypeFilter');

    if (fileTree) fileTree.style.display = isAPK ? '' : 'none';
    if (fileTreeHeader) fileTreeHeader.style.display = isAPK ? '' : 'none';
    if (typeFilter) typeFilter.style.display = isAPK ? '' : 'none';

    if (classSearch) classSearch.style.display = 'none';
    if (smaliTreeEl) smaliTreeEl.style.display = isClass ? '' : 'none';

    if (javaTree) javaTree.style.display = 'none';
    if (smaliTree) smaliTree.style.display = 'none';

    if (isClass) {
        state.currentViewMode = mode;
        document.querySelectorAll('.jadx-toggle-btn').forEach(b =>
            b.classList.toggle('active', b.dataset.view === mode));
    }

    if (mode === 'java' && javaTree && !javaTree.dataset.built) {
        buildSourceTree(javaTree, 'java');
        javaTree.dataset.built = '1';
    }
    if (mode === 'smali' && smaliTree && !smaliTree.dataset.built) {
        buildSourceTree(smaliTree, 'smali');
        smaliTree.dataset.built = '1';
    }
}

function buildSourceTree(container, ext) {
    container.innerHTML = '';
    const tree = {};
    for (let dexIdx = 0; dexIdx < state.dexParsed.length; dexIdx++) {
        const dex = state.dexParsed[dexIdx];
        for (const cls of (dex.classes || [])) {
            const fqn = (cls.name || '').replace(/^L/, '').replace(/;$/, '').replace(/\//g, '.');
            const parts = fqn.split('.');
            let node = tree;
            for (let p = 0; p < parts.length - 1; p++) {
                if (!node[parts[p]]) node[parts[p]] = { _type: 'dir', _children: {} };
                node = node[parts[p]]._children;
            }
            const fileName = parts[parts.length - 1] + '.' + ext;
            node[fileName] = { _type: 'file', _cls: cls, _fqn: fqn, _dexIdx: dexIdx };
        }
    }
    renderSourceNode(container, tree, ext);
}

function renderSourceNode(el, tree, ext) {
    const dirs = Object.keys(tree).filter(k => tree[k]._type === 'dir').sort();
    const files = Object.keys(tree).filter(k => tree[k]._type === 'file').sort();
    for (const d of dirs) {
        const det = document.createElement('details');
        det.innerHTML = `<summary class="tree-dir"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:12px;height:12px"><path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2z"/></svg>${esc(d)}</summary>`;
        const inner = document.createElement('div'); inner.className = 'tree-children';
        renderSourceNode(inner, tree[d]._children, ext);
        det.appendChild(inner); el.appendChild(det);
    }
    for (const f of files) {
        const info = tree[f];
        const btn = document.createElement('div'); btn.className = 'tree-file';
        const icon = ext === 'java' ? '&#9670;' : '&#9671;';
        btn.innerHTML = `<span class="file-icon">${icon}</span><span class="file-name">${esc(f)}</span>`;
        btn.onclick = () => openSourceFile(info._cls, info._fqn, info._dexIdx, ext);
        el.appendChild(btn);
    }
}

function openSourceFile(cls, fqn, dexIdx, ext) {
    const viewer = document.getElementById('fileViewer');
    const pathEl = document.getElementById('currentFilePath');
    if (pathEl) pathEl.textContent = fqn.replace(/\./g, '/') + '.' + ext;

    const dex = state.dexParsed[dexIdx ?? 0];
    let code, highlighted;
    if (ext === 'java') {
        if (state.javaCache.has(fqn)) {
            code = state.javaCache.get(fqn);
        } else {
            code = dex
                ? generateJavaView(cls, dex.buf, dex.strings, dex.types, dex.methods, dex.fields || [])
                : generateJavaView(cls, null, [], [], [], []);
            state.javaCache.set(fqn, code);
        }
        highlighted = highlightJava(code);
    } else {
        code = dex
            ? generateSmaliView(cls, dex.buf, dex.strings, dex.types, dex.methods, dex.fields || [])
            : generateSmaliView(cls, null, [], [], [], []);
        highlighted = highlightSmali(code);
    }
    if (viewer) viewer.innerHTML = `<div class="cwl">${highlighted}</div>`;
}

function analyzeExportedComponents(manifest) {
    if (!manifest) return { activities: [], services: [], receivers: [], providers: [] };
    const app = findFirst(manifest, 'application');
    if (!app) return { activities: [], services: [], receivers: [], providers: [] };
    const result = { activities: [], services: [], receivers: [], providers: [] };

    const processComponent = (node, type) => {
        const a = node.attribs || {};
        const name = a.name || '';
        const filters = findAll(node, 'intent-filter');
        const intentFilters = filters.map(f => {
            const actions = findAll(f, 'action').map(x => x.attribs?.name || '');
            const categories = findAll(f, 'category').map(x => x.attribs?.name || '');
            const dataEls = findAll(f, 'data').map(x => ({
                scheme: x.attribs?.scheme, host: x.attribs?.host,
                port: x.attribs?.port, path: x.attribs?.path,
                pathPrefix: x.attribs?.pathPrefix, pathPattern: x.attribs?.pathPattern,
                mimeType: x.attribs?.mimeType
            }));
            return { actions, categories, data: dataEls };
        });

        let isExported = false;
        if (a.exported === true || a.exported === 'true') isExported = true;
        else if (a.exported === false || a.exported === 'false') isExported = false;
        else isExported = intentFilters.length > 0;

        const comp = {
            name, type, isExported,
            permission: a.permission || null,
            intentFilters,
            launchMode: a.launchMode || 'standard',
            taskAffinity: a.taskAffinity || null,
            authorities: a.authorities || null,
            grantUriPermissions: a.grantUriPermissions === true || a.grantUriPermissions === 'true',
            readPermission: a.readPermission || null,
            writePermission: a.writePermission || null
        };
        return comp;
    };

    for (const act of findAll(app, 'activity')) result.activities.push(processComponent(act, 'activity'));
    for (const act of findAll(app, 'activity-alias')) result.activities.push(processComponent(act, 'activity'));
    for (const svc of findAll(app, 'service')) result.services.push(processComponent(svc, 'service'));
    for (const rcv of findAll(app, 'receiver')) result.receivers.push(processComponent(rcv, 'receiver'));
    for (const prov of findAll(app, 'provider')) result.providers.push(processComponent(prov, 'provider'));
    return result;
}

function generateExploitCommands(comp, packageName) {
    const cmds = [];
    const fqn = comp.name.includes('.') ? comp.name : packageName + '.' + comp.name;
    const cn = `${packageName}/${fqn}`;

    if (comp.type === 'activity') {
        cmds.push({ desc: 'Launch activity', cmd: `adb shell am start -n ${cn}` });
        for (const f of comp.intentFilters) {
            for (const action of f.actions) {
                if (action === 'android.intent.action.MAIN') continue;
                let cmd = `adb shell am start -n ${cn} -a ${action}`;
                for (const cat of f.categories) cmd += ` -c ${cat}`;
                for (const d of f.data) {
                    if (d.scheme && d.host) {
                        const uri = `${d.scheme}://${d.host}${d.port ? ':' + d.port : ''}${d.path || d.pathPrefix || '/test'}`;
                        cmd += ` -d "${uri}"`;
                    } else if (d.scheme) {
                        cmd += ` -d "${d.scheme}://test"`;
                    }
                }
                cmds.push({ desc: `Action: ${action}`, cmd });
            }
        }
        if (comp.launchMode === 'singleTask') {
            cmds.push({ desc: 'Task hijacking test', cmd: `adb shell am start -n ${cn} --activity-clear-task` });
        }
    } else if (comp.type === 'service') {
        cmds.push({ desc: 'Start service', cmd: `adb shell am startservice -n ${cn}` });
        for (const f of comp.intentFilters) {
            for (const action of f.actions) {
                cmds.push({ desc: `Action: ${action}`, cmd: `adb shell am startservice -n ${cn} -a ${action}` });
            }
        }
    } else if (comp.type === 'receiver') {
        for (const f of comp.intentFilters) {
            for (const action of f.actions) {
                const isSystem = action.startsWith('android.');
                const cmd = isSystem
                    ? `adb shell am broadcast -a ${action}`
                    : `adb shell am broadcast -n ${cn} -a ${action}`;
                cmds.push({ desc: `Broadcast: ${action}`, cmd });
            }
        }
        if (cmds.length === 0) {
            cmds.push({ desc: 'Send broadcast', cmd: `adb shell am broadcast -n ${cn}` });
        }
    } else if (comp.type === 'provider') {
        if (comp.authorities) {
            const auth = comp.authorities.split(';')[0];
            cmds.push({ desc: 'Query provider', cmd: `adb shell content query --uri content://${auth}/` });
            cmds.push({ desc: 'SQL injection test', cmd: `adb shell content query --uri content://${auth}/ --where "1=1--"` });
            if (comp.grantUriPermissions) {
                cmds.push({ desc: 'Read via URI grant', cmd: `adb shell content read --uri content://${auth}/test` });
            }
        }
    }
    return cmds;
}

function renderInspectorTab(R) {
    try {
        const allComps = analyzeExportedComponents(R.manifest);
        state.inspectorData = allComps;
        const pkg = R.appInfo.packageName || '';

        const exported = {
            activities: allComps.activities.filter(c => c.isExported),
            services: allComps.services.filter(c => c.isExported),
            receivers: allComps.receivers.filter(c => c.isExported),
            providers: allComps.providers.filter(c => c.isExported)
        };
        const totalExported = exported.activities.length + exported.services.length + exported.receivers.length + exported.providers.length;
        const totalAll = allComps.activities.length + allComps.services.length + allComps.receivers.length + allComps.providers.length;
        const noPermExported = [...exported.activities, ...exported.services, ...exported.receivers, ...exported.providers].filter(c => !c.permission);

        document.getElementById('inspectorSummary').innerHTML = `
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px">
            <div class="stat-card" style="padding:10px"><div class="stat-card-value">${totalAll}</div><div class="stat-card-desc">Total components</div></div>
            <div class="stat-card" style="padding:10px"><div class="stat-card-value" style="color:var(--orange)">${totalExported}</div><div class="stat-card-desc">Exported</div></div>
            <div class="stat-card" style="padding:10px"><div class="stat-card-value" style="color:var(--red)">${noPermExported.length}</div><div class="stat-card-desc">No permission</div></div>
            <div class="stat-card" style="padding:10px">
                <div class="stat-card-desc" style="font-size:10px">${exported.activities.length} act · ${exported.services.length} svc · ${exported.receivers.length} rcv · ${exported.providers.length} prov</div>
            </div>
        </div>`;

        const allExported = [
            ...exported.activities.map(c => ({ ...c, _type: 'activity' })),
            ...exported.services.map(c => ({ ...c, _type: 'service' })),
            ...exported.receivers.map(c => ({ ...c, _type: 'receiver' })),
            ...exported.providers.map(c => ({ ...c, _type: 'provider' }))
        ];

        document.getElementById('inspectorList').innerHTML = allExported.map(c => {
            const cmds = generateExploitCommands(c, pkg);
            const simpleName = c.name.split('.').pop();
            const badges = [];
            if (!c.permission) badges.push('<span class="comp-badge danger">No Permission</span>');
            else badges.push(`<span class="comp-badge warn">Requires: ${esc(c.permission)}</span>`);
            if (c.type === 'activity' && c.launchMode !== 'standard') badges.push(`<span class="comp-badge">launchMode: ${esc(c.launchMode)}</span>`);
            if (c.type === 'provider' && c.grantUriPermissions) badges.push('<span class="comp-badge danger">grantUriPermissions</span>');
            if (c.type === 'provider' && c.authorities) badges.push(`<span class="comp-badge">auth: ${esc(c.authorities)}</span>`);

            const intents = c.intentFilters.flatMap(f => f.actions).filter(a => a !== 'android.intent.action.MAIN');
            const schemes = c.intentFilters.flatMap(f => f.data.map(d => d.scheme)).filter(Boolean);
            let intentHtml = '';
            if (intents.length) intentHtml += `<div class="comp-intents">Actions: ${intents.map(a => esc(a.replace('android.intent.action.', ''))).join(', ')}</div>`;
            if (schemes.length) intentHtml += `<div class="comp-intents">Schemes: ${[...new Set(schemes)].map(s => `<span class="comp-badge">${esc(s)}://</span>`).join(' ')}</div>`;

            const cmdsHtml = cmds.map(cmd =>
                `<div class="comp-cmd" onclick="navigator.clipboard.writeText(this.textContent.trim());showToast('Copied!','success')" title="Click to copy">${esc(cmd.cmd)}</div>`
            ).join('');

            return `<div class="comp-card" data-comp-type="${c.type}">
            <div class="comp-card-hdr">
                <span class="comp-type-badge ${c.type}">${c.type}</span>
                <span class="comp-name">${esc(simpleName)}</span>
            </div>
            <div style="font-size:11px;color:var(--text-muted);margin-bottom:4px;word-break:break-all">${esc(c.name)}</div>
            <div class="comp-badges">${badges.join('')}</div>
            ${intentHtml}
            ${cmds.length ? `<details><summary style="font-size:11px;color:var(--accent-primary);cursor:pointer;margin-top:4px">ADB Commands (${cmds.length})</summary>${cmdsHtml}</details>` : ''}
        </div>`;
        }).join('') || '<div class="no-data">No exported components found</div>';
    } catch (e) {

        const sumEl = document.getElementById('inspectorSummary');
        const listEl = document.getElementById('inspectorList');
        if (sumEl) sumEl.innerHTML = `<div class="no-data">Component analysis failed: ${esc(e.message)}</div>`;
        if (listEl) listEl.innerHTML = '';
    }
}

function filterInspector(type, btn) {
    if (btn) {
        btn.parentElement.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
    }
    document.querySelectorAll('#inspectorList .comp-card').forEach(c => {
        c.style.display = (type === 'all' || c.dataset.compType === type) ? '' : 'none';
    });
}

function renderExplorerTab(R) {
    document.getElementById('totalFileCount').textContent = R.files.length + ' files';
    buildFileTree(document.getElementById('fileTree'), R.fileTree);

    const javaTree = document.getElementById('javaSourceTree');
    const smaliTree = document.getElementById('smaliSourceTree');
    if (javaTree) { javaTree.innerHTML = ''; delete javaTree.dataset.built; }
    if (smaliTree) { smaliTree.innerHTML = ''; delete smaliTree.dataset.built; }
}

function buildFileTree(el, tree) {
    el.innerHTML = '';
    const dirs = Object.keys(tree).filter(k => tree[k]._type === 'dir').sort();
    const files = Object.keys(tree).filter(k => tree[k]._type === 'file').sort();
    for (const d of dirs) {
        const det = document.createElement('details');
        det.innerHTML = `<summary class="tree-dir"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:12px;height:12px"><path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2z"/></svg>${esc(d)}</summary>`;
        const inner = document.createElement('div'); inner.className = 'tree-children';
        buildFileTree(inner, tree[d]);
        det.appendChild(inner); el.appendChild(det);
    }
    for (const f of files) {
        const btn = document.createElement('div'); btn.className = 'tree-file';
        const ext = (f.split('.').pop() || '').toLowerCase();
        btn.innerHTML = `<span class="file-icon">${fileIcon(ext)}</span><span class="file-name">${esc(f)}</span><span class="file-size">${formatSize(tree[f]._size || 0)}</span>`;
        btn.onclick = () => openFile(tree[f]._path, f);
        el.appendChild(btn);
    }
}

function fileIcon(ext) {
    const M = { dex: '&#9638;', xml: '&#9671;', json: '&#9671;', so: '&#9881;', png: '&#9633;', jpg: '&#9633;', class: '&#9670;', jar: '&#9638;', db: '&#9707;', sqlite: '&#9707;', properties: '&#9881;', html: '&#9671;', js: '&#9671;', txt: '&#9671;', mf: '&#9671;' };
    return M[ext] || '&#9671;';
}

async function openFile(path) {
    const codeEl = document.getElementById('jadxCode');
    const nameEl = document.getElementById('jadxFileName');
    const pathEl = document.getElementById('jadxFilePath');
    const metaEl = document.getElementById('jadxFileMeta');
    const toggleEl = document.getElementById('jadxViewToggle');
    const jumpEl = document.getElementById('methodJump');

    const fileName = path.split('/').pop();
    if (nameEl) nameEl.textContent = fileName;
    if (pathEl) pathEl.textContent = path;
    if (metaEl) metaEl.textContent = '';
    if (toggleEl) toggleEl.style.display = 'none';
    if (jumpEl) jumpEl.style.display = 'none';

    const ext = (path.split('.').pop() || '').toLowerCase();

    const showContent = (text) => {
        if (['xml'].includes(ext)) {
            codeEl.innerHTML = `<div class="cwl">${highlightXML(text)}</div>`;
        } else if (['json', 'properties', 'yaml'].includes(ext)) {
            codeEl.innerHTML = `<pre class="file-text" style="padding:12px">${esc(text.slice(0, 50000))}</pre>`;
        } else {
            codeEl.innerHTML = `<pre class="file-text" style="padding:12px">${esc(text.slice(0, 50000))}</pre>`;
        }
        if (typeof _activeSearchQuery === 'string' && _activeSearchQuery.length > 0) setTimeout(() => applyCodeSearch(_activeSearchQuery), 50);
    };

    if (state.fileContents.has(path)) {
        showContent(state.fileContents.get(path));
        return;
    }
    const entry = state.zipContent?.file(path);
    if (!entry) { codeEl.innerHTML = `<div class="no-data">File not found in package</div>`; return; }
    codeEl.innerHTML = '<div class="no-data">Loading...</div>';
    try {
        if (['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp'].includes(ext)) {
            const data = await entry.async('arraybuffer');
            const url = URL.createObjectURL(new Blob([data], { type: 'image/' + ext }));
            codeEl.innerHTML = `<div style="padding:16px;text-align:center"><img src="${url}" style="max-width:100%;max-height:400px;border-radius:8px" onload="URL.revokeObjectURL(this.src)"></div>`;
            return;
        }
        if (ext === 'dex') {
            codeEl.innerHTML = `<div class="no-data">DEX binary -switch to <strong>Java</strong> or <strong>Smali</strong> view to browse classes</div>`;
            return;
        }
        if (ext === 'arsc') {
            const data = await entry.async('arraybuffer');
            const arscData = parseArsc(data);
            if (arscData && arscData.strings.length > 0) {
                const rendered = renderArsc(arscData);
                state.fileContents.set(path, rendered);
                showContent(rendered);
            } else {
                codeEl.innerHTML = `<pre class="file-hex" style="padding:12px">resources.arsc -Could not extract strings (${formatSize(data.byteLength)})\n\n${hexDump(new Uint8Array(data), 512)}</pre>`;
            }
            return;
        }
        if (ext === 'so') {
            const data = await entry.async('arraybuffer');
            codeEl.innerHTML = `<pre class="file-hex" style="padding:12px">${hexDump(new Uint8Array(data), 1024)}</pre>`;
            return;
        }
        if (ext === 'xml') {
            try {
                const data = await entry.async('arraybuffer');
                const bytes = new Uint8Array(data);
                const isAXML = bytes.length > 8 && bytes[0] === 0x03 && bytes[1] === 0x00;
                if (isAXML) {
                    try {
                        const parser = new AXMLParser(data);
                        const parsed = parser.parse();
                        if (parsed) {
                            const xmlStr = '<?xml version="1.0" encoding="utf-8"?>\n' + xmlToStr(parsed);
                            const badRatio = (xmlStr.match(/\uFFFD/g) || []).length / xmlStr.length;
                            if (badRatio < 0.05) {
                                state.fileContents.set(path, xmlStr);
                                showContent(xmlStr);
                                return;
                            }
                        }
                    } catch (parseErr) { }
                }
                const text = new TextDecoder('utf-8', { fatal: false }).decode(data);
                const badChars = (text.match(/[\x00-\x08\x0E-\x1F]/g) || []).length;
                if (badChars / Math.max(text.length, 1) < 0.1 && text.length > 0) {
                    state.fileContents.set(path, text);
                    showContent(text);
                } else {
                    codeEl.innerHTML = `<div style="padding:12px"><div class="no-data" style="margin-bottom:8px">Binary XML file (${formatSize(data.byteLength)}) -compiled Android resource</div><pre class="file-hex">${hexDump(bytes, 512)}</pre></div>`;
                }
                return;
            } catch (e) {
                codeEl.innerHTML = `<div class="no-data">Cannot read file: ${esc(e.message)}</div>`;
                return;
            }
        }
        const text = await entry.async('string');
        state.fileContents.set(path, text);
        showContent(text);
    } catch (e) { codeEl.innerHTML = `<div class="no-data">Cannot display file: ${esc(e.message)}</div>`; }
}

function hexDump(bytes, limit = 512) {
    let out = 'Offset    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  ASCII\n' + '─'.repeat(72) + '\n';
    for (let i = 0; i < Math.min(bytes.length, limit); i += 16) {
        const row = bytes.slice(i, i + 16);
        const hex = Array.from(row).map((b, j) => (j === 8 ? ' ' : '') + (b < 16 ? '0' : '') + b.toString(16).toUpperCase()).join(' ');
        const ascii = Array.from(row).map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join('');
        out += `${i.toString(16).padStart(8, '0')}  ${hex.padEnd(50)}  ${ascii}\n`;
    }
    if (bytes.length > limit) out += `\n... ${bytes.length - limit} more bytes`;
    return out;
}

function exportReport() {
    const R = state.analysisResults;
    if (!R) { showToast('No analysis results to export', 'error'); return; }
    try {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
        const W = 210, M = 15, maxW = W - 2 * M; let y = M;
        const newPg = () => { doc.addPage(); y = M; };
        const ln = (h = 5) => { y += h; if (y > 275) newPg(); };
        const row = (k, v) => { doc.setFontSize(9); doc.setTextColor(100, 100, 100); doc.text(k, M, y); doc.setTextColor(30, 30, 30); doc.text(String(v).slice(0, 90), M + 38, y); ln(5); };
        const heading = (s) => { ln(3); doc.setFontSize(11); doc.setTextColor(30, 30, 100); doc.text(s, M, y); ln(2); doc.setDrawColor(180, 180, 200); doc.line(M, y, W - M, y); ln(5); };
        doc.setFillColor(30, 30, 80); doc.rect(0, 0, W, 35, 'F');
        doc.setFontSize(18); doc.setTextColor(255, 255, 255); doc.text('APK Auditor - Security Report', M, 16);
        doc.setFontSize(9); doc.setTextColor(200, 200, 220); doc.text(R.appInfo.packageName || R.appInfo.fileName, M, 24);
        doc.setFontSize(8); doc.setTextColor(180, 180, 200); doc.text(new Date().toISOString().split('T')[0], M, 30);
        y = 42;

        const g = state.groupedFindings;

        heading('Application');
        row('Package', R.appInfo.packageName || R.appInfo.fileName);
        row('Size', R.appInfo.fileSize);
        row('Min SDK', R.minSdk ? 'API ' + R.minSdk + ' (Android ' + sdkToVer(R.minSdk) + ')' : '-');
        row('Target SDK', R.targetSdk ? 'API ' + R.targetSdk + ' (Android ' + sdkToVer(R.targetSdk) + ')' : '-');
        row('Permissions', R.permissions.length + ' (' + R.dangerousPerms.length + ' dangerous)');
        if (R.certInfo) row('Signing', (R.certInfo.sigAlg || '?') + (R.certInfo.isDebug ? ' [DEBUG]' : ''));
        row('Issues Found', g.issue.length);

        doc.setFontSize(8); doc.setTextColor(120, 120, 120);
        doc.splitTextToSize('Note: All findings are from automated static analysis and require manual verification. False positives may occur. Each issue should be validated in context before reporting.', maxW).forEach(l => { doc.text(l, M, y); ln(4); });
        ln(4);

        if (g.issue.length) {
            heading('Issues (' + g.issue.length + ')');
            for (const f of g.issue) {
                if (y > 260) newPg();
                const cnt = f.count > 1 ? ' [' + f.count + 'x]' : '';
                doc.setFontSize(10); doc.setTextColor(50, 50, 50);
                doc.text(f.ruleName + cnt, M, y); ln(5);
                doc.setFontSize(8); doc.setTextColor(80, 80, 80);
                doc.splitTextToSize(f.description.slice(0, 250), maxW - 4).forEach(l => { doc.text(l, M + 2, y); ln(4); });
                if (f.matches && f.matches.length) {
                    doc.setFontSize(7); doc.setTextColor(100, 70, 30);
                    for (const m of f.matches) {
                        if (y > 272) newPg();
                        const loc = (m.file || '') + (m.line ? ':' + m.line : '');
                        doc.text('  ' + (m.match || '').slice(0, 85) + (loc ? '  [' + loc + ']' : ''), M + 2, y);
                        ln(3.5);
                    }
                }
                if (f.cwe) { doc.setFontSize(7); doc.setTextColor(140, 140, 140); doc.text(f.cwe, M + 2, y); ln(3); }
                ln(2);
            }
        }

        const exported = [...R.components.activities, ...R.components.services, ...R.components.receivers, ...R.components.providers].filter(c => c.exported === true || c.exported === 'true');
        if (exported.length) {
            heading('Exported Components (' + exported.length + ')');
            doc.setFontSize(8); doc.setTextColor(60, 60, 60);
            for (const c of exported.slice(0, 30)) { if (y > 272) newPg(); doc.text((c.name || '?') + (c.permission ? '' : ' [no perm]'), M + 2, y); ln(4); }
        }

        if (R.trackers.length) {
            heading('SDKs & Trackers');
            doc.setFontSize(8); doc.setTextColor(60, 60, 60);
            doc.text(R.trackers.join(', '), M, y, { maxWidth: maxW }); ln(8);
        }

        if (R.dangerousPerms.length) {
            heading('Dangerous Permissions');
            doc.setFontSize(8); doc.setTextColor(60, 60, 60);
            doc.text(R.dangerousPerms.join(', '), M, y, { maxWidth: maxW }); ln(8);
        }

        if (y > 250) newPg();
        ln(6);
        doc.setDrawColor(180, 180, 200); doc.line(M, y, W - M, y); ln(5);
        doc.setFontSize(8); doc.setTextColor(130, 130, 130);
        doc.splitTextToSize('Disclaimer: This report is generated by automated static analysis. All findings are potential issues identified through pattern matching on decompiled code and manifest data. Results may include false positives and do not confirm exploitability. Manual verification and dynamic testing are required before including any finding in a security assessment.', maxW).forEach(l => { doc.text(l, M, y); ln(4); });

        doc.save('apk-report-' + (R.appInfo.packageName || 'unknown').replace(/\./g, '-') + '.pdf');
        showToast('Report exported!', 'success');
    } catch (e) { showToast('Export failed: ' + e.message, 'error'); }
}

function showLoading(msg = 'Analyzing...') { document.getElementById('loadingOverlay').classList.add('active'); document.getElementById('loadingText').textContent = msg; }
function hideLoading() { document.getElementById('loadingOverlay').classList.remove('active'); }
function updateProgress(pct, msg) { document.getElementById('progressFill').style.width = pct + '%'; if (msg) document.getElementById('progressText').textContent = msg; }
function showToast(msg, type = 'info') {
    const c = document.getElementById('toastContainer');
    const t = document.createElement('div'); t.className = 'toast ' + type;
    const icon = type === 'success'
        ? '<svg viewBox="0 0 24 24" fill="none" stroke="#34d399" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>'
        : '<svg viewBox="0 0 24 24" fill="none" stroke="#fb7185" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';
    t.innerHTML = icon + msg; c.appendChild(t); setTimeout(() => t.remove(), 4000);
}

async function startAnalysis(file) {
    try {
        const results = await analyzeAPK(file);
        hideLoading();
        document.getElementById('landingContent').style.display = 'none';
        document.querySelector('.privacy-section').style.display = 'none';
        document.getElementById('appContainer').classList.add('active');
        const pkg = results.appInfo.packageName || results.appInfo.fileName.replace('.apk', '');
        document.getElementById('appName').textContent = pkg.split('.').pop() || pkg;
        document.getElementById('appPackage').textContent = pkg;
        const tot = state.groupedFindings.issue.length;
        document.getElementById('findingsCount').textContent = tot;
        renderOverviewTab(results);
        renderManifestTab(results);
        renderFindingsTab();
        renderSmaliTab(results);
        renderExplorerTab(results);
        renderInspectorTab(results);
        showToast('Analysis complete!', 'success');
    } catch (e) {

        hideLoading();
        showToast('Analysis failed: ' + e.message, 'error');
    }
}

function filterFileTree(ext) { if (!ext) { document.querySelectorAll('.tree-file').forEach(f => f.style.display = ''); return; } const exts = ext.split(','); document.querySelectorAll('.tree-file').forEach(f => { const e = (f.querySelector('.file-name')?.textContent || '').split('.').pop().toLowerCase(); f.style.display = exts.includes(e) ? '' : 'none'; }); }
function expandAllFolders() { document.querySelectorAll('#panel-explorer details').forEach(d => d.open = true); }
function collapseAllFolders() { document.querySelectorAll('#panel-explorer details').forEach(d => d.open = false); }

function downloadCurrentFile() {
    let p = document.getElementById('currentFilePath')?.textContent || '';
    if (!p || p === 'Select a file to view its contents') p = document.getElementById('jadxFilePath')?.textContent || '';
    if (!p) return;
    if (state.currentViewClass && (state.explorerView === 'java' || state.explorerView === 'smali')) {
        const code = document.getElementById('jadxCode')?.innerText || '';
        const blob = new Blob([code], { type: 'text/plain' });
        const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
        a.download = p.split('.').pop() === p ? p + '.java' : p.split('/').pop();
        a.click(); return;
    }
    const e = state.zipContent?.file(p);
    if (!e) { showToast('File not found in APK', 'error'); return; }
    e.async('blob').then(b => { const a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = p.split('/').pop(); a.click(); });
}
function navigateToFile(file, line) {
    if (!file) return;
    function switchTab(tabName) {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
        const tabBtn = document.querySelector('.tab[data-tab="' + tabName + '"]');
        const panel = document.getElementById('panel-' + tabName);
        if (tabBtn) tabBtn.classList.add('active');
        if (panel) panel.classList.add('active');
    }
    function highlightLine(container, ln) {
        if (!ln) return;
        setTimeout(() => {
            const lines = document.querySelectorAll(container + ' .cl');
            const n = parseInt(ln);
            if (lines[n - 1]) {
                lines[n - 1].scrollIntoView({ behavior: 'smooth', block: 'center' });
                lines[n - 1].style.background = 'rgba(251,146,60,.25)';
                setTimeout(() => { lines[n - 1].style.background = ''; }, 3000);
            }
        }, 200);
    }
    if (file === 'AndroidManifest.xml') {
        switchTab('manifest');
        highlightLine('#manifestViewer', line);
        return;
    }
    if (file.endsWith('.java')) {
        switchTab('explorer');
        var fqn = file.replace(/\.java$/, '');
        var javaTabs = document.querySelectorAll('.explorer-view-tabs .stab');
        if (javaTabs[1]) switchExplorerView('java', javaTabs[1]);
        state.currentViewMode = 'java';
        if (state.javaCache.has(fqn)) {
            var nameEl = document.getElementById('jadxFileName');
            var pathEl = document.getElementById('jadxFilePath');
            var metaEl = document.getElementById('jadxFileMeta');
            var codeEl = document.getElementById('jadxCode');
            var toggleEl = document.getElementById('jadxViewToggle');
            if (nameEl) nameEl.textContent = fqn.split('.').pop() + '.java';
            if (pathEl) pathEl.textContent = fqn;
            if (metaEl) metaEl.textContent = '';
            if (toggleEl) toggleEl.style.display = 'none';
            if (codeEl) codeEl.innerHTML = '<div class="cwl">' + highlightJava(state.javaCache.get(fqn)) + '</div>';
            highlightLine('#jadxCode', line);
        } else {
            for (var di = 0; di < state.dexParsed.length; di++) {
                var dex = state.dexParsed[di];
                var cls = (dex.classes || []).find(c => (c.name || '').replace(/^L/, '').replace(/;$/, '').replace(/\//g, '.') === fqn);
                if (cls) {
                    showSmaliClass(cls, fqn, di);
                    highlightLine('#jadxCode', line);
                    break;
                }
            }
        }
        return;
    }
    switchTab('explorer');
    var apkTab = document.querySelector('.explorer-view-tabs .stab');
    if (apkTab) switchExplorerView('apk', apkTab);
}


// --- Remote Analysis Integration ---
function openRemoteModal() {
    document.getElementById('remoteModal').style.display = 'flex';
}
function closeRemoteModal() {
    document.getElementById('remoteModal').style.display = 'none';
}

async function startRemoteAnalysis() {
    const pkgId = document.getElementById('remotePkgId').value.trim();
    const mitm = document.getElementById('remoteMitm').checked;
    if (!pkgId) { showToast('Please enter a Package ID', 'error'); return; }

    document.getElementById('remoteModal').style.display = 'none';
    showLoading('Starting Remote Scan...');

    const token = localStorage.getItem('autoar_local_token');
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;

    try {
        // 1. Launch
        const startResp = await fetch('/scan/apkx', { method: 'POST', headers, body: JSON.stringify({ package_id: pkgId, mitm }) });
        const startData = await startResp.json();
        if (!startResp.ok || !startData.scan_id) throw new Error(startData.error || 'Failed to start scan');
        const scanId = startData.scan_id;

        // 2. Poll
        let status = 'running', attempts = 0;
        while (status === 'running' || status === 'pending') {
            await new Promise(r => setTimeout(r, 2000));
            if (++attempts > 300) throw new Error('Scan timed out after 10 minutes');
            const sd = await (await fetch('/api/scans/' + scanId, { headers })).json();
            status = (sd.scan?.status || 'running').toLowerCase();
            showLoading(`Processing ${pkgId}... (${attempts * 2}s)`);
            if (status === 'failed' || status === 'error') throw new Error('Scan failed on server');
        }

        // 3. Fetch results
        showLoading('Fetching download links...');
        const resData = await (await fetch(`/api/scans/${scanId}/results/summary`, { headers })).json();
        const files = resData.files || [];

        const mitmFile = files.find(f => f.file_name && f.file_name.includes('-mitm.apk'));
        const baseFile = files.find(f => f.file_name && f.file_name.endsWith('.apk') && !f.file_name.includes('-mitm'));
        const primaryFile = mitmFile || baseFile;

        hideLoading();
        if (!primaryFile) { showToast('Scan done but no APK artifact found. Check server logs.', 'warning'); return; }

        const mitmUrl = mitmFile ? (mitmFile.public_url || `/api/scans/${scanId}/results/download?file=${encodeURIComponent(mitmFile.file_name)}`) : null;
        const baseUrl = baseFile ? (baseFile.public_url || `/api/scans/${scanId}/results/download?file=${encodeURIComponent(baseFile.file_name)}`) : null;

        // 4. Show download panel on page
        _showApkPanel(pkgId, mitmFile, baseFile, mitmUrl, baseUrl, scanId);

        // 5. Auto-load into Auditor
        const loadUrl = mitmUrl || baseUrl;
        showLoading('Loading APK into Auditor...');
        try {
            const dlResp = await fetch(loadUrl, { headers });
            if (dlResp.ok) {
                const blob = await dlResp.blob();
                startAnalysis(new File([blob], primaryFile.file_name, { type: 'application/vnd.android.package-archive' }));
                showToast('APK loaded into Auditor!', 'success');
            }
        } catch (_) { showToast('Links ready above — could not auto-load.', 'warning'); }
        hideLoading();

    } catch (e) {
        hideLoading();
        showToast('Remote analysis failed: ' + e.message, 'error');
    }
}

function _showApkPanel(pkgId, mitmFile, baseFile, mitmUrl, baseUrl, scanId) {
    const old = document.getElementById('apkDownloadPanel');
    if (old) old.remove();

    function row(label, color, inputId, url) {
        if (!url) return '';
        return `<div style="margin-bottom:12px">
            <div style="font-size:11px;color:${color};font-weight:700;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">${label}</div>
            <div style="display:flex;gap:8px;align-items:center">
                <input id="${inputId}" type="text" readonly value="${url}" style="flex:1;background:#161b22;border:1px solid #30363d;color:#e6edf3;padding:8px 12px;border-radius:8px;font-size:11px;font-family:monospace;min-width:0">
                <button onclick="window._copyApkLink('${inputId}')" style="background:#30363d;color:#e6edf3;border:none;padding:8px 14px;border-radius:8px;font-weight:700;cursor:pointer;white-space:nowrap;font-size:12px">Copy</button>
                <a href="${url}" download style="background:#1f6feb;color:#fff;border:none;padding:8px 14px;border-radius:8px;font-weight:700;text-decoration:none;white-space:nowrap;font-size:12px">⬇ Download</a>
            </div>
        </div>`;
    }

    const p = document.createElement('div');
    p.id = 'apkDownloadPanel';
    p.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);z-index:9999;width:560px;max-width:calc(100vw - 32px);background:#0d1117;border:1.5px solid #00ff41;border-radius:16px;padding:20px 24px;box-shadow:0 0 40px rgba(0,255,65,0.25),0 8px 32px rgba(0,0,0,0.8);font-family:inherit;animation:slideUp 0.3s ease';
    p.innerHTML = `
        <style>@keyframes slideUp{from{opacity:0;transform:translateX(-50%) translateY(20px)}to{opacity:1;transform:translateX(-50%) translateY(0)}}</style>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
            <div><span style="color:#00ff41;font-weight:700;font-size:14px">✓ Scan Complete</span><span style="color:#8b949e;font-size:12px;margin-left:8px">${pkgId}</span></div>
            <button onclick="document.getElementById('apkDownloadPanel').remove()" style="background:none;border:none;color:#8b949e;cursor:pointer;font-size:20px;line-height:1;padding:2px 6px">✕</button>
        </div>
        ${row('🔒 MITM Patched APK', '#00ff41', 'mitmLinkInput', mitmUrl)}
        ${row('📦 Original APK', '#8b949e', 'baseLinkInput', baseUrl)}
        <div style="margin-top:10px;font-size:10px;color:#484f58;text-align:center">Scan ID: ${scanId}</div>
    `;
    document.body.appendChild(p);

    window._copyApkLink = (id) => {
        const el = document.getElementById(id);
        if (!el) return;
        el.select();
        navigator.clipboard.writeText(el.value)
            .then(() => showToast('Link copied!', 'success'))
            .catch(() => { document.execCommand('copy'); showToast('Link copied!', 'success'); });
    };
}


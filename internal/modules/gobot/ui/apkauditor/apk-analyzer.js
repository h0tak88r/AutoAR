/** @preserve @author Sandeep Wawdane @license MIT */
'use strict';

const apkState = {
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
    regexMode: false
};

const esc = s => { if (!s && s !== 0) return ''; return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); };
const formatSize = b => b < 1024 ? b + ' B' : b < 1048576 ? (b/1024).toFixed(1) + ' KB' : (b/1048576).toFixed(2) + ' MB';
const sleep = ms => new Promise(r => setTimeout(r, ms));
const yield_ = () => sleep(0);

async function sha256hex(buf) {
    const h = await crypto.subtle.digest('SHA-256', buf);
    return Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2,'0')).join('');
}
async function md5hex(buf) {
    const b = new Uint8Array(buf);
    let a0=0x67452301,b0=0xefcdab89,c0=0x98badcfe,d0=0x10325476;
    const s=[7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
    const K=[0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391];
    const len=b.length,bitLen=len*8;
    const padLen=len+1+((56-(len+1)%64+64)%64)+8;
    const pad=new Uint8Array(padLen);
    pad.set(b);pad[len]=0x80;
    const dv=new DataView(pad.buffer);
    dv.setUint32(padLen-8,bitLen>>>0,true);dv.setUint32(padLen-4,Math.floor(bitLen/0x100000000),true);
    for(let i=0;i<padLen;i+=64){
        const M=[];for(let j=0;j<16;j++)M[j]=dv.getUint32(i+j*4,true);
        let A=a0,B=b0,C=c0,D=d0;
        for(let j=0;j<64;j++){
            let F,g;
            if(j<16){F=(B&C)|((~B)&D);g=j;}
            else if(j<32){F=(D&B)|((~D)&C);g=(5*j+1)%16;}
            else if(j<48){F=B^C^D;g=(3*j+5)%16;}
            else{F=C^(B|(~D));g=(7*j)%16;}
            F=(F+A+K[j]+M[g])>>>0;A=D;D=C;C=B;B=(B+((F<<s[j])|(F>>>(32-s[j]))))>>>0;
        }
        a0=(a0+A)>>>0;b0=(b0+B)>>>0;c0=(c0+C)>>>0;d0=(d0+D)>>>0;
    }
    const hex=v=>[v&0xff,(v>>8)&0xff,(v>>16)&0xff,(v>>24)&0xff].map(x=>x.toString(16).padStart(2,'0')).join('');
    return hex(a0)+hex(b0)+hex(c0)+hex(d0);
}
function sdkToVer(s) {
    const M = {14:'4.0',15:'4.0.3',16:'4.1',17:'4.2',18:'4.3',19:'4.4',21:'5.0',22:'5.1',23:'6.0',24:'7.0',25:'7.1',26:'8.0',27:'8.1',28:'9',29:'10',30:'11',31:'12',32:'12L',33:'13',34:'14',35:'15'};
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
            } catch(e) { this.strings.push(''); }
        }
    }
    parseStartNs(off) { }
    parseStartElem(off) {
        if (off + 36 > this.b.length) return;
        const nameIdx  = this.u32(off + 20);
        const attrStart = this.u16(off + 24);
        const attrSize = Math.max(this.u16(off + 26), 20);
        const attrCnt  = this.u16(off + 28);
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
                default:   val = (rs !== 0xFFFFFFFF && rs < this.strings.length) ? (this.strings[rs] ?? dv) : dv;
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
        } catch(e) { }
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
            } catch(e) { strings.push(''); }
        }

        const allStrings = strings.filter(s => s.length > 0 && s.length < 1000);
        return { strings: allStrings, allStrings };
    } catch(e) { return null; }
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
                strSize: this.u32(56),  strOff: this.u32(60),
                typSize: this.u32(64),  typOff: this.u32(68),
                protoSize: this.u32(72), protoOff: this.u32(76),
                fldSize: this.u32(80),  fldOff: this.u32(84),
                mthSize: this.u32(88),  mthOff: this.u32(92),
                clsSize: this.u32(96),  clsOff: this.u32(100)
            };
            if (H.strSize > 2000000 || H.typSize > 1000000 || H.mthSize > 1000000 || H.clsSize > 500000) return null;
            const strings = this._strings(H);
            const types   = this._types(H, strings);
            const protos  = this._protos(H, strings, types);
            const fields  = this._fields(H, strings, types);
            const methods = this._methods(H, strings, types, protos);
            const classes = this._classes(H, strings, types, methods, fields);
            return { strings, types, fields, methods, classes };
        } catch(e) { return null; }
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
                cls:  ci < types.length ? types[ci] : '',
                type: ti < types.length ? types[ti] : '',
                name: ni < strs.length  ? strs[ni]  : ''
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
                cls:        ci < types.length ? types[ci] : '',
                name:       ni < strs.length  ? strs[ni]  : '',
                returnType: proto ? proto.ret    : 'V',
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
                name:      ci < types.length ? types[ci] : '',
                superName: si !== 0xFFFFFFFF && si < types.length ? types[si] : '',
                srcFile:   src !== 0xFFFFFFFF && src < strs.length ? strs[src] : '',
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
                    cls.fields  = cd.fields;
                } catch(e) {}
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
            '2.5.4.3':'CN','2.5.4.6':'C','2.5.4.7':'L','2.5.4.8':'ST','2.5.4.10':'O','2.5.4.11':'OU',
            '1.2.840.113549.1.1.4':'MD5withRSA','1.2.840.113549.1.1.5':'SHA1withRSA',
            '1.2.840.113549.1.1.11':'SHA256withRSA','1.2.840.113549.1.1.12':'SHA384withRSA',
            '1.2.840.10045.4.3.2':'SHA256withECDSA','1.2.840.10045.4.3.3':'SHA384withECDSA'
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
            try { out[k] = new TextDecoder('utf-8', { fatal: false }).decode(vt.d); } catch(e) {}
        }
        return out;
    }
    parseTime(tag, d) {
        try {
            const s = new TextDecoder().decode(d);
            if (tag === 0x17) { const yr = parseInt(s.slice(0, 2)); return `${yr >= 50 ? '19' : '20'}${s.slice(0,2)}-${s.slice(2,4)}-${s.slice(4,6)}`; }
            return `${s.slice(0,4)}-${s.slice(4,6)}-${s.slice(6,8)}`;
        } catch(e) { return '?'; }
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
        } catch(e) { return null; }
    }
    _x509direct() { this.p = 0; try { const s = this.tlv(); return s && s.tag === 0x30 ? this._x509(s.d) : null; } catch(e) { return null; } }
    _x509(d) {
        try {
            const tp = new CertParser(d), tbs = tp.tlv(); if (!tbs || tbs.tag !== 0x30) return null;
            const sa = tp.tlv();
            const res = { subject: {}, issuer: {}, validity: {}, sigAlg: '', serial: '', isDebug: false, isExpired: false };
            if (sa && sa.tag === 0x30) { const ap = new CertParser(sa.d), ot = ap.tlv(); if (ot && ot.tag === 0x06) res.sigAlg = this.oid(ot.d); }
            const ip = new CertParser(tbs.d); let cur = ip.tlv();
            if (cur && (cur.tag & 0xE0) === 0xA0) cur = ip.tlv();
            res.serial = Array.from(cur?.d || []).slice(0, 20).map(b => b.toString(16).padStart(2,'0')).join(':');
            ip.tlv();
            const iss = ip.tlv(); if (iss) res.issuer = this.parseName(iss.d);
            const val = ip.tlv();
            if (val) { const vp = new CertParser(val.d), nb = vp.tlv(), na = vp.tlv(); if (nb) res.validity.notBefore = this.parseTime(nb.tag, nb.d); if (na) res.validity.notAfter = this.parseTime(na.tag, na.d); }
            const sub = ip.tlv(); if (sub) res.subject = this.parseName(sub.d);
            const cn = res.subject.CN || '', org = res.subject.O || '';
            res.isDebug = cn.includes('Android Debug') || org === 'Android' || cn === 'Unknown';
            if (res.validity.notAfter) res.isExpired = new Date(res.validity.notAfter) < new Date();
            return res;
        } catch(e) { return null; }
    }
}

const ANDROID_RULES = [
    {id:'world_readable',name:'SharedPreferences World Readable',severity:'issue',
     patterns:[/MODE_WORLD_READABLE/g,/openFileOutput\([^,]{1,80},\s*1\)/g],
     description:'World-readable files can be read by any installed app on the device.',cwe:'CWE-276',owasp:'M2',masvs:'STORAGE-2'},
    {id:'world_writable',name:'SharedPreferences World Writable',severity:'issue',
     patterns:[/MODE_WORLD_WRITEABLE/g,/openFileOutput\([^,]{1,80},\s*2\)/g],
     description:'World-writable files can be modified by any installed app on the device.',cwe:'CWE-276',owasp:'M2',masvs:'STORAGE-2'},
    {id:'external_storage',name:'External Storage Write',severity:'issue',
     patterns:[/getExternalStorageDirectory/g,/getExternalFilesDir/g,/Environment\.getExternal/g],
     description:'External storage is world-readable. Never write sensitive data to external storage.',cwe:'CWE-312',owasp:'M2',masvs:'STORAGE-2'},
    {id:'sqlite_raw',name:'SQLite Raw Query',severity:'issue',
     patterns:[/rawQuery\s*\(/g,/execSQL\s*\(/g],
     description:'Raw SQL queries without parameterization are vulnerable to injection attacks.',cwe:'CWE-89',owasp:'M7',masvs:'PLATFORM-2'},
    {id:'sqlite_plain',name:'SQLite Unencrypted Database',severity:'issue',
     patterns:[/SQLiteOpenHelper/g,/SQLiteDatabase/g,/openOrCreateDatabase/g],
     description:'SQLite databases are stored unencrypted. Use encrypted storage for sensitive data.',cwe:'CWE-312',owasp:'M2',masvs:'STORAGE-14'},
    {id:'sqlcipher',name:'SQLCipher Encrypted Database',severity:'secure',
     patterns:[/SQLCipher/g,/net\.sqlcipher/g],
     description:'SQLCipher is used for encrypted SQLite storage -a good security practice.',cwe:'',owasp:'',masvs:'STORAGE-14'},
    {id:'weak_md5',name:'Weak Hash Algorithm (MD5)',severity:'issue',
     patterns:[/MessageDigest\.getInstance\(["']MD5["']/gi,/DigestUtils\.md5/gi,/"MD5"/g],
     description:'MD5 is cryptographically broken. Collisions can be generated trivially. Use SHA-256.',cwe:'CWE-327',owasp:'M5',masvs:'CRYPTO-4'},
    {id:'weak_sha1',name:'Weak Hash Algorithm (SHA-1)',severity:'issue',
     patterns:[/MessageDigest\.getInstance\(["']SHA-?1["']/gi,/DigestUtils\.sha1/gi],
     description:'SHA-1 is deprecated due to practical collision attacks. Migrate to SHA-256.',cwe:'CWE-327',owasp:'M5',masvs:'CRYPTO-4'},
    {id:'weak_des',name:'Weak Cipher (DES/3DES)',severity:'issue',
     patterns:[/Cipher\.getInstance\(["']DES/gi,/DESKeySpec/g,/"DESede"/g],
     description:'DES and Triple-DES are obsolete. Use AES-256-GCM for symmetric encryption.',cwe:'CWE-327',owasp:'M5',masvs:'CRYPTO-3'},
    {id:'ecb_mode',name:'ECB Mode Encryption',severity:'issue',
     patterns:[/\/ECB\//g,/AES\/ECB/g,/Cipher\.getInstance\(["']AES["']\)/gi],
     description:'ECB mode reveals patterns in encrypted data. Use AES/GCM/NoPadding instead.',cwe:'CWE-327',owasp:'M5',masvs:'CRYPTO-3'},
    {id:'insecure_random',name:'Insecure Random Generator',severity:'issue',
     patterns:[/new\s+Random\s*\(/g,/java\.util\.Random/g,/Math\.random\s*\(/g],
     description:'java.util.Random is predictable. Use java.security.SecureRandom for cryptographic operations.',cwe:'CWE-330',owasp:'M5',masvs:'CRYPTO-6'},
    {id:'null_cipher',name:'NullCipher Usage',severity:'issue',
     patterns:[/NullCipher/g],
     description:'NullCipher performs no actual encryption. Data is stored/transmitted in plaintext.',cwe:'CWE-327',owasp:'M5',masvs:'CRYPTO-3'},
    {id:'hardcoded_iv',name:'Hardcoded Initialization Vector',severity:'issue',
     patterns:[/IvParameterSpec\s*\(\s*new\s+byte\s*\[\s*\]\s*\{/g,/new\s+IvParameterSpec\s*\(["']/g],
     description:'A static IV makes encryption deterministic and compromises ciphertext confidentiality.',cwe:'CWE-329',owasp:'M5',masvs:'CRYPTO-3'},
    {id:'hardcoded_key',name:'Hardcoded Encryption Key',severity:'issue',
     patterns:[/SecretKeySpec\s*\(\s*["'][^"']{1,100}["']/g],
     description:'Hardcoded keys can be extracted by anyone who reverse-engineers the APK.',cwe:'CWE-321',owasp:'M5',masvs:'CRYPTO-1'},
    {id:'http_url',name:'Insecure HTTP URL',severity:'issue',
     patterns:[/http:\/\/(?!localhost|127\.|10\.|192\.168)[a-zA-Z][a-zA-Z0-9._-]{3,}/g],
     description:'Cleartext HTTP traffic can be intercepted. All endpoints should use HTTPS.',cwe:'CWE-319',owasp:'M3',masvs:'NETWORK-1'},
    {id:'ssl_disabled',name:'SSL Validation Disabled',severity:'issue',
     patterns:[/ALLOW_ALL_HOSTNAME_VERIFIER/g,/getInsecure\s*\(/g,/TrustAllX509/gi,/setHostnameVerifier\s*\(\s*ALLOW_ALL/g],
     description:'Disabling SSL validation allows attackers to intercept encrypted connections.',cwe:'CWE-295',owasp:'M3',masvs:'NETWORK-4'},
    {id:'trust_all',name:'Trust All SSL Certificates',severity:'issue',
     patterns:[/checkServerTrusted/g,/X509TrustManager/g,/TrustAllCerts/g],
     description:'Accepting all certificates makes the app vulnerable to man-in-the-middle attacks.',cwe:'CWE-295',owasp:'M3',masvs:'NETWORK-4'},
    {id:'cert_pinning',name:'Certificate Pinning Implemented',severity:'secure',
     patterns:[/CertificatePinner/g,/pin-sha256/gi,/PublicKeyPinning/g],
     description:'Certificate pinning is in place to prevent certificate substitution attacks.',cwe:'',owasp:'',masvs:'NETWORK-4'},
    {id:'ssl_error_override',name:'WebView SSL Error Override',severity:'issue',
     patterns:[/onReceivedSslError/g],
     description:'Overriding onReceivedSslError without rejection allows connections with invalid certificates.',cwe:'CWE-295',owasp:'M3',masvs:'NETWORK-4'},
    {id:'webview_js',name:'WebView JavaScript Enabled',severity:'issue',
     patterns:[/setJavaScriptEnabled\s*\(\s*true/g,/javaScriptEnabled\s*=\s*true/g],
     description:'Enabling JavaScript in WebView is a prerequisite for cross-site scripting attacks.',cwe:'CWE-79',owasp:'M7',masvs:'PLATFORM-6'},
    {id:'webview_addjs',name:'WebView addJavascriptInterface',severity:'issue',
     patterns:[/addJavascriptInterface\s*\(/g,/@JavascriptInterface/g],
     description:'Exposes Java methods to JavaScript -enables remote code execution on Android < 4.2.',cwe:'CWE-749',owasp:'M7',masvs:'PLATFORM-6'},
    {id:'webview_file',name:'WebView File Access Enabled',severity:'issue',
     patterns:[/setAllowFileAccess\s*\(\s*true/g,/setAllowFileAccessFromFileURLs\s*\(\s*true/g,/setAllowUniversalAccessFromFileURLs\s*\(\s*true/g],
     description:'WebView file access allows malicious scripts to read arbitrary files via file:// URIs.',cwe:'CWE-200',owasp:'M7',masvs:'PLATFORM-6'},
    {id:'webview_savepass',name:'WebView Password Saving',severity:'issue',
     patterns:[/setSavePassword\s*\(\s*true/g],
     description:'Saved WebView passwords can be recovered from device storage.',cwe:'CWE-256',owasp:'M2',masvs:'STORAGE-14'},
    {id:'runtime_exec',name:'Runtime Command Execution',severity:'issue',
     patterns:[/Runtime\.getRuntime\(\)\.exec\s*\(/g,/ProcessBuilder\s*\(/g],
     description:'Dynamic process execution with user-controlled input enables OS command injection.',cwe:'CWE-78',owasp:'M7',masvs:'CODE-6'},
    {id:'implicit_intent',name:'Implicit Intent',severity:'issue',
     patterns:[/new\s+Intent\s*\(\s*["']android\./g,/sendBroadcast\s*\(\s*new\s+Intent/g],
     description:'Implicit intents can be intercepted or redirected by other installed applications.',cwe:'CWE-925',owasp:'M1',masvs:'PLATFORM-1'},
    {id:'sticky_broadcast',name:'Sticky Broadcast',severity:'issue',
     patterns:[/sendStickyBroadcast/g,/sendStickyOrderedBroadcast/g],
     description:'Sticky broadcasts are deprecated (API 21) and accessible to any app.',cwe:'CWE-200',owasp:'M1',masvs:'PLATFORM-2'},
    {id:'pending_mutable',name:'Mutable PendingIntent',severity:'issue',
     patterns:[/FLAG_MUTABLE/g],
     description:'Mutable PendingIntents can be hijacked. Use FLAG_IMMUTABLE on Android 12+.',cwe:'CWE-927',owasp:'M1',masvs:'PLATFORM-1'},
    {id:'hardcoded_pw',name:'Hardcoded Password/Secret',severity:'issue',
     patterns:[/password\s*=\s*["'][^"'\n]{3,80}["']/gi,/secret\s*=\s*["'][^"'\n]{4,80}["']/gi,/api[_-]?key\s*=\s*["'][^"'\n]{8,80}["']/gi],
     description:'Hardcoded credentials embedded in APKs are trivially recoverable via static analysis.',cwe:'CWE-798',owasp:'M9',masvs:'STORAGE-14'},
    {id:'hardcoded_token',name:'Hardcoded Token/Bearer',severity:'issue',
     patterns:[/Bearer\s+[A-Za-z0-9\-_]{20,}/g,/authorization\s*[:=]\s*["'][^"'\n]{20,80}["']/gi],
     description:'Authentication tokens must be fetched dynamically, not embedded in the binary.',cwe:'CWE-798',owasp:'M9',masvs:'STORAGE-14'},
    {id:'aws_key',name:'AWS Credentials Exposed',severity:'issue',
     patterns:[/AKIA[0-9A-Z]{16}/g],
     description:'AWS access key found. Rotate credentials immediately in AWS IAM console.',cwe:'CWE-798',owasp:'M9',masvs:'STORAGE-14'},
    {id:'google_key',name:'Google API Key Exposed',severity:'issue',
     patterns:[/AIza[0-9A-Za-z\-_]{35}/g],
     description:'Google API key embedded in the APK. Restrict key scope in Google Cloud Console.',cwe:'CWE-798',owasp:'M9',masvs:'STORAGE-14'},
    {id:'firebase_url',name:'Firebase Database URL',severity:'issue',
     patterns:[/[a-zA-Z0-9\-]+\.firebaseio\.com/gi,/[a-zA-Z0-9\-]+\.firebasedatabase\.app/gi],
     description:'Firebase database URL found. Verify that security rules block unauthorized access.',cwe:'CWE-200',owasp:'M1',masvs:'STORAGE-12'},
    {id:'aws_s3',name:'AWS S3 Bucket URL',severity:'issue',
     patterns:[/[a-z0-9\-]+\.s3[.\-][a-z0-9\-]+\.amazonaws\.com/gi],
     description:'S3 bucket URL detected. Verify the bucket policy does not permit public access.',cwe:'CWE-200',owasp:'M1',masvs:'STORAGE-12'},
    {id:'localhost_url',name:'Debug/Localhost URL',severity:'issue',
     patterns:[/https?:\/\/localhost[\/:]/gi,/https?:\/\/127\.0\.0\.1[\/:]/g],
     description:'Development/debug endpoints found in the release binary. Remove before shipping.',cwe:'CWE-489',owasp:'M1',masvs:'CODE-4'},
    {id:'jwt_hardcoded',name:'Hardcoded JWT Token',severity:'issue',
     patterns:[/eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}/g],
     description:'A signed JWT was found embedded in the binary -tokens must not be hardcoded.',cwe:'CWE-798',owasp:'M9',masvs:'STORAGE-14'},
    {id:'private_key',name:'Private Key Material',severity:'issue',
     patterns:[/-----BEGIN (?:RSA )?PRIVATE KEY-----/g,/-----BEGIN EC PRIVATE KEY-----/g],
     description:'Private key material embedded in the APK allows complete impersonation.',cwe:'CWE-321',owasp:'M9',masvs:'CRYPTO-1'},
    {id:'android_keystore',name:'Android Keystore Used',severity:'secure',
     patterns:[/AndroidKeyStore/g,/KeyStore\.getInstance\(["']AndroidKeyStore["']/g],
     description:'Android Keystore provides hardware-backed cryptographic key storage.',cwe:'',owasp:'',masvs:'STORAGE-1'},
    {id:'biometric',name:'Biometric Authentication',severity:'issue',
     patterns:[/BiometricPrompt/g,/FingerprintManager/g,/BiometricManager/g],
     description:'Biometric authentication (fingerprint/face) is implemented.',cwe:'',owasp:'',masvs:'AUTH-8'},
    {id:'root_detect',name:'Root Detection',severity:'secure',
     patterns:[/RootBeer/g,/isRooted/g,/isDeviceRooted/g,/\/system\/xbin\/su/g],
     description:'Root detection is implemented to identify compromised devices.',cwe:'',owasp:'',masvs:'RESILIENCE-1'},
    {id:'emulator_detect',name:'Emulator Detection',severity:'secure',
     patterns:[/isEmulator/g,/Build\.FINGERPRINT.*generic/gi,/Build\.MODEL.*Emulator/gi],
     description:'Emulator detection for runtime environment integrity checks.',cwe:'',owasp:'',masvs:'RESILIENCE-3'},
    {id:'antidebug',name:'Anti-Debug Protection',severity:'secure',
     patterns:[/isDebuggerConnected/g,/android\.os\.Debug\.isDebuggerConnected/g],
     description:'Anti-debugging protection is implemented to resist dynamic analysis.',cwe:'',owasp:'',masvs:'RESILIENCE-2'},
    {id:'integrity_check',name:'App Integrity Check',severity:'secure',
     patterns:[/SafetyNet/g,/PlayIntegrity/g],
     description:'Play Integrity or SafetyNet attestation verifies app has not been tampered with.',cwe:'',owasp:'',masvs:'RESILIENCE-4'},
    {id:'native_jni',name:'Native JNI Code',severity:'issue',
     patterns:[/System\.loadLibrary\s*\(/g,/System\.load\s*\(/g],
     description:'Native code is loaded. JNI bridges may introduce memory-safety vulnerabilities.',cwe:'CWE-120',owasp:'M7',masvs:'CODE-6'},
    {id:'unsafe_native',name:'Unsafe Native Functions',severity:'issue',
     patterns:[/memcpy\s*\(/g,/strcpy\s*\(/g,/sprintf\s*\(/g,/gets\s*\(/g],
     description:'Unsafe C standard library functions found. These can cause buffer overflows.',cwe:'CWE-120',owasp:'M7',masvs:'CODE-6'},
    {id:'github_token',name:'GitHub Token Exposed',severity:'issue',
     patterns:[/ghp_[A-Za-z0-9_]{36}/g,/gho_[A-Za-z0-9_]{36}/g,/ghs_[A-Za-z0-9_]{36}/g,/github_pat_[A-Za-z0-9_]{22,}/g],
     description:'GitHub personal access token found. Revoke it immediately in GitHub Settings > Tokens.',cwe:'CWE-798',owasp:'M9',masvs:'STORAGE-14'},
    {id:'stripe_secret',name:'Stripe Secret Key Exposed',severity:'issue',
     patterns:[/sk_live_[A-Za-z0-9]{24,}/g,/sk_test_[A-Za-z0-9]{24,}/g,/rk_live_[A-Za-z0-9]{24,}/g],
     description:'Stripe secret key found in APK. This allows full access to the payment account.',cwe:'CWE-798',owasp:'M9',masvs:'STORAGE-14'},
    {id:'slack_webhook',name:'Slack Webhook URL',severity:'issue',
     patterns:[/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g],
     description:'Slack webhook URL exposed. Anyone can post messages to this channel.',cwe:'CWE-798',owasp:'M9',masvs:'STORAGE-14'},
    {id:'sendgrid_key',name:'SendGrid API Key Exposed',severity:'issue',
     patterns:[/SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g],
     description:'SendGrid API key found. Attacker can send emails from your domain.',cwe:'CWE-798',owasp:'M9',masvs:'STORAGE-14'},
    {id:'mailgun_key',name:'Mailgun API Key',severity:'issue',
     patterns:[/key-[0-9a-zA-Z]{32}/g],
     description:'Mailgun API key detected in the application.',cwe:'CWE-798',owasp:'M9',masvs:'STORAGE-14'},
    {id:'api_key_xml',name:'API Key in XML Resource',severity:'issue',
     patterns:[/google_maps_key/gi,/google_api_key/gi,/api_key.*>[A-Za-z0-9_\-]{20,}/g,/maps_api_key/gi,/facebook_app_id.*>[0-9]{10,}/g],
     description:'API key found in XML resources (strings.xml / config). These are trivially extractable.',cwe:'CWE-798',owasp:'M9',masvs:'STORAGE-14'},
    {id:'cleartext_nsc',name:'Cleartext Traffic in Network Security Config',severity:'issue',
     patterns:[/cleartextTrafficPermitted\s*=\s*["']true/gi],
     description:'Network security config explicitly allows cleartext HTTP traffic to specific domains.',cwe:'CWE-319',owasp:'M3',masvs:'NETWORK-1'},
    {id:'deeplink_handler',name:'Custom URL Scheme Handler',severity:'issue',
     patterns:[/android:scheme=["'][a-zA-Z][a-zA-Z0-9+.\-]*["']/g],
     description:'Custom URL scheme registered. Verify deep link inputs are validated to prevent injection.',cwe:'CWE-939',owasp:'M1',masvs:'PLATFORM-3'},
    {id:'intent_extra_unvalidated',name:'Unvalidated Intent Extras',severity:'issue',
     patterns:[/getStringExtra\s*\(/g,/getIntExtra\s*\(/g,/getSerializableExtra\s*\(/g,/getParcelableExtra\s*\(/g],
     description:'Intent extras are read without validation. Exported components receiving these may be exploitable.',cwe:'CWE-20',owasp:'M1',masvs:'PLATFORM-2'},
    {id:'shared_prefs_plain',name:'SharedPreferences for Sensitive Data',severity:'issue',
     patterns:[/getSharedPreferences\s*\([^)]*(?:password|token|secret|key|credential)/gi],
     description:'SharedPreferences used to store potentially sensitive data. Use EncryptedSharedPreferences instead.',cwe:'CWE-312',owasp:'M2',masvs:'STORAGE-2'},
    {id:'tapjacking',name:'Tapjacking Vulnerability',severity:'issue',
     patterns:[/filterTouchesWhenObscured\s*=\s*["']?false/gi],
     description:'Touch filtering disabled. The app may be vulnerable to tapjacking overlay attacks.',cwe:'CWE-1021',owasp:'M1',masvs:'PLATFORM-9'},
    {id:'file_mode_private',name:'Insecure File Creation Mode',severity:'issue',
     patterns:[/openFileOutput\s*\([^)]*,\s*(?:1|2|3)\s*\)/g,/MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE/g],
     description:'Files created with world-readable/writable mode can be accessed by any app on the device.',cwe:'CWE-276',owasp:'M2',masvs:'STORAGE-2'},
    {id:'temp_file',name:'Insecure Temp File Creation',severity:'issue',
     patterns:[/File\.createTempFile\s*\(/g,/\.createTempFile\s*\(/g],
     description:'Temp files may persist on disk with predictable names. Ensure cleanup and proper permissions.',cwe:'CWE-377',owasp:'M2',masvs:'STORAGE-2'},
    {id:'webview_content_access',name:'WebView Content Provider Access',severity:'issue',
     patterns:[/setAllowContentAccess\s*\(\s*true/g],
     description:'WebView can access content:// URIs -may allow reading arbitrary app data via content providers.',cwe:'CWE-200',owasp:'M7',masvs:'PLATFORM-6'},
    {id:'content_provider_sql',name:'Content Provider SQL Injection',severity:'issue',
     patterns:[/query\s*\([^)]*\+[^)]*selection/gi,/rawQuery\s*\([^)]*\+/g],
     description:'SQL query concatenates user input. Use parameterized queries (selectionArgs) to prevent SQL injection.',cwe:'CWE-89',owasp:'M7',masvs:'PLATFORM-2'},
    {id:'ordered_broadcast',name:'Ordered Broadcast Without Permission',severity:'issue',
     patterns:[/sendOrderedBroadcast\s*\([^,]+,\s*null/g],
     description:'Ordered broadcast sent with null permission -any app can receive and modify the result.',cwe:'CWE-925',owasp:'M1',masvs:'PLATFORM-4'},
    {id:'clipboard_copy',name:'Sensitive Data Copied to Clipboard',severity:'issue',
     patterns:[/setPrimaryClip\s*\(/g],
     description:'Data copied to clipboard is accessible to all apps. On Android < 12, background apps can read clipboard silently.',cwe:'CWE-200',owasp:'M2',masvs:'STORAGE-10'},
    {id:'insecure_deser',name:'Insecure Deserialization',severity:'issue',
     patterns:[/ObjectInputStream\s*\(/g,/readObject\s*\(\s*\)/g,/\.readUnshared\s*\(/g],
     description:'Java deserialization of untrusted data can lead to remote code execution via gadget chains.',cwe:'CWE-502',owasp:'M7',masvs:'PLATFORM-8'},
    {id:'fileprovider_root',name:'FileProvider Exposes Root Path',severity:'issue',
     patterns:[/root-path\s*name/g,/external-path\s*name/g],
     description:'FileProvider configuration may expose root or external paths. Verify only intended directories are shared.',cwe:'CWE-200',owasp:'M2',masvs:'STORAGE-12'},
    {id:'hardcoded_ip',name:'Hardcoded IP Address',severity:'issue',
     patterns:[/["'](?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)["']/g],
     description:'Hardcoded IP address found. Use hostnames to allow certificate validation and DNS-based security.',cwe:'CWE-798',owasp:'M3',masvs:'NETWORK-1'},
    {id:'implicit_chooser',name:'Implicit Intent Without Chooser',severity:'issue',
     patterns:[/startActivity\s*\(\s*new\s+Intent\s*\(\s*Intent\./g],
     description:'Implicit intent sent without Intent.createChooser(). A malicious app can register as handler to intercept data.',cwe:'CWE-925',owasp:'M1',masvs:'PLATFORM-4'},
    {id:'log_sensitive',name:'Sensitive Data in Logs',severity:'issue',
     patterns:[/Log\.[dievw]\s*\([^)]*(?:password|passwd|token|secret|pin|otp|credential|auth_token|session_id|access_key)/gi],
     description:'Sensitive data (passwords, tokens, PINs) written to Android logs. Logs are readable by any app with READ_LOGS or via ADB.',cwe:'CWE-532',owasp:'M2',masvs:'STORAGE-3'},
    {id:'sms_send',name:'SMS Sending Capability',severity:'issue',
     patterns:[/SmsManager\.getDefault\(\)\.send/g,/sendTextMessage\s*\(/g,/sendMultipartTextMessage\s*\(/g],
     description:'App sends SMS programmatically. If triggered by untrusted input, this enables premium SMS fraud.',cwe:'CWE-927',owasp:'M1',masvs:'PLATFORM-4'},
    {id:'webview_inject',name:'WebView URL from External Input',severity:'issue',
     patterns:[/\.loadUrl\s*\(\s*(?:url|uri|link|data|intent|getIntent)/gi,/\.loadData\s*\(\s*(?:html|content|data|getIntent)/gi],
     description:'WebView loads content from a variable that may originate from untrusted input (intent, deep link). Attacker can inject javascript: URIs for XSS or file: URIs to steal data.',cwe:'CWE-79',owasp:'M7',masvs:'PLATFORM-6'},
    {id:'deeplink_data_unsafe',name:'Deep Link Data Used Without Validation',severity:'issue',
     patterns:[/getIntent\(\)\.getData\(\)\.get(?:Host|Path|Query|Fragment|Scheme)/g,/getIntent\(\)\.getData\(\)\.toString/g],
     description:'URI data from deep link intent read without validation. Can enable open redirect, SSRF, or account takeover if used in navigation or API calls.',cwe:'CWE-601',owasp:'M1',masvs:'PLATFORM-3'},
    {id:'dynamic_receiver',name:'Dynamic Broadcast Receiver (Potentially Exported)',severity:'issue',
     patterns:[/registerReceiver\s*\([^)]*(?:new\s+IntentFilter|filter)/g],
     description:'Dynamically registered BroadcastReceiver. On Android 14+, receivers must specify RECEIVER_NOT_EXPORTED or RECEIVER_EXPORTED flag. Missing flag defaults to exported.',cwe:'CWE-926',owasp:'M1',masvs:'PLATFORM-4'},
    {id:'classloader_rce',name:'Dynamic Class Loading (Code Execution Risk)',severity:'issue',
     patterns:[/new\s+DexClassLoader\s*\(/g,/new\s+PathClassLoader\s*\(/g,/new\s+URLClassLoader\s*\(/g,/InMemoryDexClassLoader/g],
     description:'Classes loaded dynamically from external paths. If the loaded code path is attacker-controllable, this leads to arbitrary code execution.',cwe:'CWE-94',owasp:'M7',masvs:'RESILIENCE-9'},
    {id:'reflect_invoke',name:'Reflective Method Invocation',severity:'issue',
     patterns:[/\.invoke\s*\(\s*[^)]*getMethod/g,/getDeclaredMethod\s*\([^)]*\)\.invoke/g],
     description:'Method invoked via reflection. If the class/method name comes from untrusted input, this can execute arbitrary code.',cwe:'CWE-470',owasp:'M7',masvs:'CODE-6'},
    {id:'provider_openfile',name:'Content Provider openFile (Path Traversal Risk)',severity:'issue',
     patterns:[/openFile\s*\([^)]*Uri[^)]*\)/g],
     description:'Content Provider implements openFile(). Without proper path canonicalization, "../" in URIs can read arbitrary files from the app sandbox.',cwe:'CWE-22',owasp:'M2',masvs:'PLATFORM-2'},
    {id:'pending_implicit_full',name:'Mutable PendingIntent with Empty Intent',severity:'issue',
     patterns:[/PendingIntent\.get(?:Activity|Service|Broadcast)\s*\([^)]*new\s+Intent\s*\(\s*\)/g,/PendingIntent\.get(?:Activity|Service|Broadcast)\s*\([^)]*FLAG_MUTABLE/g],
     description:'PendingIntent created with mutable flag or empty base intent. Attacker app can fill in the intent to hijack the operation and steal data.',cwe:'CWE-927',owasp:'M1',masvs:'PLATFORM-1'},
    {id:'prefs_sensitive_store',name:'Credentials Stored in SharedPreferences',severity:'issue',
     patterns:[/\.edit\(\)\.put(?:String|Int|Boolean)\s*\([^)]*(?:password|token|secret|pin|session|auth_key|access_token|refresh_token)/gi],
     description:'Sensitive credentials written to SharedPreferences (plain XML on disk). Use EncryptedSharedPreferences or Android Keystore.',cwe:'CWE-312',owasp:'M2',masvs:'STORAGE-2'},
    {id:'fragment_inject',name:'Fragment Injection via Intent Extras',severity:'issue',
     patterns:[/getStringExtra\s*\(\s*["']:android:show_fragment["']/g,/PreferenceActivity/g],
     description:'Exported activity extending PreferenceActivity is vulnerable to fragment injection. Attacker can load arbitrary fragments including non-exported ones.',cwe:'CWE-470',owasp:'M1',masvs:'PLATFORM-2'},
    {id:'intent_redir',name:'Intent Redirection (Access Non-Exported Components)',severity:'issue',
     patterns:[/startActivity\s*\(\s*\(?Intent\)?\s*get(?:Parcelable|Serializable)Extra/g,/startActivity\s*\([^)]*getParcelableExtra\s*\(/g,/startService\s*\([^)]*getParcelableExtra/g],
     description:'Activity/Service started from an Intent received via extras. Attacker can craft an intent pointing to non-exported components, bypassing access controls.',cwe:'CWE-926',owasp:'M1',masvs:'PLATFORM-1'},
    {id:'provider_query_exposed',name:'Content Provider Query Without Permission Check',severity:'issue',
     patterns:[/\.query\s*\(\s*uri/gi,/getContentResolver\(\)\.query/g],
     description:'Content resolver query executed. If the target provider is exported without permissions, any app can read its data (contacts, messages, app data).',cwe:'CWE-200',owasp:'M2',masvs:'PLATFORM-2'},
    {id:'math_random_security',name:'Math.random() for Security Token',severity:'issue',
     patterns:[/Math\.random\s*\(\s*\).*(?:token|key|nonce|salt|iv|seed|otp|code|pin)/gi,/Random\s*\(\s*\).*(?:token|key|nonce|otp|pin)/gi],
     description:'Predictable random generator used to create security tokens. Use SecureRandom for all cryptographic and authentication-related randomness.',cwe:'CWE-330',owasp:'M5',masvs:'CRYPTO-6'},
    {id:'rsa_no_padding',name:'RSA Without Padding',severity:'issue',
     patterns:[/Cipher\.getInstance\s*\(\s*["']RSA[^"']*\/NoPadding/gi],
     description:'RSA used without OAEP padding. Textbook RSA is vulnerable to chosen-ciphertext attacks. Use RSA/ECB/OAEPWithSHA-256AndMGF1Padding.',cwe:'CWE-780',owasp:'M5',masvs:'CRYPTO-3'},
    {id:'cbc_padding',name:'CBC with PKCS Padding (Padding Oracle)',severity:'issue',
     patterns:[/Cipher\.getInstance\s*\(\s*["'][^"']*\/CBC\/PKCS5Padding/gi,/Cipher\.getInstance\s*\(\s*["'][^"']*\/CBC\/PKCS7Padding/gi],
     description:'CBC mode with PKCS5/PKCS7 padding is vulnerable to padding oracle attacks. Use AES/GCM/NoPadding for authenticated encryption.',cwe:'CWE-649',owasp:'M5',masvs:'CRYPTO-3'},
    {id:'weak_rc4',name:'Weak Cipher (RC4/Blowfish)',severity:'issue',
     patterns:[/Cipher\.getInstance\s*\(\s*["'](?:RC2|RC4|ARCFOUR|Blowfish)/gi],
     description:'RC4/Blowfish are deprecated ciphers with known weaknesses. Use AES-256-GCM instead.',cwe:'CWE-327',owasp:'M5',masvs:'CRYPTO-3'},
    {id:'weak_md4',name:'Weak Hash (MD4)',severity:'issue',
     patterns:[/MessageDigest\.getInstance\s*\(\s*["']MD4/gi],
     description:'MD4 is completely broken. Collisions can be found in milliseconds. Use SHA-256 or SHA-3.',cwe:'CWE-327',owasp:'M5',masvs:'CRYPTO-4'},
    {id:'webview_debug',name:'WebView Debugging Enabled',severity:'issue',
     patterns:[/setWebContentsDebuggingEnabled\s*\(\s*true/g],
     description:'WebView remote debugging is enabled. Attacker on same network can inspect WebView contents via chrome://inspect. Disable in production.',cwe:'CWE-489',owasp:'M1',masvs:'RESILIENCE-2'},
    {id:'no_screenshot_protect',name:'No Screenshot Protection (FLAG_SECURE)',severity:'issue',
     patterns:[/FLAG_SECURE/g],
     description:'FLAG_SECURE is used to prevent screenshots and recent-app thumbnails from leaking sensitive UI content.',cwe:'CWE-200',owasp:'M2',masvs:'STORAGE-9'},
    {id:'hidden_ui',name:'Hidden UI Elements (Data Leak)',severity:'issue',
     patterns:[/setVisibility\s*\(\s*View\.GONE\s*\)/g,/setVisibility\s*\(\s*View\.INVISIBLE\s*\)/g],
     description:'UI elements hidden with GONE/INVISIBLE may still hold sensitive data in memory. Attacker can reveal them via layout inspection.',cwe:'CWE-200',owasp:'M2',masvs:'STORAGE-7'},
    {id:'jackson_deser',name:'Jackson Default Typing (Deserialization)',severity:'issue',
     patterns:[/enableDefaultTyping\s*\(/g,/activateDefaultTyping\s*\(/g],
     description:'Jackson ObjectMapper with default typing enabled allows arbitrary class instantiation from JSON input, leading to RCE.',cwe:'CWE-502',owasp:'M7',masvs:'PLATFORM-8'},
    {id:'download_mgr',name:'Download Manager Usage',severity:'issue',
     patterns:[/getSystemService\s*\(\s*[^)]*DOWNLOAD_SERVICE/g,/DownloadManager\.Request\s*\(/g],
     description:'DownloadManager saves files to public storage by default. Downloaded files can be read or tampered with by other apps.',cwe:'CWE-276',owasp:'M2',masvs:'STORAGE-2'},
    {id:'clipboard_listen',name:'Clipboard Listener',severity:'issue',
     patterns:[/OnPrimaryClipChangedListener/g,/addPrimaryClipChangedListener/g],
     description:'App listens to clipboard changes. Can capture passwords, OTPs, and sensitive data copied by the user from other apps.',cwe:'CWE-200',owasp:'M2',masvs:'STORAGE-10'},
    {id:'debug_build',name:'Debug Build Flag Enabled',severity:'issue',
     patterns:[/BuildConfig\.DEBUG\s*==\s*true/g,/BuildConfig\.DEBUG\s*\)/g],
     description:'Code checks or relies on BuildConfig.DEBUG. If debug flag is left true in release builds, debug code paths remain active.',cwe:'CWE-489',owasp:'M9',masvs:'CODE-5'},
    {id:'world_readwrite',name:'World Read+Write File Mode',severity:'issue',
     patterns:[/openFileOutput\s*\([^)]*,\s*3\s*\)/g],
     description:'File created with mode 3 (world-readable + world-writable). Any app on the device can read and modify this file.',cwe:'CWE-276',owasp:'M2',masvs:'STORAGE-2'},
    {id:'frida_detect',name:'Frida Detection',severity:'issue',
     patterns:[/fridaserver/gi,/27047/g,/LIBFRIDA/g,/frida-agent/gi],
     description:'Anti-tampering check for Frida instrumentation framework. Presence suggests the app has runtime protection.',cwe:'',owasp:'',masvs:'RESILIENCE-4'},
    {id:'webview_sdcard',name:'WebView Loads from External Storage',severity:'issue',
     patterns:[/loadUrl\s*\([^)]*getExternalStorageDirectory/g,/loadUrl\s*\([^)]*getExternalFilesDir/g],
     description:'WebView loads HTML from external storage. Any app with storage permission can replace the HTML with malicious content.',cwe:'CWE-749',owasp:'M7',masvs:'PLATFORM-6'},
    {id:'slack_token',name:'Slack Token',severity:'issue',
     patterns:[/xox[baprs]-[0-9a-zA-Z]{10,48}/g],
     description:'Slack API token found. Allows reading messages, posting, and accessing workspace data.',cwe:'CWE-798',owasp:'M9',masvs:'STORAGE-14'},
    {id:'fb_access_token',name:'Facebook Access Token',severity:'issue',
     patterns:[/EAACEdEose0cBA[0-9A-Za-z]+/g],
     description:'Facebook access token found. Grants access to user profile, posts, and connected apps.',cwe:'CWE-798',owasp:'M9',masvs:'STORAGE-14'},
    {id:'gcp_oauth_token',name:'Google OAuth Access Token',severity:'issue',
     patterns:[/ya29\.[0-9A-Za-z\-_]+/g],
     description:'Google OAuth access token embedded in code. These tokens grant API access to Google services.',cwe:'CWE-798',owasp:'M9',masvs:'STORAGE-14'},
    {id:'gcp_oauth_client',name:'Google OAuth Client ID',severity:'issue',
     patterns:[/[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g],
     description:'Google OAuth client ID found. Combined with a secret, this enables impersonating the app for OAuth flows.',cwe:'CWE-200',owasp:'M9',masvs:'STORAGE-14'},
    {id:'gcp_service_account',name:'GCP Service Account Key',severity:'issue',
     patterns:[/"type"\s*:\s*"service_account"/g],
     description:'Google Cloud service account key file detected. Full access to GCP resources tied to this account.',cwe:'CWE-798',owasp:'M9',masvs:'STORAGE-14'},
    {id:'password_in_url',name:'Credentials in URL',severity:'issue',
     patterns:[/[a-zA-Z]{3,10}:\/\/[^\s:@]{3,20}:[^\s:@]{3,20}@.{1,100}/g],
     description:'URL contains embedded username:password. These are logged in browser history, server logs, and proxy logs.',cwe:'CWE-522',owasp:'M9',masvs:'STORAGE-14'},
    {id:'square_token',name:'Square Payment Token',severity:'issue',
     patterns:[/sq0atp-[0-9A-Za-z\-_]{22}/g,/sq0csp-[0-9A-Za-z\-_]{43}/g],
     description:'Square payment API token found. Allows processing transactions on the merchant account.',cwe:'CWE-798',owasp:'M9',masvs:'STORAGE-14'},
    {id:'telegram_bot',name:'Telegram Bot Token',severity:'issue',
     patterns:[/[0-9]{5,10}:AA[0-9A-Za-z\-_]{33}/g],
     description:'Telegram bot API token. Allows sending messages, reading updates, and controlling the bot.',cwe:'CWE-798',owasp:'M9',masvs:'STORAGE-14'},
    {id:'aws_secret',name:'AWS Secret Access Key',severity:'issue',
     patterns:[/(?:aws|AWS).*['"][0-9a-zA-Z\/+]{40}['"]/g],
     description:'AWS secret access key found near an AWS context string. Full programmatic access to AWS resources.',cwe:'CWE-798',owasp:'M9',masvs:'STORAGE-14'},
    {id:'mailchimp_key',name:'MailChimp API Key',severity:'issue',
     patterns:[/[0-9a-f]{32}-us[0-9]{1,2}/g],
     description:'MailChimp API key found. Allows managing email campaigns and subscriber lists.',cwe:'CWE-798',owasp:'M9',masvs:'STORAGE-14'},
    {id:'paypal_token',name:'PayPal/Braintree Token',severity:'issue',
     patterns:[/access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g],
     description:'PayPal/Braintree production access token. Enables payment processing on the merchant account.',cwe:'CWE-798',owasp:'M9',masvs:'STORAGE-14'},
    {id:'pgp_private',name:'PGP Private Key',severity:'issue',
     patterns:[/-----BEGIN PGP PRIVATE KEY BLOCK-----/g],
     description:'PGP private key block found in the app. Allows decrypting messages and forging signatures.',cwe:'CWE-321',owasp:'M9',masvs:'CRYPTO-1'},
    {id:'ssh_private',name:'SSH/DSA Private Key',severity:'issue',
     patterns:[/-----BEGIN DSA PRIVATE KEY-----/g,/-----BEGIN OPENSSH PRIVATE KEY-----/g],
     description:'SSH private key embedded in the app. Allows authenticating to servers as the key owner.',cwe:'CWE-321',owasp:'M9',masvs:'CRYPTO-1'},
];
if (typeof SECRETS_RULES !== 'undefined' && Array.isArray(SECRETS_RULES)) {
    ANDROID_RULES.push(...SECRETS_RULES);
}

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

const DANGEROUS_PERMS = new Set(['READ_CONTACTS','WRITE_CONTACTS','GET_ACCOUNTS','READ_CALL_LOG','WRITE_CALL_LOG','PROCESS_OUTGOING_CALLS','READ_CALENDAR','WRITE_CALENDAR','CAMERA','RECORD_AUDIO','READ_SMS','RECEIVE_SMS','SEND_SMS','READ_PHONE_STATE','READ_PHONE_NUMBERS','CALL_PHONE','ACCESS_FINE_LOCATION','ACCESS_COARSE_LOCATION','ACCESS_BACKGROUND_LOCATION','BODY_SENSORS','ACTIVITY_RECOGNITION','READ_EXTERNAL_STORAGE','WRITE_EXTERNAL_STORAGE','BLUETOOTH_CONNECT','BLUETOOTH_SCAN','BLUETOOTH_ADVERTISE','READ_MEDIA_IMAGES','READ_MEDIA_VIDEO','READ_MEDIA_AUDIO']);

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
        
        const packageName = manifest.attribs?.package || '';
        if (a.taskAffinity !== undefined && a.taskAffinity !== '' && a.taskAffinity !== packageName)
            f('task_affinity', 'Custom taskAffinity (Task Hijacking Risk)', 'issue', `Activity "${n}" sets a custom taskAffinity (${a.taskAffinity}). If not explicitly intended, this can enable task hijacking attacks.`, 'CWE-926', 'M1', 'PLATFORM-3', `<activity> ${short} [taskAffinity="${a.taskAffinity}"]`);
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
                if (scheme && !['http','https'].includes(scheme))
                    f('deeplink_scheme', `Custom URL Scheme: ${scheme}://`, 'issue', `Activity "${n}" handles "${scheme}://" scheme. Validate deep link input.`, 'CWE-939', 'M1', 'PLATFORM-3', `<activity> ${short} [scheme="${scheme}://"]`);
            }
        }
        const lm = String(a.launchMode);
        if (lm === 'singleTask' || lm === '2') {
            f('launch_mode_singletask', 'SingleTask LaunchMode (Task Hijack Risk)', 'warning', `Activity "${n}" uses singleTask launchMode. It may be vulnerable to StrandHogg-style task hijacking if taskAffinity is not properly configured.`, 'CWE-1021', 'M1', 'PLATFORM-2', `<activity> ${short} [launchMode="${a.launchMode}"]`);
            
            if (!a.taskAffinity) {
                f('task_hijack', 'Task Hijacking Risk (singleTask + no-taskAffinity)', 'issue', `Activity "${n}" uses singleTask without a custom taskAffinity, making it highly vulnerable to StrandHogg task hijacking.`, 'CWE-1021', 'M1', 'PLATFORM-2', `<activity> ${short} [singleTask + no-taskAffinity]`);
            }
        }
        
        if (a.taskAffinity && a.taskAffinity !== R.appInfo?.packageName) {
            f('task_affinity_hijack', 'Task Hijacking Risk (Custom TaskAffinity)', 'issue', `Activity "${n}" has a custom taskAffinity ("${a.taskAffinity}") which can be hijacked by malicious apps.`, 'CWE-1021', 'M1', 'PLATFORM-2', `<activity> ${short} [taskAffinity="${a.taskAffinity}"]`);
        }
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
    const safe = content.length > 300000 ? content.slice(0, 300000) : content;

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
            } catch(e) {}
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

async function analyzeAPK(file, options = {}) {
    const R = {
        appInfo: { fileName: file.name, fileSize: formatSize(file.size) },
        manifest: null, manifestStr: '', permissions: [], dangerousPerms: [],
        components: { activities: [], services: [], receivers: [], providers: [] },
        certInfo: null, findings: [], files: [], fileTree: {},
        dexFiles: [], trackers: [], nativeLibs: [],
        specialFiles: { dex: [], databases: [], configs: [] },
        strings: [], urls: [], minSdk: null, targetSdk: null, isObfuscated: false
    };
    apkState.findings = { issue: [], secure: [] };
    apkState.groupedFindings = { issue: [], secure: [] };
    apkState.fileContents.clear();
    apkState.dexParsed = [];
    apkState.smaliTree = {};
    apkState.currentViewMode = 'java';
    apkState.currentViewClass = null;
    apkState.currentViewFqn = null;
    apkState.currentViewDexIdx = null;
    apkState.javaCache = new Map();
    apkState.explorerView = 'apk';
    apkState.arscData = null;
    apkState.inspectorData = null;

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
    apkState.zipContent = zip;

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
                apkState.fileContents.set('AndroidManifest.xml', R.manifestStr);
                extractManifestInfo(R);
                R.findings.push(...analyzeManifest(R.manifest));
            }
        } catch(e) { }
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
            } catch(e) { }
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
                if (raw[i] === magic[0] && raw[i+1] === magic[1] && raw[i+2] === magic[2] &&
                    raw[i+3] === magic[3] && raw[i+4] === magic[4] && raw[i+5] === magic[5] && raw[i+6] === magic[6]) {
                    hasV2 = true; break;
                }
            }
        } catch(e) { }

        if (hasV1 && !hasV2) {
            R.findings.push({ ruleId: 'v1_only_sig', ruleName: 'v1 (JAR) Signature Only', severity: 'issue',
                description: 'Only v1 signing found. Vulnerable to Janus (CVE-2017-13156) on Android < 7. Enable v2/v3.',
                cwe: 'CWE-345', owasp: 'M8', masvs: 'CODE-1', file: 'META-INF/', line: null,
                match: 'JAR signature only, no APK Signing Block v2/v3' });
        }
        R.hasV2Sig = hasV2;
    }

    updateProgress(40, 'Parsing DEX files...');
    await yield_();
    const allDexStrings = [];
    for (const dp of R.specialFiles.dex.slice(0, 5)) {
        try {
            updateProgress(40, `Parsing ${dp}...`);
            await yield_();
            const db = await zip.file(dp).async('arraybuffer');
            const parser = new DEXParser(db);
            const parsed = parser.parse();
            if (parsed) {
                apkState.dexParsed.push({ name: dp, buf: db, ...parsed });
                allDexStrings.push(...parsed.strings);
                buildSmaliTree(parsed.classes, apkState.smaliTree, apkState.dexParsed.length - 1);
                R.dexFiles.push({ name: dp, classes: parsed.classes.length, methods: parsed.methods.length, strings: parsed.strings.length });
            }
        } catch(e) { }
    }

    updateProgress(44, 'Parsing resources.arsc...');
    await yield_();
    const arscFile = zip.file('resources.arsc');
    if (arscFile) {
        try {
            const arscBuf = await arscFile.async('arraybuffer');
            const arscData = parseArsc(arscBuf);
            if (arscData) {
                apkState.arscData = arscData;
                apkState.fileContents.set('resources.arsc', renderArsc(arscData));
                const arscContent = arscData.allStrings.join('\n');
                R.findings.push(...analyzeContent(arscContent, 'resources.arsc', ANDROID_RULES));
            }
        } catch(e) { }
    }

    const allClasses = apkState.dexParsed.flatMap(d => d.classes);
    if (allClasses.length > 10) {
        const short = allClasses.filter(c => { const s = c.name.replace(/.*\//,'').replace(/;/,''); return s.length <= 2; }).length;
        R.isObfuscated = (short / allClasses.length) > 0.4;
    }
    if (R.isObfuscated) R.findings.push({ ruleId: 'obfuscated', ruleName: 'Code Obfuscation Active', severity: 'secure', description: 'ProGuard/R8 obfuscation detected from class name analysis.', cwe: '', owasp: '', masvs: 'RESILIENCE-9', file: 'classes.dex', line: null, match: 'Short class names >40% of total' });

    updateProgress(56, 'Scanning decompiled classes...');
    await yield_();
    let classesScanned = 0;
    for (const dex of apkState.dexParsed) {
        for (const cls of (dex.classes || []).slice(0, 500)) {
            if (classesScanned++ > 2000) break;
            const fqn = (cls.name || '').replace(/^L/, '').replace(/;$/, '').replace(/\//g, '.');
            if (!fqn || fqn.length < 3) continue;
            try {
                const javaCode = generateJavaView(cls, dex.buf, dex.strings, dex.types, dex.methods, dex.fields || []);
                apkState.javaCache.set(fqn, javaCode);
                const classFindings = analyzeContent(javaCode, fqn + '.java', ANDROID_RULES);
                R.findings.push(...classFindings);
            } catch(e) {}
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
    const textFiles = [...priorityFiles, ...otherTextFiles].slice(0, 80);
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
                    } catch(pe) { }
                }
                if (!c) c = new TextDecoder('utf-8', { fatal: false }).decode(ab);
            } else {
                c = await zip.file(path).async('string');
            }
            apkState.fileContents.set(path, c);
            R.findings.push(...analyzeContent(c, path, ANDROID_RULES));
        } catch(e) {}
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
        apkState.groupedFindings[s].push(g);
    }
    apkState.analysisResults = R;
    updateProgress(100, 'Complete!');
    return R;
}

function dexTypeToJava(t) {
    if (!t) return 'Object';
    const PRIM = { 'V':'void','Z':'boolean','B':'byte','S':'short','C':'char','I':'int','J':'long','F':'float','D':'double' };
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
        [0x0001,'public'],[0x0002,'private'],[0x0004,'protected'],
        [0x0008,'static'],[0x0010,'final'],[0x0400,'abstract'],
        [0x1000,'synthetic']
    ];
    const mods = f => ACC.filter(([bit]) => f & bit).map(([,n]) => n).join(' ');

    const isIface = (cls.flags & 0x0200) !== 0;
    const isEnum  = (cls.flags & 0x4000) !== 0;
    const isAbst  = (cls.flags & 0x0400) !== 0;

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

    const staticFields   = (cls.fields || []).filter(f => f.isStatic).slice(0, 60);
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
    const directMethods  = methodList.filter(m => m.isDirect);
    const virtualMethods = methodList.filter(m => !m.isDirect);

    const hasBuf = buf && (buf instanceof ArrayBuffer ? buf.byteLength > 0 : buf.buffer?.byteLength > 0);
    const dexBuf = hasBuf ? buf : null;
    const dexV = dexBuf ? new DataView(dexBuf instanceof ArrayBuffer ? dexBuf : dexBuf.buffer) : null;

    const renderMethod = (m) => {
        const ret    = dexTypeToJava(m.returnType || 'V');
        const params = (m.paramTypes || []).map((t, i) => `${dexTypeToJava(t)} arg${i}`).join(', ');
        const mmods  = mods(m.af || 0);
        const isCtor = m.name === '<init>' || m.name === '<clinit>';
        const isStaticMethod = (m.af & 0x0008) !== 0;
        const retStr = isCtor ? '' : ret + ' ';
        const nameStr = isCtor ? simpleName : (m.name || '?');
        out += `\n    ${mmods}${mmods ? ' ' : ''}${retStr}${nameStr}(${params}) {\n`;

        if (m.co && dexBuf) {
            const declaredParams = (m.paramTypes || []).length;
            const totalParams = isStaticMethod ? declaredParams : declaredParams + 1;
            let regCount = 0;
            try { regCount = dexV.getUint16(m.co, true); } catch(e) { regCount = totalParams; }
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
            return `${m.cls}->${m.name}(${(m.paramTypes||[]).join('')})${m.returnType||'V'}`;
        };
        const fref = i => {
            if (i >= fields.length) return `field@${i}`;
            const f = fields[i];
            return `${f.cls}->${f.name}:${f.type}`;
        };
        const tref = i => i < types.length ? types[i] : `type@${i}`;
        const sref = i => {
            if (i >= strings.length) return `string@${i}`;
            return `"${strings[i].replace(/\\/g,'\\\\').replace(/"/g,'\\"').replace(/\n/g,'\\n').replace(/\r/g,'\\r').slice(0,120)}"`;
        };
        const lbl = t => `:L${(t<0?'m':'')+(Math.abs(t)).toString(16).padStart(4,'0')}`;

        const branchTargetPCs = new Set();
        { let _pc = 0, _itr = 0;
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
            else if (_op === 0x29) { _sz = 2; branchTargetPCs.add(_pc + sw(_pc+1)); }
            else if (_op === 0x2a) { _sz = 3; branchTargetPCs.add(_pc + ((iw(_pc+2)<<16)|iw(_pc+1))); }
            else if (_op === 0x2b || _op === 0x2c) _sz = 2;
            else if (_op >= 0x2d && _op <= 0x31) _sz = 2;
            else if (_op >= 0x32 && _op <= 0x37) { _sz = 2; branchTargetPCs.add(_pc + sw(_pc+1)); }
            else if (_op >= 0x38 && _op <= 0x3d) { _sz = 2; branchTargetPCs.add(_pc + sw(_pc+1)); }
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
            out.push(`    .catch all {:L${t.start.toString(16).padStart(4,'0')} .. :L${(t.start+t.count).toString(16).padStart(4,'0')}} :handler_${t.handler.toString(16)}`);
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
                case 0x00: s='nop'; break;
                case 0x01: s=`move v${a}, v${bN}`; break;
                case 0x02: sz=2; s=`move/from16 v${A}, v${iw(pc+1)}`; break;
                case 0x03: sz=3; s=`move/16 v${iw(pc+1)}, v${iw(pc+2)}`; break;
                case 0x04: s=`move-wide v${a}, v${bN}`; break;
                case 0x05: sz=2; s=`move-wide/from16 v${A}, v${iw(pc+1)}`; break;
                case 0x06: sz=3; s=`move-wide/16 v${iw(pc+1)}, v${iw(pc+2)}`; break;
                case 0x07: s=`move-object v${a}, v${bN}`; break;
                case 0x08: sz=2; s=`move-object/from16 v${A}, v${iw(pc+1)}`; break;
                case 0x09: sz=3; s=`move-object/16 v${iw(pc+1)}, v${iw(pc+2)}`; break;
                case 0x0a: s=`move-result v${A}`; break;
                case 0x0b: s=`move-result-wide v${A}`; break;
                case 0x0c: s=`move-result-object v${A}`; break;
                case 0x0d: s=`move-exception v${A}`; break;
                case 0x0e: s='return-void'; break;
                case 0x0f: s=`return v${A}`; break;
                case 0x10: s=`return-wide v${A}`; break;
                case 0x11: s=`return-object v${A}`; break;
                case 0x12: { const lit=(bN&8)?bN-16:bN; s=`const/4 v${a}, #${lit}`; break; }
                case 0x13: sz=2; s=`const/16 v${A}, #${sw(pc+1)}`; break;
                case 0x14: sz=3; s=`const v${A}, #${(iw(pc+2)<<16)|iw(pc+1)}`; break;
                case 0x15: sz=2; s=`const/high16 v${A}, #0x${iw(pc+1).toString(16)}0000`; break;
                case 0x16: sz=2; s=`const-wide/16 v${A}, #${sw(pc+1)}`; break;
                case 0x17: sz=3; s=`const-wide/32 v${A}, #${(iw(pc+2)<<16)|iw(pc+1)}`; break;
                case 0x18: sz=5; s=`const-wide v${A}, #wide`; break;
                case 0x19: sz=2; s=`const-wide/high16 v${A}, #0x${iw(pc+1).toString(16)}000000000000`; break;
                case 0x1a: sz=2; s=`const-string v${A}, ${sref(iw(pc+1))}`; break;
                case 0x1b: sz=3; s=`const-string/jumbo v${A}, ${sref((iw(pc+2)<<16)|iw(pc+1))}`; break;
                case 0x1c: sz=2; s=`const-class v${A}, ${tref(iw(pc+1))}`; break;
                case 0x1d: s=`monitor-enter v${A}`; break;
                case 0x1e: s=`monitor-exit v${A}`; break;
                case 0x1f: sz=2; s=`check-cast v${A}, ${tref(iw(pc+1))}`; break;
                case 0x20: sz=2; s=`instance-of v${a}, v${bN}, ${tref(iw(pc+1))}`; break;
                case 0x21: s=`array-length v${a}, v${bN}`; break;
                case 0x22: sz=2; s=`new-instance v${A}, ${tref(iw(pc+1))}`; break;
                case 0x23: sz=2; s=`new-array v${a}, v${bN}, ${tref(iw(pc+1))}`; break;
                case 0x24: { sz=3; const cnt=(w0>>12)&0xF; s=`filled-new-array {${cnt > 0 ? '...' : ''}}, ${tref(iw(pc+1))}`; break; }
                case 0x25: sz=3; s=`filled-new-array/range {v${iw(pc+2)} .. v${iw(pc+2)+A-1}}, ${tref(iw(pc+1))}`; break;
                case 0x26: { sz=3; const off=(iw(pc+2)<<16)|iw(pc+1); s=`fill-array-data v${A}, ${lbl(pc+off)}`; break; }
                case 0x27: s=`throw v${A}`; break;
                case 0x28: { const o8=(A>=128?A-256:A); s=`goto ${lbl(pc+o8)}`; break; }
                case 0x29: { sz=2; s=`goto/16 ${lbl(pc+sw(pc+1))}`; break; }
                case 0x2a: { sz=3; const o=(iw(pc+2)<<16)|iw(pc+1); s=`goto/32 ${lbl(pc+o)}`; break; }
                case 0x2b: { sz=2; s=`packed-switch v${A}, ${lbl(pc+sw(pc+1))}`; break; }
                case 0x2c: { sz=2; s=`sparse-switch v${A}, ${lbl(pc+sw(pc+1))}`; break; }
                case 0x2d: { sz=2; const w1=iw(pc+1); s=`cmpl-float v${A}, v${w1&0xFF}, v${(w1>>8)&0xFF}`; break; }
                case 0x2e: { sz=2; const w1=iw(pc+1); s=`cmpg-float v${A}, v${w1&0xFF}, v${(w1>>8)&0xFF}`; break; }
                case 0x2f: { sz=2; const w1=iw(pc+1); s=`cmpl-double v${A}, v${w1&0xFF}, v${(w1>>8)&0xFF}`; break; }
                case 0x30: { sz=2; const w1=iw(pc+1); s=`cmpg-double v${A}, v${w1&0xFF}, v${(w1>>8)&0xFF}`; break; }
                case 0x31: { sz=2; const w1=iw(pc+1); s=`cmp-long v${A}, v${w1&0xFF}, v${(w1>>8)&0xFF}`; break; }
                case 0x32: { sz=2; s=`if-eq v${a}, v${bN}, ${lbl(pc+sw(pc+1))}`; break; }
                case 0x33: { sz=2; s=`if-ne v${a}, v${bN}, ${lbl(pc+sw(pc+1))}`; break; }
                case 0x34: { sz=2; s=`if-lt v${a}, v${bN}, ${lbl(pc+sw(pc+1))}`; break; }
                case 0x35: { sz=2; s=`if-ge v${a}, v${bN}, ${lbl(pc+sw(pc+1))}`; break; }
                case 0x36: { sz=2; s=`if-gt v${a}, v${bN}, ${lbl(pc+sw(pc+1))}`; break; }
                case 0x37: { sz=2; s=`if-le v${a}, v${bN}, ${lbl(pc+sw(pc+1))}`; break; }
                case 0x38: { sz=2; s=`if-eqz v${A}, ${lbl(pc+sw(pc+1))}`; break; }
                case 0x39: { sz=2; s=`if-nez v${A}, ${lbl(pc+sw(pc+1))}`; break; }
                case 0x3a: { sz=2; s=`if-ltz v${A}, ${lbl(pc+sw(pc+1))}`; break; }
                case 0x3b: { sz=2; s=`if-gez v${A}, ${lbl(pc+sw(pc+1))}`; break; }
                case 0x3c: { sz=2; s=`if-gtz v${A}, ${lbl(pc+sw(pc+1))}`; break; }
                case 0x3d: { sz=2; s=`if-lez v${A}, ${lbl(pc+sw(pc+1))}`; break; }
                case 0x44: case 0x45: case 0x46: case 0x47: case 0x48: case 0x49: case 0x4a: {
                    const NS=['aget','aget-wide','aget-object','aget-boolean','aget-byte','aget-char','aget-short'];
                    sz=2; const w1=iw(pc+1); s=`${NS[op-0x44]} v${A}, v${w1&0xFF}, v${(w1>>8)&0xFF}`; break;
                }
                case 0x4b: case 0x4c: case 0x4d: case 0x4e: case 0x4f: case 0x50: case 0x51: {
                    const NS=['aput','aput-wide','aput-object','aput-boolean','aput-byte','aput-char','aput-short'];
                    sz=2; const w1=iw(pc+1); s=`${NS[op-0x4b]} v${A}, v${w1&0xFF}, v${(w1>>8)&0xFF}`; break;
                }
                case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57: case 0x58: {
                    const NS=['iget','iget-wide','iget-object','iget-boolean','iget-byte','iget-char','iget-short'];
                    sz=2; s=`${NS[op-0x52]} v${a}, v${bN}, ${fref(iw(pc+1))}`; break;
                }
                case 0x59: case 0x5a: case 0x5b: case 0x5c: case 0x5d: case 0x5e: case 0x5f: {
                    const NS=['iput','iput-wide','iput-object','iput-boolean','iput-byte','iput-char','iput-short'];
                    sz=2; s=`${NS[op-0x59]} v${a}, v${bN}, ${fref(iw(pc+1))}`; break;
                }
                case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65: case 0x66: {
                    const NS=['sget','sget-wide','sget-object','sget-boolean','sget-byte','sget-char','sget-short'];
                    sz=2; s=`${NS[op-0x60]} v${A}, ${fref(iw(pc+1))}`; break;
                }
                case 0x67: case 0x68: case 0x69: case 0x6a: case 0x6b: case 0x6c: case 0x6d: {
                    const NS=['sput','sput-wide','sput-object','sput-boolean','sput-byte','sput-char','sput-short'];
                    sz=2; s=`${NS[op-0x67]} v${A}, ${fref(iw(pc+1))}`; break;
                }
                case 0x6e: case 0x6f: case 0x70: case 0x71: case 0x72: {
                    const NS=['invoke-virtual','invoke-super','invoke-direct','invoke-static','invoke-interface'];
                    sz=3; const w1=iw(pc+1), w2=iw(pc+2);
                    const cnt=(w0>>12)&0xF, ref=w1;
                    const regsArr=[w2&0xF,(w2>>4)&0xF,(w2>>8)&0xF,(w2>>12)&0xF,(w0>>8)&0xF].slice(0,cnt).map(r=>`v${r}`).join(', ');
                    s=`${NS[op-0x6e]} {${regsArr}}, ${mref(ref)}`; break;
                }
                case 0x74: case 0x75: case 0x76: case 0x77: case 0x78: {
                    const NS=['invoke-virtual/range','invoke-super/range','invoke-direct/range','invoke-static/range','invoke-interface/range'];
                    sz=3; const w1=iw(pc+1), w2=iw(pc+2);
                    s=`${NS[op-0x74]} {v${w2} .. v${w2+A-1}}, ${mref(w1)}`; break;
                }
                case 0x7b: s=`neg-int v${a}, v${bN}`; break;
                case 0x7c: s=`not-int v${a}, v${bN}`; break;
                case 0x7d: s=`neg-long v${a}, v${bN}`; break;
                case 0x7e: s=`not-long v${a}, v${bN}`; break;
                case 0x7f: s=`neg-float v${a}, v${bN}`; break;
                case 0x80: s=`neg-double v${a}, v${bN}`; break;
                case 0x81: s=`int-to-long v${a}, v${bN}`; break;
                case 0x82: s=`int-to-float v${a}, v${bN}`; break;
                case 0x83: s=`int-to-double v${a}, v${bN}`; break;
                case 0x84: s=`long-to-int v${a}, v${bN}`; break;
                case 0x85: s=`long-to-float v${a}, v${bN}`; break;
                case 0x86: s=`long-to-double v${a}, v${bN}`; break;
                case 0x87: s=`float-to-int v${a}, v${bN}`; break;
                case 0x88: s=`float-to-long v${a}, v${bN}`; break;
                case 0x89: s=`float-to-double v${a}, v${bN}`; break;
                case 0x8a: s=`double-to-int v${a}, v${bN}`; break;
                case 0x8b: s=`double-to-long v${a}, v${bN}`; break;
                case 0x8c: s=`double-to-float v${a}, v${bN}`; break;
                case 0x8d: s=`int-to-byte v${a}, v${bN}`; break;
                case 0x8e: s=`int-to-char v${a}, v${bN}`; break;
                case 0x8f: s=`int-to-short v${a}, v${bN}`; break;
                case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95:
                case 0x96: case 0x97: case 0x98: case 0x99: case 0x9a: case 0x9b:
                case 0x9c: case 0x9d: case 0x9e: case 0x9f: case 0xa0: case 0xa1:
                case 0xa2: case 0xa3: case 0xa4: case 0xa5: case 0xa6: case 0xa7:
                case 0xa8: case 0xa9: case 0xaa: case 0xab: case 0xac: case 0xad:
                case 0xae: case 0xaf: {
                    const NS=['add-int','sub-int','mul-int','div-int','rem-int','and-int','or-int','xor-int','shl-int','shr-int','ushr-int','add-long','sub-long','mul-long','div-long','rem-long','and-long','or-long','xor-long','shl-long','shr-long','ushr-long','add-float','sub-float','mul-float','div-float','rem-float','add-double','sub-double','mul-double','div-double','rem-double'];
                    sz=2; const w1=iw(pc+1); s=`${NS[op-0x90]||'op'} v${A}, v${w1&0xFF}, v${(w1>>8)&0xFF}`; break;
                }
                case 0xb0: case 0xb1: case 0xb2: case 0xb3: case 0xb4: case 0xb5:
                case 0xb6: case 0xb7: case 0xb8: case 0xb9: case 0xba: case 0xbb:
                case 0xbc: case 0xbd: case 0xbe: case 0xbf: case 0xc0: case 0xc1:
                case 0xc2: case 0xc3: case 0xc4: case 0xc5: case 0xc6: case 0xc7:
                case 0xc8: case 0xc9: case 0xca: case 0xcb: case 0xcc: case 0xcd:
                case 0xce: case 0xcf: {
                    const NS=['add-int','sub-int','mul-int','div-int','rem-int','and-int','or-int','xor-int','shl-int','shr-int','ushr-int','add-long','sub-long','mul-long','div-long','rem-long','and-long','or-long','xor-long','shl-long','shr-long','ushr-long','add-float','sub-float','mul-float','div-float','rem-float','add-double','sub-double','mul-double','div-double','rem-double'];
                    s=`${NS[op-0xb0]||'op'}/2addr v${a}, v${bN}`; break;
                }
                case 0xd0: case 0xd1: case 0xd2: case 0xd3: case 0xd4: case 0xd5: case 0xd6: case 0xd7: {
                    const NS=['add-int','rsub-int','mul-int','div-int','rem-int','and-int','or-int','xor-int'];
                    sz=2; s=`${NS[op-0xd0]||'op'}/lit16 v${a}, v${bN}, #${sw(pc+1)}`; break;
                }
                case 0xd8: case 0xd9: case 0xda: case 0xdb: case 0xdc: case 0xdd:
                case 0xde: case 0xdf: case 0xe0: case 0xe1: case 0xe2: {
                    const NS=['add-int','rsub-int','mul-int','div-int','rem-int','and-int','or-int','xor-int','shl-int','shr-int','ushr-int'];
                    sz=2; const w1=iw(pc+1); const l8=(w1>>8)&0xFF; const sl8=l8>=128?l8-256:l8;
                    s=`${NS[op-0xd8]||'op'}/lit8 v${A}, v${w1&0xFF}, #${sl8}`; break;
                }
                default:
                    s=`# 0x${op.toString(16).padStart(2,'0')} (unknown)`;
                    break;
            }
            out.push(`    ${s}`);
            pc += sz;
        }
        if (pc < insn_count) out.push(`    # ... ${insn_count - pc} more instructions (capped)`);
        return out.join('\n');
    } catch(e) { return `    # disassembly error: ${e.message}`; }
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
            return `"${strings[i].replace(/\\/g,'\\\\').replace(/"/g,'\\"').replace(/\n/g,'\\n').replace(/\r/g,'\\r').slice(0,200)}"`;
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
                case 0x02: insn.sz = 2; insn.type = 'move'; insn.dst = A; insn.src = iw(pc+1); break;
                case 0x03: insn.sz = 3; insn.type = 'move'; insn.dst = iw(pc+1); insn.src = iw(pc+2); break;
                case 0x04: insn.type = 'move'; insn.dst = a; insn.src = bN; break;
                case 0x05: insn.sz = 2; insn.type = 'move'; insn.dst = A; insn.src = iw(pc+1); break;
                case 0x06: insn.sz = 3; insn.type = 'move'; insn.dst = iw(pc+1); insn.src = iw(pc+2); break;
                case 0x07: insn.type = 'move'; insn.dst = a; insn.src = bN; break;
                case 0x08: insn.sz = 2; insn.type = 'move'; insn.dst = A; insn.src = iw(pc+1); break;
                case 0x09: insn.sz = 3; insn.type = 'move'; insn.dst = iw(pc+1); insn.src = iw(pc+2); break;
                case 0x0a: insn.type = 'move_result'; insn.dst = A; break;
                case 0x0b: insn.type = 'move_result'; insn.dst = A; break;
                case 0x0c: insn.type = 'move_result'; insn.dst = A; break;
                case 0x0d: insn.type = 'move_exception'; insn.dst = A; break;
                case 0x0e: insn.type = 'return_void'; break;
                case 0x0f: insn.type = 'return'; insn.src = A; break;
                case 0x10: insn.type = 'return'; insn.src = A; break;
                case 0x11: insn.type = 'return'; insn.src = A; break;
                case 0x12: { const lit = (bN & 8) ? bN - 16 : bN; insn.type = 'const'; insn.dst = a; insn.literal = lit; break; }
                case 0x13: insn.sz = 2; insn.type = 'const'; insn.dst = A; insn.literal = sw(pc+1); break;
                case 0x14: insn.sz = 3; insn.type = 'const'; insn.dst = A; insn.literal = (iw(pc+2) << 16) | iw(pc+1); break;
                case 0x15: insn.sz = 2; insn.type = 'const'; insn.dst = A; insn.literal = iw(pc+1) << 16; break;
                case 0x16: insn.sz = 2; insn.type = 'const_wide'; insn.dst = A; insn.literal = sw(pc+1); break;
                case 0x17: insn.sz = 3; insn.type = 'const_wide'; insn.dst = A; insn.literal = (iw(pc+2) << 16) | iw(pc+1); break;
                case 0x18: insn.sz = 5; insn.type = 'const_wide'; insn.dst = A; insn.literal = 0; break;
                case 0x19: insn.sz = 2; insn.type = 'const_wide'; insn.dst = A; insn.literal = 0; break;
                case 0x1a: insn.sz = 2; insn.type = 'const_string'; insn.dst = A; insn.stringIdx = iw(pc+1); break;
                case 0x1b: insn.sz = 3; insn.type = 'const_string'; insn.dst = A; insn.stringIdx = (iw(pc+2) << 16) | iw(pc+1); break;
                case 0x1c: insn.sz = 2; insn.type = 'const_class'; insn.dst = A; insn.typeIdx = iw(pc+1); break;
                case 0x1d: insn.type = 'monitor_enter'; insn.src = A; break;
                case 0x1e: insn.type = 'monitor_exit'; insn.src = A; break;
                case 0x1f: insn.sz = 2; insn.type = 'check_cast'; insn.dst = A; insn.typeIdx = iw(pc+1); break;
                case 0x20: insn.sz = 2; insn.type = 'instance_of'; insn.dst = a; insn.src = bN; insn.typeIdx = iw(pc+1); break;
                case 0x21: insn.type = 'array_length'; insn.dst = a; insn.src = bN; break;
                case 0x22: insn.sz = 2; insn.type = 'new_instance'; insn.dst = A; insn.typeIdx = iw(pc+1); break;
                case 0x23: insn.sz = 2; insn.type = 'new_array'; insn.dst = a; insn.src = bN; insn.typeIdx = iw(pc+1); break;
                case 0x24: { insn.sz = 3; const cnt = (w0 >> 12) & 0xF; const w2 = iw(pc+2);
                    insn.type = 'filled_new_array'; insn.typeIdx = iw(pc+1);
                    insn.args = [w2&0xF,(w2>>4)&0xF,(w2>>8)&0xF,(w2>>12)&0xF,A].slice(0,cnt); break; }
                case 0x25: { insn.sz = 3; insn.type = 'filled_new_array_range'; insn.typeIdx = iw(pc+1);
                    const start = iw(pc+2); insn.args = []; for (let r = 0; r < A; r++) insn.args.push(start+r); break; }
                case 0x26: insn.sz = 3; insn.type = 'fill_array_data'; insn.dst = A; break;
                case 0x27: insn.type = 'throw'; insn.src = A; break;
                case 0x28: { const o8 = (A >= 128 ? A - 256 : A); insn.type = 'goto'; insn.target = pc + o8; break; }
                case 0x29: insn.sz = 2; insn.type = 'goto'; insn.target = pc + sw(pc+1); break;
                case 0x2a: insn.sz = 3; insn.type = 'goto'; insn.target = pc + ((iw(pc+2) << 16) | iw(pc+1)); break;
                case 0x2b: insn.sz = 2; insn.type = 'switch'; insn.src = A; break;
                case 0x2c: insn.sz = 2; insn.type = 'switch'; insn.src = A; break;
                case 0x2d: case 0x2e: case 0x2f: case 0x30: case 0x31: {
                    insn.sz = 2; const w1 = iw(pc+1);
                    insn.type = 'cmp'; insn.dst = A; insn.srcA = w1 & 0xFF; insn.srcB = (w1 >> 8) & 0xFF; break;
                }
                case 0x32: case 0x33: case 0x34: case 0x35: case 0x36: case 0x37: {
                    insn.sz = 2; insn.type = 'if';
                    const CMP = ['==','!=','<','>=','>','<='];
                    insn.cmp = CMP[op - 0x32]; insn.srcA = a; insn.srcB = bN; insn.target = pc + sw(pc+1); break;
                }
                case 0x38: case 0x39: case 0x3a: case 0x3b: case 0x3c: case 0x3d: {
                    insn.sz = 2; insn.type = 'ifz';
                    const CMP = ['==','!=','<','>=','>','<='];
                    insn.cmp = CMP[op - 0x38]; insn.src = A; insn.target = pc + sw(pc+1); break;
                }
                case 0x44: case 0x45: case 0x46: case 0x47: case 0x48: case 0x49: case 0x4a: {
                    insn.sz = 2; const w1 = iw(pc+1);
                    insn.type = 'aget'; insn.dst = A; insn.arr = w1 & 0xFF; insn.idx = (w1 >> 8) & 0xFF; break;
                }
                case 0x4b: case 0x4c: case 0x4d: case 0x4e: case 0x4f: case 0x50: case 0x51: {
                    insn.sz = 2; const w1 = iw(pc+1);
                    insn.type = 'aput'; insn.src = A; insn.arr = w1 & 0xFF; insn.idx = (w1 >> 8) & 0xFF; break;
                }
                case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57: case 0x58: {
                    insn.sz = 2; insn.type = 'iget'; insn.dst = a; insn.obj = bN; insn.fieldIdx = iw(pc+1); break;
                }
                case 0x59: case 0x5a: case 0x5b: case 0x5c: case 0x5d: case 0x5e: case 0x5f: {
                    insn.sz = 2; insn.type = 'iput'; insn.src = a; insn.obj = bN; insn.fieldIdx = iw(pc+1); break;
                }
                case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65: case 0x66: {
                    insn.sz = 2; insn.type = 'sget'; insn.dst = A; insn.fieldIdx = iw(pc+1); break;
                }
                case 0x67: case 0x68: case 0x69: case 0x6a: case 0x6b: case 0x6c: case 0x6d: {
                    insn.sz = 2; insn.type = 'sput'; insn.src = A; insn.fieldIdx = iw(pc+1); break;
                }
                case 0x6e: case 0x6f: case 0x70: case 0x71: case 0x72: {
                    insn.sz = 3; const w1 = iw(pc+1); const w2 = iw(pc+2);
                    const cnt = (w0 >> 12) & 0xF;
                    const KINDS = ['virtual','super','direct','static','interface'];
                    insn.type = 'invoke'; insn.kind = KINDS[op - 0x6e]; insn.methodIdx = w1;
                    insn.args = [w2&0xF,(w2>>4)&0xF,(w2>>8)&0xF,(w2>>12)&0xF,(w0>>8)&0xF].slice(0,cnt);
                    break;
                }
                case 0x74: case 0x75: case 0x76: case 0x77: case 0x78: {
                    insn.sz = 3; const w1 = iw(pc+1); const w2 = iw(pc+2);
                    const KINDS = ['virtual','super','direct','static','interface'];
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
                    const CASTS = ['(long)','(float)','(double)','(int)','(float)','(double)',
                                   '(int)','(long)','(double)','(int)','(long)','(float)'];
                    insn.type = 'cast'; insn.dst = a; insn.src = bN; insn.castTo = CASTS[op-0x81]; break;
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
                    const OPS = ['+','-','*','/',  '%','&','|','^','<<','>>','>>>',
                                 '+','-','*','/',  '%','&','|','^','<<','>>','>>>',
                                 '+','-','*','/',  '%',
                                 '+','-','*','/',  '%'];
                    insn.sz = 2; const w1 = iw(pc+1);
                    insn.type = 'binop'; insn.dst = A; insn.srcA = w1 & 0xFF; insn.srcB = (w1 >> 8) & 0xFF;
                    insn.bop = OPS[op - 0x90] || '+'; break;
                }
                case 0xb0: case 0xb1: case 0xb2: case 0xb3: case 0xb4: case 0xb5:
                case 0xb6: case 0xb7: case 0xb8: case 0xb9: case 0xba: case 0xbb:
                case 0xbc: case 0xbd: case 0xbe: case 0xbf: case 0xc0: case 0xc1:
                case 0xc2: case 0xc3: case 0xc4: case 0xc5: case 0xc6: case 0xc7:
                case 0xc8: case 0xc9: case 0xca: case 0xcb: case 0xcc: case 0xcd:
                case 0xce: case 0xcf: {
                    const OPS = ['+','-','*','/',  '%','&','|','^','<<','>>','>>>',
                                 '+','-','*','/',  '%','&','|','^','<<','>>','>>>',
                                 '+','-','*','/',  '%',
                                 '+','-','*','/',  '%'];
                    insn.type = 'binop2addr'; insn.dst = a; insn.srcB = bN;
                    insn.bop = OPS[op - 0xb0] || '+'; break;
                }
                case 0xd0: case 0xd1: case 0xd2: case 0xd3: case 0xd4: case 0xd5: case 0xd6: case 0xd7: {
                    const OPS = ['+','-','*','/','%','&','|','^'];
                    insn.sz = 2; insn.type = 'binop_lit'; insn.dst = a; insn.src = bN; insn.literal = sw(pc+1);
                    insn.bop = OPS[op - 0xd0] || '+'; break;
                }
                case 0xd8: case 0xd9: case 0xda: case 0xdb: case 0xdc: case 0xdd:
                case 0xde: case 0xdf: case 0xe0: case 0xe1: case 0xe2: {
                    const OPS = ['+','-','*','/','%','&','|','^','<<','>>','>>>'];
                    insn.sz = 2; const w1 = iw(pc+1);
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
                    setReg(ins.dst, `new ${t.replace('[]','')}[${reg(ins.src)}]`, t, i);
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
                    const INV = {'==':'!=','!=':'==','<':'>=','>=':'<','>':'<=','<=':'>'};
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
                    const INV = {'==':'!=','!=':'==','<':'>=','>=':'<','>':'<=','<=':'>'};
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
                    setReg(ins.dst, `${ins.castTo} ${reg(ins.src)}`, ins.castTo.replace(/[()]/g,''), i);
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
    if (cls.srcFile)   L.push(`.source "${cls.srcFile}"`);
    for (const iface of (cls.interfaces || [])) L.push(`.implements ${iface}`);
    L.push('');
    const sF = (cls.fields||[]).filter(f => f.isStatic);
    const iF = (cls.fields||[]).filter(f => !f.isStatic);
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
    for (const m of (cls.methods||[]).slice(0, 80)) {
        const params = (m.paramTypes||[]).join('');
        const ret    = m.returnType || 'V';
        L.push(`.method ${smaliFlags(m.af||0)} ${m.name}(${params})${ret}`);
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
    const KW  = /\b(package|import|class|interface|enum|extends|implements|new|return|if|else|while|for|do|try|catch|finally|throw|throws|super|this|null|true|false|instanceof)\b/g;
    const MOD = /\b(public|private|protected|static|final|abstract|synchronized|native|transient|volatile|strictfp)\b/g;
    const PRIM = /\b(void|boolean|byte|short|char|int|long|float|double)\b/g;
    return raw.split('\n').map((line, idx) => {
        let s = esc(line);
        const ci = s.indexOf('//');
        let code = ci >= 0 ? s.slice(0, ci) : s;
        const cmt = ci >= 0 ? `<span class="sc">${s.slice(ci)}</span>` : '';
        code = code.replace(/(&quot;(?:[^&]|&amp;|&lt;|&gt;)*?&quot;|&#39;(?:[^&]|&amp;)*?&#39;)/g, '<span class="ss">$1</span>');
        code = code.replace(KW,   '<span class="sk">$1</span>');
        code = code.replace(MOD,  '<span class="sm">$1</span>');
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
    const R = apkState.analysisResults;
    if (!R || !R.manifestStr) { showToast('No manifest available', 'error'); return; }
    navigator.clipboard.writeText(R.manifestStr).then(() => showToast('Manifest copied!', 'success')).catch(() => showToast('Copy failed', 'error'));
}

function downloadManifestFile() {
    const R = apkState.analysisResults;
    if (!R || !R.manifestStr) { showToast('No manifest available', 'error'); return; }
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([R.manifestStr], { type: 'text/xml' }));
    a.download = 'AndroidManifest.xml'; a.click();
}

function renderOverviewTab(R) {
    const g = apkState.groupedFindings;
    document.getElementById('overviewStats').innerHTML = `
    <div class="stat-card findings-card">
        <div class="stat-card-header"><span class="stat-card-label">Findings</span><div class="stat-card-icon accent"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg></div></div>
        <div class="findings-vertical">
            <div class="finding-row warning"><span class="count">${g.issue.length}</span><span class="label">Issues</span></div>
        </div>
    </div>
    <div class="stat-card">
        <div class="stat-card-header"><span class="stat-card-label">Components</span><div class="stat-card-icon cyan"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg></div></div>
        <div class="stat-card-value">${R.components.activities.length + R.components.services.length + R.components.receivers.length + R.components.providers.length}</div>
        <div class="stat-card-desc">${R.components.activities.filter(c => c.exported === true || c.exported === 'true').length + R.components.services.filter(c => c.exported === true || c.exported === 'true').length} exported</div>
    </div>
    <div class="stat-card">
        <div class="stat-card-header"><span class="stat-card-label">Permissions</span><div class="stat-card-icon orange"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div></div>
        <div class="stat-card-value">${R.permissions.length}</div><div class="stat-card-desc">${R.dangerousPerms.length} dangerous</div>
    </div>
    <div class="stat-card">
        <div class="stat-card-header"><span class="stat-card-label">Files</span><div class="stat-card-icon cyan"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/></svg></div></div>
        <div class="stat-card-value">${R.files.length}</div><div class="stat-card-desc">${R.dexFiles.length} DEX · ${R.nativeLibs.length} native</div>
    </div>
    <div class="stat-card">
        <div class="stat-card-header"><span class="stat-card-label">Trackers</span><div class="stat-card-icon green"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></div></div>
        <div class="stat-card-value">${R.trackers.length}</div><div class="stat-card-desc">SDKs detected</div>
    </div>`;

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
        ${ci ? ir('Cert Subject', Object.entries(ci.subject).map(([k,v]) => `${k}=${esc(v)}`).join(', ') || '—') : ''}
        ${ci ? ir('Cert Algorithm', `<span style="color:${['MD5withRSA','SHA1withRSA'].includes(ci.sigAlg)?'var(--red)':'var(--green)'}">${esc(ci.sigAlg) || '—'}</span>`) : ''}
        ${ci ? ir('Cert Validity', `${ci.validity?.notBefore || '?'} → ${ci.validity?.notAfter || '?'}${ci.isExpired ? ' <span style="color:var(--red)">(EXPIRED)</span>' : ''}`) : ''}
        ${ci ? ir('Debug Cert', ci.isDebug ? '<span style="color:var(--red)">Yes -debug signed!</span>' : '<span style="color:var(--green)">No</span>') : ''}
    </div>`;

    const pEl = document.getElementById('permissionsList');
    pEl.innerHTML = R.permissions.length ? R.permissions.map(p => {
        const d = DANGEROUS_PERMS.has(p);
        return `<div class="perm-item ${d?'danger':'normal'}"><span class="perm-icon" style="color:${d?'var(--red)':'var(--orange)'}">${d?'&#9679;':'&#9675;'}</span><div><div class="perm-name">${esc(p)}</div><div class="perm-full">android.permission.${esc(p)}</div></div>${d?'<span class="badge-danger">Dangerous</span>':''}</div>`;
    }).join('') : '<div class="no-data">No permissions declared</div>';

    const cEl = document.getElementById('componentsList');
    const cmp = R.components;
    const mkComp = (arr, type) => arr.map(c => {
        const exp = c.exported === true || c.exported === 'true';
        return `<div class="comp-item ${exp?'exported':''}"><span class="comp-type">${type}</span><span class="comp-name">${esc(c.name.split('.').pop())}</span>${exp&&!c.permission?'<span class="badge-danger">Exported</span>':exp?'<span class="badge-warn">Exported</span>':''}</div>`;
    }).join('');
    cEl.innerHTML = mkComp(cmp.activities,'Activity') + mkComp(cmp.services,'Service') + mkComp(cmp.receivers,'Receiver') + mkComp(cmp.providers,'Provider') || '<div class="no-data">No components found</div>';

    document.getElementById('trackersList').innerHTML = R.trackers.length
        ? R.trackers.map(t => `<div class="tracker-item"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:13px;height:13px;opacity:.5;flex-shrink:0"><circle cx="12" cy="12" r="10"/></svg>${esc(t)}</div>`).join('')
        : '<div class="no-data">No known third-party SDKs detected</div>';
}
function ir(k, v) { return `<div class="info-row"><span class="info-key">${esc(k)}</span><span class="info-val">${v}</span></div>`; }

function renderFindingsTab() {
    const q = (document.getElementById('findingsSearch')?.value || '').toLowerCase();
    let all = [...apkState.groupedFindings.issue];
    
    if (q) {
        all = all.filter(f => 
            (f.ruleName || '').toLowerCase().includes(q) || 
            (f.description || '').toLowerCase().includes(q) ||
            (f.cwe || '').toLowerCase().includes(q) ||
            (f.masvs || '').toLowerCase().includes(q)
        );
    }

    const renderMatch = m => {
        const file = m.file || '';
        return `<div class="finding-match-item"><code>${esc((m.match||'').slice(0,150))}</code><span class="match-loc finding-goto" data-file="${esc(file)}" data-line="${m.line||''}">${esc(file)}${m.line?':'+m.line:''}</span></div>`;
    };

    document.getElementById('findingsList').innerHTML = all.map((f, idx) => {
        const countBadge = f.count > 1 ? `<span class="finding-count">${f.count}</span>` : '';
        let matchesHtml = '';
        if (f.matches && f.matches.length > 0) {
            if (f.matches.length === 1) {
                matchesHtml = `<div class="finding-matches">${renderMatch(f.matches[0])}</div>`;
            } else {
                matchesHtml = `<div class="finding-matches">${renderMatch(f.matches[0])}<button class="finding-expand-btn" data-target="fml_${idx}" data-total="${f.matches.length}">Show ${f.matches.length} more</button><div id="fml_${idx}" class="finding-match-list" style="display:none">${f.matches.slice(1).map(renderMatch).join('')}</div></div>`;
            }
        }
        const tags = [
            f.cwe ? `<span class="tag">${esc(f.cwe)}</span>` : '',
            f.owasp ? `<span class="tag">OWASP M${esc(f.owasp.replace('M',''))}</span>` : '',
            f.masvs ? `<span class="tag">MASVS-${esc(f.masvs)}</span>` : ''
        ].filter(Boolean).join('');

        return `
            <div class="finding-card compact-finding" data-severity="${f.severity}">
                <div class="finding-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                    <div style="display:flex;align-items:center;gap:12px;flex:1">
                        <span class="sev-badge sev-${f.severity}">${f.severity.slice(0,1).toUpperCase()}</span>
                        <span class="finding-title" style="font-size:13px;font-weight:600">${esc(f.ruleName)}</span>
                    </div>
                    <div style="display:flex;align-items:center;gap:8px">
                        ${tags}
                        ${countBadge}
                        <span class="chevron" style="opacity:0.3;font-size:10px">▼</span>
                    </div>
                </div>
                <div class="finding-details hidden" style="padding-top:12px;margin-top:8px;border-top:1px solid rgba(255,255,255,0.05)">
                    <p class="finding-desc" style="margin-bottom:12px;font-size:12px;line-height:1.5">${esc(f.description)}</p>
                    ${matchesHtml}
                </div>
            </div>`;
    }).join('') || `<div class="no-data">${q ? 'No results matching search' : 'No findings'}</div>`;
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

function renderSmaliTab(R) {
    const total = apkState.dexParsed.reduce((s, d) => s + d.classes.length, 0);
    const totalM = apkState.dexParsed.reduce((s, d) => s + d.methods.length, 0);
    document.getElementById('smaliInfo').innerHTML = `<div class="dex-stats">
        ${R.dexFiles.map(d => `<div class="dex-stat-card"><div class="dex-name">${esc(d.name)}</div><div class="dex-nums"><span>${d.classes} classes</span><span>${d.methods} methods</span><span>${d.strings} strings</span></div></div>`).join('')}
        <div class="dex-stat-card total"><div class="dex-name">Totals</div><div class="dex-nums"><span>${total} classes</span><span>${totalM} methods</span><span>${R.strings.length} strings</span></div></div>
    </div>`;
    const treeEl = document.getElementById('smaliTree');
    if (!R.dexFiles.length) {
        treeEl.innerHTML = '<div style="padding:16px;text-align:center;color:var(--text-muted);font-size:12px">No DEX files found</div>';
    } else {
        renderSmaliTree(treeEl, apkState.smaliTree);
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
        const isAbst  = (node._cls.flags & 0x0400) !== 0;
        const icon = isIface ? '&#11041;' : isAbst ? '&#9672;' : '&#9670;';
        const col  = isIface ? 'var(--cyan)' : isAbst ? 'var(--orange)' : 'var(--accent-primary)';
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
    if (!q) { renderSmaliTree(el, apkState.smaliTree); return; }
    el.innerHTML = '';
    const lq = q.toLowerCase();
    const results = [];
    function walk(tree) {
        for (const [, node] of Object.entries(tree)) {
            if (node._type === 'class') { if (node._fqn.toLowerCase().includes(lq)) results.push(node); }
            else if (node._type === 'pkg') walk(node._ch);
        }
    }
    walk(apkState.smaliTree);
    if (!results.length) { el.innerHTML = '<div style="padding:12px 16px;color:var(--text-muted);font-size:12px">No results</div>'; return; }
    results.slice(0, 200).forEach(node => {
        const isIface = (node._cls.flags & 0x0200) !== 0;
        const isAbst  = (node._cls.flags & 0x0400) !== 0;
        const icon = isIface ? '&#11041;' : isAbst ? '&#9672;' : '&#9670;';
        const col  = isIface ? 'var(--cyan)' : isAbst ? 'var(--orange)' : 'var(--accent-primary)';
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
        <button class="stab" onclick="showStringsTab(this,'stab-all')">All Strings (${Math.min(R.strings.length,1000)})</button>
    </div>
    <div id="stab-interesting" class="strings-list active">${interesting.map(s => `<div class="str-item">${esc(s)}</div>`).join('') || '<div class="no-data">No interesting strings</div>'}</div>
    <div id="stab-urls" class="strings-list">${urls.map(s => `<div class="str-item url">${esc(s)}</div>`).join('') || '<div class="no-data">No URLs found</div>'}</div>
    <div id="stab-all" class="strings-list">${R.strings.slice(0,1000).map(s => `<div class="str-item">${esc(s)}</div>`).join('')}</div>`;
}

function showStringsTab(btn, id) {
    document.querySelectorAll('.stab').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.strings-list').forEach(l => l.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(id)?.classList.add('active');
}

function showSmaliClass(cls, fqn, dexIdx) {
    apkState.currentViewClass = cls;
    apkState.currentViewFqn = fqn;
    apkState.currentViewDexIdx = dexIdx ?? 0;

    const simple = fqn.split('.').pop();
    const mCnt = (cls.methods||[]).length, fCnt = (cls.fields||[]).length;

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
    apkState.currentViewMode = mode;
    document.querySelectorAll('.jadx-toggle-btn').forEach(b =>
        b.classList.toggle('active', b.dataset.view === mode));
    renderCodeView();
}

function renderCodeView() {
    const cls = apkState.currentViewClass;
    if (!cls) return;
    const fqn = apkState.currentViewFqn;
    const simple = (fqn || '').split('.').pop();
    const dex = apkState.dexParsed[apkState.currentViewDexIdx ?? 0];
    const mode = apkState.currentViewMode;

    const ext = mode === 'java' ? '.java' : '.smali';
    document.getElementById('jadxFileName').textContent = simple + ext;

    document.querySelectorAll('.jadx-toggle-btn').forEach(b =>
        b.classList.toggle('active', b.dataset.view === mode));

    let code, highlighted;
    if (mode === 'java') {
        if (apkState.javaCache.has(fqn)) {
            code = apkState.javaCache.get(fqn);
        } else {
            code = dex
                ? generateJavaView(cls, dex.buf, dex.strings, dex.types, dex.methods, dex.fields || [])
                : generateJavaView(cls, null, [], [], [], []);
            apkState.javaCache.set(fqn, code);
        }
        highlighted = highlightJava(code);
    } else {
        code = dex
            ? generateSmaliView(cls, dex.buf, dex.strings, dex.types, dex.methods, dex.fields || [])
            : generateSmaliView(cls, null, [], [], [], []);
        highlighted = highlightSmali(code);
    }

    document.getElementById('jadxCode').innerHTML = `<div class="cwl">${highlighted}</div>`;
    if(typeof _activeSearchQuery==='string'&&_activeSearchQuery.length>0) setTimeout(()=>applyCodeSearch(_activeSearchQuery),50);
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
    apkState.explorerView = mode;
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
        apkState.currentViewMode = mode;
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
    for (let dexIdx = 0; dexIdx < apkState.dexParsed.length; dexIdx++) {
        const dex = apkState.dexParsed[dexIdx];
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

    const dex = apkState.dexParsed[dexIdx ?? 0];
    let code, highlighted;
    if (ext === 'java') {
        if (apkState.javaCache.has(fqn)) {
            code = apkState.javaCache.get(fqn);
        } else {
            code = dex
                ? generateJavaView(cls, dex.buf, dex.strings, dex.types, dex.methods, dex.fields || [])
                : generateJavaView(cls, null, [], [], [], []);
            apkState.javaCache.set(fqn, code);
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
    apkState.inspectorData = allComps;
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
        ...exported.activities.map(c => ({...c, _type: 'activity'})),
        ...exported.services.map(c => ({...c, _type: 'service'})),
        ...exported.receivers.map(c => ({...c, _type: 'receiver'})),
        ...exported.providers.map(c => ({...c, _type: 'provider'}))
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
        if (intents.length) intentHtml += `<div class="comp-intents">Actions: ${intents.map(a => esc(a.replace('android.intent.action.',''))).join(', ')}</div>`;
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
    } catch(e) {

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
    const M = { dex:'&#9638;', xml:'&#9671;', json:'&#9671;', so:'&#9881;', png:'&#9633;', jpg:'&#9633;', class:'&#9670;', jar:'&#9638;', db:'&#9707;', sqlite:'&#9707;', properties:'&#9881;', html:'&#9671;', js:'&#9671;', txt:'&#9671;', mf:'&#9671;' };
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
        } else if (['json','properties','yaml'].includes(ext)) {
            codeEl.innerHTML = `<pre class="file-text" style="padding:12px">${esc(text.slice(0,50000))}</pre>`;
        } else {
            codeEl.innerHTML = `<pre class="file-text" style="padding:12px">${esc(text.slice(0,50000))}</pre>`;
        }
        if(typeof _activeSearchQuery==='string'&&_activeSearchQuery.length>0) setTimeout(()=>applyCodeSearch(_activeSearchQuery),50);
    };

    if (apkState.fileContents.has(path)) {
        showContent(apkState.fileContents.get(path));
        return;
    }
    const entry = apkState.zipContent?.file(path);
    if (!entry) { codeEl.innerHTML = `<div class="no-data">File not found in package</div>`; return; }
    codeEl.innerHTML = '<div class="no-data">Loading...</div>';
    try {
        if (['png','jpg','jpeg','gif','webp','bmp'].includes(ext)) {
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
                apkState.fileContents.set(path, rendered);
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
                                apkState.fileContents.set(path, xmlStr);
                                showContent(xmlStr);
                                return;
                            }
                        }
                    } catch(parseErr) { }
                }
                const text = new TextDecoder('utf-8', { fatal: false }).decode(data);
                const badChars = (text.match(/[\x00-\x08\x0E-\x1F]/g) || []).length;
                if (badChars / Math.max(text.length, 1) < 0.1 && text.length > 0) {
                    apkState.fileContents.set(path, text);
                    showContent(text);
                } else {
                    codeEl.innerHTML = `<div style="padding:12px"><div class="no-data" style="margin-bottom:8px">Binary XML file (${formatSize(data.byteLength)}) -compiled Android resource</div><pre class="file-hex">${hexDump(bytes, 512)}</pre></div>`;
                }
                return;
            } catch(e) {
                codeEl.innerHTML = `<div class="no-data">Cannot read file: ${esc(e.message)}</div>`;
                return;
            }
        }
        const text = await entry.async('string');
        apkState.fileContents.set(path, text);
        showContent(text);
    } catch(e) { codeEl.innerHTML = `<div class="no-data">Cannot display file: ${esc(e.message)}</div>`; }
}

function hexDump(bytes, limit = 512) {
    let out = 'Offset    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  ASCII\n' + '─'.repeat(72) + '\n';
    for (let i = 0; i < Math.min(bytes.length, limit); i += 16) {
        const row = bytes.slice(i, i + 16);
        const hex = Array.from(row).map((b, j) => (j === 8 ? ' ' : '') + (b < 16 ? '0' : '') + b.toString(16).toUpperCase()).join(' ');
        const ascii = Array.from(row).map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join('');
        out += `${i.toString(16).padStart(8,'0')}  ${hex.padEnd(50)}  ${ascii}\n`;
    }
    if (bytes.length > limit) out += `\n... ${bytes.length - limit} more bytes`;
    return out;
}

function exportReport() {
    const R = apkState.analysisResults;
    if (!R) { showToast('No analysis results to export', 'error'); return; }
    try {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
        const W = 210, M = 15, maxW = W - 2 * M; let y = M;
        const newPg = () => { doc.addPage(); y = M; };
        const ln = (h = 5) => { y += h; if (y > 275) newPg(); };
        const row = (k, v) => { doc.setFontSize(9); doc.setTextColor(100,100,100); doc.text(k, M, y); doc.setTextColor(30,30,30); doc.text(String(v).slice(0,90), M + 38, y); ln(5); };
        const heading = (s) => { ln(3); doc.setFontSize(11); doc.setTextColor(30,30,100); doc.text(s, M, y); ln(2); doc.setDrawColor(180,180,200); doc.line(M, y, W - M, y); ln(5); };
        doc.setFillColor(30,30,80); doc.rect(0,0,W,35,'F');
        doc.setFontSize(18); doc.setTextColor(255,255,255); doc.text('APK Auditor - Security Report', M, 16);
        doc.setFontSize(9); doc.setTextColor(200,200,220); doc.text(R.appInfo.packageName || R.appInfo.fileName, M, 24);
        doc.setFontSize(8); doc.setTextColor(180,180,200); doc.text(new Date().toISOString().split('T')[0], M, 30);
        y = 42;

        const g = apkState.groupedFindings;

        heading('Application');
        row('Package', R.appInfo.packageName || R.appInfo.fileName);
        row('Size', R.appInfo.fileSize);
        row('Min SDK', R.minSdk ? 'API ' + R.minSdk + ' (Android ' + sdkToVer(R.minSdk) + ')' : '-');
        row('Target SDK', R.targetSdk ? 'API ' + R.targetSdk + ' (Android ' + sdkToVer(R.targetSdk) + ')' : '-');
        row('Permissions', R.permissions.length + ' (' + R.dangerousPerms.length + ' dangerous)');
        if (R.certInfo) row('Signing', (R.certInfo.sigAlg || '?') + (R.certInfo.isDebug ? ' [DEBUG]' : ''));
        row('Issues Found', g.issue.length);

        doc.setFontSize(8); doc.setTextColor(120,120,120);
        doc.splitTextToSize('Note: All findings are from automated static analysis and require manual verification. False positives may occur. Each issue should be validated in context before reporting.', maxW).forEach(l => { doc.text(l, M, y); ln(4); });
        ln(4);

        if (g.issue.length) {
            heading('Issues (' + g.issue.length + ')');
            for (const f of g.issue) {
                if (y > 260) newPg();
                const cnt = f.count > 1 ? ' [' + f.count + 'x]' : '';
                doc.setFontSize(10); doc.setTextColor(50,50,50);
                doc.text(f.ruleName + cnt, M, y); ln(5);
                doc.setFontSize(8); doc.setTextColor(80,80,80);
                doc.splitTextToSize(f.description.slice(0,250), maxW - 4).forEach(l => { doc.text(l, M+2, y); ln(4); });
                if (f.matches && f.matches.length) {
                    doc.setFontSize(7); doc.setTextColor(100,70,30);
                    for (const m of f.matches) {
                        if (y > 272) newPg();
                        const loc = (m.file||'') + (m.line ? ':'+m.line : '');
                        doc.text('  ' + (m.match||'').slice(0,85) + (loc ? '  [' + loc + ']' : ''), M+2, y);
                        ln(3.5);
                    }
                }
                if (f.cwe) { doc.setFontSize(7); doc.setTextColor(140,140,140); doc.text(f.cwe, M+2, y); ln(3); }
                ln(2);
            }
        }

        const exported = [...R.components.activities,...R.components.services,...R.components.receivers,...R.components.providers].filter(c => c.exported===true||c.exported==='true');
        if (exported.length) {
            heading('Exported Components (' + exported.length + ')');
            doc.setFontSize(8); doc.setTextColor(60,60,60);
            for (const c of exported.slice(0,30)) { if (y>272) newPg(); doc.text((c.name||'?') + (c.permission?'':' [no perm]'), M+2, y); ln(4); }
        }

        if (R.trackers.length) {
            heading('SDKs & Trackers');
            doc.setFontSize(8); doc.setTextColor(60,60,60);
            doc.text(R.trackers.join(', '), M, y, { maxWidth: maxW }); ln(8);
        }

        if (R.dangerousPerms.length) {
            heading('Dangerous Permissions');
            doc.setFontSize(8); doc.setTextColor(60,60,60);
            doc.text(R.dangerousPerms.join(', '), M, y, { maxWidth: maxW }); ln(8);
        }

        if (y > 250) newPg();
        ln(6);
        doc.setDrawColor(180,180,200); doc.line(M, y, W - M, y); ln(5);
        doc.setFontSize(8); doc.setTextColor(130,130,130);
        doc.splitTextToSize('Disclaimer: This report is generated by automated static analysis. All findings are potential issues identified through pattern matching on decompiled code and manifest data. Results may include false positives and do not confirm exploitability. Manual verification and dynamic testing are required before including any finding in a security assessment.', maxW).forEach(l => { doc.text(l, M, y); ln(4); });

        doc.save('apk-report-' + (R.appInfo.packageName || 'unknown').replace(/\./g,'-') + '.pdf');
        showToast('Report exported!', 'success');
    } catch(e) { showToast('Export failed: ' + e.message, 'error'); }
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

async function startAnalysis(file, options = {}) {
    try {
        const results = await analyzeAPK(file, options);
        hideLoading();
        document.getElementById('landingContent').style.display = 'none';
        document.querySelector('.privacy-section').style.display = 'none';
        document.getElementById('appContainer').classList.add('active');
        const pkg = results.appInfo.packageName || results.appInfo.fileName.replace('.apk', '');
        document.getElementById('appName').textContent = pkg.split('.').pop() || pkg;
        document.getElementById('appPackage').textContent = pkg;
        const tot = apkState.groupedFindings.issue.length;
        document.getElementById('findingsCount').textContent = tot;
        renderOverviewTab(results);
        renderManifestTab(results);
        renderFindingsTab();
        renderSmaliTab(results);
        renderExplorerTab(results);
        renderInspectorTab(results);
        showToast('Analysis complete!', 'success');
    } catch(e) {

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
    if (apkState.currentViewClass && (apkState.explorerView === 'java' || apkState.explorerView === 'smali')) {
        const code = document.getElementById('jadxCode')?.innerText || '';
        const blob = new Blob([code], { type: 'text/plain' });
        const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
        a.download = p.split('.').pop() === p ? p + '.java' : p.split('/').pop();
        a.click(); return;
    }
    const e = apkState.zipContent?.file(p);
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
        apkState.currentViewMode = 'java';
        if (apkState.javaCache.has(fqn)) {
            var nameEl = document.getElementById('jadxFileName');
            var pathEl = document.getElementById('jadxFilePath');
            var metaEl = document.getElementById('jadxFileMeta');
            var codeEl = document.getElementById('jadxCode');
            var toggleEl = document.getElementById('jadxViewToggle');
            if (nameEl) nameEl.textContent = fqn.split('.').pop() + '.java';
            if (pathEl) pathEl.textContent = fqn;
            if (metaEl) metaEl.textContent = '';
            if (toggleEl) toggleEl.style.display = 'none';
            if (codeEl) codeEl.innerHTML = '<div class="cwl">' + highlightJava(apkState.javaCache.get(fqn)) + '</div>';
            highlightLine('#jadxCode', line);
        } else {
            for (var di = 0; di < apkState.dexParsed.length; di++) {
                var dex = apkState.dexParsed[di];
                var cls = (dex.classes || []).find(c => (c.name || '').replace(/^L/,'').replace(/;$/,'').replace(/\//g,'.') === fqn);
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
    openFile(file);
    highlightLine('#jadxCode', line);
}

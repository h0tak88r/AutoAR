/* IPA Auditor - iOS Security Analysis Tool | By Sandeep (https://www.linkedin.com/in/sandeepwawdane/) */
const state = {
    analysisResults: null,
    zipContent: null,
    appPath: null,
    findings: { high: [], warning: [], info: [], secure: [] },
    groupedFindings: { high: [], warning: [], info: [], secure: [] },
    fileContents: new Map(),
    binaryStrings: [],
    debug: true
};

function log(...args) {
    if (state.debug) console.log('[IPA-Auditor]', ...args);
}

class BinaryPlistParser {
    constructor(buffer) {

        if (buffer instanceof ArrayBuffer) {
            this.buffer = new Uint8Array(buffer);
            this.view = new DataView(buffer);
        } else if (buffer instanceof Uint8Array) {
            this.buffer = buffer;
            this.view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
        } else {
            throw new Error('Invalid buffer type');
        }
    }

    parse() {
        const magic = String.fromCharCode(...this.buffer.slice(0, 6));
        if (!magic.startsWith('bplist')) return null;

        try {

            const trailerOffset = this.buffer.length - 32;

            if (trailerOffset < 8) {
                console.error('Plist too small');
                return null;
            }

            const offsetSize = this.buffer[trailerOffset + 6];
            const objectRefSize = this.buffer[trailerOffset + 7];

            if (offsetSize === 0 || objectRefSize === 0 || offsetSize > 8 || objectRefSize > 8) {
                console.error('Invalid offset/ref size:', offsetSize, objectRefSize);
                return null;
            }

            const numObjects = this.readUIntBE(trailerOffset + 8, 8);
            const topObject = this.readUIntBE(trailerOffset + 16, 8);
            const offsetTableOffset = this.readUIntBE(trailerOffset + 24, 8);

            if (numObjects === 0 || offsetTableOffset >= this.buffer.length) {
                console.error('Invalid numObjects or offsetTableOffset');
                return null;
            }

            this.offsetSize = offsetSize;
            this.objectRefSize = objectRefSize;

            this.offsets = [];
            for (let i = 0; i < numObjects; i++) {
                const off = this.readUIntBE(offsetTableOffset + i * offsetSize, offsetSize);
                this.offsets.push(off);
            }

            return this.parseObject(topObject);
        } catch (e) {
            console.error('Binary plist parse error:', e);
            return null;
        }
    }

    readUIntBE(offset, size) {
        let val = 0;
        for (let i = 0; i < size; i++) {
            val = val * 256 + (this.buffer[offset + i] || 0);
        }
        return val;
    }

    parseObject(index) {
        if (index >= this.offsets.length) return null;

        const offset = this.offsets[index];
        if (offset >= this.buffer.length) return null;

        const marker = this.buffer[offset];
        const type = marker >> 4;
        const info = marker & 0x0F;

        try {
            switch (type) {
                case 0x0:
                    if (info === 0x00) return null;
                    if (info === 0x08) return false;
                    if (info === 0x09) return true;
                    return null;
                case 0x1: return this.parseInteger(offset, info);
                case 0x2: return this.parseReal(offset, info);
                case 0x3: return this.parseDate(offset);
                case 0x4: return this.parseData(offset, info);
                case 0x5: return this.parseAsciiString(offset, info);
                case 0x6: return this.parseUnicodeString(offset, info);
                case 0x8: return this.parseUID(offset, info);
                case 0xA: return this.parseArray(offset, info);
                case 0xC: return this.parseSet(offset, info);
                case 0xD: return this.parseDict(offset, info);
                default: return null;
            }
        } catch (e) {
            console.error('Error parsing object at', offset, ':', e);
            return null;
        }
    }

    getLength(offset, info) {
        if (info !== 0x0F) return { length: info, dataOffset: offset + 1 };

        const intMarker = this.buffer[offset + 1];
        const intType = intMarker >> 4;
        const intInfo = intMarker & 0x0F;

        if (intType !== 0x1) {
            console.error('Expected int marker for length');
            return { length: 0, dataOffset: offset + 2 };
        }

        const intBytes = 1 << intInfo;
        const length = this.readUIntBE(offset + 2, intBytes);
        return { length, dataOffset: offset + 2 + intBytes };
    }

    parseInteger(offset, info) {
        const bytes = 1 << info;
        let val = 0;
        for (let i = 0; i < bytes; i++) {
            val = val * 256 + this.buffer[offset + 1 + i];
        }

        if (bytes === 8 && val > 0x7FFFFFFFFFFFFFFF) {
            val = val - 0x10000000000000000;
        }
        return val;
    }

    parseReal(offset, info) {
        const bytes = 1 << info;
        if (bytes === 4) {
            return this.view.getFloat32(offset + 1, false);
        } else if (bytes === 8) {
            return this.view.getFloat64(offset + 1, false);
        }
        return 0;
    }

    parseDate(offset) {
        const timestamp = this.view.getFloat64(offset + 1, false);

        return new Date((timestamp + 978307200) * 1000).toISOString();
    }

    parseData(offset, info) {
        const { length, dataOffset } = this.getLength(offset, info);
        const data = this.buffer.slice(dataOffset, dataOffset + length);

        return btoa(String.fromCharCode(...data));
    }

    parseAsciiString(offset, info) {
        const { length, dataOffset } = this.getLength(offset, info);
        let str = '';
        for (let i = 0; i < length; i++) {
            str += String.fromCharCode(this.buffer[dataOffset + i]);
        }
        return str;
    }

    parseUnicodeString(offset, info) {
        const { length, dataOffset } = this.getLength(offset, info);
        let str = '';
        for (let i = 0; i < length; i++) {
            const code = (this.buffer[dataOffset + i * 2] << 8) | this.buffer[dataOffset + i * 2 + 1];
            str += String.fromCharCode(code);
        }
        return str;
    }

    parseUID(offset, info) {
        const bytes = info + 1;
        let val = 0;
        for (let i = 0; i < bytes; i++) {
            val = val * 256 + this.buffer[offset + 1 + i];
        }
        return { UID: val };
    }

    parseArray(offset, info) {
        const { length, dataOffset } = this.getLength(offset, info);
        const arr = [];
        for (let i = 0; i < length; i++) {
            const ref = this.readUIntBE(dataOffset + i * this.objectRefSize, this.objectRefSize);
            arr.push(this.parseObject(ref));
        }
        return arr;
    }

    parseSet(offset, info) {

        return this.parseArray(offset, info);
    }

    parseDict(offset, info) {
        const { length, dataOffset } = this.getLength(offset, info);
        const dict = {};
        const keysOffset = dataOffset;
        const valsOffset = dataOffset + length * this.objectRefSize;

        for (let i = 0; i < length; i++) {
            const keyRef = this.readUIntBE(keysOffset + i * this.objectRefSize, this.objectRefSize);
            const valRef = this.readUIntBE(valsOffset + i * this.objectRefSize, this.objectRefSize);
            const key = this.parseObject(keyRef);
            const val = this.parseObject(valRef);
            if (key !== null && typeof key === 'string') {
                dict[key] = val;
            }
        }
        return dict;
    }
}

function parsePlist(data) {
    if (!data || data.length === 0) return null;

    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    const header = String.fromCharCode(...bytes.slice(0, 6));

    let textContent = null;
    try {
        textContent = new TextDecoder('utf-8').decode(bytes);
    } catch (e) {}

    if (textContent && textContent.includes('<?xml') && textContent.includes('<plist')) {
        try {

            if (typeof plist !== 'undefined') {
                const result = plist.parse(textContent);
                if (result) return result;
            }
        } catch (e) {
            log('plist.js XML parse failed:', e);
        }

        try {
            const result = parseXMLPlist(textContent);
            if (result) return result;
        } catch (e) {
            log('Custom XML plist parse failed:', e);
        }
    }

    if (header === 'bplist' || header.startsWith('bplist')) {

        if (typeof plist !== 'undefined') {
            try {
                const result = plist.parse(buffer);
                if (result) return result;
            } catch (e) {
                log('plist.js binary parse failed:', e);
            }
        }

        try {
            const result = new BinaryPlistParser(buffer).parse();
            if (result) return result;
        } catch (e) {
            log('Custom binary plist parse failed:', e);
        }
    }

    return null;
}

function parseXMLPlist(xml) {
    const doc = new DOMParser().parseFromString(xml, 'text/xml');
    if (doc.querySelector('parsererror')) return null;

    function parseNode(node) {
        if (!node) return null;
        switch (node.tagName) {
            case 'string': return node.textContent || '';
            case 'integer': return parseInt(node.textContent, 10);
            case 'real': return parseFloat(node.textContent);
            case 'true': return true;
            case 'false': return false;
            case 'data': return node.textContent.trim();
            case 'date': return new Date(node.textContent);
            case 'array': return Array.from(node.children).map(parseNode);
            case 'dict':
                const obj = {};
                const children = Array.from(node.children);
                for (let i = 0; i < children.length; i += 2) {
                    if (children[i]?.tagName === 'key') obj[children[i].textContent] = parseNode(children[i + 1]);
                }
                return obj;
            default: return node.textContent;
        }
    }
    const dictNode = doc.querySelector('plist > dict');
    return dictNode ? parseNode(dictNode) : null;
}

function extractStrings(buffer, minLen = 4) {
    const bytes = new Uint8Array(buffer);
    const strings = [];
    let current = '', startOffset = 0;

    for (let i = 0; i < bytes.length; i++) {
        const b = bytes[i];
        if (b >= 32 && b <= 126) {
            if (current.length === 0) startOffset = i;
            current += String.fromCharCode(b);
        } else {
            if (current.length >= minLen) {
                strings.push({ str: current, offset: startOffset });
            }
            current = '';
        }
    }
    if (current.length >= minLen) strings.push({ str: current, offset: startOffset });
    return strings;
}

const SECURITY_RULES = [

    {
        id: 'nsuserdefaults',
        name: 'NSUserDefaults Insecure Storage',
        severity: 'warning',
        patterns: [/NSUserDefaults/g, /UserDefaults\.standard/g, /\.standardUserDefaults/g],
        description: 'NSUserDefaults stores data unencrypted in plist files. Sensitive data can be extracted from device backups.',
        cwe: 'CWE-312', owasp: 'M2', masvs: 'STORAGE-2'
    },
    {
        id: 'coredata',
        name: 'CoreData Unencrypted Storage',
        severity: 'warning',
        patterns: [/NSManagedObject/g, /NSPersistentContainer/g, /NSManagedObjectContext/g, /\.xcdatamodel/g],
        description: 'CoreData stores data in unencrypted SQLite database. Use encrypted-core-data for sensitive information.',
        cwe: 'CWE-312', owasp: 'M2', masvs: 'STORAGE-14'
    },
    {
        id: 'realm',
        name: 'Realm Database (Check Encryption)',
        severity: 'warning',
        patterns: [/Realm\(/g, /RealmSwift/g, /RLMRealm/g, /\.realm/g],
        description: 'Realm database detected. Ensure encryptionKey is set for sensitive data storage.',
        cwe: 'CWE-312', owasp: 'M2', masvs: 'STORAGE-14'
    },
    {
        id: 'sqlite',
        name: 'SQLite Database Usage',
        severity: 'warning',
        patterns: [/sqlite3_open/g, /sqlite3_exec/g, /FMDB/g, /FMDatabase/g],
        description: 'SQLite database used. Data is stored unencrypted unless using SQLCipher.',
        cwe: 'CWE-312', owasp: 'M2', masvs: 'STORAGE-14'
    },
    {
        id: 'keychain',
        name: 'Keychain Secure Storage',
        severity: 'secure',
        patterns: [/SecItemAdd/g, /SecItemCopy/g, /kSecClass/g, /KeychainSwift/g],
        description: 'Keychain is used for secure credential storage. This is the recommended approach.',
        cwe: '', owasp: '', masvs: 'STORAGE-1'
    },
    {
        id: 'plist_write',
        name: 'Plist File Write',
        severity: 'warning',
        patterns: [/writeToFile.*plist/gi, /NSKeyedArchiver/g, /PropertyListSerialization/g],
        description: 'Data written to plist files is not encrypted and easily accessible.',
        cwe: 'CWE-312', owasp: 'M2', masvs: 'STORAGE-2'
    },

    {
        id: 'weak_md5',
        name: 'Weak Hash Algorithm (MD5)',
        severity: 'high',
        patterns: [/CC_MD5/g, /MD5\(/g, /\.md5/g, /kCCHmacAlgMD5/g],
        description: 'MD5 is cryptographically broken. Collisions can be generated. Use SHA-256 or better.',
        cwe: 'CWE-327', owasp: 'M5', masvs: 'CRYPTO-4'
    },
    {
        id: 'weak_sha1',
        name: 'Weak Hash Algorithm (SHA1)',
        severity: 'high',
        patterns: [/CC_SHA1/g, /SHA1\(/g, /\.sha1/g, /kCCHmacAlgSHA1/g],
        description: 'SHA1 is deprecated due to collision vulnerabilities. Use SHA-256 or better.',
        cwe: 'CWE-327', owasp: 'M5', masvs: 'CRYPTO-4'
    },
    {
        id: 'weak_des',
        name: 'Weak Encryption (DES/3DES)',
        severity: 'high',
        patterns: [/kCCAlgorithmDES/g, /kCCAlgorithm3DES/g, /DES_ecb_encrypt/g],
        description: 'DES and 3DES are obsolete. Use AES-256 for encryption.',
        cwe: 'CWE-327', owasp: 'M5', masvs: 'CRYPTO-3'
    },
    {
        id: 'ecb_mode',
        name: 'ECB Mode Encryption',
        severity: 'high',
        patterns: [/kCCOptionECBMode/g, /\.ECB/g, /ECBMode/g],
        description: 'ECB mode reveals patterns in encrypted data. Use CBC or GCM mode.',
        cwe: 'CWE-327', owasp: 'M5', masvs: 'CRYPTO-3'
    },
    {
        id: 'hardcoded_secret',
        name: 'Hardcoded Secret/Password',
        severity: 'high',
        patterns: [
            /password\s*[:=]\s*["'][^"']{4,}["']/gi,
            /secret\s*[:=]\s*["'][^"']{4,}["']/gi,
            /api[_-]?key\s*[:=]\s*["'][^"']+["']/gi,
            /private[_-]?key\s*[:=]\s*["'][^"']+["']/gi
        ],
        description: 'Hardcoded credentials found. Store secrets in Keychain or fetch from secure server.',
        cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'insecure_random',
        name: 'Insecure Random Generator',
        severity: 'warning',
        patterns: [/\brand\(\)/g, /\brandom\(\)/g, /arc4random\(\)/g, /srand\(/g],
        description: 'Use SecRandomCopyBytes for cryptographically secure random numbers.',
        cwe: 'CWE-330', owasp: 'M5', masvs: 'CRYPTO-6'
    },

    {
        id: 'http_url',
        name: 'Insecure HTTP URL',
        severity: 'high',
        patterns: [/http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-zA-Z0-9][^\s"'<>]*/g],
        description: 'Unencrypted HTTP connection. Data can be intercepted. Use HTTPS.',
        cwe: 'CWE-319', owasp: 'M3', masvs: 'NETWORK-1'
    },
    {
        id: 'ssl_disabled',
        name: 'SSL/TLS Validation Disabled',
        severity: 'high',
        patterns: [
            /allowInvalidCertificates\s*=\s*true/gi,
            /validatesDomainName\s*=\s*false/gi,
            /SSLPinningMode\.none/g,
            /CURLOPT_SSL_VERIFYPEER.*0/g
        ],
        description: 'SSL certificate validation disabled. App is vulnerable to MITM attacks.',
        cwe: 'CWE-295', owasp: 'M3', masvs: 'NETWORK-4'
    },
    {
        id: 'ssl_pinning',
        name: 'SSL Pinning Implemented',
        severity: 'secure',
        patterns: [/evaluateServerTrust/g, /SecTrustEvaluate/g, /TrustKit/g, /pinnedCertificates/g],
        description: 'SSL certificate pinning is implemented to prevent MITM attacks.',
        cwe: '', owasp: '', masvs: 'NETWORK-4'
    },

    {
        id: 'logging',
        name: 'Debug Logging',
        severity: 'warning',
        patterns: [/NSLog\s*\(/g, /print\s*\(/g, /println\s*\(/g, /os_log\s*\(/g],
        description: 'Logging may expose sensitive data. Remove or guard logs in production.',
        cwe: 'CWE-532', owasp: 'M9', masvs: 'STORAGE-3'
    },
    {
        id: 'clipboard',
        name: 'Clipboard/Pasteboard Access',
        severity: 'warning',
        patterns: [/UIPasteboard/g, /generalPasteboard/g, /\[.*pasteboard.*\]/gi],
        description: 'Clipboard data is accessible to all apps. Clear sensitive data after use.',
        cwe: 'CWE-200', owasp: 'M2', masvs: 'STORAGE-10'
    },
    {
        id: 'screenshot',
        name: 'Screenshot/Backgrounding',
        severity: 'info',
        patterns: [/applicationDidEnterBackground/g, /willResignActive/g],
        description: 'iOS captures screenshots when backgrounding. Hide sensitive UI in these methods.',
        cwe: 'CWE-200', owasp: 'M2', masvs: 'STORAGE-9'
    },
    {
        id: 'cache',
        name: 'URL/HTTP Cache',
        severity: 'warning',
        patterns: [/URLCache/g, /NSURLCache/g, /HTTPCookieStorage/g],
        description: 'Cached responses may contain sensitive data. Disable caching for sensitive requests.',
        cwe: 'CWE-524', owasp: 'M2', masvs: 'STORAGE-5'
    },

    {
        id: 'jailbreak',
        name: 'Jailbreak Detection',
        severity: 'secure',
        patterns: [
            /\/Applications\/Cydia\.app/g,
            /\/bin\/bash/g,
            /\/usr\/sbin\/sshd/g,
            /cydia:\/\//g,
            /isJailbroken/g,
            /canOpenURL.*cydia/gi
        ],
        description: 'Jailbreak detection is implemented to detect compromised devices.',
        cwe: '', owasp: '', masvs: 'RESILIENCE-1'
    },
    {
        id: 'antidebug',
        name: 'Anti-Debug Protection',
        severity: 'secure',
        patterns: [/ptrace/g, /PT_DENY_ATTACH/g, /sysctl.*P_TRACED/g],
        description: 'Anti-debugging measures are implemented.',
        cwe: '', owasp: '', masvs: 'RESILIENCE-2'
    },
    {
        id: 'uiwebview',
        name: 'Deprecated UIWebView',
        severity: 'warning',
        patterns: [/UIWebView/g],
        description: 'UIWebView is deprecated since iOS 12. Use WKWebView instead.',
        cwe: 'CWE-919', owasp: 'M1', masvs: 'PLATFORM-5'
    },
    {
        id: 'webview_js',
        name: 'JavaScript in WebView',
        severity: 'warning',
        patterns: [/evaluateJavaScript/g, /stringByEvaluatingJavaScriptFromString/g],
        description: 'JavaScript execution in WebView can lead to injection attacks.',
        cwe: 'CWE-79', owasp: 'M7', masvs: 'PLATFORM-6'
    },
    {
        id: 'biometric',
        name: 'Biometric Authentication',
        severity: 'info',
        patterns: [/LAContext/g, /evaluatePolicy/g, /biometryType/g],
        description: 'Biometric authentication (Face ID/Touch ID) is implemented.',
        cwe: '', owasp: '', masvs: 'AUTH-8'
    },

    {
        id: 'file_no_protection',
        name: 'File Without Protection',
        severity: 'high',
        patterns: [/NSFileProtectionNone/g, /FileProtectionType\.none/g],
        description: 'Files are accessible even when device is locked. Use NSFileProtectionComplete.',
        cwe: 'CWE-311', owasp: 'M2', masvs: 'STORAGE-1'
    },
    {
        id: 'file_protected',
        name: 'File Protection Enabled',
        severity: 'secure',
        patterns: [/NSFileProtectionComplete/g, /FileProtectionType\.complete/g],
        description: 'Files are encrypted and only accessible when device is unlocked.',
        cwe: '', owasp: '', masvs: 'STORAGE-1'
    },

    {
        id: 'aws_s3_url',
        name: 'AWS S3 Bucket Exposed',
        severity: 'high',
        patterns: [/https?:\/\/[a-zA-Z0-9.-]*\.?s3[.-][a-zA-Z0-9.-]*\.amazonaws\.com[^\s"'<>]*/gi, /s3:\/\/[a-zA-Z0-9.-]+/gi],
        description: 'AWS S3 bucket URL found. Verify bucket permissions are not public. Exposed buckets can leak sensitive data.',
        cwe: 'CWE-200', owasp: 'M1', masvs: 'STORAGE-12'
    },
    {
        id: 'firebase_url',
        name: 'Firebase Database URL',
        severity: 'warning',
        patterns: [/https?:\/\/[a-zA-Z0-9-]+\.firebaseio\.com[^\s"'<>]*/gi, /https?:\/\/[a-zA-Z0-9-]+\.firebasedatabase\.app[^\s"'<>]*/gi],
        description: 'Firebase database URL found. Verify security rules are properly configured.',
        cwe: 'CWE-200', owasp: 'M1', masvs: 'STORAGE-12'
    },
    {
        id: 'google_api_key',
        name: 'Google API Key Exposed',
        severity: 'high',
        patterns: [/AIza[0-9A-Za-z_-]{35}/g],
        description: 'Google API key found in code. API keys should be restricted and not embedded in apps.',
        cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },

    {
        id: 'hardcoded_password_value',
        name: 'Hardcoded Password Value',
        severity: 'high',
        patterns: [
            /"[Pp]assword"\s*:\s*"[^"]+"/g,
            /<key>[Pp]assword<\/key>\s*<string>[^<]+<\/string>/g,
            /[Pp]assword\s*=\s*["'][^"']{3,}["']/g
        ],
        description: 'Hardcoded password value found. Never store passwords in code or config files.',
        cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },
    {
        id: 'hardcoded_token',
        name: 'Hardcoded Token/Bearer',
        severity: 'high',
        patterns: [
            /Bearer\s+[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/g,
            /token\s*[:=]\s*["'][A-Za-z0-9-_.]{20,}["']/gi,
            /authorization\s*[:=]\s*["'][^"']{20,}["']/gi
        ],
        description: 'Hardcoded authentication token found. Tokens should be dynamically retrieved.',
        cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14'
    },

    {
        id: 'loadhtml_xss',
        name: 'loadHTMLString XSS Risk',
        severity: 'high',
        patterns: [/loadHTMLString/g, /loadHTML/g],
        description: 'loadHTMLString with untrusted input can lead to XSS attacks. Sanitize all HTML content.',
        cwe: 'CWE-79', owasp: 'M7', masvs: 'PLATFORM-6'
    },
    {
        id: 'format_string',
        name: 'Format String Vulnerability',
        severity: 'warning',
        patterns: [/String\(format:/g, /stringWithFormat:/g, /%@.*%@.*%@/g],
        description: 'Format string vulnerabilities can lead to information disclosure or crashes.',
        cwe: 'CWE-134', owasp: 'M7', masvs: 'CODE-6'
    },

    {
        id: 'writeto_file',
        name: 'Insecure File Write',
        severity: 'warning',
        patterns: [/writeToFile\s*\(/g, /write\(toFile:/g, /createFile\(atPath:/g],
        description: 'Data written to files may not be encrypted. Use Data Protection APIs.',
        cwe: 'CWE-312', owasp: 'M2', masvs: 'STORAGE-1'
    },
    {
        id: 'temp_directory',
        name: 'Temporary Directory Usage',
        severity: 'info',
        patterns: [/NSTemporaryDirectory/g, /FileManager.*temporaryDirectory/g, /tmp\//g],
        description: 'Temporary files may persist and contain sensitive data. Clean up temp files.',
        cwe: 'CWE-377', owasp: 'M2', masvs: 'STORAGE-4'
    },

    {
        id: 'custom_url_scheme',
        name: 'Custom URL Scheme Handler',
        severity: 'info',
        patterns: [/application.*open.*url.*options/gi, /handleOpenURL/g, /CFBundleURLSchemes/g],
        description: 'Custom URL schemes can be hijacked. Validate all URL scheme inputs.',
        cwe: 'CWE-939', owasp: 'M1', masvs: 'PLATFORM-3'
    },
    {
        id: 'universal_links',
        name: 'Universal Links Handler',
        severity: 'info',
        patterns: [/application.*continue.*userActivity/gi, /NSUserActivity/g],
        description: 'Universal Links should validate the source and parameters.',
        cwe: '', owasp: '', masvs: 'PLATFORM-3'
    },

    {
        id: 'localhost_url',
        name: 'Debug/Localhost URL',
        severity: 'warning',
        patterns: [/https?:\/\/localhost[:\d]*[^\s"'<>]*/gi, /https?:\/\/127\.0\.0\.1[:\d]*[^\s"'<>]*/gi, /https?:\/\/0\.0\.0\.0[:\d]*[^\s"'<>]*/gi],
        description: 'Localhost/debug URLs found. Remove before production release.',
        cwe: 'CWE-489', owasp: 'M1', masvs: 'CODE-4'
    },

    {
        id: 'objc_runtime',
        name: 'Objective-C Runtime Usage',
        severity: 'info',
        patterns: [/objc_msgSend/g, /class_addMethod/g, /method_exchangeImplementations/g, /object_setClass/g],
        description: 'ObjC runtime allows method swizzling. Consider runtime integrity checks.',
        cwe: '', owasp: '', masvs: 'RESILIENCE-9'
    },
    {
        id: 'dynamic_library',
        name: 'Dynamic Library Loading',
        severity: 'warning',
        patterns: [/dlopen/g, /dlsym/g, /NSBundle.*load/g],
        description: 'Dynamic library loading can be exploited for code injection.',
        cwe: 'CWE-427', owasp: 'M7', masvs: 'RESILIENCE-9'
    },

    {
        id: 'location_tracking',
        name: 'Location Tracking',
        severity: 'info',
        patterns: [/CLLocationManager/g, /startUpdatingLocation/g, /requestAlwaysAuthorization/g],
        description: 'Location tracking is enabled. Ensure proper user consent and data handling.',
        cwe: '', owasp: '', masvs: 'PRIVACY-1'
    },
    {
        id: 'contacts_access',
        name: 'Contacts Access',
        severity: 'info',
        patterns: [/CNContactStore/g, /ABAddressBook/g, /requestAccess.*contacts/gi],
        description: 'App accesses user contacts. Ensure proper consent and data protection.',
        cwe: '', owasp: '', masvs: 'PRIVACY-1'
    },
    {
        id: 'camera_microphone',
        name: 'Camera/Microphone Access',
        severity: 'info',
        patterns: [/AVCaptureDevice/g, /requestAccess.*video/gi, /requestAccess.*audio/gi],
        description: 'App accesses camera or microphone. Ensure proper consent.',
        cwe: '', owasp: '', masvs: 'PRIVACY-1'
    }
];

function analyzeContentWithContext(content, filePath, rules) {
    const findings = [];
    const lines = content.split('\n');

    for (const rule of rules) {
        for (const pattern of rule.patterns) {
            pattern.lastIndex = 0;
            let match;

            while ((match = pattern.exec(content)) !== null) {

                const beforeMatch = content.substring(0, match.index);
                const lineNum = (beforeMatch.match(/\n/g) || []).length + 1;

                const startLine = Math.max(0, lineNum - 3);
                const endLine = Math.min(lines.length, lineNum + 2);
                const contextLines = lines.slice(startLine, endLine);

                const snippet = contextLines.map((line, idx) => {
                    const actualLineNum = startLine + idx + 1;
                    const marker = actualLineNum === lineNum ? '>>>' : '   ';
                    return `${marker} ${actualLineNum}: ${line}`;
                }).join('\n');

                findings.push({
                    ruleId: rule.id,
                    ruleName: rule.name,
                    severity: rule.severity,
                    description: rule.description,
                    cwe: rule.cwe,
                    owasp: rule.owasp,
                    masvs: rule.masvs,
                    file: filePath,
                    line: lineNum,
                    match: match[0],
                    snippet: snippet
                });

                if (match.index === pattern.lastIndex) pattern.lastIndex++;
            }
        }
    }

    return findings;
}

function analyzeATSWithContext(plistData, filePath) {
    const findings = [];
    const ats = plistData?.NSAppTransportSecurity;

    if (!ats) {
        findings.push({
            ruleId: 'ats_default',
            ruleName: 'ATS Default Configuration',
            severity: 'info',
            description: 'No custom ATS configuration. iOS defaults (HTTPS required) are used.',
            file: filePath,
            line: null,
            match: 'NSAppTransportSecurity: not present',
            snippet: 'Info.plist does not contain NSAppTransportSecurity key.\nDefault secure settings are applied.',
            cwe: '', owasp: '', masvs: 'NETWORK-1'
        });
        return findings;
    }

    if (ats.NSAllowsArbitraryLoads === true) {
        findings.push({
            ruleId: 'ats_disabled',
            ruleName: 'ATS Completely Disabled',
            severity: 'high',
            description: 'NSAllowsArbitraryLoads is TRUE. All HTTP connections are allowed without encryption.',
            file: filePath,
            line: null,
            match: 'NSAllowsArbitraryLoads: true',
            snippet: `<key>NSAppTransportSecurity</key>\n<dict>\n>>> <key>NSAllowsArbitraryLoads</key>\n>>> <true/>\n</dict>`,
            cwe: 'CWE-319', owasp: 'M3', masvs: 'NETWORK-1'
        });
    }

    if (ats.NSAllowsArbitraryLoadsInWebContent === true) {
        findings.push({
            ruleId: 'ats_webview_disabled',
            ruleName: 'ATS Disabled for WebView',
            severity: 'high',
            description: 'NSAllowsArbitraryLoadsInWebContent allows insecure loads in WKWebView.',
            file: filePath,
            line: null,
            match: 'NSAllowsArbitraryLoadsInWebContent: true',
            snippet: `<key>NSAllowsArbitraryLoadsInWebContent</key>\n<true/>`,
            cwe: 'CWE-319', owasp: 'M3', masvs: 'NETWORK-1'
        });
    }

    if (ats.NSExceptionDomains) {
        for (const [domain, config] of Object.entries(ats.NSExceptionDomains)) {
            if (config?.NSExceptionAllowsInsecureHTTPLoads === true) {
                findings.push({
                    ruleId: 'ats_exception_http',
                    ruleName: `ATS Exception: HTTP for ${domain}`,
                    severity: 'warning',
                    description: `Domain "${domain}" allows insecure HTTP connections.`,
                    file: filePath,
                    line: null,
                    match: `${domain}: NSExceptionAllowsInsecureHTTPLoads = true`,
                    snippet: `<key>${domain}</key>\n<dict>\n>>> <key>NSExceptionAllowsInsecureHTTPLoads</key>\n>>> <true/>\n</dict>`,
                    cwe: 'CWE-319', owasp: 'M3', masvs: 'NETWORK-1'
                });
            }

            const tlsVersion = config?.NSExceptionMinimumTLSVersion;
            if (tlsVersion === 'TLSv1.0' || tlsVersion === 'TLSv1.1') {
                findings.push({
                    ruleId: 'ats_weak_tls',
                    ruleName: `Weak TLS for ${domain}`,
                    severity: 'high',
                    description: `Domain "${domain}" allows deprecated ${tlsVersion}.`,
                    file: filePath,
                    line: null,
                    match: `NSExceptionMinimumTLSVersion: ${tlsVersion}`,
                    snippet: `<key>${domain}</key>\n<dict>\n>>> <key>NSExceptionMinimumTLSVersion</key>\n>>> <string>${tlsVersion}</string>\n</dict>`,
                    cwe: 'CWE-326', owasp: 'M3', masvs: 'NETWORK-2'
                });
            }
        }
    }

    return findings;
}

async function analyzeIPA(file) {
    log('Starting analysis:', file.name);

    const results = {
        appInfo: { fileName: file.name, fileSize: formatSize(file.size) },
        plistData: null,
        findings: [],
        files: [],
        fileTree: {},
        specialFiles: { databases: [], plists: [], certificates: [], configs: [] },
        permissions: {},
        strings: [],
        urls: [],
        emails: [],
        checksec: { pie: false, arc: false, canary: false, is64bit: false },
        libraries: [],
        binType: 'Unknown',
        trackers: [],
        urlSchemes: [],
        queriedSchemes: []
    };

    state.findings = { high: [], warning: [], info: [], secure: [] };
    state.groupedFindings = { high: [], warning: [], info: [], secure: [] };
    state.fileContents.clear();
    state.binaryStrings = [];

    try {
        showLoading('Loading IPA...');
        updateProgress(5, 'Reading file...');

        const arrayBuffer = await file.arrayBuffer();
        results.appInfo.sha256 = await sha256(arrayBuffer);

        updateProgress(10, 'Extracting...');
        const zip = await JSZip.loadAsync(arrayBuffer);
        state.zipContent = zip;

        let appPath = null;
        for (const path of Object.keys(zip.files)) {
            const match = path.match(/^Payload\/([^\/]+\.app)\//i);
            if (match) {
                appPath = `Payload/${match[1]}/`;
                break;
            }
        }
        if (!appPath) throw new Error('No .app bundle found in IPA');

        state.appPath = appPath;
        log('App path:', appPath);

        updateProgress(15, 'Building file tree...');
        for (const [path, entry] of Object.entries(zip.files)) {
            if (entry.dir || path.includes('__MACOSX')) continue;

            const relPath = path.startsWith(appPath) ? path.slice(appPath.length) : path;
            results.files.push(relPath);

            const ext = path.split('.').pop().toLowerCase();
            if (['db', 'sqlite', 'sqlite3', 'realm'].includes(ext)) {
                results.specialFiles.databases.push(relPath);
            } else if (ext === 'plist') {
                results.specialFiles.plists.push(relPath);
            } else if (['cer', 'pem', 'crt', 'p12', 'key'].includes(ext)) {
                results.specialFiles.certificates.push(relPath);
            } else if (['json', 'xml', 'yaml', 'config'].includes(ext)) {
                results.specialFiles.configs.push(relPath);
            }

            const parts = relPath.split('/');
            let current = results.fileTree;
            for (let i = 0; i < parts.length; i++) {
                const part = parts[i];
                if (i === parts.length - 1) {
                    current[part] = { _type: 'file', _path: relPath, _size: entry._data?.uncompressedSize || 0 };
                } else {
                    current[part] = current[part] || { _type: 'dir' };
                    current = current[part];
                }
            }
        }

        updateProgress(20, 'Parsing Info.plist...');
        const plistFile = zip.file(appPath + 'Info.plist');
        if (plistFile) {
            const plistData = await plistFile.async('arraybuffer');
            results.plistData = parsePlist(plistData);
            state.fileContents.set('Info.plist', JSON.stringify(results.plistData, null, 2));

            if (results.plistData) {
                results.appInfo.appName = results.plistData.CFBundleDisplayName || results.plistData.CFBundleName || 'Unknown';
                results.appInfo.bundleId = results.plistData.CFBundleIdentifier || '';
                results.appInfo.version = results.plistData.CFBundleShortVersionString || '';
                results.appInfo.build = results.plistData.CFBundleVersion || '';
                results.appInfo.minOS = results.plistData.MinimumOSVersion || '';
                results.appInfo.executableName = results.plistData.CFBundleExecutable || '';

                const permKeys = {
                    'NSCameraUsageDescription': 'Camera',
                    'NSMicrophoneUsageDescription': 'Microphone',
                    'NSPhotoLibraryUsageDescription': 'Photos',
                    'NSLocationWhenInUseUsageDescription': 'Location (In Use)',
                    'NSLocationAlwaysUsageDescription': 'Location (Always)',
                    'NSContactsUsageDescription': 'Contacts',
                    'NSCalendarsUsageDescription': 'Calendar',
                    'NSBluetoothAlwaysUsageDescription': 'Bluetooth',
                    'NSFaceIDUsageDescription': 'Face ID'
                };
                for (const [key, name] of Object.entries(permKeys)) {
                    if (results.plistData[key]) {
                        results.permissions[key] = { name, reason: results.plistData[key] };
                    }
                }

                const urlTypes = results.plistData.CFBundleURLTypes;
                if (Array.isArray(urlTypes)) {
                    for (const t of urlTypes) {
                        if (Array.isArray(t.CFBundleURLSchemes)) {
                            results.urlSchemes.push(...t.CFBundleURLSchemes);
                        }
                    }
                }
                if (Array.isArray(results.plistData.LSApplicationQueriesSchemes)) {
                    results.queriedSchemes = results.plistData.LSApplicationQueriesSchemes;
                }

                const atsFindings = analyzeATSWithContext(results.plistData, 'Info.plist');
                results.findings.push(...atsFindings);

                const iconFiles = results.plistData.CFBundleIcons?.CFBundlePrimaryIcon?.CFBundleIconFiles ||
                                  results.plistData['CFBundleIcons~ipad']?.CFBundlePrimaryIcon?.CFBundleIconFiles ||
                                  results.plistData.CFBundleIconFiles || [];
                if (iconFiles.length > 0) {
                    const iconName = iconFiles[iconFiles.length - 1];
                    const iconPatterns = [
                        appPath + iconName + '@3x.png',
                        appPath + iconName + '@2x.png',
                        appPath + iconName + '.png',
                        appPath + 'AppIcon60x60@3x.png',
                        appPath + 'AppIcon60x60@2x.png',
                        appPath + 'AppIcon76x76@2x~ipad.png'
                    ];
                    for (const iconPath of iconPatterns) {
                        const iconFile = zip.file(iconPath);
                        if (iconFile) {
                            try {
                                const iconData = await iconFile.async('arraybuffer');
                                const iconBytes = new Uint8Array(iconData);
                                if (!isCrushedPNG(iconBytes)) {
                                    const blob = new Blob([iconData], { type: 'image/png' });
                                    results.appIcon = await blobToDataURL(blob);
                                }
                            } catch (e) { }
                            break;
                        }
                    }
                }
            }
        }

        updateProgress(30, 'Analyzing source files...');
        let processed = 0;
        const textExts = ['m', 'swift', 'h', 'c', 'cpp', 'mm', 'js', 'json', 'xml', 'plist', 'strings'];

        for (const [path, entry] of Object.entries(zip.files)) {
            if (entry.dir) continue;
            const ext = path.split('.').pop().toLowerCase();

            if (textExts.includes(ext)) {
                try {
                    let content = await entry.async('string');
                    const relPath = path.startsWith(appPath) ? path.slice(appPath.length) : path;
                    let contentForAnalysis = content;

                    if (ext === 'plist' && content.startsWith('bplist')) {
                        try {
                            const binData = await entry.async('arraybuffer');
                            const parser = new BinaryPlistParser(binData);
                            const parsed = parser.parse();
                            if (parsed) {

                                contentForAnalysis = JSON.stringify(parsed, null, 2);

                                content = contentForAnalysis;
                            }
                        } catch (e) {
                            log('Failed to parse binary plist:', relPath, e);
                        }
                    }

                    state.fileContents.set(relPath, content);

                    const fileFindings = analyzeContentWithContext(contentForAnalysis, relPath, SECURITY_RULES);
                    results.findings.push(...fileFindings);

                    const urls = content.match(/https?:\/\/[^\s"'<>\]\)]+/gi) || [];
                    const emails = content.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi) || [];
                    results.urls.push(...urls);
                    results.emails.push(...emails);

                    processed++;
                    if (processed % 50 === 0) {
                        updateProgress(30 + Math.floor((processed / results.files.length) * 20), `Analyzed ${processed} files...`);
                    }
                } catch (e) {}
            }
        }

        updateProgress(55, 'Analyzing binary...');
        if (results.appInfo.executableName) {
            const binPath = appPath + results.appInfo.executableName;
            const binFile = zip.file(binPath);

            if (binFile) {
                const binData = await binFile.async('arraybuffer');
                log('Binary size:', binData.byteLength);

                const stringData = extractStrings(binData, 4);
                state.binaryStrings = stringData;
                results.strings = stringData.map(s => s.str);

                const stringsContent = stringData.map(s => s.str).join('\n');

                const binFindings = analyzeContentWithContext(stringsContent, `BINARY:${results.appInfo.executableName}`, SECURITY_RULES);

                for (const finding of binFindings) {
                    const matchingStr = stringData.find(s => s.str.includes(finding.match));
                    if (matchingStr) {
                        finding.binaryOffset = '0x' + matchingStr.offset.toString(16);
                    }
                }
                results.findings.push(...binFindings);

                const binUrls = stringsContent.match(/https?:\/\/[^\s"'<>\]\)]+/gi) || [];
                results.urls.push(...binUrls);

                results.binType = stringsContent.includes('swift') ? 'Swift' : 'Objective-C';
                results.checksec.pie = stringsContent.includes('__PAGEZERO');
                results.checksec.arc = stringsContent.includes('objc_release') || stringsContent.includes('swift_release');
                results.checksec.canary = stringsContent.includes('__stack_chk_fail');

                const bytes = new Uint8Array(binData);
                const magic = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
                results.checksec.is64bit = magic === 0xfeedfacf || magic === 0xcffaedfe;

                results.libraries = stringData
                    .map(s => s.str)
                    .filter(s => s.endsWith('.dylib') || s.includes('.framework'));

                const trackerPatterns = [
                    { name: 'Facebook SDK', pattern: /FBSDKCore|com\.facebook/i },
                    { name: 'Google Analytics', pattern: /GoogleAnalytics|GAI\./i },
                    { name: 'Firebase', pattern: /Firebase|FIRAnalytics/i },
                    { name: 'Crashlytics', pattern: /Crashlytics/i },
                    { name: 'Mixpanel', pattern: /Mixpanel/i },
                    { name: 'Adjust', pattern: /AdjustSdk/i },
                    { name: 'AppsFlyer', pattern: /AppsFlyerLib/i },
                    { name: 'Branch', pattern: /Branch\.getInstance/i }
                ];
                for (const t of trackerPatterns) {
                    if (t.pattern.test(stringsContent)) results.trackers.push(t.name);
                }
            }
        }

        const sdkPatterns = [
            { name: 'Facebook SDK', pattern: /FBSDK|FBSDKCore|FacebookSDK/i },
            { name: 'Google Analytics', pattern: /GoogleAnalytics|GTMSession/i },
            { name: 'Firebase', pattern: /Firebase|GoogleUtilities|nanopb/i },
            { name: 'Crashlytics', pattern: /Crashlytics|Fabric/i },
            { name: 'Mixpanel', pattern: /Mixpanel/i },
            { name: 'Adjust', pattern: /Adjust\.framework|AdjustSdk/i },
            { name: 'AppsFlyer', pattern: /AppsFlyerLib|AppsFlyer/i },
            { name: 'Branch', pattern: /Branch\.framework/i },
            { name: 'Amplitude', pattern: /Amplitude/i },
            { name: 'Segment', pattern: /Analytics\.framework|Segment/i },
            { name: 'Flurry', pattern: /Flurry/i },
            { name: 'OneSignal', pattern: /OneSignal/i },
            { name: 'Braze (Appboy)', pattern: /Appboy|Braze/i },
            { name: 'Intercom', pattern: /Intercom/i },
            { name: 'Leanplum', pattern: /Leanplum/i },
            { name: 'CleverTap', pattern: /CleverTap/i },
            { name: 'Sentry', pattern: /Sentry\.framework|SentryPrivate/i },
            { name: 'New Relic', pattern: /NewRelic/i },
            { name: 'Bugsnag', pattern: /Bugsnag/i },
            { name: 'Instabug', pattern: /Instabug/i },
            { name: 'RevenueCat', pattern: /RevenueCat|Purchases\.framework/i },
            { name: 'AdMob', pattern: /GoogleMobileAds|GAD/i },
            { name: 'MoPub', pattern: /MoPub/i },
            { name: 'AppLovin', pattern: /AppLovin/i },
            { name: 'Unity Ads', pattern: /UnityAds/i },
            { name: 'ironSource', pattern: /IronSource/i },
            { name: 'Chartboost', pattern: /Chartboost/i },
            { name: 'Vungle', pattern: /Vungle/i },
            { name: 'AdColony', pattern: /AdColony/i },
            { name: 'Tapjoy', pattern: /Tapjoy/i },
            { name: 'Fyber', pattern: /Fyber/i },
            { name: 'Realm', pattern: /Realm\.framework|RealmSwift/i },
            { name: 'Alamofire', pattern: /Alamofire/i },
            { name: 'AFNetworking', pattern: /AFNetworking/i },
            { name: 'SDWebImage', pattern: /SDWebImage/i },
            { name: 'Kingfisher', pattern: /Kingfisher/i },
            { name: 'SnapKit', pattern: /SnapKit/i },
            { name: 'RxSwift', pattern: /RxSwift|RxCocoa/i },
            { name: 'Stripe', pattern: /Stripe\.framework|StripeCore/i },
            { name: 'Braintree', pattern: /Braintree/i },
            { name: 'PayPal', pattern: /PayPal/i },
            { name: 'AWS SDK', pattern: /AWSS3|AWSCore|AWSCognito/i },
            { name: 'Zendesk', pattern: /Zendesk|ZendeskSDK/i },
            { name: 'Twilio', pattern: /Twilio/i },
            { name: 'Mapbox', pattern: /Mapbox/i },
            { name: 'Google Maps', pattern: /GoogleMaps/i }
        ];

        const allFilesStr = results.files.join('\n');
        for (const sdk of sdkPatterns) {
            if (sdk.pattern.test(allFilesStr) && !results.trackers.includes(sdk.name)) {
                results.trackers.push(sdk.name);
            }
        }

        results.trackers = [...new Set(results.trackers)];
        results.urls = [...new Set(results.urls)];
        results.emails = [...new Set(results.emails)];

        updateProgress(80, 'Generating findings...');
        if (!results.checksec.pie) {
            results.findings.push({
                ruleId: 'no_pie', ruleName: 'PIE Not Enabled', severity: 'high',
                description: 'Binary is not position-independent. ASLR cannot fully protect against memory attacks.',
                file: `BINARY:${results.appInfo.executableName}`, line: null,
                match: 'PIE flag not detected', snippet: 'Mach-O header does not have MH_PIE flag.\nCompile with -pie flag.',
                cwe: 'CWE-119', owasp: 'M7', masvs: 'CODE-2'
            });
        }
        if (!results.checksec.canary) {
            results.findings.push({
                ruleId: 'no_canary', ruleName: 'Stack Canary Not Detected', severity: 'warning',
                description: 'Stack buffer overflow protection may not be enabled.',
                file: `BINARY:${results.appInfo.executableName}`, line: null,
                match: '__stack_chk_fail not found', snippet: 'Symbol __stack_chk_fail not found in binary.\nEnable -fstack-protector-all.',
                cwe: 'CWE-121', owasp: 'M7', masvs: 'CODE-2'
            });
        }

        if (results.specialFiles.databases.length > 0) {
            results.findings.push({
                ruleId: 'database_files', ruleName: 'Database Files in Bundle', severity: 'warning',
                description: 'Database files found. These may contain cached sensitive data.',
                file: results.specialFiles.databases[0],
                line: null,
                match: results.specialFiles.databases.join(', '),
                snippet: 'Found database files:\n' + results.specialFiles.databases.map(f => `  - ${f}`).join('\n'),
                cwe: 'CWE-312', owasp: 'M2', masvs: 'STORAGE-14'
            });
        }

        for (const f of results.findings) {
            const sev = f.severity === 'secure' ? 'secure' : f.severity;
            if (state.findings[sev]) state.findings[sev].push(f);
        }

        state.groupedFindings = groupFindingsByRule(results.findings);

        updateProgress(95, 'Calculating score...');
        let score = 100;
        score -= state.groupedFindings.high.length * 12;
        score -= state.groupedFindings.warning.length * 4;
        score += state.groupedFindings.secure.length * 2;
        results.securityScore = Math.max(0, Math.min(100, score));

        state.analysisResults = results;
        log('Analysis complete!', {
            total: results.findings.length,
            high: state.findings.high.length,
            warning: state.findings.warning.length,
            secure: state.findings.secure.length
        });

        updateProgress(100, 'Done!');
        return results;

    } catch (error) {
        console.error('Analysis failed:', error);
        throw error;
    }
}

function groupFindingsByRule(findings) {
    const grouped = { high: [], warning: [], info: [], secure: [] };
    const ruleMap = new Map();

    for (const f of findings) {
        const key = f.ruleId;
        if (!ruleMap.has(key)) {
            ruleMap.set(key, {
                ruleId: f.ruleId,
                ruleName: f.ruleName,
                severity: f.severity,
                description: f.description,
                cwe: f.cwe,
                owasp: f.owasp,
                masvs: f.masvs,
                instances: []
            });
        }
        ruleMap.get(key).instances.push({
            file: f.file,
            line: f.line,
            match: f.match,
            snippet: f.snippet,
            binaryOffset: f.binaryOffset
        });
    }

    for (const [, groupedFinding] of ruleMap) {
        const sev = groupedFinding.severity === 'secure' ? 'secure' : groupedFinding.severity;
        if (grouped[sev]) grouped[sev].push(groupedFinding);
    }

    return grouped;
}

async function loadFileContent(filePath, options = {}) {
    const cacheKey = filePath + (options.hexOffset ? `_hex_${options.hexOffset}` : '');

    if (!options.hexOffset && !options.isBinaryReference && state.fileContents.has(cacheKey)) {
        const cached = state.fileContents.get(cacheKey);

        if (typeof cached === 'string' && !cached.startsWith('bplist')) {
            return cached;
        }

        state.fileContents.delete(cacheKey);
    }

    if (!state.zipContent || !state.appPath) return null;

    let file = null;

    if (options.isBinaryReference) {
        const execName = filePath;

        const possiblePaths = [
            state.appPath + execName,
            state.appPath + '/' + execName,
            execName
        ];

        for (const path of possiblePaths) {
            file = state.zipContent.file(path);
            if (file) {
                log('Found executable at:', path);
                break;
            }
        }

        if (!file) {
            const allFiles = Object.keys(state.zipContent.files);
            const execFile = allFiles.find(f => f.endsWith('/' + execName) || f === execName);
            if (execFile) {
                file = state.zipContent.file(execFile);
                log('Found executable via search:', execFile);
            }
        }
    } else {
        const fullPath = state.appPath + filePath;
        file = state.zipContent.file(fullPath) || state.zipContent.file(filePath);
    }

    if (!file) return null;

    const ext = filePath.split('.').pop().toLowerCase();

    try {
        const data = await file.async('arraybuffer');
        const bytes = new Uint8Array(data);

        const imageExts = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'ico', 'icns'];
        if (imageExts.includes(ext) || isPNG(bytes) || isJPEG(bytes)) {
            if (isCrushedPNG(bytes)) {
                return { type: 'image', dataUrl: null, size: bytes.length, ext, crushed: true };
            }
            const blob = new Blob([data], { type: getMimeType(ext, bytes) });
            const dataUrl = await blobToDataURL(blob);
            return { type: 'image', dataUrl, size: bytes.length, ext };
        }

        const header = String.fromCharCode(...bytes.slice(0, 6));
        const isBinaryPlist = header === 'bplist' || header.startsWith('bplist');

        if (ext === 'plist' || isBinaryPlist) {
            log('Parsing plist file:', filePath, 'isBinary:', isBinaryPlist);

            if (isBinaryPlist) {
                try {
                    const parsed = new BinaryPlistParser(data).parse();
                    if (parsed) {
                        const content = JSON.stringify(parsed, null, 2);
                        state.fileContents.set(cacheKey, content);
                        log('Binary plist parsed successfully');
                        return content;
                    }
                } catch (e) {
                    log('Binary plist parse error:', e);
                }
            } else {
                try {
                    const textContent = new TextDecoder('utf-8').decode(bytes);
                    if (textContent.includes('<plist')) {
                        if (typeof plist !== 'undefined') {
                            try {
                                const parsed = plist.parse(textContent);
                                if (parsed) {
                                    const content = JSON.stringify(parsed, null, 2);
                                    state.fileContents.set(cacheKey, content);
                                    return content;
                                }
                            } catch (e) {}
                        }
                        const parsed = parseXMLPlist(textContent);
                        if (parsed) {
                            const content = JSON.stringify(parsed, null, 2);
                            state.fileContents.set(cacheKey, content);
                            return content;
                        }
                    }
                } catch (e) {
                    log('XML plist parse error:', e);
                }
            }
            log('Plist parsing failed, showing hex dump');
        }

        const isMachO = isMachOBinary(bytes);

        let isText = true;
        const sampleSize = Math.min(bytes.length, 1000);
        for (let i = 0; i < sampleSize; i++) {
            const b = bytes[i];
            if (b !== 0x09 && b !== 0x0A && b !== 0x0D && (b < 0x20 || b > 0x7E) && b < 0xC0) {
                if (b < 0x80 || b > 0xBF) {
                    isText = false;
                    break;
                }
            }
        }

        if (isText && !isBinaryPlist && !isMachO) {
            try {
                const content = new TextDecoder('utf-8').decode(bytes);
                state.fileContents.set(cacheKey, content);
                return content;
            } catch (e) {}
        }

        return {
            type: 'binary',
            isMachO,
            size: bytes.length,
            data: bytes,
            header: analyzeBinaryHeader(bytes),
            offset: options.hexOffset || 0
        };
    } catch (e) {
        log('Error loading file:', e);
        return '[Unable to read file: ' + e.message + ']';
    }
}

function isPNG(bytes) {
    return bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47;
}

function isJPEG(bytes) {
    return bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF;
}

function isCrushedPNG(bytes) {
    if (!isPNG(bytes)) return false;
    for (let i = 8; i < Math.min(bytes.length, 100); i++) {
        if (bytes[i] === 0x43 && bytes[i+1] === 0x67 && bytes[i+2] === 0x42 && bytes[i+3] === 0x49) {
            return true;
        }
    }
    return false;
}

function isMachOBinary(bytes) {
    if (bytes.length < 4) return false;

    const magic = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
    const magicLE = (bytes[3] << 24) | (bytes[2] << 16) | (bytes[1] << 8) | bytes[0];
    return magic === 0xFEEDFACE || magic === 0xFEEDFACF ||
           magicLE === 0xFEEDFACE || magicLE === 0xFEEDFACF ||
           magic === 0xCAFEBABE || magicLE === 0xCAFEBABE;
}

function getMimeType(ext, bytes) {
    if (isPNG(bytes)) return 'image/png';
    if (isJPEG(bytes)) return 'image/jpeg';
    const mimes = {
        'png': 'image/png', 'jpg': 'image/jpeg', 'jpeg': 'image/jpeg',
        'gif': 'image/gif', 'webp': 'image/webp', 'bmp': 'image/bmp',
        'ico': 'image/x-icon', 'icns': 'image/x-icns'
    };
    return mimes[ext] || 'application/octet-stream';
}

function blobToDataURL(blob) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = reject;
        reader.readAsDataURL(blob);
    });
}

function analyzeBinaryHeader(bytes) {
    const info = { format: 'Unknown', details: [] };

    if (isMachOBinary(bytes)) {
        const magic = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
        const isLE = magic !== 0xFEEDFACE && magic !== 0xFEEDFACF && magic !== 0xCAFEBABE;

        let m = isLE ? ((bytes[3] << 24) | (bytes[2] << 16) | (bytes[1] << 8) | bytes[0]) : magic;

        if (m === 0xCAFEBABE) {
            info.format = 'Mach-O FAT Binary (Universal)';
            const nfat = isLE ?
                ((bytes[7] << 24) | (bytes[6] << 16) | (bytes[5] << 8) | bytes[4]) :
                ((bytes[4] << 24) | (bytes[5] << 16) | (bytes[6] << 8) | bytes[7]);
            info.details.push(`Architectures: ${nfat}`);
        } else if (m === 0xFEEDFACE) {
            info.format = 'Mach-O 32-bit';
        } else if (m === 0xFEEDFACF) {
            info.format = 'Mach-O 64-bit';
        }

        if (m !== 0xCAFEBABE && bytes.length > 8) {
            const cpuType = isLE ?
                ((bytes[7] << 24) | (bytes[6] << 16) | (bytes[5] << 8) | bytes[4]) :
                ((bytes[4] << 24) | (bytes[5] << 16) | (bytes[6] << 8) | bytes[7]);

            const cpuNames = {
                7: 'x86', 12: 'ARM', 16777223: 'x86_64', 16777228: 'ARM64'
            };
            info.details.push(`CPU: ${cpuNames[cpuType] || 'Unknown (0x' + cpuType.toString(16) + ')'}`);

            const fileType = isLE ?
                ((bytes[15] << 24) | (bytes[14] << 16) | (bytes[13] << 8) | bytes[12]) :
                ((bytes[12] << 24) | (bytes[13] << 16) | (bytes[14] << 8) | bytes[15]);

            const fileTypes = {
                1: 'Object', 2: 'Executable', 3: 'Fixed VM Library',
                4: 'Core', 5: 'Preload', 6: 'Dylib', 7: 'Dylinker',
                8: 'Bundle', 9: 'Dylib Stub', 10: 'Dsym', 11: 'Kext'
            };
            info.details.push(`Type: ${fileTypes[fileType] || 'Unknown'}`);
        }

        info.segments = extractMachOSegments(bytes, isLE, m === 0xFEEDFACF);
    }

    info.details.push(`Size: ${formatSize(bytes.length)}`);
    return info;
}

function extractMachOSegments(bytes, isLE, is64) {
    const segments = [];
    try {
        const headerSize = is64 ? 32 : 28;
        const ncmds = readUInt32(bytes, is64 ? 16 : 16, isLE);

        let offset = headerSize;
        for (let i = 0; i < ncmds && offset < bytes.length - 8; i++) {
            const cmd = readUInt32(bytes, offset, isLE);
            const cmdsize = readUInt32(bytes, offset + 4, isLE);

            if (cmd === 0x19 || cmd === 0x1) {
                const nameBytes = bytes.slice(offset + 8, offset + 24);
                const name = String.fromCharCode(...nameBytes).replace(/\0/g, '');
                const vmaddr = is64 ? readUInt64(bytes, offset + 24, isLE) : readUInt32(bytes, offset + 24, isLE);
                const vmsize = is64 ? readUInt64(bytes, offset + 32, isLE) : readUInt32(bytes, offset + 28, isLE);
                segments.push({ name, vmaddr: '0x' + vmaddr.toString(16), vmsize: formatSize(vmsize) });
            }

            offset += cmdsize;
            if (cmdsize === 0) break;
        }
    } catch (e) {}
    return segments;
}

function readUInt32(bytes, offset, isLE) {
    if (isLE) {
        return (bytes[offset + 3] << 24) | (bytes[offset + 2] << 16) | (bytes[offset + 1] << 8) | bytes[offset];
    }
    return (bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3];
}

function readUInt64(bytes, offset, isLE) {

    return readUInt32(bytes, offset, isLE);
}

function searchBinaryStrings(query) {
    if (!state.binaryStrings.length) return [];

    const lower = query.toLowerCase();
    return state.binaryStrings
        .filter(s => s.str.toLowerCase().includes(lower))
        .slice(0, 500)
        .map(s => ({
            string: s.str,
            offset: '0x' + s.offset.toString(16),
            length: s.str.length
        }));
}

function searchFiles(query) {
    if (!state.analysisResults) return [];

    const lower = query.toLowerCase();
    return state.analysisResults.files
        .filter(f => f.toLowerCase().includes(lower))
        .slice(0, 100);
}

async function sha256(buffer) {
    const hash = await crypto.subtle.digest('SHA-256', buffer);
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function formatSize(bytes) {
    const units = ['B', 'KB', 'MB', 'GB'];
    let i = 0;
    while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
    return bytes.toFixed(1) + ' ' + units[i];
}

function showLoading(text) {
    const overlay = document.getElementById('loadingOverlay');
    const textEl = document.getElementById('loadingText');
    if (overlay) overlay.classList.add('active');
    if (textEl) textEl.textContent = text;
}

function hideLoading() {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) overlay.classList.remove('active');
}

function updateProgress(percent, text) {
    const fill = document.getElementById('progressFill');
    const textEl = document.getElementById('progressText');
    if (fill) fill.style.width = percent + '%';
    if (textEl) textEl.textContent = text;
}

function escapeHtml(text) {
    if (text == null) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

function escapeAttr(text) {
    if (text == null) return '';
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/'/g, '&#39;')
        .replace(/"/g, '&quot;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

function escapeJs(text) {
    if (text == null) return '';
    return String(text)
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "\\'")
        .replace(/"/g, '\\"')
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r')
        .replace(/</g, '\\x3c')
        .replace(/>/g, '\\x3e');
}

function renderResults(results) {
    document.getElementById('resultsSection').style.display = 'block';
    document.getElementById('progressContainer').style.display = 'none';

    document.getElementById('appName').textContent = results.appInfo.appName || 'Unknown';
    document.getElementById('bundleId').textContent = results.appInfo.bundleId || '';
    document.getElementById('appVersion').textContent = `v${results.appInfo.version || '?'} (${results.appInfo.build || '?'})`;
    document.getElementById('appSize').textContent = results.appInfo.fileSize;
    document.getElementById('appType').textContent = results.binType;

    const score = results.securityScore;
    document.getElementById('scoreCircle').style.setProperty('--score', score);
    document.getElementById('scoreValue').textContent = score;
    document.getElementById('highCount').textContent = state.groupedFindings.high.length;
    document.getElementById('warningCount').textContent = state.groupedFindings.warning.length;
    document.getElementById('infoCount').textContent = state.groupedFindings.info.length;
    document.getElementById('secureCount').textContent = state.groupedFindings.secure.length;

    renderOverviewTab(results);
    renderFindingsTab(results);
    renderBinaryTab(results);
    renderExplorerTab(results);
    renderStringsTab(results);
    renderPlistTab(results);
}

function renderOverviewTab(results) {
    const grid = document.getElementById('appInfoGrid');
    const items = [
        ['Bundle ID', results.appInfo.bundleId],
        ['Version', results.appInfo.version],
        ['Build', results.appInfo.build],
        ['Min iOS', results.appInfo.minOS],
        ['Executable', results.appInfo.executableName],
        ['Binary Type', results.binType],
        ['Total Files', results.files.length],
        ['SHA-256', results.appInfo.sha256?.slice(0, 16) + '...']
    ];
    grid.innerHTML = items.filter(([,v]) => v).map(([k, v]) => `
        <div class="info-item"><label>${k}</label><div class="value">${escapeHtml(String(v))}</div></div>
    `).join('');

    const permList = document.getElementById('permissionsList');
    if (permList) {
        const perms = Object.entries(results.permissions);
        permList.innerHTML = perms.length === 0 ? '<div class="no-data">No permissions</div>' :
            perms.map(([k, v]) => `<div class="permission-tag" title="${escapeHtml(v.reason)}">${escapeHtml(v.name)}</div>`).join('');
    }

    const schemesList = document.getElementById('urlSchemesList');
    if (schemesList) {
        schemesList.innerHTML = results.urlSchemes.length === 0 ? '<div class="no-data">None</div>' :
            results.urlSchemes.map(s => `<span class="scheme-tag">${escapeHtml(s)}://</span>`).join('');
    }

    const trackersList = document.getElementById('trackersList');
    if (trackersList) {
        trackersList.innerHTML = results.trackers.length === 0 ? '<div class="no-data">None detected</div>' :
            results.trackers.map(t => `<span class="tracker-tag">${escapeHtml(t)}</span>`).join('');
    }
}

function renderFindingsTab(results) {
    const container = document.getElementById('findingsList');
    const allGrouped = [
        ...state.groupedFindings.high,
        ...state.groupedFindings.warning,
        ...state.groupedFindings.info,
        ...state.groupedFindings.secure
    ];

    if (allGrouped.length === 0) {
        container.innerHTML = '<div class="no-data">No findings</div>';
        return;
    }

    container.innerHTML = allGrouped.map((f, i) => {
        const instanceCount = f.instances.length;
        const instancesHtml = f.instances.map((inst, j) => `
            <div class="instance-item" onclick="openFileInExplorer('${escapeJs(inst.file)}', ${parseInt(inst.line) || 0})">
                <div class="instance-header">
                    <span class="instance-number">#${j + 1}</span>
                    <span class="instance-file">${escapeHtml(inst.file)}${inst.line ? ':' + inst.line : ''}</span>
                    ${inst.binaryOffset ? `<span class="instance-offset">@ ${inst.binaryOffset}</span>` : ''}
                </div>
                <div class="instance-match"><code>${escapeHtml(inst.match)}</code></div>
                <pre class="instance-snippet">${escapeHtml(inst.snippet)}</pre>
            </div>
        `).join('');

        return `
            <div class="finding-card ${f.severity}" data-finding-id="${i}">
                <div class="finding-header" onclick="toggleFinding(${i})">
                    <span class="severity-badge ${f.severity}">${f.severity.toUpperCase()}</span>
                    <span class="finding-title">${escapeHtml(f.ruleName)}</span>
                    <span class="instance-count">${instanceCount} instance${instanceCount > 1 ? 's' : ''}</span>
                    <span class="finding-toggle">▼</span>
                </div>
                <div class="finding-body" id="finding-body-${i}">
                    <div class="finding-description">${escapeHtml(f.description)}</div>
                    <div class="finding-meta">
                        ${f.cwe ? `<span class="meta-tag">CWE: ${f.cwe}</span>` : ''}
                        ${f.owasp ? `<span class="meta-tag">OWASP: ${f.owasp}</span>` : ''}
                        ${f.masvs ? `<span class="meta-tag">MASVS: ${f.masvs}</span>` : ''}
                    </div>
                    <div class="instances-section">
                        <div class="instances-header">Found in ${instanceCount} location${instanceCount > 1 ? 's' : ''}:</div>
                        <div class="instances-list">${instancesHtml}</div>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function toggleFinding(idx) {
    const body = document.getElementById(`finding-body-${idx}`);
    if (body) body.classList.toggle('expanded');
}

function renderBinaryTab(results) {

    const checks = [
        ['PIE (ASLR)', results.checksec.pie, 'Position Independent Executable'],
        ['ARC', results.checksec.arc, 'Automatic Reference Counting'],
        ['Stack Canary', results.checksec.canary, 'Buffer overflow protection'],
        ['64-bit', results.checksec.is64bit, 'Modern architecture']
    ];

    document.getElementById('checksecGrid').innerHTML = checks.map(([name, ok, desc]) => `
        <div class="checksec-item ${ok ? 'pass' : 'fail'}">
            <div class="checksec-status">${ok ? '✓' : '✗'}</div>
            <div class="checksec-info">
                <div class="checksec-name">${name}</div>
                <div class="checksec-desc">${desc}</div>
            </div>
        </div>
    `).join('');

    document.getElementById('librariesList').innerHTML = results.libraries.length === 0 ?
        '<div class="no-data">No libraries detected</div>' :
        results.libraries.map(l => `<div class="library-item">${escapeHtml(l)}</div>`).join('');
}

function renderExplorerTab(results) {

    const treeContainer = document.getElementById('fileTree');
    treeContainer.innerHTML = renderTree(results.fileTree, '');

    const searchInput = document.getElementById('fileSearchInput');
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            const query = e.target.value;
            if (query.length >= 2) {
                const matches = searchFiles(query);
                showSearchResults('fileSearchResults', matches, openFileInExplorer);
            } else {
                document.getElementById('fileSearchResults').innerHTML = '';
            }
        });
    }
}

function renderTree(tree, prefix) {
    let html = '';
    const entries = Object.entries(tree).filter(([k]) => !k.startsWith('_')).sort((a, b) => {
        const aIsDir = a[1]._type === 'dir';
        const bIsDir = b[1]._type === 'dir';
        if (aIsDir !== bIsDir) return aIsDir ? -1 : 1;
        return a[0].localeCompare(b[0]);
    });

    for (const [name, node] of entries) {
        if (node._type === 'dir') {
            html += `
                <div class="tree-folder">
                    <div class="tree-folder-header" onclick="this.parentElement.classList.toggle('open')">
                        <span class="folder-icon">📁</span>
                        <span class="folder-name">${escapeHtml(name)}</span>
                    </div>
                    <div class="tree-folder-content">${renderTree(node, prefix + name + '/')}</div>
                </div>
            `;
        } else {
            const ext = name.split('.').pop().toLowerCase();
            const icon = getFileIcon(ext);
            html += `
                <div class="tree-file" onclick="openFileInExplorer('${escapeJs(node._path)}')">
                    <span class="file-icon">${icon}</span>
                    <span class="file-name">${escapeHtml(name)}</span>
                </div>
            `;
        }
    }
    return html;
}

function getFileIcon(ext) {
    const icons = {
        'swift': '🔶', 'm': '📘', 'h': '📄', 'plist': '📋', 'json': '📜',
        'xml': '📰', 'db': '🗄️', 'sqlite': '🗄️', 'realm': '🗄️',
        'png': '🖼️', 'jpg': '🖼️', 'jpeg': '🖼️', 'gif': '🖼️',
        'js': '📒', 'html': '🌐', 'css': '🎨', 'strings': '🔤',
        'cer': '🔐', 'pem': '🔐', 'p12': '🔐', 'dylib': '⚙️'
    };
    return icons[ext] || '📄';
}

async function openFileInExplorer(filePath, line = 0) {

    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelector('[data-tab="explorer"]')?.classList.add('active');
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.getElementById('tab-explorer')?.classList.add('active');

    const viewer = document.getElementById('fileViewer');
    const pathDisplay = document.getElementById('currentFilePath');

    let actualPath = filePath;
    let isBinaryReference = false;
    if (filePath.startsWith('BINARY:')) {
        const execName = filePath.replace('BINARY:', '');

        actualPath = execName;
        isBinaryReference = true;
    }

    pathDisplay.textContent = filePath;
    viewer.innerHTML = '<div class="loading-file">Loading...</div>';

    const content = await loadFileContent(actualPath, { isBinaryReference });

    if (!content) {
        viewer.innerHTML = '<div class="no-data">Unable to load file</div>';
        return;
    }

    if (content.type === 'image') {
        viewer.innerHTML = `
            <div class="image-viewer">
                <div class="image-info">
                    <span class="info-badge">${content.ext.toUpperCase()}</span>
                    <span class="info-badge">${formatSize(content.size)}</span>
                </div>
                <div class="image-container">
                    <img src="${content.dataUrl}" alt="${escapeHtml(filePath)}" />
                </div>
            </div>
        `;
        return;
    }

    if (content.type === 'binary') {
        viewer.innerHTML = renderBinaryViewer(content, filePath);
        setupBinaryViewerEvents(content, filePath);
        return;
    }

    if (typeof content === 'string') {
        const lines = content.split('\n');
        const numbered = lines.map((l, i) => {
            const lineNum = i + 1;
            const highlight = lineNum === line ? ' class="highlight-line"' : '';
            return `<div${highlight}><span class="line-num">${lineNum}</span><span class="line-content">${escapeHtml(l)}</span></div>`;
        }).join('');
        viewer.innerHTML = `<div class="code-viewer">${numbered}</div>`;

        if (line > 0) {
            const highlightedLine = viewer.querySelector('.highlight-line');
            if (highlightedLine) highlightedLine.scrollIntoView({ block: 'center' });
        }
        return;
    }

    viewer.innerHTML = '<div class="no-data">Unable to display file</div>';
}

function renderBinaryViewer(content, filePath) {
    const { data, header, isMachO, size } = content;
    const offset = content.offset || 0;
    const bytesPerPage = 4096;
    const totalPages = Math.ceil(size / bytesPerPage);
    const currentPage = Math.floor(offset / bytesPerPage);
    const viewMode = content.viewMode || 'hex';

    let segmentsHtml = '';
    if (isMachO && header.segments && header.segments.length > 0) {
        segmentsHtml = `
            <div class="binary-section">
                <h4>Segments</h4>
                <table class="segments-table">
                    <tr><th>Name</th><th>VM Address</th><th>VM Size</th></tr>
                    ${header.segments.map(s => `<tr><td>${escapeHtml(s.name)}</td><td>${s.vmaddr}</td><td>${s.vmsize}</td></tr>`).join('')}
                </table>
            </div>
        `;
    }

    const searchInfo = content.searchResults ?
        `<span class="search-info">Found ${content.searchResults.length} matches${content.currentMatch !== undefined ? ` (${content.currentMatch + 1}/${content.searchResults.length})` : ''}</span>` : '';

    let viewContent = '';
    if (viewMode === 'hex') {
        viewContent = renderHexView(content, data, offset, bytesPerPage, size);
    } else if (viewMode === 'strings') {
        viewContent = renderStringsView(content, data);
    }

    return `
        <div class="binary-viewer">
            <div class="binary-header">
                <div class="binary-info">
                    <span class="info-badge format">${escapeHtml(header.format)}</span>
                    ${header.details.map(d => `<span class="info-badge">${escapeHtml(d)}</span>`).join('')}
                </div>
                ${segmentsHtml}
            </div>
            <div class="binary-view-tabs">
                <button class="view-tab ${viewMode === 'hex' ? 'active' : ''}" data-view="hex">Hex Dump</button>
                <button class="view-tab ${viewMode === 'strings' ? 'active' : ''}" data-view="strings">Strings</button>
            </div>
            ${viewMode === 'hex' ? `
            <div class="hex-controls">
                <button class="hex-nav" data-action="first" ${currentPage === 0 ? 'disabled' : ''}>⏮ First</button>
                <button class="hex-nav" data-action="prev" ${currentPage === 0 ? 'disabled' : ''}>◀ Prev</button>
                <span class="hex-page-info">Page ${currentPage + 1} of ${totalPages} (offset 0x${offset.toString(16)})</span>
                <button class="hex-nav" data-action="next" ${currentPage >= totalPages - 1 ? 'disabled' : ''}>Next ▶</button>
                <button class="hex-nav" data-action="last" ${currentPage >= totalPages - 1 ? 'disabled' : ''}>Last ⏭</button>
                <input type="text" class="hex-goto" placeholder="Go to offset (hex)..." />
            </div>
            <div class="hex-search-controls">
                <input type="text" class="hex-search" placeholder="Search string..." value="${escapeHtml(content.searchQuery || '')}" />
                <button class="hex-search-btn">Search</button>
                <button class="hex-search-prev" ${!content.searchResults?.length ? 'disabled' : ''}>◀ Prev</button>
                <button class="hex-search-next" ${!content.searchResults?.length ? 'disabled' : ''}>Next ▶</button>
                ${searchInfo}
            </div>
            ` : ''}
            ${viewMode === 'strings' ? (() => {
                const stringsPerPage = 200;
                const stringsPage = content.stringsPage || 0;
                const filter = (content.stringsFilter || '').toLowerCase();
                const allStrings = content.extractedStrings || [];
                const filteredStrings = filter ? allStrings.filter(s => s.str.toLowerCase().includes(filter)) : allStrings;
                const totalStringsPages = Math.ceil(filteredStrings.length / stringsPerPage);
                return `
            <div class="strings-filter">
                <input type="text" class="strings-filter-input" placeholder="Filter strings..." value="${escapeHtml(content.stringsFilter || '')}" />
                <span class="strings-count">${filteredStrings.length} strings${filter ? ' (filtered)' : ''}</span>
            </div>
            <div class="strings-nav">
                <button class="strings-nav-btn" data-action="first" ${stringsPage === 0 ? 'disabled' : ''}>⏮ First</button>
                <button class="strings-nav-btn" data-action="prev" ${stringsPage === 0 ? 'disabled' : ''}>◀ Prev</button>
                <span class="strings-page-info">Page ${stringsPage + 1} of ${totalStringsPages || 1}</span>
                <button class="strings-nav-btn" data-action="next" ${stringsPage >= totalStringsPages - 1 ? 'disabled' : ''}>Next ▶</button>
                <button class="strings-nav-btn" data-action="last" ${stringsPage >= totalStringsPages - 1 ? 'disabled' : ''}>Last ⏭</button>
            </div>
            `;
            })() : ''}
            <div class="binary-content">${viewContent}</div>
        </div>
    `;
}

function renderHexView(content, data, offset, bytesPerPage, size) {
    const currentMatchOffset = content.currentMatch !== undefined && content.searchResults
        ? content.searchResults[content.currentMatch] : -1;
    const queryLen = content.searchQuery ? content.searchQuery.length : 0;

    const hexLines = [];
    const viewStart = offset;
    const viewEnd = Math.min(offset + bytesPerPage, size);

    for (let i = viewStart; i < viewEnd; i += 16) {
        const lineEnd = Math.min(i + 16, viewEnd);
        let hexParts = [];
        let asciiParts = [];
        let lineHasHighlight = false;

        for (let j = i; j < lineEnd; j++) {
            const byte = data[j];
            const hexByte = byte.toString(16).padStart(2, '0');
            const asciiChar = byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.';

            const isHighlighted = currentMatchOffset >= 0 &&
                j >= currentMatchOffset &&
                j < currentMatchOffset + queryLen;

            if (isHighlighted) {
                lineHasHighlight = true;
                hexParts.push(`<span class="hex-highlight">${hexByte}</span>`);
                asciiParts.push(`<span class="hex-highlight">${escapeHtml(asciiChar)}</span>`);
            } else {
                hexParts.push(hexByte);
                asciiParts.push(escapeHtml(asciiChar));
            }
        }

        const hex = hexParts.join(' ');
        const ascii = asciiParts.join('');
        const padding = (16 - (lineEnd - i)) * 3;
        const highlightClass = lineHasHighlight ? ' hex-line-highlight' : '';
        const highlightId = lineHasHighlight ? ' id="hex-match-line"' : '';
        hexLines.push(`<div class="hex-line${highlightClass}"${highlightId}><span class="hex-offset">${i.toString(16).padStart(8, '0')}</span><span class="hex-bytes">${hex}${''.padEnd(padding)}</span><span class="hex-ascii">${ascii}</span></div>`);
    }

    return `<div class="hex-dump">${hexLines.join('')}</div>`;
}

function renderStringsView(content, data) {

    if (!content.extractedStrings) {
        content.extractedStrings = extractStringsFromBinary(data);
    }

    const stringsPerPage = 200;
    const stringsPage = content.stringsPage || 0;
    const filter = (content.stringsFilter || '').toLowerCase();
    const filteredStrings = filter
        ? content.extractedStrings.filter(s => s.str.toLowerCase().includes(filter))
        : content.extractedStrings;

    const startIdx = stringsPage * stringsPerPage;
    const endIdx = startIdx + stringsPerPage;
    const displayStrings = filteredStrings.slice(startIdx, endIdx);

    if (filteredStrings.length === 0) {
        return '<div class="no-data">No strings found</div>';
    }

    return `
        <div class="strings-list">
            ${displayStrings.map((s, i) => `
                <div class="string-entry" data-offset="${s.offset}">
                    <span class="string-index">${startIdx + i + 1}</span>
                    <span class="string-offset">0x${s.offset.toString(16).padStart(8, '0')}</span>
                    <span class="string-value">${escapeHtml(s.str)}</span>
                </div>
            `).join('')}
        </div>
    `;
}

function renderImportsView(content, data, isMachO) {

    if (!content.extractedImports) {
        content.extractedImports = extractImportsFromBinary(data, isMachO);
    }

    const imports = content.extractedImports;

    if (!imports || imports.length === 0) {
        return '<div class="no-data">No imports detected</div>';
    }

    const grouped = {};
    imports.forEach(imp => {
        const lib = imp.library || 'Unknown';
        if (!grouped[lib]) grouped[lib] = [];
        grouped[lib].push(imp);
    });

    return `
        <div class="imports-list">
            ${Object.entries(grouped).map(([lib, imps]) => `
                <div class="import-library">
                    <div class="import-lib-header">${escapeHtml(lib)} <span class="import-count">(${imps.length})</span></div>
                    <div class="import-symbols">
                        ${imps.map(imp => `<div class="import-symbol">${escapeHtml(imp.name)}</div>`).join('')}
                    </div>
                </div>
            `).join('')}
        </div>
    `;
}

function extractStringsFromBinary(data, minLength = 4) {
    const strings = [];
    let currentStr = '';
    let startOffset = 0;

    for (let i = 0; i < data.length; i++) {
        const byte = data[i];
        if (byte >= 32 && byte <= 126) {
            if (currentStr.length === 0) startOffset = i;
            currentStr += String.fromCharCode(byte);
        } else {
            if (currentStr.length >= minLength) {
                strings.push({ offset: startOffset, str: currentStr });
            }
            currentStr = '';
        }
    }

    if (currentStr.length >= minLength) {
        strings.push({ offset: startOffset, str: currentStr });
    }

    return strings;
}

function extractImportsFromBinary(data, isMachO) {
    const imports = [];

    if (!isMachO) return imports;

    const strings = extractStringsFromBinary(data, 3);
    const importPatterns = [
        /^_objc_/,
        /^_NS\w+/,
        /^_UI\w+/,
        /^_CG\w+/,
        /^_CF\w+/,
        /^_sec_/,
        /^_sqlite3_/,
        /^_CC\w+/,
        /^_dispatch_/,
        /^_os_log/
    ];

    const seen = new Set();
    strings.forEach(s => {
        if (s.str.startsWith('_') && s.str.length > 2 && !seen.has(s.str)) {
            for (const pattern of importPatterns) {
                if (pattern.test(s.str)) {
                    seen.add(s.str);
                    let library = 'System';
                    if (s.str.startsWith('_objc_')) library = 'libobjc';
                    else if (s.str.startsWith('_NS') || s.str.startsWith('_UI')) library = 'Foundation/UIKit';
                    else if (s.str.startsWith('_CG')) library = 'CoreGraphics';
                    else if (s.str.startsWith('_CF')) library = 'CoreFoundation';
                    else if (s.str.startsWith('_sec_')) library = 'Security';
                    else if (s.str.startsWith('_sqlite3_')) library = 'libsqlite3';
                    else if (s.str.startsWith('_CC')) library = 'CommonCrypto';
                    else if (s.str.startsWith('_dispatch_')) library = 'libdispatch';

                    imports.push({ name: s.str, library });
                    break;
                }
            }
        }
    });

    return imports;
}

function setupBinaryViewerEvents(content, filePath) {
    const viewer = document.getElementById('fileViewer');
    const bytesPerPage = 4096;

    const matchLine = viewer.querySelector('#hex-match-line');
    if (matchLine) {
        setTimeout(() => {
            matchLine.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }, 50);
    }

    viewer.querySelectorAll('.view-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            const newMode = tab.dataset.view;
            if (newMode !== content.viewMode) {
                content.viewMode = newMode;
                viewer.innerHTML = renderBinaryViewer(content, filePath);
                setupBinaryViewerEvents(content, filePath);
            }
        });
    });

    const stringsFilter = viewer.querySelector('.strings-filter-input');
    if (stringsFilter) {
        let filterTimeout;
        stringsFilter.addEventListener('input', () => {
            clearTimeout(filterTimeout);
            filterTimeout = setTimeout(() => {
                content.stringsFilter = stringsFilter.value;
                content.stringsPage = 0;
                viewer.innerHTML = renderBinaryViewer(content, filePath);
                setupBinaryViewerEvents(content, filePath);

                const newInput = document.querySelector('.strings-filter-input');
                if (newInput) {
                    newInput.focus();
                    newInput.setSelectionRange(newInput.value.length, newInput.value.length);
                }
            }, 300);
        });
    }

    viewer.querySelectorAll('.strings-nav-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const action = btn.dataset.action;
            const stringsPerPage = 200;
            const filter = (content.stringsFilter || '').toLowerCase();
            const allStrings = content.extractedStrings || [];
            const filteredStrings = filter ? allStrings.filter(s => s.str.toLowerCase().includes(filter)) : allStrings;
            const totalPages = Math.ceil(filteredStrings.length / stringsPerPage);
            let page = content.stringsPage || 0;

            switch (action) {
                case 'first': page = 0; break;
                case 'prev': page = Math.max(0, page - 1); break;
                case 'next': page = Math.min(totalPages - 1, page + 1); break;
                case 'last': page = Math.max(0, totalPages - 1); break;
            }

            content.stringsPage = page;
            viewer.innerHTML = renderBinaryViewer(content, filePath);
            setupBinaryViewerEvents(content, filePath);
        });
    });

    viewer.querySelectorAll('.string-entry').forEach(entry => {
        entry.addEventListener('click', () => {
            const offset = parseInt(entry.dataset.offset);
            content.viewMode = 'hex';
            content.offset = Math.floor(offset / 16) * 16;
            viewer.innerHTML = renderBinaryViewer(content, filePath);
            setupBinaryViewerEvents(content, filePath);
        });
    });

    viewer.querySelectorAll('.hex-nav').forEach(btn => {
        btn.addEventListener('click', async () => {
            const action = btn.dataset.action;
            let newOffset = content.offset || 0;

            switch (action) {
                case 'first': newOffset = 0; break;
                case 'prev': newOffset = Math.max(0, newOffset - bytesPerPage); break;
                case 'next': newOffset = Math.min(content.size - bytesPerPage, newOffset + bytesPerPage); break;
                case 'last': newOffset = Math.max(0, content.size - bytesPerPage); break;
            }

            content.offset = newOffset;
            viewer.innerHTML = renderBinaryViewer(content, filePath);
            setupBinaryViewerEvents(content, filePath);
        });
    });

    const gotoInput = viewer.querySelector('.hex-goto');
    if (gotoInput) {
        gotoInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                const val = gotoInput.value.trim();
                let offset = parseInt(val, 16);
                if (!isNaN(offset)) {
                    offset = Math.max(0, Math.min(content.size - 1, offset));
                    offset = Math.floor(offset / 16) * 16;
                    content.offset = offset;
                    viewer.innerHTML = renderBinaryViewer(content, filePath);
                    setupBinaryViewerEvents(content, filePath);
                }
            }
        });
    }

    const searchInput = viewer.querySelector('.hex-search');
    const searchBtn = viewer.querySelector('.hex-search-btn');
    const searchPrev = viewer.querySelector('.hex-search-prev');
    const searchNext = viewer.querySelector('.hex-search-next');

    const performSearch = () => {
        const query = searchInput.value.trim();
        if (!query) return;

        content.searchQuery = query;
        content.searchResults = searchBinaryData(content.data, query);
        content.currentMatch = content.searchResults.length > 0 ? 0 : undefined;

        if (content.searchResults.length > 0) {

            jumpToMatch(content, 0);
        }

        viewer.innerHTML = renderBinaryViewer(content, filePath);
        setupBinaryViewerEvents(content, filePath);
    };

    const jumpToMatch = (content, matchIndex) => {
        if (!content.searchResults || matchIndex < 0 || matchIndex >= content.searchResults.length) return;
        content.currentMatch = matchIndex;
        const matchOffset = content.searchResults[matchIndex];

        content.offset = Math.floor(matchOffset / 16) * 16;

        content.offset = Math.max(0, content.offset - bytesPerPage / 2);
        content.offset = Math.floor(content.offset / 16) * 16;
    };

    if (searchBtn) {
        searchBtn.addEventListener('click', performSearch);
    }

    if (searchInput) {
        searchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') performSearch();
        });
    }

    if (searchPrev) {
        searchPrev.addEventListener('click', () => {
            if (!content.searchResults?.length) return;
            const newIndex = (content.currentMatch - 1 + content.searchResults.length) % content.searchResults.length;
            jumpToMatch(content, newIndex);
            viewer.innerHTML = renderBinaryViewer(content, filePath);
            setupBinaryViewerEvents(content, filePath);
        });
    }

    if (searchNext) {
        searchNext.addEventListener('click', () => {
            if (!content.searchResults?.length) return;
            const newIndex = (content.currentMatch + 1) % content.searchResults.length;
            jumpToMatch(content, newIndex);
            viewer.innerHTML = renderBinaryViewer(content, filePath);
            setupBinaryViewerEvents(content, filePath);
        });
    }
}

function searchBinaryData(data, query) {
    const results = [];
    if (!query || !data) return results;

    const queryBytes = [];
    for (let i = 0; i < query.length; i++) {
        queryBytes.push(query.charCodeAt(i));
    }

    let hexBytes = null;
    if (/^[0-9a-fA-F\s]+$/.test(query)) {
        const hexStr = query.replace(/\s+/g, '');
        if (hexStr.length % 2 === 0) {
            hexBytes = [];
            for (let i = 0; i < hexStr.length; i += 2) {
                hexBytes.push(parseInt(hexStr.substr(i, 2), 16));
            }
        }
    }

    for (let i = 0; i <= data.length - queryBytes.length; i++) {
        let match = true;
        for (let j = 0; j < queryBytes.length; j++) {
            if (data[i + j] !== queryBytes[j]) {
                match = false;
                break;
            }
        }
        if (match) results.push(i);
    }

    if (hexBytes && hexBytes.length > 0) {
        for (let i = 0; i <= data.length - hexBytes.length; i++) {
            let match = true;
            for (let j = 0; j < hexBytes.length; j++) {
                if (data[i + j] !== hexBytes[j]) {
                    match = false;
                    break;
                }
            }
            if (match && !results.includes(i)) results.push(i);
        }
    }

    return results.sort((a, b) => a - b);
}

function renderStringsTab(results) {

}

function showSearchResults(containerId, results, clickHandler) {
    const container = document.getElementById(containerId);
    container.innerHTML = results.length === 0 ? '<div class="no-data">No matches</div>' :
        results.map(r => `<div class="search-result" onclick="${escapeAttr(clickHandler.name)}('${escapeJs(r)}')">${escapeHtml(r)}</div>`).join('');
}

function renderPlistTab(results) {
    const plistContent = document.getElementById('plistContent');
    if (results.plistData) {
        plistContent.textContent = JSON.stringify(results.plistData, null, 2);
    } else {
        plistContent.textContent = 'Unable to parse Info.plist';
    }
}

function exportReport() {
    const results = state.analysisResults;
    if (!results) return alert('No results');

    const report = {
        generatedAt: new Date().toISOString(),
        tool: 'IPA Auditor v2.0',
        appInfo: results.appInfo,
        securityScore: results.securityScore,
        summary: {
            high: state.findings.high.length,
            warning: state.findings.warning.length,
            info: state.findings.info.length,
            secure: state.findings.secure.length
        },
        findings: results.findings.map(f => ({
            severity: f.severity,
            rule: f.ruleName,
            file: f.file,
            line: f.line,
            match: f.match,
            description: f.description,
            cwe: f.cwe,
            owasp: f.owasp
        })),
        checksec: results.checksec,
        permissions: results.permissions,
        urls: results.urls,
        trackers: results.trackers
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${results.appInfo.appName || 'ipa'}_audit_report.json`;
    a.click();
}

document.addEventListener('DOMContentLoaded', () => {
    const upload = document.getElementById('uploadSection');
    const input = document.getElementById('fileInput');

    input?.addEventListener('change', e => e.target.files[0] && processFile(e.target.files[0]));

    upload?.addEventListener('dragover', e => { e.preventDefault(); upload.classList.add('dragover'); });
    upload?.addEventListener('dragleave', () => upload.classList.remove('dragover'));
    upload?.addEventListener('drop', e => {
        e.preventDefault();
        upload.classList.remove('dragover');
        const file = e.dataTransfer.files[0];
        if (file?.name.match(/\.(ipa|zip)$/i)) processFile(file);
        else alert('Please drop a valid IPA file');
    });

    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            document.getElementById(`tab-${btn.dataset.tab}`)?.classList.add('active');
        });
    });

    log('IPA Auditor v2.0 initialized');
});

async function processFile(file) {
    document.getElementById('progressContainer').style.display = 'block';
    try {
        const results = await analyzeIPA(file);
        hideLoading();
        renderResults(results);
    } catch (error) {
        hideLoading();
        document.getElementById('progressContainer').style.display = 'none';
        alert('Error: ' + error.message);
        console.error(error);
    }
}

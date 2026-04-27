/** @preserve @author Sandeep Wawdane @license MIT */
(function() {
    'use strict';

    const CONFIG = { buildKey: 'c2FuZGVlcHdhd2RhbmU=', version: 2026 };

    const state = {
        connected: false,
        currentSection: 'overview',
        deviceInfo: {},
        apps: [],
        currentPath: '/storage/emulated/0',
        files: [],
        shellHistory: [],
        shellHistoryIndex: -1,
        shellCwd: '',
        shellRootMode: false,
        showSystemApps: false,
        securityApps: [],
        currentSecurityTab: 'fullScan',
        selectedPackage: '',
        screenshotBlob: null,
        devices: [],
        selectedDeviceSerial: null,
        addMenuOpen: false,
        rootMode: false,
        tcpModalOpen: false
    };
    const escapeHtml = (str) => {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = String(str);
        return div.innerHTML;
    };
    const escapeShellArg = (str) => {
        if (!str) return '';
        return String(str).replace(/[`$\\!"']/g, '\\$&');
    };
    const escapeAttr = (str) => {
        if (!str) return '';
        return String(str).replace(/[&<>"']/g, (c) => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
        }[c]));
    };
    const safeEncode = (str) => {
        try { return btoa(unescape(encodeURIComponent(str))); } catch(e) { return btoa(str); }
    };
    const safeDecode = (str) => {
        try { return decodeURIComponent(escape(atob(str))); } catch(e) { return atob(str); }
    };
    const shellQuote = (path) => {
        return '"' + String(path).replace(/["\\$`]/g, '\\$&') + '"';
    };
    async function shellReadBase64(path) {
        const q = shellQuote(path);
        if (path.startsWith('/sdcard/') || path.startsWith('/storage/emulated/')) {
            return await adb.shell('base64 ' + q);
        }
        return await adb.shell('su -c "base64 ' + q.replace(/"/g, '\\"') + '"');
    }
    function base64ToBytes(b64) {
        const clean = b64.trim().replace(/\s/g, '');
        if (!clean) throw new Error('Empty file or access denied');
        const binary = atob(clean);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes;
    }
    let adb = null;
    let deviceManager = null;
    const el = {
        connectBtn: document.getElementById('connectBtn'),
        disconnectBtn: document.getElementById('disconnectBtn'),
        statusDot: document.getElementById('statusDot'),
        statusText: document.getElementById('statusText'),
        statusPill: document.getElementById('statusPill'),
        contentArea: document.getElementById('contentArea'),
        toastContainer: document.getElementById('toastContainer'),
        loadingOverlay: document.getElementById('loadingOverlay'),
        loadingText: document.getElementById('loadingText'),
        loadingSubtext: document.getElementById('loadingSubtext'),
        deviceSelect: document.getElementById('deviceSelect'),
        addDeviceBtn: document.getElementById('addDeviceBtn'),
        addDeviceMenu: document.getElementById('addDeviceMenu'),
        deviceListContainer: document.getElementById('deviceListContainer')
    };
    function setAmbientActive(active) {
        document.querySelectorAll('.ambient-orb').forEach(orb => {
            orb.classList.toggle('active', active);
        });
    }
    const templates = {
        welcome: `
            <div class="landing-page">
                <section class="hero-section">
                    <div class="hero-canvas">
                        <div class="hero-glow glow-primary active"></div>
                        <div class="hero-glow glow-secondary active"></div>
                        <div class="hero-glow glow-tertiary active"></div>
                        <div class="hero-grid"></div>
                        <div class="hero-particles">
                            <div class="particle"></div>
                            <div class="particle"></div>
                            <div class="particle"></div>
                            <div class="particle"></div>
                            <div class="particle"></div>
                            <div class="particle"></div>
                            <div class="particle"></div>
                            <div class="particle"></div>
                        </div>
                    </div>
                    <div class="hero-content">
                        <h1 class="hero-title">
                            <span class="title-line title-gradient">Android Security</span>
                            <span class="title-line title-accent">Reimagined</span>
                        </h1>
                        <p class="hero-tagline">
                            The most advanced <strong>client-side</strong> Android auditing platform. 
                            Analyze apps, extract data, and perform deep security assessments, 
                            all without your data ever leaving your device.
                        </p>
                        <div class="hero-trust">
                            <div class="trust-item">
                                <div class="trust-icon">
                                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
                                </div>
                                <div class="trust-text">
                                    <span class="trust-label">Privacy</span>
                                    <span class="trust-value">100% Client-Side</span>
                                </div>
                            </div>
                            <div class="trust-item">
                                <div class="trust-icon">
                                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"/></svg>
                                </div>
                                <div class="trust-text">
                                    <span class="trust-label">Data Storage</span>
                                    <span class="trust-value">Zero Upload</span>
                                </div>
                            </div>
                            <div class="trust-item">
                                <div class="trust-icon">
                                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
                                </div>
                                <div class="trust-text">
                                    <span class="trust-label">Protocol</span>
                                    <span class="trust-value">WebUSB + ADB</span>
                                </div>
                            </div>
                        </div>
                        <div class="hero-cta">
                            <button class="btn-hero btn-hero-primary" onclick="document.getElementById('connectBtn').click()">
                                <span>
                                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
                                    Connect Device
                                </span>
                            </button>
                            <a href="https://github.com/thecybersandeep/adbauditor" target="_blank" rel="noopener" class="btn-hero btn-hero-secondary">
                                <span>
                                    <svg viewBox="0 0 24 24" fill="currentColor" width="20" height="20"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
                                    View Source
                                </span>
                            </a>
                        </div>
                    </div>
                    <div class="hero-scroll" onclick="document.querySelector('.features-section').scrollIntoView({behavior:'smooth'})">
                        <div class="scroll-indicator">
                            <div class="scroll-dot"></div>
                        </div>
                        <span>Explore</span>
                    </div>
                </section>

                <div class="section-divider"></div>

                <section class="features-section">
                    <div class="features-header">
                        <span class="section-label">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="14" height="14"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 3v4M3 5h4M6 17v4m-2-2h4m5-16l2.286 6.857L21 12l-5.714 2.143L13 21l-2.286-6.857L5 12l5.714-2.143L13 3z"/></svg>
                            Capabilities
                        </span>
                        <h2 class="section-title">Powerful Security Tools</h2>
                        <p class="section-desc">Everything you need for comprehensive Android security assessments, built right into your browser.</p>
                    </div>
                    <div class="features-grid">
                        <div class="feature-card">
                            <div class="feature-glow"></div>
                            <div class="feature-icon">
                                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"/></svg>
                            </div>
                            <h3>App Analysis</h3>
                            <p>Deep dive into installed applications. Extract APKs, analyze permissions, signatures, and package metadata.</p>
                        </div>
                        <div class="feature-card">
                            <div class="feature-glow"></div>
                            <div class="feature-icon">
                                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>
                            </div>
                            <h3>File System</h3>
                            <p>Full filesystem access with root support. Navigate, upload, download, and manage device files securely.</p>
                        </div>
                        <div class="feature-card">
                            <div class="feature-glow"></div>
                            <div class="feature-icon">
                                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                            </div>
                            <h3>Security Audit</h3>
                            <p>OWASP MASTG aligned tests. Analyze storage, backup configs, exported components, and permissions.</p>
                        </div>
                        <div class="feature-card">
                            <div class="feature-glow"></div>
                            <div class="feature-icon">
                                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>
                            </div>
                            <h3>Shell Access</h3>
                            <p>Direct ADB shell with command history. Execute commands, scripts, and interact with the device in real-time.</p>
                        </div>
                        <div class="feature-card">
                            <div class="feature-glow"></div>
                            <div class="feature-icon">
                                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>
                            </div>
                            <h3>Screenshot</h3>
                            <p>Instant screen capture for documentation. Perfect for evidence collection and audit reporting.</p>
                        </div>
                        <div class="feature-card">
                            <div class="feature-glow"></div>
                            <div class="feature-icon">
                                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.141 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0"/></svg>
                            </div>
                            <h3>Multi-Device</h3>
                            <p>Connect and manage multiple devices simultaneously. Switch between targets seamlessly during assessments.</p>
                        </div>
                    </div>
                </section>

                <section class="setup-section">
                    <div class="setup-header">
                        <span class="section-label">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="14" height="14"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
                            Quick Start
                        </span>
                        <h2 class="section-title">Ready in Seconds</h2>
                        <p class="section-desc">No installation required. Connect your device and start auditing immediately.</p>
                    </div>
                    <div class="setup-steps">
                        <div class="setup-step">
                            <div class="step-number">1</div>
                            <div class="step-content">
                                <h4>Enable USB Debugging</h4>
                                <p>Settings → Developer Options → USB Debugging</p>
                            </div>
                        </div>
                        <div class="setup-step">
                            <div class="step-number">2</div>
                            <div class="step-content">
                                <h4>Connect Device</h4>
                                <p>Use a data-capable USB cable to connect</p>
                            </div>
                        </div>
                        <div class="setup-step">
                            <div class="step-number">3</div>
                            <div class="step-content">
                                <h4>Authorize Access</h4>
                                <p>Accept the USB debugging prompt on device</p>
                            </div>
                        </div>
                        <div class="setup-step">
                            <div class="step-number">4</div>
                            <div class="step-content">
                                <h4>Start Auditing</h4>
                                <p>Click Connect and select your device</p>
                            </div>
                        </div>
                    </div>
                </section>

                <section class="tech-section">
                    <div class="tech-header">
                        <span class="section-label">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="14" height="14"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"/></svg>
                            Technology
                        </span>
                        <h2 class="section-title">Built Different</h2>
                    </div>
                    <div class="tech-grid">
                        <div class="tech-item">
                            <span class="tech-label">Protocol</span>
                            <span class="tech-value">WebUSB + ADB</span>
                        </div>
                        <div class="tech-item">
                            <span class="tech-label">Processing</span>
                            <span class="tech-value">100% Browser</span>
                        </div>
                        <div class="tech-item">
                            <span class="tech-label">Data Upload</span>
                            <span class="tech-value">None</span>
                        </div>
                        <div class="tech-item">
                            <span class="tech-label">Requirements</span>
                            <span class="tech-value">Chrome / Edge</span>
                        </div>
                    </div>
                </section>

                <footer class="landing-footer">
                    <a href="https://github.com/thecybersandeep/adbauditor" target="_blank" rel="noopener noreferrer" class="github-link">
                        <svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
                        <span>Star on GitHub</span>
                    </a>
                    <span class="footer-divider"></span>
                    <span>© 2026 A Project by</span>
                    <a href="https://www.linkedin.com/in/sandeepwawdane/" target="_blank" rel="noopener noreferrer">
                        <svg viewBox="0 0 24 24" fill="currentColor"><path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/></svg>
                        Sandeep
                    </a>
                </footer>
            </div>`,
        overview: `
            <div class="page">
                <div class="page-header">
                    <h1 class="page-title">Device Overview</h1>
                    <div class="page-actions">
                        <button class="btn btn-ghost" onclick="app.loadOverview()">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                            Refresh
                        </button>
                    </div>
                </div>
                <div class="stats-grid" id="statsGrid">
                    <div class="stat-card"><div class="stat-label">Loading</div><div class="stat-value">...</div></div>
                    <div class="stat-card"><div class="stat-label">Loading</div><div class="stat-value">...</div></div>
                    <div class="stat-card"><div class="stat-label">Loading</div><div class="stat-value">...</div></div>
                    <div class="stat-card"><div class="stat-label">Loading</div><div class="stat-value">...</div></div>
                </div>
                <div class="card">
                    <div class="card-header"><span class="card-title">Device Properties</span></div>
                    <div class="prop-list" id="propList"></div>
                </div>
            </div>`,
        apps: `
            <div class="page">
                <div class="page-header">
                    <h1 class="page-title">Applications</h1>
                    <div class="page-actions">
                        <button class="btn btn-ghost" id="toggleSystemApps">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
                            System Apps
                        </button>
                        <button class="btn btn-ghost" onclick="app.loadApps()">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                            Refresh
                        </button>
                    </div>
                </div>
                <div class="drop-zone" id="dropZone" onclick="document.getElementById('apkInput').click()">
                    <input type="file" id="apkInput" accept=".apk" onchange="app.handleApkSelect(event)">
                    <div class="drop-icon">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/></svg>
                    </div>
                    <h3>Install APK</h3>
                    <p>Drop file or click to browse</p>
                </div>
                <div class="search-box">
                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
                    <input type="text" class="search-input" id="appSearch" placeholder="Search applications...">
                </div>
                <div class="card">
                    <div class="app-list" id="appList">
                        <div class="empty-state"><p>Loading applications...</p></div>
                    </div>
                </div>
            </div>`,
        files: `
            <div class="page">
                <div class="page-header">
                    <h1 class="page-title">File Browser</h1>
                    <div class="page-actions">
                        <label class="root-toggle">
                            <input type="checkbox" id="rootToggle" onchange="app.toggleRootMode()">
                            <span class="toggle-slider"></span>
                            <span class="toggle-label">Root</span>
                        </label>
                        <button class="btn btn-ghost" onclick="document.getElementById('fileUploadInput').click()">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/></svg>
                            Upload
                        </button>
                        <input type="file" id="fileUploadInput" multiple style="display:none" onchange="app.handleFileUpload(event)">
                        <button class="btn btn-ghost" onclick="app.navigateUp()">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 10l7-7m0 0l7 7m-7-7v18"/></svg>
                            Up
                        </button>
                        <button class="btn btn-ghost" onclick="app.refreshFiles()">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                            Refresh
                        </button>
                    </div>
                </div>
                <div class="card file-card" id="fileCard">
                    <div class="path-bar" id="pathBar"></div>
                    <div class="file-drop-zone" id="fileDropZone">
                        <div class="drop-indicator">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/></svg>
                            <span>Drop files here to upload</span>
                        </div>
                        <div class="file-list" id="fileList">
                            <div class="empty-state"><p>Loading...</p></div>
                        </div>
                    </div>
                </div>
            </div>`,
        screenshot: `
            <div class="page">
                <div class="page-header">
                    <h1 class="page-title">Screenshot</h1>
                    <div class="page-actions">
                        <button class="btn btn-primary" onclick="app.captureScreenshot()">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 9a2 2 0 012-2h.93a2 2 0 001.664-.89l.812-1.22A2 2 0 0110.07 4h3.86a2 2 0 011.664.89l.812 1.22A2 2 0 0018.07 7H19a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2V9z"/></svg>
                            Capture
                        </button>
                        <button class="btn btn-ghost" id="saveScreenshotBtn" disabled onclick="app.saveScreenshot()">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
                            Save
                        </button>
                    </div>
                </div>
                <div class="screenshot-area" id="screenshotArea">
                    <div class="screenshot-placeholder">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>
                        <p>Click Capture to take a screenshot</p>
                    </div>
                </div>
            </div>`,
        shell: `
            <div class="page">
                <div class="page-header">
                    <h1 class="page-title">Shell</h1>
                    <div class="page-actions">
                        <label class="root-toggle">
                            <input type="checkbox" id="shellRootToggle" onchange="app.toggleShellRoot()">
                            <span class="toggle-slider"></span>
                            <span class="toggle-label">Root</span>
                        </label>
                        <button class="btn btn-ghost" onclick="app.clearShell()">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                            Clear
                        </button>
                    </div>
                </div>
                <div class="shell-container">
                    <div class="shell-header">
                        <div class="shell-dot r"></div>
                        <div class="shell-dot y"></div>
                        <div class="shell-dot g"></div>
                        <span class="shell-title">ADB Shell</span>
                    </div>
                    <div class="shell-output" id="shellOutput">
                        <div class="shell-line" style="color: var(--lum-50);">Type commands and press Enter. Type 'help' for available commands.</div>
                    </div>
                    <div class="shell-input-row">
                        <span class="shell-prompt-char" id="shellPrompt">$</span>
                        <input type="text" class="shell-input" id="shellInput" placeholder="Enter command...">
                    </div>
                </div>
            </div>`,
        security: `
            <div class="page">
                <div class="page-header">
                    <h1 class="page-title">Security Analysis</h1>
                </div>
                <div class="tab-bar">
                    <button class="tab-btn active" data-tab="fullScan" onclick="app.switchSecurityTab('fullScan')">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                        Full Scan
                    </button>
                    <button class="tab-btn" data-tab="localStorage" onclick="app.switchSecurityTab('localStorage')">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4"/></svg>
                        Storage
                    </button>
                    <button class="tab-btn" data-tab="backup" onclick="app.switchSecurityTab('backup')">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4"/></svg>
                        Backup
                    </button>
                    <button class="tab-btn" data-tab="exported" onclick="app.switchSecurityTab('exported')">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
                        Components
                    </button>
                    <button class="tab-btn" data-tab="debuggable" onclick="app.switchSecurityTab('debuggable')">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                        Debug
                    </button>
                    <button class="tab-btn" data-tab="permissions" onclick="app.switchSecurityTab('permissions')">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/></svg>
                        Permissions
                    </button>
                    <button class="tab-btn" data-tab="logcat" onclick="app.switchSecurityTab('logcat')">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h7"/></svg>
                        Logcat
                    </button>
                    <button class="tab-btn" data-tab="appInfo" onclick="app.switchSecurityTab('appInfo')">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                        App Info
                    </button>
                </div>
                <div id="securityTabContent"></div>
            </div>`
    };
    const securityTabs = {
        localStorage: `
            <div class="security-panel">
                <div class="panel-header">
                    <div class="panel-title">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4"/></svg>
                        Local Storage Analyzer
                    </div>
                    <span class="badge warning">Root Required</span>
                </div>
                <p class="panel-desc">Analyze app storage using root access. Extracts SharedPreferences, databases, and internal files.</p>
                <div class="form-row">
                    <select id="storageSelect"><option value="">Select application...</option></select>
                    <button class="btn btn-primary" onclick="app.analyzeStorage()">Analyze</button>
                </div>
                <div id="storageResults"></div>
            </div>`,
        backup: `
            <div class="security-panel">
                <div class="panel-header">
                    <div class="panel-title">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4"/></svg>
                        Backup Configuration
                    </div>
                </div>
                <p class="panel-desc">Check if allowBackup is enabled. Apps with backup enabled may expose sensitive data.</p>
                <div class="form-row">
                    <select id="backupSelect"><option value="">Select application...</option></select>
                    <button class="btn btn-primary" onclick="app.checkBackup()">Check</button>
                </div>
                <div id="backupResults"></div>
            </div>`,
        exported: `
            <div class="security-panel">
                <div class="panel-header">
                    <div class="panel-title">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
                        Exported Components
                    </div>
                </div>
                <p class="panel-desc">Find exported Activities, Services, Receivers, and Providers accessible by other apps.</p>
                <div class="form-row">
                    <select id="exportedSelect"><option value="">Select application...</option></select>
                    <button class="btn btn-primary" onclick="app.analyzeExported()">Analyze</button>
                </div>
                <div id="exportedResults"></div>
            </div>`,
        debuggable: `
            <div class="security-panel">
                <div class="panel-header">
                    <div class="panel-title">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                        Debuggable Check
                    </div>
                </div>
                <p class="panel-desc">Check if the debuggable flag is enabled, allowing debugger attachment.</p>
                <div class="form-row">
                    <select id="debugSelect"><option value="">Select application...</option></select>
                    <button class="btn btn-primary" onclick="app.checkDebuggable()">Check</button>
                </div>
                <div id="debugResults"></div>
            </div>`,
        permissions: `
            <div class="security-panel">
                <div class="panel-header">
                    <div class="panel-title">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/></svg>
                        Dangerous Permissions
                    </div>
                </div>
                <p class="panel-desc">Analyze dangerous runtime permissions granted to the application.</p>
                <div class="form-row">
                    <select id="permSelect"><option value="">Select application...</option></select>
                    <button class="btn btn-primary" onclick="app.analyzePermissions()">Analyze</button>
                </div>
                <div id="permResults"></div>
            </div>`,
        logcat: `
            <div class="security-panel">
                <div class="panel-header">
                    <div class="panel-title">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h7"/></svg>
                        Live Logcat
                    </div>
                    <div style="display:flex;gap:8px;align-items:center">
                        <span class="badge" id="logcatStatus">Stopped</span>
                        <button class="btn btn-ghost" onclick="app.downloadLogcat()" title="Download Logs">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width:16px;height:16px"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
                        </button>
                    </div>
                </div>
                <p class="panel-desc">Stream live device logs with grep filter. Monitor app behavior in real-time.</p>
                <div class="logcat-controls">
                    <input type="text" id="logcatFilter" class="logcat-input" placeholder="Filter (e.g. ActivityManager, Error, com.app.name)">
                    <button class="btn btn-primary" id="logcatStartBtn" onclick="app.startLogcat()">Start</button>
                    <button class="btn btn-danger hidden" id="logcatStopBtn" onclick="app.stopLogcat()">Stop</button>
                    <button class="btn btn-ghost" onclick="app.clearLogcat()" title="Clear Logs">Clear</button>
                </div>
                <div id="logcatOutput" class="logcat-output"></div>
            </div>`,
        appInfo: `
            <div class="security-panel">
                <div class="panel-header">
                    <div class="panel-title">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                        Application Details
                    </div>
                </div>
                <p class="panel-desc">View detailed metadata, flags, install dates, signing info, and resource usage for any installed app.</p>
                <div class="form-row">
                    <select id="appInfoSelect"><option value="">Select application...</option></select>
                    <button class="btn btn-primary" onclick="app.loadAppInfo()">Inspect</button>
                </div>
                <div id="appInfoResults"></div>
            </div>`,
        fullScan: `
            <div class="security-panel">
                <div class="panel-header">
                    <div class="panel-title">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                        Full Security Scan
                    </div>
                    <span class="badge warning">Comprehensive</span>
                </div>
                <p class="panel-desc">Run all security tests against a single application. Checks storage, backup, components, signing, network, permissions, and more.</p>
                <div class="form-row">
                    <select id="fullScanSelect"><option value="">Select application...</option></select>
                    <button class="btn btn-primary" onclick="app.runFullScan()">Run Full Scan</button>
                </div>
                <div id="fullScanProgress" class="hidden" style="margin-top:12px">
                    <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
                        <div class="spinner-sm"></div>
                        <span id="fullScanStatus" style="color:var(--lum-60);font-size:13px">Starting...</span>
                    </div>
                    <div style="background:var(--surface-2);border-radius:4px;height:4px;overflow:hidden"><div id="fullScanBar" style="background:var(--primary);height:100%;width:0%;transition:width 0.3s"></div></div>
                </div>
                <div id="fullScanResults"></div>
            </div>`
    };

    function showToast(message, type = 'info') {
        const icons = {
            success: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>',
            error: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>',
            warning: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>',
            info: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>'
        };
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `<svg class="toast-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">${icons[type]}</svg><span class="toast-text"></span>`;
        toast.querySelector('.toast-text').textContent = message;
        el.toastContainer.appendChild(toast);
        setTimeout(() => toast.remove(), 4000);
    }
    function showLoading(text = 'Loading...', subtext = '') {
        el.loadingText.textContent = text;
        el.loadingSubtext.textContent = subtext;
        el.loadingOverlay.classList.add('visible');
    }
    function hideLoading() {
        el.loadingOverlay.classList.remove('visible');
    }
    function formatSize(bytes) {
        const num = parseInt(bytes);
        if (isNaN(num)) return bytes;
        if (num < 1024) return num + ' B';
        if (num < 1048576) return (num / 1024).toFixed(1) + ' KB';
        if (num < 1073741824) return (num / 1048576).toFixed(1) + ' MB';
        return (num / 1073741824).toFixed(1) + ' GB';
    }
    function setupLandingInteractivity() {
        const featureCards = document.querySelectorAll('.feature-card');
        featureCards.forEach(card => {
            card.addEventListener('mousemove', (e) => {
                const rect = card.getBoundingClientRect();
                const x = ((e.clientX - rect.left) / rect.width) * 100;
                const y = ((e.clientY - rect.top) / rect.height) * 100;
                card.style.setProperty('--mouse-x', x + '%');
                card.style.setProperty('--mouse-y', y + '%');
            });
        });
        const heroContent = document.querySelector('.hero-content');
        if (heroContent) {
            document.addEventListener('mousemove', (e) => {
                const x = (e.clientX / window.innerWidth - 0.5) * 20;
                const y = (e.clientY / window.innerHeight - 0.5) * 20;
                const glows = document.querySelectorAll('.hero-glow');
                glows.forEach((glow, i) => {
                    const factor = (i + 1) * 0.5;
                    glow.style.transform = `translate(${x * factor}px, ${y * factor}px)`;
                });
            });
        }
    }
    function navigate(section) {
        if (section !== 'overview' && !state.connected) return;
        state.currentSection = section;
        document.querySelectorAll('.dock-item').forEach(item => {
            item.classList.toggle('active', item.dataset.section === section);
        });
        const dock = document.querySelector('.dock');
        const main = document.querySelector('.main');
        if (!state.connected && section === 'overview') {
            el.contentArea.innerHTML = templates.welcome;
            if (dock) dock.style.display = 'none';
            if (main) {
                main.style.marginLeft = 'auto';
                main.style.marginRight = 'auto';
            }
            setupLandingInteractivity();
            return;
        }
        if (dock) dock.style.display = '';
        if (main) {
            main.style.marginLeft = '';
            main.style.marginRight = '';
        }
        el.contentArea.innerHTML = templates[section] || templates.welcome;
        switch (section) {
            case 'overview': app.loadOverview(); break;
            case 'apps': setupApps(); break;
            case 'files': app.loadFiles(state.currentPath); break;
            case 'shell': setupShell(); break;
            case 'security': setupSecurity(); break;
        }
    }
    function setupApps() {
        app.loadApps();
        const dropZone = document.getElementById('dropZone');
        if (dropZone) {
            dropZone.addEventListener('dragover', e => {
                e.preventDefault();
                dropZone.classList.add('drag-over');
            });
            dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
            dropZone.addEventListener('drop', e => {
                e.preventDefault();
                dropZone.classList.remove('drag-over');
                const file = e.dataTransfer.files[0];
                if (file?.name.endsWith('.apk')) {
                    app.installApk(file);
                } else {
                    showToast('Please drop a valid APK file', 'warning');
                }
            });
        }
        const search = document.getElementById('appSearch');
        if (search) {
            search.addEventListener('input', () => app.filterApps(search.value));
        }
        const toggleBtn = document.getElementById('toggleSystemApps');
        if (toggleBtn) {
            if (state.showSystemApps) toggleBtn.classList.add('active');
            toggleBtn.addEventListener('click', () => {
                state.showSystemApps = !state.showSystemApps;
                toggleBtn.style.background = state.showSystemApps ? 'var(--pulse-subtle)' : '';
                toggleBtn.style.color = state.showSystemApps ? 'var(--pulse)' : '';
                app.loadApps();
            });
        }
    }
    function setupShell() {
        const input = document.getElementById('shellInput');
        const prompt = document.getElementById('shellPrompt');
        const shellRootToggle = document.getElementById('shellRootToggle');
        if (shellRootToggle) {
            shellRootToggle.checked = state.shellRootMode;
        }
        if (prompt) {
            const p = state.shellRootMode ? '#' : '$';
            prompt.textContent = state.shellCwd ? state.shellCwd + ' ' + p : p;
        }
        if (input) {
            input.addEventListener('keydown', async e => {
                if (e.key === 'Enter' && input.value.trim()) {
                    const cmd = input.value.trim();
                    input.value = '';
                    await app.executeCommand(cmd);
                    const pr = document.getElementById('shellPrompt');
                    if (pr) {
                        const ch = state.shellRootMode ? '#' : '$';
                        pr.textContent = state.shellCwd ? state.shellCwd + ' ' + ch : ch;
                    }
                } else if (e.key === 'ArrowUp') {
                    e.preventDefault();
                    if (state.shellHistoryIndex < state.shellHistory.length - 1) {
                        state.shellHistoryIndex++;
                        input.value = state.shellHistory[state.shellHistory.length - 1 - state.shellHistoryIndex];
                    }
                } else if (e.key === 'ArrowDown') {
                    e.preventDefault();
                    if (state.shellHistoryIndex > 0) {
                        state.shellHistoryIndex--;
                        input.value = state.shellHistory[state.shellHistory.length - 1 - state.shellHistoryIndex];
                    } else {
                        state.shellHistoryIndex = -1;
                        input.value = '';
                    }
                }
            });
            input.focus();
        }
    }
    async function setupSecurity() {
        app.switchSecurityTab('fullScan');
        await loadSecurityApps();
    }
    async function loadSecurityApps() {
        const selectMap = {
            localStorage: 'storageSelect',
            backup: 'backupSelect',
            exported: 'exportedSelect',
            debuggable: 'debugSelect',
            permissions: 'permSelect',
            appInfo: 'appInfoSelect',
            fullScan: 'fullScanSelect'
        };
        const currentSelectId = selectMap[state.currentSecurityTab];
        const currentSelect = document.getElementById(currentSelectId);
        if (currentSelect) {
            currentSelect.innerHTML = '<option value="">Loading applications...</option>';
            currentSelect.disabled = true;
        }
        try {
            state.securityApps = await adb.listPackages(false);
            Object.values(selectMap).forEach(id => populateSelect(id));
        } catch (e) {
            console.error('Failed to load apps:', e);
            state.securityApps = [];
            if (currentSelect) {
                currentSelect.innerHTML = '<option value="">Failed to load apps</option>';
            }
        }
    }
    function populateSelect(selectId) {
        const select = document.getElementById(selectId);
        if (!select) return;
        select.disabled = false;
        if (state.securityApps.length > 0) {
            select.innerHTML = '<option value="">Select application...</option>' +
                state.securityApps.map(p => `<option value="${escapeAttr(p)}">${escapeHtml(p)}</option>`).join('');
        } else {
            select.innerHTML = '<option value="">No applications found</option>';
        }
    }
    const app = {
        async initDeviceManager() {
            if (typeof DeviceManager === 'undefined') {
                console.warn('DeviceManager not available');
                return;
            }
            deviceManager = new DeviceManager();
            deviceManager.addEventListener((event, data) => {
                switch (event) {
                    case 'devicesChanged':
                        this.updateDeviceList(data);
                        break;
                    case 'activeDeviceDisconnected':
                        this.handleDeviceDisconnected(data);
                        break;
                    case 'deviceAdded':
                        showToast(`Device detected: ${data.displayName}`, 'info');
                        break;
                    case 'deviceRemoved':
                        if (data.serial === state.selectedDeviceSerial && state.connected) {
                            this.handleDeviceDisconnected(data);
                        }
                        break;
                }
            });
            await deviceManager.initialize();
            this.updateDeviceList(deviceManager.getDeviceList());
        },
        updateDeviceList(devices) {
            state.devices = devices || [];
            if (el.deviceSelect) {
                if (state.devices.length === 0) {
                    el.deviceSelect.innerHTML = '<option value="">No devices found</option>';
                    el.deviceSelect.disabled = true;
                } else {
                    el.deviceSelect.innerHTML = state.devices.map(d => 
                        `<option value="${escapeAttr(d.serial)}" ${d.serial === state.selectedDeviceSerial ? 'selected' : ''}>${escapeHtml(d.displayName)}</option>`
                    ).join('');
                    el.deviceSelect.disabled = false;
                    if (!state.selectedDeviceSerial && state.devices.length > 0) {
                        state.selectedDeviceSerial = state.devices[0].serial;
                    }
                }
            }
            if (el.connectBtn && !state.connected) {
                el.connectBtn.disabled = false;
            }
        },
        onDeviceSelect(serial) {
            state.selectedDeviceSerial = serial;
        },
        toggleAddMenu() {
            state.addMenuOpen = !state.addMenuOpen;
            if (el.addDeviceMenu) {
                el.addDeviceMenu.classList.toggle('show', state.addMenuOpen);
            }
        },
        closeAddMenu() {
            state.addMenuOpen = false;
            if (el.addDeviceMenu) {
                el.addDeviceMenu.classList.remove('show');
            }
        },
        async addUSBDevice() {
            this.closeAddMenu();
            try {
                const device = await deviceManager.requestUSBDevice();
                if (device) {
                    state.selectedDeviceSerial = device.serial;
                    showToast(`Device paired: ${device.displayName}`, 'success');
                }
            } catch (e) {
                if (e.message !== 'No device selected') {
                    showToast('Failed to add device: ' + e.message, 'error');
                }
            }
        },
        showWebSocketModal() {
            this.closeAddMenu();
            showToast('WebSocket connection coming soon!', 'info');
        },
        showTCPModal() {
            this.closeAddMenu();
            showToast('WebSocket connection coming soon!', 'info');
        },
        closeTCPModal() {
            state.tcpModalOpen = false;
            document.getElementById('tcpModal').classList.remove('show');
            document.getElementById('tcpIpInput').value = '';
            document.getElementById('tcpPortInput').value = '5555';
        },
        addTCPDeviceFromModal() {
            const ipInput = document.getElementById('tcpIpInput');
            const portInput = document.getElementById('tcpPortInput');
            const host = ipInput.value.trim();
            const port = parseInt(portInput.value) || 5555;
            const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
            if (!ipRegex.test(host)) {
                showToast('Invalid IP address format', 'error');
                ipInput.focus();
                return;
            }
            if (port < 1 || port > 65535) {
                showToast('Invalid port number', 'error');
                portInput.focus();
                return;
            }
            deviceManager.addTCPDevice(host, port, `ADB WiFi (${host})`);
            showToast(`Device added: ${host}:${port}`, 'success');
            this.closeTCPModal();
        },
        removeDevice(serial) {
            if (confirm('Remove this device from the list?')) {
                deviceManager.removeDevice(serial);
                if (state.selectedDeviceSerial === serial) {
                    state.selectedDeviceSerial = null;
                }
                showToast('Device removed', 'info');
            }
        },
        handleDeviceDisconnected(device) {
            this.stopLogcat();
            if (state.connected) {
                state.connected = false;
                state.shellCwd = '';
                state.shellRootMode = false;
                setAmbientActive(false);
                el.connectBtn.classList.remove('hidden');
                el.disconnectBtn.classList.add('hidden');
                el.statusDot.classList.remove('active');
                el.statusText.textContent = 'Disconnected';
                el.statusPill.classList.remove('connected');
                if (el.deviceSelect) el.deviceSelect.disabled = false;
                document.querySelectorAll('.dock-item').forEach(item => {
                    if (item.dataset.section !== 'overview') item.classList.add('disabled');
                });
                navigate('overview');
                showToast('Device disconnected', 'warning');
            }
        },
        async connect() {
            try {
                showLoading('Connecting...', 'Checking for paired devices...');
                if (typeof ADBConnection === 'undefined') {
                    throw new Error('ADB library not loaded. Refresh the page.');
                }
                adb = new ADBConnection();
                if (deviceManager) {
                    await deviceManager.refreshUSBDevices();
                    this.updateDeviceList(deviceManager.getDeviceList());
                }
                let selectedDevice = null;
                if (deviceManager && state.selectedDeviceSerial) {
                    selectedDevice = deviceManager.getDevice(state.selectedDeviceSerial);
                    
                }
                if (!selectedDevice && deviceManager) {
                    const devices = deviceManager.getDeviceList();
                    const usbDevice = devices.find(d => d.type === 'usb');
                    if (usbDevice) {
                        selectedDevice = usbDevice;
                        state.selectedDeviceSerial = usbDevice.serial;
                        if (el.deviceSelect) el.deviceSelect.value = usbDevice.serial;
                    }
                }
                if (selectedDevice && selectedDevice.type === 'usb' && selectedDevice.usbDevice) {
                    
                    showLoading('Connecting...', 'Accept USB debugging prompt on device');
                    adb.device = selectedDevice.usbDevice;
                    adb.deviceDescriptor = selectedDevice;
                    await adb.openDevice();
                    await adb.authenticate();
                } else if (selectedDevice && selectedDevice.type === 'tcp') {
                    hideLoading();
                    showToast('WebSocket connection coming soon! Please use USB connection for now.', 'info');
                    return;
                } else {
                    showLoading('Waiting...', 'Select device from browser dialog');
                    await adb.connect();
                    if (deviceManager && adb.device?.serialNumber) {
                        await deviceManager.refreshUSBDevices();
                        this.updateDeviceList(deviceManager.getDeviceList());
                        state.selectedDeviceSerial = adb.device.serialNumber;
                        if (el.deviceSelect) el.deviceSelect.value = adb.device.serialNumber;
                    }
                }
                state.connected = true;
                setAmbientActive(true);
                if (adb.device?.serialNumber) {
                    state.selectedDeviceSerial = adb.device.serialNumber;
                }
                el.connectBtn.classList.add('hidden');
                el.disconnectBtn.classList.remove('hidden');
                el.statusDot.classList.add('active');
                el.statusText.textContent = 'Connected';
                el.statusPill.classList.add('connected');
                if (el.deviceSelect) el.deviceSelect.disabled = true;
                document.querySelectorAll('.dock-item.disabled').forEach(item => item.classList.remove('disabled'));
                adb.onDisconnect = (reason) => {
                    
                    this.handleDeviceDisconnected({ serial: state.selectedDeviceSerial });
                };
                hideLoading();
                showToast('Device connected successfully', 'success');
                navigate('overview');
            } catch (e) {
                hideLoading();
                showToast('Connection failed: ' + e.message, 'error');
                console.error('Connection error:', e);
            }
        },
        async disconnect() {
            this.stopLogcat();
            if (adb) {
                try { await adb.disconnect(); } catch (e) {}
                adb = null;
            }
            state.connected = false;
            state.shellCwd = '';
            state.shellRootMode = false;
            setAmbientActive(false);
            el.connectBtn.classList.remove('hidden');
            el.disconnectBtn.classList.add('hidden');
            el.statusDot.classList.remove('active');
            el.statusText.textContent = 'Disconnected';
            el.statusPill.classList.remove('connected');
            if (el.deviceSelect) el.deviceSelect.disabled = false;
            document.querySelectorAll('.dock-item').forEach(item => {
                if (item.dataset.section !== 'overview') item.classList.add('disabled');
            });
            navigate('overview');
            showToast('Device disconnected', 'info');
        },
        async loadOverview() {
            const statsGrid = document.getElementById('statsGrid');
            const propList = document.getElementById('propList');
            try {
                const props = await adb.getDeviceProps();
                const apps = await adb.listPackages(false);
                let storagePercent = '-';
                try {
                    const storage = await adb.shell('df /data | tail -1');
                    const parts = storage.trim().split(/\s+/);
                    storagePercent = parts[4]?.replace('%', '') || '-';
                } catch (e) {}
                statsGrid.innerHTML = `
                    <div class="stat-card">
                        <div class="stat-label">Android</div>
                        <div class="stat-value">${props.androidVersion || '-'}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">SDK Level</div>
                        <div class="stat-value">${props.sdkVersion || '-'}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">User Apps</div>
                        <div class="stat-value">${apps.length}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Storage</div>
                        <div class="stat-value">${storagePercent}%</div>
                    </div>
                `;
                let manufacturer = 'Unknown';
                let cpu = 'Unknown';
                try {
                    manufacturer = await adb.shell('getprop ro.product.manufacturer');
                    cpu = await adb.shell('getprop ro.product.cpu.abi');
                } catch (e) {}
                propList.innerHTML = [
                    { label: 'Model', value: props.model || '-' },
                    { label: 'Brand', value: props.brand || '-' },
                    { label: 'Manufacturer', value: manufacturer.trim() },
                    { label: 'Serial', value: props.serial || '-' },
                    { label: 'CPU', value: cpu.trim() },
                    { label: 'Build ID', value: props.buildId || '-' },
                    { label: 'Battery', value: props.batteryLevel ? `${props.batteryLevel}%` : '-' }
                ].map(p => `
                    <div class="prop-item">
                        <span class="prop-label">${p.label}</span>
                        <span class="prop-value">${p.value}</span>
                    </div>
                `).join('');
            } catch (e) {
                showToast('Failed to load device info: ' + e.message, 'error');
                console.error('Overview error:', e);
            }
        },
        async loadApps() {
            const list = document.getElementById('appList');
            if (!list) return;
            list.innerHTML = '<div class="empty-state"><p>Loading...</p></div>';
            try {
                const packages = await adb.listPackages(state.showSystemApps);
                state.apps = packages.map(pkg => ({
                    package: pkg,
                    name: pkg.split('.').pop()
                })).sort((a, b) => a.name.localeCompare(b.name));
                this.renderApps(state.apps);
            } catch (e) {
                list.innerHTML = '<div class="empty-state"><p>Failed to load applications</p></div>';
                showToast('Failed to load apps: ' + e.message, 'error');
            }
        },
        renderApps(apps) {
            const list = document.getElementById('appList');
            if (!list) return;
            if (apps.length === 0) {
                list.innerHTML = '<div class="empty-state"><p>No applications found</p></div>';
                return;
            }
            list.innerHTML = apps.map(a => `
                <div class="app-item">
                    <div class="app-icon">${escapeHtml(a.name.charAt(0).toUpperCase())}</div>
                    <div class="app-details">
                        <div class="app-name">${escapeHtml(a.name)}</div>
                        <div class="app-package">${escapeHtml(a.package)}</div>
                    </div>
                    <div class="app-actions">
                        <button class="btn btn-sm btn-ghost" onclick="app.downloadApk('${escapeAttr(a.package)}')" title="Download APK">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
                        </button>
                    </div>
                </div>
            `).join('');
        },
        filterApps(query) {
            const filtered = state.apps.filter(a => 
                a.name.toLowerCase().includes(query.toLowerCase()) ||
                a.package.toLowerCase().includes(query.toLowerCase())
            );
            this.renderApps(filtered);
        },
        handleApkSelect(event) {
            const file = event.target.files[0];
            if (file?.name.endsWith('.apk')) this.installApk(file);
        },
        async installApk(file) {
            if (!file.name.endsWith('.apk')) {
                showToast('Invalid file type', 'error');
                return;
            }
            if (file.size > 500 * 1024 * 1024) {
                showToast('File too large (max 500MB)', 'error');
                return;
            }
            showLoading('Installing APK...', file.name);
            try {
                const buffer = await file.arrayBuffer();
                const bytes = new Uint8Array(buffer);
                const remotePath = `/data/local/tmp/${file.name}`;
                showLoading('Uploading...', '0%');
                await adb.pushFile(remotePath, bytes, 0o644);
                showLoading('Installing...', 'Please wait');
                const result = await adb.shell(`pm install -r "${remotePath}"`);
                await adb.shell(`rm "${remotePath}"`);
                hideLoading();
                if (result.includes('Success')) {
                    showToast('APK installed successfully', 'success');
                    this.loadApps();
                } else {
                    const error = result.match(/Failure \[(.+)\]/);
                    showToast('Install failed: ' + (error?.[1] || result), 'error');
                }
            } catch (e) {
                hideLoading();
                showToast('Install failed: ' + e.message, 'error');
            }
        },
        async downloadApk(pkg) {
            showLoading('Downloading APK...', '0 MB');
            try {
                const bytes = await adb.pullApk(pkg, (downloaded) => {
                    showLoading('Downloading APK...', formatSize(downloaded));
                });
                const blob = new Blob([bytes], { type: 'application/vnd.android.package-archive' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `${pkg}.apk`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                hideLoading();
                showToast(`APK downloaded (${formatSize(bytes.length)})`, 'success');
            } catch (e) {
                hideLoading();
                showToast('Download failed: ' + e.message, 'error');
            }
        },
        async loadFiles(path) {
            path = ('/' + path).replace(/\/+/g, '/').replace(/\/$/, '') || '/';
            state.currentPath = path;
            const pathBar = document.getElementById('pathBar');
            const fileList = document.getElementById('fileList');
            const rootToggle = document.getElementById('rootToggle');
            if (rootToggle) {
                rootToggle.checked = state.rootMode;
            }
            this.setupFileDragDrop();
            if (pathBar) {
                const segments = path.split('/').filter(s => s);
                pathBar.innerHTML = `
                    <span class="path-segment root" data-path="/">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width:14px;height:14px;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/></svg>
                    </span>
                    ${segments.map((seg, i) => {
                        const segPath = '/' + segments.slice(0, i + 1).join('/');
                        return `<span class="path-sep">/</span><span class="path-segment" data-path="${segPath}">${seg}</span>`;
                    }).join('')}
                `;
                pathBar.querySelectorAll('.path-segment').forEach(seg => {
                    seg.onclick = () => this.loadFiles(seg.dataset.path);
                });
            }
            if (!fileList) return;
            fileList.innerHTML = '<div class="empty-state"><p>Loading...</p></div>';
            try {
                const safePath = path.replace(/"/g, '\\"');
                const lsCmd = `ls -la "${safePath}" 2>/dev/null`;
                const cmd = state.rootMode ? `su -c '${lsCmd.replace(/'/g, "'\\''")}'` : lsCmd;
                const output = await adb.shell(cmd);
                const lines = output.split('\n').filter(l => l.trim() && !l.startsWith('total'));
                state.files = lines.map(line => {
                    const parts = line.trim().split(/\s+/);
                    if (parts.length < 7) return null;
                    const perms = parts[0];
                    const isDir = perms.startsWith('d');
                    const isLink = perms.startsWith('l');
                    const size = parts[4];
                    const name = parts.slice(7).join(' ').split(' -> ')[0]; 
                    if (name === '.' || name === '..') return null;
                    return { name, size, isDir: isDir || isLink, perms };
                }).filter(Boolean).sort((a, b) => {
                    if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
                    return a.name.localeCompare(b.name);
                });
                if (state.files.length === 0) {
                    fileList.innerHTML = `
                        <div class="empty-state">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width:48px;height:48px;color:var(--lum-30);margin-bottom:12px;">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/>
                            </svg>
                            <p>Empty directory</p>
                        </div>`;
                    return;
                }
                fileList.innerHTML = state.files.map((f, idx) => `
                    <div class="file-item" data-index="${idx}" data-is-dir="${f.isDir}">
                        <div class="file-info">
                            <div class="file-icon ${f.isDir ? 'folder' : ''}">
                                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    ${f.isDir 
                                        ? '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/>'
                                        : '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>'}
                                </svg>
                            </div>
                            <span class="file-name">${escapeHtml(f.name)}</span>
                        </div>
                        <span class="file-size">${f.isDir ? '-' : escapeHtml(formatSize(f.size))}</span>
                        <span class="file-perms">${escapeHtml(f.perms.substring(0, 10))}</span>
                        <div class="file-actions">
                            ${!f.isDir ? `
                                <button class="file-action-btn download-btn" data-index="${idx}" title="Download">
                                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
                                </button>
                            ` : `
                                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" class="folder-arrow">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
                                </svg>
                            `}
                        </div>
                    </div>
                `).join('');
                fileList.querySelectorAll('.file-item').forEach(item => {
                    const idx = parseInt(item.dataset.index);
                    const isDir = item.dataset.isDir === 'true';
                    const file = state.files[idx];
                    const fullPath = (path === '/' ? '' : path) + '/' + file.name;
                    item.addEventListener('click', (e) => {
                        if (e.target.closest('.download-btn')) return;
                        if (isDir) {
                            this.loadFiles(fullPath);
                        } else {
                            this.downloadFile(fullPath);
                        }
                    });
                    const downloadBtn = item.querySelector('.download-btn');
                    if (downloadBtn) {
                        downloadBtn.addEventListener('click', (e) => {
                            e.stopPropagation();
                            this.downloadFile(fullPath);
                        });
                    }
                });
            } catch (e) {
                const errorMsg = state.rootMode ? 'Cannot access (device may not be rooted)' : 'Cannot access directory';
                fileList.innerHTML = `
                    <div class="empty-state">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width:48px;height:48px;color:var(--alert);margin-bottom:12px;">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                        </svg>
                        <p>${errorMsg}</p>
                    </div>`;
            }
        },
        setupFileDragDrop() {
            const dropZone = document.getElementById('fileDropZone');
            if (!dropZone || dropZone.dataset.initialized) return;
            dropZone.dataset.initialized = 'true';
            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
                dropZone.addEventListener(eventName, (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                });
            });
            ['dragenter', 'dragover'].forEach(eventName => {
                dropZone.addEventListener(eventName, () => {
                    dropZone.classList.add('drag-active');
                });
            });
            ['dragleave', 'drop'].forEach(eventName => {
                dropZone.addEventListener(eventName, () => {
                    dropZone.classList.remove('drag-active');
                });
            });
            dropZone.addEventListener('drop', (e) => {
                const files = e.dataTransfer.files;
                if (files.length > 0) {
                    Array.from(files).forEach(file => this.uploadFile(file));
                }
            });
        },
        toggleRootMode() {
            state.rootMode = !state.rootMode;
            showToast(state.rootMode ? 'Root mode enabled' : 'Root mode disabled', 'info');
            this.loadFiles(state.currentPath);
        },
        navigateUp() {
            const parts = state.currentPath.split('/').filter(s => s);
            if (parts.length > 0) {
                parts.pop();
                this.loadFiles('/' + parts.join('/') || '/');
            }
        },
        refreshFiles() {
            this.loadFiles(state.currentPath);
        },
        async downloadFile(path) {
            const fileName = path.split('/').pop();
            showLoading('Downloading...', '0 MB');
            try {
                let bytes;
                if (state.rootMode) {
                    showLoading('Downloading...', fileName + ' (root mode)');
                    const safePath = path.replace(/"/g, '\\"');
                    const cmd = `su -c "base64 \\"${safePath}\\""`;
                    const base64Output = await adb.shell(cmd);
                    if (!base64Output || base64Output.includes('Permission denied') || base64Output.includes('No such file')) {
                        throw new Error('Cannot read file (permission denied or not found)');
                    }
                    const cleanBase64 = base64Output.trim().replace(/\s/g, '');
                    const binaryString = atob(cleanBase64);
                    bytes = new Uint8Array(binaryString.length);
                    for (let i = 0; i < binaryString.length; i++) {
                        bytes[i] = binaryString.charCodeAt(i);
                    }
                } else {
                    bytes = await adb.pullFile(path, (downloaded) => {
                        showLoading('Downloading...', formatSize(downloaded));
                    });
                }
                const blob = new Blob([bytes]);
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = fileName;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                hideLoading();
                showToast(`Downloaded: ${fileName} (${formatSize(bytes.length)})`, 'success');
            } catch (e) {
                hideLoading();
                showToast('Download failed: ' + e.message, 'error');
            }
        },
        handleFileUpload(event) {
            const files = event.target.files;
            if (!files || files.length === 0) return;
            Array.from(files).forEach(file => {
                this.uploadFile(file);
            });
            event.target.value = '';
        },
        async uploadFile(file) {
            const destPath = (state.currentPath === '/' ? '' : state.currentPath) + '/' + file.name;
            showLoading('Uploading...', file.name);
            try {
                const buffer = await file.arrayBuffer();
                const bytes = new Uint8Array(buffer);
                if (state.rootMode) {
                    let binary = '';
                    for (let i = 0; i < bytes.length; i++) {
                        binary += String.fromCharCode(bytes[i]);
                    }
                    const base64Data = btoa(binary);
                    const safeDestPath = destPath.replace(/"/g, '\\"');
                    await adb.shell(`su -c "echo -n '' > \\"${safeDestPath}\\""`);
                    const chunkSize = 32000; 
                    for (let i = 0; i < base64Data.length; i += chunkSize) {
                        const chunk = base64Data.slice(i, i + chunkSize);
                        await adb.shell(`su -c "echo -n '${chunk}' | base64 -d >> \\"${safeDestPath}\\""`);
                    }
                    hideLoading();
                    showToast(`Uploaded: ${file.name}`, 'success');
                } else {
                    await adb.pushFile(destPath, bytes);
                    hideLoading();
                    showToast(`Uploaded: ${file.name}`, 'success');
                }
                this.loadFiles(state.currentPath);
            } catch (e) {
                hideLoading();
                let errMsg = 'Upload failed: ' + e.message;
                if (e.message.includes('not permitted') || e.message.includes('Permission denied') || e.message.includes('Read-only')) {
                    errMsg += '. Try enabling Root Mode toggle above to write to system directories.';
                }
                showToast(errMsg, 'error');
            }
        },
        async captureScreenshot() {
            showLoading('Capturing...');
            try {
                const blob = await adb.takeScreenshot();
                state.screenshotBlob = blob;
                const url = URL.createObjectURL(blob);
                const area = document.getElementById('screenshotArea');
                area.innerHTML = `<img class="screenshot-preview" src="${url}" alt="Screenshot">`;
                document.getElementById('saveScreenshotBtn').disabled = false;
                hideLoading();
                showToast('Screenshot captured', 'success');
            } catch (e) {
                hideLoading();
                showToast('Capture failed: ' + e.message, 'error');
            }
        },
        saveScreenshot() {
            if (state.screenshotBlob) {
                const url = URL.createObjectURL(state.screenshotBlob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `screenshot_${Date.now()}.png`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                showToast('Screenshot saved', 'success');
            }
        },
        async executeCommand(cmd) {
            const output = document.getElementById('shellOutput');
            const input = document.getElementById('shellInput');
            state.shellHistory.push(cmd);
            state.shellHistoryIndex = -1;
            const promptChar = state.shellRootMode ? '#' : '$';
            output.insertAdjacentHTML('beforeend', `<div class="shell-line"><span class="shell-prompt">${promptChar} </span>${escapeHtml(cmd)}</div>`);
            if (cmd === 'clear') {
                output.innerHTML = '';
                if (input) input.focus();
                return;
            }
            if (cmd === 'help') {
                const rootNote = state.shellRootMode ? ' (root mode active — commands run via su)' : '';
                output.insertAdjacentHTML('beforeend', `<div class="shell-result">Commands: ls, cd, pwd, cat, ps, df, pm, dumpsys, getprop, logcat, clear${rootNote}</div>`);
                output.scrollTop = output.scrollHeight;
                if (input) input.focus();
                return;
            }
            const isAlreadySu = /^\s*su\b/.test(cmd);
            const useRoot = state.shellRootMode && !isAlreadySu;
            const wrapRoot = (shellCmd) => {
                if (!useRoot) return shellCmd;
                const escaped = shellCmd.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\$/g, '\\$').replace(/`/g, '\\`');
                return `su -c "${escaped}"`;
            };
            try {
                const cdMatch = cmd.match(/^\s*cd\s+(.*)/);
                if (cdMatch) {
                    const target = cdMatch[1].trim().replace(/^["']|["']$/g, '');
                    let resolveCmd;
                    if (target === '~' || target === '') {
                        resolveCmd = useRoot ? 'echo /' : 'echo /storage/emulated/0';
                    } else if (target.startsWith('/')) {
                        resolveCmd = `cd "${target}" 2>&1 && pwd`;
                    } else if (state.shellCwd) {
                        resolveCmd = `cd "${state.shellCwd}" && cd "${target}" 2>&1 && pwd`;
                    } else {
                        resolveCmd = `cd "${target}" 2>&1 && pwd`;
                    }
                    const result = await adb.shell(wrapRoot(resolveCmd));
                    const trimmed = result.trim();
                    if (trimmed.startsWith('/')) {
                        state.shellCwd = trimmed;
                        output.insertAdjacentHTML('beforeend', `<div class="shell-result">${escapeHtml(state.shellCwd)}</div>`);
                    } else {
                        output.insertAdjacentHTML('beforeend', `<div class="shell-error">${escapeHtml(trimmed || 'No such directory')}</div>`);
                    }
                } else {
                    let fullCmd;
                    if (isAlreadySu) {
                        fullCmd = state.shellCwd ? `cd "${state.shellCwd}" 2>/dev/null; ${cmd}` : cmd;
                    } else {
                        const baseCmd = state.shellCwd ? `cd "${state.shellCwd}" && ${cmd}` : cmd;
                        fullCmd = wrapRoot(baseCmd);
                    }
                    const result = await adb.shell(fullCmd);
                    if (result) {
                        output.insertAdjacentHTML('beforeend', `<div class="shell-result">${escapeHtml(result)}</div>`);
                    }
                }
            } catch (e) {
                output.insertAdjacentHTML('beforeend', `<div class="shell-error">Error: ${escapeHtml(e.message)}</div>`);
            }
            output.scrollTop = output.scrollHeight;
            if (input) input.focus();
        },
        toggleShellRoot() {
            state.shellRootMode = !state.shellRootMode;
            const prompt = document.getElementById('shellPrompt');
            const output = document.getElementById('shellOutput');
            const ch = state.shellRootMode ? '#' : '$';
            if (prompt) {
                prompt.textContent = state.shellCwd ? state.shellCwd + ' ' + ch : ch;
            }
            if (state.shellRootMode) {
                if (output) {
                    output.insertAdjacentHTML('beforeend', `<div class="shell-line" style="color:var(--warning)">Root mode enabled — commands will run via su</div>`);
                    output.scrollTop = output.scrollHeight;
                }
            } else {
                if (output) {
                    output.insertAdjacentHTML('beforeend', `<div class="shell-line" style="color:var(--lum-50)">Root mode disabled</div>`);
                    output.scrollTop = output.scrollHeight;
                }
            }
            showToast(state.shellRootMode ? 'Shell root mode enabled' : 'Shell root mode disabled', 'info');
        },
        clearShell() {
            const output = document.getElementById('shellOutput');
            if (output) output.innerHTML = '';
        },
        switchSecurityTab(tab) {
            const selectMap = {
                localStorage: 'storageSelect',
                backup: 'backupSelect',
                exported: 'exportedSelect',
                debuggable: 'debugSelect',
                permissions: 'permSelect',
                appInfo: 'appInfoSelect',
                fullScan: 'fullScanSelect'
            };
            // Save the current selection before switching tabs
            const prevSelectId = selectMap[state.currentSecurityTab];
            const prevSelect = document.getElementById(prevSelectId);
            if (prevSelect && prevSelect.value) {
                state.selectedPackage = prevSelect.value;
            }
            state.currentSecurityTab = tab;
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.classList.toggle('active', btn.dataset.tab === tab);
            });
            const content = document.getElementById('securityTabContent');
            if (content) {
                content.innerHTML = securityTabs[tab] || '';
                const selectId = selectMap[tab];
                if (selectId) {
                    const select = document.getElementById(selectId);
                    if (select) {
                        if (state.securityApps && state.securityApps.length > 0) {
                            populateSelect(selectId);
                            // Restore the previously selected package
                            if (state.selectedPackage) {
                                select.value = state.selectedPackage;
                            }
                        } else {
                            select.innerHTML = '<option value="">Loading applications...</option>';
                            select.disabled = true;
                        }
                    }
                }
            }
        },
        logcatInterval: null,
        logcatRunning: false,
        async startLogcat() {
            const filter = document.getElementById('logcatFilter')?.value.trim() || '';
            const output = document.getElementById('logcatOutput');
            const startBtn = document.getElementById('logcatStartBtn');
            const stopBtn = document.getElementById('logcatStopBtn');
            const status = document.getElementById('logcatStatus');
            if (!output) return;
            output.innerHTML = '';
            startBtn.classList.add('hidden');
            stopBtn.classList.remove('hidden');
            status.textContent = 'Running';
            status.className = 'badge success';
            this.logcatRunning = true;
            await adb.shell('logcat -c');
            const safeFilter = filter.replace(/[`$\\!"'|;&<>(){}[\]]/g, '');
            const grepCmd = safeFilter ? ` | grep -i "${safeFilter}"` : '';
            const poll = async () => {
                if (!this.logcatRunning) return;
                try {
                    const logs = await adb.shell(`logcat -d -v brief${grepCmd} | tail -50`);
                    if (logs.trim() && this.logcatRunning) {
                        const lines = logs.trim().split('\n');
                        for (const line of lines) {
                            const div = document.createElement('div');
                            div.className = 'logcat-line ' + this.getLogLevel(line);
                            div.textContent = line;
                            output.appendChild(div);
                        }
                        output.scrollTop = output.scrollHeight;
                        await adb.shell('logcat -c');
                    }
                } catch (e) {
                }
                if (this.logcatRunning) {
                    this.logcatInterval = setTimeout(poll, 1000);
                }
            };
            this.logcatInterval = setTimeout(poll, 500);
        },
        stopLogcat() {
            this.logcatRunning = false;
            if (this.logcatInterval) {
                clearTimeout(this.logcatInterval);
                this.logcatInterval = null;
            }
            const startBtn = document.getElementById('logcatStartBtn');
            const stopBtn = document.getElementById('logcatStopBtn');
            const status = document.getElementById('logcatStatus');
            if (startBtn) startBtn.classList.remove('hidden');
            if (stopBtn) stopBtn.classList.add('hidden');
            if (status) {
                status.textContent = 'Stopped';
                status.className = 'badge';
            }
        },
        clearLogcat() {
            const output = document.getElementById('logcatOutput');
            if (output) output.innerHTML = '';
        },
        downloadLogcat() {
            const output = document.getElementById('logcatOutput');
            if (!output || !output.textContent.trim()) {
                showToast('No logs to download', 'warning');
                return;
            }
            const lines = Array.from(output.querySelectorAll('.logcat-line')).map(el => el.textContent);
            const content = lines.join('\n');
            const blob = new Blob([content], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `logcat_${new Date().toISOString().slice(0,19).replace(/:/g,'-')}.txt`;
            a.click();
            URL.revokeObjectURL(url);
            showToast('Logs downloaded', 'success');
        },
        getLogLevel(line) {
            if (line.includes(' V/') || line.startsWith('V/')) return 'verbose';
            if (line.includes(' D/') || line.startsWith('D/')) return 'debug';
            if (line.includes(' I/') || line.startsWith('I/')) return 'info';
            if (line.includes(' W/') || line.startsWith('W/')) return 'warn';
            if (line.includes(' E/') || line.startsWith('E/')) return 'error';
            if (line.includes(' F/') || line.startsWith('F/')) return 'fatal';
            return '';
        },
        async analyzeStorage() {
            const pkg = document.getElementById('storageSelect')?.value;
            if (!pkg) { showToast('Select an application', 'warning'); return; }
            const results = document.getElementById('storageResults');
            results.innerHTML = '<div class="empty-state"><p>Analyzing with root...</p></div>';
            try {
                const auditor = new SecurityAuditor(adb);
                const data = await auditor.getLocalStorageFiles(pkg);
                let html = '';
                const sections = [
                    { key: 'sharedPrefs', title: 'SharedPreferences', icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z' },
                    { key: 'databases', title: 'Databases', icon: 'M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4' },
                    { key: 'files', title: 'Internal Files', icon: 'M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z' },
                    { key: 'external', title: 'External Storage', icon: 'M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8' }
                ];
                const encodedPkg = safeEncode(pkg);
                for (const section of sections) {
                    if (data[section.key]?.length > 0) {
                        html += `<div class="result-box"><div class="result-header"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width:16px;height:16px;opacity:0.6"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="${section.icon}"/></svg><strong>${section.title} (${data[section.key].length})</strong></div><div class="file-grid">`;
                        for (const f of data[section.key]) {
                            const encodedPath = safeEncode(f.path);
                            const encodedName = safeEncode(f.name);
                            const sizeStr = f.size && f.size !== '-' ? `<span class="file-row-size">${escapeHtml(f.size)}B</span>` : '';
                            html += `<div class="file-row">
                                <div class="file-row-info">
                                    <div class="file-row-icon"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg></div>
                                    <span class="file-row-name">${escapeHtml(f.name)}</span>${sizeStr}
                                </div>
                                <div class="file-row-actions">
                                    <button class="btn btn-sm btn-ghost" onclick="window.viewStorageFile('${encodedPath}')">View</button>
                                    <button class="btn btn-sm btn-ghost" onclick="window.downloadStorageFile('${encodedPkg}','${encodedPath}','${encodedName}')">Download</button>
                                </div>
                            </div>`;
                        }
                        html += '</div></div>';
                    }
                }
                if (!html) {
                    html = '<div class="empty-state"><p>No files found. Device may need root.</p></div>';
                }
                results.innerHTML = html;
            } catch (e) {
                results.innerHTML = `<div class="result-box"><span class="badge fail">Error</span><p style="margin-top:8px">${escapeHtml(e.message)}</p></div>`;
            }
        },
        async checkBackup() {
            const pkg = document.getElementById('backupSelect')?.value;
            if (!pkg) { showToast('Select an application', 'warning'); return; }
            const results = document.getElementById('backupResults');
            results.innerHTML = '<div class="empty-state"><p>Checking...</p></div>';
            try {
                const auditor = new SecurityAuditor(adb);
                const result = await auditor.testBackupEnabled(pkg);
                const badge = result.status === 'pass' ? 'pass' : result.status === 'fail' ? 'fail' : 'warning';
                const label = result.status === 'pass' ? '✓ Secure' : result.status === 'fail' ? '✗ Vulnerable' : '⚠ Review';
                results.innerHTML = `<div class="result-box"><div class="result-header"><span class="badge ${badge}">${label}</span></div><p style="margin-top:12px;color:var(--lum-70)">${result.description}</p></div>`;
            } catch (e) {
                results.innerHTML = `<div class="result-box"><span class="badge fail">Error</span><p style="margin-top:8px">${escapeHtml(e.message)}</p></div>`;
            }
        },
        async analyzeExported() {
            const pkg = document.getElementById('exportedSelect')?.value;
            if (!pkg) { showToast('Select an application', 'warning'); return; }
            const results = document.getElementById('exportedResults');
            results.innerHTML = '<div class="empty-state"><p>Analyzing...</p></div>';
            try {
                const auditor = new SecurityAuditor(adb);
                const result = await auditor.testExportedComponents(pkg);
                let html = '<div class="result-box"><div class="result-header"><strong>Exported Components</strong></div><div class="component-list">';
                let hasComponents = false;
                if (result.findings) {
                    for (const f of result.findings) {
                        if (f.components) {
                            const type = f.type.replace('exported_', '');
                            for (const c of f.components) {
                                hasComponents = true;
                                html += `<div class="component-item"><span class="component-type ${type}">${type}</span><span class="component-name">${c}</span></div>`;
                            }
                        }
                    }
                }
                if (!hasComponents) {
                    html += '<div style="padding:12px;color:var(--lum-50)">No exported components found</div>';
                }
                html += '</div></div>';
                results.innerHTML = html;
            } catch (e) {
                results.innerHTML = `<div class="result-box"><span class="badge fail">Error</span><p style="margin-top:8px">${escapeHtml(e.message)}</p></div>`;
            }
        },
        async checkDebuggable() {
            const pkg = document.getElementById('debugSelect')?.value;
            if (!pkg) { showToast('Select an application', 'warning'); return; }
            const results = document.getElementById('debugResults');
            results.innerHTML = '<div class="empty-state"><p>Checking...</p></div>';
            try {
                const auditor = new SecurityAuditor(adb);
                const result = await auditor.testDebuggable(pkg);
                const badge = result.status === 'pass' ? 'pass' : 'fail';
                const label = result.status === 'pass' ? '✓ Not Debuggable' : '✗ Debuggable';
                results.innerHTML = `<div class="result-box"><div class="result-header"><span class="badge ${badge}">${label}</span></div><p style="margin-top:12px;color:var(--lum-70)">${result.description}</p></div>`;
            } catch (e) {
                results.innerHTML = `<div class="result-box"><span class="badge fail">Error</span><p style="margin-top:8px">${escapeHtml(e.message)}</p></div>`;
            }
        },
        async analyzePermissions() {
            const pkg = document.getElementById('permSelect')?.value;
            if (!pkg) { showToast('Select an application', 'warning'); return; }
            const results = document.getElementById('permResults');
            results.innerHTML = '<div class="empty-state"><p>Analyzing...</p></div>';
            try {
                const auditor = new SecurityAuditor(adb);
                const result = await auditor.testDangerousPermissionsOnly(pkg);
                const permFinding = result.findings?.find(f => f.type === 'granted_dangerous_permissions');
                const perms = permFinding?.permissions || [];
                let html = '<div class="result-box"><div class="result-header"><strong>Dangerous Permissions</strong></div>';
                if (perms.length > 0) {
                    html += '<div class="perm-list" style="margin-top:12px">';
                    for (const p of perms) {
                        const name = (p.permission || p).replace('android.permission.', '');
                        html += `<span class="perm-tag">${escapeHtml(name)}</span>`;
                    }
                    html += '</div>';
                } else {
                    html += '<p style="margin-top:12px;color:var(--lum-50)">No dangerous permissions granted</p>';
                }
                html += '</div>';
                results.innerHTML = html;
            } catch (e) {
                results.innerHTML = `<div class="result-box"><span class="badge fail">Error</span><p style="margin-top:8px">${escapeHtml(e.message)}</p></div>`;
            }
        },
        async loadAppInfo() {
            const pkg = document.getElementById('appInfoSelect')?.value;
            if (!pkg) { showToast('Select an application', 'warning'); return; }
            const results = document.getElementById('appInfoResults');
            results.innerHTML = '<div class="empty-state"><p>Loading info...</p></div>';
            try {
                const auditor = new SecurityAuditor(adb);
                const info = await auditor.getAppInfo(pkg);
                let flagsHtml = '';
                if (info.flags && info.flags.length > 0) {
                    flagsHtml = info.flags.map(f => {
                        const danger = ['DEBUGGABLE', 'ALLOW_BACKUP', 'CLEARTEXT_TRAFFIC'].includes(f);
                        return `<span class="badge ${danger ? 'fail' : 'pass'}" style="margin:2px">${escapeHtml(f)}</span>`;
                    }).join('');
                }
                let html = '<div class="result-box">';
                html += `<div class="result-header"><strong>${escapeHtml(pkg)}</strong></div>`;
                html += '<div class="prop-list" style="margin-top:8px">';
                const rows = [
                    ['Version', (info.versionName || '?') + ' (' + (info.versionCode || '?') + ')'],
                    ['Target SDK', info.targetSdk ? 'API ' + info.targetSdk + ' (Android ' + (new SecurityAuditor(adb)).sdkToAndroidVersion(parseInt(info.targetSdk)) + ')' : '?'],
                    ['Min SDK', info.minSdk ? 'API ' + info.minSdk : '?'],
                    ['Signing', info.signingVersion || '?'],
                    ['UID', info.uid || '?'],
                    ['Data Dir', info.dataDir || '?'],
                    ['APK Path', info.apkPath || '?'],
                    ['Data Size', info.dataSize || '?'],
                    ['APK Size', info.apkSize || '?'],
                    ['Installed', info.firstInstall || '?'],
                    ['Last Updated', info.lastUpdate || '?']
                ];
                for (const [label, val] of rows) {
                    html += `<div class="prop-row"><span class="prop-key">${escapeHtml(label)}</span><span class="prop-val" style="font-family:monospace;font-size:12px">${escapeHtml(val)}</span></div>`;
                }
                html += '</div>';
                if (flagsHtml) {
                    html += `<div style="margin-top:12px;padding-top:12px;border-top:1px solid rgba(255,255,255,0.06)"><strong style="font-size:12px;color:var(--lum-50)">Flags</strong><div style="margin-top:6px">${flagsHtml}</div></div>`;
                }
                html += '</div>';
                results.innerHTML = html;
            } catch (e) {
                results.innerHTML = `<div class="result-box"><span class="badge fail">Error</span><p style="margin-top:8px">${escapeHtml(e.message)}</p></div>`;
            }
        },
        async runFullScan() {
            const pkg = document.getElementById('fullScanSelect')?.value;
            if (!pkg) { showToast('Select an application', 'warning'); return; }
            const results = document.getElementById('fullScanResults');
            const progress = document.getElementById('fullScanProgress');
            const statusEl = document.getElementById('fullScanStatus');
            const bar = document.getElementById('fullScanBar');
            results.innerHTML = '';
            progress.classList.remove('hidden');
            try {
                const auditor = new SecurityAuditor(adb);
                const scanResult = await auditor.runFullAudit(pkg, (name, current, total) => {
                    statusEl.textContent = `Running: ${name} (${current}/${total})`;
                    bar.style.width = Math.round((current / total) * 100) + '%';
                });
                progress.classList.add('hidden');
                let html = '<div class="result-box" style="margin-top:12px">';
                html += `<div class="result-header"><strong>Scan Report: ${escapeHtml(pkg)}</strong><span style="color:var(--lum-40);font-size:12px;margin-left:auto">${escapeHtml(scanResult.timestamp)}</span></div>`;
                html += '<div style="display:flex;gap:12px;margin-top:12px;flex-wrap:wrap">';
                html += `<div style="padding:8px 16px;border-radius:8px;background:rgba(76,175,80,0.1);text-align:center"><div style="font-size:20px;font-weight:700;color:var(--success)">${scanResult.summary.pass}</div><div style="font-size:11px;color:var(--lum-50)">Pass</div></div>`;
                html += `<div style="padding:8px 16px;border-radius:8px;background:rgba(244,67,54,0.1);text-align:center"><div style="font-size:20px;font-weight:700;color:var(--danger)">${scanResult.summary.fail}</div><div style="font-size:11px;color:var(--lum-50)">Fail</div></div>`;
                html += `<div style="padding:8px 16px;border-radius:8px;background:rgba(255,152,0,0.1);text-align:center"><div style="font-size:20px;font-weight:700;color:var(--warning)">${scanResult.summary.review}</div><div style="font-size:11px;color:var(--lum-50)">Review</div></div>`;
                html += `<div style="padding:8px 16px;border-radius:8px;background:rgba(255,255,255,0.05);text-align:center"><div style="font-size:20px;font-weight:700;color:var(--lum-50)">${scanResult.summary.error}</div><div style="font-size:11px;color:var(--lum-50)">Error</div></div>`;
                html += '</div></div>';
                for (const test of scanResult.tests) {
                    const badge = test.status === 'pass' ? 'pass' : test.status === 'fail' ? 'fail' : test.status === 'review' ? 'warning' : '';
                    const label = test.status === 'pass' ? '✓ Pass' : test.status === 'fail' ? '✗ Fail' : test.status === 'review' ? '⚠ Review' : '? Error';
                    html += `<div class="result-box" style="margin-top:8px"><div class="result-header"><span class="badge ${badge}">${label}</span><strong style="margin-left:8px">${escapeHtml(test.title || test.id)}</strong></div>`;
                    if (test.description) {
                        html += `<p style="margin-top:6px;color:var(--lum-50);font-size:12px">${escapeHtml(test.description)}</p>`;
                    }
                    if (test.findings && test.findings.length > 0) {
                        html += '<div style="margin-top:8px">';
                        for (const f of test.findings) {
                            const note = f.note || f.type || '';
                            const sev = f.severity || '';
                            const sevColor = sev === 'high' ? 'var(--danger)' : sev === 'medium' ? 'var(--warning)' : 'var(--lum-60)';
                            html += `<div style="padding:4px 0;font-size:12px;color:${sevColor}">• ${escapeHtml(note)}</div>`;
                        }
                        html += '</div>';
                    }
                    if (test.error) {
                        html += `<p style="margin-top:6px;color:var(--danger);font-size:12px">${escapeHtml(test.error)}</p>`;
                    }
                    html += '</div>';
                }
                const blob = new Blob([JSON.stringify(scanResult, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                html += `<div style="margin-top:16px;text-align:center"><a href="${url}" download="${escapeAttr(pkg)}_security_scan.json" class="btn btn-ghost" style="display:inline-flex;align-items:center;gap:6px;text-decoration:none"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width:14px;height:14px"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>Download Full Report (JSON)</a></div>`;
                results.innerHTML = html;
            } catch (e) {
                progress.classList.add('hidden');
                results.innerHTML = `<div class="result-box"><span class="badge fail">Error</span><p style="margin-top:8px">${escapeHtml(e.message)}</p></div>`;
            }
        }
    };
    el.connectBtn.addEventListener('click', () => app.connect());
    el.disconnectBtn.addEventListener('click', () => app.disconnect());
    if (el.deviceSelect) {
        el.deviceSelect.addEventListener('change', (e) => app.onDeviceSelect(e.target.value));
    }
    if (el.addDeviceBtn) {
        el.addDeviceBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            app.toggleAddMenu();
        });
    }
    document.addEventListener('click', (e) => {
        if (el.addDeviceMenu && !el.addDeviceMenu.contains(e.target) && e.target !== el.addDeviceBtn) {
            app.closeAddMenu();
        }
    });
    document.querySelectorAll('.dock-item').forEach(item => {
        item.addEventListener('click', () => {
            if (!item.classList.contains('disabled')) {
                navigate(item.dataset.section);
            }
        });
    });
    app.initDeviceManager().catch(err => {
        console.warn('Device manager initialization failed:', err);
    });
    navigate('overview');
    window.app = app;
    window.viewStorageFile = async function(encodedPath) {
        const path = safeDecode(encodedPath);
        const fileName = path.split('/').pop() || 'file';
        showLoading('Loading file...');
        try {
            const content = await shellReadBase64(path);
            const clean = content.trim().replace(/\s/g, '');
            if (!clean || clean.includes('Permission denied') || clean.includes('No such file') || clean.includes('not found')) {
                throw new Error('Cannot read file — permission denied or not found');
            }
            const bytes = base64ToBytes(clean);
            const blob = new Blob([bytes]);
            const reader = new FileReader();
            reader.onload = function() {
                hideLoading();
                const textContent = reader.result;
                const existing = document.getElementById('fileViewModal');
                if (existing) existing.remove();
                const modal = document.createElement('div');
                modal.id = 'fileViewModal';
                modal.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.9);display:flex;align-items:center;justify-content:center;z-index:9999;padding:20px;';
                const inner = document.createElement('div');
                inner.style.cssText = 'background:#0f1015;border:1px solid rgba(255,255,255,0.1);border-radius:16px;max-width:800px;width:100%;max-height:85vh;display:flex;flex-direction:column;';
                const header = document.createElement('div');
                header.style.cssText = 'display:flex;justify-content:space-between;align-items:center;padding:16px 20px;border-bottom:1px solid rgba(255,255,255,0.06);';
                const title = document.createElement('span');
                title.style.cssText = 'font-weight:600;color:#fff;font-family:monospace;font-size:13px;';
                title.textContent = fileName;
                const pathEl = document.createElement('span');
                pathEl.style.cssText = 'font-size:11px;color:var(--lum-40);margin-left:8px;';
                pathEl.textContent = path;
                const headerLeft = document.createElement('div');
                headerLeft.style.cssText = 'display:flex;flex-direction:column;gap:2px;overflow:hidden;flex:1;';
                headerLeft.appendChild(title);
                headerLeft.appendChild(pathEl);
                const closeBtn = document.createElement('button');
                closeBtn.style.cssText = 'background:#1a1b24;border:none;width:32px;height:32px;border-radius:8px;cursor:pointer;color:#fff;font-size:18px;flex-shrink:0;';
                closeBtn.textContent = '\u00d7';
                closeBtn.onclick = function() { modal.remove(); };
                header.appendChild(headerLeft);
                header.appendChild(closeBtn);
                const body = document.createElement('div');
                body.style.cssText = 'padding:20px;overflow:auto;flex:1;';
                const pre = document.createElement('pre');
                pre.style.cssText = 'font-family:monospace;font-size:12px;line-height:1.6;white-space:pre-wrap;word-break:break-word;color:#a0a3b1;margin:0;';
                pre.textContent = textContent || '[Empty file]';
                body.appendChild(pre);
                inner.appendChild(header);
                inner.appendChild(body);
                modal.appendChild(inner);
                modal.onclick = function(e) { if (e.target === modal) modal.remove(); };
                document.body.appendChild(modal);
            };
            reader.onerror = function() {
                hideLoading();
                showToast('Failed to read file content', 'error');
            };
            reader.readAsText(blob);
        } catch (e) {
            hideLoading();
            showToast('Error: ' + (e.message || 'Unknown'), 'error');
        }
    };
    window.downloadStorageFile = async function(encodedPkg, encodedPath, encodedName) {
        const pkg = safeDecode(encodedPkg);
        const path = safeDecode(encodedPath);
        const name = safeDecode(encodedName);
        showLoading('Downloading...');
        try {
            const content = await shellReadBase64(path);
            const clean = content.trim().replace(/\s/g, '');
            if (!clean || clean.includes('Permission denied') || clean.includes('No such file')) {
                throw new Error('Cannot read file — permission denied or not found');
            }
            const bytes = base64ToBytes(clean);
            const blob = new Blob([bytes]);
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = pkg + '_' + name;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            hideLoading();
            showToast('Downloaded: ' + name + ' (' + formatSize(bytes.length) + ')', 'success');
        } catch (e) {
            hideLoading();
            showToast('Download failed: ' + (e.message || 'Unknown'), 'error');
        }
    };
})();

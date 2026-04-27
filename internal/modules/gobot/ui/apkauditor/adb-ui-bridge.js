/** @preserve @author Sandeep Wawdane @license MIT */
(function() {
    'use strict';

    window.adbUI = {
        state: {
            connected: false,
            currentSection: 'overview',
            deviceInfo: {},
            apps: [],
            devices: [],
            selectedDeviceSerial: null,
            rootMode: false
        },

        init: function() {
            this.el = {
                connectBtn: document.getElementById('adbConnectBtn'),
                disconnectBtn: document.getElementById('adbDisconnectBtn'),
                deviceSelect: document.getElementById('adbDeviceSelect'),
                contentArea: document.getElementById('adbContentArea'),
                statusText: document.getElementById('adbStatusText')
            };

            if (this.el.connectBtn) {
                this.el.connectBtn.addEventListener('click', () => this.connect());
            }
            if (this.el.disconnectBtn) {
                this.el.disconnectBtn.addEventListener('click', () => this.disconnect());
            }
            
            // Periodically check for devices
            setInterval(() => this.refreshDevices(), 3000);
            this.refreshDevices();
        },

        refreshDevices: async function() {
            if (!window.DeviceManager) return;
            const manager = new window.DeviceManager();
            const devices = await manager.refreshUSBDevices();
            this.state.devices = devices;
            
            if (this.el.deviceSelect) {
                const current = this.el.deviceSelect.value;
                this.el.deviceSelect.innerHTML = devices.length ? '' : '<option value="">No devices found</option>';
                devices.forEach(d => {
                    const opt = document.createElement('option');
                    opt.value = d.serial;
                    opt.textContent = `${d.name || 'Unknown'} (${d.serial})`;
                    if (d.serial === current) opt.selected = true;
                    this.el.deviceSelect.appendChild(opt);
                });
            }
        },

        connect: async function() {
            try {
                const manager = new window.DeviceManager();
                const device = await manager.requestUSBDevice();
                if (!device) return;
                
                const conn = new window.ADBConnection();
                await conn.connectToDevice(device);
                this.adb = conn;
                this.state.connected = true;
                this.state.selectedDeviceSerial = device.serial;
                
                this.updateUI();
                this.loadOverview();
                showToast('Device connected successfully', 'success');
            } catch (e) {
                console.error(e);
                showToast('Connection failed: ' + e.message, 'error');
            }
        },

        disconnect: async function() {
            if (this.adb) {
                this.adb.markDisconnected();
                this.adb = null;
            }
            this.state.connected = false;
            this.updateUI();
            showToast('Device disconnected', 'info');
        },

        updateUI: function() {
            if (this.el.connectBtn) this.el.connectBtn.classList.toggle('hidden', this.state.connected);
            if (this.el.disconnectBtn) this.el.disconnectBtn.classList.toggle('hidden', !this.state.connected);
            if (this.el.statusText) this.el.statusText.textContent = this.state.connected ? 'Connected' : 'Disconnected';
        },

        loadOverview: async function() {
            if (!this.adb) return;
            this.el.contentArea.innerHTML = '<div class="loader-container" style="text-align:center; padding:40px"><div class="loader"></div><p>Gathering device info...</p></div>';
            
            try {
                const props = await this.adb.shell('getprop');
                const parsedProps = this.parseProps(props);
                this.state.deviceInfo = parsedProps;
                
                this.renderOverview(parsedProps);
            } catch (e) {
                this.el.contentArea.innerHTML = '<div class="error-state">Failed to load device info: ' + e.message + '</div>';
            }
        },

        parseProps: function(raw) {
            const props = {};
            raw.split('\n').forEach(line => {
                const match = line.match(/\[(.*)\]: \[(.*)\]/);
                if (match) props[match[1]] = match[2];
            });
            return props;
        },

        renderOverview: function(props) {
            let html = `
                <div class="adb-overview">
                    <div class="info-grid">
                        <div class="info-item"><label>Model</label><div class="value">${props['ro.product.model'] || 'Unknown'}</div></div>
                        <div class="info-item"><label>Manufacturer</label><div class="value">${props['ro.product.manufacturer'] || 'Unknown'}</div></div>
                        <div class="info-item"><label>Android Version</label><div class="value">${props['ro.build.version.release'] || 'Unknown'} (API ${props['ro.build.version.sdk'] || '?'})</div></div>
                        <div class="info-item"><label>Security Patch</label><div class="value">${props['ro.build.version.security_patch'] || 'Unknown'}</div></div>
                    </div>
                    
                    <div class="adb-actions" style="margin-top: 24px; display: flex; gap: 12px;">
                        <button class="btn btn-primary" onclick="adbUI.runSecurityAudit()">Run Security Audit</button>
                        <button class="btn btn-ghost" onclick="adbUI.loadOverview()">Refresh</button>
                    </div>
                    
                    <div id="adbAuditResults" style="margin-top: 24px;"></div>
                </div>
            `;
            this.el.contentArea.innerHTML = html;
        },

        runSecurityAudit: async function() {
            if (!this.adb) return;
            const resultsDiv = document.getElementById('adbAuditResults');
            resultsDiv.innerHTML = '<div class="loader-container" style="text-align:center; padding:40px"><div class="loader"></div><p>Running security audit...</p></div>';
            
            try {
                const auditor = new window.SecurityAuditor(this.adb);
                const results = await auditor.runFullScan();
                this.renderAuditResults(results);
            } catch (e) {
                resultsDiv.innerHTML = '<div class="error-state">Audit failed: ' + e.message + '</div>';
            }
        },

        renderAuditResults: function(results) {
            const resultsDiv = document.getElementById('adbAuditResults');
            let html = '<h3 style="margin-bottom: 16px;">Security Audit Results</h3>';
            
            results.forEach(res => {
                const statusClass = res.status === 'pass' ? 'secure' : (res.status === 'fail' ? 'high' : 'warning');
                html += `
                    <div class="finding-card ${statusClass}" style="margin-bottom: 12px; border-left: 4px solid">
                        <div class="finding-header" onclick="this.nextElementSibling.classList.toggle('expanded')">
                            <span class="severity-badge ${statusClass}">${res.status.toUpperCase()}</span>
                            <span class="finding-title">${res.name}</span>
                        </div>
                        <div class="finding-body" style="padding: 16px; background: rgba(255,255,255,0.02)">
                            <div class="finding-description">${res.description}</div>
                            ${res.details ? `<pre class="instance-snippet" style="margin-top: 8px;">${res.details}</pre>` : ''}
                        </div>
                    </div>
                `;
            });
            resultsDiv.innerHTML = html;
        }
    };

})();

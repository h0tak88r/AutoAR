/** @preserve @author Sandeep Wawdane @license MIT */
(function(global) {
    'use strict';

    const MODULE_KEY = 'dGhlY3liZXJzYW5kZWVw';

    const isValidPackageName = (name) => {
        if (!name || typeof name !== 'string') return false;
        return /^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)*$/.test(name);
    };

    const sanitizePath = (path) => {
        if (!path) return '';
        return path.replace(/[`$\\!"'|;&<>(){}[\]]/g, '');
    };

    class SecurityAuditor {
        constructor(adb) {
            this.adb = adb;
        }


        /**
         * MASTG-TEST-0001: Test Local Storage for Sensitive Data
         * Checks shared_prefs, databases, and files directories
         */
        async testLocalStorage(packageName) {
            if (!isValidPackageName(packageName)) {
                throw new Error('Invalid package name');
            }
            const results = {
                id: 'MASTG-TEST-0001',
                category: 'MASVS-STORAGE',
                title: 'Local Storage for Sensitive Data',
                description: 'Checks app storage directories for potentially sensitive data',
                findings: [],
                severity: 'info',
                status: 'pass'
            };

            try {
                const dataDir = `/data/data/${packageName}`;
                
                const prefs = await this.adb.shell(`run-as ${packageName} ls -la shared_prefs/ 2>/dev/null || su -c "ls -la ${dataDir}/shared_prefs/" 2>/dev/null || echo "ACCESS_DENIED"`);
                if (prefs && !prefs.includes('ACCESS_DENIED') && !prefs.includes('No such file')) {
                    const prefFiles = prefs.split('\n').filter(l => l.includes('.xml'));
                    for (const file of prefFiles) {
                        const fileName = file.split(/\s+/).pop();
                        if (fileName && fileName.endsWith('.xml')) {
                            results.findings.push({
                                type: 'shared_prefs',
                                file: fileName,
                                note: 'SharedPreferences file found - verify no sensitive data stored in plaintext'
                            });
                        }
                    }
                }

                const dbs = await this.adb.shell(`run-as ${packageName} ls -la databases/ 2>/dev/null || su -c "ls -la ${dataDir}/databases/" 2>/dev/null || echo "ACCESS_DENIED"`);
                if (dbs && !dbs.includes('ACCESS_DENIED') && !dbs.includes('No such file')) {
                    const dbFiles = dbs.split('\n').filter(l => l.includes('.db'));
                    for (const file of dbFiles) {
                        const fileName = file.split(/\s+/).pop();
                        if (fileName) {
                            results.findings.push({
                                type: 'database',
                                file: fileName,
                                note: 'SQLite database found - verify encryption and no sensitive data in plaintext'
                            });
                        }
                    }
                }

                const files = await this.adb.shell(`run-as ${packageName} ls -laR files/ 2>/dev/null || echo "ACCESS_DENIED"`);
                if (files && !files.includes('ACCESS_DENIED') && files.length > 10) {
                    results.findings.push({
                        type: 'files_directory',
                        note: 'Files directory contains data - manual review recommended'
                    });
                }

                const extStorage = await this.adb.shell(`ls -la /sdcard/Android/data/${packageName}/ 2>/dev/null || echo "NONE"`);
                if (extStorage && !extStorage.includes('NONE') && !extStorage.includes('No such file')) {
                    results.findings.push({
                        type: 'external_storage',
                        note: 'App uses external storage - data may be accessible to other apps',
                        severity: 'warning'
                    });
                    results.severity = 'warning';
                }

                if (results.findings.length > 0) {
                    results.status = 'review';
                }

            } catch (e) {
                results.status = 'error';
                results.error = e.message;
            }

            return results;
        }

        /**
         * MASTG-TEST-0002: Test Backup Flag
         * Checks android:allowBackup setting in manifest
         */
        async testBackupEnabled(packageName) {
            if (!isValidPackageName(packageName)) throw new Error('Invalid package name');
            const results = {
                id: 'MASTG-TEST-0002',
                category: 'MASVS-STORAGE',
                title: 'Backup Configuration',
                description: 'Checks if app allows backup which could expose sensitive data',
                findings: [],
                severity: 'info',
                status: 'pass'
            };

            try {
                const dumpsys = await this.adb.shell(`dumpsys package ${packageName} | grep -i "flags\\|allowBackup"`);
                
                if (dumpsys.toLowerCase().includes('allow_backup') || 
                    !dumpsys.toLowerCase().includes('disallow_backup')) {
                    results.findings.push({
                        type: 'backup_enabled',
                        note: 'App allows backup (android:allowBackup=true or not set)',
                        recommendation: 'Set android:allowBackup="false" or implement BackupAgent to exclude sensitive data'
                    });
                    results.severity = 'medium';
                    results.status = 'fail';
                }

            } catch (e) {
                results.status = 'error';
                results.error = e.message;
            }

            return results;
        }

        /**
         * MASTG-TEST-0003: Test for Sensitive Data in Logs
         * Checks logcat for potential sensitive data exposure
         */
        async testLogcat(packageName) {
            if (!isValidPackageName(packageName)) throw new Error('Invalid package name');
            const results = {
                id: 'MASTG-TEST-0003',
                category: 'MASVS-STORAGE',
                title: 'Sensitive Data in Logs',
                description: 'Analyzes app logs for potential sensitive data leakage',
                findings: [],
                severity: 'info',
                status: 'pass'
            };

            try {
                await this.adb.shell('logcat -c');
                
                await new Promise(r => setTimeout(r, 1000));
                
                const logs = await this.adb.shell(`logcat -d -v brief | grep -i "${packageName}" | tail -100`);
                
                const sensitivePatterns = [
                    { pattern: /password[=:]\s*\S+/gi, type: 'password' },
                    { pattern: /token[=:]\s*[a-zA-Z0-9_-]{10,}/gi, type: 'token' },
                    { pattern: /api[_-]?key[=:]\s*\S+/gi, type: 'api_key' },
                    { pattern: /bearer\s+[a-zA-Z0-9_-]+/gi, type: 'bearer_token' },
                    { pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, type: 'email' },
                    { pattern: /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/g, type: 'credit_card' },
                    { pattern: /secret[=:]\s*\S+/gi, type: 'secret' }
                ];

                for (const { pattern, type } of sensitivePatterns) {
                    const matches = logs.match(pattern);
                    if (matches && matches.length > 0) {
                        results.findings.push({
                            type: 'sensitive_log',
                            dataType: type,
                            count: matches.length,
                            note: `Found ${matches.length} potential ${type} value(s) in logs`
                        });
                        results.severity = 'high';
                        results.status = 'fail';
                    }
                }

                if (logs.length > 100 && results.findings.length === 0) {
                    results.findings.push({
                        type: 'verbose_logging',
                        note: 'App produces verbose logs - review for sensitive data'
                    });
                    results.status = 'review';
                }

            } catch (e) {
                results.status = 'error';
                results.error = e.message;
            }

            return results;
        }

        /**
         * MASTG-TEST-0004: Test Clipboard Data
         */
        async testClipboard() {
            const results = {
                id: 'MASTG-TEST-0004',
                category: 'MASVS-STORAGE',
                title: 'Clipboard Data Exposure',
                description: 'Checks clipboard for sensitive data that could be accessed by other apps',
                findings: [],
                severity: 'info',
                status: 'pass'
            };

            try {
                const clipboard = await this.adb.shell('service call clipboard 2 s16 com.android.shell 2>/dev/null');
                if (clipboard && clipboard.length > 50) {
                    results.findings.push({
                        type: 'clipboard_data',
                        note: 'Clipboard contains data - verify sensitive data is not being copied'
                    });
                    results.status = 'review';
                }
            } catch (e) {
                results.findings.push({
                    type: 'clipboard_check_failed',
                    note: 'Could not check clipboard (may require root)'
                });
            }

            return results;
        }


        /**
         * MASTG-TEST-0020: Test Exported Components
         * Checks for insecurely exported activities, services, receivers, providers
         */
        async testExportedComponents(packageName) {
            if (!isValidPackageName(packageName)) throw new Error('Invalid package name');
            const results = {
                id: 'MASTG-TEST-0020',
                category: 'MASVS-PLATFORM',
                title: 'Exported Components Analysis',
                description: 'Analyzes exported components that could be accessed by other apps',
                findings: [],
                severity: 'info',
                status: 'pass'
            };

            try {
                const dumpsys = await this.adb.shell(`dumpsys package ${packageName}`);

                const activityMatch = dumpsys.match(/Activity Resolver Table:[\s\S]*?(?=Receiver Resolver|Service Resolver|Provider Resolver|Packages:|$)/);
                if (activityMatch) {
                    const exportedActivities = activityMatch[0].match(/[a-zA-Z0-9_.]+\/[a-zA-Z0-9_.]+/g) || [];
                    const uniqueActivities = [...new Set(exportedActivities.filter(a => a.includes(packageName)))];
                    if (uniqueActivities.length > 0) {
                        results.findings.push({
                            type: 'exported_activities',
                            count: uniqueActivities.length,
                            components: uniqueActivities.slice(0, 10),
                            note: 'Exported activities found - verify they handle untrusted input safely'
                        });
                    }
                }

                const serviceMatch = dumpsys.match(/Service Resolver Table:[\s\S]*?(?=Receiver Resolver|Activity Resolver|Provider Resolver|Packages:|$)/);
                if (serviceMatch) {
                    const exportedServices = serviceMatch[0].match(/[a-zA-Z0-9_.]+\/[a-zA-Z0-9_.]+/g) || [];
                    const uniqueServices = [...new Set(exportedServices.filter(s => s.includes(packageName)))];
                    if (uniqueServices.length > 0) {
                        results.findings.push({
                            type: 'exported_services',
                            count: uniqueServices.length,
                            components: uniqueServices.slice(0, 10),
                            note: 'Exported services found - verify proper permission checks'
                        });
                    }
                }

                const receiverMatch = dumpsys.match(/Receiver Resolver Table:[\s\S]*?(?=Service Resolver|Activity Resolver|Provider Resolver|Packages:|$)/);
                if (receiverMatch) {
                    const exportedReceivers = receiverMatch[0].match(/[a-zA-Z0-9_.]+\/[a-zA-Z0-9_.]+/g) || [];
                    const uniqueReceivers = [...new Set(exportedReceivers.filter(r => r.includes(packageName)))];
                    if (uniqueReceivers.length > 0) {
                        results.findings.push({
                            type: 'exported_receivers',
                            count: uniqueReceivers.length,
                            components: uniqueReceivers.slice(0, 10),
                            note: 'Exported broadcast receivers found - verify intent filter security'
                        });
                    }
                }

                const providerMatch = dumpsys.match(/Registered ContentProviders:[\s\S]*?(?=ContentProvider Authorities|Packages:|$)/);
                if (providerMatch) {
                    const exportedProviders = providerMatch[0].match(/[a-zA-Z0-9_.]+\/[a-zA-Z0-9_.]+/g) || [];
                    const uniqueProviders = [...new Set(exportedProviders.filter(p => p.includes(packageName)))];
                    if (uniqueProviders.length > 0) {
                        results.findings.push({
                            type: 'exported_providers',
                            count: uniqueProviders.length,
                            components: uniqueProviders.slice(0, 10),
                            note: 'Content providers found - verify SQL injection and path traversal protection',
                            severity: 'warning'
                        });
                        results.severity = 'warning';
                    }
                }

                if (results.findings.length > 0) {
                    results.status = 'review';
                }

            } catch (e) {
                results.status = 'error';
                results.error = e.message;
            }

            return results;
        }

        /**
         * MASTG-TEST-0021: Test Deep Links
         * Analyzes deep link handlers for security issues
         */
        async testDeepLinks(packageName) {
            if (!isValidPackageName(packageName)) throw new Error('Invalid package name');
            const results = {
                id: 'MASTG-TEST-0021',
                category: 'MASVS-PLATFORM',
                title: 'Deep Link Analysis',
                description: 'Analyzes deep link/app link configurations for security issues',
                findings: [],
                severity: 'info',
                status: 'pass'
            };

            try {
                const dumpsys = await this.adb.shell(`dumpsys package ${packageName} | grep -A 20 "intent-filter"`);
                
                const schemes = dumpsys.match(/scheme="([^"]+)"/g) || [];
                const customSchemes = schemes.filter(s => !s.includes('http') && !s.includes('https'));
                
                if (customSchemes.length > 0) {
                    results.findings.push({
                        type: 'custom_schemes',
                        schemes: customSchemes.map(s => s.replace('scheme="', '').replace('"', '')),
                        note: 'Custom URL schemes found - verify input validation on deep link parameters',
                        severity: 'medium'
                    });
                    results.severity = 'medium';
                    results.status = 'review';
                }

                if (dumpsys.includes('scheme="http"') || dumpsys.includes('scheme="https"')) {
                    results.findings.push({
                        type: 'web_links',
                        note: 'App handles web URLs - verify App Links are properly verified'
                    });
                }

            } catch (e) {
                results.status = 'error';
                results.error = e.message;
            }

            return results;
        }

        /**
         * MASTG-TEST-0022: Test WebView Configuration
         */
        async testWebViewConfig(packageName) {
            if (!isValidPackageName(packageName)) throw new Error('Invalid package name');
            const results = {
                id: 'MASTG-TEST-0022',
                category: 'MASVS-PLATFORM',
                title: 'WebView Security Configuration',
                description: 'Checks WebView security settings by analyzing app behavior',
                findings: [],
                severity: 'info',
                status: 'pass'
            };

            try {
                const apkPath = await this.adb.shell(`pm path ${packageName} | head -1`);
                if (apkPath.includes('package:')) {
                    const path = apkPath.replace('package:', '').trim();
                    
                    const webviewCheck = await this.adb.shell(`strings ${path} 2>/dev/null | grep -i "webview\\|javascript\\|addJavascriptInterface" | head -20`);
                    
                    if (webviewCheck && webviewCheck.length > 0) {
                        results.findings.push({
                            type: 'webview_detected',
                            note: 'App appears to use WebView - verify JavaScript is disabled if not needed'
                        });

                        if (webviewCheck.toLowerCase().includes('addjavascriptinterface')) {
                            results.findings.push({
                                type: 'javascript_interface',
                                note: 'JavaScript interface detected - verify no sensitive APIs exposed',
                                severity: 'high'
                            });
                            results.severity = 'high';
                            results.status = 'review';
                        }
                    }
                }

            } catch (e) {
                results.status = 'error';
                results.error = e.message;
            }

            return results;
        }


        /**
         * MASTG-TEST-0038: Test Root Detection
         */
        async testRootDetection() {
            const results = {
                id: 'MASTG-TEST-0038',
                category: 'MASVS-RESILIENCE',
                title: 'Root Detection Analysis',
                description: 'Checks device root status and common root indicators',
                findings: [],
                severity: 'info',
                status: 'pass'
            };

            try {
                const suCheck = await this.adb.shell('which su 2>/dev/null || echo "NOT_FOUND"');
                if (suCheck && !suCheck.includes('NOT_FOUND')) {
                    results.findings.push({
                        type: 'su_binary',
                        path: suCheck.trim(),
                        note: 'su binary found - device appears to be rooted'
                    });
                    results.severity = 'warning';
                }

                const magiskCheck = await this.adb.shell('ls /data/adb/magisk 2>/dev/null || echo "NOT_FOUND"');
                if (!magiskCheck.includes('NOT_FOUND')) {
                    results.findings.push({
                        type: 'magisk',
                        note: 'Magisk installation detected'
                    });
                }

                const supersuCheck = await this.adb.shell('pm list packages | grep supersu 2>/dev/null');
                if (supersuCheck && supersuCheck.includes('supersu')) {
                    results.findings.push({
                        type: 'supersu',
                        note: 'SuperSU package detected'
                    });
                }

                const buildTags = await this.adb.shell('getprop ro.build.tags');
                if (buildTags && buildTags.includes('test-keys')) {
                    results.findings.push({
                        type: 'test_keys',
                        note: 'Device built with test-keys - indicates custom ROM'
                    });
                }

                const rootApps = ['com.topjohnwu.magisk', 'eu.chainfire.supersu', 'com.koushikdutta.superuser', 'com.noshufou.android.su'];
                for (const app of rootApps) {
                    const check = await this.adb.shell(`pm path ${app} 2>/dev/null`);
                    if (check && check.includes('package:')) {
                        results.findings.push({
                            type: 'root_app',
                            package: app,
                            note: 'Root management app detected'
                        });
                    }
                }

                const fridaCheck = await this.adb.shell('ps -A 2>/dev/null | grep -i frida || echo "NOT_FOUND"');
                if (!fridaCheck.includes('NOT_FOUND') && fridaCheck.trim().length > 0) {
                    results.findings.push({
                        type: 'frida_server',
                        note: 'Frida server process detected - dynamic instrumentation active',
                        severity: 'high'
                    });
                    results.severity = 'high';
                }

                if (results.findings.length > 0) {
                    results.status = 'review';
                }

            } catch (e) {
                results.status = 'error';
                results.error = e.message;
            }

            return results;
        }

        /**
         * MASTG-TEST-0039: Test Debuggable Flag
         */
        async testDebuggable(packageName) {
            if (!isValidPackageName(packageName)) throw new Error('Invalid package name');
            const results = {
                id: 'MASTG-TEST-0039',
                category: 'MASVS-RESILIENCE',
                title: 'Debuggable Application Check',
                description: 'Checks if app is debuggable which allows runtime manipulation',
                findings: [],
                severity: 'info',
                status: 'pass'
            };

            try {
                const dumpsys = await this.adb.shell(`dumpsys package ${packageName} | grep -i "flags\\|debuggable"`);
                
                if (dumpsys.toLowerCase().includes('debuggable')) {
                    results.findings.push({
                        type: 'debuggable',
                        note: 'Application is debuggable - allows runtime manipulation via JDWP',
                        severity: 'critical'
                    });
                    results.severity = 'critical';
                    results.status = 'fail';
                }

                const cert = await this.adb.shell(`pm dump ${packageName} | grep -i "signatures\\|debug"`);
                if (cert && cert.toLowerCase().includes('debug')) {
                    results.findings.push({
                        type: 'debug_certificate',
                        note: 'App may be signed with debug certificate'
                    });
                }

            } catch (e) {
                results.status = 'error';
                results.error = e.message;
            }

            return results;
        }

        /**
         * MASTG-TEST-0044: Test for Emulator Detection
         */
        async testEmulatorDetection() {
            const results = {
                id: 'MASTG-TEST-0044',
                category: 'MASVS-RESILIENCE',
                title: 'Emulator Detection',
                description: 'Checks if running on emulator (apps should detect this)',
                findings: [],
                severity: 'info',
                status: 'pass'
            };

            try {
                const props = await this.adb.shell('getprop ro.build.fingerprint; getprop ro.product.model; getprop ro.hardware; getprop ro.kernel.qemu');
                
                const emulatorIndicators = ['sdk', 'generic', 'emulator', 'goldfish', 'ranchu', 'vbox', 'genymotion'];
                const propsLower = props.toLowerCase();
                
                for (const indicator of emulatorIndicators) {
                    if (propsLower.includes(indicator)) {
                        results.findings.push({
                            type: 'emulator_indicator',
                            indicator: indicator,
                            note: `Emulator indicator "${indicator}" found in build properties`
                        });
                    }
                }

                const qemuCheck = await this.adb.shell('getprop ro.kernel.qemu');
                if (qemuCheck && qemuCheck.trim() === '1') {
                    results.findings.push({
                        type: 'qemu',
                        note: 'Running on QEMU-based emulator'
                    });
                }

                if (results.findings.length > 0) {
                    results.status = 'review';
                    results.severity = 'info';
                }

            } catch (e) {
                results.status = 'error';
                results.error = e.message;
            }

            return results;
        }


        /**
         * MASTG-TEST-0033: Test for Minimum SDK Version
         */
        async testMinSdkVersion(packageName) {
            if (!isValidPackageName(packageName)) throw new Error('Invalid package name');
            const results = {
                id: 'MASTG-TEST-0033',
                category: 'MASVS-CODE',
                title: 'Minimum SDK Version',
                description: 'Checks if app targets outdated Android versions with known vulnerabilities',
                findings: [],
                severity: 'info',
                status: 'pass'
            };

            try {
                const dumpsys = await this.adb.shell(`dumpsys package ${packageName} | grep -i "minSdk\\|targetSdk\\|versionCode\\|versionName"`);
                
                const minSdkMatch = dumpsys.match(/minSdk=(\d+)/);
                const targetSdkMatch = dumpsys.match(/targetSdk=(\d+)/);
                const versionMatch = dumpsys.match(/versionName=([^\s]+)/);
                
                if (minSdkMatch) {
                    const minSdk = parseInt(minSdkMatch[1]);
                    results.findings.push({
                        type: 'min_sdk',
                        value: minSdk,
                        note: `Minimum SDK: ${minSdk} (Android ${this.sdkToAndroidVersion(minSdk)})`
                    });
                    
                    if (minSdk < 21) {
                        results.findings.push({
                            type: 'outdated_min_sdk',
                            note: 'minSdkVersion < 21 - app supports Android 4.x with known vulnerabilities',
                            severity: 'high'
                        });
                        results.severity = 'high';
                        results.status = 'fail';
                    } else if (minSdk < 26) {
                        results.findings.push({
                            type: 'old_min_sdk',
                            note: 'minSdkVersion < 26 - consider increasing for better security defaults',
                            severity: 'medium'
                        });
                        results.severity = 'medium';
                        results.status = 'review';
                    }
                }

                if (targetSdkMatch) {
                    const targetSdk = parseInt(targetSdkMatch[1]);
                    results.findings.push({
                        type: 'target_sdk',
                        value: targetSdk,
                        note: `Target SDK: ${targetSdk} (Android ${this.sdkToAndroidVersion(targetSdk)})`
                    });
                    
                    if (targetSdk < 30) {
                        results.findings.push({
                            type: 'outdated_target_sdk',
                            note: 'targetSdkVersion < 30 - missing scoped storage and other security improvements',
                            severity: 'medium'
                        });
                        if (results.severity === 'info') results.severity = 'medium';
                    }
                }

                if (versionMatch) {
                    results.findings.push({
                        type: 'app_version',
                        value: versionMatch[1]
                    });
                }

            } catch (e) {
                results.status = 'error';
                results.error = e.message;
            }

            return results;
        }

        /**
         * MASTG-TEST-0035: Test APK Signature
         */
        async testApkSignature(packageName) {
            if (!isValidPackageName(packageName)) throw new Error('Invalid package name');
            const results = {
                id: 'MASTG-TEST-0035',
                category: 'MASVS-CODE',
                title: 'APK Signature Analysis',
                description: 'Analyzes APK signing scheme and certificate',
                findings: [],
                severity: 'info',
                status: 'pass'
            };

            try {
                const dumpsys = await this.adb.shell(`dumpsys package ${packageName} | grep -A 5 "Signatures\\|signing"`);
                
                if (dumpsys.includes('apkSigningVersion')) {
                    const versionMatch = dumpsys.match(/apkSigningVersion[:=]\s*(\d+)/);
                    if (versionMatch) {
                        const sigVersion = parseInt(versionMatch[1]);
                        results.findings.push({
                            type: 'signing_scheme',
                            version: sigVersion,
                            note: `APK Signature Scheme v${sigVersion}`
                        });
                        
                        if (sigVersion < 2) {
                            results.findings.push({
                                type: 'weak_signing',
                                note: 'Uses v1 signing only - consider v2/v3 for better integrity protection',
                                severity: 'low'
                            });
                            results.severity = 'low';
                        }
                    }
                }

            } catch (e) {
                results.status = 'error';
                results.error = e.message;
            }

            return results;
        }


        /**
         * MASTG-TEST-0019: Test Network Security Configuration
         */
        async testNetworkSecurity(packageName) {
            if (!isValidPackageName(packageName)) throw new Error('Invalid package name');
            const results = {
                id: 'MASTG-TEST-0019',
                category: 'MASVS-NETWORK',
                title: 'Network Security Configuration',
                description: 'Analyzes network security settings and cleartext traffic policy',
                findings: [],
                severity: 'info',
                status: 'pass'
            };

            try {
                const dumpsys = await this.adb.shell(`dumpsys package ${packageName}`);
                
                if (dumpsys.includes('usesCleartextTraffic=true') || 
                    (!dumpsys.includes('usesCleartextTraffic=false') && !dumpsys.includes('networkSecurityConfig'))) {
                    results.findings.push({
                        type: 'cleartext_traffic',
                        note: 'App may allow cleartext (HTTP) traffic',
                        severity: 'medium'
                    });
                    results.severity = 'medium';
                    results.status = 'review';
                }

                if (dumpsys.includes('networkSecurityConfig')) {
                    results.findings.push({
                        type: 'network_security_config',
                        note: 'App uses network_security_config.xml - review for proper pinning'
                    });
                }

                const netstat = await this.adb.shell(`cat /proc/net/tcp 2>/dev/null | head -20`);
                if (netstat) {
                    results.findings.push({
                        type: 'active_connections',
                        note: 'Active network connections detected - manual traffic analysis recommended'
                    });
                }

            } catch (e) {
                results.status = 'error';
                results.error = e.message;
            }

            return results;
        }


        /**
         * Test for insecure authentication storage
         */
        async testAuthStorage(packageName) {
            if (!isValidPackageName(packageName)) throw new Error('Invalid package name');
            const results = {
                id: 'MASTG-TEST-0010',
                category: 'MASVS-AUTH',
                title: 'Authentication Data Storage',
                description: 'Checks for insecure storage of authentication tokens',
                findings: [],
                severity: 'info',
                status: 'pass'
            };

            try {
                const dataDir = `/data/data/${packageName}`;
                
                const prefs = await this.adb.shell(`run-as ${packageName} cat shared_prefs/*.xml 2>/dev/null | grep -i "token\\|auth\\|session\\|password\\|key" || echo "ACCESS_DENIED"`);
                
                if (prefs && !prefs.includes('ACCESS_DENIED')) {
                    const tokenPatterns = [
                        { pattern: /token/i, type: 'auth_token' },
                        { pattern: /session/i, type: 'session_data' },
                        { pattern: /password/i, type: 'password' },
                        { pattern: /apikey/i, type: 'api_key' }
                    ];

                    for (const { pattern, type } of tokenPatterns) {
                        if (pattern.test(prefs)) {
                            results.findings.push({
                                type: 'insecure_storage',
                                dataType: type,
                                note: `${type} found in SharedPreferences - verify encryption`,
                                severity: 'medium'
                            });
                            results.severity = 'medium';
                            results.status = 'review';
                        }
                    }
                }

            } catch (e) {
                results.status = 'error';
                results.error = e.message;
            }

            return results;
        }


        /**
         * Analyze app permissions for security concerns
         */
        async testPermissions(packageName) {
            if (!isValidPackageName(packageName)) throw new Error('Invalid package name');
            const results = {
                id: 'PERM-ANALYSIS',
                category: 'MASVS-PLATFORM',
                title: 'Permission Analysis',
                description: 'Analyzes app permissions for security and privacy concerns',
                findings: [],
                severity: 'info',
                status: 'pass'
            };

            const dangerousPerms = {
                'android.permission.READ_CONTACTS': 'Access to contacts',
                'android.permission.WRITE_CONTACTS': 'Modify contacts',
                'android.permission.READ_CALL_LOG': 'Access to call history',
                'android.permission.WRITE_CALL_LOG': 'Modify call history',
                'android.permission.READ_CALENDAR': 'Access to calendar',
                'android.permission.WRITE_CALENDAR': 'Modify calendar',
                'android.permission.CAMERA': 'Camera access',
                'android.permission.RECORD_AUDIO': 'Microphone access',
                'android.permission.ACCESS_FINE_LOCATION': 'Precise location',
                'android.permission.ACCESS_COARSE_LOCATION': 'Approximate location',
                'android.permission.READ_EXTERNAL_STORAGE': 'Read external storage',
                'android.permission.WRITE_EXTERNAL_STORAGE': 'Write external storage',
                'android.permission.READ_SMS': 'Read SMS messages',
                'android.permission.SEND_SMS': 'Send SMS messages',
                'android.permission.RECEIVE_SMS': 'Receive SMS messages',
                'android.permission.READ_PHONE_STATE': 'Phone state and identity',
                'android.permission.CALL_PHONE': 'Make phone calls',
                'android.permission.BODY_SENSORS': 'Body sensors',
                'android.permission.ACTIVITY_RECOGNITION': 'Activity recognition',
                'android.permission.ACCESS_BACKGROUND_LOCATION': 'Background location access',
                'android.permission.SYSTEM_ALERT_WINDOW': 'Draw over other apps',
                'android.permission.MANAGE_EXTERNAL_STORAGE': 'Manage all files',
                'android.permission.REQUEST_INSTALL_PACKAGES': 'Install packages',
                'android.permission.QUERY_ALL_PACKAGES': 'Query all packages'
            };

            try {
                const dumpsys = await this.adb.shell(`dumpsys package ${packageName} | grep -A 100 "requested permissions:" | grep -B 100 "install permissions:"`);
                
                const requestedPerms = [];
                const grantedPerms = [];
                
                for (const [perm, desc] of Object.entries(dangerousPerms)) {
                    if (dumpsys.includes(perm)) {
                        const isGranted = dumpsys.includes(`${perm}: granted=true`);
                        requestedPerms.push({ permission: perm, description: desc, granted: isGranted });
                        
                        if (isGranted) {
                            grantedPerms.push({ permission: perm, description: desc });
                        }
                    }
                }

                if (grantedPerms.length > 0) {
                    results.findings.push({
                        type: 'dangerous_permissions',
                        count: grantedPerms.length,
                        permissions: grantedPerms,
                        note: `${grantedPerms.length} dangerous permission(s) granted`
                    });
                    results.status = 'review';
                }

                const hasLocation = grantedPerms.some(p => p.permission.includes('LOCATION'));
                const hasCamera = grantedPerms.some(p => p.permission.includes('CAMERA'));
                const hasAudio = grantedPerms.some(p => p.permission.includes('RECORD_AUDIO'));
                const hasSms = grantedPerms.some(p => p.permission.includes('SMS'));

                if ((hasLocation && hasCamera) || (hasLocation && hasAudio) || hasSms) {
                    results.findings.push({
                        type: 'sensitive_permission_combo',
                        note: 'High-risk permission combination detected - verify legitimate use',
                        severity: 'warning'
                    });
                    results.severity = 'warning';
                }

            } catch (e) {
                results.status = 'error';
                results.error = e.message;
            }

            return results;
        }


        /**
         * Get all local storage files for an app
         * Returns categorized files: sharedPrefs, databases, files, external
         * Uses root su -c commands for direct access to app data
         */
        async getLocalStorageFiles(packageName) {
            if (!isValidPackageName(packageName)) throw new Error('Invalid package name');
            const result = {
                sharedPrefs: [],
                databases: [],
                files: [],
                external: []
            };

            try {
                const dataDir = `/data/data/${packageName}`;
                const safeDd = dataDir.replace(/["\\$`]/g, '\\$&');

                const prefsOutput = await this.adb.shell(`su -c "ls -la \\"${safeDd}/shared_prefs/\\"" 2>/dev/null || echo "ACCESS_DENIED"`);
                if (prefsOutput && !prefsOutput.includes('ACCESS_DENIED') && !prefsOutput.includes('No such file') && !prefsOutput.includes('not found')) {
                    const lines = prefsOutput.split('\n').filter(l => l.trim() && !l.startsWith('total'));
                    for (const line of lines) {
                        const parts = line.trim().split(/\s+/);
                        if (parts.length >= 7) {
                            const fileName = parts.slice(7).join(' ');
                            if (fileName && fileName !== '.' && fileName !== '..') {
                                const size = parts[4] || '0';
                                result.sharedPrefs.push({
                                    name: fileName,
                                    path: `${dataDir}/shared_prefs/${fileName}`,
                                    size: size,
                                    type: 'xml'
                                });
                            }
                        }
                    }
                }

                const dbOutput = await this.adb.shell(`su -c "ls -la \\"${safeDd}/databases/\\"" 2>/dev/null || echo "ACCESS_DENIED"`);
                if (dbOutput && !dbOutput.includes('ACCESS_DENIED') && !dbOutput.includes('No such file') && !dbOutput.includes('not found')) {
                    const lines = dbOutput.split('\n').filter(l => l.trim() && !l.startsWith('total'));
                    for (const line of lines) {
                        const parts = line.trim().split(/\s+/);
                        if (parts.length >= 7) {
                            const fileName = parts.slice(7).join(' ');
                            if (fileName && fileName !== '.' && fileName !== '..' && !fileName.endsWith('-journal') && !fileName.endsWith('-wal') && !fileName.endsWith('-shm')) {
                                const size = parts[4] || '0';
                                result.databases.push({
                                    name: fileName,
                                    path: `${dataDir}/databases/${fileName}`,
                                    size: size,
                                    type: 'db'
                                });
                            }
                        }
                    }
                }

                const filesOutput = await this.adb.shell(`su -c "find \\"${safeDd}/files/\\" -type f 2>/dev/null | head -50" || echo "ACCESS_DENIED"`);
                if (filesOutput && !filesOutput.includes('ACCESS_DENIED') && !filesOutput.includes('No such file') && !filesOutput.includes('not found')) {
                    const filePaths = filesOutput.split('\n').filter(l => l.trim() && l.startsWith('/'));
                    for (const filePath of filePaths) {
                        if (filePath) {
                            const fileName = filePath.trim().split('/').pop();
                            result.files.push({
                                name: fileName,
                                path: filePath.trim(),
                                size: '-',
                                type: this.getFileType(fileName)
                            });
                        }
                    }
                }

                const cacheOutput = await this.adb.shell(`su -c "ls -la \\"${safeDd}/cache/\\"" 2>/dev/null || echo "ACCESS_DENIED"`);
                if (cacheOutput && !cacheOutput.includes('ACCESS_DENIED') && !cacheOutput.includes('No such file') && !cacheOutput.includes('not found')) {
                    const lines = cacheOutput.split('\n').filter(l => l.trim() && !l.startsWith('total'));
                    for (const line of lines) {
                        const parts = line.trim().split(/\s+/);
                        if (parts.length >= 7) {
                            const fileName = parts.slice(7).join(' ');
                            if (fileName && fileName !== '.' && fileName !== '..') {
                                const size = parts[4] || '0';
                                result.files.push({
                                    name: `[cache] ${fileName}`,
                                    path: `${dataDir}/cache/${fileName}`,
                                    size: size,
                                    type: line.startsWith('d') ? 'folder' : this.getFileType(fileName)
                                });
                            }
                        }
                    }
                }

                const safeExtDir = `/sdcard/Android/data/${packageName}/`.replace(/["\\$`]/g, '\\$&');
                const extOutput = await this.adb.shell(`ls -la "${safeExtDir}" 2>/dev/null || echo "NOT_FOUND"`);
                if (extOutput && !extOutput.includes('NOT_FOUND') && !extOutput.includes('No such file')) {
                    const lines = extOutput.split('\n').filter(l => l.trim() && !l.startsWith('total'));
                    for (const line of lines) {
                        const parts = line.trim().split(/\s+/);
                        if (parts.length >= 7) {
                            const fileName = parts.slice(7).join(' ');
                            if (fileName && fileName !== '.' && fileName !== '..') {
                                const size = parts[4] || '0';
                                result.external.push({
                                    name: fileName,
                                    path: `/sdcard/Android/data/${packageName}/${fileName}`,
                                    size: size,
                                    type: line.startsWith('d') ? 'folder' : this.getFileType(fileName)
                                });
                            }
                        }
                    }
                }

            } catch (e) {
            }

            return result;
        }

        /**
         * Read a storage file content using root su -c
         */
        async readStorageFile(packageName, filePath) {
            if (!isValidPackageName(packageName)) throw new Error('Invalid package name');
            if (!filePath) throw new Error('No file path provided');
            
            try {
                let content = '';
                const safePath = filePath.replace(/["\\$`]/g, '\\$&');
                
                if (filePath.startsWith('/sdcard/') || filePath.startsWith('/storage/emulated/')) {
                    content = await this.adb.shell(`cat "${safePath}"`);
                } else {
                    content = await this.adb.shell(`su -c "cat \\"${safePath}\\""`);
                }
                
                if (!content || content.trim() === '') {
                    return '[File is empty or could not be read]';
                }
                return content;
            } catch (e) {
                return '[Could not read file - root access may be required]';
            }
        }

        /**
         * Get file type based on extension
         */
        getFileType(fileName) {
            if (!fileName) return 'file';
            const ext = fileName.split('.').pop()?.toLowerCase();
            const types = {
                'xml': 'xml',
                'json': 'json',
                'db': 'db',
                'sqlite': 'db',
                'sqlite3': 'db',
                'txt': 'text',
                'log': 'text',
                'cfg': 'config',
                'conf': 'config',
                'properties': 'config',
                'png': 'image',
                'jpg': 'image',
                'jpeg': 'image',
                'gif': 'image',
                'webp': 'image'
            };
            return types[ext] || 'file';
        }

        /**
         * Test only dangerous permissions (filtered subset)
         */
        async testDangerousPermissionsOnly(packageName) {
            if (!isValidPackageName(packageName)) throw new Error('Invalid package name');
            const results = {
                id: 'DANGEROUS-PERMS',
                category: 'MASVS-PLATFORM',
                title: 'Dangerous Permissions Analysis',
                description: 'Analyzes only dangerous runtime permissions that access sensitive user data',
                findings: [],
                severity: 'info',
                status: 'pass'
            };

            const dangerousPerms = {
                'android.permission.READ_EXTERNAL_STORAGE': { desc: 'Read files on external storage', group: 'Storage' },
                'android.permission.WRITE_EXTERNAL_STORAGE': { desc: 'Write files on external storage', group: 'Storage' },
                'android.permission.MANAGE_EXTERNAL_STORAGE': { desc: 'Access all files on device', group: 'Storage' },
                
                'android.permission.CAMERA': { desc: 'Take photos and record videos', group: 'Camera' },
                
                'android.permission.RECORD_AUDIO': { desc: 'Record audio via microphone', group: 'Microphone' },
                
                'android.permission.ACCESS_FINE_LOCATION': { desc: 'Access precise GPS location', group: 'Location' },
                'android.permission.ACCESS_COARSE_LOCATION': { desc: 'Access approximate location', group: 'Location' },
                'android.permission.ACCESS_BACKGROUND_LOCATION': { desc: 'Access location in background', group: 'Location' },
                
                'android.permission.READ_CONTACTS': { desc: 'Read contact information', group: 'Contacts' },
                'android.permission.WRITE_CONTACTS': { desc: 'Modify contact information', group: 'Contacts' },
                
                'android.permission.READ_PHONE_STATE': { desc: 'Read phone status and identity', group: 'Phone' },
                'android.permission.CALL_PHONE': { desc: 'Make phone calls directly', group: 'Phone' },
                'android.permission.READ_CALL_LOG': { desc: 'Read call history', group: 'Phone' },
                'android.permission.WRITE_CALL_LOG': { desc: 'Modify call history', group: 'Phone' },
                
                'android.permission.READ_SMS': { desc: 'Read SMS messages', group: 'SMS' },
                'android.permission.SEND_SMS': { desc: 'Send SMS messages', group: 'SMS' },
                'android.permission.RECEIVE_SMS': { desc: 'Receive SMS messages', group: 'SMS' },
                
                'android.permission.READ_CALENDAR': { desc: 'Read calendar events', group: 'Calendar' },
                'android.permission.WRITE_CALENDAR': { desc: 'Modify calendar events', group: 'Calendar' },
                
                'android.permission.BODY_SENSORS': { desc: 'Access body sensors like heart rate', group: 'Sensors' },
                'android.permission.ACTIVITY_RECOGNITION': { desc: 'Recognize physical activity', group: 'Sensors' }
            };

            try {
                const dumpsys = await this.adb.shell(`dumpsys package ${packageName}`);
                const grantedPerms = [];

                for (const [perm, info] of Object.entries(dangerousPerms)) {
                    const grantedMatch = dumpsys.includes(`${perm}: granted=true`);
                    if (grantedMatch) {
                        grantedPerms.push({
                            permission: perm,
                            description: info.desc,
                            group: info.group
                        });
                    }
                }

                if (grantedPerms.length > 0) {
                    const groups = {};
                    for (const perm of grantedPerms) {
                        if (!groups[perm.group]) {
                            groups[perm.group] = [];
                        }
                        groups[perm.group].push(perm);
                    }

                    results.findings.push({
                        type: 'granted_dangerous_permissions',
                        count: grantedPerms.length,
                        permissions: grantedPerms,
                        groups: groups,
                        note: `${grantedPerms.length} dangerous permission(s) currently granted to this app`
                    });

                    const hasHighRisk = grantedPerms.some(p => 
                        p.permission.includes('SMS') || 
                        p.permission.includes('CALL_LOG') ||
                        p.permission.includes('BACKGROUND_LOCATION') ||
                        p.permission.includes('MANAGE_EXTERNAL_STORAGE')
                    );
                    
                    results.severity = hasHighRisk ? 'high' : 'medium';
                    results.status = 'review';
                }

            } catch (e) {
                results.status = 'error';
                results.error = e.message;
            }

            return results;
        }


        async getAppInfo(packageName) {
            if (!isValidPackageName(packageName)) throw new Error('Invalid package name');
            const info = { packageName };
            try {
                const dump = await this.adb.shell(`dumpsys package ${packageName}`);
                const match = (re) => { const m = dump.match(re); return m ? m[1].trim() : null; };
                info.versionName = match(/versionName=(\S+)/);
                info.versionCode = match(/versionCode=(\d+)/);
                info.targetSdk = match(/targetSdk=(\d+)/);
                info.minSdk = match(/minSdk=(\d+)/);
                info.firstInstall = match(/firstInstallTime=(.+)/);
                info.lastUpdate = match(/lastUpdateTime=(.+)/);
                info.dataDir = match(/dataDir=(\S+)/);
                info.uid = match(/userId=(\d+)/);
                info.flags = [];
                if (dump.includes('DEBUGGABLE')) info.flags.push('DEBUGGABLE');
                if (dump.includes('ALLOW_BACKUP')) info.flags.push('ALLOW_BACKUP');
                if (dump.includes('SYSTEM')) info.flags.push('SYSTEM');
                if (dump.includes('HAS_CODE')) info.flags.push('HAS_CODE');
                if (dump.includes('LARGE_HEAP')) info.flags.push('LARGE_HEAP');
                if (dump.includes('usesCleartextTraffic=true')) info.flags.push('CLEARTEXT_TRAFFIC');
                const sigMatch = dump.match(/apkSigningVersion[:=]\s*(\d+)/);
                info.signingVersion = sigMatch ? 'v' + sigMatch[1] : null;
                const sizeOut = await this.adb.shell(`du -sh /data/data/${packageName}/ 2>/dev/null || echo "0"`);
                const sizeMatch = sizeOut.match(/^([\d.]+\S+)/);
                info.dataSize = sizeMatch ? sizeMatch[1] : null;
                const apkPath = match(/codePath=(\S+)/);
                if (apkPath) {
                    info.apkPath = apkPath;
                    const apkSizeOut = await this.adb.shell(`du -sh "${apkPath.replace(/"/g, '\\"')}" 2>/dev/null || echo "0"`);
                    const apkSizeMatch = apkSizeOut.match(/^([\d.]+\S+)/);
                    info.apkSize = apkSizeMatch ? apkSizeMatch[1] : null;
                }
            } catch (e) {
                info.error = e.message;
            }
            return info;
        }

        async getRunningProcesses(packageName) {
            if (packageName && !isValidPackageName(packageName)) throw new Error('Invalid package name');
            try {
                let cmd = 'ps -A -o PID,USER,VSZ,RSS,STAT,NAME 2>/dev/null || ps -A 2>/dev/null || ps';
                if (packageName) {
                    cmd += ` | grep -i "${packageName}"`;
                }
                const output = await this.adb.shell(cmd);
                const lines = output.split('\n').filter(l => l.trim());
                const procs = [];
                for (const line of lines) {
                    const parts = line.trim().split(/\s+/);
                    if (parts.length >= 2 && /^\d+$/.test(parts[0])) {
                        procs.push({
                            pid: parts[0],
                            user: parts[1],
                            vsz: parts[2] || '-',
                            rss: parts[3] || '-',
                            stat: parts[4] || '-',
                            name: parts.slice(5).join(' ') || parts[parts.length - 1]
                        });
                    }
                }
                return procs;
            } catch (e) {
                return [];
            }
        }

        async getActiveConnections(packageName) {
            if (packageName && !isValidPackageName(packageName)) throw new Error('Invalid package name');
            try {
                let uid = '';
                if (packageName) {
                    const uidOut = await this.adb.shell(`dumpsys package ${packageName} | grep userId=`);
                    const uidMatch = uidOut.match(/userId=(\d+)/);
                    uid = uidMatch ? uidMatch[1] : '';
                }
                const tcp = await this.adb.shell('cat /proc/net/tcp 2>/dev/null');
                const tcp6 = await this.adb.shell('cat /proc/net/tcp6 2>/dev/null');
                const all = (tcp + '\n' + tcp6).split('\n').filter(l => l.trim() && !l.includes('local_address'));
                const connections = [];
                for (const line of all) {
                    const parts = line.trim().split(/\s+/);
                    if (parts.length < 4) continue;
                    const localAddr = parts[1];
                    const remoteAddr = parts[2];
                    const state = parts[3];
                    const lineUid = parts[7];
                    if (uid && lineUid !== uid) continue;
                    const parseAddr = (hex) => {
                        const [ip, port] = hex.split(':');
                        const p = parseInt(port, 16);
                        if (ip.length === 8) {
                            const o = [];
                            for (let i = ip.length - 2; i >= 0; i -= 2) {
                                o.push(parseInt(ip.substr(i, 2), 16));
                            }
                            return o.join('.') + ':' + p;
                        }
                        return ip + ':' + p;
                    };
                    const states = { '01': 'ESTABLISHED', '02': 'SYN_SENT', '06': 'TIME_WAIT', '0A': 'LISTEN', '08': 'CLOSE_WAIT' };
                    connections.push({
                        local: parseAddr(localAddr),
                        remote: parseAddr(remoteAddr),
                        state: states[state] || state,
                        uid: lineUid
                    });
                }
                return connections;
            } catch (e) {
                return [];
            }
        }

        async testIntentFilters(packageName) {
            if (!isValidPackageName(packageName)) throw new Error('Invalid package name');
            const results = {
                id: 'INTENT-FILTERS',
                category: 'MASVS-PLATFORM',
                title: 'Intent Filter Analysis',
                description: 'Analyzes intent filters for potential attack surface',
                findings: [],
                severity: 'info',
                status: 'pass'
            };
            try {
                const dump = await this.adb.shell(`dumpsys package ${packageName} | grep -A 10 "intent-filter"`);
                const schemes = new Set();
                const hosts = new Set();
                const actions = new Set();
                const lines = dump.split('\n');
                for (const line of lines) {
                    const schemeMatch = line.match(/scheme="([^"]+)"/);
                    if (schemeMatch) schemes.add(schemeMatch[1]);
                    const hostMatch = line.match(/host="([^"]+)"/);
                    if (hostMatch) hosts.add(hostMatch[1]);
                    const actionMatch = line.match(/Action:\s*"([^"]+)"/);
                    if (actionMatch) actions.add(actionMatch[1]);
                }
                if (schemes.size > 0) {
                    results.findings.push({ type: 'url_schemes', schemes: Array.from(schemes), note: 'Custom URL schemes registered' });
                    if (schemes.has('http') || schemes.has('https')) {
                        results.findings.push({ type: 'app_links', hosts: Array.from(hosts), note: 'App Links / deep links detected' });
                    }
                }
                if (actions.size > 0) {
                    const customActions = Array.from(actions).filter(a => !a.startsWith('android.'));
                    if (customActions.length > 0) {
                        results.findings.push({ type: 'custom_actions', actions: customActions, note: 'Custom intent actions' });
                    }
                }
            } catch (e) {
                results.status = 'error';
                results.error = e.message;
            }
            return results;
        }


        sdkToAndroidVersion(sdk) {
            const versions = {
                34: '14', 33: '13', 32: '12L', 31: '12', 30: '11', 29: '10',
                28: '9', 27: '8.1', 26: '8.0', 25: '7.1', 24: '7.0', 23: '6.0',
                22: '5.1', 21: '5.0', 19: '4.4', 18: '4.3', 17: '4.2', 16: '4.1'
            };
            return versions[sdk] || `SDK ${sdk}`;
        }

        /**
         * Run all security tests for a package
         */
        async runFullAudit(packageName, onProgress = null) {
            const allResults = {
                packageName,
                timestamp: new Date().toISOString(),
                summary: { pass: 0, fail: 0, review: 0, error: 0 },
                tests: []
            };

            const tests = [
                { name: 'Local Storage', fn: () => this.testLocalStorage(packageName) },
                { name: 'Backup Configuration', fn: () => this.testBackupEnabled(packageName) },
                { name: 'Log Analysis', fn: () => this.testLogcat(packageName) },
                { name: 'Exported Components', fn: () => this.testExportedComponents(packageName) },
                { name: 'Deep Links', fn: () => this.testDeepLinks(packageName) },
                { name: 'WebView Security', fn: () => this.testWebViewConfig(packageName) },
                { name: 'Root Detection', fn: () => this.testRootDetection() },
                { name: 'Debuggable Check', fn: () => this.testDebuggable(packageName) },
                { name: 'Emulator Detection', fn: () => this.testEmulatorDetection() },
                { name: 'SDK Version', fn: () => this.testMinSdkVersion(packageName) },
                { name: 'APK Signature', fn: () => this.testApkSignature(packageName) },
                { name: 'Network Security', fn: () => this.testNetworkSecurity(packageName) },
                { name: 'Auth Storage', fn: () => this.testAuthStorage(packageName) },
                { name: 'Permissions', fn: () => this.testPermissions(packageName) }
            ];

            for (let i = 0; i < tests.length; i++) {
                if (onProgress) onProgress(tests[i].name, i + 1, tests.length);
                
                try {
                    const result = await tests[i].fn();
                    allResults.tests.push(result);
                    allResults.summary[result.status]++;
                } catch (e) {
                    allResults.tests.push({
                        id: 'ERROR',
                        title: tests[i].name,
                        status: 'error',
                        error: e.message
                    });
                    allResults.summary.error++;
                }
            }

            return allResults;
        }
    }

    global.SecurityAuditor = SecurityAuditor;
})(window);

/** @preserve @author Sandeep Wawdane @license MIT */
(function(global) {
    'use strict';

    const DEBUG = false;
    const BUILD_ID = 'U2FuZGVlcFc=';
    function log(...args) { if (DEBUG) console.log('[ADB]', ...args); }
    function logError(...args) { console.error('[ADB ERROR]', ...args); }

    const ADB = {
        VERSION: 0x01000001,
        MAX_PAYLOAD: 256 * 1024,
        CMD_CNXN: 0x4e584e43,
        CMD_AUTH: 0x48545541,
        CMD_OPEN: 0x4e45504f,
        CMD_OKAY: 0x59414b4f,
        CMD_CLSE: 0x45534c43,
        CMD_WRTE: 0x45545257,
        AUTH_TOKEN: 1,
        AUTH_SIGNATURE: 2,
        AUTH_RSAPUBLICKEY: 3,
    };

    function cmdName(cmd) {
        const names = {
            [ADB.CMD_CNXN]: 'CNXN',
            [ADB.CMD_AUTH]: 'AUTH',
            [ADB.CMD_OPEN]: 'OPEN',
            [ADB.CMD_OKAY]: 'OKAY',
            [ADB.CMD_CLSE]: 'CLSE',
            [ADB.CMD_WRTE]: 'WRTE'
        };
        return names[cmd] || `0x${cmd.toString(16)}`;
    }

    const ErrorType = {
        CONNECTION_LOST: 'CONNECTION_LOST',
        DEVICE_BUSY: 'DEVICE_BUSY',
        PERMISSION_DENIED: 'PERMISSION_DENIED',
        TIMEOUT: 'TIMEOUT',
        PROTOCOL_ERROR: 'PROTOCOL_ERROR',
        NOT_FOUND: 'NOT_FOUND',
        UNKNOWN: 'UNKNOWN'
    };

    class ADBError extends Error {
        constructor(message, type = ErrorType.UNKNOWN, recoverable = false) {
            super(message);
            this.name = 'ADBError';
            this.type = type;
            this.recoverable = recoverable;
        }

        getUserMessage() {
            switch (this.type) {
                case ErrorType.CONNECTION_LOST:
                    return 'Connection lost. Your device may have gone to sleep, been unplugged, or you switched tabs. Please click "Reconnect" to continue.';
                case ErrorType.DEVICE_BUSY:
                    return 'Device is busy. Close any other ADB connections (like Android Studio or Chrome DevTools) and try again.';
                case ErrorType.PERMISSION_DENIED:
                    return 'Access denied. Check if USB debugging is still enabled and authorized on your device.';
                case ErrorType.TIMEOUT:
                    return 'Operation timed out. Your device may be slow to respond. Try again.';
                case ErrorType.PROTOCOL_ERROR:
                    return 'Communication error. Please disconnect and reconnect your device.';
                case ErrorType.NOT_FOUND:
                    return this.message;
                default:
                    return this.message;
            }
        }
    }

    const USB_FILTER = { classCode: 0xFF, subclassCode: 0x42, protocolCode: 0x01 };
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    function checksum(data) {
        let sum = 0;
        for (let i = 0; i < data.length; i++) sum = (sum + data[i]) >>> 0;
        return sum;
    }

    function makePacket(cmd, arg0, arg1, payload = new Uint8Array(0)) {
        const header = new Uint8Array(24);
        const v = new DataView(header.buffer);
        v.setUint32(0, cmd, true);
        v.setUint32(4, arg0, true);
        v.setUint32(8, arg1, true);
        v.setUint32(12, payload.length, true);
        v.setUint32(16, checksum(payload), true);
        v.setUint32(20, (cmd ^ 0xFFFFFFFF) >>> 0, true);
        return { header, payload };
    }

    function parseHeader(data) {
        const v = new DataView(data.buffer, data.byteOffset, 24);
        return {
            cmd: v.getUint32(0, true),
            arg0: v.getUint32(4, true),
            arg1: v.getUint32(8, true),
            len: v.getUint32(12, true),
            check: v.getUint32(16, true),
            magic: v.getUint32(20, true)
        };
    }

    function syncId(s) {
        return s.charCodeAt(0) | (s.charCodeAt(1) << 8) | (s.charCodeAt(2) << 16) | (s.charCodeAt(3) << 24);
    }

    function syncIdStr(id) {
        return String.fromCharCode(id & 0xFF, (id >> 8) & 0xFF, (id >> 16) & 0xFF, (id >> 24) & 0xFF);
    }

    class CredentialStore {
        constructor() {
            this.dbName = 'ADBauditorDB';
            this.storeName = 'keys';
        }

        async open() {
            return new Promise((resolve, reject) => {
                const req = indexedDB.open(this.dbName, 1);
                req.onerror = () => reject(req.error);
                req.onupgradeneeded = () => req.result.createObjectStore(this.storeName, { autoIncrement: true });
                req.onsuccess = () => resolve(req.result);
            });
        }

        async generateKey() {
            log('Generating new RSA key pair');
            const keyPair = await crypto.subtle.generateKey(
                { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' },
                true, ['sign']
            );
            const pkcs8 = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
            const keyBuffer = new Uint8Array(pkcs8);
            
            const db = await this.open();
            await new Promise((resolve, reject) => {
                const tx = db.transaction(this.storeName, 'readwrite');
                tx.objectStore(this.storeName).add(keyBuffer);
                tx.oncomplete = () => { db.close(); resolve(); };
                tx.onerror = () => reject(tx.error);
            });
            log('New key saved to IndexedDB');
            return { buffer: keyBuffer, privateKey: keyPair.privateKey };
        }

        async getKeys() {
            const db = await this.open();
            return new Promise((resolve, reject) => {
                const tx = db.transaction(this.storeName, 'readonly');
                const req = tx.objectStore(this.storeName).getAll();
                req.onsuccess = () => {
                    log(`Found ${req.result?.length || 0} stored keys`);
                    resolve(req.result || []);
                };
                tx.oncomplete = () => db.close();
                tx.onerror = () => reject(tx.error);
            });
        }

        async importKey(buf) {
            return crypto.subtle.importKey('pkcs8', buf, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-1' }, false, ['sign']);
        }
    }

    function generatePublicKey(privKeyBuf) {
        const n = privKeyBuf.slice(38, 38 + 256);
        const pubKey = new Uint8Array(4 + 4 + 256 + 256 + 4);
        const v = new DataView(pubKey.buffer);
        v.setUint32(0, 64, true);
        v.setInt32(4, 0, true);
        for (let i = 0; i < 256; i++) pubKey[8 + i] = n[255 - i];
        v.setUint32(8 + 256 + 256, 65537, true);
        return btoa(String.fromCharCode(...pubKey));
    }

    class USBWatcher {
        constructor(callback) {
            this.callback = callback;
            this.disposed = false;
            
            if (navigator.usb) {
                navigator.usb.addEventListener('connect', this.handleConnect);
                navigator.usb.addEventListener('disconnect', this.handleDisconnect);
                log('USB Watcher initialized');
            }
        }

        handleConnect = (event) => {
            if (this.disposed) return;
            log('USB device connected:', event.device.serialNumber);
            this.callback('connect', event.device);
        }

        handleDisconnect = (event) => {
            if (this.disposed) return;
            log('USB device disconnected:', event.device.serialNumber);
            this.callback('disconnect', event.device);
        }

        dispose() {
            this.disposed = true;
            if (navigator.usb) {
                navigator.usb.removeEventListener('connect', this.handleConnect);
                navigator.usb.removeEventListener('disconnect', this.handleDisconnect);
            }
            log('USB Watcher disposed');
        }
    }


    class DeviceDescriptor {
        constructor(type, serial, name) {
            this.type = type;
            this.serial = serial;
            this.name = name || serial;
            this.lastConnected = null;
        }

        get displayName() {
            return this.name ? `${this.serial} (${this.name})` : this.serial;
        }

        toJSON() {
            return {
                type: this.type,
                serial: this.serial,
                name: this.name,
                lastConnected: this.lastConnected
            };
        }
    }

    class USBDeviceDescriptor extends DeviceDescriptor {
        constructor(usbDevice) {
            super('usb', usbDevice.serialNumber, usbDevice.productName);
            this.usbDevice = usbDevice;
        }

        get displayName() {
            const name = this.usbDevice.productName || 'USB Device';
            return `${this.serial} (${name})`;
        }
    }

    class WebSocketDeviceDescriptor extends DeviceDescriptor {
        constructor(address, name) {
            super('websocket', address, name || 'WebSocket');
            this.address = address;
        }
    }

    class TCPDeviceDescriptor extends DeviceDescriptor {
        constructor(host, port, name) {
            super('tcp', `${host}:${port}`, name || 'TCP/ADB');
            this.host = host;
            this.port = port;
        }
    }

    class DeviceManager {
        constructor() {
            this.devices = new Map();
            this.activeConnection = null;
            this.activeDevice = null;
            this.watcher = null;
            this.listeners = new Set();
            
            this.loadSavedDevices();
        }

        static isWebUSBSupported() {
            return !!navigator.usb;
        }

        static isTCPSupported() {
            return typeof navigator.openTCPSocket === 'function';
        }

        addEventListener(callback) {
            this.listeners.add(callback);
            return () => this.listeners.delete(callback);
        }

        emit(event, data) {
            for (const listener of this.listeners) {
                try {
                    listener(event, data);
                } catch (e) {
                    logError('Event listener error:', e);
                }
            }
        }

        startWatching() {
            if (this.watcher) return;
            
            this.watcher = new USBWatcher((event, usbDevice) => {
                if (event === 'connect') {
                    const descriptor = new USBDeviceDescriptor(usbDevice);
                    this.devices.set(descriptor.serial, descriptor);
                    this.emit('deviceAdded', descriptor);
                    this.emit('devicesChanged', this.getDeviceList());
                } else if (event === 'disconnect') {
                    const serial = usbDevice.serialNumber;
                    if (this.activeDevice?.serial === serial) {
                        this.emit('activeDeviceDisconnected', this.activeDevice);
                        this.activeDevice = null;
                        this.activeConnection = null;
                    }
                    this.emit('deviceRemoved', { serial });
                    this.emit('devicesChanged', this.getDeviceList());
                }
            });
        }

        stopWatching() {
            if (this.watcher) {
                this.watcher.dispose();
                this.watcher = null;
            }
        }

        async refreshUSBDevices() {
            if (!navigator.usb) return [];
            
            try {
                const usbDevices = await navigator.usb.getDevices();
                log(`Found ${usbDevices.length} paired USB devices`);
                
                for (const [serial, descriptor] of this.devices) {
                    if (descriptor.type === 'usb') {
                        const stillPresent = usbDevices.some(d => 
                            d.serialNumber === serial || 
                            (!d.serialNumber && !serial)
                        );
                        if (!stillPresent) {
                            this.devices.delete(serial);
                            log('Removed disconnected USB device:', serial);
                        }
                    }
                }
                
                const descriptors = [];
                for (const usbDevice of usbDevices) {
                    const serial = usbDevice.serialNumber || 
                        `usb-${usbDevice.vendorId}-${usbDevice.productId}`;
                    
                    const descriptor = new USBDeviceDescriptor(usbDevice);
                    descriptor.serial = serial;
                    this.devices.set(serial, descriptor);
                    descriptors.push(descriptor);
                    log('Updated USB device:', serial, '- Product:', usbDevice.productName);
                }
                
                this.emit('devicesChanged', this.getDeviceList());
                
                return descriptors;
            } catch (e) {
                logError('Failed to get USB devices:', e);
                return [];
            }
        }

        async requestUSBDevice() {
            if (!navigator.usb) {
                throw new ADBError('WebUSB not supported', ErrorType.UNKNOWN);
            }

            try {
                const usbDevice = await navigator.usb.requestDevice({
                    filters: [USB_FILTER]
                });
                
                const descriptor = new USBDeviceDescriptor(usbDevice);
                this.devices.set(descriptor.serial, descriptor);
                this.emit('deviceAdded', descriptor);
                this.emit('devicesChanged', this.getDeviceList());
                
                log('New USB device paired:', descriptor.serial);
                return descriptor;
            } catch (e) {
                if (e.name === 'NotFoundError') {
                    throw new ADBError('No device selected', ErrorType.NOT_FOUND);
                }
                throw new ADBError('USB access failed: ' + e.message, ErrorType.PERMISSION_DENIED);
            }
        }

        addWebSocketDevice(address, name) {
            const descriptor = new WebSocketDeviceDescriptor(address, name);
            this.devices.set(descriptor.serial, descriptor);
            this.saveDevices();
            this.emit('deviceAdded', descriptor);
            this.emit('devicesChanged', this.getDeviceList());
            return descriptor;
        }

        addTCPDevice(host, port, name) {
            const descriptor = new TCPDeviceDescriptor(host, port, name);
            this.devices.set(descriptor.serial, descriptor);
            this.saveDevices();
            this.emit('deviceAdded', descriptor);
            this.emit('devicesChanged', this.getDeviceList());
            return descriptor;
        }

        removeDevice(serial) {
            const device = this.devices.get(serial);
            if (device) {
                this.devices.delete(serial);
                if (device.type !== 'usb') {
                    this.saveDevices();
                }
                this.emit('deviceRemoved', device);
                this.emit('devicesChanged', this.getDeviceList());
            }
        }

        getDevice(serial) {
            return this.devices.get(serial);
        }

        getDeviceList() {
            return Array.from(this.devices.values());
        }

        getDevicesByType() {
            const usb = [];
            const websocket = [];
            const tcp = [];
            
            for (const device of this.devices.values()) {
                switch (device.type) {
                    case 'usb': usb.push(device); break;
                    case 'websocket': websocket.push(device); break;
                    case 'tcp': tcp.push(device); break;
                }
            }
            
            return { usb, websocket, tcp };
        }

        saveDevices() {
            const toSave = {
                websocket: [],
                tcp: []
            };
            
            for (const device of this.devices.values()) {
                if (device.type === 'websocket') {
                    toSave.websocket.push({
                        address: device.address,
                        name: device.name
                    });
                } else if (device.type === 'tcp') {
                    toSave.tcp.push({
                        host: device.host,
                        port: device.port,
                        name: device.name
                    });
                }
            }
            
            localStorage.setItem('adb-devices', JSON.stringify(toSave));
            log('Saved devices to localStorage');
        }

        loadSavedDevices() {
            try {
                const saved = localStorage.getItem('adb-devices');
                if (!saved) return;
                
                const data = JSON.parse(saved);
                
                if (data.websocket) {
                    for (const ws of data.websocket) {
                        const descriptor = new WebSocketDeviceDescriptor(ws.address, ws.name);
                        this.devices.set(descriptor.serial, descriptor);
                    }
                }
                
                if (data.tcp) {
                    for (const tcp of data.tcp) {
                        const descriptor = new TCPDeviceDescriptor(tcp.host, tcp.port, tcp.name);
                        this.devices.set(descriptor.serial, descriptor);
                    }
                }
                
                log('Loaded saved devices from localStorage');
            } catch (e) {
                logError('Failed to load saved devices:', e);
            }
        }

        async initialize() {
            this.startWatching();
            
            await this.refreshUSBDevices();
            
            this.emit('devicesChanged', this.getDeviceList());
            
            log('Device Manager initialized');
        }

        dispose() {
            this.stopWatching();
            this.devices.clear();
            this.listeners.clear();
        }
    }

    class ADBConnection {
        constructor() {
            this.device = null;
            this.deviceDescriptor = null;
            this.inEndpoint = null;
            this.outEndpoint = null;
            this.connected = false;
            this.localId = 1;
            this.credentials = new CredentialStore();
            this.maxPayload = ADB.MAX_PAYLOAD;
            
            this.readBuffer = new Uint8Array(0);
            this.pendingPackets = new Map();
            
            this.lastActivity = Date.now();
            this.connectionLost = false;
            
            this.onDisconnect = null;
            this.onError = null;
            
            this._disconnectedResolve = null;
            this._disconnectedReject = null;
            this.disconnected = new Promise((resolve, reject) => {
                this._disconnectedResolve = resolve;
                this._disconnectedReject = reject;
            });
        }

        async connectToDevice(descriptor) {
            if (descriptor.type !== 'usb') {
                throw new ADBError('Only USB devices are currently supported', ErrorType.UNKNOWN);
            }
            
            this.deviceDescriptor = descriptor;
            this.device = descriptor.usbDevice;
            
            await this.openDevice();
            await this.authenticate();
            
            descriptor.lastConnected = new Date();
            
            return true;
        }

        async requestDevice() {
            if (!navigator.usb) {
                throw new ADBError('WebUSB not supported. Use Chrome, Edge, or Opera browser.', ErrorType.UNKNOWN);
            }
            try {
                this.device = await navigator.usb.requestDevice({ filters: [USB_FILTER] });
                log('Device selected:', this.device.productName);
                return this.device;
            } catch (e) {
                if (e.name === 'NotFoundError') {
                    throw new ADBError('No device selected. Click Connect and select your Android device.', ErrorType.NOT_FOUND);
                }
                throw new ADBError('USB access failed: ' + e.message, ErrorType.PERMISSION_DENIED);
            }
        }

        findInterface() {
            for (const cfg of this.device.configurations) {
                for (const iface of cfg.interfaces) {
                    for (const alt of iface.alternates) {
                        if (alt.interfaceClass === USB_FILTER.classCode &&
                            alt.interfaceSubclass === USB_FILTER.subclassCode &&
                            alt.interfaceProtocol === USB_FILTER.protocolCode) {
                            let inEp = null, outEp = null;
                            for (const ep of alt.endpoints) {
                                if (ep.type === 'bulk') {
                                    if (ep.direction === 'in') inEp = ep;
                                    else outEp = ep;
                                }
                            }
                            if (inEp && outEp) return { cfg, iface, alt, inEp, outEp };
                        }
                    }
                }
            }
            return null;
        }

        async openDevice() {
            try {
                await this.device.open();
                const info = this.findInterface();
                if (!info) { 
                    await this.device.close(); 
                    throw new ADBError('No ADB interface found. Enable USB debugging on your device.', ErrorType.NOT_FOUND);
                }
                
                if (this.device.configuration?.configurationValue !== info.cfg.configurationValue) {
                    await this.device.selectConfiguration(info.cfg.configurationValue);
                }
                await this.device.claimInterface(info.iface.interfaceNumber);
                this.inEndpoint = info.inEp;
                this.outEndpoint = info.outEp;
                log('USB interface claimed successfully');
            } catch (e) {
                if (e instanceof ADBError) throw e;
                if (e.message?.includes('claimed')) {
                    throw new ADBError('Device already in use. Close Chrome DevTools, Android Studio, or other ADB connections.', ErrorType.DEVICE_BUSY);
                }
                throw new ADBError('Failed to open device: ' + e.message, ErrorType.UNKNOWN);
            }
        }

        async send(pkt) {
            if (this.connectionLost) {
                throw new ADBError('Connection lost', ErrorType.CONNECTION_LOST, true);
            }
            try {
                await this.device.transferOut(this.outEndpoint.endpointNumber, pkt.header);
                if (pkt.payload.length > 0) {
                    await this.device.transferOut(this.outEndpoint.endpointNumber, pkt.payload);
                }
                this.lastActivity = Date.now();
            } catch (e) {
                logError('Send failed:', e);
                this.markDisconnected('USB write failed: ' + e.message);
                throw new ADBError('Connection lost during send', ErrorType.CONNECTION_LOST, true);
            }
        }

        markDisconnected(reason = 'Connection lost') {
            if (!this.connectionLost) {
                log('Marking connection as lost:', reason);
                this.connectionLost = true;
                this.connected = false;
                
                if (this._disconnectedResolve) {
                    this._disconnectedResolve(reason);
                }
                
                if (this.onDisconnect) {
                    this.onDisconnect(reason);
                }
            }
        }

        async readExact(len, timeout = 30000) {
            const startTime = Date.now();
            
            while (this.readBuffer.length < len) {
                if (this.connectionLost) {
                    throw new ADBError('Connection lost', ErrorType.CONNECTION_LOST, true);
                }
                
                if (Date.now() - startTime > timeout) {
                    throw new ADBError('Read timeout - device not responding', ErrorType.TIMEOUT, true);
                }
                
                try {
                    const result = await this.device.transferIn(
                        this.inEndpoint.endpointNumber, 
                        this.inEndpoint.packetSize || 512
                    );
                    if (result.data && result.data.byteLength > 0) {
                        const newData = new Uint8Array(result.data.buffer);
                        const combined = new Uint8Array(this.readBuffer.length + newData.length);
                        combined.set(this.readBuffer, 0);
                        combined.set(newData, this.readBuffer.length);
                        this.readBuffer = combined;
                        this.lastActivity = Date.now();
                    }
                } catch (e) {
                    logError('Read failed:', e);
                    this.markDisconnected('USB read failed: ' + e.message);
                    throw new ADBError('Connection lost during read', ErrorType.CONNECTION_LOST, true);
                }
            }
            const data = this.readBuffer.slice(0, len);
            this.readBuffer = this.readBuffer.slice(len);
            return data;
        }

        async recvPacket() {
            const headerData = await this.readExact(24);
            const header = parseHeader(headerData);
            
            const expectedMagic = (header.cmd ^ 0xFFFFFFFF) >>> 0;
            if (header.magic !== expectedMagic) {
                logError(`Invalid packet magic! cmd=${cmdName(header.cmd)} magic=${header.magic.toString(16)} expected=${expectedMagic.toString(16)}`);
                this.readBuffer = new Uint8Array(0);
                this.markDisconnected('Invalid packet received - connection may be stale');
                throw new ADBError('Invalid packet - connection lost', ErrorType.CONNECTION_LOST, true);
            }
            
            let payload = new Uint8Array(0);
            if (header.len > 0) {
                if (header.len > ADB.MAX_PAYLOAD) {
                    throw new ADBError(`Payload too large: ${header.len}`, ErrorType.PROTOCOL_ERROR);
                }
                payload = await this.readExact(header.len);
            }
            
            log(`<< ${cmdName(header.cmd)} arg0=${header.arg0} arg1=${header.arg1} len=${header.len}`);
            return { ...header, payload };
        }

        async waitPacket(localId, expectedCmds, timeout = 30000) {
            const queue = this.pendingPackets.get(localId) || [];
            for (let i = 0; i < queue.length; i++) {
                if (expectedCmds.includes(queue[i].cmd)) {
                    return queue.splice(i, 1)[0];
                }
            }

            const startTime = Date.now();
            while (true) {
                if (Date.now() - startTime > timeout) {
                    throw new ADBError('Operation timed out', ErrorType.TIMEOUT, true);
                }
                
                const pkt = await this.recvPacket();
                
                if (pkt.arg1 === localId && expectedCmds.includes(pkt.cmd)) {
                    return pkt;
                }
                
                if (pkt.arg1 === localId && pkt.cmd === ADB.CMD_CLSE) {
                    return pkt;
                }

                const targetId = pkt.arg1;
                if (!this.pendingPackets.has(targetId)) {
                    this.pendingPackets.set(targetId, []);
                }
                this.pendingPackets.get(targetId).push(pkt);
            }
        }

        async authenticate() {
            this.readBuffer = new Uint8Array(0);
            this.pendingPackets.clear();
            this.connectionLost = false;
            this.localId = 1;

            const identity = encoder.encode('host::features=shell_v2,cmd,stat_v2,ls_v2,fixed_push_mkdir,abb');
            log('>> CNXN');
            await this.send(makePacket(ADB.CMD_CNXN, ADB.VERSION, this.maxPayload, identity));

            const authTimeout = 60000;
            const startTime = Date.now();
            
            while (true) {
                if (Date.now() - startTime > authTimeout) {
                    throw new ADBError('Connection timeout. Accept the USB debugging prompt on your device.', ErrorType.TIMEOUT);
                }
                
                const pkt = await this.recvPacket();
                if (pkt.cmd === ADB.CMD_CNXN) {
                    this.maxPayload = Math.min(this.maxPayload, pkt.arg1);
                    this.connected = true;
                    this.banner = decoder.decode(pkt.payload);
                    log('Connected! Banner:', this.banner);
                    return true;
                } else if (pkt.cmd === ADB.CMD_AUTH) {
                    await this.handleAuth(pkt);
                }
            }
        }

        async connect() {
            if (!this.device) await this.requestDevice();
            await this.openDevice();
            return this.authenticate();
        }

        async handleAuth(pkt) {
            if (pkt.arg0 !== ADB.AUTH_TOKEN) return;
            let token = pkt.payload;
            log('Auth requested, token length:', token.length);

            const keys = await this.credentials.getKeys();
            for (const keyBuf of keys) {
                try {
                    const privKey = await this.credentials.importKey(keyBuf);
                    const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privKey, token);
                    log('>> AUTH_SIGNATURE');
                    await this.send(makePacket(ADB.CMD_AUTH, ADB.AUTH_SIGNATURE, 0, new Uint8Array(sig)));
                    
                    const resp = await this.recvPacket();
                    if (resp.cmd === ADB.CMD_CNXN) {
                        this.maxPayload = Math.min(this.maxPayload, resp.arg1);
                        this.connected = true;
                        this.banner = decoder.decode(resp.payload);
                        log('Auth success with stored key');
                        return;
                    }
                    if (resp.cmd === ADB.CMD_AUTH && resp.arg0 === ADB.AUTH_TOKEN) {
                        token = resp.payload;
                        log('Key rejected, got new token');
                    }
                } catch (e) {
                    log('Key failed:', e.message);
                }
            }

            log('Generating new key and sending public key');
            const newKey = await this.credentials.generateKey();
            const pubKeyB64 = generatePublicKey(newKey.buffer);
            log('>> AUTH_RSAPUBLICKEY');
            await this.send(makePacket(ADB.CMD_AUTH, ADB.AUTH_RSAPUBLICKEY, 0, 
                encoder.encode(pubKeyB64 + ' ADBauditor@browser\0')));
        }

        async openSocket(service) {
            const localId = this.localId++;
            this.pendingPackets.set(localId, []);
            
            log(`>> OPEN[${localId}] ${service}`);
            await this.send(makePacket(ADB.CMD_OPEN, localId, 0, encoder.encode(service + '\0')));
            
            const pkt = await this.waitPacket(localId, [ADB.CMD_OKAY, ADB.CMD_CLSE]);
            if (pkt.cmd === ADB.CMD_CLSE) {
                this.pendingPackets.delete(localId);
                throw new ADBError(`Service unavailable: ${service}`, ErrorType.PERMISSION_DENIED);
            }
            
            log(`Socket opened: local=${localId} remote=${pkt.arg0}`);
            return { localId, remoteId: pkt.arg0 };
        }

        async writeSocket(sock, data) {
            await this.send(makePacket(ADB.CMD_WRTE, sock.localId, sock.remoteId, data));
            const pkt = await this.waitPacket(sock.localId, [ADB.CMD_OKAY, ADB.CMD_CLSE]);
            return pkt.cmd === ADB.CMD_OKAY;
        }

        async readSocket(sock) {
            const pkt = await this.waitPacket(sock.localId, [ADB.CMD_WRTE, ADB.CMD_CLSE]);
            if (pkt.cmd === ADB.CMD_CLSE) return null;
            await this.send(makePacket(ADB.CMD_OKAY, sock.localId, sock.remoteId));
            return pkt.payload;
        }

        async closeSocket(sock) {
            try {
                await this.send(makePacket(ADB.CMD_CLSE, sock.localId, sock.remoteId));
            } catch (e) { /* ignore */ }
            this.pendingPackets.delete(sock.localId);
        }

        async shell(cmd, timeout = 30000) {
            log('Shell:', cmd);
            const sock = await this.openSocket(`shell:${cmd}`);
            let output = '';
            try {
                while (true) {
                    const data = await this.readSocket(sock);
                    if (!data) break;
                    output += decoder.decode(data);
                }
            } finally {
                await this.closeSocket(sock);
            }
            return output.trim();
        }

        async listDirectory(path) {
            log('List directory:', path);
            const sock = await this.openSocket('sync:');
            const sync = new SyncSession(this, sock);
            try {
                return await sync.list(path);
            } finally {
                await this.closeSocket(sock);
            }
        }

        async pullFile(path, onProgress = null) {
            log('Pull file:', path);
            const sock = await this.openSocket('sync:');
            const sync = new SyncSession(this, sock);
            try {
                return await sync.pull(path, onProgress);
            } finally {
                await this.closeSocket(sock);
            }
        }

        async pushFile(path, data, mode = 0o644) {
            log('Push file:', path);
            const sock = await this.openSocket('sync:');
            const sync = new SyncSession(this, sock);
            try {
                return await sync.push(path, data, mode);
            } finally {
                await this.closeSocket(sock);
            }
        }

        async takeScreenshot() {
            log('Taking screenshot');
            const sock = await this.openSocket('shell:screencap -p');
            const chunks = [];
            try {
                while (true) {
                    const data = await this.readSocket(sock);
                    if (!data) break;
                    chunks.push(data);
                }
            } finally {
                await this.closeSocket(sock);
            }
            const total = chunks.reduce((s, c) => s + c.length, 0);
            log('Screenshot size:', total);
            const result = new Uint8Array(total);
            let off = 0;
            for (const c of chunks) { result.set(c, off); off += c.length; }
            return new Blob([result], { type: 'image/png' });
        }

        async getDeviceProps() {
            const props = {};
            const cmds = {
                model: 'getprop ro.product.model',
                brand: 'getprop ro.product.brand',
                device: 'getprop ro.product.device',
                androidVersion: 'getprop ro.build.version.release',
                sdkVersion: 'getprop ro.build.version.sdk',
                serial: 'getprop ro.serialno',
                buildId: 'getprop ro.build.id'
            };
            for (const [k, cmd] of Object.entries(cmds)) {
                try { props[k] = await this.shell(cmd); } catch { props[k] = 'Unknown'; }
            }
            try {
                const bat = await this.shell('dumpsys battery');
                const m = bat.match(/level:\s*(\d+)/);
                props.batteryLevel = m ? parseInt(m[1]) : null;
            } catch { props.batteryLevel = null; }
            return props;
        }

        async listPackages(includeSystem = false) {
            const flag = includeSystem ? '' : '-3';
            const out = await this.shell(`pm list packages ${flag}`);
            return out.split('\n').filter(l => l.startsWith('package:')).map(l => l.substring(8).trim()).filter(Boolean).sort();
        }

        async getApkPath(pkg) {
            log('Getting APK path for:', pkg);
            const out = await this.shell(`pm path ${pkg}`);
            log('pm path output:', out);
            const lines = out.split('\n').filter(l => l.startsWith('package:'));
            if (lines.length === 0) {
                throw new ADBError(`No APK found for package: ${pkg}`, ErrorType.NOT_FOUND);
            }
            const path = lines[0].substring(8).trim();
            log('APK path:', path);
            return path;
        }

        async pullApk(pkg, onProgress = null) {
            const path = await this.getApkPath(pkg);
            return this.pullFile(path, onProgress);
        }

        async disconnect() {
            log('Disconnecting');
            this.connected = false;
            this.connectionLost = true;
            if (this.device?.opened) {
                try { await this.device.close(); } catch {}
            }
            this.device = null;
            this.deviceDescriptor = null;
            this.pendingPackets.clear();
            this.readBuffer = new Uint8Array(0);
            
            if (this._disconnectedResolve) {
                this._disconnectedResolve('User disconnected');
            }
        }

        isConnected() {
            return this.connected && !this.connectionLost && this.device?.opened;
        }

        async ping() {
            try {
                await this.shell('echo ping');
                return true;
            } catch (e) {
                return false;
            }
        }

        getDeviceInfo() {
            if (!this.device) return null;
            return {
                serial: this.device.serialNumber,
                name: this.device.productName,
                manufacturer: this.device.manufacturerName,
                connected: this.isConnected(),
                banner: this.banner
            };
        }
    }

    class SyncSession {
        constructor(adb, sock) {
            this.adb = adb;
            this.sock = sock;
            this.buffer = new Uint8Array(0);
        }

        async writeCmd(id, arg) {
            const idVal = typeof id === 'string' ? syncId(id) : id;
            if (typeof arg === 'string') {
                const strBytes = encoder.encode(arg);
                const data = new Uint8Array(8 + strBytes.length);
                const v = new DataView(data.buffer);
                v.setUint32(0, idVal, true);
                v.setUint32(4, strBytes.length, true);
                data.set(strBytes, 8);
                await this.adb.writeSocket(this.sock, data);
            } else {
                const data = new Uint8Array(8);
                const v = new DataView(data.buffer);
                v.setUint32(0, idVal, true);
                v.setUint32(4, arg, true);
                await this.adb.writeSocket(this.sock, data);
            }
        }

        async readBytes(len) {
            while (this.buffer.length < len) {
                const data = await this.adb.readSocket(this.sock);
                if (!data) {
                    throw new ADBError('Sync connection closed unexpectedly', ErrorType.CONNECTION_LOST);
                }
                const combined = new Uint8Array(this.buffer.length + data.length);
                combined.set(this.buffer, 0);
                combined.set(data, this.buffer.length);
                this.buffer = combined;
            }
            const result = this.buffer.slice(0, len);
            this.buffer = this.buffer.slice(len);
            return result;
        }

        async list(path) {
            await this.writeCmd('LIST', path);
            const entries = [];
            
            while (true) {
                const idBytes = await this.readBytes(4);
                const idVal = new DataView(idBytes.buffer, idBytes.byteOffset).getUint32(0, true);
                const id = syncIdStr(idVal);
                
                if (id === 'DENT') {
                    const meta = await this.readBytes(16);
                    const mv = new DataView(meta.buffer, meta.byteOffset);
                    const mode = mv.getUint32(0, true);
                    const size = mv.getUint32(4, true);
                    const mtime = mv.getUint32(8, true);
                    const nameLen = mv.getUint32(12, true);
                    const nameBytes = await this.readBytes(nameLen);
                    const name = decoder.decode(nameBytes);
                    if (name !== '.' && name !== '..') {
                        entries.push({
                            name, mode, size,
                            mtime: new Date(mtime * 1000),
                            isDirectory: (mode & 0o040000) !== 0,
                            isFile: (mode & 0o100000) !== 0,
                            isLink: (mode & 0o120000) === 0o120000
                        });
                    }
                } else if (id === 'DONE') {
                    break;
                } else if (id === 'FAIL') {
                    const lenBytes = await this.readBytes(4);
                    const msgLen = new DataView(lenBytes.buffer, lenBytes.byteOffset).getUint32(0, true);
                    const msg = decoder.decode(await this.readBytes(msgLen));
                    throw new ADBError('Directory access denied: ' + msg, ErrorType.PERMISSION_DENIED);
                } else {
                    throw new ADBError('Unexpected sync response: ' + id, ErrorType.PROTOCOL_ERROR);
                }
            }
            
            log(`Listed ${entries.length} entries in ${path}`);
            return entries;
        }

        async pull(path, onProgress = null) {
            log('RECV:', path);
            await this.writeCmd('RECV', path);
            const chunks = [];
            let totalSize = 0;
            
            while (true) {
                const header = await this.readBytes(8);
                const hv = new DataView(header.buffer, header.byteOffset);
                const idVal = hv.getUint32(0, true);
                const len = hv.getUint32(4, true);
                const id = syncIdStr(idVal);
                
                if (id === 'DATA') {
                    const chunk = await this.readBytes(len);
                    chunks.push(chunk);
                    totalSize += len;
                    if (onProgress) onProgress(totalSize);
                } else if (id === 'DONE') {
                    log('Pull complete, total size:', totalSize);
                    break;
                } else if (id === 'FAIL') {
                    const msg = decoder.decode(await this.readBytes(len));
                    throw new ADBError('File read failed: ' + msg, ErrorType.PERMISSION_DENIED);
                } else {
                    throw new ADBError('Unexpected response: ' + id, ErrorType.PROTOCOL_ERROR);
                }
            }
            
            const result = new Uint8Array(totalSize);
            let off = 0;
            for (const c of chunks) { result.set(c, off); off += c.length; }
            return result;
        }

        async push(path, data, mode) {
            log('SEND:', path, 'size:', data.length);
            await this.writeCmd('SEND', `${path},${mode}`);
            
            const chunkSize = 64 * 1024;
            let off = 0;
            while (off < data.length) {
                const chunk = data.slice(off, off + chunkSize);
                const pkt = new Uint8Array(8 + chunk.length);
                const v = new DataView(pkt.buffer);
                v.setUint32(0, syncId('DATA'), true);
                v.setUint32(4, chunk.length, true);
                pkt.set(chunk, 8);
                await this.adb.writeSocket(this.sock, pkt);
                off += chunk.length;
            }
            
            const done = new Uint8Array(8);
            const dv = new DataView(done.buffer);
            dv.setUint32(0, syncId('DONE'), true);
            dv.setUint32(4, Math.floor(Date.now() / 1000), true);
            await this.adb.writeSocket(this.sock, done);
            
            const header = await this.readBytes(8);
            const hv = new DataView(header.buffer, header.byteOffset);
            const id = syncIdStr(hv.getUint32(0, true));
            const len = hv.getUint32(4, true);
            
            if (id === 'FAIL') {
                throw new ADBError('File write failed: ' + decoder.decode(await this.readBytes(len)), ErrorType.PERMISSION_DENIED);
            }
            
            log('Push complete');
            return true;
        }
    }

    global.ADBConnection = ADBConnection;
    global.ADBError = ADBError;
    global.ADBErrorType = ErrorType;
    global.DeviceManager = DeviceManager;
    global.USBWatcher = USBWatcher;
    global.USBDeviceDescriptor = USBDeviceDescriptor;
    global.WebSocketDeviceDescriptor = WebSocketDeviceDescriptor;
    global.TCPDeviceDescriptor = TCPDeviceDescriptor;
})(window);

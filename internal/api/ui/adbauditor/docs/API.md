# ADB Auditor API Documentation

## Overview

ADB Auditor uses the WebUSB API to communicate with Android devices through the ADB protocol. This document describes the internal API structure for developers who want to extend or modify the tool.

## Core Classes

### ADBConnection

Main class for managing ADB connections.

```javascript
const adb = new ADBConnection();
```

#### Methods

##### connect(deviceDescriptor)
Establishes connection to an Android device.

```javascript
await adb.connect(usbDeviceDescriptor);
```

##### disconnect()
Closes the current connection.

```javascript
await adb.disconnect();
```

##### shell(command)
Executes a shell command on the device.

```javascript
const output = await adb.shell('ls -la /sdcard');
```

##### pullFile(path)
Downloads a file from the device.

```javascript
const bytes = await adb.pullFile('/sdcard/file.txt');
```

##### pushFile(path, data, mode)
Uploads a file to the device.

```javascript
await adb.pushFile('/sdcard/file.txt', uint8Array, 0o644);
```

##### takeScreenshot()
Captures the device screen.

```javascript
const blob = await adb.takeScreenshot();
```

##### listPackages(includeSystem)
Lists installed packages.

```javascript
const packages = await adb.listPackages(false); // User apps only
const allPackages = await adb.listPackages(true); // Include system
```

##### pullApk(packageName)
Extracts APK file for a package.

```javascript
const apkBytes = await adb.pullApk('com.example.app');
```

### DeviceManager

Manages multiple device connections and USB events.

```javascript
const deviceManager = new DeviceManager();
```

#### Methods

##### getDeviceList()
Returns array of available devices.

##### addUSBDevice()
Prompts user to select a USB device.

##### refreshUSBDevices()
Updates the list of connected USB devices.

### USBWatcher

Monitors USB connect/disconnect events.

```javascript
const watcher = new USBWatcher();
watcher.onDeviceConnected = (device) => { ... };
watcher.onDeviceDisconnected = (device) => { ... };
watcher.start();
```

## Security Auditor Module

### SecurityAuditor

Performs automated security checks.

```javascript
const auditor = new SecurityAuditor(adb);
const results = await auditor.runFullAudit('com.example.app');
```

#### Audit Categories

- `localStorage` - SharedPreferences analysis
- `databases` - SQLite database inspection
- `files` - File permission checks
- `permissions` - App permission analysis
- `signatures` - Certificate validation

## Events

### Connection Events

```javascript
adb.onDisconnect = () => {
    console.log('Device disconnected');
};
```

### Progress Events

```javascript
adb.pullFile(path, (progress) => {
    console.log(`Downloaded: ${progress} bytes`);
});
```

## Error Handling

```javascript
try {
    await adb.connect(device);
} catch (error) {
    if (error.type === 'AUTH_FAILED') {
        // Handle authentication failure
    } else if (error.type === 'CONNECTION_LOST') {
        // Handle disconnection
    }
}
```

## Error Types

- `AUTH_FAILED` - Device rejected connection
- `CONNECTION_LOST` - USB connection interrupted
- `PERMISSION_DENIED` - Insufficient permissions
- `NOT_FOUND` - File or package not found
- `PROTOCOL_ERROR` - ADB protocol error

## Examples

### Full Workflow Example

```javascript
// Initialize
const adb = new ADBConnection();
const deviceManager = new DeviceManager();

// Connect
const devices = await deviceManager.addUSBDevice();
await adb.connect(devices[0]);

// Get device info
const props = await adb.getDeviceProps();
console.log(`Connected to: ${props.model}`);

// List apps
const apps = await adb.listPackages(false);

// Run shell command
const output = await adb.shell('pm list permissions -g');

// Disconnect
await adb.disconnect();
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on contributing to the API.

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

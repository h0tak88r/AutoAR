(() => {
  // Scan titles and descriptions. A scan shows its operator title when it has
  // one, otherwise "<Type> · <target>" (the raw target, e.g.
  // "global-subdomains", meant nothing on its own). Titles are edited here and
  // saved with PATCH /api/scans/:id. All values reach the DOM via esc() or
  // .value/.textContent, never raw innerHTML.
  const esc = (v) =>
    window.esc ? window.esc(v) : String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  const TARGET_LABEL = { 'global-subdomains': 'all subdomains', corpus: 'whole corpus' };

  function prettyScanTarget(target) {
    const t = String(target || '').trim();
    return TARGET_LABEL[t] || t || 'no target';
  }

  function scanTitle(s) {
    const name = String((s && (s.name || s.Name)) || '').trim();
    if (name) return name;
    const type = (s && (s.scan_type || s.ScanType)) || '';
    const label = typeof window.scanTypeLabel === 'function' ? window.scanTypeLabel(type) : type;
    return `${label || 'Scan'} · ${prettyScanTarget(s && (s.target || s.Target))}`;
  }

  const descOf = (s) => String((s && (s.description || s.Description)) || '').trim();

  // Applies title/description right after a launch (most launch endpoints
  // don't take them). The server holds them if the scan row isn't written yet.
  async function applyLaunchMeta(scanId, meta) {
    const body = {};
    if (meta && meta.name) body.name = meta.name;
    if (meta && meta.description) body.description = meta.description;
    if (!scanId || !Object.keys(body).length) return;
    try {
      await window.apiPatch(`/api/scans/${encodeURIComponent(scanId)}`, body);
    } catch (e) {
      window.showToast('error', 'Title not saved', e.message || String(e));
    }
  }

  // Title + description inputs shared by the launch forms.
  function launchMetaFields(prefix) {
    return `<div class="sm-launch-meta">
      <label class="ff-field"><span>Title (optional)</span>
        <input id="${prefix}-title" maxlength="120" placeholder="e.g. Smarty CVE-2026-82531 sweep" autocomplete="off"></label>
      <label class="ff-field"><span>Description (optional)</span>
        <textarea id="${prefix}-desc" rows="2" maxlength="2000" placeholder="Why this scan, what to look for"></textarea></label>
    </div>`;
  }
  function readLaunchMeta(prefix) {
    const v = (id) => String(document.getElementById(id)?.value || '').trim();
    return { name: v(prefix + '-title'), description: v(prefix + '-desc') };
  }

  function editScanMeta(scan, onSaved) {
    const scanId = scan && (scan.scan_id || scan.ScanID);
    if (!scanId) return;
    document.getElementById('scan-meta-modal')?.remove();
    const opener = document.activeElement;
    const overlay = document.createElement('div');
    overlay.id = 'scan-meta-modal';
    overlay.className = 'ff-overlay';
    overlay.innerHTML = `
      <form class="ff-dialog sm-dialog" role="dialog" aria-modal="true" aria-labelledby="sm-title" novalidate>
        <div class="ff-head"><h2 id="sm-title">Edit scan</h2>
          <button type="button" class="tri-x" data-sm-close aria-label="Close">×</button></div>
        <div class="ff-body sm-body">
          <label class="ff-field ff-wide"><span>Title</span>
            <input name="name" maxlength="120" autocomplete="off"></label>
          <label class="ff-field ff-wide"><span>Description</span>
            <textarea name="description" rows="4" maxlength="2000" placeholder="Why this scan, what it covers, what to look for"></textarea></label>
          <div class="sm-hint ff-wide">Leave the title empty to show the default: <b></b></div>
          <div class="ff-err" role="alert" hidden></div>
        </div>
        <div class="ff-foot">
          <button type="button" class="btn btn-ghost" data-sm-close>Cancel</button>
          <button type="submit" class="btn btn-primary">Save</button>
        </div>
      </form>`;
    const form = overlay.querySelector('form');
    form.elements.name.value = String(scan.name || scan.Name || '');
    form.elements.description.value = descOf(scan);
    const fallback = scanTitle({ ...scan, name: '', Name: '' });
    overlay.querySelector('.sm-hint b').textContent = fallback;
    form.elements.name.placeholder = fallback;

    const close = () => {
      document.removeEventListener('keydown', onKey, true);
      overlay.remove();
      if (opener && opener.focus && document.contains(opener)) opener.focus();
    };
    function onKey(e) { if (e.key === 'Escape') { e.stopPropagation(); close(); } }
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay || e.target.closest('[data-sm-close]')) close();
    });
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = form.querySelector('button[type="submit"]');
      const err = overlay.querySelector('.ff-err');
      btn.disabled = true;
      btn.textContent = 'Saving…';
      try {
        const res = await window.apiPatch(`/api/scans/${encodeURIComponent(scanId)}`, {
          name: form.elements.name.value, description: form.elements.description.value,
        });
        const updated = { ...scan, name: res.name ?? '', description: res.description ?? '' };
        window.showToast('success', 'Scan updated', scanTitle(updated));
        close();
        if (typeof onSaved === 'function') onSaved(updated);
      } catch (ex) {
        err.textContent = ex.message || String(ex);
        err.hidden = false;
        btn.disabled = false;
        btn.textContent = 'Save';
      }
    });
    document.addEventListener('keydown', onKey, true);
    document.body.appendChild(overlay);
    form.elements.name.focus();
    form.elements.name.select();
  }

  window.scanTitle = scanTitle;
  window.prettyScanTarget = prettyScanTarget;
  window.scanDescription = descOf;
  window.editScanMeta = editScanMeta;
  window.applyLaunchMeta = applyLaunchMeta;
  window.ScanMeta = { scanTitle, prettyScanTarget, descOf, editScanMeta, applyLaunchMeta, launchMetaFields, readLaunchMeta };
})();

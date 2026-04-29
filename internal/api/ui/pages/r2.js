(() => {
  const { esc, escAttr, fmtDate, fmtSize, fileIcon, emptyState } = window;

  async function loadR2(prefix = '') {
    window.state.r2.prefix = prefix;
    const el = document.getElementById('r2-loading');
    if (el) el.style.display = 'block';
    try {
      const data = await window.apiFetch(`/api/r2/files?prefix=${encodeURIComponent(prefix)}`);
      window.state.r2 = { prefix, dirs: data.dirs || [], files: data.files || [] };
      if (window.state.view === 'r2') renderR2();
    } catch (e) {
      window.showToast('error', 'R2 Error', e.message);
    } finally {
      if (el) el.style.display = 'none';
    }
  }

  function renderR2() {
    const treeEl = document.getElementById('r2-tree-list');
    const filesEl = document.getElementById('r2-files-list');
    const pathEl = document.getElementById('r2-path');
    if (!treeEl || !filesEl) return;

    const { prefix, dirs, files } = window.state.r2;
    if (pathEl) pathEl.textContent = '/' + (prefix || '');

    // Tree — root always + current dirs
    let treeHtml = `<div class="r2-tree-item ${!prefix ? 'active' : ''}">
      <span class="r2-tree-nav" onclick="window.MonitorPage ? window.MonitorPage.loadR2('') : window.loadR2('')">📦</span>
      <span class="r2-tree-nav r2-tree-label" onclick="window.MonitorPage ? window.MonitorPage.loadR2('') : window.loadR2('')">root</span>
    </div>`;
    // Wait, it should be R2Page.loadR2. I'll use window.R2Page.loadR2.
    
    treeHtml = `<div class="r2-tree-item ${!prefix ? 'active' : ''}">
      <span class="r2-tree-nav" onclick="window.R2Page.loadR2('')">📦</span>
      <span class="r2-tree-nav r2-tree-label" onclick="window.R2Page.loadR2('')">root</span>
    </div>`;

    (dirs || []).forEach(d => {
      const name = d.replace(prefix, '').replace(/\/$/, '');
      treeHtml += `<div class="r2-tree-item" data-r2-prefix="${escAttr(d)}">
        <span class="r2-tree-nav" onclick='window.R2Page.loadR2(${JSON.stringify(d)})'>📁</span>
        <span class="r2-tree-nav r2-tree-label" onclick='window.R2Page.loadR2(${JSON.stringify(d)})'>${esc(name || d)}</span>
        <button type="button" class="r2-row-action" title="Delete folder" aria-label="Delete folder" onclick='event.stopPropagation();window.R2Page.r2DeletePrefixInteractive(${JSON.stringify(d)})'>🗑</button>
      </div>`;
    });
    treeEl.innerHTML = treeHtml;

    // Files list
    if (!files.length && !dirs.length) {
      filesEl.innerHTML = emptyState('📂', 'Empty folder', 'No files in this prefix.');
      r2UpdateDeleteSelectedVisibility();
      return;
    }

    let html = '';
    // Show parent nav if in a sub-prefix
    if (prefix) {
      const parent = prefix.split('/').slice(0, -2).join('/');
      html += `<div class="r2-file-row" style="cursor:pointer" onclick='window.R2Page.loadR2(${JSON.stringify(parent)})'>
        <span class="r2-file-icon">⬆️</span>
        <span class="r2-file-name">.. (go up)</span>
      </div>`;
    }
    // Sub-dirs as rows
    (dirs || []).forEach(d => {
      const name = d.replace(prefix, '').replace(/\/$/, '');
      html += `<div class="r2-file-row r2-file-row-dir" data-r2-prefix="${escAttr(d)}">
        <input type="checkbox" class="r2-row-cb" data-r2-prefix="${escAttr(d)}" onclick="event.stopPropagation()" title="Select for bulk delete" />
        <span class="r2-file-icon r2-file-row-nav" onclick='window.R2Page.loadR2(${JSON.stringify(d)})'>📁</span>
        <span class="r2-file-name r2-file-row-nav" onclick='window.R2Page.loadR2(${JSON.stringify(d)})'>${esc(name || d)}/</span>
        <span class="r2-file-size">—</span>
        <span class="r2-file-date">—</span>
        <button type="button" class="r2-row-action" title="Delete folder" aria-label="Delete folder" onclick='event.stopPropagation();window.R2Page.r2DeletePrefixInteractive(${JSON.stringify(d)})'>🗑</button>
      </div>`;
    });
    // Files
    (files || []).forEach(f => {
      const name = f.key.replace(prefix, '');
      const ext = name.split('.').pop().toLowerCase();
      html += `<div class="r2-file-row" data-file-name="${escAttr(f.key)}">
        <input type="checkbox" class="r2-row-cb" data-file-name="${escAttr(f.key)}" onclick="event.stopPropagation()" title="Select for bulk delete" />
        <span class="r2-file-icon">${fileIcon(ext)}</span>
        <span class="r2-file-name" title="${esc(f.key)}">${esc(name)}</span>
        <span class="r2-file-size">${fmtSize(f.size)}</span>
        <span class="r2-file-date">${fmtDate(f.last_modified)}</span>
        <button type="button" class="r2-row-action" title="Delete file" aria-label="Delete file" onclick='event.stopPropagation();window.R2Page.r2DeleteKeyInteractive(${JSON.stringify(f.key)})'>🗑</button>
        <a href="${esc(f.public_url)}" target="_blank" class="r2-download-btn" title="Download" onclick="event.stopPropagation()">⬇</a>
      </div>`;
    });
    filesEl.innerHTML = html;
    r2UpdateDeleteSelectedVisibility();
  }

  function wireR2BrowserOnce() {
    if (window.state._r2BrowserWired) return;
    window.state._r2BrowserWired = true;

    const delSel = document.getElementById('r2-delete-selected');
    if (delSel && !delSel.dataset.wired) {
      delSel.dataset.wired = '1';
      delSel.addEventListener('click', (e) => {
        e.stopPropagation();
        r2DeleteSelected();
      });
    }

    let menu = document.getElementById('r2-ctx-menu');
    if (!menu) {
      menu = document.createElement('div');
      menu.id = 'r2-ctx-menu';
      menu.className = 'r2-ctx-menu';
      menu.setAttribute('role', 'menu');
      menu.innerHTML = '<button type="button" class="r2-ctx-item" data-action="delete">Delete…</button>';
      menu.style.display = 'none';
      document.body.appendChild(menu);
    }

    let r2CtxTarget = null;

    document.addEventListener('click', (e) => {
      if (menu.contains(e.target)) return;
      menu.style.display = 'none';
      r2CtxTarget = null;
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') menu.style.display = 'none';
    });

    document.addEventListener('contextmenu', (e) => {
      const row = e.target.closest('.r2-file-row[data-r2-prefix], .r2-file-row[data-r2-key], .r2-tree-item[data-r2-prefix]');
      if (!row || !document.getElementById('view-r2')?.contains(row)) return;
      e.preventDefault();
      r2CtxTarget = row;
      menu.style.display = 'block';
      menu.style.left = `${e.clientX}px`;
      menu.style.top = `${e.clientY}px`;
      requestAnimationFrame(() => {
        const r = menu.getBoundingClientRect();
        let left = e.clientX;
        let top = e.clientY;
        if (r.right > window.innerWidth) left = Math.max(8, window.innerWidth - r.width - 8);
        if (r.bottom > window.innerHeight) top = Math.max(8, window.innerHeight - r.height - 8);
        menu.style.left = `${left}px`;
        menu.style.top = `${top}px`;
      });
    });

    menu.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-action="delete"]');
      if (!btn || !r2CtxTarget) return;
      e.stopPropagation();
      menu.style.display = 'none';
      const t = r2CtxTarget;
      r2CtxTarget = null;
      const p = t.getAttribute('data-r2-prefix');
      const k = t.getAttribute('data-r2-key');
      if (p) r2DeletePrefixInteractive(p);
      else if (k) r2DeleteKeyInteractive(k);
    });

    const filesList = document.getElementById('r2-files-list');
    if (filesList && !filesList.dataset.changeWired) {
      filesList.dataset.changeWired = '1';
      filesList.addEventListener('change', (e) => {
        if (e.target && e.target.classList.contains('r2-row-cb')) r2UpdateDeleteSelectedVisibility();
      });
    }
  }

  function r2UpdateDeleteSelectedVisibility() {
    const btn = document.getElementById('r2-delete-selected');
    if (!btn) return;
    const n = document.querySelectorAll('#r2-files-list .r2-row-cb:checked').length;
    btn.style.display = n > 0 ? 'inline-block' : 'none';
    btn.textContent = n > 0 ? `🗑 Delete selected (${n})` : '🗑 Delete selected';
  }

  async function r2DeletePrefixInteractive(prefix) {
    if (!prefix) return;
    if (!confirm(`Delete this folder and everything under it?\n\n${prefix}\n\nThis cannot be undone.`)) return;
    try {
      const res = await window.apiPost('/api/r2/delete', { prefix });
      const n = res.deleted != null ? res.deleted : '?';
      window.showToast('success', 'R2', `Deleted (${n} object${n === 1 ? '' : 's'})`);
      await loadR2(window.state.r2.prefix);
    } catch (e) {
      window.showToast('error', 'R2', e.message);
    }
  }

  async function r2DeleteKeyInteractive(key) {
    if (!key) return;
    if (!confirm(`Delete this file?\n\n${key}\n\nThis cannot be undone.`)) return;
    try {
      await window.apiPost('/api/r2/delete', { key });
      window.showToast('success', 'R2', 'File deleted');
      await loadR2(window.state.r2.prefix);
    } catch (e) {
      window.showToast('error', 'R2', e.message);
    }
  }

  async function r2DeleteSelected() {
    const boxes = [...document.querySelectorAll('#r2-files-list .r2-row-cb:checked')];
    if (!boxes.length) return;
    const prefixes = [];
    const keys = [];
    for (const cb of boxes) {
      if (cb.dataset.r2Prefix) prefixes.push(cb.dataset.r2Prefix);
      if (cb.dataset.r2Key) keys.push(cb.dataset.r2Key);
    }
    const total = prefixes.length + keys.length;
    if (!total) return;
    if (!confirm(`Delete ${prefixes.length} folder tree(s) and ${keys.length} file(s)? This cannot be undone.`)) return;
    try {
      for (const p of prefixes) {
        await window.apiPost('/api/r2/delete', { prefix: p });
      }
      for (const k of keys) {
        await window.apiPost('/api/r2/delete', { key: k });
      }
      window.showToast('success', 'R2', `Deleted ${total} items`);
      await loadR2(window.state.r2.prefix);
    } catch (e) {
      window.showToast('error', 'R2', e.message);
    }
  }

  window.R2Page = {
    loadR2,
    renderR2,
    wireR2BrowserOnce,
    r2UpdateDeleteSelectedVisibility,
    r2DeletePrefixInteractive,
    r2DeleteKeyInteractive,
    r2DeleteSelected,
  };
})();

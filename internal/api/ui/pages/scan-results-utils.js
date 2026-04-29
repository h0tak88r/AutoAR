(() => {
  function filterScanFiles(files, searchQuery, filters = {}) {
    let filtered = files;

    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      filtered = filtered.filter((f) =>
        f.file_name.toLowerCase().includes(q) ||
        (f.source && f.source.toLowerCase().includes(q)) ||
        (f.module && f.module.toLowerCase().includes(q)) ||
        (f.category && f.category.toLowerCase().includes(q))
      );
    }

    if (filters.module) {
      filtered = filtered.filter((f) => {
        const mod = window.detectModuleFromFileName(f.file_name, f.module);
        return mod === filters.module;
      });
    }

    if (filters.category) {
      filtered = filtered.filter((f) => {
        const cat = f.category || window.categorizeScanArtifactFile(f.file_name);
        return cat === filters.category;
      });
    }

    if (filters.type) {
      filtered = filtered.filter((f) => {
        if (filters.type === 'json') return f.is_json;
        if (filters.type === 'text') return !f.is_json;
        return true;
      });
    }

    return filtered;
  }

  function renderModuleBadge(module) {
    const info = window.getModuleDisplayInfo(module);
    return `<span class="module-badge" style="background:${info.color}22;color:${info.color};border:1px solid ${info.color}44">${info.icon} ${info.name}</span>`;
  }

  function renderCategoryBadge(category) {
    const info = window.getCategoryDisplayInfo(category);
    return `<span class="category-badge ${info.badge}">${info.icon} ${info.name}</span>`;
  }

  async function copyAllScanResults(scanId) {
    try {
      window.showToast('info', 'Copying results...', 'Fetching all file contents');
      const sum = await window.apiFetch(`/api/scans/${encodeURIComponent(scanId)}/results/summary?page=1&per_page=200`);
      const files = sum.files || [];

      let allContent = `AutoAR Scan Results - ${scanId}\n`;
      allContent += `Generated: ${new Date().toISOString()}\n`;
      allContent += `${'='.repeat(80)}\n\n`;

      for (const f of files) {
        allContent += `\n${'='.repeat(80)}\n`;
        allContent += `FILE: ${f.file_name}\n`;
        allContent += `MODULE: ${window.detectModuleFromFileName(f.file_name, f.module)}\n`;
        allContent += `SOURCE: ${f.source}\n`;
        allContent += `${'='.repeat(80)}\n\n`;

        try {
          const data = await window.apiFetch(`/api/scans/${encodeURIComponent(scanId)}/results/file?file_name=${encodeURIComponent(f.file_name)}&page=1&per_page=500`);
          if (data.format === 'text' && data.lines) allContent += data.lines.join('\n');
          else if (data.format === 'json-array' && data.items) allContent += JSON.stringify(data.items, null, 2);
          else if (data.format === 'json-object' && data.data) allContent += JSON.stringify(data.data, null, 2);
          else allContent += '[Content not available or too large]';
        } catch (e) {
          allContent += `[Error loading file: ${e.message}]`;
        }
        allContent += '\n\n';
      }

      await window.copyToClipboard(allContent);
      window.showToast('success', 'Results copied!', `${files.length} files copied to clipboard`);
    } catch (e) {
      window.showToast('error', 'Copy failed', e.message);
    }
  }

  window.ScanResultsUtilsPage = {
    filterScanFiles,
    renderModuleBadge,
    renderCategoryBadge,
    copyAllScanResults,
  };
})();

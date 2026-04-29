(() => {
  let reportTemplateOriginalName = '';

  async function renderReportTemplates(search = '') {
    const container = document.getElementById('report-templates-container');
    if (!container) return;

    try {
      let templates = await window.apiFetch('/api/report-templates');
      if (search) {
        const q = search.toLowerCase();
        templates = templates.filter((name) => name.toLowerCase().includes(q));
      }

      const headerBlock = `
      <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:14px;">
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          <button class="btn btn-ghost" onclick="exportReportTemplates()">⬇️ Export JSON</button>
          <button class="btn btn-ghost" onclick="triggerImportReportTemplates()">⬆️ Import JSON</button>
        </div>
        <button class="btn btn-primary" onclick="openReportTemplateModal()">➕ Add Template</button>
      </div>
    `;

      if (!templates || templates.length === 0) {
        container.innerHTML = `
        ${headerBlock}
        <div class="empty-state">
          <div class="empty-icon">📝</div>
          <div class="empty-title">No templates found</div>
          <p class="empty-sub">Create your first markdown report template.</p>
        </div>
      `;
        return;
      }

      container.innerHTML = `
      ${headerBlock}
      <div class="domain-grid">
        ${templates.map((name) => `
          <div class="domain-card" onclick="openReportTemplateModalByName('${encodeURIComponent(name)}')">
            <div class="domain-name">📄 ${window.esc(name)}</div>
            <div class="domain-stats">
              <div class="domain-stat">
                <div class="domain-stat-label">Format</div>
                <div class="domain-stat-value" style="font-size: 14px;">Markdown</div>
              </div>
            </div>
            <div style="margin-top: 16px; display: flex; gap: 8px;">
              <button class="btn btn-ghost btn-sm" onclick="event.stopPropagation(); openReportTemplateModalByName('${encodeURIComponent(name)}')">✏️ Edit</button>
              <button class="btn btn-ghost btn-sm" style="color: var(--accent-red);" onclick="event.stopPropagation(); deleteReportTemplateByName('${encodeURIComponent(name)}')">🗑️ Delete</button>
            </div>
          </div>
        `).join('')}
      </div>
    `;
    } catch (err) {
      container.innerHTML = `<div class="error-state">❌ ${window.esc(err.message)}</div>`;
    }
  }

  function openReportTemplateModalByName(encodedName) {
    openReportTemplateModal(decodeURIComponent(encodedName || ''));
  }

  async function openReportTemplateModal(name = '') {
    const modal = document.getElementById('modal-report-template');
    const title = document.getElementById('report-template-modal-title');
    const nameInput = document.getElementById('report-template-name');
    const contentInput = document.getElementById('report-template-content');
    if (!modal || !title || !nameInput || !contentInput) return;

    nameInput.value = name;
    nameInput.readOnly = false;
    reportTemplateOriginalName = name || '';
    contentInput.value = '';
    title.textContent = name ? '📝 Edit Template' : '➕ New Template';

    if (name) {
      try {
        const data = await window.apiFetch(`/api/report-templates/${encodeURIComponent(name)}`);
        contentInput.value = data.content;
      } catch (err) {
        window.showToast('error', 'Failed to load template', err.message);
      }
    }

    modal.style.display = 'flex';
    updateTemplatePreview();
  }

  function updateTemplatePreview() {
    const content = document.getElementById('report-template-content').value;
    const preview = document.getElementById('report-template-preview');
    if (!preview) return;
    if (typeof marked !== 'undefined') preview.innerHTML = marked.parse(content || '*No content yet...*');
    else preview.textContent = content;
  }

  function closeReportTemplateModal() {
    const modal = document.getElementById('modal-report-template');
    reportTemplateOriginalName = '';
    if (modal) modal.style.display = 'none';
  }

  async function saveReportTemplate() {
    const name = document.getElementById('report-template-name').value.trim();
    const content = document.getElementById('report-template-content').value;
    const originalName = String(reportTemplateOriginalName || '').trim();
    if (!name || !content) {
      window.showToast('error', 'Validation', 'Name and content are required');
      return;
    }

    try {
      const headers = await window.buildAuthHeaders({ 'Content-Type': 'application/json' });
      const res = await fetch(`/api/report-templates`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ name, content })
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'Failed to save template');
      }

      if (originalName && originalName !== name) {
        try {
          const delHeaders = await window.buildAuthHeaders();
          await fetch(`/api/report-templates/${encodeURIComponent(originalName)}`, { method: 'DELETE', headers: delHeaders });
        } catch (_) {}
      }

      window.showToast('success', 'Template Saved', `Template "${name}" saved successfully`);
      closeReportTemplateModal();
      renderReportTemplates();
    } catch (err) {
      window.showToast('error', 'Save Failed', err.message);
    }
  }

  function deleteReportTemplateByName(encodedName) {
    deleteReportTemplate(decodeURIComponent(encodedName || ''));
  }

  async function exportReportTemplates() {
    try {
      const headers = await window.buildAuthHeaders();
      const res = await fetch(`/api/report-templates/export`, { method: 'GET', headers });
      if (!res.ok) {
        let msg = 'Failed to export templates';
        try {
          const data = await res.json();
          msg = data.error || msg;
        } catch (_) {}
        throw new Error(msg);
      }
      const blob = await res.blob();
      const ts = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
      const filename = `report-templates-${ts}.json`;
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      window.showToast('success', 'Export Ready', `Downloaded ${filename}`);
    } catch (err) {
      window.showToast('error', 'Export Failed', err.message);
    }
  }

  function triggerImportReportTemplates() {
    const input = document.getElementById('report-templates-import-file');
    if (!input) return;
    input.value = '';
    input.click();
  }

  async function handleImportReportTemplatesFile(event) {
    const file = event?.target?.files?.[0];
    if (!file) return;
    try {
      const headers = await window.buildAuthHeaders();
      const form = new FormData();
      form.append('file', file);
      form.append('overwrite', 'true');
      const res = await fetch(`/api/report-templates/import`, {
        method: 'POST',
        headers,
        body: form,
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || 'Failed to import templates');
      window.showToast('success', 'Import Completed', `Imported ${data.imported || 0}, skipped ${data.skipped || 0}`);
      renderReportTemplates((document.getElementById('report-templates-search')?.value || '').trim());
    } catch (err) {
      window.showToast('error', 'Import Failed', err.message);
    } finally {
      if (event?.target) event.target.value = '';
    }
  }

  async function deleteReportTemplate(name) {
    if (!confirm(`Are you sure you want to delete the template "${name}"?`)) return;
    try {
      const headers = await window.buildAuthHeaders();
      const res = await fetch(`/api/report-templates/${encodeURIComponent(name)}`, {
        method: 'DELETE',
        headers
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'Failed to delete template');
      }
      window.showToast('success', 'Template Deleted', `Template "${name}" removed`);
      renderReportTemplates();
    } catch (err) {
      window.showToast('error', 'Delete Failed', err.message);
    }
  }

  window.ReportTemplatesPage = {
    renderReportTemplates,
    openReportTemplateModalByName,
    openReportTemplateModal,
    updateTemplatePreview,
    closeReportTemplateModal,
    saveReportTemplate,
    deleteReportTemplateByName,
    exportReportTemplates,
    triggerImportReportTemplates,
    handleImportReportTemplatesFile,
    deleteReportTemplate,
  };
})();

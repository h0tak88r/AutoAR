(() => {
  async function loadResource(key, path, stateKey) {
    const state = window.state;
    state.loading[key] = true;
    try {
      const data = await window.apiFetch(path);
      state[stateKey] = data;
      state.error[key] = null;
    } catch (e) {
      state.error[key] = e.message;
    } finally {
      state.loading[key] = false;
    }
  }

  function updateStatusDot() {
    const dot = document.getElementById('status-dot');
    const text = document.getElementById('status-text');
    if (!dot || !text) return;
    if (window.state.config) {
      dot.className = 'status-dot';
      text.textContent = 'Connected';
    } else {
      dot.className = 'status-dot error';
      text.textContent = 'Offline';
    }
  }

  function manualRefresh() {
    const btn = document.getElementById('refresh-btn');
    if (btn) btn.classList.add('spinning');
    window.refreshCurrentView();
    setTimeout(() => { if (btn) btn.classList.remove('spinning'); }, 1200);
  }

  window.AppCoreActionsPage = {
    loadResource,
    updateStatusDot,
    manualRefresh,
  };
})();

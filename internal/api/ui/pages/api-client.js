(() => {
  async function buildAuthHeaders(extra = {}) {
    const h = { ...extra };
    const tok = window.state._authAccessToken || window.localTokenGet();
    if (tok) h.Authorization = `Bearer ${tok}`;
    return h;
  }

  function handleAuthError() {
    window.localTokenClear();
    window.state._authAccessToken = null;
    window.state._dashboardStarted = false;
    window.showAuthGate();
  }

  async function apiFetch(path) {
    const headers = await buildAuthHeaders();
    const res = await fetch(`${window.API}${path}`, { headers });
    if (res.status === 401) {
      handleAuthError();
      throw new Error('Session expired — sign in again');
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  async function apiPost(path, body, customHeaders = {}) {
    const headers = await buildAuthHeaders({ 'Content-Type': 'application/json', ...customHeaders });
    const res = await fetch(`${window.API}${path}`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
    if (res.status === 401) {
      handleAuthError();
      throw new Error('Session expired — sign in again');
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return res.json();
  }

  async function apiDelete(path) {
    const headers = await buildAuthHeaders();
    const res = await fetch(`${window.API}${path}`, { method: 'DELETE', headers });
    if (res.status === 401) {
      handleAuthError();
      throw new Error('Session expired — sign in again');
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return res.json();
  }

  window.ApiClientPage = {
    buildAuthHeaders,
    handleAuthError,
    apiFetch,
    apiPost,
    apiDelete,
  };
})();

(() => {
  const LOCAL_TOKEN_KEY = 'autoar_local_token';

  function localTokenGet() {
    try { return localStorage.getItem(LOCAL_TOKEN_KEY) || null; } catch { return null; }
  }

  function localTokenSet(tok) {
    try { localStorage.setItem(LOCAL_TOKEN_KEY, tok); } catch { /* ignore */ }
  }

  function localTokenClear() {
    try { localStorage.removeItem(LOCAL_TOKEN_KEY); } catch { /* ignore */ }
  }

  function showAuthGate(hintMsg) {
    const gate = document.getElementById('auth-gate');
    const shell = document.getElementById('app-shell');
    const hint = document.getElementById('auth-config-hint');
    if (hint && hintMsg) {
      hint.style.display = 'block';
      hint.textContent = hintMsg;
    }
    if (gate) gate.style.display = 'flex';
    if (shell) shell.style.display = 'none';
  }

  function hideAuthGate() {
    const gate = document.getElementById('auth-gate');
    const shell = document.getElementById('app-shell');
    if (gate) gate.style.display = 'none';
    if (shell) shell.style.display = '';
  }

  function wireAuthForm() {
    const form = document.getElementById('auth-form');
    if (!form || form.dataset.wired) return;
    form.dataset.wired = '1';
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const errEl = document.getElementById('auth-error');
      const submit = document.getElementById('auth-submit');
      if (errEl) errEl.textContent = '';
      const username = (document.getElementById('auth-username') || {}).value || '';
      const password = (document.getElementById('auth-password') || {}).value || '';
      if (submit) submit.disabled = true;
      try {
        const res = await fetch(`${window.API}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password }),
        });
        const data = await res.json();
        if (!res.ok) {
          if (errEl) errEl.textContent = data.error || 'Login failed';
          return;
        }
        window.state._authAccessToken = data.token;
        localTokenSet(data.token);
        await window.startDashboard();
      } catch (err) {
        if (errEl) errEl.textContent = err.message || 'Network error';
      } finally {
        if (submit) submit.disabled = false;
      }
    });
  }

  window.AuthSessionPage = {
    localTokenGet,
    localTokenSet,
    localTokenClear,
    showAuthGate,
    hideAuthGate,
    wireAuthForm,
  };
})();

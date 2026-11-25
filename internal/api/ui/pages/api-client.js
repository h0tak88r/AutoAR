(() => {
 async function buildAuthHeaders(extra = {}) {
 const h = { ...extra };
 const tok = window.state._authAccessToken || window.localTokenGet();
 if (tok) h.Authorization = `Bearer ${tok}`;
 return h;
 }

 // Session expired or revoked (logout elsewhere, password change, disable):
 // drop the token everywhere it was copied, clear the previous session's data
 // (the next sign-in may be a different user) and re-arm the login form.
 function handleAuthError() {
 window.localTokenClear();
 if (typeof window.clearAuditorTokenCookies === 'function') window.clearAuditorTokenCookies();
 const boot = window.DashboardBootstrapPage;
 if (boot && typeof boot.clearSessionState === 'function') boot.clearSessionState(window.state);
 window.state._authAccessToken = null;
 window.state._dashboardStarted = false;
 window.showAuthGate();
 if (typeof window.wireAuthForm === 'function') window.wireAuthForm();
 }

 async function apiFetch(path) {
 const headers = await buildAuthHeaders();
 const res = await fetch(`${window.API}${path}`, { headers });
 if (res.status === 401) {
 handleAuthError();
 throw new Error('Session expired — sign in again');
 }
 if (!res.ok) {
 // Surface the server's own message ("R2 storage is not enabled") instead
 // of a bare status, and keep the code for callers that branch on it.
 const body = await res.json().catch(() => null);
 const err = new Error((body && body.error) || `HTTP ${res.status}`);
 err.status = res.status;
 throw err;
 }
 return res.json();
 }

 async function apiPatch(path, body) {
 const res = await fetch(path, {
 method: 'PATCH',
 headers: { 'Content-Type': 'application/json', ...await buildAuthHeaders() },
 body: JSON.stringify(body || {}),
 });
 if (!res.ok) {
 let msg = res.statusText;
 try { msg = (await res.json()).error || msg; } catch (e) { /* keep */ }
 throw new Error(msg);
 }
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

 async function apiPut(path, body, customHeaders = {}) {
 const headers = await buildAuthHeaders({ 'Content-Type': 'application/json', ...customHeaders });
 const res = await fetch(`${window.API}${path}`, {
 method: 'PUT',
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
 apiPatch,
 apiPut,
 apiDelete,
 };
})();

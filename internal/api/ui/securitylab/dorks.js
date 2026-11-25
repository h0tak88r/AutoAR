// Recon dork backend accessor.
//
// The corpus lives in the AutoAR backend (/api/dorks) — a single source of truth
// shared with the MCP `recon_dorks` tool. This exposes the loader the Security
// Lab page calls to fetch dorks fully resolved for a target: every platform URL
// is built server-side (Google wrap, FOFA base64, {T} substitution), so the page
// renders exactly what the MCP tool returns.
window.loadReconDorks = function (target) {
  var u = '/api/dorks?format=full' + (target ? '&target=' + encodeURIComponent(target) : '');
  return fetch(u, { credentials: 'same-origin' }).then(function (r) {
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  });
};

// XSS cheat-sheet loader.
//
// The payload corpus now lives in the AutoAR backend (/api/seclab/xss) — a
// single source of truth shared with the MCP `xss_payloads` tool. This fetches
// it, sets window.XSS_PAYLOADS (the flat list the page renders), and fires
// `xss-loaded` so the page renders.
(function () {
  fetch('/api/seclab/xss', { credentials: 'same-origin' })
    .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
    .then(function (data) {
      window.XSS_PAYLOADS = data;
      window.dispatchEvent(new Event('xss-loaded'));
    })
    .catch(function (err) {
      console.error('[xss] failed to load /api/seclab/xss:', err);
      var el = document.getElementById('xssResults');
      if (el) el.innerHTML = '<div class="item muted" style="padding:20px">Failed to load XSS payloads from the backend (/api/seclab/xss).</div>';
    });
})();

// SSRF payloads loader.
//
// The payload corpus now lives in the AutoAR backend (/api/seclab/ssrf) — a
// single source of truth shared with the MCP `ssrf_payloads` tool. This fetches
// it, sets window.SSRF_PAYLOADS (the groups shape the page renders), and fires
// `ssrf-loaded` so the page renders.
(function () {
  fetch('/api/seclab/ssrf', { credentials: 'same-origin' })
    .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
    .then(function (data) {
      window.SSRF_PAYLOADS = data;
      window.dispatchEvent(new Event('ssrf-loaded'));
    })
    .catch(function (err) {
      console.error('[ssrf] failed to load /api/seclab/ssrf:', err);
      var el = document.getElementById('ssrfResults');
      if (el) el.innerHTML = '<div class="item muted">Failed to load SSRF payloads from the backend (/api/seclab/ssrf).</div>';
    });
})();

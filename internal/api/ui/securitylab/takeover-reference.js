let subdomainData = [], dnsData = [], filteredSubdomainData = [], filteredDnsData = [];

function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function initTakeoverRef() {
  const trefTabs = document.querySelectorAll('#panel-takeover .tref-tab');
  trefTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const tabName = tab.dataset.tab;
      trefTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      document.querySelectorAll('#panel-takeover .tref-content').forEach(c => c.classList.remove('active'));
      document.getElementById('tref-' + tabName).classList.add('active');
    });
  });

  document.getElementById('tref-subdomain-search').addEventListener('input', (e) => {
    filterSubdomainData(e.target.value);
  });
  document.getElementById('tref-dns-search').addEventListener('input', (e) => {
    filterDnsData(e.target.value);
  });

  loadTakeoverData();
}

async function loadTakeoverData() {
  try {
    const subRes = await fetch('/static/data/subdomain-takeover.json');
    subdomainData = await subRes.json();
    filteredSubdomainData = [...subdomainData];
    renderSubdomainTable();
    updateSubdomainStats();

    const dnsRes = await fetch('/static/data/dns-takeover.json');
    dnsData = await dnsRes.json();
    filteredDnsData = [...dnsData];
    renderDnsTable();
    updateDnsStats();
  } catch (error) {
    console.error('Error loading takeover data:', error);
    document.getElementById('tref-sub-loading').textContent = 'Error loading data. Please try again.';
    document.getElementById('tref-dns-loading').textContent = 'Error loading data. Please try again.';
  }
}

function filterSubdomainData(query) {
  query = query.toLowerCase().trim();
  if (!query) {
    filteredSubdomainData = [...subdomainData];
  } else {
    filteredSubdomainData = subdomainData.filter(entry => {
      return (entry.engine && entry.engine.toLowerCase().includes(query)) ||
             (entry.status && entry.status.toLowerCase().includes(query)) ||
             (entry.fingerprint && entry.fingerprint.toLowerCase().includes(query)) ||
             (entry.discussion && entry.discussion.toLowerCase().includes(query));
    });
  }
  renderSubdomainTable();
}

function filterDnsData(query) {
  query = query.toLowerCase().trim();
  if (!query) {
    filteredDnsData = [...dnsData];
  } else {
    filteredDnsData = dnsData.filter(entry => {
      return (entry.provider && entry.provider.toLowerCase().includes(query)) ||
             (entry.status && entry.status.toLowerCase().includes(query)) ||
             (entry.fingerprint && entry.fingerprint.toLowerCase().includes(query)) ||
             (entry.instructions && entry.instructions.toLowerCase().includes(query));
    });
  }
  renderDnsTable();
}

function renderSubdomainTable() {
  const tbody = document.getElementById('tref-sub-tbody');
  const loading = document.getElementById('tref-sub-loading');
  const wrap = document.getElementById('tref-sub-table-wrap');
  const noRes = document.getElementById('tref-sub-noresults');

  loading.style.display = 'none';
  if (filteredSubdomainData.length === 0) {
    wrap.style.display = 'none';
    noRes.style.display = 'block';
    return;
  }
  noRes.style.display = 'none';
  wrap.style.display = 'block';

  tbody.innerHTML = filteredSubdomainData.map(entry => {
    const statusClass = getStatusClass(entry.status);
    const verifiedIcon = entry.verified === 'Yes' ? 'Yes' : entry.verified === 'No' ? 'No' : (entry.verified || '');
    return '<tr>' +
      '<td><strong>' + escapeHtml(entry.engine) + '</strong></td>' +
      '<td><span class="status-badge ' + statusClass + '">' + escapeHtml(entry.status) + '</span></td>' +
      '<td><span class="verified-icon">' + escapeHtml(verifiedIcon) + '</span></td>' +
      '<td><code class="fingerprint">' + escapeHtml(entry.fingerprint) + '</code></td>' +
      '<td>' + parseLinks(entry.discussion) + '</td>' +
      '<td>' + parseLinks(entry.documentation) + '</td>' +
    '</tr>';
  }).join('');
}

function renderDnsTable() {
  const tbody = document.getElementById('tref-dns-tbody');
  const loading = document.getElementById('tref-dns-loading');
  const wrap = document.getElementById('tref-dns-table-wrap');
  const noRes = document.getElementById('tref-dns-noresults');

  loading.style.display = 'none';
  if (filteredDnsData.length === 0) {
    wrap.style.display = 'none';
    noRes.style.display = 'block';
    return;
  }
  noRes.style.display = 'none';
  wrap.style.display = 'block';

  tbody.innerHTML = filteredDnsData.map(entry => {
    const statusClass = getStatusClass(entry.status);
    return '<tr>' +
      '<td><strong>' + escapeHtml(entry.provider) + '</strong></td>' +
      '<td><span class="status-badge ' + statusClass + '">' + escapeHtml(entry.status) + '</span></td>' +
      '<td><code class="fingerprint">' + escapeHtml(entry.fingerprint) + '</code></td>' +
      '<td>' + parseLinks(entry.instructions) + '</td>' +
    '</tr>';
  }).join('');
}

function updateSubdomainStats() {
  const vuln = subdomainData.filter(e => e.status && e.status.toLowerCase().includes('vulnerable')).length;
  const safe = subdomainData.filter(e => e.status && e.status.toLowerCase().includes('not vulnerable')).length;
  document.getElementById('tref-sub-vuln').textContent = vuln;
  document.getElementById('tref-sub-safe').textContent = safe;
  document.getElementById('tref-sub-total').textContent = subdomainData.length;
}

function updateDnsStats() {
  const vuln = dnsData.filter(e => e.status && e.status.toLowerCase().includes('vulnerable')).length;
  const safe = dnsData.filter(e => e.status && e.status.toLowerCase().includes('not vulnerable')).length;
  const edge = dnsData.filter(e => e.status && e.status.toLowerCase().includes('edge case')).length;
  document.getElementById('tref-dns-vuln').textContent = vuln;
  document.getElementById('tref-dns-safe').textContent = safe;
  document.getElementById('tref-dns-edge').textContent = edge;
  document.getElementById('tref-dns-total').textContent = dnsData.length;
}

function getStatusClass(status) {
  const lower = (status || '').toLowerCase();
  if (lower.includes('vulnerable') && !lower.includes('not')) return 'status-vulnerable';
  if (lower.includes('not vulnerable')) return 'status-not-vulnerable';
  if (lower.includes('edge case')) return 'status-edge-case';
  return '';
}

function parseLinks(text) {
  if (!text) return '';
  const linkRegex = /\[([^\]]+)\]\(([^)]+)\)/g;
  return escapeHtml(text).replace(linkRegex, function(match, txt, url) {
    return '<a href="' + url + '" class="tref-link" target="_blank" rel="noopener noreferrer">' + txt + '</a>';
  });
}

window.checkTakeoverExploitability = function(cname, fingerprint, nsServer) {
  const results = { subdomain: null, dns: null, isExploitable: false };
  if (cname) {
    const cnameMatch = subdomainData.find(entry => {
      const domains = (entry.engine || '').toLowerCase();
      const cnameL = cname.toLowerCase();
      return (domains.includes(cnameL) || cnameL.includes(domains)) &&
             entry.status && entry.status.toLowerCase().includes('vulnerable');
    });
    if (cnameMatch) { results.subdomain = cnameMatch; results.isExploitable = true; }
  }
  if (nsServer) {
    const nsMatch = dnsData.find(entry => {
      const fp = (entry.fingerprint || '').toLowerCase();
      const nsL = nsServer.toLowerCase();
      const patterns = fp.split(',').map(p => p.trim());
      return patterns.some(pattern => {
        const regexPattern = pattern.replace(/\*/g, '.*').replace(/\./g, '\\.');
        const regex = new RegExp(regexPattern, 'i');
        return regex.test(nsL);
      }) && entry.status && entry.status.toLowerCase().includes('vulnerable');
    });
    if (nsMatch) { results.dns = nsMatch; results.isExploitable = true; }
  }
  return results;
};

document.querySelectorAll('.tab').forEach(btn => {
  btn.addEventListener('click', () => {
    if (btn.dataset.tab === 'takeover') {
      if (!subdomainData.length && !dnsData.length) initTakeoverRef();
    }
  });
});
initTakeoverRef();

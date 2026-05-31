// Takeover Reference JavaScript
let subdomainData = [];
let dnsData = [];
let filteredSubdomainData = [];
let filteredDnsData = [];

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    initializeTabs();
    loadData();
});

// Tab switching
function initializeTabs() {
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const tabName = tab.dataset.tab;
            switchTab(tabName);
        });
    });
}

function switchTab(tabName) {
    // Update tab buttons
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

    // Update tab content
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.getElementById(`${tabName}-tab`).classList.add('active');
}

// Load JSON data
async function loadData() {
    try {
        // Load subdomain takeover data
        const subdomainResponse = await fetch('/static/data/subdomain-takeover.json');
        subdomainData = await subdomainResponse.json();
        filteredSubdomainData = [...subdomainData];
        renderSubdomainTable();
        updateSubdomainStats();

        // Load DNS takeover data
        const dnsResponse = await fetch('/static/data/dns-takeover.json');
        dnsData = await dnsResponse.json();
        filteredDnsData = [...dnsData];
        renderDnsTable();
        updateDnsStats();

        // Setup search
        setupSearch();
    } catch (error) {
        console.error('Error loading takeover data:', error);
        document.getElementById('subdomain-loading').textContent = 'Error loading data. Please try again.';
        document.getElementById('dns-loading').textContent = 'Error loading data. Please try again.';
    }
}

// Setup search functionality
function setupSearch() {
    const subdomainSearch = document.getElementById('subdomain-search');
    const dnsSearch = document.getElementById('dns-search');

    subdomainSearch.addEventListener('input', (e) => {
        filterSubdomainData(e.target.value);
    });

    dnsSearch.addEventListener('input', (e) => {
        filterDnsData(e.target.value);
    });
}

// Filter subdomain data
function filterSubdomainData(query) {
    query = query.toLowerCase().trim();

    if (!query) {
        filteredSubdomainData = [...subdomainData];
    } else {
        filteredSubdomainData = subdomainData.filter(entry => {
            return (
                entry.engine.toLowerCase().includes(query) ||
                entry.status.toLowerCase().includes(query) ||
                entry.fingerprint.toLowerCase().includes(query) ||
                entry.discussion.toLowerCase().includes(query)
            );
        });
    }

    renderSubdomainTable();
}

// Filter DNS data
function filterDnsData(query) {
    query = query.toLowerCase().trim();

    if (!query) {
        filteredDnsData = [...dnsData];
    } else {
        filteredDnsData = dnsData.filter(entry => {
            return (
                entry.provider.toLowerCase().includes(query) ||
                entry.status.toLowerCase().includes(query) ||
                entry.fingerprint.toLowerCase().includes(query) ||
                entry.instructions.toLowerCase().includes(query)
            );
        });
    }

    renderDnsTable();
}

// Render subdomain takeover table
function renderSubdomainTable() {
    const tbody = document.getElementById('subdomain-tbody');
    const loading = document.getElementById('subdomain-loading');
    const tableContainer = document.getElementById('subdomain-table-container');
    const noResults = document.getElementById('subdomain-no-results');

    loading.style.display = 'none';

    if (filteredSubdomainData.length === 0) {
        tableContainer.style.display = 'none';
        noResults.style.display = 'block';
        return;
    }

    noResults.style.display = 'none';
    tableContainer.style.display = 'block';

    tbody.innerHTML = filteredSubdomainData.map(entry => {
        const statusClass = getStatusClass(entry.status);
        const verifiedIcon = entry.verified === '🟩' ? '✅' : entry.verified === '🟥' ? '❌' : entry.verified;

        return `
            <tr>
                <td><strong>${escapeHtml(entry.engine)}</strong></td>
                <td><span class="status-badge ${statusClass}">${escapeHtml(entry.status)}</span></td>
                <td><span class="verified-icon">${verifiedIcon}</span></td>
                <td><code class="fingerprint">${escapeHtml(entry.fingerprint)}</code></td>
                <td>${parseLinks(entry.discussion)}</td>
                <td>${parseLinks(entry.documentation)}</td>
            </tr>
        `;
    }).join('');
}

// Render DNS takeover table
function renderDnsTable() {
    const tbody = document.getElementById('dns-tbody');
    const loading = document.getElementById('dns-loading');
    const tableContainer = document.getElementById('dns-table-container');
    const noResults = document.getElementById('dns-no-results');

    loading.style.display = 'none';

    if (filteredDnsData.length === 0) {
        tableContainer.style.display = 'none';
        noResults.style.display = 'block';
        return;
    }

    noResults.style.display = 'none';
    tableContainer.style.display = 'block';

    tbody.innerHTML = filteredDnsData.map(entry => {
        const statusClass = getStatusClass(entry.status);

        return `
            <tr>
                <td><strong>${escapeHtml(entry.provider)}</strong></td>
                <td><span class="status-badge ${statusClass}">${escapeHtml(entry.status)}</span></td>
                <td><code class="fingerprint">${escapeHtml(entry.fingerprint)}</code></td>
                <td>${parseLinks(entry.instructions)}</td>
            </tr>
        `;
    }).join('');
}

// Update subdomain stats
function updateSubdomainStats() {
    const vulnerable = subdomainData.filter(e => e.status.toLowerCase().includes('vulnerable')).length;
    const notVulnerable = subdomainData.filter(e => e.status.toLowerCase().includes('not vulnerable')).length;

    document.getElementById('subdomain-vulnerable-count').textContent = vulnerable;
    document.getElementById('subdomain-safe-count').textContent = notVulnerable;
    document.getElementById('subdomain-total-count').textContent = subdomainData.length;
}

// Update DNS stats
function updateDnsStats() {
    const vulnerable = dnsData.filter(e => e.status.toLowerCase().includes('vulnerable')).length;
    const notVulnerable = dnsData.filter(e => e.status.toLowerCase().includes('not vulnerable')).length;
    const edgeCase = dnsData.filter(e => e.status.toLowerCase().includes('edge case')).length;

    document.getElementById('dns-vulnerable-count').textContent = vulnerable;
    document.getElementById('dns-safe-count').textContent = notVulnerable;
    document.getElementById('dns-edge-count').textContent = edgeCase;
    document.getElementById('dns-total-count').textContent = dnsData.length;
}

// Get status CSS class
function getStatusClass(status) {
    const lower = status.toLowerCase();
    if (lower.includes('vulnerable') && !lower.includes('not')) {
        return 'status-vulnerable';
    } else if (lower.includes('not vulnerable')) {
        return 'status-not-vulnerable';
    } else if (lower.includes('edge case')) {
        return 'status-edge-case';
    }
    return '';
}

// Parse markdown links
function parseLinks(text) {
    if (!text) return '';

    // Parse markdown links [text](url)
    const linkRegex = /\[([^\]]+)\]\(([^)]+)\)/g;
    return escapeHtml(text).replace(linkRegex, (match, text, url) => {
        return `<a href="${url}" class="link" target="_blank" rel="noopener noreferrer">${text}</a>`;
    });
}

// Escape HTML
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Export function to check if a finding is exploitable
window.checkTakeoverExploitability = function(cname, fingerprint, nsServer) {
    const results = {
        subdomain: null,
        dns: null,
        isExploitable: false
    };

    // Check subdomain takeover
    if (cname) {
        const cnameMatch = subdomainData.find(entry => {
            const domains = entry.engine.toLowerCase();
            const fp = entry.fingerprint.toLowerCase();
            const cnameL = cname.toLowerCase();

            return (domains.includes(cnameL) || cnameL.includes(domains)) &&
                   entry.status.toLowerCase().includes('vulnerable');
        });

        if (cnameMatch) {
            results.subdomain = cnameMatch;
            results.isExploitable = true;
        }
    }

    // Check DNS/NS takeover
    if (nsServer) {
        const nsMatch = dnsData.find(entry => {
            const fp = entry.fingerprint.toLowerCase();
            const nsL = nsServer.toLowerCase();

            // Check if NS server matches fingerprint pattern
            const patterns = fp.split(',').map(p => p.trim());
            return patterns.some(pattern => {
                // Convert wildcard pattern to regex
                const regexPattern = pattern
                    .replace(/\*/g, '.*')
                    .replace(/\./g, '\\.');
                const regex = new RegExp(regexPattern, 'i');
                return regex.test(nsL);
            }) && entry.status.toLowerCase().includes('vulnerable');
        });

        if (nsMatch) {
            results.dns = nsMatch;
            results.isExploitable = true;
        }
    }

    return results;
};

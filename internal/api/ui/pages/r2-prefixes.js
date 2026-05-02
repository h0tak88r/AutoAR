(() => {
  function targetToHostname(target) {
    if (target == null || target === '') return '';
    const t = String(target).trim();
    try {
      if (t.includes('://')) {
        const u = new URL(t);
        return (u.hostname || '').replace(/^www\./i, '') || u.hostname;
      }
    } catch (e) { /* use heuristic below */ }
    const noProto = t.replace(/^https?:\/\//i, '');
    const host = noProto.split('/')[0] || '';
    return host.replace(/^www\./i, '') || noProto;
  }

  function uniquePrefixList(prefixes) {
    const out = [];
    const seen = new Set();
    for (const p of prefixes) {
      if (!p || seen.has(p)) continue;
      seen.add(p);
      out.push(p);
    }
    return out;
  }

  function r2PrefixesForScan(target, scanType) {
    const t = (target || '').trim();
    const st = (scanType || '').toLowerCase();
    const host = targetToHostname(t) || t;

    const domainTriad = (h) => [
      `new-results/${h}/`,
      `results/${h}/`,
      `lite/${h}/`,
    ];

    if (st.startsWith('nuclei')) {
      const hosts = new Set();
      if (host) hosts.add(host);
      if (/^https?:\/\//i.test(t)) {
        const uh = targetToHostname(t);
        if (uh) hosts.add(uh);
      }
      const prefixes = [];
      for (const h of hosts) prefixes.push(...domainTriad(h));
      const h0 = [...hosts][0];
      if (h0) prefixes.push(`new-results/misconfig/${h0}/`, `misconfig/${h0}/`);
      if (!prefixes.length && (host || t)) return uniquePrefixList(domainTriad(host || t));
      return uniquePrefixList(prefixes);
    }

    if (st === 'misconfig') {
      return uniquePrefixList([
        `new-results/misconfig/${host}/`,
        `misconfig/${host}/`,
        ...domainTriad(host),
      ]);
    }

    if (st === 'dns-takeover' || st === 'dns' || st.startsWith('dns-')) {
      return uniquePrefixList([
        `new-results/${host}/vulnerabilities/dns-takeover/`,
        `results/${host}/vulnerabilities/dns-takeover/`,
        ...domainTriad(host),
      ]);
    }

    if (st === 's3') {
      const b = t || host;
      return uniquePrefixList([
        `new-results/s3/${b}/`,
        `s3/${b}/`,
        `results/s3/${b}/`,
      ]);
    }

    if (st === 'github') {
      const slug = t;
      return uniquePrefixList([
        `new-results/${scanID}/`,
        `new-results/${scanID}/github-secrets.json`,
        `new-results/github/repos/${slug}/`,
        `github/repos/${slug}/`,
        ...domainTriad(host),
      ]);
    }

    if (st === 'github_org') {
      return uniquePrefixList([
        `new-results/${scanID}/`,
        `new-results/${scanID}/github-secrets.json`,
        `new-results/github/orgs/${t}/`,
        `github/orgs/${t}/`,
      ]);
    }

    if (st === 'ffuf') {
      return uniquePrefixList([
        `new-results/ffuf/`,
        `ffuf/`,
        ...domainTriad(host),
      ]);
    }

    if (st === 'jwt') {
      return uniquePrefixList([
        `new-results/jwt-scan/`,
        `jwt-scan/`,
      ]);
    }

    if (st === 'apkx') {
      return uniquePrefixList([
        `new-results/apkx/`,
        `apkx/`,
        `results/apkx/`,
      ]);
    }

    if (st === 'zerodays') {
      return uniquePrefixList([
        ...domainTriad(host),
        `new-results/zerodays/`,
        `zerodays/`,
      ]);
    }

    return uniquePrefixList([
      ...domainTriad(host),
      `new-results/misconfig/${host}/`,
      `misconfig/${host}/`,
    ]);
  }

  window.R2PrefixesPage = {
    targetToHostname,
    uniquePrefixList,
    r2PrefixesForScan,
  };
})();

(() => {
  function viewTitle(v) {
    return {
      overview: 'Overview', scans: 'Scans', domains: 'Domains', subdomains: 'Subdomains',
      targets: 'Bug Bounty Targets',
      keyhacks: 'Keyhacks',
      monitor: 'Monitor', r2: 'R2 Storage', settings: 'Settings',
      'report-templates': 'Report Templates',
      apkauditor: '🤖 APK Auditor',
      ipaauditor: '🍏 IPA Auditor',
      adbauditor: '⚡ ADB Auditor',
      securitylab: '🧪 Security Lab',
    }[v] || v;
  }

  function openAuditorInNewTab(view) {
    const tok = window.state._authAccessToken || window.localTokenGet();
    const pathMap = { apkauditor: '/ui/apkauditor/', ipaauditor: '/ui/ipaauditor/', adbauditor: '/ui/adbauditor/', securitylab: '/ui/securitylab/' };
    const targetPath = pathMap[view] || '/ui/apkauditor/';

    if (tok) {
      document.cookie = `autoar_token=${tok}; path=/ui/apkauditor; max-age=3600; SameSite=Strict`;
      document.cookie = `autoar_token=${tok}; path=/ui/ipaauditor; max-age=3600; SameSite=Strict`;
      document.cookie = `autoar_token=${tok}; path=/ui/adbauditor; max-age=3600; SameSite=Strict`;
      document.cookie = `autoar_token=${tok}; path=/ui/securitylab; max-age=3600; SameSite=Strict`;
    }
    window.open(targetPath, '_blank');
  }

  window.NavigationUIPage = {
    viewTitle,
    openAuditorInNewTab,
  };
})();

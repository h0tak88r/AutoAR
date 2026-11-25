(() => {
 function viewTitle(v) {
 return {
 overview: 'Overview', scans: 'Scans', triage: 'AI Triage', 'ai-agent': 'AI Agent', domains: 'Domains', subdomains: 'Subdomains',
 targets: 'Bug Bounty Targets',
 programs: 'Programs',
 'program-lookup': 'Program Lookup',
 'cve-radar': 'CVE Radar',
 'findings': 'Findings', 'ports': 'Port Surface',
 keyhacks: 'Keyhacks',
 monitor: 'Monitor', r2: 'R2 Storage', settings: 'Settings',
 'report-templates': 'Report Templates',
 apkauditor: ' APK Auditor',
 ipaauditor: ' IPA Auditor',
 adbauditor: ' ADB Auditor',
 securitylab: ' Security Lab',
 }[v] || v;
 }

 // The auditors / Security Lab run as separate pages that read the session
 // token from a JS-readable cookie scoped to their path.
 const AUDITOR_COOKIE_PATHS = ['/ui/apkauditor', '/ui/ipaauditor', '/ui/adbauditor', '/ui/securitylab'];

 function setAuditorTokenCookies(tok) {
 if (!tok) return;
 const secure = location.protocol === 'https:' ? '; Secure' : '';
 AUDITOR_COOKIE_PATHS.forEach((p) => {
 document.cookie = `autoar_token=${tok}; path=${p}; max-age=3600; SameSite=Strict${secure}`;
 });
 }

 // Expire the token cookies (on logout / after a password change revoked the token).
 function clearAuditorTokenCookies() {
 const secure = location.protocol === 'https:' ? '; Secure' : '';
 AUDITOR_COOKIE_PATHS.forEach((p) => {
 document.cookie = `autoar_token=; path=${p}; max-age=0; SameSite=Strict${secure}`;
 });
 }

 function openAuditorInNewTab(view) {
 const tok = window.state._authAccessToken || window.localTokenGet();
 const pathMap = { apkauditor: '/ui/apkauditor/', ipaauditor: '/ui/ipaauditor/', adbauditor: '/ui/adbauditor/', securitylab: '/ui/securitylab/' };
 const targetPath = pathMap[view] || '/ui/apkauditor/';

 setAuditorTokenCookies(tok);
 window.open(targetPath, '_blank');
 }

 window.setAuditorTokenCookies = setAuditorTokenCookies;
 window.clearAuditorTokenCookies = clearAuditorTokenCookies;

 window.NavigationUIPage = {
 viewTitle,
 openAuditorInNewTab,
 setAuditorTokenCookies,
 clearAuditorTokenCookies,
 };
})();

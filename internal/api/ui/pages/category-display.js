(() => {
  function getCategoryDisplayInfo(category) {
    const cat = String(category || '').toLowerCase();
    const categories = {
      vulnerability: { icon: '⚠️', name: 'Vulnerability', badge: 'badge-failed' },
      recon: { icon: '🔭', name: 'Reconnaissance', badge: 'badge-running' },
      config: { icon: '⚙️', name: 'Configuration', badge: 'badge-starting' },
      output: { icon: '📊', name: 'Output', badge: 'badge-done' },
      log: { icon: '📝', name: 'Log', badge: 'badge-monitor-off' },
    };
    return categories[cat] || { icon: '📄', name: 'File', badge: '' };
  }

  window.CategoryDisplayPage = {
    getCategoryDisplayInfo,
  };
})();

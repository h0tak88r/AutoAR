(() => {
  function elapsedStr(start) {
    try {
      const diff = Date.now() - new Date(start).getTime();
      if (isNaN(diff)) return '';
      const h = Math.floor(diff / 3600000);
      const m = Math.floor((diff % 3600000) / 60000);
      const s = Math.floor((diff % 60000) / 1000);
      if (h > 0) return `${h}h ${m}m`;
      if (m > 0) return `${m}m ${s}s`;
      return `${s}s`;
    } catch { return ''; }
  }

  function elapsedBetween(start, end) {
    try {
      const diff = new Date(end).getTime() - new Date(start).getTime();
      if (isNaN(diff) || diff < 0) return '—';
      const h = Math.floor(diff / 3600000);
      const m = Math.floor((diff % 3600000) / 60000);
      const s = Math.floor((diff % 60000) / 1000);
      if (h > 0) return `${h}h ${m}m`;
      if (m > 0) return `${m}m ${s}s`;
      return `${s}s`;
    } catch { return '—'; }
  }

  function fmtSize(bytes) {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return (bytes / Math.pow(k, i)).toFixed(i > 0 ? 1 : 0) + ' ' + sizes[i];
  }

  window.FormatUtilsPage = {
    elapsedStr,
    elapsedBetween,
    fmtSize,
  };
})();

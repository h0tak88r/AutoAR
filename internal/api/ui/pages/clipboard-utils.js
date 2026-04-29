(() => {
  async function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      try {
        await navigator.clipboard.writeText(text);
        return;
      } catch (e) { /* fallback below */ }
    }

    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.top = '0';
    textArea.style.left = '0';
    textArea.style.opacity = '0';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    try {
      const successful = document.execCommand('copy');
      if (!successful) throw new Error('execCommand returned false');
    } finally {
      document.body.removeChild(textArea);
    }
  }

  window.ClipboardUtilsPage = {
    copyToClipboard,
  };
})();

(() => {
  function prevFilesPage(scanId) {
    if (window.state.scanDetailUI.filesPage > 1) {
      window.state.scanDetailUI.filesPage--;
      window.renderScanDetailView(scanId);
    }
  }

  function nextFilesPage(scanId, total) {
    if (window.state.scanDetailUI.filesPage * window.state.scanDetailUI.filesPerPage < total) {
      window.state.scanDetailUI.filesPage++;
      window.renderScanDetailView(scanId);
    }
  }

  window.ScanDetailPaginationPage = {
    prevFilesPage,
    nextFilesPage,
  };
})();

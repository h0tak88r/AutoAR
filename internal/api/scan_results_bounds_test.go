package api

import (
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/db"
)

func TestPageBoundsNeverPanics(t *testing.T) {
	cases := []struct {
		page, perPage, total, start, end int
	}{
		{1, 20, 50, 0, 20},
		{3, 20, 50, 40, 50},
		{4, 20, 50, 50, 50},
		{0, 20, 50, 0, 20},
		{1, 0, 5, 0, 1},
		{math.MaxInt, 100, 50, 50, 50},
		{math.MaxInt / 2, math.MaxInt / 2, 50, 50, 50},
		{1, math.MaxInt, 50, 0, 50},
		{5, 10, 0, 0, 0},
	}
	for _, tc := range cases {
		s, e := pageBounds(tc.page, tc.perPage, tc.total)
		if s != tc.start || e != tc.end {
			t.Errorf("pageBounds(%d,%d,%d) = [%d,%d), want [%d,%d)", tc.page, tc.perPage, tc.total, s, e, tc.start, tc.end)
		}
	}
	entries := make([]fileEntry, 7)
	if items, total := paginateFileEntries(entries, math.MaxInt, 100); len(items) != 0 || total != 7 {
		t.Errorf("paginateFileEntries huge page = %d items / %d total", len(items), total)
	}
}

func TestResultFileEndpointsBoundedReads(t *testing.T) {
	withTestSQLite(t)
	gin.SetMode(gin.TestMode)
	const scanID = "bounds-scan"
	now := time.Now()
	if err := db.CreateScan(&db.ScanRecord{ScanID: scanID, ScanType: "subdomains", Target: "example.com", Status: "completed", StartedAt: now, LastUpdate: now}); err != nil {
		t.Fatal(err)
	}
	dir := getScanResultsDir(scanID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "subs.txt"), []byte("a\nb\nc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Sparse file over the inline cap: must be refused by size, not read.
	big, err := os.Create(filepath.Join(dir, "huge.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := big.Truncate(scanResultMaxBody + 1); err != nil {
		t.Fatal(err)
	}
	big.Close()

	_, _, err = loadFileContent(scanID, "huge.json")
	var tooLarge *resultFileTooLargeError
	if !errors.As(err, &tooLarge) || tooLarge.Size != scanResultMaxBody+1 || tooLarge.LocalPath == "" {
		t.Fatalf("loadFileContent(oversized) err = %v, want *resultFileTooLargeError with size+path", err)
	}

	r := gin.New()
	r.GET("/scans/:id/results/file", apiScanResultFileContent)
	r.GET("/scans/:id/results/files", apiScanResultFiles)
	get := func(url string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, url, nil))
		return w
	}

	huge := strconv.Itoa(math.MaxInt)
	if w := get("/scans/" + scanID + "/results/file?file_name=subs.txt&page=" + huge); w.Code != http.StatusOK {
		t.Fatalf("huge page on text file: %d %s", w.Code, w.Body.String())
	}
	if w := get("/scans/" + scanID + "/results/files?page=" + huge); w.Code != http.StatusOK {
		t.Fatalf("huge page on file list: %d %s", w.Code, w.Body.String())
	}
	w := get("/scans/" + scanID + "/results/file?file_name=huge.json")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"too_large"`) {
		t.Fatalf("oversized file preview: %d %s", w.Code, w.Body.String())
	}

	// Line counts stream once and are then served from the cache.
	info, _ := os.Stat(filepath.Join(dir, "subs.txt"))
	if n := cachedLineCount(filepath.Join(dir, "subs.txt"), info); n != 3 {
		t.Fatalf("cachedLineCount = %d, want 3", n)
	}
	lineCountMu.Lock()
	_, cached := lineCountCache[filepath.Join(dir, "subs.txt")]
	lineCountMu.Unlock()
	if !cached {
		t.Fatal("line count was not cached")
	}
}

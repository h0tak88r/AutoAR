package firebase

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func testClient() *http.Client { return &http.Client{Timeout: 5 * time.Second} }

// TestMergeConfig verifies extraction from both a JS firebaseConfig blob and a
// JSON init.json body.
func TestMergeConfig(t *testing.T) {
	js := `const firebaseConfig = {
		apiKey: "AIzaSyA1234567890abcdef_GHIJKLMNOPqrstuv",
		authDomain: "myproj.firebaseapp.com",
		databaseURL: "https://myproj-default-rtdb.firebasedatabase.app",
		projectId: "myproj",
		storageBucket: "myproj.appspot.com"
	};`
	var cfg fbConfig
	mergeConfig(&cfg, js)
	if cfg.ProjectID != "myproj" {
		t.Errorf("projectId: got %q", cfg.ProjectID)
	}
	if !strings.HasPrefix(cfg.APIKey, "AIzaSyA") {
		t.Errorf("apiKey not extracted: %q", cfg.APIKey)
	}
	if cfg.DatabaseURL != "https://myproj-default-rtdb.firebasedatabase.app" {
		t.Errorf("databaseURL: got %q", cfg.DatabaseURL)
	}
	if cfg.StorageBucket != "myproj.appspot.com" {
		t.Errorf("storageBucket: got %q", cfg.StorageBucket)
	}

	// JSON init.json body uses the same keys, quoted.
	jsonBody := `{"projectId":"jproj","apiKey":"AIzaSyJSON567890abcdefghij_KLMNOPqrstuv","storageBucket":"jproj.appspot.com"}`
	var jcfg fbConfig
	mergeConfig(&jcfg, jsonBody)
	if jcfg.ProjectID != "jproj" || jcfg.StorageBucket != "jproj.appspot.com" {
		t.Errorf("json extraction failed: %+v", jcfg)
	}
}

// TestDeriveProjectID backfills the projectId from the other config fields.
func TestDeriveProjectID(t *testing.T) {
	cases := []struct {
		cfg  fbConfig
		want string
	}{
		{fbConfig{AuthDomain: "acme.firebaseapp.com"}, "acme"},
		{fbConfig{StorageBucket: "acme.appspot.com"}, "acme"},
		{fbConfig{DatabaseURL: "https://acme.firebaseio.com"}, "acme"},
		{fbConfig{DatabaseURL: "https://acme-default-rtdb.firebasedatabase.app"}, "acme"},
		{fbConfig{ProjectID: "explicit", AuthDomain: "other.firebaseapp.com"}, "explicit"}, // explicit wins
	}
	for i, c := range cases {
		cfg := c.cfg
		deriveProjectID(&cfg)
		if cfg.ProjectID != c.want {
			t.Errorf("case %d: got %q want %q", i, cfg.ProjectID, c.want)
		}
	}
}

// TestServiceURLDerivation checks the RTDB/storage URL variants.
func TestServiceURLDerivation(t *testing.T) {
	// Explicit databaseURL is used verbatim.
	if got := rtdbURLs(fbConfig{DatabaseURL: "https://x.firebaseio.com/"}); len(got) != 1 || got[0] != "https://x.firebaseio.com" {
		t.Errorf("explicit rtdb: %v", got)
	}
	// Derived variants from projectId.
	got := rtdbURLs(fbConfig{ProjectID: "p"})
	if len(got) != 2 || got[0] != "https://p.firebaseio.com" || got[1] != "https://p-default-rtdb.firebasedatabase.app" {
		t.Errorf("derived rtdb: %v", got)
	}
	if b := storageBuckets(fbConfig{ProjectID: "p"}); len(b) != 2 || b[0] != "p.appspot.com" {
		t.Errorf("storage buckets: %v", b)
	}
}

// TestRealtimeDBClassification exercises the four response outcomes.
func TestRealtimeDBClassification(t *testing.T) {
	cases := []struct {
		name, body string
		code       int
		want       string
	}{
		{"open", `{"users":true,"config":true}`, 200, "public-read"},
		{"empty", `null`, 200, "accessible-empty"},
		{"secured", `{"error":"Permission denied"}`, 401, "secured"},
		{"notfound", `404 page not found`, 404, "not-found"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("shallow") != "true" {
					t.Errorf("expected shallow=true, got %q", r.URL.RawQuery)
				}
				w.WriteHeader(c.code)
				_, _ = w.Write([]byte(c.body))
			}))
			defer srv.Close()
			access, _, _ := testRealtimeDB(testClient(), srv.URL)
			if access != c.want {
				t.Errorf("got %q want %q", access, c.want)
			}
		})
	}
}

// TestFingerprintFromInitJSON is the end-to-end happy path: init.json detected,
// config extracted, project id present.
func TestFingerprintFromInitJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/__/firebase/init.json":
			_, _ = w.Write([]byte(`{"projectId":"hostproj","apiKey":"AIzaSyHOST7890abcdefghij_KLMNOPqrstuvw","databaseURL":"https://hostproj.firebaseio.com","storageBucket":"hostproj.appspot.com"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	detected, cfg, evidence := fingerprint(testClient(), srv.URL)
	if !detected {
		t.Fatal("expected Firebase detected via init.json")
	}
	if cfg.ProjectID != "hostproj" {
		t.Errorf("projectId: got %q", cfg.ProjectID)
	}
	if evidence != "init.json" {
		t.Errorf("evidence: got %q", evidence)
	}
}

// TestFingerprintFromHandlerJS detects via the auth helper license (the nuclei
// template's signal) even without init.json.
func TestFingerprintFromHandlerJS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__/auth/handler.js" {
			_, _ = w.Write([]byte(`/*! @license Firebase v9.0.0 Build: 9.0.0 https://firebase.google.com/terms/ */`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	detected, _, evidence := fingerprint(testClient(), srv.URL)
	if !detected {
		t.Fatal("expected Firebase detected via handler.js license")
	}
	if evidence != "auth/handler.js" {
		t.Errorf("evidence: got %q", evidence)
	}
}

// TestRealtimeDBWriteCleansUp verifies the write probe PUTs a marker and then
// DELETEs the same key (leaves nothing behind) when the write succeeds.
func TestRealtimeDBWriteCleansUp(t *testing.T) {
	var mu sync.Mutex
	var calls []string // "METHOD path"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	writable, url, _ := testRealtimeDBWrite(testClient(), srv.URL)
	if !writable {
		t.Fatal("expected writable=true on a 200 PUT")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 2 {
		t.Fatalf("expected a PUT then a DELETE, got %v", calls)
	}
	if !strings.HasPrefix(calls[0], "PUT ") {
		t.Errorf("first call should be PUT, got %q", calls[0])
	}
	if !strings.HasPrefix(calls[1], "DELETE ") {
		t.Errorf("cleanup call should be DELETE, got %q", calls[1])
	}
	// PUT and DELETE must target the same key path (from the returned url).
	if !strings.Contains(url, "_autoar_wtest_") {
		t.Errorf("write url not labelled: %q", url)
	}
	putPath := strings.TrimPrefix(calls[0], "PUT ")
	delPath := strings.TrimPrefix(calls[1], "DELETE ")
	if putPath != delPath {
		t.Errorf("cleanup targeted a different key: PUT %q vs DELETE %q", putPath, delPath)
	}
}

// TestRealtimeDBWriteDeniedNoCleanup: a denied write does not report writable and
// performs no DELETE.
func TestRealtimeDBWriteDeniedNoCleanup(t *testing.T) {
	var mu sync.Mutex
	deletes := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			mu.Lock()
			deletes++
			mu.Unlock()
		}
		w.WriteHeader(403)
	}))
	defer srv.Close()

	writable, _, _ := testRealtimeDBWrite(testClient(), srv.URL)
	if writable {
		t.Error("expected writable=false on a 403 PUT")
	}
	mu.Lock()
	defer mu.Unlock()
	if deletes != 0 {
		t.Errorf("no cleanup DELETE should happen when the write is denied, got %d", deletes)
	}
}

// TestFingerprintNegative: a plain site is not flagged.
func TestFingerprintNegative(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body>hello world, no firebase here</body></html>`))
	}))
	defer srv.Close()
	if detected, _, _ := fingerprint(testClient(), srv.URL); detected {
		t.Error("false positive on a non-Firebase site")
	}
}

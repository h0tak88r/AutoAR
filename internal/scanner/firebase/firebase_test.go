package firebase

import (
	"net/http"
	"net/http/httptest"
	"strings"
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

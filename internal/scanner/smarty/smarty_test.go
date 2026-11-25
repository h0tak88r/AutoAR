package smarty

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFingerprint(t *testing.T) {
	cases := map[string]string{
		`<meta name="generator" content="PrestaShop">`:      "PrestaShop",
		`<html>powered by SuiteCRM</html>`:                   "SuiteCRM",
		`<meta name="generator" content="X-Cart">`:           "X-Cart",
		`Fatal error: SmartyCompilerException in ...`:        "Smarty-artifact",
		`<html>plain wordpress site</html>`:                  "",
		`<title>Index of /</title>`:                          "",
	}
	for body, want := range cases {
		if got := Fingerprint(body); got != want {
			t.Errorf("Fingerprint(%q) = %q, want %q", body, got, want)
		}
	}
}

func TestExtractMarker(t *testing.T) {
	if m := ExtractMarker("junk SMVERIFY87:64 trailing"); m != VulnerableMarker {
		t.Errorf("marker not extracted: %q", m)
	}
	// Reflection / template-echo of the payload string itself must NOT count:
	// the payload contains the marker prefix without the computed value.
	if m := ExtractMarker(BuildPayload()); m != "" {
		t.Errorf("unexecuted payload echoed verbatim must not validate, got %q", m)
	}
	if m := ExtractMarker("SMVERIFY87:99 wrong value"); m != "" {
		t.Errorf("wrong computed value must not validate, got %q", m)
	}
}

// End-to-end chain against a fake vulnerable app: assigns the param into a
// cached template — the poison value is reflected on the NEXT request only
// when it contains the forged block, simulating cache regeneration.
func TestProbeVulnerableApp(t *testing.T) {
	var lastVal string
	var poisoned bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("name")
		if r.Method == http.MethodPost {
			// body parse skipped: probe posts form-encoded; emulate read
			r.ParseForm()
			v = r.Form.Get("name")
		}
		if v == "world" {
			w.Write([]byte("hello"))
			return
		}
		if strings.Contains(lastVal, "SmartyNocache") {
			poisoned = true
			w.Write([]byte("page SMVERIFY87:64 page"))
			return
		}
		lastVal = v
		w.Write([]byte("page"))
	}))
	defer srv.Close()

	res := Probe(t.Context(), NewClient(5e9), Target{BaseURL: srv.URL, Path: "/", Param: "name"}, "FakeSmarty", 1)
	if !res.Vulnerable {
		t.Fatalf("expected vulnerable, got %+v", res)
	}
	if res.Evidence != VulnerableMarker {
		t.Errorf("evidence = %q", res.Evidence)
	}
	_ = poisoned
}

func TestProbePatchedApp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello world page"))
	}))
	defer srv.Close()

	res := Probe(t.Context(), NewClient(5e9), Target{BaseURL: srv.URL, Path: "/", Param: "name"}, "FakeSmarty", 0)
	if res.Vulnerable {
		t.Fatalf("patched app must not validate: %+v", res)
	}
}

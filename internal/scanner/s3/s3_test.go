package s3

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestParseBucketInput(t *testing.T) {
	cases := []struct {
		in         string
		wantBucket string
		wantRegion string
	}{
		// Plain bucket name.
		{"my-bucket", "my-bucket", ""},
		{"unifyapps-sonydev-application-uploads-cloudstorage-2", "unifyapps-sonydev-application-uploads-cloudstorage-2", ""},
		// Virtual-hosted, modern dot.
		{"unifyapps-sonydev-application-uploads-cloudstorage-2.s3.ap-south-1.amazonaws.com", "unifyapps-sonydev-application-uploads-cloudstorage-2", "ap-south-1"},
		{"my-bucket.s3.ap-south-1.amazonaws.com", "my-bucket", "ap-south-1"},
		{"https://my-bucket.s3.eu-west-1.amazonaws.com/", "my-bucket", "eu-west-1"},
		{"http://my-bucket.s3.us-west-2.amazonaws.com/some/key.txt", "my-bucket", "us-west-2"},
		// Virtual-hosted, global (no region).
		{"my-bucket.s3.amazonaws.com", "my-bucket", ""},
		{"https://my-bucket.s3.amazonaws.com", "my-bucket", ""},
		// Virtual-hosted, legacy dash.
		{"my-bucket.s3-ap-south-1.amazonaws.com", "my-bucket", "ap-south-1"},
		// Virtual-hosted, dualstack.
		{"my-bucket.s3.dualstack.ap-south-1.amazonaws.com", "my-bucket", "ap-south-1"},
		// Transfer-acceleration endpoint — not a region.
		{"my-bucket.s3-accelerate.amazonaws.com", "my-bucket", ""},
		{"my-bucket.s3-accelerate.dualstack.amazonaws.com", "my-bucket", ""},
		// Website endpoint — region is the real region, "website" prefix stripped.
		{"my-bucket.s3-website-us-east-1.amazonaws.com", "my-bucket", "us-east-1"},
		// GovCloud region passes through unchanged.
		{"my-bucket.s3.us-gov-west-1.amazonaws.com", "my-bucket", "us-gov-west-1"},
		// Path-style.
		{"s3.amazonaws.com/my-bucket", "my-bucket", ""},
		{"s3.ap-south-1.amazonaws.com/my-bucket", "my-bucket", "ap-south-1"},
		{"https://s3.ap-south-1.amazonaws.com/my-bucket/key", "my-bucket", "ap-south-1"},
		{"s3-eu-west-1.amazonaws.com/my-bucket", "my-bucket", "eu-west-1"},
		// Dotted bucket name in virtual-hosted form (LastIndex handling).
		{"assets.media.s3.eu-central-1.amazonaws.com", "assets.media", "eu-central-1"},
		// Whitespace + trailing dot/port.
		{"  my-bucket.s3.ap-south-1.amazonaws.com  ", "my-bucket", "ap-south-1"},
		// Empty.
		{"", "", ""},
	}
	for _, c := range cases {
		gotB, gotR := ParseBucketInput(c.in)
		if gotB != c.wantBucket || gotR != c.wantRegion {
			t.Errorf("ParseBucketInput(%q) = (%q, %q), want (%q, %q)", c.in, gotB, gotR, c.wantBucket, c.wantRegion)
		}
	}
}

func TestGenerateBucketNamesSimple(t *testing.T) {
	names := generateBucketNames("example.com")
	if len(names) != 22 {
		t.Fatalf("generateBucketNames() len = %d, want 22", len(names))
	}
	expected := []string{
		"example",
		"example-backup",
		"example-backups",
		"example-dev",
		"example-development",
		"example-prod",
		"example-production",
		"example-staging",
		"example-test",
		"example-testing",
		"example-www",
		"example-uploads",
		"example-files",
		"example-assets",
		"example-media",
		"example-static",
		"example-public",
		"example-private",
		"www.example",
		"s3.example",
		"storage.example",
		"cdn.example",
	}
	for i, want := range expected {
		if names[i] != want {
			t.Errorf("generateBucketNames()[%d] = %q, want %q", i, names[i], want)
		}
	}
}

func TestGenerateBucketNamesSingleLabel(t *testing.T) {
	names := generateBucketNames("local")
	if len(names) != 22 {
		t.Fatalf("generateBucketNames() len = %d, want 22", len(names))
	}
	if names[0] != "local" {
		t.Errorf("generateBucketNames()[0] = %q, want %q", names[0], "local")
	}
}

func TestGenerateBucketNamesDotNet(t *testing.T) {
	names := generateBucketNames("example.net")
	if names[0] != "example" {
		t.Errorf("generateBucketNames()[0] = %q, want %q (TLD stripped)", names[0], "example")
	}
}

func TestGenerateBucketNamesDotOrg(t *testing.T) {
	names := generateBucketNames("example.org")
	if names[0] != "example" {
		t.Errorf("generateBucketNames()[0] = %q, want %q (TLD stripped)", names[0], "example")
	}
}

func TestGenerateBucketNamesDotIO(t *testing.T) {
	names := generateBucketNames("test.io")
	if names[0] != "test" {
		t.Errorf("generateBucketNames()[0] = %q, want %q (TLD stripped)", names[0], "test")
	}
}

func TestGenerateBucketNamesUppercase(t *testing.T) {
	names := generateBucketNames("EXAMPLE.COM")
	if names[0] != "example" {
		t.Errorf("generateBucketNames()[0] = %q, want %q (lowercased)", names[0], "example")
	}
}

func TestGenerateBucketNamesMultiTLD(t *testing.T) {
	// Only the first matching TLD suffix is stripped
	names := generateBucketNames("example.co.io")
	if names[0] != "example.co" {
		t.Errorf("generateBucketNames()[0] = %q, want %q (only .io stripped)", names[0], "example.co")
	}
}

func TestGenerateBucketNamesWWWPrefix(t *testing.T) {
	names := generateBucketNames("www.example.com")
	expected := []string{
		"www.example",
		"www.example-backup",
		"www.example-backups",
		"www.example-dev",
		"www.example-development",
		"www.example-prod",
		"www.example-production",
		"www.example-staging",
		"www.example-test",
		"www.example-testing",
		"www.example-www",
		"www.example-uploads",
		"www.example-files",
		"www.example-assets",
		"www.example-media",
		"www.example-static",
		"www.example-public",
		"www.example-private",
		"www.www.example",
		"s3.www.example",
		"storage.www.example",
		"cdn.www.example",
	}
	for i, want := range expected {
		if names[i] != want {
			t.Errorf("generateBucketNames()[%d] = %q, want %q", i, names[i], want)
		}
	}
}

func TestGenerateBucketNamesNoDot(t *testing.T) {
	names := generateBucketNames("mybucket")
	if names[0] != "mybucket" {
		t.Errorf("generateBucketNames()[0] = %q, want %q", names[0], "mybucket")
	}
}

// fakeBucket is a minimal S3 stand-in: public list + read of one existing
// object, public PUT, and a configurable DELETE status.
func fakeBucket(t *testing.T, deleteStatus int) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.EscapedPath())
		mu.Unlock()
		switch {
		case r.Method == "GET" && r.URL.Path == "/":
			_, _ = w.Write([]byte(`<ListBucketResult><Contents><Key>docs/a &amp; b.txt</Key></Contents></ListBucketResult>`))
		case r.Method == "HEAD" && r.URL.Path == "/docs/a & b.txt":
			w.WriteHeader(http.StatusOK)
		case r.Method == "PUT":
			w.WriteHeader(http.StatusOK)
		case r.Method == "GET":
			w.WriteHeader(http.StatusOK)
		case r.Method == "DELETE":
			w.WriteHeader(deleteStatus)
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestProbeBucketReadOnlyByDefault(t *testing.T) {
	srv, calls := fakeBucket(t, http.StatusNoContent)
	p := probeBucketBase(srv.Client(), srv.URL, "autoar-perm-test-1.txt", false, nil)
	if !p.List || !p.Read {
		t.Fatalf("list/read inference failed: %+v", p)
	}
	if p.Write || p.Delete || p.LeftoverKey != "" {
		t.Fatalf("read-only probe reported write/delete: %+v", p)
	}
	for _, c := range *calls {
		if strings.HasPrefix(c, "PUT") || strings.HasPrefix(c, "DELETE") {
			t.Fatalf("state-changing request sent without opt-in: %s", c)
		}
	}
}

func TestProbeBucketWriteCleanup(t *testing.T) {
	srv, _ := fakeBucket(t, http.StatusNoContent)
	p := probeBucketBase(srv.Client(), srv.URL, "autoar-perm-test-2.txt", true, nil)
	if !p.Write || !p.Delete || p.LeftoverKey != "" || p.cleanupNote() != "" {
		t.Fatalf("clean write probe: %+v", p)
	}
}

func TestProbeBucketWriteCleanupFailureReported(t *testing.T) {
	srv, calls := fakeBucket(t, http.StatusForbidden)
	p := probeBucketBase(srv.Client(), srv.URL, "autoar-perm-test-3.txt", true, nil)
	if !p.Write || p.Delete {
		t.Fatalf("write probe with denied delete: %+v", p)
	}
	if p.LeftoverKey != "autoar-perm-test-3.txt" || !strings.HasSuffix(p.LeftoverURL, "/autoar-perm-test-3.txt") {
		t.Fatalf("leftover object not reported: %+v", p)
	}
	if !strings.Contains(p.cleanupNote(), "test object left in bucket: autoar-perm-test-3.txt") {
		t.Fatalf("cleanup note = %q", p.cleanupNote())
	}
	deletes := 0
	for _, c := range *calls {
		if strings.HasPrefix(c, "DELETE") {
			deletes++
		}
	}
	if deletes != 2 {
		t.Fatalf("DELETE attempts = %d, want 2 (one retry)", deletes)
	}
}

func TestS3WriteProbeOptIn(t *testing.T) {
	t.Setenv(envS3WriteProbe, "")
	if s3WriteProbeAllowed() {
		t.Fatal("write probe must be off by default")
	}
	t.Setenv(envS3WriteProbe, "true")
	if !s3WriteProbeAllowed() {
		t.Fatal("opt-in env not honoured")
	}
}

package s3

import (
	"testing"
)

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

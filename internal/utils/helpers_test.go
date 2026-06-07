package utils

import "testing"

func TestExtractFirstHTTPURL(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{"empty string", "", ""},
		{"no url", "some text without url", ""},
		{"http url at start", "http://example.com/path", "http://example.com/path"},
		{"https url at start", "https://example.com/path", "https://example.com/path"},
		{"url in middle", "result: https://example.com/file.zip is ready", "https://example.com/file.zip"},
		{"url terminated by space", "http://example.com some trailing text", "http://example.com"},
		{"url terminated by newline", "http://example.com\nnext line", "http://example.com"},
		{"url terminated by quote", "\"https://example.com\"", "https://example.com"},
		{"multiple urls returns first", "http://first.com and https://second.com", "http://first.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractFirstHTTPURL(tt.input)
			if got != tt.expect {
				t.Errorf("ExtractFirstHTTPURL(%q) = %q, want %q", tt.input, got, tt.expect)
			}
		})
	}
}

func TestExtractR2ZipURLFromOutput(t *testing.T) {
	tests := []struct {
		name   string
		output string
		expect string
	}{
		{"empty output", "", ""},
		{"no match", "some log output\nanother line", ""},
		{"results zip uploaded", "Processing...\nResults zip uploaded: https://r2.example.com/file.zip\nDone.", "https://r2.example.com/file.zip"},
		{"zip file uploaded", "Zip file uploaded: https://r2.example.com/backup.zip", "https://r2.example.com/backup.zip"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractR2ZipURLFromOutput(tt.output)
			if got != tt.expect {
				t.Errorf("ExtractR2ZipURLFromOutput() = %q, want %q", got, tt.expect)
			}
		})
	}
}

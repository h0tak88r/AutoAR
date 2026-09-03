package apidocs

import (
	"encoding/json"
	"testing"
)

func TestParseSwagger20(t *testing.T) {
	doc := []byte(`{
		"swagger": "2.0",
		"info": {"title": "Demo", "version": "1.0"},
		"host": "api.example.com",
		"basePath": "/v2",
		"schemes": ["https"],
		"paths": {
			"/pets/{petId}": {
				"get": {
					"operationId": "getPet",
					"parameters": [
						{"name": "petId", "in": "path", "type": "integer"},
						{"name": "verbose", "in": "query", "type": "boolean", "default": "true"}
					]
				},
				"delete": {"operationId": "delPet"}
			},
			"/users/admin/list": {"get": {}}
		}
	}`)
	parsed, err := parseAPIDoc(doc, "https://api.example.com/v2/swagger.json")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.BaseURL != "https://api.example.com/v2" {
		t.Fatalf("BaseURL = %q", parsed.BaseURL)
	}
	if len(parsed.Paths) != 3 {
		t.Fatalf("paths = %d, want 3", len(parsed.Paths))
	}
	for _, pm := range parsed.Paths {
		u := pm.BuildURL(parsed.BaseURL)
		switch {
		case pm.Method == "GET" && pm.Path == "/pets/{petId}":
			if u != "https://api.example.com/v2/pets/1?verbose=true" {
				t.Fatalf("built URL = %q", u)
			}
		case pm.Method == "DELETE":
			if u != "https://api.example.com/v2/pets/1" {
				t.Fatalf("delete URL = %q", u)
			}
		}
	}
}

func TestParseOpenAPI30(t *testing.T) {
	doc := []byte(`{
		"openapi": "3.0.0",
		"info": {"title": "Demo3", "version": "2.0"},
		"servers": [{"url": "https://svc.internal.example.io/api"}],
		"paths": {
			"/accounts/{accountId}": {
				"get": {
					"parameters": [
						{"name": "accountId", "in": "path", "schema": {"example": "acct-42"}}
					]
				}
			}
		}
	}`)
	parsed, err := parseAPIDoc(doc, "https://example.com/openapi.json")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.BaseURL != "https://svc.internal.example.io/api" {
		t.Fatalf("BaseURL = %q", parsed.BaseURL)
	}
	pm := parsed.Paths[0]
	if u := pm.BuildURL(parsed.BaseURL); u != "https://svc.internal.example.io/api/accounts/acct-42" {
		t.Fatalf("URL = %q", pm.BuildURL(parsed.BaseURL))
	}
}

func TestParseRelativeServer(t *testing.T) {
	doc := []byte(`{"openapi":"3.0.0","servers":[{"url":"/api"}],"paths":{"/x":{"get":{}}}}`)
	parsed, err := parseAPIDoc(doc, "https://rel.example.com/docs/openapi.json")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.BaseURL != "https://rel.example.com/api" {
		t.Fatalf("BaseURL = %q", parsed.BaseURL)
	}
}

func TestRedactSecrets(t *testing.T) {
	in := `{"token":"eyJhbGciOiJIUzI1NiJ9.x.y","api_key":"sk_live_abcdef123456","data":[1,2]}`
	out := redact(in)
	b, _ := json.Marshal(out)
	s := string(b)
	for _, leak := range []string{"eyJhbGciOiJIUzI1NiJ9", "sk_live_abcdef123456"} {
		if contains := stringsContains(s, leak); contains {
			t.Fatalf("leaked %s in %s", leak, s)
		}
	}
}

func stringsContains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

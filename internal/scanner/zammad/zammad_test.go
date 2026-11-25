package zammad

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestFingerprint(t *testing.T) {
	if !Fingerprint(`<html><title>Support | Zammad</title>`) {
		t.Error("zammad homepage must fingerprint")
	}
	if Fingerprint(`<html>plain wordpress</html>`) {
		t.Error("non-zammad must not fingerprint")
	}
}

func TestIsVulnerableError(t *testing.T) {
	vuln := `[{"event":"error","data":{"error":"undefined method ` + "`run`" + ` for #<Sessions::Event::Base:0x000 @clients={...\"Cookie\"=>\"_zammad_session=abc\"}>..."}}]`
	if !IsVulnerableError(vuln) {
		t.Error("leaked inspect must be flagged vulnerable")
	}
	patched := `[{"event":"error","data":{"error":"The event could not be processed.","payload":{"event":"base"}}}]`
	if IsVulnerableError(patched) {
		t.Error("patched generic error must not be flagged")
	}
	if IsVulnerableError("random body without markers") {
		t.Error("unrelated body must not be flagged")
	}
}

func wsServer(t *testing.T, handler func(conn *websocket.Conn)) *httptest.Server {
	t.Helper()
	up := websocket.Upgrader{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != wsPath {
			http.NotFound(w, r)
			return
		}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		handler(c)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestProbeVulnerable(t *testing.T) {
	srv := wsServer(t, func(c *websocket.Conn) {
		_, _, err := c.ReadMessage()
		if err != nil {
			return
		}
		_ = c.WriteMessage(websocket.TextMessage,
			[]byte(`[{"event":"error","data":{"error":"undefined method run for #<Sessions::Event::Base:0x7f @clients={1=>{ \"Cookie\"=>\"x\" }}>..."}}]`))
	})
	res := Probe(t.Context(), srv.URL, 5*time.Second)
	if !res.Vulnerable {
		t.Fatalf("expected vulnerable, got %+v", res)
	}
}

func TestProbePatched(t *testing.T) {
	srv := wsServer(t, func(c *websocket.Conn) {
		_, _, err := c.ReadMessage()
		if err != nil {
			return
		}
		_ = c.WriteMessage(websocket.TextMessage,
			[]byte(`[{"event":"error","data":{"error":"The event could not be processed."}}]`))
	})
	res := Probe(t.Context(), srv.URL, 5*time.Second)
	if res.Vulnerable {
		t.Fatalf("patched server must not validate: %+v", res)
	}
	if !strings.Contains(res.Detail, "patched") {
		t.Errorf("detail = %q, want patched marker", res.Detail)
	}
}

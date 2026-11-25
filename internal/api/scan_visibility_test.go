package api

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/h0tak88r/AutoAR/internal/db"
)

func visCtx(t *testing.T, role, user string) *gin.Context {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("auth_role", role)
	c.Set("auth_sub", user)
	return c
}

func TestScanVisible(t *testing.T) {
	mine := &db.ScanRecord{ScanID: "s1", CreatedBy: "sabla"}
	sys := &db.ScanRecord{ScanID: "s2", CreatedBy: "system"}
	legacy := &db.ScanRecord{ScanID: "s3", CreatedBy: ""}

	// Admin sees everything.
	for _, rec := range []*db.ScanRecord{mine, sys, legacy, nil} {
		if !scanVisible(visCtx(t, "admin", "admin"), rec) {
			t.Errorf("admin must see scan %v", rec)
		}
	}
	// Viewer sees only their own.
	viewer := visCtx(t, "viewer", "sabla")
	if !scanVisible(viewer, mine) {
		t.Error("viewer must see own scan")
	}
	for _, rec := range []*db.ScanRecord{sys, legacy, nil} {
		if scanVisible(viewer, rec) {
			t.Errorf("viewer must NOT see scan owned by %q", rec.CreatedBy)
		}
	}
	// Viewer with no attached username sees nothing.
	if scanVisible(visCtx(t, "viewer", ""), mine) {
		t.Error("anonymous non-admin must see nothing")
	}
}

func TestFilterScansToOwner(t *testing.T) {
	in := []*db.ScanRecord{
		{ScanID: "a", CreatedBy: "sabla"},
		{ScanID: "b", CreatedBy: "system"},
		{ScanID: "c", CreatedBy: "samii"},
		{ScanID: "d", CreatedBy: ""},
	}
	got := filterScansToOwner(visCtx(t, "viewer", "sabla"), in)
	if len(got) != 1 || got[0].ScanID != "a" {
		t.Fatalf("viewer filter = %v; want only own scan", got)
	}
	if got := filterScansToOwner(visCtx(t, "admin", "admin"), in); len(got) != 4 {
		t.Fatalf("admin filter must keep all 4, got %d", len(got))
	}
	if got := filterScansToOwner(visCtx(t, "viewer", "samii"), in); len(got) != 1 || got[0].ScanID != "c" {
		t.Fatalf("second viewer filter = %v; want only c", got)
	}
}

func TestOwnScanOnlyWrapper(t *testing.T) {
	gin.SetMode(gin.TestMode)
	called := false
	h := ownScanOnly(func(c *gin.Context) { called = true })

	// Admin passes through without a DB lookup.
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: "anything"}}
	c.Set("auth_role", "admin")
	h(c)
	if !called {
		t.Error("admin request must reach the handler")
	}
}

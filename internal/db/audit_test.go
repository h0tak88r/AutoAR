package db

import (
	"path/filepath"
	"testing"
)

func TestAuditEventRoundTrip(t *testing.T) {
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "audit.db"))
	t.Setenv("AUTOAR_SILENT", "true")

	s := &SQLiteDB{}
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := s.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	if err := s.InsertAuditEvent(AuditEvent{Actor: "alice", Action: "scan.launch", Target: "example.com", Detail: "nuclei", IP: "1.2.3.4"}); err != nil {
		t.Fatalf("insert1: %v", err)
	}
	if err := s.InsertAuditEvent(AuditEvent{Actor: "bob", Action: "user.delete", Target: "carol"}); err != nil {
		t.Fatalf("insert2: %v", err)
	}

	all, err := s.ListAuditEvents(10, "", "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("want 2 events, got %d", len(all))
	}
	if all[0].Actor != "bob" { // newest first
		t.Errorf("expected newest (bob) first, got %q", all[0].Actor)
	}
	if all[1].IP != "1.2.3.4" || all[1].Detail != "nuclei" {
		t.Errorf("fields not round-tripped: ip=%q detail=%q", all[1].IP, all[1].Detail)
	}

	byActor, _ := s.ListAuditEvents(10, "alice", "")
	if len(byActor) != 1 || byActor[0].Action != "scan.launch" {
		t.Errorf("actor filter failed: %+v", byActor)
	}
	byAction, _ := s.ListAuditEvents(10, "", "user.delete")
	if len(byAction) != 1 || byAction[0].Actor != "bob" {
		t.Errorf("action filter failed: %+v", byAction)
	}
}

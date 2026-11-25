package api

import (
	"context"
	"testing"
)

func TestPipelineStoppedFollowsScanCancel(t *testing.T) {
	const id = "pipeline-stop-test"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ScansMutex.Lock()
	ActiveScans[id] = &ScanInfo{ScanID: id, Status: "running", Ctx: ctx, CancelFunc: cancel}
	ScansMutex.Unlock()
	t.Cleanup(func() {
		ScansMutex.Lock()
		delete(ActiveScans, id)
		ScansMutex.Unlock()
	})

	if err := pipelineStopped(id); err != nil {
		t.Fatalf("running scan reported stopped: %v", err)
	}
	if err := CancelScanByID(id); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if pipelineStopped(id) == nil {
		t.Fatal("cancelled scan must stop the pipeline loops")
	}
}

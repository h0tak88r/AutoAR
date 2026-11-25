package api

import (
	"strings"
	"testing"
)

// TestFullCorpusSweepGatedInPublicEdition verifies the engine-level guard: a
// full-corpus sweep (empty host list) is rejected in the public edition, so no
// path (manual run, watcher auto-run, rescan, boot-resume) can start one there.
// The gate returns before any scan work, so this does not execute nuclei.
func TestFullCorpusSweepGatedInPublicEdition(t *testing.T) {
	saved := editionName
	t.Cleanup(func() { editionName = saved })

	editionName = "public"
	err := runGlobalNucleiScanOpts("scan-edition-test", "id: test", globalScanOpts{})
	if err == nil || !strings.Contains(err.Error(), "private-edition") {
		t.Fatalf("public edition must reject a full-corpus sweep; got err=%v", err)
	}
}

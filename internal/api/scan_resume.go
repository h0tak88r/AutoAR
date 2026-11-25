package api

// Scans cut off by a restart (a deploy) continue instead of failing:
//
//	domain_run, subdomain_run  from the last completed phase (same scan id)
//	global nuclei sweeps        after the last finished batch (sweepCheckpoint):
//	                            manual "Run template" sweeps and the template
//	                            watcher's auto-runs
//
// Paused and cancelling scans stay failed (someone stopped them), and so do
// race passes (their host list isn't stored) and every other scan type —
// those are rescanned by hand. The deploy only waits for those.

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
	domainmod "github.com/h0tak88r/AutoAR/internal/scanner/domain"
	subdomainmod "github.com/h0tak88r/AutoAR/internal/scanner/subdomain"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// watcherSweepTarget is the target label of the template watcher's sweeps.
const watcherSweepTarget = "nuclei-templates-watch"

// resumeDelay lets the server finish starting before resumed scans queue up;
// resumeStagger spaces their starts, oldest first, so the oldest reaches the
// (unordered) global-sweep queue first.
var (
	resumeDelay   = 30 * time.Second
	resumeStagger = 3 * time.Second
)

// ResumeInterruptedScans continues the scans a restart cut off. recs are the
// rows that were still active before the startup reconcile marked them
// failed; the resumable ones are flipped back to running by the resume.
func ResumeInterruptedScans(recs []*db.ScanRecord) {
	if len(recs) == 0 {
		return
	}
	utils.SafeGo("scans:resume-after-restart", func() {
		time.Sleep(resumeDelay)
		resumeInterruptedScansNow(recs)
	})
}

func resumeInterruptedScansNow(recs []*db.ScanRecord) (resumed, failed []string) {
	recs = append([]*db.ScanRecord(nil), recs...)
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].StartedAt.Before(recs[j].StartedAt) }) // oldest first
	for _, rec := range recs {
		if rec == nil {
			continue
		}
		label := fmt.Sprintf("%s %s %s", utils.DiscordEscapeTrunc(rec.ScanType, 40), utils.DiscordEscapeTrunc(rec.Target, 120), discordCode(rec.ScanID, 80))
		fn, why := resumeFuncFor(rec)
		if fn == nil {
			failed = append(failed, label+" — "+why)
			continue
		}
		if err := startResumeScan(rec.ScanID, rec.ScanType, rec.Target, rec.Command, "system", fn); err != nil {
			failed = append(failed, label+" — "+err.Error())
			continue
		}
		resumed = append(resumed, label)
		time.Sleep(resumeStagger)
	}
	if len(resumed) == 0 && len(failed) == 0 {
		return
	}
	log.Printf("[resume] after restart: %d scan(s) resumed, %d left failed", len(resumed), len(failed))
	msg := "🔁 **AutoAR restarted**"
	if len(resumed) > 0 {
		msg += fmt.Sprintf("\nResumed %d scan(s) where they stopped:%s", len(resumed), bulletList(resumed, 8))
	}
	if len(failed) > 0 {
		msg += fmt.Sprintf("\nCan't resume %d (marked failed — rescan by hand):%s", len(failed), bulletList(failed, 8))
	}
	utils.SendMonitorWebhook(msg)
	return resumed, failed
}

// bulletList is up to max lines of a Discord bullet list.
func bulletList(items []string, max int) string {
	out := ""
	for i, it := range items {
		if i == max {
			return out + fmt.Sprintf("\n• … and %d more", len(items)-max)
		}
		out += "\n• " + it
	}
	return out
}

// resumeFuncFor is interruptedScanResume (a seam for tests).
var resumeFuncFor = interruptedScanResume

// interruptedScanResume returns how to continue a scan a restart cut off, or
// nil and why it can't be continued.
func interruptedScanResume(rec *db.ScanRecord) (func() error, string) {
	switch strings.ToLower(rec.Status) {
	case "running", "starting":
	default:
		return nil, "it was " + rec.Status + " when AutoAR stopped"
	}
	if fn := checkpointResumeFunc(rec.ScanType, rec.Target, rec.Command); fn != nil {
		return fn, ""
	}
	if !strings.EqualFold(rec.ScanType, "nuclei") {
		return nil, "no resume support for " + rec.ScanType + " scans"
	}
	if isRacePassTarget(rec.Target) {
		return nil, "a race pass's host list isn't stored"
	}
	template := commandTemplate(rec.Command)
	if template == "" {
		return nil, "the template isn't recorded in its command"
	}
	if filepath.IsAbs(template) {
		if _, err := os.Stat(template); err != nil {
			return nil, "its template is gone"
		}
	}
	scanID := rec.ScanID
	switch rec.Target {
	case "global-subdomains":
		return func() error { return runGlobalNucleiScan(scanID, template) }, ""
	case watcherSweepTarget:
		return func() error {
			nucleiWatchSweepBusy.Store(true) // no new watcher sweep while this one runs
			defer nucleiWatchSweepBusy.Store(false)
			revs := stagedTemplateRevs(template)
			return runGlobalNucleiScanOpts(scanID, template, globalScanOpts{
				Sandbox: true,
				OnFinish: func(totalHosts int) {
					utils.GuardedRun("nuclei-watch:quantify", func() { suspectFPQuantify(scanID, totalHosts, revs) })
				},
			})
		}, ""
	}
	return nil, "no resume support for nuclei scans of " + rec.Target
}

// checkpointResumeFunc continues a phase-checkpointed workflow under its own
// scan id (completed phases are skipped), replaying its stored options; nil
// for other scan types.
func checkpointResumeFunc(scanType, target, command string) func() error {
	skipFFuf := commandFlag(command, "skip_ffuf")
	switch strings.ToLower(strings.TrimSpace(scanType)) {
	case "domain_run":
		return func() error {
			_, e := domainmod.RunDomain(domainmod.ScanOptions{Domain: target, SkipFFuf: skipFFuf})
			return e
		}
	case "subdomain_run":
		return func() error {
			_, e := subdomainmod.RunSubdomainWithOptions(target, subdomainmod.RunOptions{SkipFFuf: skipFFuf})
			return e
		}
	}
	return nil
}

// commandTemplate is the template a nuclei scan's stored command records
// ("inprocess:nuclei target=… template=<path or id>").
func commandTemplate(command string) string {
	_, t, _ := strings.Cut(command, " template=")
	return strings.TrimSpace(t)
}

var templateIDLineRE = regexp.MustCompile(`(?m)^id:\s*["']?([^"'\s]+)`)

// stagedTemplateRevs rebuilds the watcher's template-id → revision map from
// the templates it staged for the sweep (the files hold each raw template).
func stagedTemplateRevs(dir string) map[string]string {
	revs := map[string]string{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return revs
	}
	for _, e := range entries {
		if e.IsDir() || !(strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml")) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		if m := templateIDLineRE.FindSubmatch(raw); m != nil {
			revs[string(m[1])] = nucleiTemplateRevKey(string(m[1]), string(raw))
		}
	}
	return revs
}

// sweepCheckpoint is saved after every finished batch of a global nuclei
// sweep, in the scan's results dir (a dotfile, so it is never indexed as an
// artifact). It only outlives the sweep when the process is killed — any
// return from the sweep removes it.
type sweepCheckpoint struct {
	LastID   int64 `json:"last_id"`   // last host row id of the finished batches
	Total    int   `json:"total"`     // hosts in the whole sweep
	Batches  int   `json:"batches"`   // batches finished
	Scanned  int   `json:"scanned"`   // hosts in those batches
	OutBytes int64 `json:"out_bytes"` // size of the output after them
}

func sweepCheckpointPath(scanID string) string {
	return filepath.Join(utils.GetScanResultsDir(scanID), ".sweep-checkpoint.json")
}

func loadSweepCheckpoint(scanID string) (sweepCheckpoint, bool) {
	var ck sweepCheckpoint
	raw, err := os.ReadFile(sweepCheckpointPath(scanID))
	if err != nil || json.Unmarshal(raw, &ck) != nil || ck.Total <= 0 {
		return sweepCheckpoint{}, false
	}
	return ck, true
}

func saveSweepCheckpoint(scanID string, ck sweepCheckpoint) {
	p := sweepCheckpointPath(scanID)
	raw, _ := json.Marshal(ck)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err == nil {
		if err = os.WriteFile(p+".tmp", raw, 0o644); err == nil {
			err = os.Rename(p+".tmp", p)
		}
		if err == nil {
			return
		}
	}
	stdLog(scanID, "[WARN] could not save the sweep checkpoint — a restart would start this sweep over")
}

func clearSweepCheckpoint(scanID string) { _ = os.Remove(sweepCheckpointPath(scanID)) }

// prepareSweepOutput readies a sweep's output file and returns the hits
// already in it. Resumed: hits past the checkpoint came from the batch that
// was cut off (it runs again), so they are cut. A sweep that restarts
// without a checkpoint starts a fresh file; the old one is kept beside it.
func prepareSweepOutput(scanID, outPath string, ck sweepCheckpoint, resumed bool) int64 {
	size := fileSize(outPath)
	if !resumed {
		if size > 0 {
			aside := outPath + ".interrupted-" + time.Now().Format("20060102150405")
			if os.Rename(outPath, aside) == nil {
				stdLog(scanID, "[INFO] Starting over: the output of the interrupted run was moved to %s", filepath.Base(aside))
			}
		}
		return 0
	}
	if size > ck.OutBytes {
		_ = os.Truncate(outPath, ck.OutBytes)
	}
	n, _ := countLinesStreaming(outPath, math.MaxInt64)
	return int64(n)
}

func fileSize(path string) int64 {
	if st, err := os.Stat(path); err == nil {
		return st.Size()
	}
	return 0
}

// hostBatches is a global sweep's live-host dump: temp files of at most
// batchMax hosts, with the last host row id of each batch (the checkpoint
// cursor) and how many hosts each holds.
type hostBatches struct {
	files []string
	ends  []int64
	hosts []int
	total int
}

func (b *hostBatches) remove() {
	for _, f := range b.files {
		os.Remove(f)
	}
}

// Seams for tests: the live-host pages and the retry pause.
var (
	listLiveHostsAfter = db.ListLiveSubdomainsAfter
	dumpRetryPause     = 2 * time.Second
)

// dumpLiveHostBatches writes the live hosts after cursor to batch files.
// Keyset pages over live hosts (row id cursor): no per-page re-COUNT under a
// short query timeout, and rows inserted mid-dump can't shift later pages.
// A batch only ends on a page boundary, so its last id is a page cursor. A
// DB error fails the dump (after a couple of retries) rather than sweeping a
// truncated host list.
func dumpLiveHostBatches(scanID string, cursor int64, batchMax, pageSize int) (*hostBatches, error) {
	b := &hostBatches{}
	var cur *os.File
	n := 0
	fail := func(err error) (*hostBatches, error) {
		if cur != nil {
			cur.Close()
		}
		b.remove()
		return nil, err
	}
	newBatch := func() error {
		f, err := os.CreateTemp("", "global-nuclei-targets-*.txt")
		if err != nil {
			return fmt.Errorf("failed to create temp file: %w", err)
		}
		b.files = append(b.files, f.Name())
		cur, n = f, 0
		return nil
	}
	if err := newBatch(); err != nil {
		return fail(err)
	}
	for {
		// liveOnly: only hosts already probed live via httpx. Each is written as
		// its stored scheme-prefixed URL (https://host), so nuclei runs the
		// template directly against it and never re-probes (no httpx step).
		var (
			subs []db.GlobalSubdomain
			next int64
			err  error
		)
		for attempt := 0; attempt < 3; attempt++ {
			if subs, next, err = listLiveHostsAfter(cursor, pageSize); err == nil {
				break
			}
			time.Sleep(time.Duration(attempt+1) * dumpRetryPause)
		}
		if err != nil {
			stdLog(scanID, "[ERROR] live-host dump failed after %d host(s): %v", b.total, err)
			return fail(fmt.Errorf("live-host dump failed after %d host(s) — scan aborted rather than run on a partial list: %w", b.total, err))
		}
		if len(subs) == 0 {
			break
		}
		if n > 0 && n+len(subs) > batchMax {
			cur.Close()
			b.ends, b.hosts = append(b.ends, cursor), append(b.hosts, n)
			if err := newBatch(); err != nil {
				return fail(err)
			}
		}
		cursor = next
		for _, s := range subs {
			target := s.BestURL()
			if target == "" {
				target = s.Subdomain
			}
			if target == "" {
				continue
			}
			cur.WriteString(target + "\n")
			n++
			b.total++
		}
	}
	cur.Close()
	b.ends, b.hosts = append(b.ends, cursor), append(b.hosts, n)
	return b, nil
}

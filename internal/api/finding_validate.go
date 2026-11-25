package api

// Agent validation of selected findings. The operator picks findings on the
// Findings page (or via MCP) and the AI agent validates each one with its
// full tool belt — bash (curl, python3, nmap, sqlmap, jq, dig), every AutoAR
// platform tool and the skill guides — under non-destructive rules, then
// records a verdict with the evidence it gathered. One finding at a time;
// the transcript is a normal AI Agent session (validate-f<id>-<ts>).

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/h0tak88r/AutoAR/internal/aiagent"
	"github.com/h0tak88r/AutoAR/internal/brain"
	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

const findingValidateMaxBatch = 25

// Seams for tests.
var (
	agentValidateFn = aiagent.Validate
	fvNotify        = utils.SendMonitorWebhook
)

var (
	fvQueueMu  sync.Mutex
	fvQueue    []int64
	fvInQueue  = map[int64]bool{}
	fvWorkerOn bool
	fvCurrent  int64
)

// attachValidations sets each finding's agent validation (best-effort).
func attachValidations(fs ...*db.Finding) {
	ids := make([]int64, 0, len(fs))
	for _, f := range fs {
		if f != nil {
			ids = append(ids, f.ID)
		}
	}
	m, err := db.FindingValidationsFor(ids)
	if err != nil {
		return
	}
	for _, f := range fs {
		if f != nil {
			f.Validation = m[f.ID]
		}
	}
}

// enqueueFindingValidation queues one finding (deduped) and starts the worker.
func enqueueFindingValidation(id int64) bool {
	fvQueueMu.Lock()
	if fvInQueue[id] || fvCurrent == id {
		fvQueueMu.Unlock()
		return false
	}
	fvInQueue[id] = true
	fvQueue = append(fvQueue, id)
	start := !fvWorkerOn
	fvWorkerOn = true
	fvQueueMu.Unlock()
	_ = db.SaveFindingValidation(&db.FindingValidation{FindingID: id, Status: "queued", QueuedAt: time.Now().UTC().Unix()})
	if start {
		utils.SafeGo("finding-validate:worker", fvWorker)
	}
	return true
}

func fvWorker() {
	// Only a panic out of the loop needs this: on a normal exit the flag is
	// already off, and clearing it again could disown a worker an enqueue
	// started in between (two workers would then run at once).
	exited := false
	defer func() {
		if !exited {
			fvQueueMu.Lock()
			fvWorkerOn, fvCurrent = false, 0
			fvQueueMu.Unlock()
		}
	}()
	for {
		fvQueueMu.Lock()
		if len(fvQueue) == 0 {
			fvWorkerOn, exited = false, true
			fvQueueMu.Unlock()
			return
		}
		id := fvQueue[0]
		fvQueue = fvQueue[1:]
		delete(fvInQueue, id)
		fvCurrent = id
		fvQueueMu.Unlock()
		utils.GuardedRun(fmt.Sprintf("finding-validate:%d", id), func() { validateFindingWithAgent(id) })
		fvQueueMu.Lock()
		fvCurrent = 0
		fvQueueMu.Unlock()
	}
}

// findingScopeLine describes what the platform catalog knows about a host.
func findingScopeLine(host string) string {
	programs := raceProgramsForHost(raceHostOf(host))
	if len(programs) == 0 {
		return "no catalog program covers this host — confirm scope before doing anything"
	}
	p := programs[0]
	state := "IN SCOPE"
	switch {
	case !p.InScope:
		state = "listed OUT OF SCOPE"
	case catalogProgramInactive(programPauseStates(), p) != "":
		state = "in scope but the program is " + catalogProgramInactive(programPauseStates(), p)
	}
	return fmt.Sprintf("%s — %s %s (matched %s)", state, p.Source, p.Handle, p.MatchedDomain)
}

// validateFindingWithAgent runs one validation and stores the result.
func validateFindingWithAgent(id int64) {
	now := time.Now().UTC().Unix()
	v, _ := db.GetFindingValidation(id)
	if v == nil {
		v = &db.FindingValidation{FindingID: id, QueuedAt: now}
	}
	fail := func(msg string) {
		v.Status, v.Error, v.FinishedAt = "error", msg, time.Now().UTC().Unix()
		_ = db.SaveFindingValidation(v)
	}
	f, err := db.GetFinding(id)
	if err != nil || f == nil {
		fail("finding not found")
		return
	}
	if !brain.Available() {
		fail("no AI provider key configured")
		return
	}
	v.Status, v.StartedAt, v.FinishedAt, v.Error = "running", now, 0, ""
	v.Verdict, v.Summary, v.Evidence, v.Reproduction, v.NextSteps, v.Steps = "", "", "", "", "", 0
	v.SessionID = fmt.Sprintf("validate-f%d-%d", id, now)
	_ = db.SaveFindingValidation(v)

	aiReview := ""
	if f.AI != nil && f.AI.Verdict != "" {
		aiReview = fmt.Sprintf("%s (%d%% confidence): %s", f.AI.Verdict, f.AI.Confidence, clipText(f.AI.Reason, 600))
	}
	host := firstNonEmptyStr(f.Host, raceHostOf(f.MatchedAt))
	// Hand the agent the exact nuclei template it matched (when resolvable) so it
	// reproduces the request + matcher instead of guessing from the matched URL.
	_, templateYAML := nucleiTemplateForFinding(f)
	brief := aiagent.ValidationBrief(f.ID, f.Title, host, f.MatchedAt, f.TemplateID, f.CVE, f.Severity, f.Module,
		f.Evidence, aiReview, findingScopeLine(host), templateYAML)
	res, steps, err := agentValidateFn(v.SessionID, brief)
	v.Steps = len(steps)
	if err != nil {
		fail("agent: " + err.Error())
		return
	}
	v.Status, v.FinishedAt = "done", time.Now().UTC().Unix()
	v.Verdict, v.Confidence, v.Severity, v.Reportable = res.Verdict, res.Confidence, res.Severity, res.Reportable
	v.Summary, v.Evidence, v.Reproduction, v.NextSteps = res.Summary, res.Evidence, res.Reproduction, res.NextSteps
	if err := db.SaveFindingValidation(v); err != nil {
		logger.GetLogger().Infof("[VALIDATE] finding %d: save failed: %v", id, err)
	}
	if res.Verdict == "true_positive" || res.Verdict == "likely" {
		// The report goes to the findings channel with the draft attached;
		// the short monitor line is the fallback when that post fails.
		if reportValidatedFindingFn != nil {
			if err := reportValidatedFindingFn(f, v, host); err == nil {
				return
			} else {
				logger.GetLogger().Infof("[VALIDATE] finding %d: findings-channel report failed: %v", id, err)
			}
		}
		icon := "🧪"
		if res.Verdict == "true_positive" && res.Reportable {
			icon = "✅"
		}
		fvNotify(fmt.Sprintf("%s **Agent validated finding #%d** — %s on `%s`: **%s** (%d%%)%s\n%s",
			icon, id, utils.DiscordEscapeTrunc(f.Title, 120), discordSpanText(host, 120), strings.ReplaceAll(res.Verdict, "_", " "),
			res.Confidence, map[bool]string{true: " · reportable", false: ""}[res.Reportable], utils.DiscordEscapeTrunc(res.Summary, 600)))
	}
}

// POST /api/findings/agent-validate {ids:[...]} — queue findings for the AI
// agent's tool-backed validation (admin).
func apiFindingsAgentValidate(c *gin.Context) {
	var body struct {
		IDs []int64 `json:"ids"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || len(body.IDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ids required"})
		return
	}
	if len(body.IDs) > findingValidateMaxBatch {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("at most %d findings per batch — each one is a full agent session", findingValidateMaxBatch)})
		return
	}
	if !brain.Available() {
		c.JSON(http.StatusPreconditionFailed, gin.H{"error": "no AI provider key configured — add one in Settings ▸ AI Providers"})
		return
	}
	queued, missing := 0, 0
	for _, id := range body.IDs {
		if f, err := db.GetFinding(id); err != nil || f == nil {
			missing++
			continue
		}
		if enqueueFindingValidation(id) {
			queued++
		}
	}
	audit(c, "findings.agent_validate", "", fmt.Sprintf("%d queued", queued))
	c.JSON(http.StatusAccepted, gin.H{"queued": queued, "missing": missing})
}

// validationQueueSnapshot reports the current and queued finding ids.
func validationQueueSnapshot() (current int64, queued []int64) {
	fvQueueMu.Lock()
	defer fvQueueMu.Unlock()
	return fvCurrent, append([]int64(nil), fvQueue...)
}

// StartFindingValidations re-queues, shortly after boot, the validations a
// restart interrupted.
func StartFindingValidations() {
	utils.SafeGo("finding-validate:resume", func() {
		time.Sleep(time.Minute)
		resumeFindingValidations()
	})
}

// resumeFindingValidations re-queues validations a restart interrupted.
func resumeFindingValidations() {
	rows, err := db.ListFindingValidations(200, "queued", "running")
	if err != nil {
		return
	}
	for _, v := range rows {
		enqueueFindingValidation(v.FindingID)
	}
}

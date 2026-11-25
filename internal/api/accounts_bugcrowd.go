package api

import (
	"time"

	"github.com/h0tak88r/AutoAR/internal/accounts"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// StartBugcrowdSessionKeeper checks every Bugcrowd account that can sign in
// (email + password) shortly after boot and then every 6 hours, signing in
// again when its session has expired — so program fetches and the Settings
// tag find a working session instead of renewing it mid-fetch.
func StartBugcrowdSessionKeeper() {
	utils.SafeGo("accounts:bugcrowd-keeper", func() {
		time.Sleep(3 * time.Minute)
		for {
			keepBugcrowdSessions()
			time.Sleep(6 * time.Hour)
		}
	})
}

func keepBugcrowdSessions() {
	for _, a := range accounts.For("bc") {
		if a.Email == "" || a.Password == "" {
			continue // a pasted session only; nothing to renew it with
		}
		_, status, detail := accounts.BugcrowdSession(a, false)
		if status != "valid" {
			logger.GetLogger().Infof("[accounts] Bugcrowd %q: %s — %s", a.Label, status, detail)
		}
	}
}

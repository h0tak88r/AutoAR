package api

// "Remind me later" on a finding: defer it and resurface it when the window
// passes — e.g. a CVE a program only accepts 30-90 days after publication. A
// daily worker posts the due ones to the findings Discord and clears the timer.

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

const remindMaxDays = 365

// POST /api/findings/:id/remind {days:int} — set a reminder N days out, or
// clear it with days<=0. Admin only.
func apiFindingRemind(c *gin.Context) {
	f, ok := findingFromParam(c)
	if !ok {
		return
	}
	var body struct {
		Days int `json:"days"`
	}
	_ = c.ShouldBindJSON(&body)
	var at int64
	if body.Days > 0 {
		if body.Days > remindMaxDays {
			body.Days = remindMaxDays
		}
		at = time.Now().UTC().Add(time.Duration(body.Days) * 24 * time.Hour).Unix()
	}
	if err := db.SetFindingReminder(f.ID, at); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	detail := "cleared"
	if at > 0 {
		detail = fmt.Sprintf("in %d day(s)", body.Days)
	}
	audit(c, "finding.remind", fmt.Sprintf("#%d", f.ID), detail)
	c.JSON(http.StatusOK, gin.H{"id": f.ID, "remind_at": at})
}

// StartFindingReminders posts due reminders to Discord, shortly after boot and
// then daily, clearing each timer so it fires once.
func StartFindingReminders() {
	utils.SafeGo("findings:reminders", func() {
		time.Sleep(2 * time.Minute)
		for {
			fireDueReminders()
			time.Sleep(6 * time.Hour)
		}
	})
}

func fireDueReminders() {
	rows, err := db.DueFindingReminders(time.Now().UTC().Unix(), 100)
	if err != nil || len(rows) == 0 {
		return
	}
	for _, f := range rows {
		host := firstNonEmptyStr(f.Host, raceHostOf(f.MatchedAt))
		msg := fmt.Sprintf("⏰ **Reminder** — finding #%d is due to revisit\n**%s**%s%s",
			f.ID, utils.DiscordEscapeTrunc(f.Title, 150),
			map[bool]string{true: "\nHost: " + discordSpanText(host, 120), false: ""}[host != ""],
			map[bool]string{true: "\nCVE: " + utils.DiscordEscapeTrunc(f.CVE, 40), false: ""}[f.CVE != ""])
		if f.Program != "" {
			msg += "\nProgram: " + utils.DiscordEscapeTrunc(strings.TrimSpace(f.Platform+" "+f.Program), 80)
		}
		utils.SendPurposeWebhookErr("findings", msg)
		if err := db.SetFindingReminder(f.ID, 0); err != nil {
			logger.GetLogger().Infof("[reminders] finding %d: clear failed: %v", f.ID, err)
		}
	}
	logger.GetLogger().Infof("[reminders] fired %d due reminder(s)", len(rows))
}

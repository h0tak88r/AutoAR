package api

import (
	"strings"

	"github.com/h0tak88r/AutoAR/internal/accounts"
	scopemod "github.com/h0tak88r/AutoAR/internal/scanner/scope"
	"github.com/sw33tLie/bbscope/pkg/scope"
)

// fetchYWHPrograms fetches YesWeHack programs (with in-scope assets) across every
// configured YWH account and merges them, so YesWeHack shows up on the Programs
// page and feeds the root pipeline just like HackerOne/Bugcrowd/Intigriti. Uses
// bbscope's YesWeHack client via scopemod.FetchScope. includeScope is accepted for
// signature parity with the other fetchers — bbscope always returns scope.
func fetchYWHPrograms(bbpOnly, includeScope bool) ([]ProgramSummary, error) {
	_ = includeScope
	accts := accounts.For("ywh")
	if len(accts) == 0 {
		return nil, nil
	}
	var merged []ProgramSummary
	idx := map[string]int{}
	var firstErr error
	for _, a := range accts {
		if a.Token == "" && (a.Email == "" || a.Password == "") {
			continue
		}
		programs, err := scopemod.FetchScope(scopemod.Options{
			Platform:   scopemod.PlatformYesWeHack,
			Token:      a.Token,
			Email:      a.Email,
			Password:   a.Password,
			Categories: "all",
			BBPOnly:    bbpOnly,
			IncludeOOS: true,
		})
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		var summaries []ProgramSummary
		for _, pd := range programs {
			if s, ok := ywhProgramDataToSummary(pd); ok {
				summaries = append(summaries, s)
			}
		}
		merged = mergeProgramsByHandle(merged, idx, summaries, a.Label)
	}
	if len(merged) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return merged, nil
}

// ywhProgramDataToSummary converts a bbscope ProgramData (URL + scope) into a
// ProgramSummary. bbscope carries no program name, so the URL slug is the handle.
func ywhProgramDataToSummary(pd scope.ProgramData) (ProgramSummary, bool) {
	handle := ywhHandleFromURL(pd.Url)
	s := ProgramSummary{
		Platform:       "ywh",
		Handle:         handle,
		Name:           handle,
		URL:            pd.Url,
		OffersBounties: true, // BBPOnly filter already applied upstream
	}
	for _, e := range pd.InScope {
		t := strings.TrimSpace(e.Target)
		if t == "" {
			continue
		}
		s.ScopeTargets++
		s.Assets = append(s.Assets, t)
		if s.LatestTarget == "" {
			s.LatestTarget = t
			s.LatestTargetBrief = strings.TrimSpace(e.Description)
		}
	}
	return s, pd.Url != "" || s.ScopeTargets > 0
}

func ywhHandleFromURL(u string) string {
	u = strings.TrimRight(strings.TrimSpace(u), "/")
	if i := strings.LastIndex(u, "/"); i >= 0 && i < len(u)-1 {
		return u[i+1:]
	}
	return u
}

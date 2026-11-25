package api

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
)

// Limits shared by the targeted nuclei pass (public) and the PoC-day pipeline
// (private). Kept in a build-tag-free file so the public targeted runner still
// has them when the edge files are compiled out.
const (
	pocdayDefaultHostCap = 2000
	pocdayPassTimeout    = 25 * time.Minute
)

// pocdayHostCap is the max number of hosts a single targeted pass will scan
// (POCDAY_HOST_CAP env/setting override, else the default).
func pocdayHostCap() int {
	for _, v := range []string{os.Getenv("POCDAY_HOST_CAP"), func() string { s, _ := db.GetSetting("POCDAY_HOST_CAP"); return s }()} {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 && n <= 20000 {
			return n
		}
	}
	return pocdayDefaultHostCap
}

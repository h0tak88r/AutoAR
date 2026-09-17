package utils

import (
	"os"
	"strconv"
)

// GetThreads resolves the worker/host concurrency for a scan phase key
// (e.g. "nuclei"). Mirrors GetTimeout:
//
//  1. DB settings table  (key = "threads_<key>") — set via the dashboard Settings page
//  2. Environment variable  (AUTOAR_THREADS_<KEY>)
//  3. defaultVal
//
// The result is clamped to [min, max] regardless of source so a fat-fingered
// value can never push the engine past file-descriptor or memory limits.
// Uses the same injected dbGetSetting as GetTimeout (InitTimeoutDB wires both).
func GetThreads(key string, defaultVal, min, max int) int {
	v := defaultVal
	if dbGetSetting != nil {
		if s, err := dbGetSetting("threads_" + lowerKey(key)); err == nil && s != "" {
			if n, err := strconv.Atoi(s); err == nil {
				v = n
			}
		}
	}
	if v == defaultVal { // DB miss or unparseable — try env
		if s := os.Getenv("AUTOAR_THREADS_" + upperKey(key)); s != "" {
			if n, err := strconv.Atoi(s); err == nil {
				v = n
			} else {
				GetLogger().Warnf("[WARN] invalid value for AUTOAR_THREADS_%s: %q — using default %d", upperKey(key), s, defaultVal)
			}
		}
	}
	if v < min {
		v = min
	}
	if v > max {
		v = max
	}
	return v
}

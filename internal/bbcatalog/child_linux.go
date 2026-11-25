//go:build linux

package bbcatalog

import (
	"os/exec"
	"syscall"
)

// setChildAttrs makes the kernel SIGKILL a disposable child if the API
// process dies first, so an orphaned bbscope fetch never keeps running (and,
// on Postgres, never keeps holding the catalog-sync advisory lock) after a
// restart.
func setChildAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}

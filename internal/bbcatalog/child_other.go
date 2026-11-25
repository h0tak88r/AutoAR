//go:build !linux

package bbcatalog

import "os/exec"

// setChildAttrs is a no-op off Linux (no parent-death signal).
func setChildAttrs(cmd *exec.Cmd) {}

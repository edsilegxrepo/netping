//go:build !windows

package printers

import "os/exec"

func setDetachedProcess(cmd *exec.Cmd) {
}

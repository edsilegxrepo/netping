//go:build !windows

package printers

// EnableVirtualTerminalProcessing on non-Windows platforms always returns true
// as POSIX terminals support ANSI escape sequences natively.
func EnableVirtualTerminalProcessing() bool {
	return true
}

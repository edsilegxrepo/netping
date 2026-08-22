//go:build windows

package printers

import (
	"os"

	"golang.org/x/sys/windows"
)

// EnableVirtualTerminalProcessing attempts to enable VT100 / ANSI escape sequence
// processing on the standard output console for Windows.
// Returns true if VT processing is successfully enabled, false otherwise.
func EnableVirtualTerminalProcessing() bool {
	handle := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return false
	}
	mode |= windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
	return windows.SetConsoleMode(handle, mode) == nil
}

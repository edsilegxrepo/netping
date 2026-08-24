//go:build windows

package probers

import "syscall"

func setSocketTTL(fd uintptr, ttl int) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, 4, ttl)
}

// Package harden holds process hardening helpers.
package harden

import "syscall"

// DisableCoreDumps sets the core file size limit to zero.
func DisableCoreDumps() error {
	return syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
}

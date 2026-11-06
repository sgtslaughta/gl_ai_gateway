package harden

import (
	"syscall"
	"testing"
)

func TestDisableCoreDumps(t *testing.T) {
	if err := DisableCoreDumps(); err != nil {
		t.Fatal(err)
	}
	var l syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &l); err != nil || l.Cur != 0 {
		t.Fatal(l, err)
	}
}

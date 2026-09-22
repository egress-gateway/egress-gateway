package daemon

import (
	"os/exec"
	"syscall"
)

func configureProcess(cmd *exec.Cmd) {
	// Also kill the direct child if upstream OPA terminates the process on a
	// listener failure; PID 1/container shutdown covers the remaining namespace.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
}

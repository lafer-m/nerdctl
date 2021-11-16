package proxy

import (
	"net"
	"os"
	"syscall"
)

type userlandProxy interface {
	Start() error
	Stop() error
	PID() int
}

func NewProxyCommand(proto string, hostIP net.IP, hostPort int, containerIP net.IP, containerPort int, proxyPath string) (userlandProxy, error) {
	return newProxyCommand(proto, hostIP, hostPort, containerIP, containerPort, proxyPath)
}

func SignalStop(pid int) error {
	return syscall.Kill(pid, os.Interrupt.(syscall.Signal))
}

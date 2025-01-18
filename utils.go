package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

var exitOnce sync.Once

func cleanBpf(cancel context.CancelFunc, wg *sync.WaitGroup) {
	exitOnce.Do(func() {
		cancel()
		done := make(chan struct{})

		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}

	})
}

func getServerInfo(ip net.IP, port uint16) (int, string, int, error) {

	var ipStr string

	if ip.Equal(net.ParseIP("::")) {
		return 0, "", 0, fmt.Errorf("getServerInfo(): special ip not allowed %s", ip.String())
	}
	ipv4 := ip.To4()
	if ipv4 != nil {
		if ipv4[0] == 0 {
			return 0, "", 0, fmt.Errorf("getServerInfo(): special ip not allowed %s", ip.String())
		}
		ipStr = ip.String()
	} else {
		ipStr = fmt.Sprintf("[%s]", ipStr)
	}

	cmd := exec.Command("sh", "-c", fmt.Sprintf("lsof -a -iTCP@%s:%d -sTCP:LISTEN -Ffc", ipStr, port))
	stdout, err := cmd.Output()
	if err != nil {
		return 0, "", 0, fmt.Errorf("getServerInfo(): lsof: server listening on %s %d not found", ip, port)
	}

	lines := strings.Split(string(stdout), "\n")
	pid, err := strconv.Atoi(lines[0][1:])
	if err != nil {
		return 0, "", 0, fmt.Errorf("getServerInfo(): Atoi PID: %v", err)
	}

	command := lines[1][1:]
	fd, err := strconv.Atoi(lines[2][1:])
	if err != nil {
		return 0, "", 0, fmt.Errorf("getServerInfo(): Atoi FD: %v", err)
	}

	return pid, command, fd, nil
}

func exit(err *error) {
	if err != nil && *err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", (*err).Error())
		os.Exit(1)
	}
}

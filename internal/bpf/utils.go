package bpf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
)

const (
	AF_INET  = 2
	AF_INET6 = 10
)

func CheckKernelFeatures() error {

	if err := features.HaveMapType(ebpf.RingBuf); err != nil {
		if errors.Is(err, ebpf.ErrNotSupported) {
			return fmt.Errorf("BPF_MAP_TYPE_RINGBUF map type is not supported")
		}
		return fmt.Errorf("CheckKernelFeatures(): %w", err)
	}

	if err := features.HaveMapType(ebpf.Hash); err != nil {
		if errors.Is(err, ebpf.ErrNotSupported) {
			return fmt.Errorf("BPF_MAP_TYPE_HASH map type is not supported")
		}
		return fmt.Errorf("CheckKernelFeatures(): %w", err)
	}

	if err := features.HaveProgramType(ebpf.TracePoint); err != nil {
		if errors.Is(err, ebpf.ErrNotSupported) {
			return fmt.Errorf("TracePoint program type is not supported")
		}
		return fmt.Errorf("CheckKernelFeatures(): %w", err)
	}

	return nil
}

func LoadPrograms(ctx context.Context, wg *sync.WaitGroup, pid uint32, fd int64, dAddr net.IP, dPort uint16) (*litmObjects, error) {
	var objs litmObjects
	var err error

	defer func() {
		if err == nil {
			go func() {
				defer wg.Done()
				<-ctx.Done()
				objs.Close()
			}()
		} else {
			wg.Done()
		}
	}()

	var afFilter uint8 = 0

	// Check provided dAddr
	if dAddr.To4() != nil {
		afFilter = AF_INET
	} else if dAddr.To16() != nil {
		afFilter = AF_INET6
	} else {
		return nil, fmt.Errorf("LoadPrograms(): dAddr is not a valid IP %s", dAddr)
	}

	// Load the object file from disk using a bpf2go-generated scaffolding.
	spec, err := loadLitm()
	if err != nil {
		return nil, fmt.Errorf("LoadPrograms(): %w", err)
	}

	err = spec.Variables["PID_FILTER"].Set(pid)
	if err != nil {
		return nil, fmt.Errorf("LoadPrograms(): %w", err)
	}

	err = spec.Variables["FD_FILTER"].Set(fd)
	if err != nil {
		return nil, fmt.Errorf("LoadPrograms(): %w", err)
	}

	err = spec.Variables["PORT_FILTER"].Set(dPort)
	if err != nil {
		return nil, fmt.Errorf("LoadPrograms(): %w", err)
	}

	err = spec.Variables["AF_FILTER"].Set(afFilter)
	if err != nil {
		return nil, fmt.Errorf("LoadPrograms(): %w", err)
	}

	if afFilter == AF_INET {
		err = spec.Variables["IPV4_FILTER"].Set(dAddr.To4())
		if err != nil {
			return nil, fmt.Errorf("LoadPrograms(): %w", err)
		}
	} else {
		err = spec.Variables["IPV6_FILTER"].Set(dAddr.To16())
		if err != nil {
			return nil, fmt.Errorf("LoadPrograms(): %w", err)
		}
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("LoadPrograms(): %w", err)
	}

	return &objs, nil
}

func LinkPrograms(ctx context.Context, wg *sync.WaitGroup, objs *litmObjects) error {
	var cleanupFuncs []func()
	var err error

	defer func() {
		if err != nil {
			for _, fn := range cleanupFuncs {
				fn()
			}
			wg.Done()
		} else {
			go func() {
				defer wg.Done()
				<-ctx.Done()
				for _, fn := range cleanupFuncs {
					fn()
				}
			}()
		}
	}()

	// Helper to manage errors and cleanup
	manageLink := func(l link.Link, err error) error {
		if err != nil {
			return err
		}
		cleanupFuncs = append(cleanupFuncs, func() { l.Close() })
		return nil
	}

	if err = manageLink(link.Tracepoint("sched", "sched_process_exit", objs.ServerExit, nil)); err != nil {
		return fmt.Errorf("LinkPrograms(): %w", err)
	}
	if err = manageLink(link.Tracepoint("syscalls", "sys_enter_accept4", objs.SysEnterAccept, nil)); err != nil {
		return fmt.Errorf("LinkPrograms(): %w", err)
	}
	if err = manageLink(link.Tracepoint("syscalls", "sys_exit_accept4", objs.SysExitAccept, nil)); err != nil {
		return fmt.Errorf("LinkPrograms(): %w", err)
	}
	if err = manageLink(link.Tracepoint("syscalls", "sys_enter_accept", objs.SysEnterAccept, nil)); err != nil {
		return fmt.Errorf("LinkPrograms(): %w", err)
	}
	if err = manageLink(link.Tracepoint("syscalls", "sys_exit_accept", objs.SysExitAccept, nil)); err != nil {
		return fmt.Errorf("LinkPrograms(): %w", err)
	}
	if err = manageLink(link.Tracepoint("syscalls", "sys_enter_close", objs.SysEnterClose, nil)); err != nil {
		return fmt.Errorf("LinkPrograms(): %w", err)
	}
	if err = manageLink(link.Tracepoint("sock", "inet_sock_set_state", objs.GetConnInfo, nil)); err != nil {
		return fmt.Errorf("LinkPrograms(): %w", err)
	}

	// Receive syscalls
	if err = manageLink(link.Tracepoint("syscalls", "sys_enter_read", objs.SysEnterIo, nil)); err != nil {
		return fmt.Errorf("LinkPrograms(): %w", err)
	}
	if err = manageLink(link.Tracepoint("syscalls", "sys_exit_read", objs.SysExitIn, nil)); err != nil {
		return fmt.Errorf("LinkPrograms(): %w", err)
	}
	if err = manageLink(link.Tracepoint("syscalls", "sys_enter_recvfrom", objs.SysEnterIo, nil)); err != nil {
		return fmt.Errorf("LinkPrograms(): %w", err)
	}
	if err = manageLink(link.Tracepoint("syscalls", "sys_exit_recvfrom", objs.SysExitIn, nil)); err != nil {
		return fmt.Errorf("LinkPrograms(): %w", err)
	}
	if err = manageLink(link.Tracepoint("syscalls", "sys_enter_readv", objs.SysEnterIo, nil)); err != nil {
		return fmt.Errorf("LinkPrograms(): %w", err)
	}
	if err = manageLink(link.Tracepoint("syscalls", "sys_exit_readv", objs.SysExitInV, nil)); err != nil {
		return fmt.Errorf("LinkPrograms(): %w", err)
	}

	// Send syscalls
	if err = manageLink(link.Tracepoint("syscalls", "sys_enter_write", objs.SysEnterIo, nil)); err != nil {
		return fmt.Errorf("LinkPrograms(): %w", err)
	}
	if err = manageLink(link.Tracepoint("syscalls", "sys_exit_write", objs.SysExitOut, nil)); err != nil {
		return fmt.Errorf("LinkPrograms(): %w", err)
	}
	if err = manageLink(link.Tracepoint("syscalls", "sys_enter_sendto", objs.SysEnterIo, nil)); err != nil {
		return fmt.Errorf("LinkPrograms(): %w", err)
	}
	if err = manageLink(link.Tracepoint("syscalls", "sys_exit_sendto", objs.SysExitOut, nil)); err != nil {
		return fmt.Errorf("LinkPrograms(): %w", err)
	}
	if err = manageLink(link.Tracepoint("syscalls", "sys_enter_writev", objs.SysEnterIo, nil)); err != nil {
		return fmt.Errorf("LinkPrograms(): %w", err)
	}
	if err = manageLink(link.Tracepoint("syscalls", "sys_exit_writev", objs.SysExitOutV, nil)); err != nil {
		return fmt.Errorf("LinkPrograms(): %w", err)
	}

	return nil
}

type ConnEvent litmConnEventT

type ConnInfoEvent litmConnInfoEventT

type DataEvent litmDataEventT

type EventType litmEventType

type RbError litmErrorT

const (
	C_OPEN EventType = iota
	C_CLOSE
	DATA_IN
	DATA_OUT
)

package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
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

func LoadPrograms(pid uint32, listenFd int64) (*litmObjects, func(), error) {
	objs := litmObjects{}

	// Load the object file from disk using a bpf2go-generated scaffolding.
	spec, err := loadLitm()
	if err != nil {
		return &objs, nil, fmt.Errorf("LoadPrograms(): %w", err)
	}

	// https://github.com/cilium/ebpf/discussions/795
	err = spec.RewriteConstants(map[string]interface{}{
		"PID_FILTER": pid,
		"FD_FILTER":  listenFd,
	})
	if err != nil {
		return &objs, nil, fmt.Errorf("LoadPrograms(): %w", err)
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return &objs, nil, fmt.Errorf("LoadPrograms(): %w", err)
	}

	cleanup := func() {
		objs.Close()
	}

	return &objs, cleanup, nil
}

func LinkPrograms(objs *litmObjects) (func(), error) {
	var cleanupFuncs []func()

	// Helper to manage errors and cleanup
	manageLink := func(l link.Link, err error) error {
		if err != nil {
			return err
		}
		cleanupFuncs = append(cleanupFuncs, func() { l.Close() })
		return nil
	}

	if err := manageLink(link.Tracepoint("syscalls", "sys_enter_accept4", objs.SysEnterAccept, nil)); err != nil {
		return nil, fmt.Errorf("LinkPrograms(): %w", err)
	}
	if err := manageLink(link.Tracepoint("syscalls", "sys_exit_accept4", objs.SysExitAccept, nil)); err != nil {
		return nil, fmt.Errorf("LinkPrograms(): %w", err)
	}
	if err := manageLink(link.Tracepoint("syscalls", "sys_enter_close", objs.SysEnterClose, nil)); err != nil {
		return nil, fmt.Errorf("LinkPrograms(): %w", err)
	}
	if err := manageLink(link.Tracepoint("syscalls", "sys_exit_close", objs.SysExitClose, nil)); err != nil {
		return nil, fmt.Errorf("LinkPrograms(): %w", err)
	}
	if err := manageLink(link.Tracepoint("syscalls", "sys_enter_read", objs.SysEnterRead, nil)); err != nil {
		return nil, fmt.Errorf("LinkPrograms(): %w", err)
	}
	if err := manageLink(link.Tracepoint("syscalls", "sys_exit_read", objs.SysExitRead, nil)); err != nil {
		return nil, fmt.Errorf("LinkPrograms(): %w", err)
	}

	cleanup := func() {
		for _, fn := range cleanupFuncs {
			fn()
		}
	}

	return cleanup, nil
}

func HandleErrorEventsRb(objs *litmObjects) (chan litmErrorEventT, func(), error) {
	rd, err := ringbuf.NewReader(objs.ErrorEventsRb)
	if err != nil {
		return nil, nil, fmt.Errorf("HandleReadEventsRb(): %w", err)
	}

	ch := make(chan litmErrorEventT)

	go func() {
		defer close(ch)
		var errorEvent litmErrorEventT
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Fatalf("HandleErrorEventsRb():reading from RingBuf: %s", err.Error())
			}

			// Parse the ringbuf event entry into a litmErrorEventT structure.
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.NativeEndian, &errorEvent); err != nil {
				log.Fatalf("HandleErrorEventsRb(): parsing RingBuf event: %s", err.Error())
			}

			select {
			case ch <- errorEvent:
			default:
				log.Fatalf("HandleErrorEventsRb(): channel full, too much traffic")
			}
		}
	}()

	cleanup := func() {
		rd.Close()
	}

	return ch, cleanup, nil
}

func HandleConnEventsRb(objs *litmObjects) (chan litmConnEventT, func(), error) {
	rd, err := ringbuf.NewReader(objs.ConnEventsRb)
	if err != nil {
		return nil, nil, fmt.Errorf("HandleConnEventsRb(): %w", err)
	}

	ch := make(chan litmConnEventT)

	go func() {
		defer close(ch)
		var connEvent litmConnEventT
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Fatalf("HandleConnEventsRb():reading from RingBuf: %s", err.Error())
			}

			// Parse the ringbuf event into a litmConnEventT structure.
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.NativeEndian, &connEvent); err != nil {
				log.Fatalf("HandleConnEventsRb(): parsing RingBuf event: %s", err.Error())

			}

			select {
			case ch <- connEvent:
			default:
				log.Fatalf("HandleConnEventsRb(): channel full, too much traffic")
			}
		}
	}()

	cleanup := func() {
		rd.Close()
	}

	return ch, cleanup, nil
}

type dataRead struct {
	Fd   int64
	Data []uint8
}

func HandleReadEventsRb(objs *litmObjects) (chan dataRead, func(), error) {
	rd, err := ringbuf.NewReader(objs.ReadEventsRb)
	if err != nil {
		return nil, nil, fmt.Errorf("HandleReadEventsRb(): %w", err)
	}

	// TODO: Maybe have to be buffered for handling high traffic
	ch := make(chan dataRead)

	go func() {
		defer close(ch)
		var readEvent litmReadEventT
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Fatalf("HandleReadEventsRb():reading from RingBuf: %s", err.Error())
			}

			// Parse the ringbuf event entry into a litmReadEventT structure.
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.NativeEndian, &readEvent); err != nil {
				log.Fatalf("HandleReadEventsRb(): parsing RingBuf event: %s", err.Error())
			}

			data := dataRead{
				Fd:   readEvent.Fd,
				Data: readEvent.Msg[:readEvent.MsgLen],
			}

			select {
			case ch <- data:
			default:
				log.Fatalf("HandleReadEventsRb(): channel full, too much traffic")
			}
		}
	}()

	cleanup := func() {
		rd.Close()
	}

	return ch, cleanup, nil
}

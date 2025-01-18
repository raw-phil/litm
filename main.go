package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
	bpf "github.com/raw-phil/litm/internal/bpf"
	logger "github.com/raw-phil/litm/internal/core"
)

var (
	port   = flag.Uint("p", 0, "Port where the server is listening")
	ip     = flag.String("ip", "", "Ip (IPv4 or IPv6) where the server is listening")
	format = flag.Bool("F", false, "Remove info logs to produce output that is suitable for processing by another program")
)

func main() {

	flag.Parse()

	// Variable where the error causing LITM termination is saved.
	var gErr error
	defer exit(&gErr)

	if *ip == "" || *port == 0 {
		flag.Usage()
		os.Exit(1)
	}
	dAddr := net.ParseIP(*ip)
	if dAddr == nil {
		gErr = fmt.Errorf("invalid ip: %s", *ip)
		flag.Usage()
		return
	}
	pid, command, fd, err := getServerInfo(dAddr, uint16(*port))
	if err != nil {
		gErr = err
		return
	}

	if !*format {
		defer log.Println("Litm terminated")
		log.Printf("LITM attched to server:\n\t- pid: %d\n\t- cmd: %s\n\t- ip: %s\n\t- port: %d\n", pid, command, dAddr, *port)
	}

	// -----------------------------------------------------------------------------------------------------------------------

	// Remove resource limits for kernels <5.11.
	if err = rlimit.RemoveMemlock(); err != nil {
		gErr = fmt.Errorf("RemoveMemlock(): %w", err)
		return
	}

	if err = bpf.CheckKernelFeatures(); err != nil {
		gErr = err
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	defer cleanBpf(cancel, &wg)

	wg.Add(1)
	objs, err := bpf.LoadPrograms(ctx, &wg, uint32(pid), int64(fd), dAddr, uint16(*port))
	if err != nil {
		gErr = err
		return
	}

	wg.Add(1)
	err = bpf.LinkPrograms(ctx, &wg, objs)
	if err != nil {
		gErr = err
		return
	}

	// -----------------------------------------------------------------------------------------------------------------------

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	l, err := logger.NewLitm(objs.EventRb, objs.ErrorRb, objs.ConnInfoRb)
	if err != nil {
		gErr = err
		return
	}

	resCh, errorCh, done := l.Start()

	go func() {
		for res := range resCh {
			if err = logger.ClfLog(res); err != nil {
				fmt.Fprintf(os.Stderr, "error: litm: %s\n", err.Error())
			}
		}
	}()

	select {
	case <-sigCh:
		stop := make(chan struct{})
		go func() {
			l.Stop()
			close(stop)
		}()
		select {
		case <-stop:
		case <-time.After(3 * time.Second):
		}
	case <-done:
		select {
		case err, ok := <-errorCh:
			if ok {
				gErr = fmt.Errorf("litm: %w", err)
			}
		default:
		}
	}
}

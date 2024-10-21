package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	litm_bpf "github.com/raw-phil/litm/internal/bpf"
)

func main() {

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	pid := flag.Uint("p", 0, "Process ID to monitor")
	listenFd := flag.Int64("fd", 0, "File descriptor to monitor")

	// Parse the flags
	flag.Parse()

	if *pid == 0 || *listenFd == 0 {
		flag.Usage()
		os.Exit(1)
	}

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Removing memlock: %s", err.Error())
	}

	// -----------------------------------------------------------------------------------------------------------------------

	if err := litm_bpf.CheckKernelFeatures(); err != nil {
		log.Fatalf("error: %s", err.Error())
	}

	objs, progsClean, err := litm_bpf.LoadPrograms(uint32(*pid), *listenFd)
	if err != nil {
		log.Fatalf("error: %s", err.Error())
	}
	defer progsClean()

	linksClean, err := litm_bpf.LinkPrograms(objs)
	if err != nil {
		log.Fatalf("error: %s", err.Error())
	}
	defer linksClean()

	// -----------------------------------------------------------------------------------------------------------------------

	errCh, cleanErrorRb, err := litm_bpf.HandleErrorEventsRb(objs)
	if err != nil {
		log.Fatalf("error: %s", err.Error())
	}
	defer cleanErrorRb()

	go func() {
		for e := range errCh {
			log.Printf("Error event received: %d %s", e.Code, string(e.Description[:]))
		}
	}()

	connCh, cleanConnRb, err := litm_bpf.HandleConnEventsRb(objs)
	if err != nil {
		log.Fatalf("error: %s", err.Error())
	}
	defer cleanConnRb()

	go func() {
		for e := range connCh {
			log.Printf("Connection event received: %d %d", e.Fd, e.Event)
		}
	}()

	readCh, cleanReadRb, err := litm_bpf.HandleReadEventsRb(objs)
	if err != nil {
		log.Fatalf("error: %s", err.Error())
	}
	defer cleanReadRb()

	go func() {
		for e := range readCh {
			log.Printf("Read event received, fd: %d data:\n%s", e.Fd, e.Data[:])
		}
	}()

	<-stopper

}

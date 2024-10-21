package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -type conn_event_t -type error_event_t -type read_event_t -type conn_event -type error_code litm litm.bpf.c

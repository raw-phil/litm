package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -type error_code -type error_t -type event_type -type data_event_t -type conn_event_t -type conn_info_event_t litm litm.bpf.c

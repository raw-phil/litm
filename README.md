# litm

> [!WARNING]   
> This is a free-time project created to learn eBPF. Use it at your own risk.

litm (Logger In The Middle) is a simple CLI tool that captures and logs HTTP/1.1 traffic of a web server using eBPF. Built with Go and [ebpf-go](https://github.com/cilium/ebpf), it listens to network-related syscalls, processes HTTP traffic in user space, and generates logs in Common Log Format (CLF).

[![Go Reference](https://pkg.go.dev/badge/golang.org/x/example.svg)](https://pkg.go.dev/golang.org/x/example)

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Build](#build)
- [Usage](#usage)
- [How It Works](#how-it-works)

## Features

- Monitors HTTP/1.1 traffic of a web-server using eBPF
- Parses TCP data using Go’s `net/http` package
- Logs HTTP traffic in [CLF](https://en.wikipedia.org/wiki/Common_Log_Format) format

## Installation

### Prerequisites

- Go (1.18+ recommended)
- Linux 5.x+ with eBPF support

### Install

```sh
go install github.com/raw-phil/litm@latest
```

## Build
### Build Go part
- Clone repository
```sh
git clone https://github.com/raw-phil/litm && cd litm
```
- Build
```sh
go build -o litm .
```

### Build eBPF part
Do it if you want to modify the content of eBPF programs (litm.bpf.c):

- Clone repository
```sh
git clone https://github.com/raw-phil/litm && cd litm
```
- Generate vmlinux.h
```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > internal/bpf/vmlinux.h
```
- Build
```sh
go generate ./internal/bpf
```

## Usage

### Help
```sh
litm --help
```
```
  -F	Remove info logs to produce output that is suitable for processing by another program
  -ip string
    	Ip (IPv4 or IPv6) where the server is listening
  -p uint
    	Port where the server is listening
```
### Run

> [!NOTE] 
> litm uses eBPF, so it must be run by the root user or with the `CAP_BPF` capability set.

```sh
litm -p 3000 -ip 127.0.0.1
```
This command start logging on STDOUT, http traffic processed by web-server on 127.0.0.1:3000

## How It Works

1. litm attaches to the most common syscalls that web servers use to read and write to a TCP connection.
2. The eBPF program collects HTTP data and transfers it to user space via a ring buffer.
3. The Go program reconstructs HTTP requests and responses using `net/http`.
4. The parsed data is logged in Common Log Format (CLF).

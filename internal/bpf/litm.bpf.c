
//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

volatile static const u32 PID_FILTER;
volatile static const s64 FD_FILTER;

__hidden static const u8 one = 1;

// /proc/sys/net/core/rmem_max
#define MAX_MSG_SIZE 256

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024 /* 256 KB */);
} conn_events_rb SEC(".maps");

enum conn_event { OPEN, CLOSE } event;
enum conn_event *unused_conn_event_enum __attribute__((unused));

struct conn_event_t {
  s64 fd;
  enum conn_event event;
};
struct conn_event_t *unused_conn_event __attribute__((unused));

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024 /* 256 KB */);
} error_events_rb SEC(".maps");

enum error_code { WR_CONN_RB_FAIL, WR_READ_RB_FAIL, MSG_TOO_BIG };
enum error_code *unused_error_code_enum __attribute__((unused));

struct error_event_t {
  enum error_code code;
  u8 description[64];
};
struct error_event_t *unused_error_event __attribute__((unused));

// Store active connection fd
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 131072);
  __type(key, s64);
  __type(value, u8);
} conn_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, u64);
  __type(value, u8);
} active_accept_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, u64);
  __type(value, s64);
} active_close_map SEC(".maps");

// -------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_accept")
int sys_enter_accept(struct trace_event_raw_sys_enter *ctx) {

  s64 sockfd = (s64)BPF_CORE_READ(ctx, args[0]);
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tgid = pid_tgid;

  if (pid != PID_FILTER || sockfd != FD_FILTER) {
    return 0;
  }

  bpf_map_update_elem(&active_accept_map, &pid_tgid, &one, BPF_ANY);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int sys_exit_accept(struct trace_event_raw_sys_exit *ctx) {

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tgid = pid_tgid;

  u8 *value = bpf_map_lookup_elem(&active_accept_map, &pid_tgid);
  if (!value) {
    return 0;
  }

  s64 ret_fd = (s64)BPF_CORE_READ(ctx, ret);
  if (ret_fd <= 0) {
    bpf_map_delete_elem(&active_accept_map, &pid_tgid);
    return 0;
  }

  bpf_map_update_elem(&conn_map, &ret_fd, &one, BPF_ANY);
  bpf_map_delete_elem(&active_accept_map, &pid_tgid);

  struct conn_event_t event = {.fd = ret_fd, .event = OPEN};

  int r = bpf_ringbuf_output(&conn_events_rb, &event, sizeof(event), 0);
  if (r < 0) {
    struct error_event_t error = {.code = WR_CONN_RB_FAIL,
                                  .description =
                                      "Error writing to conn_events_rb"};
    bpf_ringbuf_output(&error_events_rb, &error, sizeof(error), 0);
    return 0;
  }

  bpf_printk("Accept4 pid: %d, tgid: %d, ret_fd: %d", pid, tgid, ret_fd);

  return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int sys_enter_close(struct trace_event_raw_sys_enter *ctx) {

  s64 fd = (s64)BPF_CORE_READ(ctx, args[0]);
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  if (pid != PID_FILTER) {
    return 0;
  }

  u8 *value = bpf_map_lookup_elem(&conn_map, &fd);
  if (!value) {
    return 0;
  }

  bpf_map_update_elem(&active_close_map, &pid_tgid, &fd, BPF_ANY);

  return 0;
}

SEC("tracepoint/syscalls/sys_exit_close")
int sys_exit_close(struct trace_event_raw_sys_exit *ctx) {

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  s64 *fd = bpf_map_lookup_elem(&active_close_map, &pid_tgid);
  if (!fd) {
    return 0;
  }

  s64 ret = (s64)BPF_CORE_READ(ctx, ret);
  if (ret != 0) {
    bpf_map_delete_elem(&active_close_map, &pid_tgid);
    return 0;
  }

  bpf_map_delete_elem(&conn_map, fd);
  struct conn_event_t event = {.fd = *fd, .event = CLOSE};

  int r = bpf_ringbuf_output(&conn_events_rb, &event, sizeof(event), 0);
  if (r < 0) {
    struct error_event_t error = {.code = WR_CONN_RB_FAIL, .description = "Error writing to conn_events_rb"};
    bpf_ringbuf_output(&error_events_rb, &error, sizeof(error), 0);
    return 0;
  }

  return 0;
}
// ------------------------------------------------------

struct read_args_t {
  s64 fd;
  u8 *buf;
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024 /* 256 KB */);
} read_events_rb SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, u64);
  __type(value, struct read_args_t);
} active_read_args_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct trace_event_raw_sys_enter *ctx) {

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  if (pid != PID_FILTER) {
    return 0;
  }

  s64 fd = (s64)BPF_CORE_READ(ctx, args[0]);
  
  u8 *value = bpf_map_lookup_elem(&conn_map, &fd);
  if (!value) {
    return 0;
  }

  struct read_args_t read_args = {};
  read_args.fd = (s64)BPF_CORE_READ(ctx, args[0]);
  read_args.buf = (u8 *)BPF_CORE_READ(ctx, args[1]);
  bpf_map_update_elem(&active_read_args_map, &pid_tgid, &read_args, BPF_ANY);


  return 0;
}

struct read_event_t {
  s64 fd;
  u8 msg[MAX_MSG_SIZE];
  u32 msg_len;
};
struct read_event_t *unused_read_event __attribute__((unused));

static inline void send_data(const struct read_args_t *args, u64 bytes_count) {

  if (args->buf == NULL) {
    return;
  }

  
  if (bytes_count > MAX_MSG_SIZE) {

    struct error_event_t error = {
        .code = MSG_TOO_BIG,
        .description = "Error: read: bytes_counts bigger than MAX_MSG_SIZE"};

    bpf_ringbuf_output(&error_events_rb, &error, sizeof(error), 0);
    return;
  }

  
  struct read_event_t event = {};

  event.fd = args->fd;
  event.msg_len = bytes_count;

  bpf_probe_read_user(&event.msg, bytes_count, (u8 *)args->buf);

  int r = bpf_ringbuf_output(&read_events_rb, &event, sizeof(event), 0);

  if (r < 0) {
    // Error writing to ringbuf, probably to much traffic
    struct error_event_t error = {
        .code = WR_READ_RB_FAIL,
        .description = "Error writing to read_events_rb ringbuf"};

    bpf_ringbuf_output(&error_events_rb, &error, sizeof(error), 0);
  }

  return;
}

SEC("tracepoint/syscalls/sys_exit_read")
int sys_exit_read(struct trace_event_raw_sys_exit *ctx) {

  u64 pid_tgid = bpf_get_current_pid_tgid();

  struct read_args_t *read_args =
      bpf_map_lookup_elem(&active_read_args_map, &pid_tgid);
  if (!read_args) {
    return 0;
  }

  s64 bytes_count = (s64)BPF_CORE_READ(ctx, ret);
  if (bytes_count <= 0) {
    bpf_map_delete_elem(&active_read_args_map, &pid_tgid);
    return 0;
  }

  send_data(read_args, bytes_count);

  bpf_map_delete_elem(&active_read_args_map, &pid_tgid);

  return 0;
}

char _license[] SEC("license") = "GPL";

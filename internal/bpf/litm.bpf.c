
//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2
#define AF_INET6 10

volatile u32 PID_FILTER SEC(".rodata.PID_FILTER");
volatile s64 FD_FILTER SEC(".rodata.FD_FILTER");
volatile u8 IPV4_FILTER[4] SEC(".rodata.IPV4_FILTER");
volatile u8 IPV6_FILTER[16] SEC(".rodata.IPV6_FILTER");
volatile u8 AF_FILTER SEC(".rodata.AF_FILTER");
volatile u16 PORT_FILTER SEC(".rodata.PORT_FILTER");

__hidden static const u8 one = 1;

#define MAX_DATA_SIZE 1024

struct conn_info_event_t {
  u16 family;
  u16 sport;
  u8 saddr[16];
};
struct conn_info_event_t *unused_connection_info __attribute__((unused));

enum error_code {
  WR_EVENT_RB_FAIL = -1,
  WR_BAD_EVENT_T = -2,
  WR_INFO_RB_FAIL = -3,
  MAP_OPERATION_FAIL = -4,
  PROBE_READ_USER_FAIL = -5,
  SERVER_EXIT = -6
};
enum error_code *unused_error_code_enum __attribute__((unused));

struct error_t {
  enum error_code code;
  u8 description[64];
};
struct error_t *unused_error __attribute__((unused));

enum event_type { C_OPEN, C_CLOSE, DATA_IN, DATA_OUT };
enum event_type *unused_event_type_enum __attribute__((unused));

struct data_event_t {
  enum event_type type;
  u32 size;
  s64 fd;
  u8 buf[MAX_DATA_SIZE];
};
struct data_event_t *unused_data_event __attribute__((unused));

struct conn_event_t {
  enum event_type type;
  s64 fd;
};
struct conn_event_t *unused_conn_event __attribute__((unused));

struct io_args_t {
  s64 fd;
  void *buf;
  u64 count;
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024 * 1024 * 64 /* 64 MB */);
} event_rb SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, u64);
  __type(value, struct io_args_t);
} active_io_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024 * 1024);
} conn_info_rb SEC(".maps");

// Store active connections
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
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024 /* 256 KB */);
} error_rb SEC(".maps");

// -------------------------------------------------------------------------------
// Common functions

static __attribute__((always_inline)) void
send_error(int error_code, const char *fmt, u64 *data, u32 data_len) {
  struct error_t error;
  error.code = error_code;
  bpf_snprintf((char *)&error.description, sizeof(error.description), fmt, data,
               data_len);

  bpf_ringbuf_output(&error_rb, &error, sizeof(struct error_t), 0);
}

static __attribute__((always_inline)) int send_data_events(enum event_type type,
                                                           s64 fd, u8 *buf,
                                                           u64 bytes_count,
                                                           void *ringbuf) {
  if (buf == NULL) {
    return 0;
  }

  if (type != DATA_IN && type != DATA_OUT) {
    return WR_BAD_EVENT_T;
  }

  u64 chunk_c = (bytes_count + MAX_DATA_SIZE - 1) / MAX_DATA_SIZE;

  u64 i;
  bpf_for(i, 0, chunk_c) {
    u64 bytes_sent = i * MAX_DATA_SIZE;
    u64 chunk_size = bytes_count - bytes_sent > MAX_DATA_SIZE
                         ? MAX_DATA_SIZE
                         : bytes_count - bytes_sent;

    struct data_event_t *data =
        bpf_ringbuf_reserve(&event_rb, sizeof(struct data_event_t), 0);
    if (!data) {
      return WR_EVENT_RB_FAIL;
    }
    data->type = type;
    data->size = chunk_size;
    data->fd = fd;

    int r = bpf_probe_read_user(&data->buf, chunk_size, buf + bytes_sent);
    if (r < 0) {
      bpf_ringbuf_discard(data, 0);
      return PROBE_READ_USER_FAIL;
    }

    bpf_ringbuf_submit(data, 0);
  }

  return 0;
}

static __attribute__((always_inline)) void
handle_sys_exit(struct trace_event_raw_sys_exit *ctx, enum event_type type) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct io_args_t *io_args = bpf_map_lookup_elem(&active_io_map, &pid_tgid);
  if (!io_args) {
    return;
  }

  s64 bytes_count = (s64)BPF_CORE_READ(ctx, ret);
  if (bytes_count <= 0) {
    bpf_map_delete_elem(&active_io_map, &pid_tgid);
    return;
  }

  int r =
      send_data_events(type, io_args->fd, io_args->buf, bytes_count, &event_rb);
  if (r < 0) {
    u64 data[] = {(u64)((type == DATA_IN) ? "sys_exit_in" : "sys_exit_out"),
                  (u64)r};
    send_error(r, "%s: send_data_events: %d", data, sizeof(data));
  }

  bpf_map_delete_elem(&active_io_map, &pid_tgid);
  return;
}

static __attribute__((always_inline)) void
handle_sys_exit_v(struct trace_event_raw_sys_exit *ctx, enum event_type type) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct io_args_t *io_args = bpf_map_lookup_elem(&active_io_map, &pid_tgid);
  if (!io_args) {
    return;
  }

  s64 bytes_count = (s64)BPF_CORE_READ(ctx, ret);
  if (bytes_count <= 0) {
    bpf_map_delete_elem(&active_io_map, &pid_tgid);
    return;
  }

  bpf_printk("count %d", io_args->count);

  u64 i;
  bpf_for(i, 0, io_args->count) {
    struct iovec iov;
    int r = bpf_probe_read_user(&iov, sizeof(struct iovec), &io_args->buf[i]);
    if (r < 0) {
      u64 data[] = {
          (u64)((type == DATA_IN) ? "sys_exit_in_v" : "sys_exit_out_v"),
          (u64)r};
      send_error(PROBE_READ_USER_FAIL, "%s: bpf_probe_read_user: %d", data,
                 sizeof(data));
      break;
    }

    if (bytes_count <= 0) {
      break;
    }
    bytes_count = bytes_count - iov.iov_len;

    r = send_data_events(type, io_args->fd, iov.iov_base, iov.iov_len,
                         &event_rb);
    if (r < 0) {
      u64 data[] = {
          (u64)((type == DATA_IN) ? "sys_exit_in_v" : "sys_exit_out_v"),
          (u64)r};
      send_error(r, "%s: send_data_events: %d", data, sizeof(data));
      break;
    }
  }

  bpf_map_delete_elem(&active_io_map, &pid_tgid);
  return;
}

// -------------------------------------------------------------------------------
// Programs for accept and close syscalls

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter_accept(struct trace_event_raw_sys_enter *ctx) {

  s64 sockfd = (s64)BPF_CORE_READ(ctx, args[0]);
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tgid = pid_tgid;

  if (pid != PID_FILTER || sockfd != FD_FILTER) {
    return 0;
  }

  int r = bpf_map_update_elem(&active_accept_map, &pid_tgid, &one, BPF_ANY);
  if (r < 0) {
    send_error(MAP_OPERATION_FAIL, "sys_enter_accept: bpf_map_update_elem: %d",
               (u64 *)&r, sizeof(u64));
  }
  return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
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

  int r = bpf_map_update_elem(&conn_map, &ret_fd, &one, BPF_ANY);
  if (r < 0) {
    send_error(MAP_OPERATION_FAIL, "sys_enter_accept: bpf_map_update_elem: %d",
               (u64 *)&r, sizeof(u64));
    return 0;
  }

  bpf_map_delete_elem(&active_accept_map, &pid_tgid);
  struct conn_event_t event = {.fd = ret_fd, .type = C_OPEN};

  r = bpf_ringbuf_output(&event_rb, (void *)&event, sizeof(struct conn_event_t),
                         0);
  if (r < 0) {
    send_error(WR_EVENT_RB_FAIL, "sys_exit_accept: bpf_ringbuf_output: %d",
               (u64 *)&r, sizeof(u64));
  }

  bpf_printk("Accept4 pid: %d, tgid: %d, ret_fd: %d", pid, tgid, ret_fd);

  return 0;
}

// There is no sys_exit_close prog because the close syscall
// always releases the file descriptor early in the close operation.
// https://www.man7.org/linux/man-pages/man2/close.2.html
SEC("tracepoint/raw_syscalls/sys_enter")
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

  bpf_map_delete_elem(&conn_map, &fd);

  struct conn_event_t event = {.fd = fd, .type = C_CLOSE};

  int r = bpf_ringbuf_output(&event_rb, (void *)&event,
                             sizeof(struct conn_event_t), 0);
  if (r < 0) {
    send_error(WR_EVENT_RB_FAIL, "sys_enter_close: bpf_ringbuf_output: %d",
               (u64 *)&r, sizeof(u64));
  }

  bpf_printk("close %d", fd);

  return 0;
}

// -------------------------------------------------------------------------------
// Programs for network in/out syscalls

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter_io(struct trace_event_raw_sys_enter *ctx) {

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

  struct io_args_t io_args = {};
  io_args.fd = (s64)BPF_CORE_READ(ctx, args[0]);
  io_args.buf = (void *)BPF_CORE_READ(ctx, args[1]);
  io_args.count = (u64)BPF_CORE_READ(ctx, args[2]);

  int r = bpf_map_update_elem(&active_io_map, &pid_tgid, &io_args, BPF_ANY);
  if (r < 0) {
    send_error(MAP_OPERATION_FAIL, "sys_enter_io: bpf_map_update_elem: %d",
               (u64 *)&r, sizeof(u64));
  }

  return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit_in(struct trace_event_raw_sys_exit *ctx) {
  handle_sys_exit(ctx, DATA_IN);
  return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit_out(struct trace_event_raw_sys_exit *ctx) {
  handle_sys_exit(ctx, DATA_OUT);
  return 0;
}

// -------------------------------------------------------------------------------
// Programs for iovec syscalls

SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit_in_v(struct trace_event_raw_sys_exit *ctx) {
  handle_sys_exit_v(ctx, DATA_IN);
  return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit_out_v(struct trace_event_raw_sys_exit *ctx) {
  handle_sys_exit_v(ctx, DATA_OUT);
  return 0;
}

// -------------------------------------------------------------------------------

// Used because the 'struct sockaddr *' arg of accept syscall is nullable.
SEC("tracepoint/sock/inet_sock_set_state")
int get_conn_info(struct trace_event_raw_inet_sock_set_state *ctx) {

  if (BPF_CORE_READ(ctx, newstate) != TCP_ESTABLISHED ||
      BPF_CORE_READ(ctx, family) != AF_FILTER ||
      BPF_CORE_READ(ctx, dport) != PORT_FILTER) {
    return 0;
  }

  struct conn_info_event_t conn_info = {};

  if (AF_FILTER == AF_INET) {
    __builtin_memcpy(&conn_info.saddr, &ctx->saddr, 4);
    if (__builtin_memcmp((const void *)&conn_info.saddr,
                         (const void *)&IPV4_FILTER, 4) != 0) {
      return 0;
    }
  } else {

    // Split to avoid dereference of modified ctx ptr
    __builtin_memcpy(&conn_info.saddr, &ctx->saddr_v6, 8);
    __builtin_memcpy(&conn_info.saddr[8], &ctx->saddr_v6[8], 8);

    if (__builtin_memcmp((const void *)&conn_info.saddr,
                         (const void *)&IPV6_FILTER, 16) != 0) {
      return 0;
    }
  }

  conn_info.family = (u16)BPF_CORE_READ(ctx, family);
  conn_info.sport = (u16)BPF_CORE_READ(ctx, sport);

  int r = bpf_ringbuf_output(&conn_info_rb, (void *)&conn_info,
                             sizeof(struct conn_info_event_t), 0);
  if (r < 0) {
    send_error(WR_INFO_RB_FAIL, "get_conn_info: bpf_ringbuf_output: %d",
               (u64 *)&r, sizeof(u64));
  }

  return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int server_exit(struct trace_event_raw_sched_process_template *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;
  if (pid == PID_FILTER && pid == tid) {
    bpf_printk("Exit pid: %d", pid);
    send_error(SERVER_EXIT, "monitored server is terminated", NULL, 0);
  }
  return 0;
}

char _license[] SEC("license") = "GPL";

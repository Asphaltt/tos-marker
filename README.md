# tos-marker

Userspace workaround for the v4-mapped IPv6 `IPV6_TCLASS` gap: an `fexit`
hook on `__sys_socket` reports every new `AF_INET`/`AF_INET6` socket created
in a target netns; a Go daemon then grabs each socket with `pidfd_getfd()`
and sets `IP_TOS`. For a v4-mapped IPv6 socket the value lands in
`inet->tos`, which the v4-mapped TX path (`ip_queue_xmit`) actually reads —
so the IPv4 packets on the wire carry the DSCP.

## What it does / does not do

- **Stamps a fixed `IP_TOS`** (the `-tos` flag) on every matched socket, set
  at `socket()` time → before `connect()`, so the SYN and all data carry it.
- Marks **IPv4 and IPv4-mapped-IPv6** egress (both use `inet->tos`).
- Does **not** mirror the app's dynamic `IPV6_TCLASS` — that option isn't set
  yet at `socket()` time. To honor the app's chosen class instead of a fixed
  policy value, hook `setsockopt(IPV6_TCLASS)` rather than `__sys_socket`.
- Does **not** mark native-IPv6 connections (their TX uses `np->tclass`, not
  `inet->tos`); they already work with plain `IPV6_TCLASS`.
- Asynchronous: there is a small window between `socket()` and the daemon's
  `setsockopt`. Because the stamp is applied before the app `connect()`s in
  practice, the SYN is usually covered, but it is best-effort, not atomic.

## Requirements

- Linux >= 5.11 (`fexit`, `bpf_get_current_task_btf`, `pidfd_getfd`).
- Build: Go >= 1.22, `clang`/`llvm`, `bpftool`, libbpf headers (`libbpf-dev`
  provides `<bpf/*.h>`).
- Run as **root**, or with `CAP_BPF`+`CAP_PERFMON` (load/attach tracing BPF)
  **and** `CAP_SYS_PTRACE` (required by `pidfd_getfd`).

## Build

```sh
make vmlinux     # dump headers/vmlinux.h from /sys/kernel/btf/vmlinux
make build       # go generate (bpf2go) + go build -> ./tos-marker
```

(`<bpf/...>` headers come from the system libbpf; if not in the default
include path, add `-I/usr/include` to the cflags in the `//go:generate`
line in main.go, or copy them into ./headers/bpf/.)

## Run

```sh
# Mark all v4 / v4-mapped egress in netns "foo" with DSCP EF (0xb8):
sudo ./tos-marker -netns /var/run/netns/foo -tos 0xb8

# By a container's pid:
sudo ./tos-marker -netns /proc/<pid>/ns/net -tos 0x88

# All namespaces (no filter):
sudo ./tos-marker -tos 0xb8
```

Verify with the netns test harness (e.g. `tcpdump -ni <veth> -v` and look at
the `tos 0x..` field on the IPv4 packets).

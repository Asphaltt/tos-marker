//go:build ignore

#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>

#define AF_INET  2
#define AF_INET6 10

char LICENSE[] SEC("license") = "GPL";

/* Emitted to userspace for every new AF_INET/AF_INET6 socket in the target netns. */
struct event {
	__u32 pid; /* tgid */
	__s32 fd;  /* the new socket fd, valid in the task's fd table */
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* Set from userspace before load. 0 == match every netns. */
const volatile __u32 target_netns_ino = 0;

/* int __sys_socket(int family, int type, int protocol)
 * fexit gives us the args plus the return value (the fd, or -errno).
 * fd_install() has already run inside __sys_socket(), so `ret` is a live
 * fd in the calling task's fd table by the time we observe it here.
 */
SEC("fexit/__sys_socket")
int BPF_PROG(handle_socket, int family, int type, int protocol, int ret)
{
	if (family != AF_INET && family != AF_INET6)
		return 0;
	if (ret < 0)
		return 0;

	if (target_netns_ino) {
		struct task_struct *task = bpf_get_current_task_btf();
		__u32 inum = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);

		if (inum != target_netns_ino)
			return 0;
	}

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = bpf_get_current_pid_tgid() >> 32; /* tgid: fd table is per-process */
	e->fd  = ret;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

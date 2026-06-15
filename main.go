// Command tos-marker watches for new AF_INET/AF_INET6 sockets created in a
// target network namespace (via an fexit hook on __sys_socket), then grabs
// each socket with pidfd_getfd() and sets IP_TOS on it. For v4-mapped IPv6
// sockets this lands in inet->tos, which the v4-mapped TX path (ip_queue_xmit)
// actually uses — working around IPV6_TCLASS being ignored on that path.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" bpf tos_marker.bpf.c -- -I./headers -I./libbpf/src -I./libbpf/include

type bpfEvent struct {
	Pid uint32
	Fd  int32
}

func pidfdOpen(pid int) (int, error) {
	fd, _, errno := unix.Syscall(unix.SYS_PIDFD_OPEN, uintptr(pid), 0, 0)
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

func pidfdGetfd(pidfd, targetfd int) (int, error) {
	fd, _, errno := unix.Syscall(unix.SYS_PIDFD_GETFD, uintptr(pidfd), uintptr(targetfd), 0)
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

// netnsIno returns the namespace inode of a netns file
// (e.g. /var/run/netns/<name> or /proc/<pid>/ns/net). This matches ns.inum.
func netnsIno(path string) (uint32, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}
	return uint32(st.Ino), nil
}

func main() {
	netnsPath := flag.String("netns", "", "netns file to filter (e.g. /var/run/netns/foo or /proc/<pid>/ns/net); empty = all netns")
	tos := flag.Int("tos", 0xb8, "IP_TOS byte to set on matched sockets (0..255); 0xb8 = DSCP EF")
	flag.Parse()

	if *tos < 0 || *tos > 0xff {
		log.Fatalf("tos must be 0..255, got %d", *tos)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	var ino uint32
	if *netnsPath != "" {
		var err error
		if ino, err = netnsIno(*netnsPath); err != nil {
			log.Fatalf("stat netns %q: %v", *netnsPath, err)
		}
		log.Printf("filtering netns %s (ino=%d)", *netnsPath, ino)
	} else {
		log.Printf("no netns filter: matching all namespaces")
	}

	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("load bpf spec: %v", err)
	}
	if v, ok := spec.Variables["target_netns_ino"]; ok {
		if err := v.Set(ino); err != nil {
			log.Fatalf("set target_netns_ino: %v", err)
		}
	}

	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("load objects: %v", err)
	}
	defer objs.Close()

	l, err := link.AttachTracing(link.TracingOptions{Program: objs.HandleSocket})
	if err != nil {
		log.Fatalf("attach fexit/__sys_socket: %v", err)
	}
	defer l.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("open ringbuf: %v", err)
	}
	defer rd.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		rd.Close()
	}()

	log.Printf("running: stamping IP_TOS=0x%02x on new AF_INET/AF_INET6 sockets", *tos)

	var e bpfEvent
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Printf("shutting down")
				return
			}
			log.Printf("ringbuf read: %v", err)
			continue
		}
		// Host is little-endian (x86_64/arm64); kernel writes native order.
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			log.Printf("decode event: %v", err)
			continue
		}
		markSocket(int(e.Pid), int(e.Fd), *tos)
	}
}

// markSocket grabs (pid, fd) via pidfd and sets IP_TOS on the shared socket.
// Any error is logged and swallowed — a single bad/short-lived socket must
// never take the daemon down.
func markSocket(pid, fd, tos int) {
	pidfd, err := pidfdOpen(pid)
	if err != nil {
		log.Printf("pidfd_open(pid=%d): %v", pid, err)
		return
	}
	defer unix.Close(pidfd)

	tfd, err := pidfdGetfd(pidfd, fd)
	if err != nil {
		// Expected sometimes: process exited, or fd already closed/reused.
		log.Printf("pidfd_getfd(pid=%d, fd=%d): %v", pid, fd, err)
		return
	}
	defer unix.Close(tfd)

	if err := unix.SetsockoptInt(tfd, unix.SOL_IP, unix.IP_TOS, tos); err != nil {
		log.Printf("setsockopt(IP_TOS) pid=%d fd=%d: %v", pid, fd, err)
		return
	}
	log.Printf("marked pid=%d fd=%d IP_TOS=0x%02x", pid, fd, tos)
}

CLANG ?= clang
BPFTOOL ?= bpftool

.PHONY: all generate build vmlinux clean

all: build

# Dump kernel BTF into a local vmlinux.h for CO-RE.
vmlinux: headers/vmlinux.h
$(vmlinux):
	mkdir -p headers
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(vmlinux)

# Compile the BPF C and generate Go bindings (bpf_bpfel.go / bpf_bpfeb.go).
generate: $(vmlinux)
	go generate ./...

.DEFAULT_GOAL = build
build: generate
	go build -trimpath -o tos-marker .

clean:
	rm -f tos-marker bpf_bpfel.go bpf_bpfeb.go bpf_bpfel.o bpf_bpfeb.o

setup_netns:
	sudo ./setup_netns.sh

clean_netns:
	sudo ip netns del cli
	sudo ip netns del srv

SUDO ?= /usr/bin/sudo
SETCAP ?= /sbin/setcap
CLANG ?= /usr/bin/clang
BPFTOOL ?= /usr/bin/bpftool
LS ?= /usr/bin/ls
UPX ?= /usr/bin/upx
FILE ?= /usr/bin/file
# user space
run: build/bpf.o
	CGO_LDFLAGS="-lbpf" go build -ldflags "-s -w" -o build/bin ./bin
	$(LS) -lah build
	$(FILE) build/bin
	$(FILE) build/bpf.o
	$(SUDO) build/bin

build/bpf.o: bpf/bpf.c bpf/vmlinux.h makefile
	$(CLANG) -fno-builtin-memset -g -target bpf -Wall -Werror -O2 -c $< -o $@

bpf/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# utils
util-dep:
	sudo yum install kernel-devel libbpf-devel bpftool go llvm-strip clang git

util-doc:
	sudo cat /sys/kernel/debug/tracing/events/$(NAME)/format

util-list:
	sudo find /sys/kernel/debug/tracing/events/

util-trace:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

# general
clean: $(wildcard build/*)
	go clean --cache
	-rm $?
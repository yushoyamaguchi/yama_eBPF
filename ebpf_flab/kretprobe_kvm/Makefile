TARGET ?= hello
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CLANG := clang -I./include -I/usr/include/bpf
VMLINUX := ./include/vmlinux.h

SUDO := sudo

BPF_OBJ := $(TARGET:=.bpf.o)

.PHONY: vmlinux
vmlinux: $(VMLINUX) $(BPFTOOL)
$(VMLINUX):
	mkdir -p include
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)


%.bpf.o: %.bpf.c include/vmlinux.h
	$(CLANG) \
		-target bpf \
	-D __TARGET_ARCH_$(ARCH) \
		-Wall \
		-O2 -g -o $@ -c $<

.PHONY: clean
clean: clean-topology
	rm *.bpf.o


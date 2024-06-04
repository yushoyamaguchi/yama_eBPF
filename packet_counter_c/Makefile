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

.PHONY: attach
attach:
	$(SUDO) ip netns exec host0 ip link set dev h0 xdp obj $(BPF_OBJ) section xdp 

.PHONY: detach
detach:
	$(SUDO) ip netns exec host0 ip link set dev h0 xdp off

.PHONY: topology
topology: clean-topology
	$(SUDO) ./pair.sh


.PHONY: clean-topology
clean-topology:
	$(SUDO) ip netns del host0 2>/dev/null || true
	$(SUDO) ip netns del host1 2>/dev/null || true
	$(SUDO) ip netns del host2 2>/dev/null || true
	$(SUDO) ip netns del host3 2>/dev/null || true
	$(SUDO) ip netns del host4 2>/dev/null || true
	$(SUDO) ip netns del host5 2>/dev/null || true
	$(SUDO) ip netns del host6 2>/dev/null || true
	$(SUDO) ip netns del host7 2>/dev/null || true
	$(SUDO) ip link del dev vipdev 2>/dev/null || true

.PHONY: log
log:
	$(SUDO) cat /sys/kernel/debug/tracing/trace_pipe

/usr/include/asm:
	$(SUDO) ln -s /usr/include/asm-generic /usr/include/asm

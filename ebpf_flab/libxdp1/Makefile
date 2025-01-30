ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CLANG := clang -I./include -I/usr/include/bpf

%.bpf.o: %.bpf.c
	$(CLANG) \
		-target bpf \
	-D __TARGET_ARCH_$(ARCH) \
		-Wall \
		-O2 -g -o $@ -c $<

.PHONY: clean
clean: clean-topology
	rm *.bpf.o


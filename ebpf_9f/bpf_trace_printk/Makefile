CLANG := clang -I./include -I/usr/include/bpf
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

show_trace_pipe:
	sudo python3 show_trace_pipe.py

sudo-in-advance:
	sudo pwd

bpf:
	$(CLANG) \
		-target bpf \
		-D __TARGET_ARCH_$(ARCH) \
		-Wall \
		-O2 -g -o hello_to_pipe.bpf.o -c hello_to_pipe.bpf.c

bpf-skelton: bpf
	bpftool gen skeleton hello_to_pipe.bpf.o > hello_to_pipe.skel.h

libbpf-prog:
	gcc -g -O2 -Wall check_execv.c -lbpf -lelf -o check_execv

run: sudo-in-advance bpf-skelton libbpf-prog
	sudo ./check_execv
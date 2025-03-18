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

bpf-skel: bpf
	bpftool gen skeleton hello_to_pipe.bpf.o > hello_to_pipe.skel.h

libbpf-prog:
	gcc -g -O2 -Wall check_execv.c -lbpf -lelf -o check_execv

run: sudo-in-advance bpf-skelton libbpf-prog
	sudo ./check_execv

docker-build:
	docker build --network=host -t bpf-trace-9f .

docker-run: bpf-skel
	docker run -d -it --privileged --name bpf-trace-9f bpf-trace-9f
	docker cp $(shell pwd)/. bpf-trace-9f:/app
	docker exec -it bpf-trace-9f /bin/bash

docker-cp-progs: bpf-skel
	docker cp $(shell pwd)/. bpf-trace-9f:/app

docker-rm:
	docker stop bpf-trace-9f
	docker remove bpf-trace-9f
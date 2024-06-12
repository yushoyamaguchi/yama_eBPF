#!/bin/bash

gcc -o attach_event1 attach_event1.c -I/home/yusho/dev/2024/others/libbpf/src -L/home/yusho/dev/2024/others/libbpf/src -lbpf -lelf -lz

gcc -o watch_event1 watch_event1.c -I/home/yusho/dev/2024/others/libbpf/src -L/home/yusho/dev/2024/others/libbpf/src -lbpf -lelf -lz
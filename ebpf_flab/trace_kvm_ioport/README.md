# How to Run
```
make vmlinux
make port_trace.bpf.o
gcc -g -O2 -Wall port_trace.c -lbpf -lelf -o port_trace
sudo ./port_trace
```
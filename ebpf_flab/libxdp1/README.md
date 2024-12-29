# How to Run
```
make pass.bpf.o
gcc -o pass pass.c -lxdp -lbpf
sudo ./pass
```
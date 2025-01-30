# How to Run
```
make pass.bpf.o
gcc -o pass pass.c -lxdp -lbpf
sudo bash ./create_veth.sh
sudo ./pass

sudo bash ./delete_veth.sh
```
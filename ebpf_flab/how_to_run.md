# 事前インストール物
- libbpf-dev
- libbpfcc-dev
- bpf-tools (linux-tools-$(uname -r), linux-cloud-tools-$(uname -r))


# vmlinux.hを作る
vmlinux.hは動的に生成する。
make vmlinuxのところを参照。

# pingを送る
sudo ip netns exec host1 ping 10.0.0.1

# bpf_printkの出力を確認する
sudo bpftool prog tracelog

# bpf mapの中身を確認する
sudo bpftool map dump name <map_name>


# attach_event1.cのビルド
gcc -o attach_event2 attach_event2.c -lbpf

gcc -o attach_watch_event1 attach_watch_event1.c -I/home/y-yamaguchi/yusho/2023/others/libbpf/src -L/home/y-yamaguchi/yusho/2023/others/libbpf/src -lbpf -lelf -lz

gcc -o attach_map_event1 attach_map_event1.c -I/home/y-yamaguchi/yusho/2023/others/libbpf/src -L/home/y-yamaguchi/yusho/2023/others/libbpf/src -lbpf -lelf -lz

gcc -o dump_map dump_map.c -I/home/y-yamaguchi/yusho/2023/others/libbpf/src -L/home/y-yamaguchi/yusho/2023/others/libbpf/src -lbpf -lelf -lz

# attach_event1でbpfプログラムをattach
sudo ./attach_event2 host0

sudo LD_LIBRARY_PATH=/home/y-yamaguchi/yusho/2023/others/libbpf/src ./attach_watch_event1 host0

sudo LD_LIBRARY_PATH=/home/y-yamaguchi/yusho/2023/others/libbpf/src ./attach_map_event1 host0

sudo LD_LIBRARY_PATH=/home/y-yamaguchi/yusho/2023/others/libbpf/src ./watch_event1

sudo LD_LIBRARY_PATH=/home/y-yamaguchi/yusho/2023/others/libbpf/src ./dump_map


# mapのpin
sudo bpftool map pin id 78 /sys/fs/bpf/xdp_perf_event_map

sudo unlink /sys/fs/bpf/xdp_perf_event_map

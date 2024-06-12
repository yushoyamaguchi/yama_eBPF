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

gcc -o attach_watch_event1 attach_watch_event1.c -I/home/yusho/dev/2024/others/libbpf/src -L/home/yusho/dev/2024/others/libbpf/src -lbpf -lelf -lz

# attach_event1でbpfプログラムをattach
sudo ./attach_event2 host0

sudo LD_LIBRARY_PATH=~/dev/2024/others/libbpf/src ./attach_watch_event1 host0

sudo LD_LIBRARY_PATH=~/dev/2024/others/libbpf/src ./attach_event1 host0

sudo LD_LIBRARY_PATH=~/dev/2024/others/libbpf/src ./watch_event1

# netnsでpingを実行
sudo ip netns exec host0 ping 10.0.0.2


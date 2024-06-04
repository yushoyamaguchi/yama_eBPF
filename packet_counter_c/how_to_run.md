# 事前インストール物
- libbpf-dev
- libbpfcc-dev
- bpf-tools (linux-tools-$(uname -r)-generic, linux-cloud-tools-$(uname -r)-generic)


# vmlinux.hを作る
vmlinux.hは動的に生成する。
make vmlinuxのところを参照。

# pingを送る
sudo ip netns exec host1 ping 10.0.0.1

# bpf_printkの出力を確認する
sudo bpftool prog tracelog

# bpf mapの中身を確認する
sudo bpftool map dump name <map_name>
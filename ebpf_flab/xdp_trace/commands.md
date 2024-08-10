# bpf_printkの内容の確認
sudo bpftool prog tracelog 

# attach_hello.cのビルド
gcc -o attach_hello attach_hello.c -lbpf

gcc -o attach_event1 attach_event1.c -lbpf

# attach_hello.cの実行(host0というnsにattach)
sudo ./attach_hello host0

# TARGETを指定してmakeを実行
make TARGET=XX attach

# netnsでpingを実行
sudo ip netns exec host0 ping 10.0.0.2

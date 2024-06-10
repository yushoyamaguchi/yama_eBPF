# bpf_printkの内容の確認
sudo bpftool prog tracelog 

# attach_hello.cのビルド
gcc -o attach_hello attach_hello.c -lbpf

# attach_hello.cの実行(attach)
sudo ./attach_hello <netns-name>

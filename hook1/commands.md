# compile
```bash
clang -O2 -target bpf -c vcpu_enter_guest.c -o vcpu_enter_guest.o
```
# load
```bash
bpftool prog load vcpu_enter_guest.o "/sys/fs/bpf/vcpu_enter_guest"
```

これ以下は工事中

# attacch
```bash
bpftool prog attach pinned /sys/fs/bpf/vcpu_enter_guest tracepoint:vcpu_enter_guest
```
# view the output
```bash
cat /sys/kernel/debug/tracing/trace_pipe
```
# detach
```bash
bpftool prog detach /sys/fs/bpf/vcpu_enter_guest tracepoint:vcpu_enter_guest
```
# unload
```bash
bpftool prog unload /sys/fs/bpf/vcpu_enter_guest
```
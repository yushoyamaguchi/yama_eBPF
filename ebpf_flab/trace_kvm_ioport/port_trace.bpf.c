#include "vmlinux.h"
#include <bpf/bpf_helpers.h>


#define TARGET_PORT 0x84

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u64);
    __type(value, __u64);
} counter SEC(".maps");

SEC("kprobe/emulator_pio_in")
int trace_emulator_pio_in(struct pt_regs *ctx)
{
    struct kvm_vcpu *vcpu = (struct kvm_vcpu *)ctx->di;
    __u16 port;
    __u64 key = 0, init_val = 1, *val;

    if (bpf_probe_read_user(&port, sizeof(port), &vcpu->run->io.port) != 0)
        return 0;

    if (port != TARGET_PORT)
        return 0;

    val = bpf_map_lookup_elem(&counter, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
    else
        bpf_map_update_elem(&counter, &key, &init_val, BPF_ANY);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
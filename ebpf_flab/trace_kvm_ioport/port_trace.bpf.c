#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define TARGET_PORT 0x84

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} counter SEC(".maps");

SEC("kprobe/kvm_fast_pio")
int bpf_prog1(struct pt_regs *ctx)
{
    struct kvm_vcpu *vcpu;
    struct kvm_run *run;
    __u64 *val;
    __u32 key = 0;
    unsigned short port;

    // Use PT_REGS_PARM3 macro directly without taking its address
    bpf_core_read(&port, sizeof(port), (void *)((char *)ctx + offsetof(struct pt_regs, dx)));

    /*// Read the first argument (vcpu) from the function arguments
    BPF_CORE_READ_INTO(&vcpu, ctx, di); 
    // Access the kvm_run structure from the vcpu structure
    bpf_core_read(&run, sizeof(run), &vcpu->run);
    // Access the io.port field from the kvm_run structure
    bpf_core_read(&port, sizeof(port), &run->io.port);*/

    // Check if the port is 0 and increment the counter
    if (port == TARGET_PORT) {
        val = bpf_map_lookup_elem(&counter, &key);
        if (val) {
            (*val)++;
        } else {
            __u64 initial_value = 1;
            bpf_map_update_elem(&counter, &key, &initial_value, BPF_ANY);
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

#include "../../header/bpf_helpers.h"


SEC("kprobe/vcpu_enter_guest")
int bpf_vcpu_enter_guest(struct pt_regs *ctx) {
    char msg[] = "vcpu_enter_guest is called\n";
    bpf_trace_printk(msg, sizeof(msg));
    return 0;
}

char _license[] SEC("license") = "GPL";
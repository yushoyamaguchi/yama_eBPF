#include <linux/ptrace.h>

int bpf_vcpu_enter_guest(struct pt_regs *ctx) {
    bpf_trace_printk("vcpu_enter_guest is called\n");
    return 0;
}
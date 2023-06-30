from bcc import BPF

# define BPF program
prog = """
#include <linux/ptrace.h>

int bpf_handle_triple_fault(struct pt_regs *ctx) {
    bpf_trace_printk("handle_triple_fault is called\\n");
    return 0;
}
"""

# load BPF program
b = BPF(text=prog)

# attach kprobe to kernel function, with the BPF program
b.attach_kprobe(event="handle_triple_fault", fn_name="bpf_handle_triple_fault")

# print output
print("Tracing handle_triple_fault()... Ctrl-C to end.")

# trace until Ctrl-C
try:
    while True:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
except KeyboardInterrupt:
    pass

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// Define the read-only data section for the string
const char hello_str[] = "hello from xdp << bpf_trace_printk";

SEC("xdp")
int hello(struct xdp_md *ctx) {
    // Use the defined string
    bpf_trace_printk(hello_str, sizeof(hello_str));
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";


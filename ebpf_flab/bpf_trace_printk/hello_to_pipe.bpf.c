// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>


// Define the read-only data section for the string
const char hello_str[] = "hello world yamaguchi\n";

SEC("kprobe/__x64_sys_execve")
int hello_world(struct pt_regs *ctx) {
    bpf_trace_printk(hello_str, sizeof(hello_str));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
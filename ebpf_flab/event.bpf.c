#include "include/vmlinux.h"
#include <bpf/bpf_helpers.h>

struct data_t {
    __s32 pkt_len;
};

// Define the perf event array map
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 0);
    __type(key, int);
    __type(value, int);
} xdp_perf_event_map SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    struct data_t data = {};
    void *data_end = (void *)(long)ctx->data_end;
    void *data_start = (void *)(long)ctx->data;

    data.pkt_len = data_end - data_start;

    // Output the event
    bpf_perf_event_output(ctx, &xdp_perf_event_map, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
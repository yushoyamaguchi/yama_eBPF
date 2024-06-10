#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>
#include <stdint.h>

struct data_t {
    __s32 pkt_len;
};

// Define the perf event array map
struct bpf_map_def SEC("maps") xdp_perf_event_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 128,
};

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
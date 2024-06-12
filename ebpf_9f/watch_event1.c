#include <stdio.h>
#include <stdlib.h>
#include "/home/yusho/dev/2024/others/libbpf/src/libbpf.h"
#include <signal.h>
#include <unistd.h>

volatile sig_atomic_t stop = 0;

void sigint_handler(int sig) {
    stop = 1;
}

struct data_t {
    __s32 pkt_len;
};

// Callback function for perf event
static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct data_t *e = data;
    printf("Packet length: %d\n", e->pkt_len);
}

// Callback function for lost samples
static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "Lost %llu events on CPU %d\n", lost_cnt, cpu);
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    const char *bpf_obj = "./event.bpf.o"; // path to your BPF object file
    signal(SIGINT, sigint_handler);

    obj = bpf_object__open_file(bpf_obj, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }

    // Find the perf event map
    struct bpf_map *perf_map = bpf_object__find_map_by_name(obj, "xdp_perf_event_map");
    if (!perf_map) {
        fprintf(stderr, "ERROR: finding perf event map in BPF object file failed\n");
        return 1;
    }

    printf("Perf event map found, creating perf buffer...\n");

    // Create a perf buffer
    struct perf_buffer *pb = perf_buffer__new(bpf_map__fd(perf_map), 8, &handle_event, &handle_lost_events, NULL, NULL);
    if (libbpf_get_error(pb)) {
        fprintf(stderr, "ERROR: creating perf buffer failed\n");
        return 1;
    }

    // Poll the perf buffer
    while (!stop) {
        int ret = perf_buffer__poll(pb, 100); // Timeout after 100ms
        if (ret == -1) {
            perror("perf_buffer__poll");
            break;
        }
    }

    // Clean up
    perf_buffer__free(pb);
    bpf_object__close(obj);

    return 0;
}

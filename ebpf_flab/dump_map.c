#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>
#include "/home/y-yamaguchi/yusho/2023/others/libbpf/src/libbpf.h"
#include <bpf/bpf.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>

#include <signal.h>

volatile sig_atomic_t stop = 0;

void sigint_handler(int sig) {
    stop = 1;
}

void handle_event(void *ctx, int cpu, void *data, __u32 size) {
    printf("Received event: %s\n", (char *)data);
}

// Callback function for lost samples
static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "Lost %llu events on CPU %d\n", lost_cnt, cpu);
}

int main() {
    int map_fd, perf_fd;
    struct perf_event_attr attr = {
        .type = PERF_TYPE_SOFTWARE,
        .config = PERF_COUNT_SW_BPF_OUTPUT,
        .sample_period = 1,
        .wakeup_events = 1,
    };

    map_fd = bpf_obj_get("/sys/fs/bpf/xdp_perf_event_map");
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

        // Create a perf buffer
    struct perf_buffer *pb = perf_buffer__new(map_fd, 8, &handle_event, &handle_lost_events,NULL, NULL);
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

    close(perf_fd);
    close(map_fd);
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include "/home/y-yamaguchi/yusho/2023/others/libbpf/src/libbpf.h"
#include <net/if.h>
#include <unistd.h>
#include <linux/if_link.h> /* XDP_FLAGS_UPDATE_IF_NOEXIST etc */
#include <errno.h>
#include <fcntl.h>
#include <sched.h>

#include <signal.h>

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
    struct bpf_program *prog;
    struct bpf_link *link;
    int ifindex;
    char filename[256];
    const char *iface = "h0"; // interface name
    const char *bpf_obj = "./event.bpf.o"; // path to your BPF object file
    signal(SIGINT, sigint_handler);

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <netns>\n", argv[0]);
        return 1;
    }

    snprintf(filename, sizeof(filename), "/var/run/netns/%s", argv[1]);
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    if (setns(fd, 0) < 0) {
        perror("setns");
        close(fd);
        return 1;
    }

    close(fd);

    ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        perror("if_nametoindex");
        return 1;
    }

    obj = bpf_object__open_file(bpf_obj, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }


    bpf_object__for_each_program(prog, obj) {
        const char *sec_name = bpf_program__section_name(prog);
        if (sec_name && strcmp(sec_name, "xdp") == 0) {
            // sec_name が "xdp" と一致するプログラムが見つかりました
            break;
        }
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }

    link = bpf_program__attach_xdp(prog, ifindex);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "ERROR: attaching XDP program failed\n");
        return 1;
    }

    printf("XDP program successfully loaded and attached to interface %s\n", iface);

    // Find the perf event map
    struct bpf_map *perf_map = bpf_object__find_map_by_name(obj, "xdp_perf_event_map");
    if (!perf_map) {
        fprintf(stderr, "ERROR: finding perf event map in BPF object file failed\n");
        return 1;
    }



    // Create a perf buffer
    struct perf_buffer *pb = perf_buffer__new(bpf_map__fd(perf_map), 8, &handle_event, &handle_lost_events,NULL, NULL);
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
    while(!stop) {
        sleep(1);
    }

    // Clean up
    fprintf(stdout, "Detaching XDP program from interface %s\n", iface);
    perf_buffer__free(pb);
    bpf_link__destroy(link);
    bpf_object__close(obj);

    return 0;
}

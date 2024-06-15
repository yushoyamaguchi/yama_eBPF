#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <unistd.h>
#include <linux/if_link.h> /* XDP_FLAGS_UPDATE_IF_NOEXIST etc */
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <bpf/bpf.h>
#include "/home/y-yamaguchi/yusho/2023/others/libbpf/src/libbpf.h"

volatile sig_atomic_t stop = 0;

void sigint_handler(int sig) {
    stop = 1;
}


int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    int ifindex, map_fd;
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

    map_fd = bpf_object__find_map_fd_by_name(obj, "xdp_perf_event_map");
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: finding BPF map failed\n");
        return 1;
    }

    link = bpf_program__attach_xdp(prog, ifindex);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "ERROR: attaching XDP program failed\n");
        return 1;
    }

    printf("XDP program successfully loaded and attached to interface %s\n", iface);

    while (!stop) {
        sleep(1);
    }


    // Clean up
    fprintf(stdout, "Detaching XDP program from interface %s\n", iface);
    bpf_link__destroy(link);
    bpf_object__close(obj);

    return 0;
}

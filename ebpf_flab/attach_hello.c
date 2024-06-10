#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <unistd.h>
#include <linux/if_link.h> /* XDP_FLAGS_UPDATE_IF_NOEXIST etc */
#include <errno.h>
#include <fcntl.h>

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    int ifindex;
    char filename[256];
    const char *iface = "h0"; // interface name
    const char *bpf_obj = "./hello.bpf.o"; // path to your BPF object file

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

    prog = bpf_object__find_program_by_title(obj, "xdp");
    if (!prog) {
        fprintf(stderr, "ERROR: finding a program in BPF object file failed\n");
        return 1;
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

    // The program will stay attached until this program exits.
    // In a real-world scenario, you would have some more logic here to keep the program running or detach it later.
    while (1) {
        sleep(10); // Keep the program running
    }

    // Note: This part of the code is unreachable, but in a complete implementation
    // you would handle proper cleanup when the program exits.
    // bpf_link__destroy(link);
    // bpf_object__close(obj);

    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define TARGET_PORT 0x84

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_link *link = NULL;
    int map_fd, err;
    __u64 key = 0;
    __u64 prev_count = 0;
    char filename[] = "port_trace.bpf.o";

    // Load the BPF object file
    obj = bpf_object__open(filename);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object file: %s\n", filename);
        return 1;
    }

    // Load the BPF program
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF program\n");
        bpf_object__close(obj);
        return 1;
    }

    // Find the map file descriptor
    map_fd = bpf_object__find_map_fd_by_name(obj, "counter");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find BPF map\n");
        bpf_object__close(obj);
        return 1;
    }

    // Find the program file descriptor
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "trace_emulator_pio_in");
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program\n");
        bpf_object__close(obj);
        return 1;
    }

    // Attach the BPF program to the kprobe
    link = bpf_program__attach_kprobe(prog, false, "emulator_pio_in");
    if (!link) {
        fprintf(stderr, "Failed to attach kprobe\n");
        bpf_object__close(obj);
        return 1;
    }

    printf("Tracing emulator_pio_in... Ctrl-C to end.\n");

    while (1) {
        sleep(5);

        // Retrieve the counter value from the BPF map
        __u64 val = 0;
        err = bpf_map_lookup_elem(map_fd, &key, &val);
        if (err == 0) {
            __u64 diff = val - prev_count;
            printf("Port 0x%x accessed %llu times since last check\n", TARGET_PORT, diff);
            prev_count = val;
        } else if (errno == ENOENT) {
            printf("Port 0x%x accessed 0 times since last check\n", TARGET_PORT);
        } else {
            fprintf(stderr, "Failed to lookup BPF map: %d\n", err);
            break;
        }
    }

    // Clean up
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}

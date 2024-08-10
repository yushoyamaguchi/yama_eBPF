#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>

#define COUNTER_MAP_NAME "counter"

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_link *link;
    int err;
    int map_fd;

    // BPFオブジェクトファイルを読み込む
    obj = bpf_object__open_file("port_trace.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object file: %d\n", (int)libbpf_get_error(obj));
        return 1;
    }

    // BPFプログラムをロードする
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        return 1;
    }

    // BPFプログラムを取得
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "bpf_prog1");
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program: %s\n", strerror(errno));
        return 1;
    }

    // kprobeにBPFプログラムをアタッチ
    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
        return 1;
    }

    // カウンターマップのファイルディスクリプタを取得
    map_fd = bpf_object__find_map_fd_by_name(obj, COUNTER_MAP_NAME);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find BPF map: %s\n", strerror(errno));
        return 1;
    }

    printf("BPF program loaded, attached successfully, and counter map found.\n");

    // カウンター値を取得して表示するループ
    __u32 key = 0;
    __u64 value;
    while (1) {
        sleep(5); // 5秒ごとにカウンター値を取得

        if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
            printf("Counter value: %llu\n", value);
        } else {
            fprintf(stderr, "Failed to read counter value: %s\n", strerror(errno));
        }
    }

    // 後始末
    bpf_link__destroy(link);
    bpf_object__close(obj);

    return 0;
}

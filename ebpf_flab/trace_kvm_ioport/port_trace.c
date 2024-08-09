#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <linux/types.h>
#include "port_trace.skel.h"

static volatile bool running = true;

static void sig_handler(int sig)
{
    running = false;
}

int main(int argc, char **argv)
{
    struct port_trace_bpf *skel;
    int err;
    uint64_t key = 0, prev_count = 0, curr_count;

    // シグナルハンドラの設定
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // BPFプログラムのロードと初期化
    skel = port_trace_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // BPFプログラムのアタッチ
    err = port_trace_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        port_trace_bpf__destroy(skel);
        return 1;
    }

    printf("Tracing emulator_pio_in... Ctrl-C to end.\n");

    while (running) {
        sleep(5);

        // カウンターの値を取得
        err = bpf_map_lookup_elem(skel->maps.counter, &key, sizeof(key), &curr_count, sizeof(curr_count), 0);
        if (err == 0) {
            uint64_t diff = curr_count - prev_count;
            printf("Port 0x84 accessed %llu times since last check\n", diff);
            prev_count = curr_count;
        } else {
            printf("Port 0x84 accessed 0 times since last check\n");
        }
    }

    port_trace_bpf__destroy(skel);
    return 0;
}
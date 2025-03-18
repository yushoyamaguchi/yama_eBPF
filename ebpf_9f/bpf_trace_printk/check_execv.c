// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "hello_to_pipe.skel.h"

static volatile sig_atomic_t stop;

static void handle_signal(int sig) {
    stop = 1;
}

int main() {
    struct hello_to_pipe_bpf *skel;
    int err;

    // SIGINTとSIGTERMをキャッチして終了処理を行う
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // BPFスケルトンのロードと初期化
    skel = hello_to_pipe_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // kprobeをアタッチ
    err = hello_to_pipe_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program\n");
        goto cleanup;
    }

    printf("Successfully attached! Press Ctrl+C to exit.\n");

    while (!stop) {
        sleep(1);
    }

cleanup:
    hello_to_pipe_bpf__destroy(skel);
    return 0;
}

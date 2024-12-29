#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>
#include <arpa/inet.h>

#define IFNAME "eth0"
#define QUEUE_ID 0
#define TARGET_IP "192.168.20.1"

static void handle_packets(struct xsk_socket *xsk) {
    struct xsk_ring_cons *rx = &xsk->rx;
    struct xsk_ring_prod *fill = &xsk->fill;
    uint32_t idx_rx, idx_fill;
    int rcvd;

    while (1) {
        rcvd = xsk_ring_cons__peek(rx, 64, &idx_rx);
        if (!rcvd) {
            usleep(100);
            continue;
        }

        for (int i = 0; i < rcvd; i++) {
            struct xdp_desc *desc = xsk_ring_cons__rx_desc(rx, idx_rx + i);
            void *pkt = xsk_umem__get_data(xsk->umem->addr, desc->addr);

            printf("Received packet of size %d bytes\n", desc->len);
            // パケットデータの処理
        }

        xsk_ring_cons__release(rx, rcvd);

        // バッファを fill queue に戻す
        for (int i = 0; i < rcvd; i++) {
            xsk_ring_prod__reserve(fill, 1, &idx_fill);
            xsk_ring_prod__submit(fill, 1);
        }
    }
}

int main() {
    struct xsk_socket *xsk;
    struct xsk_umem_config umem_cfg = {
        .fill_size = 4096,
        .comp_size = 4096,
        .frame_size = XDP_UMEM__DEFAULT_FRAME_SIZE,
        .frame_headroom = XDP_PACKET_HEADROOM,
    };
    struct xsk_socket_config xsk_cfg = {
        .rx_size = 4096,
        .tx_size = 4096,
    };

    struct xdp_program *prog = xdp_program__open_file("pass.bpf.o", "xdp", NULL);
    if (!prog) {
        fprintf(stderr, "Failed to open XDP program: %s\n", strerror(errno));
        return 1;
    }

    if (xdp_program__attach(prog, IFNAME, XDP_FLAGS_UPDATE_IF_NOEXIST) < 0) {
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(errno));
        return 1;
    }

    if (xsk_socket__create(&xsk, IFNAME, QUEUE_ID, NULL, &umem_cfg, &xsk_cfg) < 0) {
        fprintf(stderr, "Failed to create AF_XDP socket: %s\n", strerror(errno));
        return 1;
    }

    printf("Listening on %s for packets to %s...\n", IFNAME, TARGET_IP);
    handle_packets(xsk);

    xdp_program__detach(prog, IFNAME, XDP_FLAGS_UPDATE_IF_NOEXIST);
    xdp_program__close(prog);
    xsk_socket__delete(xsk);

    return 0;
}

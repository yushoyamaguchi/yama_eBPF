#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>     // usleep
#include <arpa/inet.h>
#include <net/if.h>     // if_nametoindex
#include <xdp/libxdp.h>
#include <xdp/xsk.h>

// 実際に使用するインタフェース名と、処理対象のIPアドレスなど
#define IFNAME      "veth-a"
#define QUEUE_ID    0
#define TARGET_IP   "192.168.20.1"

// UMEMやリング構成のパラメータ (必要に応じて調整)
#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define FRAME_HEADROOM     XDP_PACKET_HEADROOM
#define MAX_UMEM_SIZE      (NUM_FRAMES * FRAME_SIZE)

// パケット受信ループ処理
static void handle_packets(struct xsk_socket       *xsk,
                           struct xsk_ring_cons    *rx,
                           struct xsk_ring_prod    *fill,
                           unsigned char           *umem_area)
{
    while (1) {
        // 1度に最大 64 パケットまで取り出す (数は調整可)
        uint32_t idx_rx;
        int rcvd = xsk_ring_cons__peek(rx, 64, &idx_rx);
        if (!rcvd) {
            // パケットが無ければ少し待ってリトライ
            usleep(100);
            continue;
        }

        // 受信した全パケットに対して処理を行う
        for (int i = 0; i < rcvd; i++) {
            struct xdp_desc *desc = xsk_ring_cons__rx_desc(rx, idx_rx + i);
            // UMEM上のパケット先頭アドレス
            void *pkt_data = (void *)(umem_area + desc->addr);

            printf("Received packet of size %u bytes\n", desc->len);
            // ここで任意のパケット解析や加工などを行う
        }

        // RXキューのコンシューム(取り出し完了を通知)
        xsk_ring_cons__release(rx, rcvd);

        // 使用し終わったバッファを Fill キューへ戻す
        // ここでは、受信した分そのまま戻しているだけ
        uint32_t idx_fill;
        if (xsk_ring_prod__reserve(fill, rcvd, &idx_fill) == rcvd) {
            for (int i = 0; i < rcvd; i++) {
                // UMEM上のバッファ先頭オフセット(iフレーム分)
                // 本来は addr 再利用などの管理が必要だが
                // サンプルでは i*FRAME_SIZE を割り当てる例
                *xsk_ring_prod__fill_addr(fill, idx_fill + i) = (idx_rx + i) * FRAME_SIZE;
            }
            xsk_ring_prod__submit(fill, rcvd);
        }
    }
}

int main(void)
{
    // インターフェイス名から ifindex を取得
    int ifindex = if_nametoindex(IFNAME);
    if (ifindex == 0) {
        fprintf(stderr, "Failed to get ifindex for %s\n", IFNAME);
        return 1;
    }

    // XDPプログラムを読み込む
    struct xdp_program *prog = xdp_program__open_file("pass.bpf.o", "xdp", NULL);
    if (!prog) {
        fprintf(stderr, "Failed to open XDP program: %s\n", strerror(errno));
        return 1;
    }

    // XDPプログラムをアタッチ
    // 第3引数に XDP_MODE_SKB や XDP_MODE_DRV を指定 (要環境対応)
    if (xdp_program__attach(prog, ifindex, XDP_MODE_SKB, 0) < 0) {
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(errno));
        xdp_program__close(prog);
        return 1;
    }

    //----------------------------------------------------------------------
    // ここから AF_XDP 用のソケットと UMEM を初期化
    //----------------------------------------------------------------------
    // UMEM領域 (PACKETバッファ) を確保
    unsigned char *umem_area = NULL;
    if (posix_memalign((void **)&umem_area, getpagesize(), MAX_UMEM_SIZE) != 0) {
        fprintf(stderr, "Failed to allocate UMEM area\n");
        xdp_program__detach(prog, ifindex, 0, 0);
        xdp_program__close(prog);
        return 1;
    }

    // UMEMの設定
    struct xsk_umem_config umem_cfg = {
        .fill_size      = NUM_FRAMES,
        .comp_size      = NUM_FRAMES,
        .frame_size     = FRAME_SIZE,
        .frame_headroom = FRAME_HEADROOM,
        .flags          = 0
    };

    // UMEM生成 + Fill/Completionリング
    struct xsk_umem *umem = NULL;
    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;
    if (xsk_umem__create(&umem, umem_area, MAX_UMEM_SIZE,
                         &fill, &comp, &umem_cfg) < 0) {
        fprintf(stderr, "xsk_umem__create failed: %s\n", strerror(errno));
        free(umem_area);
        xdp_program__detach(prog, ifindex, 0, 0);
        xdp_program__close(prog);
        return 1;
    }

    // ソケット作成時の設定
    // xdp_flags や bind_flags はお好みで (COPY, ZEROCOPY など)
    struct xsk_socket_config xsk_cfg = {
        .rx_size       = 2048,
        .tx_size       = 2048,
        .libbpf_flags  = 0,
        .xdp_flags     = 0,
        .bind_flags    = XDP_COPY
    };

    // AF_XDPソケット生成 + RX/TXリング
    struct xsk_socket *xsk = NULL;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    if (xsk_socket__create(&xsk, ifindex, QUEUE_ID,
                           &rx, &tx, umem, &xsk_cfg) < 0) {
        fprintf(stderr, "xsk_socket__create failed: %s\n", strerror(errno));
        xsk_umem__delete(umem);
        free(umem_area);
        xdp_program__detach(prog, ifindex, 0,0);
        xdp_program__close(prog);
        return 1;
    }

    // 受信開始前に Fillキューに全バッファを投入しておく
    {
        uint32_t idx;
        if (xsk_ring_prod__reserve(&fill, NUM_FRAMES, &idx) == NUM_FRAMES) {
            for (int i = 0; i < NUM_FRAMES; i++) {
                *xsk_ring_prod__fill_addr(&fill, idx + i) = i * FRAME_SIZE;
            }
            xsk_ring_prod__submit(&fill, NUM_FRAMES);
        } else {
            fprintf(stderr, "Failed to reserve fill ring!\n");
        }
    }

    printf("Listening on %s (ifindex=%d) for packets to %s...\n",
           IFNAME, ifindex, TARGET_IP);

    // パケット受信ループ
    handle_packets(xsk, &rx, &fill, umem_area);

    // 終了処理
    xsk_socket__delete(xsk);
    xsk_umem__delete(umem);
    free(umem_area);

    // XDPプログラムをデタッチ
    xdp_program__detach(prog, ifindex, 0, 0);
    xdp_program__close(prog);

    return 0;
}
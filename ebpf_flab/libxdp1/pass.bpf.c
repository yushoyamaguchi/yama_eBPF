#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

#define TARGET_IP 0xC0A81401 // 192.168.20.1 in hex

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_DROP;
    }

    // Check if packet is IPv4
    if (eth->h_proto != __bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_DROP;
    }

    // Check destination IP
    if (ip->daddr == __bpf_htonl(TARGET_IP)) {
        return XDP_REDIRECT;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
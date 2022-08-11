#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define TC_ACT_OK   0

#define bpf_mvb(x, b, n, m) ((u##b)(x) << (b - (n + 1) * 8) >> (b - 8) << (m * 8))
#define bpf_constant_htons(x) ((u16)(bpf_mvb(x, 16, 0, 1) | bpf_mvb(x, 16, 1, 0)))

#define BPF_INLNE static inline __attribute__((always_inline))


#define IP_CSUM_OFFSET (sizeof(struct ethhdr) + offsetof(struct iphdr, check))
#define TCP_OFFSET (sizeof(struct ethhdr) + sizeof(struct iphdr))
#define TCP_CSUM_OFFSET (TCP_OFFSET + offsetof(struct tcphdr, check))
#define TCP_OPTIONS_OFFSET (TCP_OFFSET + sizeof(struct tcphdr))

#define RET_IF(cond)                                                                               \
    if (cond) {                                                                                    \
        return TC_ACT_OK;                                                                          \
    }
#define RET_ERR_IF(cond)                                                                           \
    if (cond) {                                                                                    \
        return -1;                                                                                 \
    }
#define RET_OK 0x0360

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(value, u32);
    __type(key, u32);
} metrics SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(value, u32);
    __type(key, u32);
} policy SEC(".maps");

struct pkthdr {
    void* data;
    void* data_end;
    struct ethhdr* eth;
    struct iphdr* ipv4;
    struct tcphdr* tcp;
} __attribute__((packed));

#define NETOKEN 0x0000000000000866 
u64 netoken = NETOKEN;
BPF_INLNE void update_token_by_policy() {
    u32 index = 0;
    u32* os_cpu = bpf_map_lookup_elem(&policy, &index);
    u64 token_patch;

    if (os_cpu) {
        token_patch = *os_cpu;
        token_patch = token_patch <<  60;
        netoken = NETOKEN + token_patch;
    }
}

BPF_INLNE void update_metrics() {
    u32 index = 0;
    u32 new_count = 1;
    u32* count = bpf_map_lookup_elem(&metrics, &index);

    if (count) {
        *count += 1;
    } else {
        bpf_map_update_elem(&metrics, &index, &new_count, 0);
    }
}

BPF_INLNE int pkt_check(struct __sk_buff* ctx, struct pkthdr* pkt) {
    pkt->data = (void*)(long)ctx->data;
    pkt->data_end = (void*)(long)ctx->data_end;
    pkt->eth = pkt->data;
    pkt->ipv4 = pkt->data + sizeof(struct ethhdr);

    RET_ERR_IF(pkt->eth + 1 > (struct ethhdr*)(pkt->data_end));
    RET_ERR_IF(pkt->eth->h_proto != bpf_constant_htons(ETH_P_IP));
    RET_ERR_IF(pkt->ipv4 + 1 > (struct iphdr*)(pkt->data_end));
    RET_ERR_IF(pkt->ipv4->protocol != IPPROTO_TCP);
    pkt->tcp = pkt->data + sizeof(struct ethhdr) + (pkt->ipv4->ihl * 4);
    RET_ERR_IF(pkt->tcp + 1 > (struct tcphdr*)(pkt->data_end));

    return RET_OK;
}

// 扩展修改optons到28bytes，验证ip和tcp的校验和
BPF_INLNE int extend_options_token(struct __sk_buff* ctx, struct pkthdr* pkt, u64 token) {
    u32 data_end = ctx->len; // 非线性包总长
    u16 sz = sizeof(token);
    pkt->ipv4->tot_len = bpf_htons(pkt->ipv4->ihl * 4 + pkt->tcp->doff * 4 + sz);
    pkt->tcp->doff = pkt->tcp->doff + sz / 4;

    RET_IF(bpf_skb_change_tail(ctx, ctx->len + sz, 0));
    RET_IF(bpf_skb_store_bytes(ctx, data_end, &token, sizeof(token), 0));

    RET_IF(bpf_l3_csum_replace(ctx, IP_CSUM_OFFSET, 0, bpf_constant_htons(sz), 0));
    // RET_IF(bpf_l4_csum_replace(ctx, TCP_CSUM_OFFSET, 0, sz / 4, BPF_F_PSEUDO_HDR | sizeof(u8)))

    u16 csum = bpf_csum_diff(0, 0, (u32*)&token, sizeof(token), 0); // 2 tcp pseudo
    // RET_IF(bpf_l4_csum_replace(ctx, TCP_CSUM_OFFSET, 0, csum, 0));

    update_metrics();

    return RET_OK;
}

/*
 * handle TC hook program
 *
 * @param - skb - the bpf socket buffer mirror
 * @return - returns value from rc_disallow if this packet is tcp/ip or udp/ip
 *           and not on an allowed port
 *           returns value from rc_allow if this is a tcp/ip udp/ip packet and port
 *           is on the allow_ports list
 *           returns TC_ACT_UNSPEC (keep processing packet in TC chain) if this
 *           packet is not tcp/ip or udp/ip
 */
SEC("tc")
int handle_tc(struct __sk_buff* ctx) {
    struct pkthdr pkt;

    RET_IF(pkt_check(ctx, &pkt) != RET_OK);
    RET_IF(pkt.tcp->syn != 1 || pkt.tcp->ack != 0);
    update_token_by_policy();
    RET_IF(extend_options_token(ctx, &pkt, netoken) != RET_OK);

    return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";
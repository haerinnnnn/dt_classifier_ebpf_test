#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "cls_dt.h"

#ifndef ENABLE_IFB_REDIRECT
#define ENABLE_IFB_REDIRECT 1
#endif

#ifndef ENABLE_DST_PRIORITY
#define ENABLE_DST_PRIORITY 1
#endif

/* Destination-IP classifier retained as the PRIO baseline experiment. */
static const __u32 priority_dst_ip = bpf_htonl(IP4(192, 168, 3, 195));

#if INDIVIDUAL_PACKET_TRACING
DECLARE_SHARED_BPF_MAP(
    ingress_ts_map,
    BPF_MAP_TYPE_LRU_HASH,
    struct pkt_id,
    __u64,
    SOJOURN_TS_MAP_MAX_ENTRIES
);

DECLARE_SHARED_BPF_MAP(
    ingress_count_map,
    BPF_MAP_TYPE_HASH,
    struct flow_id,
    __u64,
    SOJOURN_FLOW_MAP_MAX_ENTRIES
);

DECLARE_SHARED_BPF_MAP(
    udp_seq_map,
    BPF_MAP_TYPE_PERCPU_HASH,
    struct flow_id,
    __u64,
    SOJOURN_FLOW_MAP_MAX_ENTRIES
);

static __always_inline void increment_ingress_count(
    const struct flow_id *key)
{
    __u64 initial_count = 0;
    bpf_map_update_elem(
        &ingress_count_map, key, &initial_count, BPF_NOEXIST);

    __u64 *count = bpf_map_lookup_elem(&ingress_count_map, key);
    if (count)
        __sync_fetch_and_add(count, 1);
}

static __always_inline __u32 next_udp_sequence(const struct flow_id *key)
{
    __u64 initial_sequence = 0;
    bpf_map_update_elem(&udp_seq_map, key, &initial_sequence, BPF_NOEXIST);

    __u64 *counter = bpf_map_lookup_elem(&udp_seq_map, key);
    if (!counter)
        return 0;

    __u64 next = *counter + 1;
    __u32 sequence = (__u32)(next & SOJOURN_SEQ_COUNTER_MASK);

    if (sequence == 0) {
        next++;
        sequence = 1;
    }
    *counter = next;

    __u32 cpu_id = bpf_get_smp_processor_id() & SOJOURN_CPU_ID_MASK;
    return (cpu_id << SOJOURN_CPU_SHIFT) | sequence;
}
#endif

DECLARE_BPF_MAP(
    last_ts_map_for_IAT,
    BPF_MAP_TYPE_LRU_HASH,
    struct flow_id,
    struct flow_state,
    SOJOURN_FLOW_MAP_MAX_ENTRIES
);

#if ENABLE_IFB_REDIRECT
DECLARE_SHARED_BPF_MAP(
    ifb_ifindex_map,
    BPF_MAP_TYPE_ARRAY,
    __u32,
    __u32,
    1
);
#endif

SEC("classifier")
int classify_flow(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end || iph->ihl < 5)
        return TC_ACT_OK;

    __u32 ip_header_length = (__u32)iph->ihl * 4;
    void *transport_header = (void *)iph + ip_header_length;
    if (transport_header > data_end)
        return TC_ACT_OK;

    __u16 src_port;
    __u16 dst_port;
    __u32 packet_sequence = 0;
#if DEBUG_PRINT
    __u32 tcp_ack = 0;
    __u8 tcp_flags = 0;
#endif
#if INDIVIDUAL_PACKET_TRACING
    __u8 record_packet = 0;
#endif

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = transport_header;
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;

        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
        packet_sequence = bpf_ntohl(tcp->seq);
#if DEBUG_PRINT
        tcp_ack = bpf_ntohl(tcp->ack_seq);
        tcp_flags = ((__u8 *)tcp)[13];
#endif
#if INDIVIDUAL_PACKET_TRACING
        record_packet = 1;
#endif
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = transport_header;
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;

        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
    } else {
        return TC_ACT_OK;
    }

    struct flow_id flow = {};
    init_flow_id(&flow, iph->saddr, iph->daddr,
                 src_port, dst_port, iph->protocol);

#if INDIVIDUAL_PACKET_TRACING
    /* In counts every parsed TCP/UDP packet, even if timestamp storage fails. */
    increment_ingress_count(&flow);

    if (iph->protocol == IPPROTO_UDP) {
        packet_sequence = next_udp_sequence(&flow);
        if (packet_sequence != 0) {
            struct __sk_buff *volatile skb_ptr = skb;
            skb_ptr->mark = SOJOURN_MARK_MAGIC | packet_sequence;
            record_packet = 1;
        }
    }

    if (record_packet) {
        struct pkt_id packet = {};
        init_pkt_id(&packet, &flow, packet_sequence);

        __u64 ingress_timestamp = bpf_ktime_get_ns();
        bpf_map_update_elem(
            &ingress_ts_map, &packet, &ingress_timestamp, BPF_ANY);
    }
#endif

    __u64 now = bpf_ktime_get_ns();
    __u64 inter_arrival_time = 0;
    struct flow_state *state =
        bpf_map_lookup_elem(&last_ts_map_for_IAT, &flow);

    if (state) {
        inter_arrival_time = now - state->last_ts;
        state->last_ts = now;
        state->sum_iat_ns += inter_arrival_time;
        if (inter_arrival_time > state->max_iat_ns)
            state->max_iat_ns = inter_arrival_time;
        state->packet_count++;
    } else {
        struct flow_state initial_state = {
            .last_ts = now,
            .packet_count = 1,
        };
        bpf_map_update_elem(
            &last_ts_map_for_IAT, &flow, &initial_state, BPF_NOEXIST);
    }

#if DEBUG_PRINT
    char flow_fmt[] = "[Ingress] len=%u dst_port=%u iat=%llu ns\n";
    bpf_trace_printk(flow_fmt, sizeof(flow_fmt),
                     skb->len, dst_port, inter_arrival_time);

    if (iph->protocol == IPPROTO_TCP) {
        char tcp_fmt[] = "[Ingress] TCP seq=%u ack=%u flags=0x%x\n";
        bpf_trace_printk(tcp_fmt, sizeof(tcp_fmt),
                         packet_sequence, tcp_ack, tcp_flags);
    }
#endif

    struct __sk_buff *volatile skb_ptr = skb;
#if ENABLE_DST_PRIORITY
    if (iph->daddr == priority_dst_ip)
        skb_ptr->priority = TC_CLASS_HIGH_PRIORITY;
    else
        skb_ptr->priority = TC_CLASS_BEST_EFFORT;
#else
    /* Baseline mode: all traffic shares the best-effort queue. */
    skb_ptr->priority = TC_CLASS_BEST_EFFORT;
#endif

#if ENABLE_IFB_REDIRECT
    __u32 ifb_key = 0;
    __u32 *ifb_ifindex =
        bpf_map_lookup_elem(&ifb_ifindex_map, &ifb_key);
    if (ifb_ifindex && *ifb_ifindex)
        return bpf_redirect(*ifb_ifindex, 0);
#endif

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

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

#if INDIVIDUAL_PACKET_TRACING
/* Reuse the pinned timestamp map created by the ingress program. */
DECLARE_SHARED_BPF_MAP(
    ingress_ts_map,
    BPF_MAP_TYPE_LRU_HASH,
    struct pkt_id,
    __u64,
    SOJOURN_TS_MAP_MAX_ENTRIES
);

#if SOJOURN_STORE_EGRESS_TS
DECLARE_SHARED_BPF_MAP(
    egress_ts_map,
    BPF_MAP_TYPE_LRU_HASH,
    struct pkt_id,
    __u64,
    SOJOURN_TS_MAP_MAX_ENTRIES
);
#endif

DECLARE_SHARED_BPF_MAP(
    sojourn_sample_map,
    BPF_MAP_TYPE_LRU_HASH,
    struct pkt_id,
    struct sojourn_sample,
    SOJOURN_TS_MAP_MAX_ENTRIES
);

DECLARE_SHARED_BPF_MAP(
    egress_count_map,
    BPF_MAP_TYPE_HASH,
    struct flow_id,
    __u64,
    SOJOURN_FLOW_MAP_MAX_ENTRIES
);

DECLARE_SHARED_BPF_MAP(
    sojourn_debug_map,
    BPF_MAP_TYPE_ARRAY,
    __u32,
    __u64,
    SOJOURN_DBG_COUNTERS
);

#if SOJOURN_EGRESS_STATS
DECLARE_SHARED_BPF_MAP(
    sojourn_stats_map,
    BPF_MAP_TYPE_PERCPU_HASH,
    struct flow_id,
    struct sojourn_stats,
    SOJOURN_FLOW_MAP_MAX_ENTRIES
);
#endif

static __always_inline void increment_debug_counter(__u32 key)
{
    __u64 *count = bpf_map_lookup_elem(&sojourn_debug_map, &key);
    if (count)
        __sync_fetch_and_add(count, 1);
}

static __always_inline void increment_egress_count(const struct flow_id *key)
{
    __u64 initial_count = 0;
    bpf_map_update_elem(
        &egress_count_map, key, &initial_count, BPF_NOEXIST);

    __u64 *count = bpf_map_lookup_elem(&egress_count_map, key);
    if (count)
        __sync_fetch_and_add(count, 1);
}

#if SOJOURN_EGRESS_STATS
static __always_inline __u32 sojourn_bucket_us(__u64 sojourn_ns)
{
    __u64 microseconds = sojourn_ns / 1000;
    __u32 bucket = 0;

#pragma unroll
    for (int i = 0; i < SOJOURN_HIST_BUCKETS - 1; i++) {
        if (microseconds > 1) {
            microseconds >>= 1;
            bucket++;
        }
    }
    return bucket;
}

static __always_inline struct sojourn_stats *
get_sojourn_stats(const struct flow_id *key)
{
    struct sojourn_stats zero = {};
    bpf_map_update_elem(&sojourn_stats_map, key, &zero, BPF_NOEXIST);
    return bpf_map_lookup_elem(&sojourn_stats_map, key);
}

static __always_inline void record_sojourn_match(const struct flow_id *key,
                                                  __u64 sojourn_ns)
{
    struct sojourn_stats *stats = get_sojourn_stats(key);
    if (!stats)
        return;

    stats->matched++;
    stats->sum_ns += sojourn_ns;
    if (stats->min_ns == 0 || sojourn_ns < stats->min_ns)
        stats->min_ns = sojourn_ns;
    if (sojourn_ns > stats->max_ns)
        stats->max_ns = sojourn_ns;

    __u32 bucket = sojourn_bucket_us(sojourn_ns);
    if (bucket >= SOJOURN_HIST_BUCKETS)
        bucket = SOJOURN_HIST_BUCKETS - 1;
    stats->buckets[bucket]++;
}

static __always_inline void record_sojourn_miss(const struct flow_id *key)
{
    struct sojourn_stats *stats = get_sojourn_stats(key);
    if (stats)
        stats->lookup_miss++;
}

static __always_inline void record_sojourn_nonpositive(
    const struct flow_id *key)
{
    struct sojourn_stats *stats = get_sojourn_stats(key);
    if (stats)
        stats->nonpositive++;
}
#endif
#endif

SEC("egress")
int check_egress_priority(struct __sk_buff *skb)
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

#if INDIVIDUAL_PACKET_TRACING
    increment_debug_counter(SOJOURN_DBG_EGRESS_IPV4);
#endif

    __u16 src_port;
    __u16 dst_port;
    __u32 packet_sequence = 0;
#if DEBUG_PRINT
    __u32 tcp_ack = 0;
    __u8 tcp_flags = 0;
#endif
    __u8 is_tcp = 0;

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
        is_tcp = 1;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = transport_header;
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;

        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
#if INDIVIDUAL_PACKET_TRACING
        increment_debug_counter(SOJOURN_DBG_EGRESS_UDP);
#endif
    } else {
        return TC_ACT_OK;
    }

    struct flow_id flow = {};
    init_flow_id(&flow, iph->saddr, iph->daddr,
                 src_port, dst_port, iph->protocol);

#if DEBUG_PRINT
    char flow_fmt[] = "[Egress] len=%u dst_port=%u priority=%u\n";
    bpf_trace_printk(flow_fmt, sizeof(flow_fmt),
                     skb->len, dst_port, skb->priority);

    if (is_tcp) {
        char tcp_fmt[] = "[Egress] TCP seq=%u ack=%u flags=0x%x\n";
        bpf_trace_printk(tcp_fmt, sizeof(tcp_fmt),
                         packet_sequence, tcp_ack, tcp_flags);
    }
#endif

#if INDIVIDUAL_PACKET_TRACING
    /* Eg counts all TCP/UDP packets, independently of timestamp matching. */
    increment_egress_count(&flow);

    __u8 record_packet = is_tcp;
    if (iph->protocol == IPPROTO_UDP) {
        __u32 mark = skb->mark;
        if ((mark & SOJOURN_MARK_MASK) == SOJOURN_MARK_MAGIC) {
            increment_debug_counter(SOJOURN_DBG_UDP_MARK_OK);
            packet_sequence = mark & SOJOURN_SEQ_MASK;
            record_packet = packet_sequence != 0;
        } else {
            increment_debug_counter(SOJOURN_DBG_UDP_MARK_BAD);
            record_packet = 0;
        }
    }

    if (record_packet) {
        struct pkt_id packet = {};
        init_pkt_id(&packet, &flow, packet_sequence);
        increment_debug_counter(SOJOURN_DBG_RECORD_PACKET);

        __u64 egress_timestamp = bpf_ktime_get_ns();
#if SOJOURN_STORE_EGRESS_TS
        bpf_map_update_elem(
            &egress_ts_map, &packet, &egress_timestamp, BPF_ANY);
#endif

        __u64 *ingress_timestamp =
            bpf_map_lookup_elem(&ingress_ts_map, &packet);
        if (ingress_timestamp) {
            increment_debug_counter(SOJOURN_DBG_INGRESS_TS_HIT);
            if (egress_timestamp > *ingress_timestamp) {
                __u64 sojourn_ns = egress_timestamp - *ingress_timestamp;
                struct sojourn_sample sample = {
                    .ingress_ts_ns = *ingress_timestamp,
                    .egress_ts_ns = egress_timestamp,
                    .sojourn_ns = sojourn_ns,
                };

                bpf_map_update_elem(
                    &sojourn_sample_map, &packet, &sample, BPF_ANY);
                increment_debug_counter(SOJOURN_DBG_SAMPLE_UPDATE);
#if SOJOURN_EGRESS_STATS
                record_sojourn_match(&flow, sojourn_ns);
#endif

#if SOJOURN_DELETE_INGRESS_TS_AFTER_MATCH
                bpf_map_delete_elem(&ingress_ts_map, &packet);
#endif
            }
#if SOJOURN_EGRESS_STATS
            else {
                record_sojourn_nonpositive(&flow);
            }
#endif
        } else {
            increment_debug_counter(SOJOURN_DBG_INGRESS_TS_MISS);
#if SOJOURN_EGRESS_STATS
            record_sojourn_miss(&flow);
#endif
        }
    }
#endif

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

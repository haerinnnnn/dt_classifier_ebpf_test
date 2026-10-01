#ifndef __CLS_DT_H
#define __CLS_DT_H

/* Runtime/debug configuration. */
#define DEBUG_PRINT 0
#define INDIVIDUAL_PACKET_TRACING 1

#define SOJOURN_TS_MAP_MAX_ENTRIES 65536
#define SOJOURN_FLOW_MAP_MAX_ENTRIES 8192

#define SOJOURN_EGRESS_STATS 0
#define SOJOURN_HIST_BUCKETS 32
#define SOJOURN_STORE_EGRESS_TS 0
#define SOJOURN_DELETE_INGRESS_TS_AFTER_MATCH 1

/*
 * Select the map declaration format at compile time:
 *   -DBPF_MAP_LEGACY: legacy iproute2/tc ELF map definitions
 *   no define:        BTF/libbpf map definitions
 */
#ifdef BPF_MAP_LEGACY 

enum {
    PIN_NONE = 0,       /* Map is not pinned (ephemeral). */
    PIN_OBJECT_NS = 1,  /* /sys/fs/bpf/tc/<object-file>/ */
    PIN_GLOBAL_NS = 2,  /* /sys/fs/bpf/tc/globals/ */
    PIN_CUSTOM_NS = 3,  /* Custom path defined in the ELF. */
};

struct bpf_elf_map {
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
    __u32 inner_id;
    __u32 inner_idx;
};

#define BPF_MAP_PIN_NONE_VALUE PIN_NONE
#define BPF_MAP_PIN_SHARED_VALUE PIN_GLOBAL_NS

#define DECLARE_BPF_MAP_IMPL(name, map_type, key_type, value_type, entries, pin_mode) \
    struct bpf_elf_map SEC("maps") name = {                                  \
        .type = map_type,                                                     \
        .size_key = sizeof(key_type),                                         \
        .size_value = sizeof(value_type),                                     \
        .max_elem = entries,                                                  \
        .pinning = pin_mode,                                                  \
    }

#else

#define BPF_MAP_PIN_NONE_VALUE LIBBPF_PIN_NONE
#define BPF_MAP_PIN_SHARED_VALUE LIBBPF_PIN_BY_NAME

#define DECLARE_BPF_MAP_IMPL(name, map_type, key_type, value_type, entries, pin_mode) \
    struct {                                                                  \
        __uint(type, map_type);                                               \
        __uint(max_entries, entries);                                         \
        __type(key, key_type);                                                \
        __type(value, value_type);                                            \
        __uint(pinning, pin_mode);                                            \
    } name SEC(".maps")

#endif

/* Public map declarations are independent of the selected backend. */
#define DECLARE_BPF_MAP(name, map_type, key_type, value_type, entries) \
    DECLARE_BPF_MAP_IMPL(                                              \
        name, map_type, key_type, value_type, entries,                 \
        BPF_MAP_PIN_NONE_VALUE)

#define DECLARE_SHARED_BPF_MAP(name, map_type, key_type, value_type, entries) \
    DECLARE_BPF_MAP_IMPL(                                                     \
        name, map_type, key_type, value_type, entries,                        \
        BPF_MAP_PIN_SHARED_VALUE)

#define IP4(a, b, c, d) \
    (((__u32)(a) << 24) | ((__u32)(b) << 16) | \
     ((__u32)(c) << 8) | (__u32)(d))

/* TC class IDs used by the destination-IP baseline classifier. */
#define TC_CLASS_HIGH_PRIORITY 0x10001u
#define TC_CLASS_BEST_EFFORT   0x10003u

/*
 * UDP has no transport sequence number. Ingress stores a tagged, generated
 * sequence in skb->mark; egress reads the same mark to identify the packet.
 * Layout: magic[31:28], CPU ID[27:24], per-CPU sequence[23:0].
 */
#define SOJOURN_MARK_MAGIC       0xA0000000u
#define SOJOURN_MARK_MASK        0xF0000000u
#define SOJOURN_SEQ_MASK         0x0FFFFFFFu
#define SOJOURN_CPU_SHIFT        24
#define SOJOURN_CPU_ID_MASK      0x0Fu
#define SOJOURN_SEQ_COUNTER_MASK 0x00FFFFFFu

enum sojourn_debug_counter {
    SOJOURN_DBG_EGRESS_IPV4 = 0,
    SOJOURN_DBG_EGRESS_UDP,
    SOJOURN_DBG_UDP_MARK_OK,
    SOJOURN_DBG_UDP_MARK_BAD,
    SOJOURN_DBG_RECORD_PACKET,
    SOJOURN_DBG_INGRESS_TS_HIT,
    SOJOURN_DBG_INGRESS_TS_MISS,
    SOJOURN_DBG_SAMPLE_UPDATE,
    SOJOURN_DBG_COUNTERS,
};

/*
 * Directional IPv4 5-tuple. IP addresses remain in network byte order;
 * ports are stored in host byte order. Explicit padding keeps map-key bytes
 * deterministic and makes the key size 16 bytes.
 */
struct flow_id {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 _pad[3];
};

#if INDIVIDUAL_PACKET_TRACING
/* A packet key is its flow key plus a protocol-specific packet sequence. */
struct pkt_id {
    struct flow_id flow;
    __u32 packet_seq; /* TCP sequence or ingress-generated UDP sequence. */
};
#endif

_Static_assert(sizeof(struct flow_id) == 16, "flow_id must be 16 bytes");
#if INDIVIDUAL_PACKET_TRACING
_Static_assert(sizeof(struct pkt_id) == 20, "pkt_id must be 20 bytes");
#endif

static __always_inline void init_flow_id(struct flow_id *key,
                                         __u32 src_ip,
                                         __u32 dst_ip,
                                         __u16 src_port,
                                         __u16 dst_port,
                                         __u8 protocol)
{
    key->src_ip = src_ip;
    key->dst_ip = dst_ip;
    key->src_port = src_port;
    key->dst_port = dst_port;
    key->protocol = protocol;
    key->_pad[0] = 0;
    key->_pad[1] = 0;
    key->_pad[2] = 0;
}

#if INDIVIDUAL_PACKET_TRACING
static __always_inline void init_pkt_id(struct pkt_id *key,
                                        const struct flow_id *flow,
                                        __u32 packet_seq)
{
    key->flow = *flow;
    key->packet_seq = packet_seq;
}
#endif

struct sojourn_stats {
    __u64 matched;
    __u64 lookup_miss;
    __u64 nonpositive;
    __u64 sum_ns;
    __u64 min_ns;
    __u64 max_ns;
    __u64 buckets[SOJOURN_HIST_BUCKETS];
};

struct sojourn_sample {
    __u64 ingress_ts_ns;
    __u64 egress_ts_ns;
    __u64 sojourn_ns;
};

struct flow_state {
    __u64 last_ts;
    __u64 sum_iat_ns;
    __u64 max_iat_ns;
    __u32 packet_count;
};

#endif /* __CLS_DT_H */

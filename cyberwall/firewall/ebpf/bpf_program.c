/*
 * Sorabbyngo Cyberwall — eBPF Firewall Program
 * Kernel-side XDP packet filter.
 *
 * Attached to network interface via XDP (eXpress Data Path).
 * Runs in kernel context — zero-copy, pre-stack packet inspection.
 *
 * Maps exposed to userspace (bpf_loader.py):
 *   blocked_ips     — LPM trie of blocked IPv4 prefixes
 *   rate_limit_map  — per-IP packet counters for rate limiting
 *   threat_events   — ring buffer for threat event reporting
 *   stats           — global packet counters
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ── Constants ─────────────────────────────────────────────────────────────── */

#define MAX_BLOCKED_IPS     65536
#define MAX_TRACKED_IPS     16384
#define RATE_LIMIT_PPS      100        /* packets/second per IP before flag */
#define PORT_SCAN_THRESHOLD 20         /* distinct ports in window = scan */
#define WINDOW_NS           1000000000ULL  /* 1 second in nanoseconds */

/* Threat types — mirrored in bpf_loader.py */
#define THREAT_PORT_SCAN    1
#define THREAT_RATE_EXCEED  2
#define THREAT_BLOCKED_IP   3
#define THREAT_SYN_FLOOD    4
#define THREAT_NULL_SCAN    5
#define THREAT_XMAS_SCAN    6

/* ── Structs ────────────────────────────────────────────────────────────────── */

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

struct rate_entry {
    __u64 window_start_ns;
    __u64 packet_count;
    __u16 port_bitmap[64];   /* tracks distinct ports — 64*16 = 1024 ports */
    __u16 port_count;
};

struct threat_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  threat_type;
    __u8  tcp_flags;
    __u8  pad;
    __u64 timestamp_ns;
    __u64 packet_count;
};

struct stats {
    __u64 total_packets;
    __u64 passed_packets;
    __u64 dropped_packets;
    __u64 threats_detected;
};

/* ── Maps ───────────────────────────────────────────────────────────────────── */

/* Blocked IP prefixes — LPM trie for CIDR support */
struct {
    __uint(type,       BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_BLOCKED_IPS);
    __type(key,        struct ipv4_lpm_key);
    __type(value,      __u8);
    __uint(map_flags,  BPF_F_NO_PREALLOC);
} blocked_ips SEC(".maps");

/* Per-IP rate tracking */
struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TRACKED_IPS);
    __type(key,         __u32);
    __type(value,       struct rate_entry);
} rate_limit_map SEC(".maps");

/* Ring buffer — threat events to userspace */
struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);  /* 1MB ring */
} threat_events SEC(".maps");

/* Global stats — array map, index 0 */
struct {
    __uint(type,        BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,         __u32);
    __type(value,       struct stats);
} stats_map SEC(".maps");

/* ── Helpers ────────────────────────────────────────────────────────────────── */

static __always_inline void emit_threat(
    __u32 src_ip, __u32 dst_ip,
    __u16 src_port, __u16 dst_port,
    __u8 proto, __u8 threat_type,
    __u8 tcp_flags, __u64 pkt_count)
{
    struct threat_event *evt = bpf_ringbuf_reserve(
        &threat_events, sizeof(*evt), 0
    );
    if (!evt)
        return;

    evt->src_ip      = src_ip;
    evt->dst_ip      = dst_ip;
    evt->src_port    = src_port;
    evt->dst_port    = dst_port;
    evt->protocol    = proto;
    evt->threat_type = threat_type;
    evt->tcp_flags   = tcp_flags;
    evt->pad         = 0;
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->packet_count = pkt_count;

    bpf_ringbuf_submit(evt, 0);
}

static __always_inline int is_blocked(__u32 addr)
{
    struct ipv4_lpm_key key = {
        .prefixlen = 32,
        .addr      = addr,
    };
    return bpf_map_lookup_elem(&blocked_ips, &key) != NULL;
}

static __always_inline int check_rate(__u32 src_ip, __u16 dst_port)
{
    __u64 now = bpf_ktime_get_ns();
    struct rate_entry *entry = bpf_map_lookup_elem(&rate_limit_map, &src_ip);

    if (!entry) {
        struct rate_entry new_entry = {
            .window_start_ns = now,
            .packet_count    = 1,
            .port_count      = 1,
        };
        /* Track first port */
        if (dst_port < 1024)
            new_entry.port_bitmap[dst_port / 16] |= (1 << (dst_port % 16));
        bpf_map_update_elem(&rate_limit_map, &src_ip, &new_entry, BPF_ANY);
        return 0;
    }

    /* Reset window if expired */
    if (now - entry->window_start_ns > WINDOW_NS) {
        entry->window_start_ns = now;
        entry->packet_count    = 1;
        entry->port_count      = 1;
        __builtin_memset(entry->port_bitmap, 0, sizeof(entry->port_bitmap));
        return 0;
    }

    entry->packet_count++;

    /* Track distinct ports for port scan detection */
    if (dst_port < 1024) {
        __u16 idx = dst_port / 16;
        __u16 bit = 1 << (dst_port % 16);
        if (idx < 64 && !(entry->port_bitmap[idx] & bit)) {
            entry->port_bitmap[idx] |= bit;
            entry->port_count++;
        }
    }

    /* Port scan detection */
    if (entry->port_count > PORT_SCAN_THRESHOLD)
        return THREAT_PORT_SCAN;

    /* Rate limit */
    if (entry->packet_count > RATE_LIMIT_PPS)
        return THREAT_RATE_EXCEED;

    return 0;
}

/* ── XDP Main ───────────────────────────────────────────────────────────────── */

SEC("xdp")
int cyberwall_xdp(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Stats */
    __u32 key = 0;
    struct stats *s = bpf_map_lookup_elem(&stats_map, &key);
    if (s)
        __sync_fetch_and_add(&s->total_packets, 1);

    /* Parse Ethernet */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        goto pass;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        goto pass;

    /* Parse IP */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        goto pass;

    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u8  proto  = ip->protocol;
    __u16 src_port = 0, dst_port = 0;
    __u8  tcp_flags = 0;

    /* Parse TCP/UDP ports */
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            goto pass;
        src_port  = bpf_ntohs(tcp->source);
        dst_port  = bpf_ntohs(tcp->dest);
        tcp_flags = ((__u8 *)tcp)[13];

        /* NULL scan — no flags set */
        if (tcp_flags == 0) {
            emit_threat(src_ip, dst_ip, src_port, dst_port,
                        proto, THREAT_NULL_SCAN, tcp_flags, 1);
            goto drop;
        }

        /* XMAS scan — FIN+PSH+URG */
        if ((tcp_flags & 0x29) == 0x29) {
            emit_threat(src_ip, dst_ip, src_port, dst_port,
                        proto, THREAT_XMAS_SCAN, tcp_flags, 1);
            goto drop;
        }

        /* SYN flood — SYN only, no ACK */
        if ((tcp_flags & 0x03) == 0x02) {
            int rate = check_rate(src_ip, dst_port);
            if (rate == THREAT_RATE_EXCEED) {
                emit_threat(src_ip, dst_ip, src_port, dst_port,
                            proto, THREAT_SYN_FLOOD, tcp_flags, 0);
                goto drop;
            }
        }

    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            goto pass;
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
    }

    /* Blocked IP check */
    if (is_blocked(src_ip)) {
        emit_threat(src_ip, dst_ip, src_port, dst_port,
                    proto, THREAT_BLOCKED_IP, tcp_flags, 0);
        goto drop;
    }

    /* Rate limit + port scan check */
    int threat = check_rate(src_ip, dst_port);
    if (threat == THREAT_PORT_SCAN) {
        emit_threat(src_ip, dst_ip, src_port, dst_port,
                    proto, THREAT_PORT_SCAN, tcp_flags, 0);
        goto drop;
    }
    if (threat == THREAT_RATE_EXCEED) {
        emit_threat(src_ip, dst_ip, src_port, dst_port,
                    proto, THREAT_RATE_EXCEED, tcp_flags, 0);
        goto drop;
    }

pass:
    if (s) __sync_fetch_and_add(&s->passed_packets, 1);
    return XDP_PASS;

drop:
    if (s) {
        __sync_fetch_and_add(&s->dropped_packets, 1);
        __sync_fetch_and_add(&s->threats_detected, 1);
    }
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";

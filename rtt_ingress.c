#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
} syn_ts SEC(".maps");

SEC("tc")
int handle_ingress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    __u64 now = bpf_ktime_get_ns();
    __u32 seq = bpf_ntohl(tcp->seq);
    __u32 ack = bpf_ntohl(tcp->ack_seq);

    if (tcp->syn && tcp->ack) {
        bpf_printk("INGRESS SYN-ACK time=%llu seq=%u ack=%u", now, seq, ack);

        __u32 key = ack - 1;
        __u64 *ts = bpf_map_lookup_elem(&syn_ts, &key);
        if (ts) {
            __u64 rtt = now - *ts;
            bpf_printk("INGRESS RTT(ns): %llu", rtt);
            bpf_map_delete_elem(&syn_ts, &key);
        } else {
            bpf_printk("INGRESS SYN-ACK no map entry key=%u", key);
        }
    }

    if (tcp->ack && !tcp->syn) {
        bpf_printk("INGRESS ACK time=%llu seq=%u ack=%u", now, seq, ack);
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";


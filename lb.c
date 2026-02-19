//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "parse_helpers.h"

#define NUM_BACKENDS 2
#define ETH_ALEN 6
#define AF_INET 2
#define IPROTO_TCP 6
#define MAX_TCP_CHECK_WORDS 750

struct backend {
  __u32 ip;
  __u32 conns;
};

struct five_tuple_t {
  __u32 src_ip;
  __u32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
  __u8  protocol;
};

// Connection state lives ONLY here (conntrack map).
// State values:
//   0 = SYN seen, not yet established
//   1 = Established
//   2 = Client sent FIN first
//   3 = Backend sent FIN first
//   4 = Both sides have FIN'd → delete on next ACK
struct conn_meta {
  __u32 ip;           // client IP (used to rewrite dst when replying)
  __u32 backend_idx;  // index into backends map
  __u8  state;
};

// Maps

// Backend pool
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, NUM_BACKENDS);
  __type(key, __u32);
  __type(value, struct backend);
} backends SEC(".maps");

// conntrack: keyed by (LB-side five-tuple as seen FROM the backend)
//   src_ip   = LB IP
//   dst_ip   = backend IP
//   src_port = client source port  (LB preserves it when forwarding)
//   dst_port = destination port (e.g. 8000)
//
// This is the SINGLE AUTHORITATIVE store for conn_meta / state.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1000);
  __type(key, struct five_tuple_t);
  __type(value, struct conn_meta);
} conntrack SEC(".maps");

// backendtrack: keyed by the client-facing five-tuple
//   src_ip   = client IP
//   dst_ip   = LB IP
//   src_port = client source port
//   dst_port = destination port 
//
// Value is NOT conn_meta any more – it is the conntrack key so we
// can look up the single authoritative conn_meta without duplicating state.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1000);
  __type(key, struct five_tuple_t);
  __type(value, struct five_tuple_t);   // ← stores the conntrack lookup key
} backendtrack SEC(".maps");

// helpers

static __always_inline void log_fib_error(int rc) {
  switch (rc) {
  case BPF_FIB_LKUP_RET_BLACKHOLE:    break;
  case BPF_FIB_LKUP_RET_UNREACHABLE:  break;
  case BPF_FIB_LKUP_RET_PROHIBIT:     break;
  case BPF_FIB_LKUP_RET_NOT_FWDED:    break;
  case BPF_FIB_LKUP_RET_FWD_DISABLED: break;
  case BPF_FIB_LKUP_RET_UNSUPP_LWT:   break;
  case BPF_FIB_LKUP_RET_NO_NEIGH:     break;
  case BPF_FIB_LKUP_RET_FRAG_NEEDED:  break;
  case BPF_FIB_LKUP_RET_NO_SRC_ADDR:  break;
  default: break;
  }
}

static __always_inline __u16 recalc_ip_checksum(struct iphdr *ip) {
  ip->check = 0;
  __u64 csum = bpf_csum_diff(0, 0, (unsigned int *)ip, sizeof(struct iphdr), 0);
#pragma unroll
  for (int i = 0; i < 4; i++) {
    if (csum >> 16)
      csum = (csum & 0xffff) + (csum >> 16);
  }
  return ~csum;
}

static __always_inline __u16 recalc_tcp_checksum(struct tcphdr *tcph,
                                                  struct iphdr  *iph,
                                                  void          *data_end) {
  tcph->check = 0;
  __u32 sum = 0;

  sum += (__u16)(iph->saddr >> 16)   + (__u16)(iph->saddr & 0xFFFF);
  sum += (__u16)(iph->daddr >> 16)   + (__u16)(iph->daddr & 0xFFFF);
  sum += bpf_htons(IPPROTO_TCP);

  __u16 tcp_len = bpf_ntohs(iph->tot_len) - (iph->ihl * 4);
  sum += bpf_htons(tcp_len);

  __u16 *ptr = (__u16 *)tcph;
#pragma unroll
  for (int i = 0; i < MAX_TCP_CHECK_WORDS; i++) {
    if ((void *)(ptr + 1) > data_end || (void *)ptr >= (void *)tcph + tcp_len)
      break;
    sum += *ptr;
    ptr++;
  }

  if (tcp_len & 1) {
    if ((void *)ptr + 1 <= data_end)
      sum += bpf_htons(*(__u8 *)ptr << 8);
  }

  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  return ~sum;
}

static __always_inline int fib_lookup_v4_full(struct xdp_md      *ctx,
                                              struct bpf_fib_lookup *fib,
                                              __u32 src, __u32 dst,
                                              __u16 tot_len) {
  __builtin_memset(fib, 0, sizeof(*fib));
  fib->family      = AF_INET;
  fib->ipv4_src    = src;
  fib->ipv4_dst    = dst;
  fib->l4_protocol = IPPROTO_TCP;
  fib->tot_len     = tot_len;
  fib->ifindex     = ctx->ingress_ifindex;
  return bpf_fib_lookup(ctx, fib, sizeof(*fib), 0);
}

// Helper: build the conntrack key for a given (lb_ip, backend_ip,
// client_src_port, dest_port).

static __always_inline struct five_tuple_t
make_ct_key(__u32 lb_ip, __u32 backend_ip,
            __u16 client_src_port, __u16 dest_port) {
  struct five_tuple_t k = {};
  k.src_ip   = lb_ip;
  k.dst_ip   = backend_ip;
  k.src_port = client_src_port;
  k.dst_port = dest_port;
  k.protocol = IPPROTO_TCP;
  return k;
}

// Helper: build the backendtrack key for the client-facing direction

static __always_inline struct five_tuple_t
make_bt_key(__u32 client_ip, __u32 lb_ip,
            __u16 client_src_port, __u16 dest_port) {
  struct five_tuple_t k = {};
  k.src_ip   = client_ip;
  k.dst_ip   = lb_ip;
  k.src_port = client_src_port;
  k.dst_port = dest_port;
  k.protocol = IPPROTO_TCP;
  return k;
}


// XDP program

SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data     = (void *)(long)ctx->data;

  struct hdr_cursor nh = { .pos = data };

  //parse Ethernet header
  struct ethhdr *eth;
  int eth_type = parse_ethhdr(&nh, data_end, &eth);
  if (eth_type != bpf_htons(ETH_P_IP))
    return XDP_PASS;

  //parse IP header
  struct iphdr *ip;
  int ip_type = parse_iphdr(&nh, data_end, &ip);
  if ((void *)(ip + 1) > data_end)
    return XDP_PASS;
  if (ip->protocol != IPPROTO_TCP)
    return XDP_PASS;

  // parse tcp header
  struct tcphdr *tcp;
  int tcp_type = parse_tcphdr(&nh, data_end, &tcp);
  if ((void *)(tcp + 1) > data_end)
    return XDP_PASS;

  // Only handle port 8000 traffic
  if (bpf_ntohs(tcp->source) != 8000 && bpf_ntohs(tcp->dest) != 8000)
    return XDP_PASS;

  __u32 lb_ip = ip->daddr;

  struct bpf_fib_lookup fib = {};

  // Build the conntrack reverse-lookup key (used when packet came
  // FROM the backend toward the LB).
  struct five_tuple_t ct_key_from_backend = {};
  ct_key_from_backend.src_ip   = ip->daddr;   // LB IP
  ct_key_from_backend.dst_ip   = ip->saddr;   // backend IP
  ct_key_from_backend.src_port = tcp->dest;   // client src port 
  ct_key_from_backend.dst_port = tcp->source; // dest port on backend side
  ct_key_from_backend.protocol = IPPROTO_TCP;

  struct conn_meta *ct = bpf_map_lookup_elem(&conntrack, &ct_key_from_backend);

  //packet arrived from backend 
  if (ct) {
    // termination logic
    if (tcp->fin) {
      struct conn_meta updated = *ct;
      if (ct->state == 2) {
        // Client already sent FIN , both sides done
        updated.state = 4;
      } else {
        // Backend FIN is first
        updated.state = 3;
      }
      bpf_map_update_elem(&conntrack, &ct_key_from_backend, &updated, BPF_ANY);
      ct = bpf_map_lookup_elem(&conntrack, &ct_key_from_backend);
      if (!ct)
        return XDP_ABORTED;
    }

    //  Cleanup: final ACK or RST 
    if ((tcp->ack && ct->state == 4 && tcp->fin == 0) || tcp->rst) {
      // Decrement backend connection counter
      struct backend *b = bpf_map_lookup_elem(&backends, &ct->backend_idx);
      if (!b)
        return XDP_ABORTED;
      struct backend nb = *b;
      if (nb.conns > 0)
        nb.conns -= 1;
      bpf_map_update_elem(&backends, &ct->backend_idx, &nb, BPF_ANY);

      // Delete conntrack entry
      bpf_map_delete_elem(&conntrack, &ct_key_from_backend);

      // Delete backendtrack entry (key is client-facing direction)
      struct five_tuple_t bt_key = make_bt_key(ct->ip, ip->daddr,
                                               tcp->dest,  // client src port
                                               tcp->source);
      bpf_map_delete_elem(&backendtrack, &bt_key);

      /*bpf_printk("conn deleted (backend path). Backend %pI4 conns=%d",
                 &b->ip, nb.conns);*/
    }

    // FIB lookup: send reply toward the client 
    int rc = fib_lookup_v4_full(ctx, &fib, ip->daddr, ct->ip,
                                bpf_ntohs(ip->tot_len));
    if (rc != BPF_FIB_LKUP_RET_SUCCESS) {
      log_fib_error(rc);
      return XDP_ABORTED;
    }

    // Rewrite destination to client IP/MAC
    ip->daddr = ct->ip;
    __builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);

  //packet arrived from some client 

  } else {
    // Build the client-facing five-tuple for backendtrack
    struct five_tuple_t bt_key = make_bt_key(ip->saddr, ip->daddr,
                                             tcp->source, tcp->dest);

    struct five_tuple_t *ct_key_ptr =
        bpf_map_lookup_elem(&backendtrack, &bt_key);

    struct backend *b;
    struct five_tuple_t ct_key = {};

    if (!ct_key_ptr) {
      // ── New connection: pick backend with least connections ──
      __u32 key      = 0;
      __u32 min_conn = (__u32)-1;

      __u32 i0 = 0;
      struct backend *b0 = bpf_map_lookup_elem(&backends, &i0);
      if (b0 && b0->conns < min_conn) { min_conn = b0->conns; key = i0; }

      __u32 i1 = 1;
      struct backend *b1 = bpf_map_lookup_elem(&backends, &i1);
      if (b1 && b1->conns < min_conn) { min_conn = b1->conns; key = i1; }

      b = bpf_map_lookup_elem(&backends, &key);
      if (!b)
        return XDP_ABORTED;

      // Build the canonical conntrack key
      ct_key = make_ct_key(ip->daddr, b->ip, tcp->source, tcp->dest);

      // Create conn_meta (state=0: SYN seen, not yet established)
      struct conn_meta meta = {};
      meta.ip          = ip->saddr;  // client IP for reply rewriting
      meta.backend_idx = key;
      meta.state       = 0;

      // Insert into conntrack (single source of truth)
      if (bpf_map_update_elem(&conntrack, &ct_key, &meta, BPF_ANY) != 0)
        return XDP_ABORTED;

      // Insert into backendtrack with the conntrack key as value
      if (bpf_map_update_elem(&backendtrack, &bt_key, &ct_key, BPF_ANY) != 0)
        return XDP_ABORTED;

    } else {
      // ── Existing connection: look up the live conn_meta ──────
      ct_key = *ct_key_ptr;

      ct = bpf_map_lookup_elem(&conntrack, &ct_key);
      if (!ct)
        return XDP_ABORTED;

      b = bpf_map_lookup_elem(&backends, &ct->backend_idx);
      if (!b)
        return XDP_ABORTED;

      // ── State 0→1: first non-SYN packet = connection established ──
      if (ct->state == 0 && tcp->syn == 0) {
        struct conn_meta updated = *ct;
        updated.state = 1;
        // Only one write needed – backendtrack points here
        bpf_map_update_elem(&conntrack, &ct_key, &updated, BPF_ANY);

        // Increment connection counter NOW (connection is established)
        struct backend nb = *b;
        nb.conns += 1;
        bpf_map_update_elem(&backends, &ct->backend_idx, &nb, BPF_ANY);

        ct = bpf_map_lookup_elem(&conntrack, &ct_key);
        if (!ct)
          return XDP_ABORTED;
      }

      // termination logic
      if (tcp->fin) {
        struct conn_meta updated = *ct;
        if (ct->state == 3) {
          // Backend already sent FIN → both sides done
          updated.state = 4;
        } else {
          // Client FIN is first
          updated.state = 2;
        }
        // Single write to conntrack – both paths will see it
        bpf_map_update_elem(&conntrack, &ct_key, &updated, BPF_ANY);

        ct = bpf_map_lookup_elem(&conntrack, &ct_key);
        if (!ct)
          return XDP_ABORTED;
      }

      //cleanup: final ACK or RST 
      if ((tcp->ack && ct->state == 4 && tcp->fin == 0) || tcp->rst) {
        struct backend nb = *b;
        if (nb.conns > 0)
          nb.conns -= 1;
        bpf_map_update_elem(&backends, &ct->backend_idx, &nb, BPF_ANY);

        bpf_map_delete_elem(&conntrack, &ct_key);
        bpf_map_delete_elem(&backendtrack, &bt_key);

        /*bpf_printk("conn deleted (client path). Backend %pI4 conns=%d",
                   &b->ip, nb.conns);*/
      }
    }

    // FIB lookup: forward packet toward the backend 
    int rc = fib_lookup_v4_full(ctx, &fib, ip->daddr, b->ip,
                                bpf_ntohs(ip->tot_len));
    if (rc != BPF_FIB_LKUP_RET_SUCCESS) {
      log_fib_error(rc);
      return XDP_ABORTED;
    }

    // Rewrite destination to backend IP/MAC
    ip->daddr = b->ip;
    __builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);

    //bpf_printk("Backend %pI4 conns=%d", &b->ip, b->conns);
  }

  // rewrite: source IP/MAC = LB 
  ip->saddr = lb_ip;
  __builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);

  // Recalculate checksums
  ip->check   = recalc_ip_checksum(ip);
  tcp->check  = recalc_tcp_checksum(tcp, ip, data_end);

  return XDP_TX;
}

char _license[] SEC("license") = "GPL";

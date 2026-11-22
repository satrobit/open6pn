// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
//
// Mesh datapath. Four tc programs:
//
//   o6pn_from_container  ingress on the host side of every container veth
//   o6pn_to_container    egress  on the host side of every container veth
//   o6pn_from_wg         ingress on the WireGuard device
//   o6pn_to_wg           egress  on the WireGuard device
//
// Address layout (keep in sync with internal/addr):
//
//   IPv6  fdaa:NNNN:TTTT:TTTT:0000:0000:0000:EEEE   node, network, endpoint
//   IPv4  10.<node><endpoint>                       no network: it comes from
//                                                   the veth, never the packet
//
// The 24 bits of the IPv4 address are split between node and endpoint by
// cfg_ep_bits, which is the same on every host of a cluster.
//
// Isolation rests on three checks, all made here and nowhere else:
//
//   1. A container may only send from its own address (anti-spoofing).
//   2. The network of the destination is never taken from an IPv4 packet and
//      must equal the sender's network in an IPv6 packet. For IPv4 the host
//      writes the sender's network into the outer IPv6 header itself.
//   3. On arrival from another host, source and destination network must
//      match, and the inner IPv4 addresses must match the outer IPv6 ones.
//
// The host IP stack never forwards mesh traffic: packets move veth<->veth and
// veth<->WireGuard with bpf_redirect only. The egress programs drop anything
// the host is forwarding, so a stray host route cannot inject traffic into a
// network. Packets the host itself originates towards a container (neighbour
// discovery, resolver answers) are let through.
//
// Two things reach the host stack from a container, and nothing else:
//
//   - neighbour discovery, from the endpoint's own addresses only;
//   - packets to the resolver, port 53.
//
// Both are marked O6PN_MARK_HOST. The resolver address is only a local
// address for packets carrying that mark, so it cannot be reached through any
// other interface. The mark also lets a firewall's reverse-path check find the
// endpoint's route, which the host's main table does not have.
//
// A container can only send to another host if that host has an endpoint in
// the container's network (o6pn_net_nodes), so a tenant cannot make its host
// talk to every host in the mesh.

#include <linux/bpf.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define O6PN_PREFIX 0xfdaaU
#define O6PN_V4_BASE 0x0a000000U
#define O6PN_V4_MASK 0x00ffffffU
#define O6PN_MARK 0x6f36706eU /* "o6pn": put on its way by the datapath */
/* Verified traffic handed to the host. Keep in sync with
 * datapath.go, which routes on it. */
#define O6PN_MARK_HOST 0x6f36706fU

#define ICMPV6_NS 135
#define ICMPV6_NA 136

/* Not present in older UAPI headers. */
#define O6PN_ADJ_FIXED_GSO (1ULL << 0)
#define O6PN_ADJ_ENCAP_L3_IPV6 (1ULL << 2)
#define O6PN_ADJ_DECAP_L3_IPV4 (1ULL << 7)

enum {
	STAT_TX_LOCAL,	       /* container -> container on this host */
	STAT_TX_REMOTE,	       /* container -> WireGuard */
	STAT_RX_REMOTE,	       /* WireGuard -> container */
	STAT_TO_HOST,	       /* neighbour discovery and DNS handed to the host */
	STAT_ARP_REPLY,	       /* gateway ARP answered */
	STAT_DROP_UNKNOWN_IF,  /* veth has no endpoint */
	STAT_DROP_SPOOF,       /* source address is not the sender's own */
	STAT_DROP_ISOLATION,   /* destination is in another network */
	STAT_DROP_OUTSIDE,     /* destination is not a mesh address */
	STAT_DROP_NO_ENDPOINT, /* no such endpoint on this host */
	STAT_DROP_UNSUPPORTED, /* not IPv4/IPv6/ARP, link-local, or malformed */
	STAT_DROP_ENCAP,       /* header push/pop failed */
	STAT_DROP_GUARD,       /* egress packet did not come from the datapath */
	STAT_DROP_NO_PEER,     /* destination host has no endpoint in this network */
	STAT_MAX,
};

/* Filled in by the daemon before the programs are loaded. */
volatile const __u32 cfg_node_id = 0;
volatile const __u32 cfg_wg_ifindex = 0;
/* Width of the endpoint field in an IPv4 address, 8..16. The node field is
 * the remaining 24 - cfg_ep_bits. */
volatile const __u32 cfg_ep_bits = 0;
/* Always take the pre-6.3 decapsulation path. For testing that path. */
volatile const __u32 cfg_legacy_decap = 0;

struct ep_if {
	__u32 net_id;
	__u16 ep_id;
	__u8 hmac[ETH_ALEN]; /* host side of the veth */
	__u8 cmac[ETH_ALEN]; /* container side */
	__u8 pad[2];
};

struct ep_key {
	__u32 net_id;
	__u32 ep_id;
};

struct ep_val {
	__u32 ifindex;	     /* host side of the veth */
	__u8 cmac[ETH_ALEN]; /* container side */
	__u8 hmac[ETH_ALEN]; /* host side */
};

struct net_node {
	__u32 net_id;
	__u32 node;
};

/* Host veth ifindex -> the endpoint behind it. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, struct ep_if);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} o6pn_ep_by_if SEC(".maps");

/* (network, endpoint) -> where to deliver on this host. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct ep_key);
	__type(value, struct ep_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} o6pn_ep_by_addr SEC(".maps");

/* (network, node): the other hosts that have an endpoint in a network this
 * host serves. Sending to any other host is refused. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1 << 20);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct net_node);
	__type(value, __u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} o6pn_net_nodes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} o6pn_stats SEC(".maps");

struct arp_ipv4 {
	struct arphdr hdr;
	__u8 sha[ETH_ALEN];
	__u8 spa[4];
	__u8 tha[ETH_ALEN];
	__u8 tpa[4];
} __attribute__((packed));

struct icmp6_min {
	__u8 type;
	__u8 code;
	__be16 cksum;
};

static __always_inline void count(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&o6pn_stats, &idx);

	if (v)
		(*v)++;
}

static __always_inline int drop(__u32 reason)
{
	count(reason);
	return TC_ACT_SHOT;
}

/* Returns a pointer to at least len linear bytes of packet, or NULL. */
static __always_inline void *pkt(struct __sk_buff *skb, __u32 len)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + len > data_end) {
		if (bpf_skb_pull_data(skb, len))
			return 0;
		data = (void *)(long)skb->data;
		data_end = (void *)(long)skb->data_end;
		if (data + len > data_end)
			return 0;
	}
	return data;
}

static __always_inline int v6_is(const struct in6_addr *a, __u32 node, __u32 net, __u32 ep)
{
	return a->s6_addr32[0] == bpf_htonl((O6PN_PREFIX << 16) | node) &&
	       a->s6_addr32[1] == bpf_htonl(net) && a->s6_addr32[2] == 0 &&
	       a->s6_addr32[3] == bpf_htonl(ep);
}

static __always_inline void v6_set(struct in6_addr *a, __u32 node, __u32 net, __u32 ep)
{
	a->s6_addr32[0] = bpf_htonl((O6PN_PREFIX << 16) | node);
	a->s6_addr32[1] = bpf_htonl(net);
	a->s6_addr32[2] = 0;
	a->s6_addr32[3] = bpf_htonl(ep);
}

/* Callers make sure node and ep fit their fields. */
static __always_inline __be32 v4_of(__u32 node, __u32 ep)
{
	return bpf_htonl(O6PN_V4_BASE | (node << cfg_ep_bits) | ep);
}

static __always_inline __u32 v4_ep_mask(void)
{
	return (1U << cfg_ep_bits) - 1;
}

/* Put a frame on its way to another host, if that host serves the network. */
static __always_inline int send_remote(struct __sk_buff *skb, __u32 net, __u32 node)
{
	struct net_node key = { .net_id = net, .node = node };

	if (!bpf_map_lookup_elem(&o6pn_net_nodes, &key))
		return drop(STAT_DROP_NO_PEER);
	skb->mark = O6PN_MARK;
	count(STAT_TX_REMOTE);
	return bpf_redirect(cfg_wg_ifindex, 0);
}

/* Hand a frame to the container behind (net, ep) on this host. The frame must
 * start with an Ethernet header. */
static __always_inline int deliver_local(struct __sk_buff *skb, __u32 net, __u32 ep)
{
	struct ep_key key = { .net_id = net, .ep_id = ep };
	struct ep_val *dst;
	struct ethhdr *eth;

	dst = bpf_map_lookup_elem(&o6pn_ep_by_addr, &key);
	if (!dst)
		return drop(STAT_DROP_NO_ENDPOINT);
	eth = pkt(skb, ETH_HLEN);
	if (!eth)
		return drop(STAT_DROP_UNSUPPORTED);
	__builtin_memcpy(eth->h_dest, dst->cmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, dst->hmac, ETH_ALEN);
	skb->mark = O6PN_MARK;
	count(STAT_TX_LOCAL);
	return bpf_redirect(dst->ifindex, 0);
}

/* The only IPv4 neighbour a container ever resolves is its gateway. Answer
 * for it here so IPv4 never involves the host stack (and its rp_filter). */
static __always_inline int from_container_arp(struct __sk_buff *skb, const struct ep_if *self)
{
	const __u8 gw[4] = { 169, 254, 1, 1 };
	struct arp_ipv4 *arp;
	struct ethhdr *eth;
	__u8 spa[4];

	eth = pkt(skb, ETH_HLEN + sizeof(*arp));
	if (!eth)
		return drop(STAT_DROP_UNSUPPORTED);
	arp = (void *)(eth + 1);
	if (arp->hdr.ar_hrd != bpf_htons(ARPHRD_ETHER) || arp->hdr.ar_pro != bpf_htons(ETH_P_IP) ||
	    arp->hdr.ar_hln != ETH_ALEN || arp->hdr.ar_pln != 4 ||
	    arp->hdr.ar_op != bpf_htons(ARPOP_REQUEST))
		return drop(STAT_DROP_UNSUPPORTED);
	if (arp->tpa[0] != gw[0] || arp->tpa[1] != gw[1] || arp->tpa[2] != gw[2] ||
	    arp->tpa[3] != gw[3])
		return drop(STAT_DROP_OUTSIDE);

	__builtin_memcpy(spa, arp->spa, 4);
	__builtin_memcpy(arp->tha, arp->sha, ETH_ALEN);
	__builtin_memcpy(arp->tpa, spa, 4);
	__builtin_memcpy(arp->sha, self->hmac, ETH_ALEN);
	__builtin_memcpy(arp->spa, gw, 4);
	arp->hdr.ar_op = bpf_htons(ARPOP_REPLY);
	__builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, self->hmac, ETH_ALEN);

	skb->mark = O6PN_MARK;
	count(STAT_ARP_REPLY);
	return bpf_redirect(skb->ifindex, 0);
}

/* The link-local address a kernel derives from a MAC address (EUI-64). */
static __always_inline int v6_is_ll_of(const struct in6_addr *a, const __u8 *mac)
{
	return a->s6_addr32[0] == bpf_htonl(0xfe800000U) && a->s6_addr32[1] == 0 &&
	       a->s6_addr[8] == (mac[0] ^ 2) && a->s6_addr[9] == mac[1] && a->s6_addr[10] == mac[2] &&
	       a->s6_addr[11] == 0xff && a->s6_addr[12] == 0xfe && a->s6_addr[13] == mac[3] &&
	       a->s6_addr[14] == mac[4] && a->s6_addr[15] == mac[5];
}

static __always_inline int v6_is_unspecified(const struct in6_addr *a)
{
	return (a->s6_addr32[0] | a->s6_addr32[1] | a->s6_addr32[2] | a->s6_addr32[3]) == 0;
}

static __always_inline int from_container_v6(struct __sk_buff *skb, const struct ep_if *self)
{
	const __u32 net = self->net_id, ep = self->ep_id;
	const __u32 l3 = ETH_HLEN, l4 = ETH_HLEN + sizeof(struct ipv6hdr);
	struct ipv6hdr *ip6;
	void *data;
	__u32 node;
	__u8 nh;

	data = pkt(skb, l4);
	if (!data)
		return drop(STAT_DROP_UNSUPPORTED);
	ip6 = data + l3;
	if (ip6->version != 6)
		return drop(STAT_DROP_UNSUPPORTED);
	nh = ip6->nexthdr;

	/* Neighbour discovery with the host side of the veth. Only link-local
	 * and link-scope multicast destinations: those are never forwarded.
	 * Only from the endpoint's own addresses (or none, for duplicate
	 * address detection): the host keeps a neighbour entry per source,
	 * in a table every interface shares. */
	if (nh == IPPROTO_ICMPV6) {
		struct icmp6_min *ic;

		data = pkt(skb, l4 + sizeof(*ic));
		if (!data)
			return drop(STAT_DROP_UNSUPPORTED);
		ip6 = data + l3;
		ic = data + l4;
		if (ic->type == ICMPV6_NS || ic->type == ICMPV6_NA) {
			__u8 b0 = ip6->daddr.s6_addr[0], b1 = ip6->daddr.s6_addr[1];

			if (!v6_is(&ip6->saddr, cfg_node_id, net, ep) &&
			    !v6_is_ll_of(&ip6->saddr, self->cmac) && !v6_is_unspecified(&ip6->saddr))
				return drop(STAT_DROP_SPOOF);
			if ((b0 == 0xfe && (b1 & 0xc0) == 0x80) || (b0 == 0xff && b1 == 0x02)) {
				skb->mark = O6PN_MARK_HOST;
				count(STAT_TO_HOST);
				return TC_ACT_OK;
			}
			return drop(STAT_DROP_OUTSIDE);
		}
	}

	/* Link-local chatter (router solicitations, multicast listener
	 * reports) goes nowhere, but it is not an attack either. */
	if (ip6->saddr.s6_addr32[0] == 0 ||
	    (ip6->saddr.s6_addr16[0] & bpf_htons(0xffc0)) == bpf_htons(0xfe80))
		return drop(STAT_DROP_UNSUPPORTED);
	if (!v6_is(&ip6->saddr, cfg_node_id, net, ep))
		return drop(STAT_DROP_SPOOF);

	/* The resolver on this host: fdaa::53, port 53 only. */
	if (v6_is(&ip6->daddr, 0, 0, 0x53)) {
		__be16 *ports;

		if (nh != IPPROTO_UDP && nh != IPPROTO_TCP)
			return drop(STAT_DROP_OUTSIDE);
		data = pkt(skb, l4 + 4);
		if (!data)
			return drop(STAT_DROP_UNSUPPORTED);
		ports = data + l4;
		if (ports[1] != bpf_htons(53))
			return drop(STAT_DROP_OUTSIDE);
		/* The source has been checked; say so. Without this mark the
		 * host does not consider the address its own. */
		skb->mark = O6PN_MARK_HOST;
		count(STAT_TO_HOST);
		return TC_ACT_OK;
	}

	if (ip6->daddr.s6_addr16[0] != bpf_htons(O6PN_PREFIX))
		return drop(STAT_DROP_OUTSIDE);
	if (ip6->daddr.s6_addr32[1] != bpf_htonl(net))
		return drop(STAT_DROP_ISOLATION);
	if (ip6->daddr.s6_addr32[2] != 0)
		return drop(STAT_DROP_NO_ENDPOINT);
	/* Next header 4 is how IPv4 is carried between hosts; a container
	 * does not get to produce it. */
	if (nh == IPPROTO_IPIP)
		return drop(STAT_DROP_UNSUPPORTED);

	node = bpf_ntohs(ip6->daddr.s6_addr16[1]);
	if (node == cfg_node_id)
		return deliver_local(skb, net, bpf_ntohl(ip6->daddr.s6_addr32[3]));
	if (node == 0)
		return drop(STAT_DROP_OUTSIDE);
	return send_remote(skb, net, node);
}

static __always_inline int from_container_v4(struct __sk_buff *skb, __u32 net, __u32 ep)
{
	struct ipv6hdr *ip6;
	struct ethhdr *eth;
	struct iphdr *ip4;
	__u32 daddr, node, dst_ep, inner_len;
	void *data;

	data = pkt(skb, ETH_HLEN + sizeof(*ip4));
	if (!data)
		return drop(STAT_DROP_UNSUPPORTED);
	ip4 = data + ETH_HLEN;
	if (ip4->version != 4 || ip4->ihl < 5)
		return drop(STAT_DROP_UNSUPPORTED);
	if (ip4->saddr != v4_of(cfg_node_id, ep))
		return drop(STAT_DROP_SPOOF);

	daddr = bpf_ntohl(ip4->daddr);
	if ((daddr & 0xff000000U) != O6PN_V4_BASE)
		return drop(STAT_DROP_OUTSIDE);
	node = (daddr & O6PN_V4_MASK) >> cfg_ep_bits;
	dst_ep = daddr & v4_ep_mask();

	if (node == cfg_node_id)
		return deliver_local(skb, net, dst_ep);
	if (node == 0)
		return drop(STAT_DROP_OUTSIDE);
	{
		struct net_node key = { .net_id = net, .node = node };

		if (!bpf_map_lookup_elem(&o6pn_net_nodes, &key))
			return drop(STAT_DROP_NO_PEER);
	}

	/* Another host: wrap in IPv6. The network in the outer destination is
	 * the sender's own, so the packet cannot leave its network. */
	inner_len = skb->len - ETH_HLEN;
	if (bpf_skb_adjust_room(skb, sizeof(*ip6), BPF_ADJ_ROOM_MAC,
				O6PN_ADJ_ENCAP_L3_IPV6 | O6PN_ADJ_FIXED_GSO))
		return drop(STAT_DROP_ENCAP);
	data = pkt(skb, ETH_HLEN + sizeof(*ip6));
	if (!data)
		return drop(STAT_DROP_ENCAP);
	eth = data;
	eth->h_proto = bpf_htons(ETH_P_IPV6);
	ip6 = data + ETH_HLEN;
	*(__be32 *)ip6 = bpf_htonl(0x60000000U);
	ip6->payload_len = bpf_htons((__u16)inner_len);
	ip6->nexthdr = IPPROTO_IPIP;
	ip6->hop_limit = 64;
	v6_set(&ip6->saddr, cfg_node_id, net, ep);
	v6_set(&ip6->daddr, node, net, dst_ep);

	skb->mark = O6PN_MARK;
	count(STAT_TX_REMOTE);
	return bpf_redirect(cfg_wg_ifindex, 0);
}

SEC("tc")
int o6pn_from_container(struct __sk_buff *skb)
{
	__u32 ifindex = skb->ifindex;
	struct ethhdr *eth;
	struct ep_if *self;

	self = bpf_map_lookup_elem(&o6pn_ep_by_if, &ifindex);
	if (!self)
		return drop(STAT_DROP_UNKNOWN_IF);
	eth = pkt(skb, ETH_HLEN);
	if (!eth)
		return drop(STAT_DROP_UNSUPPORTED);

	switch (eth->h_proto) {
	case bpf_htons(ETH_P_IPV6):
		return from_container_v6(skb, self);
	case bpf_htons(ETH_P_IP):
		return from_container_v4(skb, self->net_id, self->ep_id);
	case bpf_htons(ETH_P_ARP):
		return from_container_arp(skb, self);
	}
	return drop(STAT_DROP_UNSUPPORTED);
}

/* Packets decrypted by WireGuard. The device has no link layer, so the packet
 * starts at the IPv6 header. WireGuard has already checked that the source
 * address lies in the sending host's own /32. */
SEC("tc")
int o6pn_from_wg(struct __sk_buff *skb)
{
	__u8 cmac[ETH_ALEN], hmac[ETH_ALEN];
	__be16 proto = bpf_htons(ETH_P_IPV6);
	struct ep_key key = {};
	struct ipv6hdr *ip6;
	struct ethhdr *eth;
	struct ep_val *dst;
	__u32 ifindex, from_node;

	if (skb->protocol != bpf_htons(ETH_P_IPV6))
		return drop(STAT_DROP_UNSUPPORTED);
	ip6 = pkt(skb, sizeof(*ip6));
	if (!ip6)
		return drop(STAT_DROP_UNSUPPORTED);

	if (ip6->saddr.s6_addr16[0] != bpf_htons(O6PN_PREFIX) ||
	    ip6->daddr.s6_addr32[0] != bpf_htonl((O6PN_PREFIX << 16) | cfg_node_id))
		return drop(STAT_DROP_OUTSIDE);
	if (ip6->saddr.s6_addr32[1] != ip6->daddr.s6_addr32[1])
		return drop(STAT_DROP_ISOLATION);
	if (ip6->saddr.s6_addr32[2] != 0 || ip6->daddr.s6_addr32[2] != 0)
		return drop(STAT_DROP_NO_ENDPOINT);

	key.net_id = bpf_ntohl(ip6->daddr.s6_addr32[1]);
	key.ep_id = bpf_ntohl(ip6->daddr.s6_addr32[3]);
	dst = bpf_map_lookup_elem(&o6pn_ep_by_addr, &key);
	if (!dst)
		return drop(STAT_DROP_NO_ENDPOINT);
	ifindex = dst->ifindex;
	__builtin_memcpy(cmac, dst->cmac, ETH_ALEN);
	__builtin_memcpy(hmac, dst->hmac, ETH_ALEN);
	from_node = bpf_ntohs(ip6->saddr.s6_addr16[1]);

	if (ip6->nexthdr == IPPROTO_IPIP) {
		__u32 src_node = bpf_ntohs(ip6->saddr.s6_addr16[1]);
		__u32 src_ep = bpf_ntohl(ip6->saddr.s6_addr32[3]);
		struct iphdr *ip4;
		void *data;

		/* Nothing that does not fit an IPv4 address can be the outside
		 * of an IPv4 packet. */
		if (src_node > (O6PN_V4_MASK >> cfg_ep_bits) || src_ep > v4_ep_mask() ||
		    key.ep_id > v4_ep_mask())
			return drop(STAT_DROP_SPOOF);
		data = pkt(skb, sizeof(*ip6) + sizeof(*ip4));
		if (!data)
			return drop(STAT_DROP_UNSUPPORTED);
		ip4 = data + sizeof(*ip6);
		/* The inner addresses must say the same thing as the outer
		 * ones, which are the ones that were checked. */
		if (ip4->version != 4 || ip4->saddr != v4_of(src_node, src_ep) ||
		    ip4->daddr != v4_of(cfg_node_id, key.ep_id))
			return drop(STAT_DROP_SPOOF);

		if (cfg_legacy_decap ||
		    bpf_skb_adjust_room(skb, -(__s32)sizeof(*ip6), BPF_ADJ_ROOM_MAC,
					O6PN_ADJ_DECAP_L3_IPV4 | O6PN_ADJ_FIXED_GSO)) {
			/* Kernels before 6.3 have no decap flag and refuse to
			 * leave less than an IPv6 header behind. Go through an
			 * IPv4-sized packet instead: 40 = 20 + 20. */
			if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IP), 0) ||
			    bpf_skb_adjust_room(skb, -20, BPF_ADJ_ROOM_MAC, O6PN_ADJ_FIXED_GSO))
				return drop(STAT_DROP_ENCAP);
		}
		proto = bpf_htons(ETH_P_IP);
	}

	/* A host that sends into one of our networks has an endpoint in it, so
	 * the answer may go back there. The daemon learns the same thing from
	 * etcd, but only some moments after a host's first container attaches;
	 * this keeps the first reply from being dropped meanwhile. */
	{
		struct net_node peer = {
			.net_id = key.net_id,
			.node = from_node,
		};
		__u8 one = 1;

		if (!bpf_map_lookup_elem(&o6pn_net_nodes, &peer))
			bpf_map_update_elem(&o6pn_net_nodes, &peer, &one, BPF_NOEXIST);
	}

	/* Give the packet the Ethernet header the veth expects. */
	if (bpf_skb_change_head(skb, ETH_HLEN, 0))
		return drop(STAT_DROP_ENCAP);
	eth = pkt(skb, ETH_HLEN);
	if (!eth)
		return drop(STAT_DROP_ENCAP);
	__builtin_memcpy(eth->h_dest, cmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, hmac, ETH_ALEN);
	eth->h_proto = proto;

	skb->mark = O6PN_MARK;
	count(STAT_RX_REMOTE);
	return bpf_redirect(ifindex, 0);
}

/* Towards a container: only what the datapath redirected here, plus packets
 * the host itself originated (neighbour discovery, DNS answers). Anything the
 * host is merely forwarding is dropped. */
SEC("tc")
int o6pn_to_container(struct __sk_buff *skb)
{
	if (skb->mark == O6PN_MARK || skb->ingress_ifindex == 0)
		return TC_ACT_OK;
	return drop(STAT_DROP_GUARD);
}

/* Into the mesh: only what o6pn_from_container redirected here. */
SEC("tc")
int o6pn_to_wg(struct __sk_buff *skb)
{
	if (skb->mark == O6PN_MARK)
		return TC_ACT_OK;
	return drop(STAT_DROP_GUARD);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

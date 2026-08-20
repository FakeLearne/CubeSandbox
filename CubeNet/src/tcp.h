// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (c) 2023 Cube Authors */
#ifndef __TCP_H
#define __TCP_H

#include <vmlinux.h>
#include "cubevs.h"
#include "l2l3.h"
#include "session.h"
#include "skb.h"

/* What TCP flags are set from RST/SYN/FIN/ACK. */
enum tcp_bit_set {
	TCP_SYN_SET,
	TCP_SYNACK_SET,
	TCP_FIN_SET,
	TCP_ACK_SET,
	TCP_RST_SET,
	TCP_NONE_SET,
};

#define TCP_CONNTRACK_SYN_SENT2	TCP_CONNTRACK_LISTEN

#define sNO TCP_CONNTRACK_NONE
#define sSS TCP_CONNTRACK_SYN_SENT
#define sSR TCP_CONNTRACK_SYN_RECV
#define sES TCP_CONNTRACK_ESTABLISHED
#define sFW TCP_CONNTRACK_FIN_WAIT
#define sCW TCP_CONNTRACK_CLOSE_WAIT
#define sLA TCP_CONNTRACK_LAST_ACK
#define sTW TCP_CONNTRACK_TIME_WAIT
#define sCL TCP_CONNTRACK_CLOSE
#define sS2 TCP_CONNTRACK_SYN_SENT2
#define sIV TCP_CONNTRACK_MAX
#define sIG TCP_CONNTRACK_IGNORE

/*
 * The TCP state transition table needs a few words...
 *
 * We are the man in the middle. All the packets go through us
 * but might get lost in transit to the destination.
 * It is assumed that the destinations can't receive segments
 * we haven't seen.
 *
 * The checked segment is in window, but our windows are *not*
 * equivalent with the ones of the sender/receiver. We always
 * try to guess the state of the current sender.
 *
 * The meaning of the states are:
 *
 * NONE:	initial state
 * SYN_SENT:	SYN-only packet seen
 * SYN_SENT2:	SYN-only packet seen from reply dir, simultaneous open
 * SYN_RECV:	SYN-ACK packet seen
 * ESTABLISHED:	ACK packet seen
 * FIN_WAIT:	FIN packet seen
 * CLOSE_WAIT:	ACK seen (after FIN)
 * LAST_ACK:	FIN seen (after FIN)
 * TIME_WAIT:	last ACK seen
 * CLOSE:	closed connection (RST)
 *
 * Packets marked as IGNORED (sIG):
 *	if they may be either invalid or valid
 *	and the receiver may send back a connection
 *	closing RST or a SYN/ACK.
 *
 * Packets marked as INVALID (sIV):
 *	if we regard them as truly invalid packets
 */
static const u8 tcp_conntracks[2][6][TCP_CONNTRACK_MAX] = {
	{
/* ORIGINAL */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*syn*/	   { sSS, sSS, sIG, sIG, sIG, sIG, sIG, sSS, sSS, sS2 },
/*
 *	sNO -> sSS	Initialize a new connection
 *	sSS -> sSS	Retransmitted SYN
 *	sS2 -> sS2	Late retransmitted SYN
 *	sSR -> sIG
 *	sES -> sIG	Error: SYNs in window outside the SYN_SENT state
 *			are errors. Receiver will reply with RST
 *			and close the connection.
 *			Or we are not in sync and hold a dead connection.
 *	sFW -> sIG
 *	sCW -> sIG
 *	sLA -> sIG
 *	sTW -> sSS	Reopened connection (RFC 1122).
 *	sCL -> sSS
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*synack*/ { sIV, sIV, sSR, sIV, sIV, sIV, sIV, sIV, sIV, sSR },
/*
 *	sNO -> sIV	Too late and no reason to do anything
 *	sSS -> sIV	Client can't send SYN and then SYN/ACK
 *	sS2 -> sSR	SYN/ACK sent to SYN2 in simultaneous open
 *	sSR -> sSR	Late retransmitted SYN/ACK in simultaneous open
 *	sES -> sIV	Invalid SYN/ACK packets sent by the client
 *	sFW -> sIV
 *	sCW -> sIV
 *	sLA -> sIV
 *	sTW -> sIV
 *	sCL -> sIV
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*fin*/    { sIV, sIV, sFW, sFW, sLA, sLA, sLA, sTW, sCL, sIV },
/*
 *	sNO -> sIV	Too late and no reason to do anything...
 *	sSS -> sIV	Client migth not send FIN in this state:
 *			we enforce waiting for a SYN/ACK reply first.
 *	sS2 -> sIV
 *	sSR -> sFW	Close started.
 *	sES -> sFW
 *	sFW -> sLA	FIN seen in both directions, waiting for
 *			the last ACK.
 *			Migth be a retransmitted FIN as well...
 *	sCW -> sLA
 *	sLA -> sLA	Retransmitted FIN. Remain in the same state.
 *	sTW -> sTW
 *	sCL -> sCL
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*ack*/	   { sES, sIV, sES, sES, sCW, sCW, sTW, sTW, sCL, sIV },
/*
 *	sNO -> sES	Assumed.
 *	sSS -> sIV	ACK is invalid: we haven't seen a SYN/ACK yet.
 *	sS2 -> sIV
 *	sSR -> sES	Established state is reached.
 *	sES -> sES	:-)
 *	sFW -> sCW	Normal close request answered by ACK.
 *	sCW -> sCW
 *	sLA -> sTW	Last ACK detected (RFC5961 challenged)
 *	sTW -> sTW	Retransmitted last ACK. Remain in the same state.
 *	sCL -> sCL
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*rst*/    { sIV, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL },
/*none*/   { sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV }
	},
	{
/* REPLY */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*syn*/	   { sIV, sS2, sIV, sIV, sIV, sIV, sIV, sSS, sIV, sS2 },
/*
 *	sNO -> sIV	Never reached.
 *	sSS -> sS2	Simultaneous open
 *	sS2 -> sS2	Retransmitted simultaneous SYN
 *	sSR -> sIV	Invalid SYN packets sent by the server
 *	sES -> sIV
 *	sFW -> sIV
 *	sCW -> sIV
 *	sLA -> sIV
 *	sTW -> sSS	Reopened connection, but server may have switched role
 *	sCL -> sIV
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*synack*/ { sIV, sSR, sIG, sIG, sIG, sIG, sIG, sIG, sIG, sSR },
/*
 *	sSS -> sSR	Standard open.
 *	sS2 -> sSR	Simultaneous open
 *	sSR -> sIG	Retransmitted SYN/ACK, ignore it.
 *	sES -> sIG	Late retransmitted SYN/ACK?
 *	sFW -> sIG	Might be SYN/ACK answering ignored SYN
 *	sCW -> sIG
 *	sLA -> sIG
 *	sTW -> sIG
 *	sCL -> sIG
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*fin*/    { sIV, sIV, sFW, sFW, sLA, sLA, sLA, sTW, sCL, sIV },
/*
 *	sSS -> sIV	Server might not send FIN in this state.
 *	sS2 -> sIV
 *	sSR -> sFW	Close started.
 *	sES -> sFW
 *	sFW -> sLA	FIN seen in both directions.
 *	sCW -> sLA
 *	sLA -> sLA	Retransmitted FIN.
 *	sTW -> sTW
 *	sCL -> sCL
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*ack*/	   { sIV, sIG, sSR, sES, sCW, sCW, sTW, sTW, sCL, sIG },
/*
 *	sSS -> sIG	Might be a half-open connection.
 *	sS2 -> sIG
 *	sSR -> sSR	Might answer late resent SYN.
 *	sES -> sES	:-)
 *	sFW -> sCW	Normal close request answered by ACK.
 *	sCW -> sCW
 *	sLA -> sTW	Last ACK detected (RFC5961 challenged)
 *	sTW -> sTW	Retransmitted last ACK.
 *	sCL -> sCL
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*rst*/    { sIV, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL },
/*none*/   { sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV }
	}
};

/* Force inlining: with a single call site inside update_session clang would
 * usually inline anyway, but if it ever emits a real BPF subprog the verifier
 * must track the returned index through the subprog boundary — extra burden
 * on the already-fragile 3D tcp_conntracks[dir][index][old_state] access.
 * Inlining lets clang constant-propagate index when the flag inputs are
 * compile-time constants (as in the tcp_state test macro and the production
 * do_tcp_nat literal-dir call), collapsing one array dimension.
 */
static __always_inline unsigned int get_conntrack_index(bool syn, bool ack, bool fin, bool rst)
{
	if (rst) return TCP_RST_SET;
	else if (syn) return (ack ? TCP_SYNACK_SET : TCP_SYN_SET);
	else if (fin) return TCP_FIN_SET;
	else if (ack) return TCP_ACK_SET;
	else return TCP_NONE_SET;
}

static __always_inline long snat_tcp(struct __sk_buff *skb,
				     __u32 ifindex, struct ethhdr *l2, struct iphdr *l3, struct tcphdr *l4,
				     __u16 listen_port, __u16 host_port)
{
	__u32 saddr, offset, node_ip = nodenic_ip;
	union macaddr *macaddr;
	__u16 ip_hlen;
	__u64 flags;
	long err;

	saddr = l3->saddr;
	node_ip = nodenic_ip;
	ip_hlen = BPF_CORE_READ_BITFIELD(l3, ihl);
	ip_hlen <<= 2;

	/* Update L2 addrs */
	macaddr = (union macaddr *)l2->h_dest;
	macaddr->p1 = nodegw_macaddr_p1;
	macaddr->p2 = nodegw_macaddr_p2;
	macaddr = (union macaddr *)l2->h_source;
	macaddr->p1 = nodenic_macaddr_p1;
	macaddr->p2 = nodenic_macaddr_p2;

	/* Update L4 csum and source port */
	offset = TCP_CSUM_OFF(ip_hlen);
	flags = BPF_F_PSEUDO_HDR | sizeof(saddr);
	err = bpf_l4_csum_replace(skb, offset, saddr, node_ip, flags);
	if (err)
		return err;

	/* update TCP csum for port change (not part of pseudo-header) */
	flags = sizeof(listen_port);
	err = bpf_l4_csum_replace(skb, offset, listen_port, host_port, flags);
	if (err)
		return err;

	flags = 0;
	err = bpf_skb_store_bytes(skb, TCP_SRC_OFF(ip_hlen), &host_port, sizeof(host_port), flags);
	if (err)
		return err;

	/* Update L3 csum and source addr */
	err = bpf_l3_csum_replace(skb, IP_CSUM_OFF, saddr, node_ip, sizeof(saddr));
	if (err)
		return err;

	flags = 0;
	err = bpf_skb_store_bytes(skb, IP_SADDR_OFF, &node_ip, sizeof(node_ip), flags);
	if (err)
		return err;

	return 0;
}

/* Shared TCP state transition core for the legacy nat_session value and the
 * new single-table session value.  Keep the wrappers typed: casting map values
 * between the two structs would hide future ABI drift from the compiler.
 */
static __always_inline void update_tcp_session_fields(enum ip_conntrack_dir dir,
						       __u64 *access_time,
						       __u8 *state,
						       __u8 *active_close,
						       __u64 now_ns,
						       bool syn, bool ack,
						       bool fin, bool rst)
{
	/* __u8 (not enum): keeps old_state in a single unsigned register. With a
	 * signed enum, older clang (14) narrows the value with `&= 255` masks that
	 * split it into a bounds-checked copy and a separate index copy, so the
	 * verifier sees the tcp_conntracks index register as unbounded (umax=255)
	 * and rejects the .rodata read. A plain __u8 keeps check and index unified.
	 */
	__u8 old_state, new_state;
	unsigned int index;

	if (now_ns - *access_time > SESSION_REFRESH_INTERVAL_NS)
		*access_time = now_ns;

	/* update CT state */
	if (dir > IP_CT_DIR_REPLY) {
		/* dir should be either IP_CT_DIR_ORIGINAL or IP_CT_DIR_REPLY */
		return;
	}

	index = get_conntrack_index(syn, ack, fin, rst);
	if (index > TCP_NONE_SET) {
		/* see enum tcp_bit_set */
		return;
	}

	old_state = *state;
	if (old_state > TCP_CONNTRACK_SYN_SENT2) {
		/* TCP_CONNTRACK_SYN_SENT2 = TCP_CONNTRACK_LISTEN = 9
		 * If we reach here, the state should be either
		 *   - sIG (IGNORED)
		 *   - sIV (INVALID)
		 * Proceed with state intact
		 */
		return;
	}

	new_state = tcp_conntracks[dir][index][old_state];

	if (index == TCP_FIN_SET) {
		/* A retransmitted FIN from the side that initiated close must not be
		 * mistaken for the peer's FIN. The generic conntrack table cannot
		 * distinguish direction once it reaches FIN_WAIT/CLOSE_WAIT, so use
		 * active_close to retain the state until the opposite side sends FIN.
		 */
		if ((old_state == TCP_CONNTRACK_FIN_WAIT ||
		     old_state == TCP_CONNTRACK_CLOSE_WAIT) &&
		    ((*active_close && dir == IP_CT_DIR_ORIGINAL) ||
		     (!*active_close && dir == IP_CT_DIR_REPLY)))
			new_state = old_state;

		/* Record only a real original-direction transition that initiates
		 * close. Checking the classified packet and computed transition avoids
		 * marking RST|FIN or SYN|FIN packets as active closes. If reply sent
		 * FIN first, the state is already FIN_WAIT/CLOSE_WAIT when original
		 * later sends FIN and active_close remains zero.
		 */
		if (dir == IP_CT_DIR_ORIGINAL &&
		    new_state == TCP_CONNTRACK_FIN_WAIT &&
		    new_state != old_state)
			*active_close = 1;
	}

	/* no store if state remain unchanged */
	if (new_state != old_state)
		*state = new_state;
}

static __always_inline void update_session(enum ip_conntrack_dir dir,
					   struct nat_session *sess,
					   __u64 now_ns, bool syn, bool ack,
					   bool fin, bool rst)
{
	update_tcp_session_fields(dir, &sess->access_time, &sess->state,
				  &sess->active_close, now_ns,
				  syn, ack, fin, rst);
}

static __always_inline void update_original_session(enum ip_conntrack_dir dir,
						    struct session *sess,
						    __u64 now_ns, bool syn,
						    bool ack, bool fin, bool rst)
{
	update_tcp_session_fields(dir, &sess->access_time, &sess->state,
				  &sess->active_close, now_ns,
				  syn, ack, fin, rst);
}

enum reset_dir {
	RESET_TO_SANDBOX = 0,
	RESET_TO_WORLD = 1,
};

static __always_inline bool tcp_segment_len(const struct iphdr *l3,
					    const struct tcphdr *l4,
					    __u32 *seg_len)
{
	__u16 ip_hlen, tcp_hlen, total_len;

	ip_hlen = BPF_CORE_READ_BITFIELD(l3, ihl);
	ip_hlen <<= 2;
	tcp_hlen = BPF_CORE_READ_BITFIELD(l4, doff);
	tcp_hlen <<= 2;
	total_len = bpf_ntohs(l3->tot_len);
	if (ip_hlen < sizeof(struct iphdr) || tcp_hlen < sizeof(struct tcphdr) ||
	    total_len < ip_hlen + tcp_hlen)
		return false;

	*seg_len = total_len - ip_hlen - tcp_hlen;
	if (l4->syn)
		(*seg_len)++;
	if (l4->fin)
		(*seg_len)++;

	return true;
}

static __always_inline int rewrite_l3_tot_len(struct __sk_buff *skb,
					      __be16 old_tot_len,
					      __be16 new_tot_len)
{
	long err;

	err = bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_tot_len, new_tot_len,
				  sizeof(new_tot_len));
	if (err)
		return err;

	return bpf_skb_store_bytes(skb, IP_TOT_LEN_OFF, &new_tot_len,
				   sizeof(new_tot_len), 0);
}

static __always_inline int tcp_ipv4_set_checksum(struct __sk_buff *skb,
						 __u32 tcp_csum_off,
						 __be32 saddr, __be32 daddr,
						 const struct tcphdr *tcp)
{
	const __u32 *words = (const __u32 *)tcp;
	__be32 proto_len = bpf_htonl(((__u32)IPPROTO_TCP << 16) | sizeof(*tcp));
	__u64 ph_flags = BPF_F_PSEUDO_HDR | sizeof(__u32);
	__u64 hdr_flags = sizeof(__u32);
	long err;

	err = bpf_l4_csum_replace(skb, tcp_csum_off, 0, saddr, ph_flags);
	if (err)
		return err;
	err = bpf_l4_csum_replace(skb, tcp_csum_off, 0, daddr, ph_flags);
	if (err)
		return err;
	err = bpf_l4_csum_replace(skb, tcp_csum_off, 0, proto_len, ph_flags);
	if (err)
		return err;

	err = bpf_l4_csum_replace(skb, tcp_csum_off, 0, words[0], hdr_flags);
	if (err)
		return err;
	err = bpf_l4_csum_replace(skb, tcp_csum_off, 0, words[1], hdr_flags);
	if (err)
		return err;
	err = bpf_l4_csum_replace(skb, tcp_csum_off, 0, words[2], hdr_flags);
	if (err)
		return err;
	err = bpf_l4_csum_replace(skb, tcp_csum_off, 0, words[3], hdr_flags);
	if (err)
		return err;
	return bpf_l4_csum_replace(skb, tcp_csum_off, 0, words[4], hdr_flags);
}

/* Turn the offending segment into an RFC 793 reset and send it back to the
 * selected side.  Any construction failure degrades to a plain drop.
 */
static __always_inline int tcp_reply_reset(struct __sk_buff *skb, __u32 ifindex,
					   enum reset_dir dir)
{
	struct tcphdr new_tcp = {};
	struct ethhdr *l2;
	struct iphdr *l3;
	struct tcphdr *l4;
	__be32 old_saddr, old_daddr, new_saddr, new_daddr;
	__be16 old_tot_len, new_tot_len;
	__u32 seq, ack_seq, new_skb_len;
	__u32 seg_len, tcp_off, tcp_csum_off;
	__u16 ip_hlen, new_ip_len;
	long err;

	if (dir > RESET_TO_WORLD)
		return TC_ACT_SHOT;

	if (skb->gso_segs)
		return TC_ACT_SHOT;

	if (!__pull_headers(skb, &l2, &l3, &l4))
		return TC_ACT_SHOT;

	if ((l3->frag_off & IP_FLAG_MF) || (l3->frag_off & IP_FRAG_OFF_MASK))
		return TC_ACT_SHOT;

	if (l4->rst)
		return TC_ACT_SHOT;

	ip_hlen = BPF_CORE_READ_BITFIELD(l3, ihl);
	ip_hlen <<= 2;
	seq = l4->seq;
	ack_seq = l4->ack_seq;
	if (!tcp_segment_len(l3, l4, &seg_len))
		return TC_ACT_SHOT;

	new_saddr = l3->daddr;
	new_daddr = dir == RESET_TO_WORLD ? l3->saddr : mvm_inner_ip;
	new_tcp.source = l4->dest;
	new_tcp.dest = l4->source;
	new_tcp.doff = sizeof(new_tcp) >> 2;
	new_tcp.rst = 1;
	if (l4->ack) {
		new_tcp.seq = ack_seq;
	} else {
		new_tcp.ack_seq = bpf_htonl(bpf_ntohl(seq) + seg_len);
		new_tcp.ack = 1;
	}

	new_ip_len = ip_hlen + sizeof(new_tcp);
	new_skb_len = sizeof(struct ethhdr) + new_ip_len;
	if (bpf_skb_change_tail(skb, new_skb_len, 0))
		return TC_ACT_SHOT;

	if (!__pull_headers(skb, &l2, &l3, &l4))
		return TC_ACT_SHOT;

	old_saddr = l3->saddr;
	old_daddr = l3->daddr;
	old_tot_len = l3->tot_len;
	new_tot_len = bpf_htons(new_ip_len);
	tcp_off = sizeof(struct ethhdr) + ip_hlen;
	tcp_csum_off = TCP_CSUM_OFF(ip_hlen);
	if (dir == RESET_TO_WORLD)
		set_mac_pair(l2, nodenic_macaddr_p1, nodenic_macaddr_p2,
			     nodegw_macaddr_p1, nodegw_macaddr_p2);
	else
		set_mac_pair(l2, cubegw0_macaddr_p1, cubegw0_macaddr_p2,
			     mvm_macaddr_p1, mvm_macaddr_p2);

	err = bpf_skb_store_bytes(skb, tcp_off, &new_tcp, sizeof(new_tcp), 0);
	if (err)
		return TC_ACT_SHOT;

	err = rewrite_l3_tot_len(skb, old_tot_len, new_tot_len);
	if (err)
		return TC_ACT_SHOT;

	err = bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_saddr, new_saddr,
				  sizeof(new_saddr));
	if (err)
		return TC_ACT_SHOT;
	err = bpf_skb_store_bytes(skb, IP_SADDR_OFF, &new_saddr,
				  sizeof(new_saddr), 0);
	if (err)
		return TC_ACT_SHOT;

	err = bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_daddr, new_daddr,
				  sizeof(new_daddr));
	if (err)
		return TC_ACT_SHOT;
	err = bpf_skb_store_bytes(skb, IP_DADDR_OFF, &new_daddr,
				  sizeof(new_daddr), 0);
	if (err)
		return TC_ACT_SHOT;

	err = tcp_ipv4_set_checksum(skb, tcp_csum_off, new_saddr, new_daddr,
				    &new_tcp);
	if (err)
		return TC_ACT_SHOT;

	return bpf_redirect(ifindex, 0);
}

static __always_inline bool create_new_sessions(struct __sk_buff *skb,
						struct session_key *ekey,
						__u64 now_ns, __u32 vm_ifindex,
						struct snat_ip *snat_ip, __u16 snat_port,
						__u8 packet_class, __u8 l7_scheme)
{
	return create_nat_session(skb, ekey, now_ns, vm_ifindex, snat_ip, snat_port,
				  TCP_CONNTRACK_SYN_SENT, packet_class, l7_scheme);
}

#endif /* __TCP_H */

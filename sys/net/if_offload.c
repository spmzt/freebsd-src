/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2026, by Timo Voelker. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * a) Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * b) Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
 *
 * c) Neither the name of Cisco Systems, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "opt_inet6.h"
#include "opt_inet.h"

#include <sys/mbuf.h>
#include <sys/systm.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_offload.h>
#include <net/if_private.h>
#include <net/ethernet.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip_carp.h>
#include <netinet/sctp_crc32.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifdef INET
#include <net/debugnet.h>
#include <netinet/if_ether.h>
#include <machine/in_cksum.h>
#include <netinet/ip_var.h>
#endif /* INET */
#ifdef INET6
#include <netinet6/in6_var.h>
#include <netinet6/ip6_var.h>
#include <netinet/ip6.h>
#endif /* INET6 */

#define IF_OFFLOAD_DEBUG 0

#if IF_OFFLOAD_DEBUG
#define IF_OFFLOAD_LOG(a) {printf("%s:%d: ", __func__, __LINE__), printf a; printf("\n");}
#else
#define IF_OFFLOAD_LOG(a)
#endif /* IF_OFFLOAD_DEBUG */

#ifdef INET
static int
if_offload_csum_ipv4(struct mbuf **mp, bool csum_ipv4, bool csum_pseudo, uint16_t *csum_start, uint16_t l4csum_field_offset)
{
	struct ip *ip;
	uint16_t ip_hdr_length;
	struct mbuf *m;

	m = *mp;
	/* pullup the IP header. */
	m = m_pullup(m, *csum_start + sizeof(struct ip));
	if (m == NULL)
		return (0);

	ip = (struct ip *)mtodo(m, *csum_start);
	ip_hdr_length = (ip->ip_hl << 2);
	if (csum_ipv4) { /* IPv4 Header Checksum */
		/* TODO: Need another m_pullup if IP options are present? */

		IF_OFFLOAD_LOG(("%s: Compute IPv4 header checksum with csum_start=%d, ip_hdr_length=%d\n", __func__, *csum_start, ip_hdr_length));
		ip->ip_sum = 0;
		ip->ip_sum = in_cksum_skip(m, *csum_start + ip_hdr_length, *csum_start);
		m->m_pkthdr.csum_flags &= ~CSUM_IP;
	}
	if (csum_pseudo) { /* TCP/UDP Pseudo Header Checksum */
		uint16_t csum, offset;

		/* compute pseudo header checksum and insert it in the protocol's checksum field */
		IF_OFFLOAD_LOG(("%s: Compute IPv4 pseudo header checksum\n", __func__));
		csum = in_pseudo(ip->ip_src.s_addr, ip->ip_dst.s_addr, htons(ntohs(ip->ip_len) - ip_hdr_length + ip->ip_p));
		offset = *csum_start + ip_hdr_length + l4csum_field_offset;
		if (m->m_len < (offset + sizeof(csum)))
			m_copyback(m, offset, sizeof(csum), (caddr_t)&csum);
		else
			*(u_short *)mtodo(m, offset) = csum;
		m->m_pkthdr.csum_flags &= ~CSUM_IP_PSEUDO;
	}
	*csum_start += ip_hdr_length;
	*mp = m;
	return (1);
}
#endif /* INET */

#ifdef INET6
/*
 * Compute TCP/UDP pseudo header checksum and insert that value in the
 * TCP/UDP checksum field.
 */
static int
if_offload_csum_ipv6(struct mbuf **mp, bool csum_pseudo, uint16_t *csum_start, uint16_t l4csum_field_offset)
{
	struct ip6_hdr *ip6;
	struct mbuf *m;
	int protocol;
	uint16_t l4offset;

	m = *mp;
	/* pullup the IPv6 fixed header. */
	m = m_pullup(m, *csum_start + sizeof(struct ip6_hdr)); /* TODO: Is this the way to add the IPv6 header length? */
	if (m == NULL) {
		return (0);
	}
	ip6 = (struct ip6_hdr *)mtodo(m, *csum_start);
	/* determine protocol and offset of layer 4 packet */
	l4offset = ip6_lasthdr(m, *csum_start, IPPROTO_IPV6, &protocol);
	/* protocol should now be IPPROTO_TCP or IPPROTO_UDP */

	if (csum_pseudo) { /* TCP/UDP Pseudo Header Checksum */
		uint16_t csum, offset;

		/* compute pseudo header checksum and insert it in the protocol's checksum field */
		IF_OFFLOAD_LOG(("%s: Compute IPv6 pseudo header checksum\n", __func__));
		csum = in6_cksum_pseudo(ip6, (m->m_pkthdr.len - l4offset), protocol, 0);
		offset = l4offset + l4csum_field_offset;
		if (m->m_len < (offset + sizeof(csum)))
			m_copyback(m, offset, sizeof(csum), (caddr_t)&csum);
		else
			*(u_short *)mtodo(m, offset) = csum;
		m->m_pkthdr.csum_flags &= ~CSUM_IP6_PSEUDO;
	}

	*csum_start = l4offset;
	*mp = m;
	return (1);
}
#endif /* INET6 */

static void
if_offload_csum_tcpudp(struct mbuf *m, uint16_t csum_start, uint16_t l4csum_field_offset, uint8_t udp)
{
	uint16_t csum, offset, cklen;

#if IF_OFFLOAD_DEBUG
	if (udp)
		IF_OFFLOAD_LOG(("%s: Compute UDP checksum\n", __func__));
	else
		IF_OFFLOAD_LOG(("%s: Compute TCP checksum\n", __func__));
#endif /* IF_OFFLOAD_DEBUG */
	cklen = m->m_pkthdr.len - csum_start;
	csum = in_cksum_skip(m, csum_start + cklen, csum_start);
	if (udp && csum == 0)
		csum = 0xffff;

	offset = csum_start + l4csum_field_offset;
	if (m->m_len < (offset + sizeof(csum)))
		m_copyback(m, offset, sizeof(csum), (caddr_t)&csum);
	else
		*(u_short *)mtodo(m, offset) = csum;
	m->m_pkthdr.csum_flags &= ~(CSUM_IP_UDP | CSUM_IP_TCP | CSUM_IP6_UDP | CSUM_IP6_TCP);
}

#if defined(SCTP) || defined(SCTP_SUPPORT)
static void
if_offload_csum_sctp(struct mbuf *m, uint16_t csum_start)
{
	IF_OFFLOAD_LOG(("%s: Compute SCTP checksum\n", __func__));
	sctp_delayed_cksum(m, csum_start);
	m->m_pkthdr.csum_flags &= ~(CSUM_IP_SCTP | CSUM_IP6_SCTP);
}
#endif /* defined(SCTP) || defined(SCTP_SUPPORT) */

/*
 * XXX-ste: Maybe this function must be moved into kern/uipc_mbuf.c
 *
 * Create a queue of packets/segments which fit the given mss + hdr_len.
 * m points to mbuf chain to be segmented.
 * This function splits the payload (m->m_pkthdr.len - hdr_len)
 * into segments of length mss bytes and then copy the first hdr_len bytes
 * from m at the top of each segment.
 *
 * Return the new queue with the segments on success, NULL on failure.
 * (the mbuf queue is freed in this case).
 */
static struct mbuf *
m_seg(struct mbuf *m, int hdr_len, int mss)
{
	struct mbuf *mi_last, *mseg;
	int off, total_len;

	total_len = m->m_pkthdr.len;
	if (total_len <= hdr_len + mss) {
		/*
		 * Segmentation unnecessary
		 */
		return m;
	}

	mi_last = m;
	for (off = hdr_len + mss; off < total_len; off += mss) {
		struct mbuf *mi;
		uint16_t payload_len;

		/*
		 * Create a new mbuf chain and copy the header from the
		 * original mbuf into it.
		 */
		mi = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
		if (mi == NULL) {
			goto err;
		}
		m_copydata(m, 0, hdr_len, mtod(mi, caddr_t));
		mi->m_len = hdr_len;
		mi->m_flags |= (m->m_flags & M_COPYFLAGS);

		/*
		 * Copy the payload from original packet
		 */
		payload_len = mss;
		if (off + mss > total_len) { /* last segment */
			payload_len = total_len - off;
		}
		mseg = m_copym(m, off, payload_len, M_NOWAIT);
		if (mseg == NULL) {
			m_freem(mi);
			goto err;
		}
		m_cat(mi, mseg);
		mi->m_pkthdr.len = hdr_len + payload_len;

		/*
		 * Copy packet header data
		 */
		mi->m_pkthdr.rcvif = m->m_pkthdr.rcvif;
		mi->m_pkthdr.csum_flags = m->m_pkthdr.csum_flags;
		mi->m_pkthdr.csum_data = m->m_pkthdr.csum_data;
		mi->m_pkthdr.tso_segsz = m->m_pkthdr.tso_segsz;

		mi_last->m_nextpkt = mi;
		mi_last = mi;
	}

	/*
	 * Use original mbuf as first mbuf.
	 */
	m_adj(m, hdr_len + mss - total_len);
	m->m_pkthdr.len = hdr_len + mss;

	return m;
err:
	while (m != NULL) {
		mseg = m->m_nextpkt;
		m->m_nextpkt = NULL;
		m_freem(m);
		m = mseg;
	}
	return NULL;
}

static void
if_offload_tso_update_ipv4(struct mbuf *m, uint16_t l3offset, u_short *tcp_sum)
{
	struct ip *ip;
	u_short id, len;

	ip = (struct ip *)mtodo(m, l3offset);
	id = ntohs(ip->ip_id) + 1; /* TODO: choose a better ID - for all but the first one? */
	len = m->m_pkthdr.len - l3offset;
	if ((m->m_pkthdr.csum_flags & CSUM_IP) == 0) {
		/* IPv4 header checksum is present. Update it. */
		ip->ip_sum += (ntohs(ip->ip_id) - id) + (ntohs(ip->ip_len) - len);
	}
	if ((m->m_pkthdr.csum_flags & CSUM_IP_PSEUDO) == 0) {
		/* TCP Pseudo Header Checksum is present. Update it. */
		*tcp_sum += (ntohs(ip->ip_len) - len);
	}

	ip->ip_id = htons(id);
	ip->ip_len = htons(len);
}

static void
if_offload_tso_update_ipv6(struct mbuf *m, uint16_t l3offset, u_short *tcp_sum)
{
	struct ip6_hdr *ip6;
	u_int16_t plen;

	ip6 = (struct ip6_hdr *)mtodo(m, l3offset);
	plen = m->m_pkthdr.len - l3offset - sizeof(struct ip6_hdr);
	if ((m->m_pkthdr.csum_flags & CSUM_IP6_PSEUDO) == 0) {
		/* TCP Pseudo Header Checksum is present. Update it. */
		*tcp_sum += (ntohs(ip6->ip6_plen) - plen);
	}

	ip6->ip6_plen = htons(plen);
}

static int
if_offload_tso(struct ifnet *ifp, struct mbuf *m, uint16_t l3offset, uint16_t l4offset,
    void (*update_ip)(struct mbuf *, uint16_t, u_short *),
    bool csum_tcp, uint16_t l4csum_field_offset)
{
	struct mbuf *m0, *mi, *mi_next;
	int mss, error;
	uint16_t l4payload_offset;
	struct tcphdr *tcp;
	tcp_seq seq_number;

	m = m_pullup(m, l4offset + sizeof(struct tcphdr));
	if (m == NULL) {
		return (ENOBUFS);
	}
	tcp = (struct tcphdr *)mtodo(m, l4offset);
	l4payload_offset = l4offset + (tcp->th_off << 2);

#if 0
	/* TSO with GSO */
	if (m0->m_pkthdr.csum_flags & ifp->if_hwassist & CSUM_TSO)
		mss = ifp->if_hw_tsomax - state->ip_hlen - state->tcp_hlen;
	else
		mss = m0->m_pkthdr.tso_segsz;
#endif
	mss = m->m_pkthdr.tso_segsz;

	/*
	 * The headers for the small packets are mostly copied from the big packet
	 * with adjustments made to certain packet header fields on a per packet
	 * basis. The IPv4 total length field or IPv6 payload length field is
	 * updated to match the shorter payload. Hop-by-Hop Options and Destination
	 * Options extension headers, are copied as is (other extension headers,
	 * including AH, ESP, and Fragmentation, aren’t compatible with
	 * segmentation offload).
	 * The TCP header, including options, is copied to each small packet with
	 * some adjustments. The sequence number in each small packet is set to the
	 * sequence number of the previous packet plus segment size (the sequence
	 * number in the first packet is set to sequence number in the big packet
	 * being split up). The FIN, PSH flags are only reflected in the last
	 * segment, and CWR is only reflected in the first segment. The TCP
	 * checksum is computed for each packet with a simple adaptation of
	 * checksum offload.
	 */

	seq_number = ntohl(tcp->th_seq);

	IF_OFFLOAD_LOG(("%s: Do TSO with l3offset=%d, l4offset=%d, csum_tcp=%d, l4csum_field_offset=%d, l4payload_offset=%d, mss=%d\n", __func__, l3offset, l4offset, csum_tcp, l4csum_field_offset, l4payload_offset, mss));
	/* XXX: Instead of a complete list, create only the next segment? */
	m0 = m_seg(m, l4payload_offset, mss);
	if (m0 == NULL) {
		return (ENOBUFS);
	}
	for (mi = m0; mi != NULL; mi = mi_next) {
		IF_OFFLOAD_LOG(("%s: send segment\n", __func__));
		tcp = (struct tcphdr *)mtodo(mi, l4offset);

		/* Update IP stuff */
		update_ip(mi, l3offset, &tcp->th_sum);

		/* Update TCP header fields */
		if (mi != m0) { /* not first one */
			/*
			 * Clear CWR flag and set sequence number in all but
			 * the first segment
			 */
			tcp->th_flags &= ~TH_CWR;
			tcp->th_seq = htonl(seq_number);
		}
		if (mi->m_nextpkt != NULL) { /* not last one */
			/*
			 * Clear FIN and PUSH flags in all but the last
			 * segment.
			 */
			tcp->th_flags &= ~(TH_FIN | TH_PUSH);
			seq_number += mi->m_pkthdr.len - l4payload_offset; /* == mss? */
		}

		mi_next = mi->m_nextpkt;
		mi->m_nextpkt = NULL;

		if (csum_tcp) {
			/* Compute and insert TCP checksum */
			if_offload_csum_tcpudp(mi, l4offset, l4csum_field_offset, false);
		}

		if ((error = ((ifp->if_transmit_org)(ifp, mi)))) {
			if_printf(ifp, "if_transmit error %d\n", error);
			/*
			 * XXX: If a segment can not be sent, discard the following
			 * segments and propagate the erorr to the upper levels.
			 * In this way the TCP retransmits all the initial packet.
			 */
			while (mi != NULL) {
				mi_next = m->m_nextpkt;
				mi->m_nextpkt = NULL;
				m_freem(mi);
				mi = mi_next;
			}
			return (error);
		}
	}

	return (0);
}

static uint16_t
if_offload_csum_start(struct mbuf **mp, bool l4header, bool ipv6)
{
	struct mbuf *m;
	struct ether_header *eh;
	uint16_t ether_type, csum_start;

	m = *mp;
	csum_start = ETHER_HDR_LEN;
	m = m_pullup(m, csum_start);
	if (m == NULL)
		return (0);

	eh = mtod(m, struct ether_header *);
	ether_type = ntohs(eh->ether_type);
	while (ether_type == ETHERTYPE_VLAN || ether_type == ETHERTYPE_QINQ) {
		csum_start += ETHER_VLAN_ENCAP_LEN;
		/* determine inner ether type */
		m = m_pullup(m, csum_start);
		if (m == NULL)
			return (0);

		eh = mtod(m, struct ether_header *);
		ether_type = ntohs(*(&(eh->ether_type) + ((csum_start - ETHER_HDR_LEN) >> 2)));
	}

	if (l4header) {
		if (ipv6) {
			csum_start = ip6_lasthdr(m, csum_start, IPPROTO_IPV6, NULL);
		} else {
			struct ip *ip;

			m = m_pullup(m, csum_start + sizeof(struct ip));
			if (m == NULL)
				return (0);

			ip = mtod(m, struct ip *);
			csum_start += ip->ip_hl << 2;
		}
	}

	*mp = m;
	return (csum_start);
}


static uint16_t
if_offload_l4csum_field_offset(struct mbuf *m)
{

	/* XXX: TSO without CSUM_IP_TCP??? */
	if ((m->m_pkthdr.csum_flags & (CSUM_IP_TCP | CSUM_IP6_TCP |
	    CSUM_IP_TSO | CSUM_IP6_TSO)) != 0)
		return (offsetof(struct tcphdr, th_sum));
	else if ((m->m_pkthdr.csum_flags & (CSUM_IP_UDP | CSUM_IP6_UDP)) != 0)
		return (offsetof(struct udphdr, uh_sum));

	return (0);
}

static void
if_offload_values(uint32_t csum_req, bool *ipv6, bool *tso, bool *csum_ipv4,
    bool *csum_pseudo, uint8_t *csum_sctptcpudp)
{

	*ipv6 = ((csum_req & IF_OFFLOAD_EXPECTED6) != 0);
	*tso = ((csum_req & (CSUM_IP_TSO | CSUM_IP6_TSO)) != 0);
	*csum_ipv4 = ((csum_req & CSUM_IP) != 0);
	*csum_pseudo = ((csum_req & (CSUM_IP_PSEUDO | CSUM_IP6_PSEUDO)) != 0);
	if ((csum_req & (CSUM_IP_TCP | CSUM_IP6_TCP)) != 0) {
		*csum_sctptcpudp = 1;
	}
	else if ((csum_req & (CSUM_IP_UDP | CSUM_IP6_UDP)) != 0) {
		*csum_sctptcpudp = 2;
	}
	else if ((csum_req & (CSUM_IP_SCTP | CSUM_IP6_SCTP)) != 0)
		*csum_sctptcpudp = 3;
	else
		*csum_sctptcpudp = 0;
}

int
if_offload_transmit(struct ifnet *ifp, struct mbuf *m)
{
	bool ipv6, tso, csum_ipv4, csum_pseudo;
	uint8_t csum_sctptcpudp;
	uint16_t csum_start, l4csum_field_offset, l3offset, l4offset;
	uint32_t csum_req;

	if ((m->m_flags & M_PKTHDR) == 0)
		return ((ifp->if_transmit_org)(ifp, m));

	csum_req = m->m_pkthdr.csum_flags & IF_OFFLOAD_EXPECTED & ~ifp->if_hwassist;
	if (csum_req == 0)
		return ((ifp->if_transmit_org)(ifp, m));
	IF_OFFLOAD_LOG(("%s: csum_flags=%b, csum_req=%b\n", __func__, m->m_pkthdr.csum_flags, CSUM_BITS, csum_req, CSUM_BITS));

	/* values that should be given */
	if_offload_values(csum_req, &ipv6, &tso, &csum_ipv4, &csum_pseudo, &csum_sctptcpudp);
	csum_start = if_offload_csum_start(&m, (!(csum_ipv4 || csum_pseudo || tso)), ipv6);
	l4csum_field_offset = if_offload_l4csum_field_offset(m);
	if (csum_start == 0)
		return (0);

	/* If TSO is requested and ifp supports TSO, check whether the packet
	 * correctly respects
	 * - maximum burst limit (if_hw_tsomax),
	 * - maximum segment count (if_hw_tsomaxsegcount), and
	 * - maximum segment size (if_hw_tsomaxsegsize)
	 * of ifp.
	 */
#if 0
	if (!offload_tso && (csum_req & (CSUM_IP_TSO | CSUM_IP6_TSO)) != 0 &&
	    (ifp->if_hw_tsomax < m->m_pkthdr.tso_segsz ||
	     if_hw_tsomaxsegcount
#endif

	/*
	 * Check IP first. Compute and insert IPv4 header checksum or TCP/UDP
	 * pseudo header checksum if still required and the NIC won't do.
	 * Then do TSO if required and the NIC won't do.
	 */
#ifdef INET6
	if (ipv6) {
		if (csum_pseudo || tso) {
			l3offset = csum_start;
			if_offload_csum_ipv6(&m, csum_pseudo, &csum_start, l4csum_field_offset);
			if (tso) {
				l4offset = csum_start;
				return (if_offload_tso(ifp, m, l3offset, l4offset,
				    if_offload_tso_update_ipv6, (csum_sctptcpudp == 1), l4csum_field_offset));
			}
		}
	}
#ifdef INET
	else
#endif /* INET */
#endif /* INET6 */
#ifdef INET
		if (csum_ipv4 || csum_pseudo || tso) {
			l3offset = csum_start;
			if_offload_csum_ipv4(&m, csum_ipv4, csum_pseudo, &csum_start, l4csum_field_offset);
			if (tso) {
				l4offset = csum_start;
				return (if_offload_tso(ifp, m, l3offset, l4offset,
				    if_offload_tso_update_ipv4, (csum_sctptcpudp == 1), l4csum_field_offset));
			}
		}
#endif /* INET */

	/*
	 * TSO not required. Compute and insert SCTP, TCP, or UDP checksum if
	 * still required and the NIC won't do.
	 */
	if (csum_sctptcpudp == 1) /* TCP */
		if_offload_csum_tcpudp(m, csum_start, l4csum_field_offset, false);
	else if (csum_sctptcpudp == 2) /* UDP */
		if_offload_csum_tcpudp(m, csum_start, l4csum_field_offset, true);
#if defined(SCTP) || defined(SCTP_SUPPORT)
	else if (csum_sctptcpudp == 3) /* SCTP */
		if_offload_csum_sctp(m, csum_start);
#endif /* defined(SCTP) || defined(SCTP_SUPPORT) */

	return ((ifp->if_transmit_org)(ifp, m));
}

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Seyed Pouria Mousavizadeh Tehrani <info@spmzt.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/nv.h>
#include <sys/socket.h>
#include <sys/sockio.h>

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <netdb.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_strings.h>
#include <net/if_geneve.h>
#include <netinet/in.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>

#include "ifconfig.h"

#ifndef WITHOUT_NETLINK
#include "ifconfig_netlink.h"
#else
#include <net/route.h>

enum ifla_geneve_df {
	IFLA_GENEVE_DF_UNSET,
	IFLA_GENEVE_DF_SET,
	IFLA_GENEVE_DF_INHERIT,
	__IFLA_GENEVE_DF_MAX,
};
#endif

static struct geneve_params gnvp = {
	.ifla_proto		=	GENEVE_PROTO_ETHER,
};

static int
get_proto(const char *cp, uint16_t *valp)
{
	uint16_t val;

	if (!strcmp(cp, "l2"))
		val = GENEVE_PROTO_ETHER;
	else if (!strcmp(cp, "l3"))
		val = GENEVE_PROTO_INHERIT;
	else
		return (-1);

	*valp = val;
	return (0);
}

static int
get_val(const char *cp, u_long *valp)
{
	char *endptr;
	u_long val;

	errno = 0;
	val = strtoul(cp, &endptr, 0);
	if (cp[0] == '\0' || endptr[0] != '\0' || errno == ERANGE)
		return (-1);

	*valp = val;
	return (0);
}

static int
get_df(const char *cp, enum ifla_geneve_df *valp)
{
	enum ifla_geneve_df df;

	if (!strcmp(cp, "set"))
		df = IFLA_GENEVE_DF_SET;
	else if (!strcmp(cp, "inherit"))
		df = IFLA_GENEVE_DF_INHERIT;
	else if (!strcmp(cp, "unset"))
		df = IFLA_GENEVE_DF_UNSET;
	else
		return (-1);

	*valp = df;
	return (0);
}

static bool
is_multicast(struct addrinfo *ai)
{
#if (defined INET || defined INET6)
	struct sockaddr *sa;
	sa = ai->ai_addr;
#endif

	switch (ai->ai_family) {
#ifdef INET
	case AF_INET: {
		struct sockaddr_in *sin = satosin(sa);

		return (IN_MULTICAST(ntohl(sin->sin_addr.s_addr)));
	}
#endif
#ifdef INET6
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = satosin6(sa);

		return (IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr));
	}
#endif
	default:
		errx(1, "address family not supported");
	}
}

/*
 * geneve mode is read-only after creation,
 * therefore there is no need for separate netlink implementation
 */
static void
setgeneve_mode_clone(if_ctx *ctx __unused, const char *arg, int dummy __unused)
{
	uint16_t val;

	if (get_proto(arg, &val) < 0)
		errx(1, "invalid inner protocol: %s", arg);

	gnvp.ifla_proto = val;
}

#ifndef WITHOUT_NETLINK

struct nl_parsed_geneve {
	/* essential */
	uint32_t			ifla_vni;
	uint16_t			ifla_proto;
	uint16_t			ifla_local_port;
	uint16_t			ifla_remote_port;
	struct sockaddr			*ifla_local;
	struct sockaddr			*ifla_remote;

	/* optional */
	bool				ifla_dscp_inherit;
	bool				ifla_ttl_inherit;
	bool				ifla_external;
	uint8_t				ifla_ttl;
	enum ifla_geneve_df		ifla_df;
	struct ifla_geneve_port_range	*ifla_port_range;

	/* multicast specific */
	union sockaddr_union		ifla_mc_ifindex;	/* read-only */
	char				*ifla_mc_ifname;

	/* l2 specific */
	bool				ifla_ftable_learn;
	bool				ifla_ftable_flush;
	uint32_t			ifla_ftable_max;
	uint32_t			ifla_ftable_timeout;
	uint32_t			ifla_ftable_count;	/* read-only */
	uint32_t			ifla_ftable_nospace;	/* read-only */
	uint32_t			ifla_ftable_lock_upgrade_failed; /* read-only */
	uint64_t			ifla_stats_txcsum;	/* read-only */
	uint64_t			ifla_stats_tso;	/* read-only */
	uint64_t			ifla_stats_rxcsum;	/* read-only */
};

struct nla_geneve_info {
	const char		*kind;
	struct nl_parsed_geneve	data;
};

struct nla_geneve_link {
	uint32_t		ifi_index;
	struct nla_geneve_info	linkinfo;
};

static inline void
geneve_nl_init(if_ctx *ctx, struct snl_writer *nw, uint32_t flags)
{
	struct nlmsghdr *hdr;

	snl_init_writer(ctx->io_ss, nw);
	hdr = snl_create_msg_request(nw, NL_RTM_NEWLINK);
	hdr->nlmsg_flags |= flags;
	snl_reserve_msg_object(nw, struct ifinfomsg);
        snl_add_msg_attr_string(nw, IFLA_IFNAME, ctx->ifname);
}

static inline void
geneve_nl_fini(if_ctx *ctx, struct snl_writer *nw)
{
	struct nlmsghdr *hdr;

	if (!(hdr = snl_finalize_msg(nw)))
		err(1, "unable to send netlink message");

	ifcreate_nl(ctx, hdr);
}

#define _OUT(_field)	offsetof(struct nl_parsed_geneve, _field)
static const struct snl_attr_parser nla_geneve_linkinfo_data[] = {
	{ .type = IFLA_GENEVE_ID, .off = _OUT(ifla_vni), .cb = snl_attr_get_uint32 },
	{ .type = IFLA_GENEVE_PROTOCOL, .off = _OUT(ifla_proto), .cb = snl_attr_get_uint16 },
	{ .type = IFLA_GENEVE_LOCAL, .off = _OUT(ifla_local), .cb = snl_attr_get_ip },
	{ .type = IFLA_GENEVE_REMOTE, .off = _OUT(ifla_remote), .cb = snl_attr_get_ip },
	{ .type = IFLA_GENEVE_LOCAL_PORT, .off = _OUT(ifla_local_port), .cb = snl_attr_get_uint16 },
	{ .type = IFLA_GENEVE_PORT, .off = _OUT(ifla_remote_port), .cb = snl_attr_get_uint16 },
	{ .type = IFLA_GENEVE_PORT_RANGE, .off = _OUT(ifla_port_range), .cb = snl_attr_dup_struct },
	{ .type = IFLA_GENEVE_DF, .off = _OUT(ifla_df), .cb = snl_attr_get_uint8 },
	{ .type = IFLA_GENEVE_TTL, .off = _OUT(ifla_ttl), .cb = snl_attr_get_uint8 },
	{ .type = IFLA_GENEVE_TTL_INHERIT, .off = _OUT(ifla_ttl_inherit), .cb = snl_attr_get_bool },
	{ .type = IFLA_GENEVE_DSCP_INHERIT, .off = _OUT(ifla_dscp_inherit), .cb = snl_attr_get_bool },
	{ .type = IFLA_GENEVE_COLLECT_METADATA, .off = _OUT(ifla_external), .cb = snl_attr_get_bool },
	{ .type = IFLA_GENEVE_FTABLE_LEARN, .off = _OUT(ifla_ftable_learn), .cb = snl_attr_get_bool },
	{ .type = IFLA_GENEVE_FTABLE_FLUSH, .off = _OUT(ifla_ftable_flush), .cb = snl_attr_get_bool },
	{ .type = IFLA_GENEVE_FTABLE_MAX, .off = _OUT(ifla_ftable_max), .cb = snl_attr_get_uint32 },
	{ .type = IFLA_GENEVE_FTABLE_TIMEOUT, .off = _OUT(ifla_ftable_timeout), .cb = snl_attr_get_uint32 },
	{ .type = IFLA_GENEVE_FTABLE_COUNT, .off = _OUT(ifla_ftable_count), .cb = snl_attr_get_uint32 },
	{ .type = IFLA_GENEVE_FTABLE_NOSPACE_CNT, .off = _OUT(ifla_ftable_nospace), .cb = snl_attr_get_uint32 },
	{ .type = IFLA_GENEVE_FTABLE_LOCK_UP_FAIL_CNT, .off = _OUT(ifla_ftable_lock_upgrade_failed), .cb = snl_attr_get_uint32 },
	{ .type = IFLA_GENEVE_MC_IFNAME, .off = _OUT(ifla_mc_ifname), .cb = snl_attr_get_string },
	{ .type = IFLA_GENEVE_MC_IFINDEX, .off = _OUT(ifla_mc_ifindex), .cb = snl_attr_get_uint32 },
	{ .type = IFLA_GENEVE_TXCSUM_CNT, .off = _OUT(ifla_stats_txcsum), .cb = snl_attr_get_uint64 },
	{ .type = IFLA_GENEVE_TSO_CNT, .off = _OUT(ifla_stats_tso), .cb = snl_attr_get_uint64 },
	{ .type = IFLA_GENEVE_RXCSUM_CNT, .off = _OUT(ifla_stats_rxcsum), .cb = snl_attr_get_uint64 },
};
#undef _OUT
SNL_DECLARE_ATTR_PARSER(geneve_linkinfo_data_parser, nla_geneve_linkinfo_data);

#define _OUT(_field)	offsetof(struct nla_geneve_info, _field)
static const struct snl_attr_parser ap_geneve_linkinfo[] = {
	{ .type = IFLA_INFO_KIND, .off = _OUT(kind), .cb = snl_attr_get_string },
	{ .type = IFLA_INFO_DATA, .off = _OUT(data),
		.arg = &geneve_linkinfo_data_parser, .cb = snl_attr_get_nested },
};
#undef _OUT
SNL_DECLARE_ATTR_PARSER(geneve_linkinfo_parser, ap_geneve_linkinfo);

#define _IN(_field)	offsetof(struct ifinfomsg, _field)
#define _OUT(_field)	offsetof(struct nla_geneve_link, _field)
static const struct snl_attr_parser ap_geneve_link[] = {
	{ .type = IFLA_LINKINFO, .off = _OUT(linkinfo),
		.arg = &geneve_linkinfo_parser, .cb = snl_attr_get_nested },
};

static const struct snl_field_parser fp_geneve_link[] = {
	{ .off_in = _IN(ifi_index), .off_out = _OUT(ifi_index), .cb = snl_field_get_uint32 },
};
#undef _IN
#undef _OUT
SNL_DECLARE_PARSER(geneve_parser, struct ifinfomsg, fp_geneve_link, ap_geneve_link);

static const struct snl_hdr_parser *all_parsers[] = {
	&geneve_linkinfo_data_parser,
	&geneve_linkinfo_parser,
	&geneve_parser,
};

static void
geneve_status_nl(if_ctx *ctx)
{
	struct snl_writer nw;
	struct nlmsghdr *hdr;
	struct snl_errmsg_data errmsg;
	struct nla_geneve_link geneve_link;
	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
	struct sockaddr *lsa, *rsa;
	int mc;
	bool ipv6 = false;

	if (strncmp(ctx->ifname, "geneve", sizeof("geneve") - 1) != 0)
		return;

	snl_init_writer(ctx->io_ss, &nw);
	hdr = snl_create_msg_request(&nw, NL_RTM_GETLINK);
	hdr->nlmsg_flags |= NLM_F_DUMP;
	snl_reserve_msg_object(&nw, struct ifinfomsg);
        snl_add_msg_attr_string(&nw, IFLA_IFNAME, ctx->ifname);

	if (!(hdr = snl_finalize_msg(&nw)) || (!snl_send_message(ctx->io_ss, hdr)))
		return;

	hdr = snl_read_reply(ctx->io_ss, hdr->nlmsg_seq);
	if (hdr->nlmsg_type != NL_RTM_NEWLINK) {
		if (!snl_parse_errmsg(ctx->io_ss, hdr, &errmsg))
			errx(EINVAL, "(NETLINK)");
		if (errmsg.error_str != NULL)
			errx(errmsg.error, "(NETLINK) %s", errmsg.error_str);
	}

	if (!snl_parse_nlmsg(ctx->io_ss, hdr, &geneve_parser, &geneve_link))
		return;

	struct nla_geneve_info geneve_info = geneve_link.linkinfo;
	struct nl_parsed_geneve geneve_data = geneve_info.data;

	printf("\tgeneve mode: ");
	switch (geneve_data.ifla_proto) {
	case GENEVE_PROTO_INHERIT:
		printf("l3");
		break;
	case GENEVE_PROTO_ETHER:
	default:
		printf("l2");
		break;
	}

	printf("\n\tgeneve config:\n");
	/* Just report nothing if the network identity isn't set yet. */
	if (geneve_data.ifla_vni >= GENEVE_VNI_MAX) {
		printf("\t\tvirtual network identifier (vni): not configured\n");
		return;
	}

	lsa = geneve_data.ifla_local;
	rsa = geneve_data.ifla_remote;

	if ((lsa == NULL) ||
	    (getnameinfo(lsa, lsa->sa_len, src, sizeof(src),
	    NULL, 0, NI_NUMERICHOST) != 0))
		src[0] = '\0';
	if ((rsa == NULL) ||
	    (getnameinfo(rsa, rsa->sa_len, dst, sizeof(dst),
	    NULL, 0, NI_NUMERICHOST) != 0))
		dst[0] = '\0';
	else {
		ipv6 = rsa->sa_family == AF_INET6;
		if (!ipv6) {
			struct sockaddr_in *sin = satosin(rsa);
			mc = IN_MULTICAST(ntohl(sin->sin_addr.s_addr));
		} else {
			struct sockaddr_in6 *sin6 = satosin6(rsa);
			mc = IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr);
		}
	}

	printf("\t\tvirtual network identifier (vni): %d", geneve_data.ifla_vni);
	if (src[0] != '\0')
		printf("\n\t\tlocal: %s%s%s:%u", ipv6 ? "[" : "", src, ipv6 ? "]" : "",
		    geneve_data.ifla_local_port);
	if (dst[0] != '\0') {
		printf("\n\t\t%s: %s%s%s:%u", mc ? "group" : "remote", ipv6 ? "[" : "",
		    dst, ipv6 ? "]" : "", geneve_data.ifla_local_port);
		if (mc)
			printf(", dev: %s", geneve_data.ifla_mc_ifname);
	}

	if (ctx->args->verbose) {
		printf("\n\t\tportrange: %u-%u",
		    geneve_data.ifla_port_range->low,
		    geneve_data.ifla_port_range->high);

		if (geneve_data.ifla_ttl_inherit)
			printf(", ttl: inherit");
		else
			printf(", ttl: %d", geneve_data.ifla_ttl);

		if (geneve_data.ifla_dscp_inherit)
			printf(", dscp: inherit");

		if (geneve_data.ifla_df == IFLA_GENEVE_DF_INHERIT)
			printf(", df: inherit");
		else if (geneve_data.ifla_df == IFLA_GENEVE_DF_SET)
			printf(", df: set");
		else if (geneve_data.ifla_df == IFLA_GENEVE_DF_UNSET)
			printf(", df: unset");

		if (geneve_data.ifla_external)
			printf(", externally controlled");

		if (geneve_data.ifla_proto == GENEVE_PROTO_ETHER) {
			printf("\n\t\tftable mode: %slearning",
			    geneve_data.ifla_ftable_learn ? "" : "no");
			printf(", count: %d, max: %d, timeout: %d",
			    geneve_data.ifla_ftable_count,
			    geneve_data.ifla_ftable_max,
			    geneve_data.ifla_ftable_timeout);
			printf(", nospace: %u",
			    geneve_data.ifla_ftable_nospace);
		}

		printf("\n\t\tstats: tso %lu, txcsum %lu, rxcsum %lu",
		    geneve_data.ifla_stats_tso,
		    geneve_data.ifla_stats_txcsum,
		    geneve_data.ifla_stats_rxcsum);
	}

	putchar('\n');
}


static void
geneve_create_nl(if_ctx *ctx, struct ifreq *ifr)
{
	struct snl_writer nw = {};
	struct nlmsghdr *hdr;
	int off, off2;

	snl_init_writer(ctx->io_ss, &nw);
	hdr = snl_create_msg_request(&nw, RTM_NEWLINK);
	hdr->nlmsg_flags |= (NLM_F_CREATE | NLM_F_EXCL);
	snl_reserve_msg_object(&nw, struct ifinfomsg);
        snl_add_msg_attr_string(&nw, IFLA_IFNAME, ifr->ifr_name);

	off = snl_add_msg_attr_nested(&nw, IFLA_LINKINFO);
        snl_add_msg_attr_string(&nw, IFLA_INFO_KIND, "geneve");

	off2 = snl_add_msg_attr_nested(&nw, IFLA_INFO_DATA);
        snl_add_msg_attr_u16(&nw, IFLA_GENEVE_PROTOCOL, gnvp.ifla_proto);

	snl_end_attr_nested(&nw, off2);
	snl_end_attr_nested(&nw, off);

	geneve_nl_fini(ctx, &nw);
}

static void
setgeneve_vni_nl(if_ctx *ctx, const char *arg, int dummy __unused)
{
	struct snl_writer nw = {};
	int off, off2;
	u_long val;

	if (get_val(arg, &val) < 0 || val >= GENEVE_VNI_MAX)
		errx(1, "invalid network identifier: %s", arg);

	geneve_nl_init(ctx, &nw, 0);
	off = snl_add_msg_attr_nested(&nw, IFLA_LINKINFO);
        snl_add_msg_attr_string(&nw, IFLA_INFO_KIND, "geneve");

	off2 = snl_add_msg_attr_nested(&nw, IFLA_INFO_DATA);
        snl_add_msg_attr_u32(&nw, IFLA_GENEVE_ID, val);

	snl_end_attr_nested(&nw, off2);
	snl_end_attr_nested(&nw, off);

	geneve_nl_fini(ctx, &nw);
}

static void
setgeneve_local_nl(if_ctx *ctx, const char *addr, int dummy __unused)
{
	struct snl_writer nw = {};
	int off, off2;
	struct addrinfo *ai;
	const struct sockaddr *sa;
	int error;

	if ((error = getaddrinfo(addr, NULL, NULL, &ai)) != 0)
		errx(1, "error in parsing local address string: %s",
		    gai_strerror(error));

	if (is_multicast(ai))
		errx(1, "local address cannot be multicast");

	geneve_nl_init(ctx, &nw, 0);
	off = snl_add_msg_attr_nested(&nw, IFLA_LINKINFO);
        snl_add_msg_attr_string(&nw, IFLA_INFO_KIND, "geneve");

	off2 = snl_add_msg_attr_nested(&nw, IFLA_INFO_DATA);

	sa = ai->ai_addr;
        snl_add_msg_attr_ip(&nw, IFLA_GENEVE_LOCAL, sa);

	snl_end_attr_nested(&nw, off2);
	snl_end_attr_nested(&nw, off);

	geneve_nl_fini(ctx, &nw);
}

static void
setgeneve_remote_nl(if_ctx *ctx, const char *addr, int dummy __unused)
{
	struct snl_writer nw = {};
	int off, off2;
	struct addrinfo *ai;
	const struct sockaddr *sa;
	int error;

	if ((error = getaddrinfo(addr, NULL, NULL, &ai)) != 0)
		errx(1, "error in parsing remote address string: %s",
		    gai_strerror(error));

	if (is_multicast(ai))
		errx(1, "remote address cannot be multicast");

	geneve_nl_init(ctx, &nw, 0);
	off = snl_add_msg_attr_nested(&nw, IFLA_LINKINFO);
        snl_add_msg_attr_string(&nw, IFLA_INFO_KIND, "geneve");

	off2 = snl_add_msg_attr_nested(&nw, IFLA_INFO_DATA);

	sa = ai->ai_addr;
        snl_add_msg_attr_ip(&nw, IFLA_GENEVE_REMOTE, sa);

	snl_end_attr_nested(&nw, off2);
	snl_end_attr_nested(&nw, off);

	geneve_nl_fini(ctx, &nw);
}

static void
setgeneve_group_nl(if_ctx *ctx, const char *addr, int dummy __unused)
{
	struct snl_writer nw = {};
	int off, off2;
	struct addrinfo *ai;
	struct sockaddr *sa;
	int error;

	if ((error = getaddrinfo(addr, NULL, NULL, &ai)) != 0)
		errx(1, "error in parsing local address string: %s",
		    gai_strerror(error));

	if (!is_multicast(ai))
		errx(1, "group address must be multicast");

	geneve_nl_init(ctx, &nw, 0);
	off = snl_add_msg_attr_nested(&nw, IFLA_LINKINFO);
        snl_add_msg_attr_string(&nw, IFLA_INFO_KIND, "geneve");

	off2 = snl_add_msg_attr_nested(&nw, IFLA_INFO_DATA);

	sa = ai->ai_addr;
        snl_add_msg_attr_ip(&nw, IFLA_GENEVE_REMOTE, sa);

	snl_end_attr_nested(&nw, off2);
	snl_end_attr_nested(&nw, off);

	geneve_nl_fini(ctx, &nw);
}


static void
setgeneve_local_port_nl(if_ctx *ctx, const char *arg, int dummy __unused)
{
	struct snl_writer nw = {};
	int off, off2;
	u_long val;

	if (get_val(arg, &val) < 0 || val >= UINT16_MAX)
		errx(1, "invalid local port: %s", arg);

	geneve_nl_init(ctx, &nw, 0);
	off = snl_add_msg_attr_nested(&nw, IFLA_LINKINFO);
        snl_add_msg_attr_string(&nw, IFLA_INFO_KIND, "geneve");

	off2 = snl_add_msg_attr_nested(&nw, IFLA_INFO_DATA);

        snl_add_msg_attr_u16(&nw, IFLA_GENEVE_LOCAL_PORT, val);

	snl_end_attr_nested(&nw, off2);
	snl_end_attr_nested(&nw, off);

	geneve_nl_fini(ctx, &nw);
}

static void
setgeneve_remote_port_nl(if_ctx *ctx, const char *arg, int dummy __unused)
{
	struct snl_writer nw = {};
	int off, off2;
	u_long val;

	if (get_val(arg, &val) < 0 || val >= UINT16_MAX)
		errx(1, "invalid remote port: %s", arg);

	geneve_nl_init(ctx, &nw, 0);
	off = snl_add_msg_attr_nested(&nw, IFLA_LINKINFO);
        snl_add_msg_attr_string(&nw, IFLA_INFO_KIND, "geneve");

	off2 = snl_add_msg_attr_nested(&nw, IFLA_INFO_DATA);

        snl_add_msg_attr_u16(&nw, IFLA_GENEVE_PORT, val);

	snl_end_attr_nested(&nw, off2);
	snl_end_attr_nested(&nw, off);

	geneve_nl_fini(ctx, &nw);
}

static void
setgeneve_port_range_nl(if_ctx *ctx, const char *arg1, const char *arg2)
{
	struct snl_writer nw = {};
	int off, off2;
	u_long min, max;

	if (get_val(arg1, &min) < 0 || min >= UINT16_MAX)
		errx(1, "invalid port range minimum: %s", arg1);
	if (get_val(arg2, &max) < 0 || max >= UINT16_MAX)
		errx(1, "invalid port range maximum: %s", arg2);
	if (max < min)
		errx(1, "invalid port range");

	const struct ifla_geneve_port_range port_range = {
		.low = min,
		.high = max
	};

	geneve_nl_init(ctx, &nw, 0);
	off = snl_add_msg_attr_nested(&nw, IFLA_LINKINFO);
        snl_add_msg_attr_string(&nw, IFLA_INFO_KIND, "geneve");

	off2 = snl_add_msg_attr_nested(&nw, IFLA_INFO_DATA);

        snl_add_msg_attr(&nw, IFLA_GENEVE_PORT_RANGE,
			sizeof(port_range), (const void *)&port_range);

	snl_end_attr_nested(&nw, off2);
	snl_end_attr_nested(&nw, off);

	geneve_nl_fini(ctx, &nw);
}

static void
setgeneve_timeout_nl(if_ctx *ctx, const char *arg, int dummy __unused)
{
	struct snl_writer nw = {};
	int off, off2;
	u_long val;

	if (get_val(arg, &val) < 0 || (val & ~0xFFFFFFFF) != 0)
		errx(1, "invalid timeout value: %s", arg);

	geneve_nl_init(ctx, &nw, 0);
	off = snl_add_msg_attr_nested(&nw, IFLA_LINKINFO);
        snl_add_msg_attr_string(&nw, IFLA_INFO_KIND, "geneve");

	off2 = snl_add_msg_attr_nested(&nw, IFLA_INFO_DATA);

        snl_add_msg_attr_u32(&nw, IFLA_GENEVE_FTABLE_TIMEOUT, val);

	snl_end_attr_nested(&nw, off2);
	snl_end_attr_nested(&nw, off);

	geneve_nl_fini(ctx, &nw);
}

static void
setgeneve_maxaddr_nl(if_ctx *ctx, const char *arg, int dummy __unused)
{
	struct snl_writer nw = {};
	int off, off2;
	u_long val;

	if (get_val(arg, &val) < 0 || (val & ~0xFFFFFFFF) != 0)
		errx(1, "invalid maxaddr value: %s",  arg);

	geneve_nl_init(ctx, &nw, 0);
	off = snl_add_msg_attr_nested(&nw, IFLA_LINKINFO);
        snl_add_msg_attr_string(&nw, IFLA_INFO_KIND, "geneve");

	off2 = snl_add_msg_attr_nested(&nw, IFLA_INFO_DATA);

        snl_add_msg_attr_u32(&nw, IFLA_GENEVE_FTABLE_MAX, val);

	snl_end_attr_nested(&nw, off2);
	snl_end_attr_nested(&nw, off);

	geneve_nl_fini(ctx, &nw);
}

static void
setgeneve_dev_nl(if_ctx *ctx, const char *arg, int dummy __unused)
{
	struct snl_writer nw = {};
	int off, off2;

	geneve_nl_init(ctx, &nw, 0);
	off = snl_add_msg_attr_nested(&nw, IFLA_LINKINFO);
        snl_add_msg_attr_string(&nw, IFLA_INFO_KIND, "geneve");

	off2 = snl_add_msg_attr_nested(&nw, IFLA_INFO_DATA);

        snl_add_msg_attr_string(&nw, IFLA_GENEVE_MC_IFNAME, arg);

	snl_end_attr_nested(&nw, off2);
	snl_end_attr_nested(&nw, off);

	geneve_nl_fini(ctx, &nw);
}

static void
setgeneve_ttl_nl(if_ctx *ctx, const char *arg, int dummy __unused)
{
	struct snl_writer nw = {};
	int off, off2;
	u_long val;

	geneve_nl_init(ctx, &nw, 0);
	off = snl_add_msg_attr_nested(&nw, IFLA_LINKINFO);
        snl_add_msg_attr_string(&nw, IFLA_INFO_KIND, "geneve");

	off2 = snl_add_msg_attr_nested(&nw, IFLA_INFO_DATA);
	if ((get_val(arg, &val) < 0 || val > 256) == 0) {
		snl_add_msg_attr_u8(&nw, IFLA_GENEVE_TTL, val);
		snl_add_msg_attr_bool(&nw, IFLA_GENEVE_TTL_INHERIT, false);
	} else if (!strcmp(arg, "inherit")) {
		snl_add_msg_attr_bool(&nw, IFLA_GENEVE_TTL_INHERIT, true);
	} else
		errx(1, "invalid TTL value: %s", arg);

	snl_end_attr_nested(&nw, off2);
	snl_end_attr_nested(&nw, off);

	geneve_nl_fini(ctx, &nw);
}

static void
setgeneve_df_nl(if_ctx *ctx, const char *arg, int dummy __unused)
{
	struct snl_writer nw = {};
	int off, off2;
	enum ifla_geneve_df df;

	if (get_df(arg, &df) < 0)
		errx(1, "invalid df value: %s", arg);

	geneve_nl_init(ctx, &nw, 0);
	off = snl_add_msg_attr_nested(&nw, IFLA_LINKINFO);
        snl_add_msg_attr_string(&nw, IFLA_INFO_KIND, "geneve");

	off2 = snl_add_msg_attr_nested(&nw, IFLA_INFO_DATA);

        snl_add_msg_attr_u8(&nw, IFLA_GENEVE_DF, df);

	snl_end_attr_nested(&nw, off2);
	snl_end_attr_nested(&nw, off);

	geneve_nl_fini(ctx, &nw);
}

static void
setgeneve_inherit_dscp_nl(if_ctx *ctx, const char *arg __unused, int d)
{
	struct snl_writer nw = {};
	int off, off2;

	geneve_nl_init(ctx, &nw, 0);
	off = snl_add_msg_attr_nested(&nw, IFLA_LINKINFO);
        snl_add_msg_attr_string(&nw, IFLA_INFO_KIND, "geneve");

	off2 = snl_add_msg_attr_nested(&nw, IFLA_INFO_DATA);

        snl_add_msg_attr_bool(&nw, IFLA_GENEVE_DSCP_INHERIT, d != 0);

	snl_end_attr_nested(&nw, off2);
	snl_end_attr_nested(&nw, off);

	geneve_nl_fini(ctx, &nw);
}

static void
setgeneve_learn_nl(if_ctx *ctx, const char *arg __unused, int d)
{
	struct snl_writer nw = {};
	int off, off2;

	geneve_nl_init(ctx, &nw, 0);
	off = snl_add_msg_attr_nested(&nw, IFLA_LINKINFO);
        snl_add_msg_attr_string(&nw, IFLA_INFO_KIND, "geneve");

	off2 = snl_add_msg_attr_nested(&nw, IFLA_INFO_DATA);

        snl_add_msg_attr_bool(&nw, IFLA_GENEVE_FTABLE_LEARN, d != 0);

	snl_end_attr_nested(&nw, off2);
	snl_end_attr_nested(&nw, off);

	geneve_nl_fini(ctx, &nw);
}

static void
setgeneve_flush_nl(if_ctx *ctx, const char *val __unused, int d)
{
	struct snl_writer nw = {};
	int off, off2;

	geneve_nl_init(ctx, &nw, 0);
	off = snl_add_msg_attr_nested(&nw, IFLA_LINKINFO);
        snl_add_msg_attr_string(&nw, IFLA_INFO_KIND, "geneve");

	off2 = snl_add_msg_attr_nested(&nw, IFLA_INFO_DATA);

        snl_add_msg_attr_bool(&nw, IFLA_GENEVE_FTABLE_FLUSH, d != 0);

	snl_end_attr_nested(&nw, off2);
	snl_end_attr_nested(&nw, off);

	geneve_nl_fini(ctx, &nw);
}

static void
setgeneve_external_nl(if_ctx *ctx, const char *val __unused, int d)
{
	struct snl_writer nw = {};
	int off, off2;

	geneve_nl_init(ctx, &nw, 0);
	off = snl_add_msg_attr_nested(&nw, IFLA_LINKINFO);
        snl_add_msg_attr_string(&nw, IFLA_INFO_KIND, "geneve");

	off2 = snl_add_msg_attr_nested(&nw, IFLA_INFO_DATA);

        snl_add_msg_attr_bool(&nw, IFLA_GENEVE_COLLECT_METADATA, d != 0);

	snl_end_attr_nested(&nw, off2);
	snl_end_attr_nested(&nw, off);

	geneve_nl_fini(ctx, &nw);
}

static struct cmd geneve_cmds[] = {

	DEF_CLONE_CMD_ARG("genevemode",		setgeneve_mode_clone),

	DEF_CMD_ARG("geneveid",			setgeneve_vni_nl),
	DEF_CMD_ARG("genevelocal",		setgeneve_local_nl),
	DEF_CMD_ARG("geneveremote",		setgeneve_remote_nl),
	DEF_CMD_ARG("genevegroup",		setgeneve_group_nl),
	DEF_CMD_ARG("genevelocalport",		setgeneve_local_port_nl),
	DEF_CMD_ARG("geneveremoteport",		setgeneve_remote_port_nl),
	DEF_CMD_ARG2("geneveportrange",		setgeneve_port_range_nl),
	DEF_CMD_ARG("genevetimeout",		setgeneve_timeout_nl),
	DEF_CMD_ARG("genevemaxaddr",		setgeneve_maxaddr_nl),
	DEF_CMD_ARG("genevedev",		setgeneve_dev_nl),
	DEF_CMD_ARG("genevettl",		setgeneve_ttl_nl),
	DEF_CMD_ARG("genevedf",			setgeneve_df_nl),
	DEF_CMD("genevedscpinherit", 1,		setgeneve_inherit_dscp_nl),
	DEF_CMD("-genevedscpinherit", 0,	setgeneve_inherit_dscp_nl),
	DEF_CMD("genevelearn", 1,		setgeneve_learn_nl),
	DEF_CMD("-genevelearn", 0,		setgeneve_learn_nl),
	DEF_CMD("geneveflush", 1,		setgeneve_flush_nl),
	DEF_CMD("geneveflushall", 0,		setgeneve_flush_nl),
	DEF_CMD("geneveexternal", 1,		setgeneve_external_nl),
	DEF_CMD("-geneveexternal", 0,		setgeneve_external_nl),

	DEF_CMD_SARG("genevehwcsum",	IFCAP2_GENEVE_HWCSUM_NAME,
	    setifcapnv),
	DEF_CMD_SARG("-genevehwcsum",	"-"IFCAP2_GENEVE_HWCSUM_NAME,
	    setifcapnv),
	DEF_CMD_SARG("genevehwtso",	IFCAP2_GENEVE_HWTSO_NAME,
	    setifcapnv),
	DEF_CMD_SARG("-genevehwtso",	"-"IFCAP2_GENEVE_HWTSO_NAME,
	    setifcapnv),
};

#else

static int
geneve_set_ioctl(if_ctx *ctx, nvlist_t **nvl)
{
	void *data;
	size_t nvlen;
	struct ifreq ifr = {};

	data = nvlist_pack(*nvl, &nvlen);

	ifr.ifr_cap_nv.buffer = malloc(IFR_CAP_NV_MAXBUFSIZE);
	ifr.ifr_cap_nv.buf_length = IFR_CAP_NV_MAXBUFSIZE;
	memcpy(ifr.ifr_cap_nv.buffer, data, nvlen);
	ifr.ifr_cap_nv.length = nvlen;

	free(data);
	nvlist_destroy(*nvl);

	if (ioctl_ctx_ifr(ctx, SIOCSDRVSPEC, &ifr) != 0) {
		free(ifr.ifr_cap_nv.buffer);
		return (-1);
	}

	return (0);
}

static int
geneve_get_ioctl(if_ctx *ctx, nvlist_t **nvl)
{
	struct ifreq ifr = {};

	ifr.ifr_cap_nv.buffer = malloc(IFR_CAP_NV_MAXBUFSIZE);
	ifr.ifr_cap_nv.buf_length = IFR_CAP_NV_MAXBUFSIZE;

	if (ioctl_ctx_ifr(ctx, SIOCGDRVSPEC, &ifr) != 0) {
		free(ifr.ifr_cap_nv.buffer);
		return (-1);
	}

	*nvl = nvlist_unpack(ifr.ifr_cap_nv.buffer, ifr.ifr_cap_nv.length, 0);
	if (*nvl == NULL) {
		free(ifr.ifr_cap_nv.buffer);
		return (EIO);
	}

	free(ifr.ifr_cap_nv.buffer);
	return (0);
}

static int
geneve_check_nvl(nvlist_t *nvl)
{
	const struct sockaddr *lsa, *rsa;
	size_t llen, rlen;
	int error = -1;

	if (!nvlist_exists_number(nvl, "vni"))
		return (error);

	if (!nvlist_exists_binary(nvl, "local_sa"))
		return (error);

	if (!nvlist_exists_binary(nvl, "remote_sa"))
		return (error);

	if (!nvlist_exists_number(nvl, "proto"))
		return (error);

	lsa = nvlist_get_binary(nvl, "local_sa", &llen);
	rsa = nvlist_get_binary(nvl, "remote_sa", &rlen);

	if (lsa->sa_family != rsa->sa_family)
		errx(1, "cannot mix IPv4 and IPv6 addresses");

	error = 0;

	return (error);
}

static void
geneve_status(if_ctx *ctx)
{
	nvlist_t *nvl;
	char src[NI_MAXHOST], dst[NI_MAXHOST];
	char srcport[NI_MAXSERV], dstport[NI_MAXSERV];
	struct sockaddr *lsa, *rsa;
	size_t llen, rlen;
	int vni, mc, proto;
	bool ipv6 = false;
	enum ifla_geneve_df df;

	nvl = nvlist_create(0);

	if (geneve_get_ioctl(ctx, &nvl) != 0)
		return;

	if (geneve_check_nvl(nvl) != 0)
		return;

	proto = nvlist_get_number(nvl, "proto");
	printf("\tgeneve mode: ");
	switch (proto) {
	case GENEVE_PROTO_INHERIT:
		printf("l3");
		break;
	case GENEVE_PROTO_ETHER:
	default:
		printf("l2");
		break;
	}

	vni = nvlist_get_number(nvl, "vni");
	printf("\n\tgeneve config:\n");
	/* Just report nothing if the network identity isn't set yet. */
	if (vni >= GENEVE_VNI_MAX) {
		printf("\t\tvirtual network identifier (vni): not configured\n");
		return;
	}

	lsa = nvlist_take_binary(nvl, "local_sa", &llen);
	rsa = nvlist_take_binary(nvl, "remote_sa", &rlen);

	if (getnameinfo(lsa, lsa->sa_len, src, sizeof(src),
	    srcport, sizeof(srcport), NI_NUMERICHOST | NI_NUMERICSERV) != 0)
		src[0] = srcport[0] = '\0';
	if (getnameinfo(rsa, rsa->sa_len, dst, sizeof(dst),
	    dstport, sizeof(dstport), NI_NUMERICHOST | NI_NUMERICSERV) != 0)
		dst[0] = dstport[0] = '\0';
	else {
		ipv6 = rsa->sa_family == AF_INET6;
		if (!ipv6) {
			struct sockaddr_in *sin = satosin(rsa);
			mc = IN_MULTICAST(ntohl(sin->sin_addr.s_addr));
		} else {
			struct sockaddr_in6 *sin6 = satosin6(rsa);
			mc = IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr);
		}
	}

	printf("\t\tvirtual network identifier (vni): %d", vni);
	if (src[0] != '\0')
		printf("\n\t\tlocal: %s%s%s:%s", ipv6 ? "[" : "", src, ipv6 ? "]" : "",
		    srcport);
	if (dst[0] != '\0') {
		printf("\n\t\t%s %s%s%s:%s", mc ? "group" : "remote", ipv6 ? "[" : "",
		    dst, ipv6 ? "]" : "", dstport);
		if (mc)
			printf(", dev: %s", nvlist_get_string(nvl, "mc_ifname"));
	}

	if (ctx->args->verbose) {
		printf("\n\t\tportrange: %u-%u",
		    (uint16_t)nvlist_get_number(nvl, "min_port"),
		    (uint16_t)nvlist_get_number(nvl, "max_port"));

		if (nvlist_get_bool(nvl, "inherit_ttl"))
			printf(", ttl: inherit");
		else
			printf(", ttl: %d", (uint8_t)nvlist_get_number(nvl, "ttl"));

		if (nvlist_get_bool(nvl, "inherit_dscp"))
			printf(", dscp: inherit");

		df = nvlist_get_number(nvl, "df");
		if (df == IFLA_GENEVE_DF_INHERIT)
			printf(", df: inherit");
		else if (df == IFLA_GENEVE_DF_SET)
			printf(", df: set");
		else if (df == IFLA_GENEVE_DF_UNSET)
			printf(", df: unset");

		if (nvlist_get_bool(nvl, "external"))
			printf(", externally controlled");

		if (proto == GENEVE_PROTO_ETHER) {
			printf("\n\t\tftable mode: %slearning",
			    nvlist_get_bool(nvl, "learn") ? "" : "no");
			printf(", count: %u, max: %u, timeout: %u",
			    (uint32_t)nvlist_get_number(nvl, "ftable_cnt"),
			    (uint32_t)nvlist_get_number(nvl, "ftable_max"),
			    (uint32_t)nvlist_get_number(nvl, "ftable_timeout"));
		}
	}

	putchar('\n');
}

static void
geneve_create(if_ctx *ctx, struct ifreq *ifr)
{
	ifr->ifr_data = (caddr_t) &gnvp;
	ifcreate_ioctl(ctx, ifr);
}

static void
setgeneve_vni(if_ctx *ctx, const char *arg, int dummy __unused)
{
	nvlist_t *nvl;
	u_long val;

	if (get_val(arg, &val) < 0 || val >= GENEVE_VNI_MAX)
		errx(1, "invalid network identifier: %s", arg);

	nvl = nvlist_create(0);
	if (nvl == NULL)
		err(1, "no memory to set vni");

	nvlist_add_number(nvl, "vni", val);

	if (geneve_set_ioctl(ctx, &nvl) != 0)
		err(1, "GENEVE_CMD_SET_VNI");
}

static void
setgeneve_local(if_ctx *ctx, const char *addr, int dummy __unused)
{
	nvlist_t *nvl;
	struct addrinfo *ai;
#if (defined INET || defined INET6)
	struct sockaddr *sa;
#endif
	int error;

	if ((error = getaddrinfo(addr, NULL, NULL, &ai)) != 0)
		errx(1, "error in parsing local address string: %s",
		    gai_strerror(error));

	if (is_multicast(ai))
		errx(1, "local address cannot be multicast");

	nvl = nvlist_create(0);
	if (nvl == NULL)
		err(1, "no memory to set local address");

#if (defined INET || defined INET6)
	sa = ai->ai_addr;
#endif

	switch (ai->ai_family) {
#ifdef INET
	case AF_INET: {
		struct sockaddr_in *sin = satosin(sa);

		if (IN_MULTICAST(ntohl(sin->sin_addr.s_addr)))
			errx(1, "local address cannot be multicast");

		nvlist_add_binary(nvl, "local_sa", sin,
		sizeof(struct sockaddr_in));
		break;
	}
#endif
#ifdef INET6
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = satosin6(sa);

		if (IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr))
			errx(1, "local address cannot be multicast");

		nvlist_add_binary(nvl, "local_sa", sin6,
		sizeof(struct sockaddr_in6));
		break;
	}
#endif
	default:
		errx(1, "local address %s not supported", addr);
	}

	freeaddrinfo(ai);

	if (geneve_set_ioctl(ctx, &nvl) != 0)
		err(1, "GENEVE_CMD_SET_LOCAL_ADDR");
}

static void
setgeneve_remote(if_ctx *ctx, const char *addr, int dummy __unused)
{
	nvlist_t *nvl;
	struct addrinfo *ai;
#if (defined INET || defined INET6)
	struct sockaddr *sa;
#endif
	int error;

	if ((error = getaddrinfo(addr, NULL, NULL, &ai)) != 0)
		errx(1, "error in parsing remote address string: %s",
		    gai_strerror(error));

	if (is_multicast(ai))
		errx(1, "remote address cannot be multicast");

	nvl = nvlist_create(0);
	if (nvl == NULL)
		err(1, "no memory to set remote address");

#if (defined INET || defined INET6)
	sa = ai->ai_addr;
#endif

	switch (ai->ai_family) {
#ifdef INET
	case AF_INET: {
		struct sockaddr_in *sin = satosin(sa);

		if (IN_MULTICAST(ntohl(sin->sin_addr.s_addr)))
			errx(1, "remote address cannot be multicast");

		nvlist_add_binary(nvl, "remote_sa", sin,
		sizeof(struct sockaddr_in));
		break;
	}
#endif
#ifdef INET6
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = satosin6(sa);

		if (IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr))
			errx(1, "remote address cannot be multicast");

		nvlist_add_binary(nvl, "remote_sa", sin6,
		sizeof(struct sockaddr_in6));
		break;
	}
#endif
	default:
		errx(1, "remote address %s not supported", addr);
	}

	freeaddrinfo(ai);

	if (geneve_set_ioctl(ctx, &nvl) != 0)
		err(1, "GENEVE_CMD_SET_REMOTE_ADDR");
}

static void
setgeneve_group(if_ctx *ctx, const char *addr, int dummy __unused)
{
	nvlist_t *nvl;
	struct addrinfo *ai;
#if (defined INET || defined INET6)
	struct sockaddr *sa;
#endif
	int error;

	if ((error = getaddrinfo(addr, NULL, NULL, &ai)) != 0)
		errx(1, "error in parsing group address string: %s",
		    gai_strerror(error));

	if (!is_multicast(ai))
		errx(1, "group address must be multicast");

	nvl = nvlist_create(0);
	if (nvl == NULL)
		err(1, "no memory to set group");

#if (defined INET || defined INET6)
	sa = ai->ai_addr;
#endif

	switch (ai->ai_family) {
#ifdef INET
	case AF_INET: {
		struct sockaddr_in *sin = satosin(sa);

		if (!IN_MULTICAST(ntohl(sin->sin_addr.s_addr)))
			errx(1, "group address must be multicast");

		nvlist_add_binary(nvl, "remote_sa", sin,
		sizeof(struct sockaddr_in));
		break;
	}
#endif
#ifdef INET6
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = satosin6(sa);

		if (!IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr))
			errx(1, "group address must be multicast");

		nvlist_add_binary(nvl, "remote_sa", sin6,
		sizeof(struct sockaddr_in6));
		break;
	}
#endif
	default:
		errx(1, "group address %s not supported", addr);
	}

	freeaddrinfo(ai);

	if (geneve_set_ioctl(ctx, &nvl) != 0)
		err(1, "GENEVE_CMD_SET_REMOTE_ADDR");

	nvlist_destroy(nvl);
}

static void
setgeneve_local_port(if_ctx *ctx, const char *arg, int dummy __unused)
{
	nvlist_t *nvl;
	u_long val;

	if (get_val(arg, &val) < 0 || val >= UINT16_MAX)
		errx(1, "invalid local port: %s", arg);

	nvl = nvlist_create(0);
	if (nvl == NULL)
		err(1, "no memory to set local port");

	nvlist_add_number(nvl, "local_port", val);

	if (geneve_set_ioctl(ctx, &nvl) != 0)
		err(1, "GENEVE_CMD_SET_LOCAL_PORT");
}

static void
setgeneve_remote_port(if_ctx *ctx, const char *arg, int dummy __unused)
{
	nvlist_t *nvl;
	u_long val;

	if (get_val(arg, &val) < 0 || val >= UINT16_MAX)
		errx(1, "invalid remote port: %s", arg);

	nvl = nvlist_create(0);
	if (nvl == NULL)
		err(1, "no memory to set remote port");

	nvlist_add_number(nvl, "remote_port", val);

	if (geneve_set_ioctl(ctx, &nvl) != 0)
		err(1, "GENEVE_CMD_SET_REMOTE_PORT");
}

static void
setgeneve_port_range(if_ctx *ctx, const char *arg1, const char *arg2)
{
	nvlist_t *nvl;
	u_long min, max;

	if (get_val(arg1, &min) < 0 || min >= UINT16_MAX)
		errx(1, "invalid port range minimum: %s", arg1);
	if (get_val(arg2, &max) < 0 || max >= UINT16_MAX)
		errx(1, "invalid port range maximum: %s", arg2);
	if (max < min)
		errx(1, "invalid port range");

	nvl = nvlist_create(0);
	if (nvl == NULL)
		err(1, "no memory to set port range");

	nvlist_add_number(nvl, "min_port", min);
	nvlist_add_number(nvl, "max_port", max);

	if (geneve_set_ioctl(ctx, &nvl) != 0)
		err(1, "GENEVE_CMD_SET_PORT_RANGE");
}

static void
setgeneve_timeout(if_ctx *ctx, const char *arg, int dummy __unused)
{
	nvlist_t *nvl;
	u_long val;

	if (get_val(arg, &val) < 0 || (val & ~0xFFFFFFFF) != 0)
		errx(1, "invalid timeout value: %s", arg);

	nvl = nvlist_create(0);
	if (nvl == NULL)
		err(1, "no memory to set timeout");

	nvlist_add_number(nvl, "ftable_timeout", val & 0xFFFFFFFF);

	if (geneve_set_ioctl(ctx, &nvl) != 0)
		err(1, "GENEVE_CMD_SET_FTABLE_TIMEOUT");
}

static void
setgeneve_maxaddr(if_ctx *ctx, const char *arg, int dummy __unused)
{
	nvlist_t *nvl;
	u_long val;

	if (get_val(arg, &val) < 0 || (val & ~0xFFFFFFFF) != 0)
		errx(1, "invalid maxaddr value: %s",  arg);

	nvl = nvlist_create(0);
	if (nvl == NULL)
		err(1, "no memory to set maxaddr");

	nvlist_add_number(nvl, "ftable_max", val & 0xFFFFFFFF);

	if (geneve_set_ioctl(ctx, &nvl) != 0)
		err(1, "GENEVE_CMD_SET_FTABLE_MAX");
}

static void
setgeneve_dev(if_ctx *ctx, const char *arg, int dummy __unused)
{
	nvlist_t *nvl;

	nvl = nvlist_create(0);
	if (nvl == NULL)
		err(1, "no memory to set multicast interface");

	nvlist_add_string(nvl, "mc_ifname", arg);

	if (geneve_set_ioctl(ctx, &nvl) != 0)
		err(1, "GENEVE_CMD_SET_MULTICAST_IF");
}

static void
setgeneve_ttl(if_ctx *ctx, const char *arg, int dummy __unused)
{
	nvlist_t *nvl;
	u_long val;

	if ((get_val(arg, &val) < 0 || val > 256) == 0) {
		nvl = nvlist_create(0);
		if (nvl == NULL)
			err(1, "no memory to set ttl");

		nvlist_add_number(nvl, "ttl", val);
		nvlist_add_bool(nvl, "inherit_ttl", false);
	} else if (!strcmp(arg, "inherit")) {
		nvl = nvlist_create(0);
			if (nvl == NULL)
		err(1, "no memory to set ttl");

		nvlist_add_bool(nvl, "inherit_ttl", true);
	} else
		errx(1, "invalid TTL value: %s", arg);

	if (geneve_set_ioctl(ctx, &nvl) != 0)
		err(1, "GENEVE_CMD_SET_TTL");
}

static void
setgeneve_df(if_ctx *ctx, const char *arg, int dummy __unused)
{
	nvlist_t *nvl;
	enum ifla_geneve_df df;

	if (get_df(arg, &df) < 0)
		errx(1, "invalid df value: %s", arg);

	nvl = nvlist_create(0);
	if (nvl == NULL)
		err(1, "no memory to set df");

	nvlist_add_number(nvl, "df", df);

	if (geneve_set_ioctl(ctx, &nvl) != 0)
		err(1, "GENEVE_CMD_SET_DF");
}

static void
setgeneve_inherit_dscp(if_ctx *ctx, const char *arg __unused, int d)
{
	nvlist_t *nvl;

	nvl = nvlist_create(0);
	if (nvl == NULL)
		err(1, "no memory to set dscp inherit");

	nvlist_add_bool(nvl, "inherit_dscp", d != 0);

	if (geneve_set_ioctl(ctx, &nvl) != 0)
		err(1, "GENEVE_CMD_SET_DSCP_INHERIT");
}

static void
setgeneve_learn(if_ctx *ctx, const char *arg __unused, int d)
{
	nvlist_t *nvl;

	nvl = nvlist_create(0);
	if (nvl == NULL)
		err(1, "no memory to set learn");

	nvlist_add_bool(nvl, "learn", d != 0);

	if (geneve_set_ioctl(ctx, &nvl) != 0)
		err(1, "GENEVE_CMD_SET_LEARN");
}

static void
setgeneve_flush(if_ctx *ctx, const char *val __unused, int d)
{
	nvlist_t *nvl;

	nvl = nvlist_create(0);
	if (nvl == NULL)
		err(1, "no memory to flush");

	nvlist_add_bool(nvl, "flush", d != 0);

	if (geneve_set_ioctl(ctx, &nvl) != 0)
		err(1, "GENEVE_CMD_FLUSH");
}

static void
setgeneve_external(if_ctx *ctx, const char *val __unused, int d)
{
	nvlist_t *nvl;

	nvl = nvlist_create(0);
	if (nvl == NULL)
		err(1, "no memory to flush");

	nvlist_add_bool(nvl, "external", d != 0);

	if (geneve_set_ioctl(ctx, &nvl) != 0)
		err(1, "GENEVE_CMD_FLUSH");
}



static struct cmd geneve_cmds[] = {

	DEF_CLONE_CMD_ARG("genevemode",		setgeneve_mode_clone),

	DEF_CMD_ARG("geneveid",			setgeneve_vni),
	DEF_CMD_ARG("genevelocal",		setgeneve_local),
	DEF_CMD_ARG("geneveremote",		setgeneve_remote),
	DEF_CMD_ARG("genevegroup",		setgeneve_group),
	DEF_CMD_ARG("genevelocalport",		setgeneve_local_port),
	DEF_CMD_ARG("geneveremoteport",		setgeneve_remote_port),
	DEF_CMD_ARG2("geneveportrange",		setgeneve_port_range),
	DEF_CMD_ARG("genevetimeout",		setgeneve_timeout),
	DEF_CMD_ARG("genevemaxaddr",		setgeneve_maxaddr),
	DEF_CMD_ARG("genevedev",		setgeneve_dev),
	DEF_CMD_ARG("genevettl",		setgeneve_ttl),
	DEF_CMD_ARG("genevedf",			setgeneve_df),
	DEF_CMD("genevedscpinherit", 1,		setgeneve_inherit_dscp),
	DEF_CMD("-genevedscpinherit", 0,	setgeneve_inherit_dscp),
	DEF_CMD("genevelearn", 1,		setgeneve_learn),
	DEF_CMD("-genevelearn", 0,		setgeneve_learn),
	DEF_CMD("geneveflush", 1,		setgeneve_flush),
	DEF_CMD("geneveflushall", 0,		setgeneve_flush),
	DEF_CMD("geneveexternal", 1,		setgeneve_external),
	DEF_CMD("-geneveexternal", 0,		setgeneve_external),

	DEF_CMD_SARG("genevehwcsum",	IFCAP2_GENEVE_HWCSUM_NAME,
	    setifcapnv),
	DEF_CMD_SARG("-genevehwcsum",	"-"IFCAP2_GENEVE_HWCSUM_NAME,
	    setifcapnv),
	DEF_CMD_SARG("genevehwtso",	IFCAP2_GENEVE_HWTSO_NAME,
	    setifcapnv),
	DEF_CMD_SARG("-genevehwtso",	"-"IFCAP2_GENEVE_HWTSO_NAME,
	    setifcapnv),
};

#endif

static struct afswtch af_geneve = {
	.af_name		= "af_geneve",
	.af_af			= AF_UNSPEC,
#ifndef WITHOUT_NETLINK
	.af_other_status	= geneve_status_nl,
#else
	.af_other_status	= geneve_status,
#endif
};

static __constructor void
geneve_ctor(void)
{
	size_t i;

	for (i = 0; i < nitems(geneve_cmds); i++)
		cmd_register(&geneve_cmds[i]);
	af_register(&af_geneve);
#ifndef WITHOUT_NETLINK
	clone_setdefcallback_prefix("geneve", geneve_create_nl);
	SNL_VERIFY_PARSERS(all_parsers);
#else
	clone_setdefcallback_prefix("geneve", geneve_create);
#endif
}

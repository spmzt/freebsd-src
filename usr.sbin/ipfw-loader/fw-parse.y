/*
 * Copyright (c) 2007-2026 Yandex, LLC.
 *
 * SPDX-License-Identifier: BSD-4-Clause
 */

%{
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <libutil.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/fnv_hash.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/pfvar.h>
#include <net/route.h>
#include <netinet/ip.h>
#include <netinet/ip_compat.h>
#include <netinet/ip_fw.h>
#include <netinet/ip_dummynet.h>
#include <alias.h>

#include "fw-parse.h"
#include <netinet6/ip_fw_nat64.h>
#include <netinet6/ip_fw_nptv6.h>


#if __FreeBSD_version >= 700000
#define ipfw_insn_pipe ipfw_insn
#endif

/* Match/set DSCP options */
#if __FreeBSD_version < 900000
#ifndef	O_DSCP
#define	O_DSCP	85
#endif

#ifndef	O_SETDSCP
#define	O_SETDSCP	86
#endif
#endif

#ifndef IP_FW_TARG
#define	IP_FW_TARG	0
#endif

#define	LABEL_ALIGN		10
#define	RESERVED_TABLE_MAX	10

#define	SCHED_KLDLOAD(MODNAME) {\
	module_load[KLD_##MODNAME] = #MODNAME; \
}

extern int yylex(void);
//int yydebug = 1;

/* init macro */
#define START_LINE \
	bzero(actbuf, sizeof(actbuf)); \
	bzero(cmdbuf, sizeof(cmdbuf)); \
	bzero(rulebuf, sizeof(rulebuf)); \
	flush_ostate(&obj_state); \
	cmd = (ipfw_insn *)cmdbuf; \
	action = (ipfw_insn *)actbuf; \
	rule = (struct ip_fw_rule *)rulebuf; \
	is_not = false; \
	empty_rule = 0; \
	curr_proto[0] = 0; \
	have_state = have_log = have_altq = have_tag = NULL; \
	prev = action_label_insn = NULL; \
	action_label = NULL; \
	STAILQ_INIT(&addr_head); \
	SLIST_INIT(&port_head); \
	SLIST_INIT(&icmp_head)

#define	HANDLE_NOT(cmd)			\
	if (is_not) {			\
		(cmd)->len |= F_NOT;	\
		is_not = false;		\
	}

static const char *default_state_name = "default";
static uint32_t rulebuf[LARGE_NUMINSN], actbuf[LARGE_NUMINSN],
   cmdbuf[LARGE_NUMINSN];
static int empty_rule = 0;
char curr_proto[32];
ipfw_insn *src, *dst, *cmd, *action, *prev=NULL;
ipfw_insn *have_state = NULL, *have_log = NULL, *have_altq = NULL, *have_tag = NULL;
struct ip_fw_rule *rule;
struct tidx obj_state;

#define	DN_SIZE		sizeof(struct dn_id) + sizeof(struct dn_sch) + \
    sizeof(struct dn_link) + sizeof(struct dn_fs) + sizeof(struct dn_profile)

char dbuf[DN_SIZE], *dn_cmd;
uint32_t dn_tokens, dn_mask;
int dn_plr;
struct dn_sch dsch;
struct dn_link dlink;
struct dn_fs dfs;
struct dn_profile dprofile;
struct ipfw_flow_id dmask;
long pipe_byte_limit=-1, pipe_slot_limit=-1;

char nat_buf[sizeof(ipfw_obj_header) + sizeof(struct nat44_cfg_nat) +
    256 * sizeof(struct nat44_cfg_redir)];
struct nat44_cfg_nat *cn;
struct nat44_cfg_redir *crdr;
struct nat44_cfg_spool *csp;
int spool_cnt, has_redirect, port_range;

uint32_t nptv6_tokens;
char nptv6_buf[sizeof(ipfw_obj_lheader) + sizeof(ipfw_nptv6_cfg)];
ipfw_nptv6_cfg *nptv6_cfg;

uint32_t nat64STL_tokens;
char nat64stl_buf[sizeof(ipfw_obj_lheader) + sizeof(ipfw_nat64stl_cfg)];
ipfw_nat64stl_cfg *nat64stl_cfg;

uint32_t nat64LSN_tokens;
char nat64lsn_buf[sizeof(ipfw_obj_lheader) + sizeof(ipfw_nat64lsn_cfg)];
ipfw_nat64lsn_cfg *nat64lsn_cfg;

uint32_t nat64CLAT_tokens;
char nat64clat_buf[sizeof(ipfw_obj_lheader) + sizeof(ipfw_nat64clat_cfg)];
ipfw_nat64clat_cfg *nat64clat_cfg;

size_t len;
long bw_val;
int action_opcode;
struct port_list *port_prev;
struct icmp_list *icmp_prev;
struct labels *label_prev, *lhave_prev;
int optionset=0,altq_fetched=0;
bool is_not;
uint8_t set=0, clear=0;
uint32_t last_rule_num;
static TAILQ_HEAD(, pf_altq) altq_entries =
	TAILQ_HEAD_INITIALIZER(altq_entries);

/* list descriptions */
struct addr_list_head addr_head;
struct addr_list_head *curr_addr_head = NULL;
struct addr_list *curr_addr_list = NULL;
struct table *curr_table = NULL;
ipfw_insn_lookup curr_tableparam = { 0 };
uint8_t table_tokens = 0;

#define	TABLE_UNIQ(t, d)			\
if (table_tokens & TABLE_TOKEN_##t)		\
	yyerror("Dublicate token %s", d);	\
else					\
	table_tokens |= TABLE_TOKEN_##t
#define	TABLE_TOKEN_TYPE	(1 << 0)
#define	TABLE_TOKEN_VALTYPE	(1 << 1)
#define	TABLE_TOKEN_ALGO	(1 << 2)

SLIST_HEAD(port_list_head, port_list) port_head;
struct port_list {
	bool is_not;
	uint16_t port1;
	uint16_t port2;
	SLIST_ENTRY(port_list) next;
};

SLIST_HEAD(icmp_list_head, icmp_list) icmp_head;
struct icmp_list {
	uint8_t icmptype;
	SLIST_ENTRY(icmp_list) next;
};

struct labels_head labels_head = SLIST_HEAD_INITIALIZER(labels_head);
SLIST_HEAD(lhave_head, labels) lhave_head = SLIST_HEAD_INITIALIZER(lhave_head);

static char *action_label=NULL;
static ipfw_insn *action_label_insn;
static size_t action_label_offset = 0;
static char *has_a_label=NULL;

/* profiling */
static struct timespec ts = { 0, 0 };

struct tables_head tables_head = STAILQ_HEAD_INITIALIZER(tables_head);

struct table_list {
	STAILQ_HEAD(tlist_head, table)	tables;
};

#define	TABLES_HASH_SIZE	4096
struct table_list *tables_hash[TABLES_HASH_SIZE];
int table_offset = 0;
struct table_record *table_rec = NULL;
int unnamed_count = 0;	/* Temporary table count */
int table_cost;	/* Minimum number of prefixes to be in table */
int tables_fin = 0; /* profiling: end of tables */

static struct table *get_unnamed_table(void);
static struct table *find_table_idx(uint32_t num);
static void ref_table(struct table *table);
static void change_table(struct table *table);
static struct table *get_table(const char *tablename, int number, int flags);
static int compile_set_table(int from);
static int compile_set_instructions(int from);
static int compile_set_asis(int from);
static int compile_set(int from, int how);
void fill_ports(int from);

static void free_addr_entry(struct addr_list *l);

static void*
malloc_wait(size_t size)
{
	void *ptr;
	int trycnt = 10;

	do {
		ptr = malloc(size);
		if (ptr != NULL)
			return (ptr);
		usleep(100);
	} while (--trycnt > 0);
	if (ptr == NULL)
		err(1, "malloc_wait");
	return (ptr);
}

static void*
calloc_wait(size_t number, size_t size)
{
	void *ptr;

	ptr = malloc_wait(number * size);
	memset(ptr, 0, number * size);
	return (ptr);
}

static char *
strdup_wait(const char *str)
{
	char *ptr;
	int trycnt = 10;

	do {
		ptr = strdup(str);
		if (ptr != NULL)
			return (ptr);
		usleep(100);
	} while (--trycnt > 0);
	if (ptr == NULL)
		err(1, "strdup_wait");
	return (ptr);
}

static struct {
	const char	*spec;
	uint8_t		value;
} dscpspecs[] = {
	{ "af11", IPTOS_DSCP_AF11 >> 2 },	/* 001010 */
	{ "af12", IPTOS_DSCP_AF12 >> 2 },	/* 001100 */
	{ "af13", IPTOS_DSCP_AF13 >> 2 },	/* 001110 */
	{ "af21", IPTOS_DSCP_AF21 >> 2 },	/* 010010 */
	{ "af22", IPTOS_DSCP_AF22 >> 2 },	/* 010100 */
	{ "af23", IPTOS_DSCP_AF23 >> 2 },	/* 010110 */
	{ "af31", IPTOS_DSCP_AF31 >> 2 },	/* 011010 */
	{ "af32", IPTOS_DSCP_AF32 >> 2 },	/* 011100 */
	{ "af33", IPTOS_DSCP_AF33 >> 2 },	/* 011110 */
	{ "af41", IPTOS_DSCP_AF41 >> 2 },	/* 100010 */
	{ "af42", IPTOS_DSCP_AF42 >> 2 },	/* 100100 */
	{ "af43", IPTOS_DSCP_AF43 >> 2 },	/* 100110 */
	{ "be", IPTOS_DSCP_CS0 >> 2 },		/* 000000 */
	{ "ef", IPTOS_DSCP_EF >> 2 },		/* 101110 */
	{ "cs0", IPTOS_DSCP_CS0 >> 2 },		/* 000000 */
	{ "cs1", IPTOS_DSCP_CS1 >> 2 },		/* 001000 */
	{ "cs2", IPTOS_DSCP_CS2 >> 2 },		/* 010000 */
	{ "cs3", IPTOS_DSCP_CS3 >> 2 },		/* 011000 */
	{ "cs4", IPTOS_DSCP_CS4 >> 2 },		/* 100000 */
	{ "cs5", IPTOS_DSCP_CS5 >> 2 },		/* 101000 */
	{ "cs6", IPTOS_DSCP_CS6 >> 2 },		/* 110000 */
	{ "cs7", IPTOS_DSCP_CS7 >> 2 },		/* 100000 */
	{ NULL, 0 }
};

static uint8_t
dscpspec_match(const char *t)
{
	int i;

	for (i = 0; dscpspecs[i].spec != NULL; i++)
		if (strcmp(dscpspecs[i].spec, t) == 0)
			return (dscpspecs[i].value);

	yyerror("Unknown DSCP spec %s", t);
	return (-1);
}

static void
check_object_name(const char *name)
{
	int c, i, l;

	/*
	 * Check that name is null-terminated and contains
	 * valid symbols only. Valid mask is:
	 * [a-zA-Z0-9\-_\.]{1,63}
	 */
	l = strlen(name);
	if (l == 0 || l >= 64)
		goto invalid;
	for (i = 0; i < l; i++) {
		c = name[i];
		if (isalpha(c) || isdigit(c) || c == '_' ||
		    c == '-' || c == '.')
			continue;
		goto invalid;
	}
	return;
invalid:
	yyerror("Invalid object name: %s", name);
}

/* utility functions */
static ipfw_insn *
next_cmd(ipfw_insn *cmd)
{
	cmd += F_LEN(cmd);
	bzero(cmd, sizeof(*cmd));
	return cmd;
}

void
yyerror(const char *s, ...)
{
	va_list ap;
	va_start(ap, s);

	fprintf(stderr,"\n");
	vfprintf(stderr,s,ap);
	fprintf(stderr,": line %d\n", line);
	va_end(ap);
	exit(1);
}

void
yywarning(const char *s, ...)
{
	va_list ap;
	va_start(ap, s);

	fprintf(stderr,"\n");
	vfprintf(stderr,s,ap);
	fprintf(stderr,": line %d\n", line);
	va_end(ap);
	unclean_test = 1;
}

void
fdebug(const char *fname, int line, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	fprintf(stderr, "%s:%d ", fname, line);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

void
profile_stage(const char *text)
{
       struct timespec ts_new, ts_diff;

       if (debug == 0)
	       return;

       clock_gettime(CLOCK_MONOTONIC, &ts_new);

       if (ts.tv_sec == 0) {
		fprintf(stderr, " -- PROFILE: %s --\n", text);
       } else {
		ts_diff.tv_sec = ts_new.tv_sec - ts.tv_sec;
		ts_diff.tv_nsec = ts_new.tv_nsec - ts.tv_nsec;
		if (ts_diff.tv_nsec < 0) {
			ts_diff.tv_nsec += 1000000000;
			ts_diff.tv_sec--;
		}

		fprintf(stderr, " -- PROFILE: STAGE %s completed: %lu.%02lu\n",
		    text, ts_diff.tv_sec, ts_diff.tv_nsec / 10000000);
       }

       ts = ts_new;
}


in_addr_t
get_ip(const char *string)
{
       in_addr_t p;

       p = inet_addr(string);
       if(p == INADDR_NONE && strcmp(string, "255.255.255.255") != 0)
	      yyerror("Wrong IP: %s", string);

       return p;
}

struct in6_addr
get_ip6(const char *string)
{
	struct in6_addr p;

	if (inet_pton(AF_INET6, string, &p) != 1)
		return p;

	return p;
}

void
print_addr(struct addr_list *addr_entry, char *buf, int buflen)
{
	struct table *t;
	int len;

	memset(buf, 0, buflen);

	switch (addr_entry->addr_type) {
	case ADDR_IPV4:
		if (inet_ntop(AF_INET, &addr_entry->ip, buf, buflen) == NULL)
			break;
		len = strlen(buf);
		if (addr_entry->masklen != 32)
			snprintf(buf + len, buflen - len, "/%d",
			    addr_entry->masklen);

		break;
	case ADDR_IPV6:
		if (inet_ntop(AF_INET6, &addr_entry->ip6, buf, buflen) == NULL)
			break;
		len = strlen(buf);
		if (addr_entry->masklen != 128)
			snprintf(buf + len, buflen - len, "/%d",
			    addr_entry->masklen);

		break;
	case ADDR_IFACE:
	case ADDR_HOSTNAME:
		snprintf(buf, buflen, addr_entry->hostname);
		break;
	case ADDR_TABLE:
		t = find_table_idx(addr_entry->kidx);
		if (t == NULL)
			snprintf(buf, buflen, "table(%d)", addr_entry->kidx);
		else
			snprintf(buf, buflen, "%s:%d", t->name, addr_entry->kidx);
		break;
	case ADDR_IPV4MASK:
		if (inet_ntop(AF_INET, &addr_entry->ip, buf, buflen) == NULL)
			break;
		snprintf(buf, buflen, "%s:", buf);
		len = strlen(buf);
		if (inet_ntop(AF_INET, &addr_entry->ipmask, buf + len,
		    buflen - len) == NULL)
			buf[0] = '\0';
		break;

	case ADDR_IPV6MASK:
		if (inet_ntop(AF_INET6, &addr_entry->ip6, buf, buflen) == NULL)
			break;

		snprintf(buf, buflen, "%s/", buf);
		len = strlen(buf);

		if (inet_ntop(AF_INET6, &addr_entry->ip6mask, buf + len,
		    buflen - len) == NULL)
			buf[0] = '\0';
		break;
	case ADDR_NUMBER:
		snprintf(buf, buflen, "%u", addr_entry->ip);
		break;
	}
}

static ipfw_insn *
add_eaction(ipfw_insn *cmd, const char *eaction, const char *instance)
{

	action_opcode = cmd->opcode = O_EXTERNAL_ACTION;
	cmd->len = F_INSN_SIZE(ipfw_insn_kidx);
	insntod(cmd, kidx)->kidx = pack_object(&obj_state,
	    eaction, IPFW_TLV_EACTION);
	cmd = next_cmd(cmd);
	cmd->opcode = O_EXTERNAL_INSTANCE;
	cmd->len = F_INSN_SIZE(ipfw_insn_kidx);
	check_object_name(instance);
	insntod(cmd, kidx)->kidx = pack_object(&obj_state, instance, 0);
	return (cmd);
}

static void
add_proto_num(int proto, int flags)
{
	struct protoent *p;

	if (proto > 255)
		yyerror("Invalid protocol: %d (must be < 255)", proto);

	p = getprotobynumber(proto);
	if (p != NULL)
		strncpy(curr_proto, p->p_name, 31);
	else
		sprintf(curr_proto, "%d", proto);
	cmd->arg1 = proto;
	cmd->opcode = O_PROTO;
	cmd->len = flags | 1;
	if (prev)
		prev->len |= F_OR;
	prev = cmd;
	cmd = next_cmd(cmd);
	if (debug)
		fprintf(stderr, "proto: %s ", curr_proto);
}

void
add_proto(char *proto, int flags)
{
	struct protoent *p;

	if (strcmp(proto, "ip4") == 0 || strcmp(proto, "ip6") == 0) {
		cmd->opcode = strcmp(proto, "ip4") ? O_IP6 : O_IP4;
		cmd->len = flags | 1;
		if(prev)
			prev->len |= F_OR;
		prev = cmd;
		cmd = next_cmd(cmd);
	} else if (strcmp(proto, "all") != 0 && strcmp(proto, "ip") != 0) {
		/* if proto == "all" or "ip", do not set either */
		p = getprotobyname(proto);
		if (p == NULL)
			yyerror("Unknown protocol: %s", proto);
		cmd->opcode = O_PROTO;
		cmd->len = flags | 1;
		cmd->arg1 = p->p_proto;
		if (prev)
			prev->len |= F_OR;
		prev = cmd;
		cmd = next_cmd(cmd);
	}

	strncpy(curr_proto, proto, 31);
	if(debug)
		fprintf(stderr, "proto: %s ", proto);
}

void
fill_iface(char *iface)
{
	((ipfw_insn_if *)cmd)->name[0] = '\0';
	((ipfw_insn_if *)cmd)->o.len |= F_INSN_SIZE(ipfw_insn_if);

	HANDLE_NOT(cmd);
	if (strcmp(iface, "any") == 0)
		((ipfw_insn_if *)cmd)->o.len = 0;
	else if (!isdigit(*iface)) {
		strlcpy(((ipfw_insn_if *)cmd)->name, iface, sizeof(((ipfw_insn_if *)cmd)->name));
		((ipfw_insn_if *)cmd)->p.glob = strpbrk(iface, "*?[") != NULL ? 1 : 0;
	} else
		yyerror("interface name error: %s", iface);
}

void
fill_iface_table(struct table *table)
{
	ipfw_insn_if *cmdif = (ipfw_insn_if *)cmd;

	ref_table(table);
	cmdif->name[0] = '\1'; /* Special value indicating table */
	cmdif->p.kidx = table->kidx;
	((ipfw_insn_if *)cmd)->o.len |= F_INSN_SIZE(ipfw_insn_if);

	HANDLE_NOT(cmd);
}

void
fill_lookup_table(struct table *table, ipfw_insn_lookup *tparam)
{

	ref_table(table);

	cmd->opcode = O_TABLE_LOOKUP;
	insntod(cmd, kidx)->kidx = table->kidx;
	if (IPFW_LOOKUP_MASKING(&tparam->o) != 0) {
		switch (IPFW_LOOKUP_TYPE(&tparam->o)) {
		case LOOKUP_DST_PORT:
		case LOOKUP_SRC_PORT:
		case LOOKUP_UID:
		case LOOKUP_JAIL:
		case LOOKUP_DSCP:
		case LOOKUP_MARK:
		case LOOKUP_RULENUM:
		case LOOKUP_SRC_MAC:
		case LOOKUP_DST_MAC:
		case LOOKUP_SRC_IP6:
		case LOOKUP_DST_IP6:
		case LOOKUP_SRC_IP4:
		case LOOKUP_DST_IP4:
			break;
		default:
			yyerror("masked lookup is not supported for type %d",
			    IPFW_LOOKUP_TYPE(&tparam->o));
		}
		cmd->len |= F_INSN_SIZE(ipfw_insn_lookup);
		/* Copy complete value/mask anonymous union */
		memcpy(insntod(cmd, lookup)->__mask64, tparam->__mask64,
		    sizeof(ipfw_insn_lookup) - offsetof(ipfw_insn_lookup, __mask64));
	} else {
		cmd->len |= F_INSN_SIZE(ipfw_insn_kidx);
	}

	IPFW_SET_LOOKUP_TYPE(cmd, tparam->o.arg1);

	HANDLE_NOT(cmd);
	cmd = next_cmd(cmd);
}

static void
fill_ip6_mask(struct in6_addr *mask, unsigned int len) {
	int i = 0;
	if (len > 128)
		yyerror("Invalid IPv6 netmask %u\n", len);
	while (len >= 8) {
		mask->s6_addr[i++] = 0xff;
		len -= 8;
	}
	if (len > 0)
		mask->s6_addr[i++] = (0xff << (8-len));
	while (i < 16) {
		mask->s6_addr[i++] = 0;
	}
}

static int
is_ip6_mask128(struct in6_addr *mask) {
	static uint32_t mask128[4] = {
		0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff
	};

	return (memcmp(&mask->s6_addr[0], mask128, sizeof(struct in6_addr)) == 0);
}

static int
update_label_entry(struct labels *label_entry, uint32_t rule_num)
{

	if (label_entry->pact != NULL)
		label_entry->pact->d[0] = rule_num;
	else if (label_entry->xe != NULL)
		label_entry->xe->xentry.value = rule_num;
	else
		return (-1);

	return (0);
}

unsigned int
get_label_number(const char *name)
{
	struct labels *label_entry;

	SLIST_FOREACH(label_entry, &lhave_head, next) {
		if (strcmp(label_entry->name, name) == 0)
			return (label_entry->number);
	}

	return (0);
}

static void
attach_label(struct labels *label_entry)
{
	if (SLIST_EMPTY(&labels_head)) {
		SLIST_INSERT_HEAD(&labels_head, label_entry, next);
		label_prev = label_entry;
	} else {
		SLIST_INSERT_AFTER(label_prev, label_entry, next);
		label_prev = label_entry;
	}
}

static void
add_label(const char *name, unsigned int num)
{
	struct labels *lhave_entry, *label_entry;

	lhave_entry = malloc_wait(sizeof(struct labels));
	lhave_entry->name = name;
	lhave_entry->number = rule_num;

	if(SLIST_EMPTY(&lhave_head)) {
		SLIST_INSERT_HEAD(&lhave_head, lhave_entry, next);
		lhave_prev = lhave_entry;
	} else {
		SLIST_INSERT_AFTER(lhave_prev, lhave_entry, next);
		lhave_prev = lhave_entry;
	}

	SLIST_FOREACH(label_entry, &labels_head, next) {
		if(strcmp(label_entry->name, name) == 0) {
			if (update_label_entry(label_entry, num) != 0)
				yyerror("internal error (add label)");
		}
	}
}


/* Compile set into one huge table */
static int
compile_set_table(int from)
{
	struct addr_list *addr_entry, *addr_temp;
	struct table *t;

	t = get_unnamed_table();

	_debug("got table %u", t->number);

	t->addrs_head = addr_head;

	resolve_table(t);

	_debug("resolve done");

	memset(&t->addrs_head, 0, sizeof(t->addrs_head));

	STAILQ_FOREACH_SAFE(addr_entry, &addr_head, next, addr_temp) {
		STAILQ_REMOVE(&addr_head, addr_entry, addr_list, next);
		free(addr_entry);
	}

	/* Write table opcode */
	cmd->opcode = from ? O_IP_SRC_LOOKUP : O_IP_DST_LOOKUP;

	/* XXX: We currently don't support result comparison on match */
	insntod(cmd, kidx)->kidx = t->number;
#if 0
	if(addr_entry->ip != (in_addr_t)-1) {
		cmd->len |= F_INSN_SIZE(ipfw_insn_table);
		insntod(cmd, table)->value = addr_entry->ip;
	} else
#endif
	{
		cmd->len |= F_INSN_SIZE(ipfw_insn_kidx);
		IPFW_SET_LOOKUP_TYPE(cmd, LOOKUP_NONE);
	}
	_debug("opcode written");

	prev = cmd;
	cmd = next_cmd(cmd);

	return (1);
}

static int
compile_set_instructions(int from)
{
	struct addr_list *addr_entry, *addr_temp;
	int i;
	struct addr_list_head v4_hosts, v4_nets, v6_hosts, v6_nets;
	int cmds, other;
	char abuf[64];

	STAILQ_INIT(&v4_hosts);
	STAILQ_INIT(&v4_nets);
	STAILQ_INIT(&v6_hosts);
	STAILQ_INIT(&v6_nets);

	other = cmds = 0;

	STAILQ_FOREACH_SAFE(addr_entry, &addr_head, next, addr_temp) {
		switch(addr_entry->addr_type) {
		case ADDR_IPV4:
			/* IPv4 host/net */
			STAILQ_REMOVE(&addr_head, addr_entry, addr_list, next);
			if (addr_entry->masklen != 32)
				STAILQ_INSERT_TAIL(&v4_nets, addr_entry, next);
			else
				STAILQ_INSERT_TAIL(&v4_hosts, addr_entry, next);
			continue;
		case ADDR_IPV4MASK:
			STAILQ_REMOVE(&addr_head, addr_entry, addr_list, next);
			STAILQ_INSERT_TAIL(&v4_nets, addr_entry, next);
			continue;
		case ADDR_IPV6:
		case ADDR_IPV6MASK:
			if (!addr_entry->is_not && !enable_ipv6) {
				STAILQ_REMOVE(&addr_head, addr_entry, addr_list, next);
				free(addr_entry);
				continue;
			} else if (addr_entry->addr_type == ADDR_IPV6MASK) {
				STAILQ_REMOVE(&addr_head, addr_entry, addr_list, next);
				STAILQ_INSERT_TAIL(&v6_nets, addr_entry, next);
				continue;
			}
			/* IPv6 host/net */
			STAILQ_REMOVE(&addr_head, addr_entry, addr_list, next);
			if (addr_entry->masklen != 128)
				STAILQ_INSERT_TAIL(&v6_nets, addr_entry, next);
			else
				STAILQ_INSERT_TAIL(&v6_hosts, addr_entry, next);
			continue;
		}

#if 0
		struct table *t;
		struct addr_list *ae;
		struct table_xentry *xe;
		if (addr_entry->addr_type == ADDR_TABLE) {
			/* table */
			STAILQ_REMOVE(&addr_head, addr_entry, addr_list, next);

			t = find_table_idx(addr_entry->kidx);
			if (t == NULL)
				yyerror("compile_set_instructions(): unknown table %d", addr_entry->kidx);

			resolve_table(t);

			/* Assume 'normal' named tables */
			STAILQ_FOREACH(xe, &t->compiled_head, next) {
				ae = calloc(1, sizeof(struct addr_list));
				convert_table_entry(xe, ae);

				if (ae->addr_type == ADDR_IPV4) {
					if (ae->masklen != 32)
						STAILQ_INSERT_TAIL(&v4_nets, ae, next);
					else
						STAILQ_INSERT_TAIL(&v4_hosts, ae, next);
				} else if (ae->addr_type == ADDR_IPV6) {
					if (ae->masklen != 128)
						STAILQ_INSERT_TAIL(&v6_nets, ae, next);
					else
						STAILQ_INSERT_TAIL(&v6_hosts, ae, next);
				} else
					yyerror("compile_set_instructions(): unknown table entry type: %d", ae->addr_type);
			}

			continue;
		}
#endif

		other++;
	}

	/* XXX: Try to convert hosts into O_IP_(SRC|DST)_SET */

	/*
	 * Currently we handle IPv4 hosts/masks unique way.
	 * This can change in future.
	 * The same for IPv6.
	 */

	STAILQ_CONCAT(&v4_hosts, &v4_nets);

	prev = NULL;
	i = 0;
	uint32_t *d = ((ipfw_insn_u32 *)cmd)->d;
	STAILQ_FOREACH_SAFE(addr_entry, &v4_hosts, next, addr_temp) {
		d[0] = addr_entry->ip;
		if (addr_entry->addr_type == ADDR_IPV4MASK)
			d[1] = addr_entry->ipmask;
		else
			d[1] = htonl(~0 << (32 - addr_entry->masklen));
		d[0] &= d[1];

		print_addr(addr_entry, abuf, sizeof(abuf));
		_debug("v4++: %s", abuf);

		d += 2;
		i++;

		free(addr_entry);
	}

	if (i > 0) {
		/* Fill cmd for IPv4 */
		cmd->opcode = from ? O_IP_SRC_MASK : O_IP_DST_MASK;
		cmd->len |= 1 + i * 2;

		prev = cmd;
		cmd = next_cmd(cmd);
		cmds++;

		_debug("Added %d addresses to IPv4 opcode O_IP_*_MASK", i);
	}

	/* Do the same for IPv6 */

	STAILQ_CONCAT(&v6_hosts, &v6_nets);
	i = 0;

	/* XXX: Should we add O_IP6_DST opcode for each host prefix? */
	struct in6_addr *d6 = &((ipfw_insn_ip6*)cmd)->addr6;
	STAILQ_FOREACH_SAFE(addr_entry, &v6_hosts, next, addr_temp) {
		*d6++ = addr_entry->ip6;
		if (addr_entry->addr_type == ADDR_IPV6MASK)
			*d6 = addr_entry->ip6mask;
		else
			fill_ip6_mask(d6, addr_entry->masklen);

		d6++;
		i++;

		print_addr(addr_entry, abuf, sizeof(abuf));
		_debug("v6++: %s", abuf);

		/*
		 * Each mask occupies 8 words, and 7 records can be used ((64 - 1) / 8)
		 */
		if (i == 7) {
			_debug("Added %d addresses to IPv6 opcode O_IP_*_MASK", i);
			cmd->opcode = from ? O_IP6_SRC_MASK : O_IP6_DST_MASK;
			cmd->len |= 1 + i * 8;
			if (prev != NULL)
				prev->len |= F_OR;

			i = 0;
			prev = cmd;
			cmd = next_cmd(cmd);
			cmds++;
			d6 = &((ipfw_insn_ip6*)cmd)->addr6;
		}

		free_addr_entry(addr_entry);
	}

	/* Finish remainings */
	if (i > 0) {
		_debug("Added %d addresses to IPv6 opcode O_IP_*_MASK", i);
		cmd->opcode = from ? O_IP6_SRC_MASK : O_IP6_DST_MASK;
		cmd->len |= 1 + i * 8;
		if (prev != NULL)
			prev->len |= F_OR;
	
		cmd = next_cmd(cmd);
		cmds++;
	}

	/* Okay. Now 'other' part (e.g. me/me6 or orher strange opcodes) */
	if (other > 0) {
		if (prev != NULL)
			prev->len |= F_OR;

		_debug("Falling back to compile_set_asis() for %d opcodes", other);
		cmds += compile_set_asis(from);
	}

	return cmds;
}

static int
compile_set_asis(int from)
{
	struct addr_list *addr_entry, *addr_temp;
	int i = 0;
	uint32_t *d;

	prev = NULL;
	STAILQ_FOREACH_SAFE(addr_entry, &addr_head, next, addr_temp) {
		if ((addr_entry->addr_type == ADDR_IPV6 || addr_entry->addr_type == ADDR_IPV6MASK)
		    && !addr_entry->is_not && !enable_ipv6) {
			STAILQ_REMOVE(&addr_head, addr_entry, addr_list, next);
			free_addr_entry(addr_entry);
			continue;
		}
		if( i > 0 ) 
			prev->len |= F_OR;
		if(addr_entry->is_not)
			cmd->len |= F_NOT;
		cmd->len &= ~F_LEN_MASK;

		switch (addr_entry->addr_type) {
		case ADDR_ME:
			cmd->len |= F_INSN_SIZE(ipfw_insn);
			cmd->opcode = from ? O_IP_SRC_ME : O_IP_DST_ME;
			break;
		case ADDR_ME6:
			cmd->len |= F_INSN_SIZE(ipfw_insn);
			cmd->opcode = from ? O_IP6_SRC_ME : O_IP6_DST_ME;
			break;
		case ADDR_IPV6:
		case ADDR_IPV6MASK:
			((ipfw_insn_ip6*)cmd)->addr6 = addr_entry->ip6;
			if (addr_entry->addr_type == ADDR_IPV6MASK)
				((ipfw_insn_ip6*)cmd)->mask6 = addr_entry->ip6mask;
			else
				fill_ip6_mask(&((ipfw_insn_ip6*)cmd)->mask6, addr_entry->masklen);

			if (addr_entry->masklen != 128 ||
			    addr_entry->addr_type == ADDR_IPV6MASK) {
				cmd->opcode = from ? O_IP6_SRC_MASK : O_IP6_DST_MASK;
				cmd->len |= F_INSN_SIZE(ipfw_insn_ip6);
			} else {
				cmd->opcode = from ? O_IP6_SRC : O_IP6_DST;
				cmd->len |= (F_INSN_SIZE(ipfw_insn) + 4);
			}
			break;
		case ADDR_TABLE:
			cmd->opcode = from ? O_IP_SRC_LOOKUP : O_IP_DST_LOOKUP;
			insntod(cmd, kidx)->kidx = addr_entry->kidx;
			if (IPFW_LOOKUP_MATCH_TVALUE(&addr_entry->tparam.o) != 0) {
				cmd->len |= F_INSN_SIZE(ipfw_insn_lookup);
				cmd->arg1 = addr_entry->tparam.o.arg1;
				/* Copy complete value/mask anonymous union */
				memcpy(insntod(cmd, lookup)->__mask64, addr_entry->tparam.__mask64,
				    sizeof(ipfw_insn_lookup) - offsetof(ipfw_insn_lookup, __mask64));
			} else
				cmd->len |= F_INSN_SIZE(ipfw_insn_kidx);
			break;
		default:
			d = ((ipfw_insn_u32*)cmd)->d;
			d[0] = addr_entry->ip;
			if (addr_entry->addr_type == ADDR_IPV4MASK)
				d[1] = addr_entry->ipmask;
			else
				d[1] = htonl(~0 << (32 - addr_entry->masklen));
			d[0] &= d[1];
			if (addr_entry->masklen != 32 ||
			    addr_entry->addr_type == ADDR_IPV4MASK) {
				cmd->opcode = from ? O_IP_SRC_MASK : O_IP_DST_MASK;
				cmd->len |= 3;
			} else {
				cmd->opcode = from ? O_IP_SRC : O_IP_DST;
				cmd->len |= F_INSN_SIZE(ipfw_insn_u32);
			}
			break;
		}
		prev = cmd;
		cmd = next_cmd(cmd);

		i++;

		STAILQ_REMOVE(&addr_head, addr_entry, addr_list, next);
		free_addr_entry(addr_entry);

	}

	return (i);
}

#define	COMPILE_AS_IS		0
#define	COMPILE_AS_TABLE	1
#define	COMPILE_AS_INSTRUCTIONS	2
static int
compile_set(int from, int how)
{
	int i = 0;

	switch (how) {
	case COMPILE_AS_IS:
		i = compile_set_asis(from);
		break;
	case COMPILE_AS_TABLE:
		i = compile_set_table(from);
		break;
	case COMPILE_AS_INSTRUCTIONS:
		i = compile_set_instructions(from);
		break;
	default:
		yyerror("Unknown compile_set type: %d", how);
	}

	return i;
}

void
fill_addr_port_set(int from)
{
	struct addr_list *addr_entry, *addr_temp;
	struct table *table;
	int i = 0, total_ignored = 0;
	int total_count = 0, total_opcodes = 0, has_not = 0, optimize = 1;
	int total_v4 = 0, total_v6 = 0, total_tables = 0, total_other = 0;

	/* Check if we can optimize given block */
	STAILQ_FOREACH_SAFE(addr_entry, &addr_head, next, addr_temp) {
		if (addr_entry->is_not) {
			optimize = 0;
			has_not++;
		}

		switch (addr_entry->addr_type) {
		case ADDR_TABLE:
			table = find_table_idx(addr_entry->kidx);
			if (table == NULL)
				optimize = 0;
			else {
				/* We need to resolve table sooner or later */
				resolve_table(table);
				total_v4 += table->count4;
				total_v6 += table->count6;
				total_count += table->count4 + table->count6;
			}
			total_tables++;
			break;

		case ADDR_ME:
		case ADDR_ME6:
			optimize = 0;
			total_other++;
			break;
		case ADDR_IPV4:
			total_v4++;
			total_count++;
			break;
		case ADDR_IPV6:
			total_v6++;
			total_count++;
			break;
		case ADDR_IPV4MASK:
		case ADDR_IPV6MASK:
			optimize = 0;
			total_other++;
			total_count++;
			break;
		case ADDR_HOSTNAME:
		case ADDR_IFACE:
		case ADDR_NUMBER:
			total_ignored++;
			break;
		}

		total_opcodes++;
	}

	/*
	 * What we can do:
	 * 1) Compile as is (optimize == 0)
	 * 2) Merge into one table (optimize = 1)
	 * 3) Compile in several instructions without tables
	 */

	i = COMPILE_AS_IS;

	if (optimize_level == 0)
		optimize = 0;

	/* XXX temporary */
	table_cost = optimize_level;
	if (table_cost < 0)
		table_cost = 0;
	if (table_cost > 16)
		table_cost = 15;

	if (optimize) {
		if (total_count > 0 && total_count <= table_cost) {
			/*
			 * Potentially we should optimize as
			 * instructions.
			 * Special case: treat 1 IPv4/IPv6 address
			 * as 'as is'
			 */

			if (total_count > 1 || total_tables != 0)
				i = COMPILE_AS_INSTRUCTIONS;
		} else if (total_count > table_cost) {
			/* If we have single (large) table - leave as is */
			if (total_opcodes > 1)
				i = COMPILE_AS_TABLE;
		}
	}

	_debug("total %d opcodes %d={4=%d 6=%d t=%d o=%d i=%d not=%d} optimize %d act=%d",
	    total_count, total_opcodes, total_v4, total_v6,
	    total_tables, total_other, total_ignored, has_not, optimize, i);

	i = compile_set(from, i);

	fill_ports(from);
}

void
fill_ports(int from)
{
	struct port_list *port_entry, *port_temp;
	int i;
	uint16_t *p;

	i = 0;
	prev = NULL;
	p = ((ipfw_insn_u16*)cmd)->ports;
	SLIST_FOREACH_SAFE(port_entry, &port_head, next, port_temp) {
		if(from)
			cmd->opcode = O_IP_SRCPORT;
		else
			cmd->opcode = O_IP_DSTPORT;

		if(port_entry->is_not)
			cmd->len |= F_NOT;
		p[0] = port_entry->port1;
		p[1] = port_entry->port2;

		SLIST_REMOVE(&port_head, port_entry, port_list, next);

		i++;
		p += 2;
		if(debug)
			fprintf(stderr, "%s: %hd-%hd ", from ? "from-port" : "to-port", port_entry->port1, port_entry->port2);
		if (i == 30 && SLIST_NEXT(port_entry, next)) {
			/* split long chain to several opcodes */
			cmd->len |= (i + 1) | F_OR;
			cmd = next_cmd(cmd);
			p = ((ipfw_insn_u16*)cmd)->ports;
			i = 0;
		}
		free(port_entry);
	}
	if(i > 0) {
		((ipfw_insn_ip*)cmd)->o.len |= i + 1;
		cmd = next_cmd(cmd);
	}
}

static struct addr_list *
get_new_list_element(enum fw_addr_type type, bool is_not)
{
	struct addr_list *ip_entry;

	ip_entry = calloc_wait(1, sizeof(struct addr_list));
	ip_entry->is_not = is_not;
	ip_entry->addr_type = type;
	STAILQ_INSERT_HEAD(curr_addr_head, ip_entry, next);

	return (ip_entry);
}

static void
free_addr_entry(struct addr_list *l)
{

	free(l);
}

static struct addr_list *
add_addr_to_list(in_addr_t ip, uint32_t mask, bool is_not)
{
	struct addr_list *ip_entry;

	if(mask > 32)
		yyerror("Invalid network mask: %d", mask);

	ip_entry = get_new_list_element(ADDR_IPV4, is_not);
	ip_entry->ip = ip;
	ip_entry->masklen = mask;

	return (ip_entry);
}

static struct addr_list *
add_me_to_list(int me_type, int is_not)
{
	struct addr_list *ip_entry;

	ip_entry = get_new_list_element(me_type, is_not);

	return (ip_entry);
}

static struct addr_list *
add_number_to_list(uint32_t value)
{
	struct addr_list *entry;

	entry = get_new_list_element(ADDR_NUMBER, 0);
	entry->ip = value;
	return (entry);
}

static struct addr_list *
add_addrmask_to_list(in_addr_t ip, in_addr_t mask, bool is_not)
{
	struct addr_list *ip_entry;

	/* A single IP can be stored in an optimized format */
	if (mask == (uint32_t)~0)
		return (add_addr_to_list(ip, 32, is_not));
	ip_entry = get_new_list_element(ADDR_IPV4MASK, is_not);
	ip_entry->ip = ip;
	ip_entry->ipmask = mask;

	return (ip_entry);
}

static struct addr_list *
add_addr6_to_list(struct in6_addr ip6, uint32_t mask, bool is_not)
{
	struct addr_list *ip_entry;

	if(mask > 128)
		yyerror("Invalid network6 mask: %d", mask);

	ip_entry = get_new_list_element(ADDR_IPV6, is_not);
	ip_entry->ip6 = ip6;
	ip_entry->masklen = mask;

	return (ip_entry);
}

static struct addr_list *
add_addr6mask_to_list(struct in6_addr ip6, struct in6_addr mask, bool is_not)
{
	struct addr_list *ip_entry;

	if(is_ip6_mask128(&mask))
		return (add_addr6_to_list(ip6, 128, is_not));

	ip_entry = get_new_list_element(ADDR_IPV6MASK, is_not);
	ip_entry->ip6 = ip6;
	ip_entry->ip6mask = mask;

	return (ip_entry);
}

static struct addr_list *
add_table_to_list(struct table *table, ipfw_insn_lookup *tparam, bool is_not)
{
	struct addr_list *ip_entry;

	ref_table(table);
	ip_entry = get_new_list_element(ADDR_TABLE, is_not);
	if (tparam != NULL)
		ip_entry->tparam = *tparam;
	ip_entry->kidx = table->kidx;
	ip_entry->hostname = table->num_name;

	return (ip_entry);
}

static struct addr_list *
add_host_to_list(char *hostname, int line, bool is_not)
{
	struct addr_list *ip_entry;

	if (debug)
		fprintf(stderr, "Added host %s, line %d\n", hostname, line);

	ip_entry = get_new_list_element(ADDR_HOSTNAME, is_not);
	ip_entry->hostname = strdup_wait(hostname);
	ip_entry->line = line;

	return (ip_entry);
}

static struct addr_list *
add_iface_to_list(char *hostname, int line, bool is_not)
{
	struct addr_list *ip_entry;

	if (debug)
		fprintf(stderr, "Added iface %s, line %d\n", hostname, line);

	ip_entry = get_new_list_element(ADDR_IFACE, is_not);
	ip_entry->hostname = strdup_wait(hostname);
	ip_entry->line = line;

	return (ip_entry);
}

void
add_port_to_list(uint16_t port1, uint16_t port2, bool is_not)
{
	struct port_list *port_entry = malloc_wait(sizeof(struct port_list));

	port_entry->port1 = port1;
	port_entry->port2 = port2;
	port_entry->is_not = is_not;

	if(SLIST_EMPTY(&port_head)) {
		SLIST_INSERT_HEAD(&port_head, port_entry, next);
		port_prev = port_entry;
	} else {
		SLIST_INSERT_AFTER(port_prev, port_entry, next);
		port_prev = port_entry;
	}
}

void
add_port(char *port, bool is_not)
{
	struct servent *serv;
	char str[32], *p;

	strncpy(str, port, 31);
	if((p = strchr(str, '\\')) != NULL)
		strcpy(p, p+1);

	if (strcmp(curr_proto, "tcp") != 0 &&
	    strcmp(curr_proto, "udp") != 0 &&
	    strcmp(curr_proto, "udplite") != 0)
		yyerror("protocol must be specified for port: %s", port);

	if((serv = getservbyname(str, curr_proto)) == NULL)
		yyerror("port name error: %s", port);

	add_port_to_list(ntohs(serv->s_port), ntohs(serv->s_port), is_not);
}

static void
altq_fetch()
{
	struct pfioc_altq pfioc;
	struct pf_altq *altq;
	int pffd;
	unsigned int mnr;

	if (altq_fetched)
		return;
	altq_fetched = 1;
	pffd = open("/dev/pf", O_RDONLY);
	if (pffd == -1) {
		warn("altq support opening pf(4) control device");
		return;
	}
	bzero(&pfioc, sizeof(pfioc));
	if (ioctl(pffd, DIOCGETALTQS, &pfioc) != 0) {
		warn("altq support getting queue list");
		close(pffd);
		return;
	}
	mnr = pfioc.nr;
	for (pfioc.nr = 0; pfioc.nr < mnr; pfioc.nr++) {
		if (ioctl(pffd, DIOCGETALTQ, &pfioc) != 0) {
			if (errno == EBUSY)
				break;
			warn("altq support getting queue list");
			close(pffd);
			return;
		}
		if (pfioc.altq.qid == 0)
			continue;
		altq = malloc(sizeof(*altq));
		if (altq == NULL)
			err(1, "malloc");
		*altq = pfioc.altq;
		TAILQ_INSERT_TAIL(&altq_entries, altq, entries);
	}
	close(pffd);
}

static u_int32_t
altq_name_to_qid(const char *name)
{
	struct pf_altq *altq;

	altq_fetch();
	TAILQ_FOREACH(altq, &altq_entries, entries)
		if (strcmp(name, altq->qname) == 0)
			break;
	if (altq == NULL)
		errx(1, "altq has no queue named `%s'", name);
	return altq->qid;
}

static inline int src_opcode(int opcode) {
	switch (opcode) {
	case O_IP_SRC_LOOKUP:
	case O_IP_SRC:
	case O_IP_SRC_MASK:
	case O_IP6_SRC:
	case O_IP6_SRC_MASK:
		return 1;
	}
	return 0;
}

static inline int dst_opcode(int opcode) {
	switch (opcode) {
	case O_IP_DST_LOOKUP:
	case O_IP_DST:
	case O_IP_DST_MASK:
	case O_IP6_DST:
	case O_IP6_DST_MASK:
		return 1;
	}
	return 0;
}

int
split_rule(struct ip_fw_rule *rule, struct ip_fw_rule **r1,
    struct ip_fw_rule **r2)
{
	int src_words = 0, dst_words = 0, split_words=0, split_src;
	int i1=0, i2=0;
	int add_to_r1, add_to_r2, break_block;

	ipfw_insn *cmd, *new_cmd = NULL;
	*r1=malloc_wait(RULESIZE(rule));
	*r2=malloc_wait(RULESIZE(rule));
	struct ip_fw_rule *rule1 = *r1;
	struct ip_fw_rule *rule2 = *r2;

	if(debug)
		printf("\nsplit rule %d: size %lu", rule->rulenum, RULESIZE(rule));

	for (cmd = rule->cmd; cmd < ACTION_PTR(rule); cmd += F_LEN(cmd)) {
		if (src_opcode(cmd->opcode))
			src_words += F_LEN(cmd);
		else if (dst_opcode(cmd->opcode))
			dst_words += F_LEN(cmd);
	}
	if (src_words > dst_words) {
		split_words = src_words / 2;
		split_src = 1;
	} else {
		split_words = dst_words / 2;
		split_src = 0;
	}

	bcopy(rule, rule1, sizeof(struct ip_fw_rule));
	bcopy(rule, rule2, sizeof(struct ip_fw_rule));

	for (cmd = rule->cmd; cmd < ACTION_PTR(rule); cmd += F_LEN(cmd)) {
		add_to_r1 = 1;
		add_to_r2 = 1;
		break_block = 0;

		if ((split_src && src_opcode(cmd->opcode)) ||
		    (!split_src && dst_opcode(cmd->opcode))) {
			if (split_words < 0)
				add_to_r1 = 0;
			else {
				add_to_r2 = 0;
				if (split_words - F_LEN(cmd) < 0)
					break_block = 1;
			}
			split_words -= F_LEN(cmd);
		}

		if (add_to_r1) {
			new_cmd = rule1->cmd+i1;
			i1 += F_LEN(cmd);
			bcopy(cmd, new_cmd, F_LEN(cmd)*sizeof(ipfw_insn));
		}
		if (add_to_r2) {
			new_cmd = rule2->cmd+i2;
			i2 += F_LEN(cmd);
			bcopy(cmd, new_cmd, F_LEN(cmd)*sizeof(ipfw_insn));
		}
		// this condition is true when only one of (add_to_r1, add_to_r2) is true
		if (break_block)
			new_cmd->len &= ~F_OR;
	}
	rule1->act_ofs = i1;
	rule2->act_ofs = i2;
	bcopy(ACTION_PTR(rule), ACTION_PTR(rule1), (rule->cmd_len-rule->act_ofs)*sizeof(ipfw_insn));
	bcopy(ACTION_PTR(rule), ACTION_PTR(rule2), (rule->cmd_len-rule->act_ofs)*sizeof(ipfw_insn));
	rule1->cmd_len = rule1->act_ofs+rule->cmd_len-rule->act_ofs;
	rule2->cmd_len = rule2->act_ofs+rule->cmd_len-rule->act_ofs;
	return RULESIZE(rule1) < RULESIZE(rule) && RULESIZE(rule2) < RULESIZE(rule);
}

static void
add_rule(struct ip_fw_rule *rule)
{
	ipfw_insn *act_ptr;
	size_t sz;
	struct ip_fw_rule *rule1, *rule2;
	int do_split = 0;

	/* If the rule too long, split it on two */
	if (RULESIZE(rule) > MAX_RULESIZE) {
		do_split = 1;
	}

	if(do_split && split_rule(rule, &rule1, &rule2)) {
		if(debug)
			printf(" to rule1: %lu and rule2: %lu\n", RULESIZE(rule1), RULESIZE(rule2));
		add_rule(rule1);
		add_rule(rule2);

		free(rule1);
		free(rule2);

		return;
	}

	void *rule_data = encap_single_rule(rule, &obj_state, &act_ptr, &sz);
	if (rule_data == NULL)
		errx(1, "\nmemory error");

	if (action_label) {
		ipfw_insn *act_label_ptr = act_ptr + action_label_offset;
		unsigned int label_number = get_label_number(action_label);

		if (label_number) {
			/* arg is referencing previously-defined label */
			if (action_opcode == O_SKIPTO)
				errx(1, "line %d: skipto label '%s' goes back", line, action_label);

			insntod(act_label_ptr, u32)->d[0] = label_number;
		} else {
			struct labels *label_entry = calloc_wait(1, sizeof(struct labels));
			label_entry->name = strdup_wait(action_label);
			label_entry->pact = insntod(act_label_ptr, u32);
			label_entry->line = line;

			attach_label(label_entry);
		}
	}

	rules[rule_count].rule = rule_data;
	rules[rule_count].sz = sz;
	rules[rule_count].line = line;
	rule_count++;
}

void
init_tables()
{

	memset(tables_hash, 0, sizeof(tables_hash));
}

static int
hash_table(const char *tablename)
{

	return fnv_32_str(tablename + 1, FNV1_32_INIT) % TABLES_HASH_SIZE;
}

static struct table *
find_table_idx(uint32_t num)
{
	int i;
	struct table_list *tl;
	struct table *table;

	for (i = 0; i < TABLES_HASH_SIZE; i++) {
		if ((tl = tables_hash[i]) == NULL)
			continue;

		STAILQ_FOREACH(table, &tl->tables, hnext) {
			if (table->number == num)
				return table;
		}
	}

	return NULL;
}


static struct table *
get_table(const char *tablename, int number, int flags)
{
	int i;
	struct table_list *tl;
	struct table *table;
	char xbuf[64];

	if (tablename == NULL) {
		if (number <= 0 || number > RESERVED_TABLE_MAX)
			errx(1, "Table number %d not in reserved range 1..%d\n",
			    number, RESERVED_TABLE_MAX);
		snprintf(xbuf, sizeof(xbuf), "%d", number);
		tablename = xbuf;
	}

	i = hash_table(tablename);
	if (tables_hash[i] == NULL) {
		tl = malloc_wait(sizeof(struct table_list));
		STAILQ_INIT(&tl->tables);
		tables_hash[i] = tl;
	}

	tl = tables_hash[i];

	STAILQ_FOREACH(table, &tl->tables, hnext) {
		if (!strcmp(table->name, tablename)) {
			if ((flags & O_SYNC) != 0)
				ref_table(table);
			return table;
		}
	}

	if ((flags & O_CREAT) == 0)
		errx(1, "Unresolved table name: %s", tablename);

	/* Not found. */
	table = calloc_wait(1, sizeof(struct table));
	if (number == 0) {
		table->number = table_get_empty_num_name();
		if (table->number == 0)
			errx(1, "Table range exceeded: used: %d\n", table_count);
	} else
		table->number = number;
	table->name = strdup_wait(tablename);
	table->set_num = TMP_SET_NUM;
	table->type = IPFW_TABLE_ADDR;
	snprintf(table->num_name, sizeof(table->num_name), "%d", table->number);
	STAILQ_INIT(&table->addrs_head);
	STAILQ_INIT(&table->compiled_head);

	/* Add to global and per-hash list */
	STAILQ_INSERT_TAIL(&tables_head, table, gnext);
	STAILQ_INSERT_TAIL(&tl->tables, table, hnext);

	if (debug)
		fprintf(stderr, "Mapping table %s to number %d\n", tablename, table->number);

	if ((flags & O_SYNC) != 0)
		ref_table(table);
	return table;
}

static struct table *
get_unnamed_table(void)
{
	char nbuf[24];

	snprintf(nbuf, sizeof(nbuf), "_UNNAMED%d_", ++unnamed_count);

	return get_table(nbuf, 0, O_CREAT);
}

static void
ref_table(struct table *table)
{

	if (table->used == 0 && debug > 0)
		fprintf(stderr, "Referenced table %s\n", table->name);

	pack_table(&obj_state, table->num_name, &table->kidx);

	table->used++;
}

static void
change_table(struct table *table)
{

	table->resolved = 0;
}

static void
resolve_table_internal(struct table *table, int depth __unused)
{
	struct addr_list *l, *l_tmp;
	struct addrinfo *ai, *res;
	struct addr_list_head lhead;
	int count4 = 0, count6 = 0, ifcount = 0, ncount = 0, uncount = 0;

	table->used++;

	if (table->resolved)
		return;

	_debug("Resolving table %d (%s)", table->number, table->name);

	STAILQ_INIT(&lhead);

	STAILQ_FOREACH_SAFE(l, &table->addrs_head, next, l_tmp) {
		switch (l->addr_type) {
		case ADDR_NUMBER:
			STAILQ_INSERT_HEAD(&lhead, l, next);
			ncount++;
			break;
		case ADDR_ME:
		case ADDR_ME6:
			yyerror("resolve_table(): me");
		case ADDR_IPV4:
			STAILQ_INSERT_HEAD(&lhead, l, next);
			count4++;
			break;
		case ADDR_IPV6:
			STAILQ_INSERT_HEAD(&lhead, l, next);
			count6++;
			break;
		case ADDR_IFACE:
			STAILQ_INSERT_HEAD(&lhead, l, next);
			ifcount++;
			break;
		case ADDR_HOSTNAME:
			/* We have to resolve all hosts */

			if ((res = y_gethostbyname(l->hostname)) == NULL) {
				if(!ignore_unresolved) {
					if (only_test) {
						yywarning("can't resolve host: %s", l->hostname);
						break;
					} else 
						yyerror("can't resolve host: %s", l->hostname);
				} else {
					printf("Line %d: can't resolve host: %s. Ignored.\n", l->line, l->hostname);
					continue;
				}
			}

			_debug("domain:%s ", l->hostname);

			for(ai = res; ai != NULL; ai = ai->ai_next) {
				struct addr_list *ip_entry = calloc_wait(1, sizeof(struct addr_list));
				ip_entry->is_not = l->is_not;
				ip_entry->label = l->label;

				if(ai->ai_family == AF_INET6) {
					ip_entry->masklen = 128;
					ip_entry->is_not = l->is_not;
					ip_entry->addr_type = ADDR_IPV6;
					ip_entry->ip6 = ((struct sockaddr_in6*)ai->ai_addr)->sin6_addr;

					count6++;
				} else {
					ip_entry->masklen = 32;
					ip_entry->ip = ((struct sockaddr_in*)ai->ai_addr)->sin_addr.s_addr;
					ip_entry->addr_type = ADDR_IPV4;
					count4++;
				}
				STAILQ_INSERT_HEAD(&lhead, ip_entry, next);
/*
				char data[64];
				inet_ntop(ai->ai_family, addr_data, data, sizeof(data));

				printf("table %s host %s resolved to %s\n", table->name, l->hostname, data);
*/
			}

			break;
		case ADDR_IPV4MASK:
		case ADDR_IPV6MASK:
		case ADDR_TABLE:
			uncount++;
			break;
#if 0
			t = find_table_idx(l->mask);
			if (t == NULL)
				yyerror("Unresolved non-nested table number %d", l->kidx);

			if (!t->used) {
				_debug("Recurse resolving table %s", t->name);
				resolve_table(t, depth + 1);
			}

			_debug("Including table %s in table %s", t->name, table->name);

			STAILQ_FOREACH(xe, &t->compiled_head, next) {
				xe_tmp = malloc(sizeof(struct table_xentry));
				memcpy(xe_tmp, xe, sizeof(struct table_xentry));
				xe_tmp->xentry.tbl = table->number;
				STAILQ_INSERT_TAIL(&table->compiled_head, xe_tmp, next);
			}

			count4 += t->count4;
			count6 += t->count6;
			break;
#endif
		}
	}

	/* XXX: Yes, we're dropping all 'hostname' records */
	STAILQ_SWAP(&table->addrs_head, &lhead, addr_list);

	_debug("%d v4 hosts, %d v6 hosts in table %s (unaccounted %d)\n",
	    count4, count6, table->name, uncount);

	table->count4 = count4;
	table->count6 = count6;
	table->ifcount = ifcount;
	table->ncount = ncount;

	/* Mark as resolved */
	table->resolved = 1;
}

void
resolve_table(struct table *t)
{

	return (resolve_table_internal(t, 0));
}

static void
cmd_mac_lookup(int opcode, struct table *table, ipfw_insn_lookup *tparam) {


	ref_table(table);

	cmd->opcode = opcode;
	insntod(cmd, kidx)->kidx = table->kidx;
	if (tparam != NULL && IPFW_LOOKUP_MATCH_TVALUE(&tparam->o) != 0) {
		cmd->len = F_INSN_SIZE(ipfw_insn_table);
		cmd->arg1 = tparam->o.arg1;
		insntod(cmd, table)->value = tparam->u32;
	} else
		cmd->len = F_INSN_SIZE(ipfw_insn_kidx);

	HANDLE_NOT(cmd);
	cmd = next_cmd(cmd);
}

/* DUMMYNET3 support functions */
#define	DN(n)			((struct dn_##n *)dn_cmd)
#define	DN_NEXT(n, type, id)	dnext_cmd(sizeof(struct dn_##n), type, id)
#define	DN_COPY(n, type)	do {		\
	bcopy(&d##n, dn_cmd, sizeof(d##n));	\
	DN_NEXT(n, type, 0);			\
} while (0)
#define	DN_UNIQ(t, d)			\
if (dn_tokens & DN_TOKEN_##t)		\
	yyerror("Dublicate token %s", d);	\
else					\
	dn_tokens |= DN_TOKEN_##t

#define	DN_CONFLICT(t, d1, d2)		\
if (dn_tokens & DN_TOKEN_##t)		\
	yyerror("Mutually exclusive tokens: %s and %s", d1, d2)

#define	DN_TOKEN_BW		(1 << 0)
#define	DN_TOKEN_DELAY		(1 << 1)
#define	DN_TOKEN_BURST		(1 << 2)
#define	DN_TOKEN_BUCKETS	(1 << 3)
#define	DN_TOKEN_PIPE		(1 << 4)
#define	DN_TOKEN_TYPE		(1 << 5)
#define	DN_TOKEN_WEIGHT		(1 << 6)
#define	DN_TOKEN_LMAX		(1 << 7)
#define	DN_TOKEN_PRI		(1 << 8)
#define	DN_TOKEN_NOERROR	(1 << 9)
#define	DN_TOKEN_PLR		(1 << 10)
#define	DN_TOKEN_QUEUE		(1 << 11)
#define	DN_TOKEN_DROPTAIL	(1 << 12)
#define	DN_TOKEN_RED		(1 << 13)
#define	DN_TOKEN_MASK		(1 << 14)
#define	DN_TOKEN_DIP6MASK	(1 << 15)
#define	DN_TOKEN_SIP6MASK	(1 << 16)
#define	DN_TOKEN_DIPMASK	(1 << 17)
#define	DN_TOKEN_SIPMASK	(1 << 18)
#define	DN_TOKEN_FIDMASK	(1 << 19)
#define	DN_TOKEN_DPORTMASK	(1 << 20)
#define	DN_TOKEN_SPORTMASK	(1 << 21)
#define	DN_TOKEN_QUEUEMASK	(1 << 22)
#define	DN_TOKEN_ALLMASK	(1 << 23)
#define	DN_TOKEN_PROTOMASK	(1 << 24)

static void *
dnext_cmd(int len, int type, uintptr_t id)
{
	struct dn_id *ret = DN(id);

	ret->len = len;
	ret->type = type;
	ret->subtype = 0;
	ret->id = id;

	dn_cmd += len;
	return (ret);
}

void
dummynet_init(void)
{
	unsigned int i;

	bzero(dbuf, sizeof(dbuf));
	bzero(&dmask, sizeof(dmask));
	bzero(&dsch, sizeof(dsch));
	bzero(&dfs, sizeof(dfs));
	for (i = 0; i < sizeof(dfs.par)/sizeof(dfs.par[0]); i++)
		dfs.par[i] = -1;
	bzero(&dlink, sizeof(dlink));
	bzero(&dprofile, sizeof(dprofile));
	dn_cmd = (char *)dbuf;
	dn_tokens = 0;
	dn_mask = 0;
	dn_plr = 0;
	DN_NEXT(id, DN_CMD_CONFIG, DN_API_VERSION);
}

static void
dummynet_init_limits(void)
{
	size_t len;

	if (pipe_byte_limit == -1) {
		len = sizeof(pipe_byte_limit);
		if (sysctlbyname("net.inet.ip.dummynet.pipe_byte_limit",
		    &pipe_byte_limit, &len, NULL, 0) == -1)
			pipe_byte_limit = 1024*1024;
	}
	if (pipe_slot_limit == -1) {
		len = sizeof(pipe_slot_limit);
		if (sysctlbyname("net.inet.ip.dummynet.pipe_slot_limit",
		    &pipe_slot_limit, &len, NULL, 0) == -1)
			pipe_slot_limit = 100;
	}
}

static void
dummynet_check_rule(void)
{

	SCHED_KLDLOAD(dummynet);
	dummynet_init_limits();

	if (dfs.flags & DN_QSIZE_BYTES) {
		if (dfs.qsize > pipe_byte_limit)
			yyerror("queue size must be < %ldB", pipe_byte_limit);
	} else if (dfs.qsize > pipe_slot_limit)
		yyerror("2 <= queue size <= %ld", pipe_slot_limit);
}

/* NAT support functions */
#define	NAT_UNIQ(t, d)				\
if (cn->mode & PKT_ALIAS_##t)			\
	yyerror("Dublicate token %s", d);	\
else						\
	cn->mode |= PKT_ALIAS_##t

void
nat_init(void)
{
	ipfw_obj_header *oh;

	bzero(nat_buf, sizeof(nat_buf));
	oh = (ipfw_obj_header *)nat_buf;
	cn = (struct nat44_cfg_nat *)(oh + 1);
	crdr = (struct nat44_cfg_redir *)(cn + 1);
	csp = (struct nat44_cfg_spool *)(crdr + 1);
	spool_cnt = 0;
	has_redirect = 0;

	oh->ntlv.head.length = sizeof(oh->ntlv);
}

static uint16_t
nat_parse_range(const char *s, uint16_t *lo)
{
	uint16_t hi;

	sscanf(s, "%hu-%hu", lo, &hi);
	if (*lo >= hi)
		yyerror("Wrong port range");
	return (hi - *lo + 1);
}

static uint16_t
nat_parse_sockaddr(const char *s, struct in_addr *a)
{
	uint16_t lo;
	char *p;

	p = strchr(s, ':');
	if (p == NULL)
		yyerror("Missing port number");
	*p++ = '\0';
	if (inet_aton(s, a) == 0)
		yyerror("Invalid IP address");
	lo = atoi(p);
	if (lo == 0)
		yyerror("Invalid port value");

	return (lo);
}

static void
set_addr_dynamic(const char *ifn, struct nat44_cfg_nat *n)
{
	size_t needed;
	int mib[6];
	char *buf, *lim, *next;
	struct if_msghdr *ifm;
	struct ifa_msghdr *ifam;
	struct sockaddr_dl *sdl;
	struct sockaddr_in *sin;
	int ifIndex;

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_INET;	
	mib[4] = NET_RT_IFLIST;
	mib[5] = 0;		
/*
 * Get interface data.
 */
	if (sysctl(mib, 6, NULL, &needed, NULL, 0) == -1)
		yyerror("iflist-sysctl-estimate");
	buf = malloc_wait(needed);
	if (sysctl(mib, 6, buf, &needed, NULL, 0) == -1)
		yyerror("iflist-sysctl-get");
	lim = buf + needed;
/*
 * Loop through interfaces until one with
 * given name is found. This is done to
 * find correct interface index for routing
 * message processing.
 */
	ifIndex	= 0;
	next = buf;
	while (next < lim) {
		ifm = (struct if_msghdr *)next;
		next += ifm->ifm_msglen;
		if (ifm->ifm_version != RTM_VERSION) {
			if (!quiet)
				yywarning("routing message version %d "
				    "not understood", ifm->ifm_version);
			continue;
		}
		if (ifm->ifm_type == RTM_IFINFO) {
			sdl = (struct sockaddr_dl *)(ifm + 1);
			if (strlen(ifn) == sdl->sdl_nlen &&
			    strncmp(ifn, sdl->sdl_data, sdl->sdl_nlen) == 0) {
				ifIndex = ifm->ifm_index;
				break;
			}
		}
	}
	if (!ifIndex)
		yyerror("unknown interface name %s", ifn);
	/*
	 * Get interface address.
	 */
	sin = NULL;
	while (next < lim) {
		ifam = (struct ifa_msghdr *)next;
		next += ifam->ifam_msglen;
		if (ifam->ifam_version != RTM_VERSION) {
			if (!quiet)
				yywarning("routing message version %d "
				    "not understood", ifam->ifam_version);
			continue;
		}
		if (ifam->ifam_type != RTM_NEWADDR)
			break;
		if (ifam->ifam_addrs & RTA_IFA) {
			int i;
			char *cp = (char *)(ifam + 1);

			for (i = 1; i < RTA_IFA; i <<= 1) {
				if (ifam->ifam_addrs & i)
					cp += SA_SIZE((struct sockaddr *)cp);
			}
			if (((struct sockaddr *)cp)->sa_family == AF_INET) {
				sin = (struct sockaddr_in *)cp;
				break;
			}
		}
	}
	if (sin == NULL)
		yyerror("%s: cannot get interface address", ifn);

	n->ip = sin->sin_addr;
	strncpy(n->if_name, ifn, IF_NAMESIZE);

	free(buf);
}

/* NPTv6 support functions */
#define	NPTV6_CONFIGURE(t)			\
    nptv6_tokens |= NPTV6_TOKEN_##t

#define	NPTV6_HAS_CONFIG(t)			\
    ((nptv6_tokens & NPTV6_TOKEN_##t) == NPTV6_TOKEN_##t)

#define	NPTV6_UNIQ(t, d)			\
if (nptv6_tokens & NPTV6_TOKEN_##t)		\
	yyerror("Dublicate token %s", d);	\
else						\
	NPTV6_CONFIGURE(t)

#define	NPTV6_TOKEN_INTPREFIX		(1 << 0)
#define	NPTV6_TOKEN_EXTPREFIX		(1 << 1)
#define	NPTV6_TOKEN_PFXLEN		(1 << 2)
#define	NPTV6_TOKEN_ALL			(NPTV6_TOKEN_INTPREFIX | \
    NPTV6_TOKEN_EXTPREFIX | NPTV6_TOKEN_PFXLEN)

void
nptv6_init(void)
{
	ipfw_obj_lheader *olh;

	nptv6_tokens = 0;
	bzero(nptv6_buf, sizeof(nptv6_buf));

	olh = (ipfw_obj_lheader *)nptv6_buf;
	olh->count = 1;
	olh->objsize = sizeof(ipfw_nptv6_cfg);
	olh->size = sizeof(nptv6_buf);
	nptv6_cfg = (ipfw_nptv6_cfg *)(olh + 1);
	nptv6_cfg->set = TMP_SET_NUM;
}

static void
nptv6_check_config(void)
{
	struct in6_addr mask;

	if (!NPTV6_HAS_CONFIG(INTPREFIX))
		yyerror("NPTv6 instance %s: int_prefix required",
		    nptv6_cfg->name);
	if (!NPTV6_HAS_CONFIG(EXTPREFIX))
		yyerror("NPTv6 instance %s: ext_prefix required",
		    nptv6_cfg->name);
	if (!NPTV6_HAS_CONFIG(PFXLEN))
		yyerror("NPTv6 instance %s: prefixlen required",
		    nptv6_cfg->name);

	n2mask(&mask, nptv6_cfg->plen);
	APPLY_MASK(&nptv6_cfg->internal, &mask);
	APPLY_MASK(&nptv6_cfg->external, &mask);
}

/* NAT64 support functions */
#define	NAT64_CONFIGURE(type, t)		\
    nat64##type##_tokens |= NAT64##type##_TOKEN_##t

#define	NAT64_HAS_CONFIG(type, t)			\
    ((nat64##type##_tokens & NAT64##type##_TOKEN_##t) == \
	NAT64##type##_TOKEN_##t)

#define	NAT64_UNIQ(type, t, d)			\
if (nat64##type##_tokens & NAT64##type##_TOKEN_##t)		\
	yyerror("Dublicate token %s", d);	\
else						\
	NAT64_CONFIGURE(type, t)

#define	NAT64CLAT_TOKEN_CLATPFX		(1 << 0)
#define	NAT64CLAT_TOKEN_PLATPFX		(1 << 1)

#define	NAT64LSN_TOKEN_PFX4		(1 << 0)
#define	NAT64LSN_TOKEN_PFX6		(1 << 1)

#define	NAT64STL_TOKEN_TBL4		(1 << 0)
#define	NAT64STL_TOKEN_TBL6		(1 << 1)
#define	NAT64STL_TOKEN_PFX6		(1 << 2)

/* Define some constants in case they are not defined */
#ifndef NAT64_LOG
#define	NAT64_LOG		0x0001
#define	NAT64_ALLOW_PRIVATE	0x0002
#endif
#ifndef NAT64LSN_ALLOW_SWAPCONF
#define	NAT64LSN_ALLOW_SWAPCONF	0x0004
#endif
#ifndef NAT64LSN_MAX_PORTS
#define	NAT64LSN_MAX_PORTS	2048	/* Max number of ports per host */
#define	NAT64LSN_JMAXLEN	2048	/* Max outstanding requests. */
#define	NAT64LSN_TCP_SYN_AGE	30	/* State's TTL after SYN received. */
#define	NAT64LSN_TCP_EST_AGE	(4 * 3600) /* TTL for established connection */
#define	NAT64LSN_TCP_FIN_AGE	180	/* State's TTL after FIN/RST received */
#define	NAT64LSN_UDP_AGE	15	/* TTL for UDP states */
#define	NAT64LSN_ICMP_AGE	15	/* TTL for ICMP states */
#define	NAT64LSN_HOST_AGE	120	/* TTL for stale host entry */
#define	NAT64LSN_PG_AGE		300	/* TTL for stale ports groups */
#endif

#define	IPV6_ADDR_INT32_WKPFX	htonl(0x64ff9b)
#define	IN6_IS_ADDR_WKPFX(a)					\
    ((a)->__u6_addr.__u6_addr32[0] == IPV6_ADDR_INT32_WKPFX &&	\
	(a)->__u6_addr.__u6_addr32[1] == 0 &&			\
	(a)->__u6_addr.__u6_addr32[2] == 0)
static int
nat64_check_prefix6(const struct in6_addr *prefix, int length)
{

	switch (length) {
	case 32:
	case 40:
	case 48:
	case 56:
	case 64:
		/* Well-known prefix has 96 prefix length */
		if (IN6_IS_ADDR_WKPFX(prefix))
			return (EINVAL);
		/* FALLTHROUGH */
	case 96:
		/* Bits 64 to 71 must be set to zero */
		if (prefix->__u6_addr.__u6_addr8[8] != 0)
			return (EINVAL);
		/* XXX: looks incorrect */
		if (IN6_IS_ADDR_MULTICAST(prefix) ||
		    IN6_IS_ADDR_UNSPECIFIED(prefix) ||
		    IN6_IS_ADDR_LOOPBACK(prefix))
			return (EINVAL);
		return (0);
	}
	return (EINVAL);
}

static void
nat64lsn_init(void)
{
	ipfw_obj_lheader *olh;

	nat64LSN_tokens = 0;
	bzero(nat64lsn_buf, sizeof(nat64lsn_buf));

	olh = (ipfw_obj_lheader *)nat64lsn_buf;
	olh->count = 1;
	olh->objsize = sizeof(ipfw_nat64lsn_cfg);
	olh->size = sizeof(nat64lsn_buf);
	nat64lsn_cfg = (ipfw_nat64lsn_cfg *)(olh + 1);

	/* Some reasonable defaults */
	inet_pton(AF_INET6, "64:ff9b::", &nat64lsn_cfg->prefix6);
	nat64lsn_cfg->plen6 = 96;
	nat64lsn_cfg->set = TMP_SET_NUM;
	nat64lsn_cfg->max_ports = NAT64LSN_MAX_PORTS;
	nat64lsn_cfg->jmaxlen = NAT64LSN_JMAXLEN;
	nat64lsn_cfg->nh_delete_delay = NAT64LSN_HOST_AGE;
	nat64lsn_cfg->pg_delete_delay = NAT64LSN_PG_AGE;
	nat64lsn_cfg->st_syn_ttl = NAT64LSN_TCP_SYN_AGE;
	nat64lsn_cfg->st_estab_ttl = NAT64LSN_TCP_EST_AGE;
	nat64lsn_cfg->st_close_ttl = NAT64LSN_TCP_FIN_AGE;
	nat64lsn_cfg->st_udp_ttl = NAT64LSN_UDP_AGE;
	nat64lsn_cfg->st_icmp_ttl = NAT64LSN_ICMP_AGE;
	nat64lsn_cfg->states_chunks = 16;
	nat64lsn_cfg->flags |= NAT64LSN_ALLOW_SWAPCONF;
}

void
nat64stl_init(void)
{
	ipfw_obj_lheader *olh;

	nat64STL_tokens = 0;
	bzero(nat64stl_buf, sizeof(nat64stl_buf));

	olh = (ipfw_obj_lheader *)nat64stl_buf;
	olh->count = 1;
	olh->objsize = sizeof(ipfw_nat64stl_cfg);
	olh->size = sizeof(nat64stl_buf);
	nat64stl_cfg = (ipfw_nat64stl_cfg *)(olh + 1);

	/* Some reasonable defaults */
	inet_pton(AF_INET6, "64:ff9b::", &nat64stl_cfg->prefix6);
	nat64stl_cfg->plen6 = 96;
	nat64stl_cfg->set = TMP_SET_NUM;
}

void
nat64clat_init(void)
{
	ipfw_obj_lheader *olh;

	nat64CLAT_tokens = 0;
	bzero(nat64clat_buf, sizeof(nat64clat_buf));

	olh = (ipfw_obj_lheader *)nat64clat_buf;
	olh->count = 1;
	olh->objsize = sizeof(ipfw_nat64clat_cfg);
	olh->size = sizeof(nat64clat_buf);
	nat64clat_cfg = (ipfw_nat64clat_cfg *)(olh + 1);

	/* Some reasonable defaults */
	inet_pton(AF_INET6, "64:ff9b::", &nat64clat_cfg->plat_prefix);
	nat64clat_cfg->plat_plen = 96;
	nat64clat_cfg->set = TMP_SET_NUM;
}

void
nat64_init(void)
{

	nat64lsn_init();
	nat64stl_init();
	nat64clat_init();
}

static void
nat64clat_check_config(void)
{

	if (!NAT64_HAS_CONFIG(CLAT, CLATPFX))
		yyerror("NAT64CLAT instance %s: clat_prefix required",
		    nat64clat_cfg->name);
}

static void
nat64lsn_check_config(void)
{

	if (!NAT64_HAS_CONFIG(LSN, PFX4))
		yyerror("NAT64LSN instance %s: prefix4 required",
		    nat64lsn_cfg->name);
}

static void
nat64stl_check_config(void)
{

	if (!NAT64_HAS_CONFIG(STL, TBL4))
		yyerror("NAT64STL instance %s: table4 required",
		    nat64stl_cfg->name);
	if (!NAT64_HAS_CONFIG(STL, TBL6))
		yyerror("NAT64STL instance %s: table6 required",
		    nat64stl_cfg->name);
}

static void
nat64stl_set_table(char *tablename, int v)
{
	struct table *table;

	table = get_table(tablename, 0, O_SYNC);

	nat64stl_fill_table(v == 4 ? &nat64stl_cfg->ntlv4:
	    &nat64stl_cfg->ntlv6, table->num_name, table->kidx);

}

#ifndef	IPFW_LOG_DEFAULT
#define	IPFW_LOG_DEFAULT	0x0000
#define	IPFW_LOG_SYSLOG		(1 << 15)
#define	IPFW_LOG_IPFW0		(1 << 14)
#define	IPFW_LOG_RTSOCK		(1 << 13)
#endif

static uint16_t
parse_logdst(char *token)
{

	if (strcmp(token, "syslog") == 0) {
		return IPFW_LOG_SYSLOG;
	}
	if (strcmp(token, "ipfw0") == 0) {
		/* XXX add multiple ipfw* */
		return IPFW_LOG_IPFW0;
	}
	if (strcmp(token, "rtsock") == 0) {
		return IPFW_LOG_RTSOCK;
	}
	yyerror("unsupported logdst token '%s'", token);
	return (IPFW_LOG_DEFAULT);
}

static void
check_ipv4_prefixlen(int len)
{
	if (len < 0 || len > 32)
		yyerror("Wrong IPv4 prefix length: %d", len);
}

static void
check_ipv6_prefixlen(int len)
{
	if (len < 0 || len > 128)
		yyerror("Wrong IPv6 prefix length: %d", len);
}

%}

%start commands

%token ACK ADD ALL ALLOW ANTISPOOF ANY BW BWBS BWBTS BWKBS BWKBTS BWMBS BWMBTS
       BUCKETS CC CHECKSTATE COMMA CONFIG CONGESTION COUNT PDELAY DENY DENY_IN
       DROPTAIL DSTADDR DSTIP DSTPORT EBRACE EOL ESTABLISHED FIN FILTERPROHIB
       FLOAT FLOWID FQDN FRAG FROM FWD HOST HOSTUNKNOWN HOSTPROHIB
       HOSTPRECEDENCE ICMPTYPES ICMP6TYPES IN IF IP IP6 DIVERT TEE DIVERTED
       DIVERTEDLOOPBACK DIVERTEDOUTPUT ALTQ SETIPPREC IPLEN IPOPTIONS IPTOS
       IPTTL ISOLATED KEEPSTATE LBRACE LIMIT LOG LOGAMOUNT LOWDELAY LSRR MASK
       ME ME6 MINCOST MSS NAT NEEDFRAG NET NETGRAPH NETPROHIB NETWORK NETWORK6
       NETUNKNOWN T_IP NOERROR NOT NOTCHAR NUMBER OBRACE OR OUT PIPE PLR PORT
       PRECEDENCECUTOFF PROTO PROXY_ONLY PSH QUEUE RANGE RBRACE RECV
       REASS RED REDPARAM REDIRECT_ADDR REDIRECT_PORT REDIRECT_PROTO REJECTT
       RELIABILITY RESET REVERSE RR RST SACK SAME_PORTS SETUP SIZEK SKIPTO
       SRCADDR SRCFAIL SRCIP SRCPORT SSRR SYN TABLE TAG TCPDATALEN TCPFLAGS
       TCPOPTIONS TCPSEQ THROUGHPUT TO TOKEN TOSHOST TOSNET TS UNREACH UNREACH6
       UNREG_ONLY URG VIA VERREVPATH VERSRCREACH WEIGHT WINDOW XMIT LABEL
       EXT6HDR HOPOPT ROUTE DSTOPT AH ESP RTHDR0 RTHDR2 IPSEC IPVER COMMENT
       TABLENAME T_IP4 T_IP6 LMAX SCHED FLOWMASK LINK PRIORITY TYPE DSTIP6
       SRCIP6 PROFILE BURST SCHEDMASK MASKLEN SETDSCP DSCP DSCPSPEC SKIP_GLOBAL
       GLOBAL SOCKADDR4 MINUS TAGGED UNTAG IPID TCPWIN IPMASK CREATE ADDR IFACE
       TABLEARG NAT64LSN NAT64STL IP6SCOPIED NPTV6 INT_PREFIX EXT_PREFIX
       PREFIXLEN PREFIX4 PREFIX6 AGG_LEN AGG_COUNT MAX_PORTS STATES_CHUNKS JMAXLEN
       PORT_RANGE NH_DEL_AGE PG_DEL_AGE TCP_SYN_AGE TCP_EST_AGE TCP_CLOSE_AGE
       UDP_AGE ICMP_AGE TABLE4 TABLE6 IP6MASK CALL RETURN
       RESET6 TCPSETMSS SETFIB VALTYPE FIB IPV4 IPV6 NAT64CLAT ALLOW_PRIVATE
       CLAT_PREFIX PLAT_PREFIX SWAP_CONF TCPMSS JAIL MF DF RF OFFSET LAYER2
       MAC MACADDR SRCMAC DSTMAC TOK_NUMBER FLOW ALGO ALGO_NAME LOOKUP UID RULENUM
       NH4 NH6 EQUAL LOGDST MARK SETMARK DSTIP4 SRCIP4
       NUMBERCOLON TABLEARGCOLON
       DSTPORTCOLON SRCPORTCOLON UIDCOLON JAILCOLON DSCPCOLON RULENUMCOLON
       MARKCOLON DSTIP4COLON SRCIP4COLON DSTIP6COLON SRCIP6COLON DSTMACCOLON
       SRCMACCOLON

// QUEUE could be an argument to *MASK
%nonassoc QUEUE
%nonassoc MASK FLOWMASK SCHEDMASK

%union {
#define MAX_TOKEN	1024
	long		ival;
	float		fval;
	char		sval[MAX_TOKEN];
};

%%

commands: 
	| commands command
	;
command:
	LABEL EOL
	{
		if (has_a_label)
			yyerror("Two labels at the same line: '%s' after '%s'", $1.sval, has_a_label);

		if (get_label_number($1.sval) != 0)
			yyerror("Dublicate label '%s'", $1.sval);

		has_a_label = strdup_wait($1.sval);
	}
	|
	nat
	{
		ipfw_obj_header *oh;
		size_t nat_len;

		nat_len = has_redirect ?  (char *)csp - nat_buf :
		    sizeof(ipfw_obj_header) + sizeof(*cn);
		nat_rules[nat_count].len = nat_len;
		nat_rules[nat_count].rule = malloc_wait(
		    nat_rules[nat_count].len);

		oh = (ipfw_obj_header *)nat_buf;
		strncpy(oh->ntlv.name, cn->name, sizeof(oh->ntlv.name));
		bcopy(nat_buf, nat_rules[nat_count].rule, nat_len);

		nat_count++;
		nat_init();
	}
	|
	pipequeue
	{
		dummynet_rules[dummynet_count].len = dn_cmd - dbuf;
		dummynet_rules[dummynet_count].rule = malloc_wait(dn_cmd - dbuf);
		bcopy(dbuf, dummynet_rules[dummynet_count].rule, dn_cmd - dbuf);
		dummynet_count++;
		dummynet_init();
	}
	|
	table
	|
	add
	{
		if(debug) {
			fprintf(stderr, "ADD RULE #%d ", rule->rulenum);
			switch(action_opcode)
			{
				case O_ACCEPT:	
						fprintf(stderr, "allow ");
						break;
				case O_DENY:	
						fprintf(stderr, "deny ");
						break;
				case O_REJECT:	
						fprintf(stderr, "reject ");
						break;
				case O_FORWARD_IP:	
						fprintf(stderr, "fwd ");
						break;
				case O_SKIPTO:	
						fprintf(stderr, "skipto ");
						break;
				case O_CALLRETURN:
						fprintf(stderr, "call/ret ");
						break;
				case O_COUNT:	
						fprintf(stderr, "count ");
						break;
				case O_CHECK_STATE: 
						fprintf(stderr, "check-state ");
						break;
				case O_EXTERNAL_ACTION:
						fprintf(stderr, "eaction ");
						break;
			};
		}

		rule->set = TMP_SET_NUM;
		int i=0;
		dst = (ipfw_insn *)rule->cmd;

		/* If there is keep-state, set PROBE_STATE as the first command */
		if (have_state && have_state->opcode != O_CHECK_STATE) {
			dst->opcode = O_PROBE_STATE;
			dst->len = F_INSN_SIZE(ipfw_insn_kidx);
			insntod(dst, kidx)->kidx =
			    insntod(have_state, kidx)->kidx;
			dst = next_cmd(dst);
		}

		for (src = (ipfw_insn *)cmdbuf; src != cmd; src += i) {
			i = F_LEN(src);
			if (src + i - (ipfw_insn *)cmdbuf > (long)nitems(cmdbuf))
				yyerror("Too many opcodes (line %u).", line);
			switch (src->opcode) {
				case O_LOG:
				case O_KEEP_STATE:
				case O_LIMIT:
				case O_ALTQ:
				case O_TAG:
					break;
				default:
					bcopy(src, dst, i * sizeof(ipfw_insn));
					dst += i;
			}
		}

		if (have_state && have_state->opcode != O_CHECK_STATE) {
			i = F_LEN(have_state);
			bcopy(have_state, dst, i * sizeof(ipfw_insn));
			dst += i;
		}

		/* we copied cmd, action then */
		rule->act_ofs = dst - rule->cmd;
		/* LOG first if is */
		if (have_log) {
			i = F_LEN(have_log);
			bcopy(have_log, dst, i * sizeof(ipfw_insn));
			dst += i;
		}
		if (have_altq) {
			i = F_LEN(have_altq);
			bcopy(have_altq, dst, i * sizeof(ipfw_insn));
			dst += i;
		}
		if (have_tag) {
			i = F_LEN(have_tag);
			bcopy(have_tag, dst, i * sizeof(ipfw_insn));
			dst += i;
		}

		for (src = (ipfw_insn *)actbuf; src != action; src += i) {
			i = F_LEN(src);
			if (src + i - (ipfw_insn *)actbuf > (long)nitems(actbuf))
				yyerror("Too many opcodes (line %u).", line);
			bcopy(src, dst, i * sizeof(ipfw_insn));
			if (src == action_label_insn)
				action_label_insn = dst;
			dst += i;
		}

		rule->cmd_len = dst - rule->cmd;
		action_label_offset = action_label_insn - rule->cmd - rule->act_ofs;

		if (!empty_rule) {
			add_rule(rule);
		} else {
			if (debug)
				fprintf(stderr, "EMPTY RULE\n");
		}

		free(action_label);
		action_label = NULL;
		if(debug)
			fprintf(stderr, " next line: %d\n",line);
	}
	|
	NPTV6 TOKEN CREATE
	{
		SCHED_KLDLOAD(ipfw_nptv6);
	}
	nptv6config EOL
	{
		check_object_name($2.sval);
		strlcpy(nptv6_cfg->name, $2.sval, sizeof(nptv6_cfg->name));

		nptv6_check_config();
		nptv6_rules[nptv6_count].len = sizeof(nptv6_buf);
		nptv6_rules[nptv6_count].rule = malloc_wait(sizeof(nptv6_buf));
		bcopy(nptv6_buf, nptv6_rules[nptv6_count].rule,
		    sizeof(nptv6_buf));
		nptv6_count++;
		nptv6_init();
	}
	|
	NAT64LSN TOKEN CREATE
	{
		SCHED_KLDLOAD(ipfw_nat64);
	}
	nat64lsn_config EOL
	{
		check_object_name($2.sval);
		strlcpy(nat64lsn_cfg->name, $2.sval,
		    sizeof(nat64lsn_cfg->name));

		nat64lsn_check_config();
		nat64lsn_rules[nat64lsn_count].len = sizeof(nat64lsn_buf);
		nat64lsn_rules[nat64lsn_count].rule =
		    malloc_wait(sizeof(nat64lsn_buf));
		bcopy(nat64lsn_buf, nat64lsn_rules[nat64lsn_count].rule,
		    sizeof(nat64lsn_buf));
		nat64lsn_count++;
		nat64lsn_init();
	}
	|
	NAT64STL TOKEN CREATE
	{
		SCHED_KLDLOAD(ipfw_nat64);
	}
	nat64stl_config EOL
	{
		check_object_name($2.sval);
		strlcpy(nat64stl_cfg->name, $2.sval,
		    sizeof(nat64stl_cfg->name));

		nat64stl_check_config();
		nat64stl_rules[nat64stl_count].len = sizeof(nat64stl_buf);
		nat64stl_rules[nat64stl_count].rule =
		    malloc_wait(sizeof(nat64stl_buf));
		bcopy(nat64stl_buf, nat64stl_rules[nat64stl_count].rule,
		    sizeof(nat64stl_buf));
		nat64stl_count++;
		nat64stl_init();
	}
	|
	NAT64CLAT TOKEN CREATE
	{
		SCHED_KLDLOAD(ipfw_nat64);
	}
	nat64clat_config EOL
	{
		check_object_name($2.sval);
		strlcpy(nat64clat_cfg->name, $2.sval,
		    sizeof(nat64clat_cfg->name));

		nat64clat_check_config();
		nat64clat_rules[nat64clat_count].len = sizeof(nat64clat_buf);
		nat64clat_rules[nat64clat_count].rule =
		    malloc_wait(sizeof(nat64clat_buf));
		bcopy(nat64clat_buf, nat64clat_rules[nat64clat_count].rule,
		    sizeof(nat64clat_buf));
		nat64clat_count++;
		nat64clat_init();
	}
	;
nat64clat_config:
	nat64clat_token
	|
	nat64clat_config nat64clat_token
	;
nat64clat_token:
	CLAT_PREFIX NETWORK6
	{
		char *mask;
		int plen;

		NAT64_UNIQ(CLAT, CLATPFX, $1.sval);
		mask = strchr($2.sval, '/');
		*mask = 0;
		mask++;
		check_ipv6_prefixlen(plen = atoi(mask));

		inet_pton(AF_INET6, $2.sval, &nat64clat_cfg->clat_prefix);
		if (nat64_check_prefix6(&nat64clat_cfg->clat_prefix,
		    plen) != 0)
			yyerror("NAT64CLAT: bad clat_prefix %s/%d",
			    $2.sval, plen);
		nat64clat_cfg->clat_plen = plen;
		NAT64_CONFIGURE(CLAT, CLATPFX);
	}
	|
	PLAT_PREFIX NETWORK6
	{
		char *mask;
		int plen;

		NAT64_UNIQ(CLAT, PLATPFX, $1.sval);
		mask = strchr($2.sval, '/');
		*mask = 0;
		mask++;
		check_ipv6_prefixlen(plen = atoi(mask));

		inet_pton(AF_INET6, $2.sval, &nat64clat_cfg->plat_prefix);
		if (nat64_check_prefix6(&nat64clat_cfg->plat_prefix,
		    plen) != 0)
			yyerror("NAT64CLAT: bad plat_prefix %s/%d",
			    $2.sval, plen);
		nat64clat_cfg->plat_plen = plen;
		NAT64_CONFIGURE(CLAT, PLATPFX);
	}
	|
	ALLOW_PRIVATE	{ nat64clat_cfg->flags |= NAT64_ALLOW_PRIVATE; }
	|
	LOG		{ nat64clat_cfg->flags |= NAT64_LOG; }
	;
nat64stl_config:
	nat64stl_token
	|
	nat64stl_config nat64stl_token
	;
nat64stl_token:
	TABLE4 TABLENAME
	{
		NAT64_UNIQ(STL, TBL4, $1.sval);
		nat64stl_set_table($2.sval, 4);
		NAT64_CONFIGURE(STL, TBL4);
	}
	|
	TABLE6 TABLENAME
	{
		NAT64_UNIQ(STL, TBL6, $1.sval);
		nat64stl_set_table($2.sval, 6);
		NAT64_CONFIGURE(STL, TBL6);
	}
	|
	PREFIX6 NETWORK6
	{
		char *mask;
		int plen;

		NAT64_UNIQ(STL, PFX6, $1.sval);
		mask = strchr($2.sval, '/');
		*mask = 0;
		mask++;
		check_ipv6_prefixlen(plen = atoi(mask));

		inet_pton(AF_INET6, $2.sval, &nat64stl_cfg->prefix6);
		if (nat64_check_prefix6(&nat64stl_cfg->prefix6, plen) != 0)
			yyerror("NAT64STL: bad prefix6 %s/%d", $2.sval, plen);
		nat64stl_cfg->plen6 = plen;
		NAT64_CONFIGURE(STL, PFX6);
	}
	|
	ALLOW_PRIVATE	{ nat64stl_cfg->flags |= NAT64_ALLOW_PRIVATE; }
	|
	LOG		{ nat64stl_cfg->flags |= NAT64_LOG; }
	;
nat64lsn_config:
	nat64lsn_token
	|
	nat64lsn_config nat64lsn_token
	;
nat64lsn_token:
	PREFIX4 NETWORK
	{
		char *mask;
		int plen;

		NAT64_UNIQ(LSN, PFX4, $1.sval);
		mask = strchr($2.sval, '/');
		*mask = 0;
		mask++;
		plen = atoi(mask);

		if (plen < 1 || plen > 32)
			yyerror("NAT64LSN: bad prefix4 length %d", plen);
		nat64lsn_cfg->plen4 = plen;
		nat64lsn_cfg->prefix4.s_addr = get_ip($2.sval);
		NAT64_CONFIGURE(LSN, PFX4);
	}
	|
	PREFIX6 NETWORK6
	{
		char *mask;
		int plen;

		NAT64_UNIQ(LSN, PFX6, $1.sval);
		mask = strchr($2.sval, '/');
		*mask = 0;
		mask++;
		check_ipv6_prefixlen(plen = atoi(mask));

		inet_pton(AF_INET6, $2.sval, &nat64lsn_cfg->prefix6);
		if (nat64_check_prefix6(&nat64lsn_cfg->prefix6, plen) != 0 &&
		    !IN6_IS_ADDR_UNSPECIFIED(&nat64lsn_cfg->prefix6))
			yyerror("NAT64LSN: bad prefix6 %s/%d", $2.sval, plen);
		nat64lsn_cfg->plen6 = plen;
		NAT64_CONFIGURE(LSN, PFX6);
	}
	|
	AGG_LEN NUMBER { /* ignore */ }
	|
	AGG_COUNT NUMBER { /* ignore */ }
	|
	PORT_RANGE NUMBER { /* ignore */ }
	|
	PORT_RANGE NUMBER ':' NUMBER { /* ignore */ }
	|
	MAX_PORTS NUMBER { nat64lsn_cfg->max_ports = $2.ival; }
	|
	STATES_CHUNKS NUMBER { nat64lsn_cfg->states_chunks = $2.ival; }
	|
	JMAXLEN NUMBER { nat64lsn_cfg->jmaxlen = $2.ival; }
	|
	NH_DEL_AGE NUMBER { nat64lsn_cfg->nh_delete_delay = $2.ival; }
	|
	PG_DEL_AGE NUMBER { nat64lsn_cfg->pg_delete_delay = $2.ival; }
	|
	TCP_SYN_AGE NUMBER { nat64lsn_cfg->st_syn_ttl = $2.ival; }
	|
	TCP_EST_AGE NUMBER { nat64lsn_cfg->st_estab_ttl = $2.ival; }
	|
	TCP_CLOSE_AGE NUMBER { nat64lsn_cfg->st_close_ttl = $2.ival; }
	|
	UDP_AGE NUMBER { nat64lsn_cfg->st_udp_ttl = $2.ival; }
	|
	ICMP_AGE NUMBER { nat64lsn_cfg->st_icmp_ttl = $2.ival; }
	|
	LOG { nat64lsn_cfg->flags |= NAT64_LOG; }
	|
	ALLOW_PRIVATE { nat64lsn_cfg->flags |= NAT64_ALLOW_PRIVATE; }
	|
	SWAP_CONF { nat64lsn_cfg->flags |= NAT64LSN_ALLOW_SWAPCONF; }
	;
nptv6config:
	nptv6token
	|
	nptv6config nptv6token
	;
nptv6token:
	INT_PREFIX NETWORK6
	{
		char *mask;
		int plen;

		NPTV6_UNIQ(INTPREFIX, $1.sval);

		mask = strchr($2.sval, '/');
		*mask = 0;
		mask++;
		plen = atoi(mask);

		if (plen < 8 || plen > 64)
			yyerror("NPTv6: bad prefixlen %d", plen);
		if (NPTV6_HAS_CONFIG(PFXLEN) &&
		    nptv6_cfg->plen != plen)
			yyerror("NPTv6: prefixes must have equal prefixlen");
		else
			nptv6_cfg->plen = plen;
		nptv6_cfg->internal = get_ip6($2.sval);
		NPTV6_CONFIGURE(PFXLEN);
	}
	|
	INT_PREFIX IP6
	{
		NPTV6_UNIQ(INTPREFIX, $1.sval);
		nptv6_cfg->internal = get_ip6($2.sval);
	}
	|
	EXT_PREFIX NETWORK6
	{
		char *mask;
		int plen;

		NPTV6_UNIQ(EXTPREFIX, $1.sval);
		mask = strchr($2.sval, '/');
		*mask = 0;
		mask++;
		plen = atoi(mask);

		if (plen < 8 || plen > 64)
			yyerror("NPTv6: bad prefixlen %d", plen);
		if (NPTV6_HAS_CONFIG(PFXLEN) &&
		    nptv6_cfg->plen != plen)
			yyerror("NPTv6: prefixes must have equal prefixlen");
		else
			nptv6_cfg->plen = plen;
		nptv6_cfg->external = get_ip6($2.sval);
		NPTV6_CONFIGURE(PFXLEN);
	}
	|
	EXT_PREFIX IP6
	{
		NPTV6_UNIQ(EXTPREFIX, $1.sval);
		nptv6_cfg->external = get_ip6($2.sval);
	}
	|
	PREFIXLEN NUMBER
	{
		if ($2.ival < 8 || $2.ival > 64)
			yyerror("NPTv6: bad prefixlen %d", $2.ival);
		if (NPTV6_HAS_CONFIG(PFXLEN) &&
		    nptv6_cfg->plen != $2.ival)
			yyerror("NPTv6: prefixes must have equal prefixlen");
		else
			nptv6_cfg->plen = $2.ival;
		NPTV6_CONFIGURE(PFXLEN);
	}
	;
add:
	ADD rulenumber action rule comment EOL
	|
	ADD rulenumber action actionmods rule comment EOL
	|
	ADD rulenumber checkstate EOL
	{
		have_state = action;
		action_opcode = action->opcode = O_CHECK_STATE;
		action->len = F_INSN_SIZE(ipfw_insn_kidx);
		action = next_cmd(action);
	}
	;
actionmods:
	actionmod
	|
	actionmods actionmod
	;
actionmod:
	tag
	|
	altq
	|
	log
	;
comment:
	COMMENT
	{
		char *p = (char *)(cmd + 1);
		cmd->opcode = O_NOP;
		cmd->len = 1 + (strlen($1.sval)+4)/4;
		strcpy(p, $1.sval);
		cmd = next_cmd(cmd);
	}
	|
	;
checkstate:
	CHECKSTATE
	{
		if (named_states == 0)
			insntod(action, kidx)->kidx = 0;
		else
			insntod(action, kidx)->kidx =
			    pack_object(&obj_state,
			    default_state_name, IPFW_TLV_STATE_NAME);
	}
	|
	CHECKSTATE LABEL
	{
		if (named_states == 0)
			yyerror("named_states are disabled");
		if (strcmp($2.sval, ":any") == 0)
			insntod(action, kidx)->kidx = 0;
		else
			insntod(action, kidx)->kidx =
			    pack_object(&obj_state, $2.sval + 1,
			    IPFW_TLV_STATE_NAME);
	}
	;
table:
	TABLE newtable ADD tablerec tableopts endtable EOL
	|
	createtable
	{
		if (curr_table->algo == NULL) {
			switch (curr_table->type) {
			case IPFW_TABLE_ADDR:
				curr_table->algo = strdup_wait("addr:radix"); break;
			case IPFW_TABLE_INTERFACE:
				curr_table->algo = strdup_wait("iface:array"); break;
			case IPFW_TABLE_FLOW:
				curr_table->algo = strdup_wait("flow:hash"); break;
			case IPFW_TABLE_NUMBER:
				curr_table->algo = strdup_wait("number:array"); break;
			}
		}
	}
	;
createtable:
	TABLE newtable CREATE EOL
	{
		table_tokens = 0;
		curr_table->type = IPFW_TABLE_ADDR;
		curr_table->vmask = IPFW_VTYPE_LEGACY;
	}
	|
	TABLE newtable CREATE defaulttableconfig tablespec EOL
	;
defaulttableconfig:
	{
		table_tokens = 0;
	}

newtable:
	tablenameornum
	{
		curr_addr_head = &curr_table->addrs_head;
	}
tablenameornum:
	TABLENAME
	{
		curr_table = get_table($1.sval, 0, O_CREAT);
	}
	|
	NUMBER
	{
		curr_table = get_table(NULL, $1.ival, O_CREAT);
	}
	;
endtable: { curr_addr_head = NULL; change_table(curr_table); curr_table = NULL; } ;

tablespec:
	tablespecopt
	|
	tablespec tablespecopt
	;
tablespecopt:
	tabletype
	{
		TABLE_UNIQ(TYPE, "type");
	}
	|
	VALTYPE tablevalmask
	{
		TABLE_UNIQ(VALTYPE, "valtype");
	}
	|
	ALGO ALGO_NAME
	{
		TABLE_UNIQ(ALGO, "algo");
		if (strcmp($2.sval, "number:array") != 0 &&
		    strcmp($2.sval, "iface:array") != 0 &&
		    strcmp($2.sval, "flow:hash") != 0 &&
		    strcmp($2.sval, "addr:radix") != 0)
			yyerror("Unsupported table algo '%s'", $2.sval);

		curr_table->algo = strdup_wait($2.sval);
	}
	;
tabletype:
	TYPE ADDR { curr_table->type = IPFW_TABLE_ADDR; }
	|
	TYPE IFACE { curr_table->type = IPFW_TABLE_INTERFACE; }
	|
	TYPE MAC { curr_table->type = IPFW_TABLE_MAC; }
	|
	TYPE TOK_NUMBER { curr_table->type = IPFW_TABLE_NUMBER; }
	|
	TYPE FLOW { curr_table->type = IPFW_TABLE_FLOW; }
	;

tablevalmask:
	tablevaluetype
	|
	tablevaluetype COMMA tablevalmask
	;

tablevaluetype:
	SKIPTO	{ curr_table->vmask |= IPFW_VTYPE_SKIPTO; }
	|
	PIPE	{ curr_table->vmask |= IPFW_VTYPE_PIPE; }
	|
	FIB	{ curr_table->vmask |= IPFW_VTYPE_FIB; }
	|
	NAT	{ curr_table->vmask |= IPFW_VTYPE_NAT; }
	|
	DSCP	{ curr_table->vmask |= IPFW_VTYPE_DSCP; }
	|
	TAG	{ curr_table->vmask |= IPFW_VTYPE_TAG; }
	|
	DIVERT	{ curr_table->vmask |= IPFW_VTYPE_DIVERT; }
	|
	NETGRAPH { curr_table->vmask |= IPFW_VTYPE_NETGRAPH; }
	|
	LIMIT	{ curr_table->vmask |= IPFW_VTYPE_LIMIT; }
	|
	MARK	{ curr_table->vmask |= IPFW_VTYPE_MARK; }
	|
	TOKEN
	{
		if (strcmp($1.sval, "ipv4") == 0)
			curr_table->vmask |= IPFW_VTYPE_NH4;
		else if (strcmp($1.sval, "ipv6") == 0)
			curr_table->vmask |= IPFW_VTYPE_NH6;
		else
			yyerror("Wrong value type %s", $1.sval);
	}
	;

tableopts:
	/* empty table value */
	|
	NUMBER
	{
		curr_addr_list->value = $1.ival;
	}
	|
	LABEL
	{
		curr_addr_list->label = strdup_wait($1.sval);
	}
	|
	IP
	{
		if ((curr_table->vmask & IPFW_VTYPE_NH4) == 0)
			yyerror("Wrong table value type: IP isn't expected");
		curr_addr_list->value_nh = get_ip($1.sval);
	}
	|
	IP6
	{
		if ((curr_table->vmask & IPFW_VTYPE_NH6) == 0)
			yyerror("Wrong table value type: IP isn't expected");
		curr_addr_list->value_nh6 = get_ip6($1.sval);
	}
	;

tablerec:
	IP
	{
		if (curr_table->type != IPFW_TABLE_ADDR)
			yyerror("Wrong (non-addr) table type");
		curr_addr_list = add_addr_to_list(get_ip($1.sval), 32, 0);
	}
	|
	NETWORK
	{
		char *mask;
		int plen;

		mask = strchr($1.sval, '/');
		*mask = 0;
		mask++;
		check_ipv4_prefixlen(plen = atoi(mask));

		if (curr_table->type != IPFW_TABLE_ADDR)
			yyerror("Wrong (non-addr) table type");
		curr_addr_list = add_addr_to_list(get_ip($1.sval), plen, 0);
	}
	|
	IP6
	{
		if (curr_table->type != IPFW_TABLE_ADDR)
			yyerror("Wrong (non-addr) table type");
		curr_addr_list = add_addr6_to_list(get_ip6($1.sval), 128, 0);
	}
	|
	NETWORK6
	{
		char *mask;
		int plen;

		mask = strchr($1.sval, '/');
		*mask = 0;
		mask++;
		check_ipv6_prefixlen(plen = atoi(mask));

		if (curr_table->type != IPFW_TABLE_ADDR)
			yyerror("Wrong (non-addr) table type");
		curr_addr_list = add_addr6_to_list(get_ip6($1.sval), plen, 0);
	}
	|
	hostname
	{
		if (curr_table->type == IPFW_TABLE_INTERFACE)
			curr_addr_list = add_iface_to_list($1.sval, line, 0);
		else
			curr_addr_list = add_host_to_list($1.sval, line, 0);

	}
	|
	NUMBER
	{
		if (curr_table->type != IPFW_TABLE_NUMBER)
			yyerror("Wrong (non-number) table type");
		curr_addr_list = add_number_to_list($1.ival);
	}
	;
nat:
	NAT NUMBER CONFIG natconfig EOL
	{
		SCHED_KLDLOAD(ipfw_nat);
		snprintf(cn->name, sizeof(cn->name), "%u", $2.ival);
	}
	;
natconfig:
	natrule
	|
	natrule natconfig
	;
natrule:
	T_IP IP
	{
		if (!inet_aton($2.sval, &cn->ip))
			yyerror("bad ip address ``%s''", $2.sval);
	}
	|
	IF TOKEN
	{
		set_addr_dynamic($2.sval, cn);
	}
	|
	LOG
	{
		NAT_UNIQ(LOG, "log");
	}
	|
	DENY_IN
	{
		NAT_UNIQ(DENY_INCOMING, "deny_in");
	}
	|
	SAME_PORTS
	{
		NAT_UNIQ(SAME_PORTS, "same_ports");
	}
	|
	SKIP_GLOBAL
	{
		NAT_UNIQ(SKIP_GLOBAL, "skip_global");
	}
	|
	UNREG_ONLY
	{
		NAT_UNIQ(UNREGISTERED_ONLY, "unreg_only");
	}
	|
	RESET
	{
		NAT_UNIQ(RESET_ON_ADDR_CHANGE, "reset");
	}
	|
	REVERSE
	{
		NAT_UNIQ(REVERSE, "reverse");
	}
	|
	PROXY_ONLY
	{
		NAT_UNIQ(PROXY_ONLY, "proxy_only");
	}
	|
	REDIRECT_ADDR RAspec
	{
		cn->redir_cnt++;
		crdr->mode = REDIR_ADDR;
		if (spool_cnt > 1)
			crdr->spool_cnt = spool_cnt;
		crdr = (struct nat44_cfg_redir *)csp;
		csp = (struct nat44_cfg_spool *)(crdr + 1);
		spool_cnt = 0;
		has_redirect = 1;
	}
	|
	REDIRECT_PORT TOKEN RPORTspec
	{
		cn->redir_cnt++;
		if (strcmp($2.sval, "tcp") == 0)
			crdr->proto = IPPROTO_TCP;
		else if (strcmp($2.sval, "udp") == 0)
			crdr->proto = IPPROTO_UDP;
		else
			yyerror("redirect_port for proto %s isn't supported",
			    $2.sval);
		if (spool_cnt > 1)
			crdr->spool_cnt = spool_cnt;
		crdr->mode = REDIR_PORT;
		crdr = (struct nat44_cfg_redir *)csp;
		csp = (struct nat44_cfg_spool *)(crdr + 1);
		spool_cnt = 0;
		has_redirect = 1;
	}
	|
	REDIRECT_PROTO TOKEN RPROTOspec
	{
		struct protoent *p;

		cn->redir_cnt++;
		p = getprotobyname($2.sval);
		if (p == NULL)
			yyerror("Unknown protocol");
		crdr->proto = p->p_proto;
		crdr->mode = REDIR_PROTO;
		crdr = (struct nat44_cfg_redir *)csp;
		csp = (struct nat44_cfg_spool *)(crdr + 1);
		has_redirect = 1;
	}
	;
RPROTOspec:
	IP
	{
		crdr->laddr.s_addr = get_ip($1.sval);
		crdr->paddr.s_addr = INADDR_ANY;
		crdr->raddr.s_addr = INADDR_ANY;
	}
	|
	IP IP
	{
		crdr->laddr.s_addr = get_ip($1.sval);
		crdr->paddr.s_addr = get_ip($2.sval);
		crdr->raddr.s_addr = INADDR_ANY;
	}
	|
	IP IP IP
	{
		crdr->laddr.s_addr = get_ip($1.sval);
		crdr->paddr.s_addr = get_ip($2.sval);
		crdr->raddr.s_addr = get_ip($3.sval);
	}
	;
RPORTspec:
	RPORTrangeladdr RPORTrangepaddr RPORTrangeraddr
	{
		if (port_range != crdr->pport_cnt || (
		    port_range != crdr->rport_cnt && (
		    crdr->rport_cnt != 1 || crdr->rport != 0)))
			yyerror("Port ranges must be equal");
	}
	|
	RPORTsingleladdr RPORTsinglepaddr RPORTsingleraddr
	;
RPORTrangeladdr:
	SOCKADDR4 MINUS NUMBER
	{
		crdr->lport = nat_parse_sockaddr($1.sval, &crdr->laddr);
		if ($3.ival < crdr->lport)
			yyerror("Wrong port range");
		port_range = $3.ival - crdr->lport + 1;
	}
	;
RPORTrangepaddr:
	RANGE
	{
		crdr->paddr.s_addr = INADDR_ANY;
		crdr->pport_cnt = nat_parse_range($1.sval, &crdr->pport);
	}
	|
	SOCKADDR4 MINUS NUMBER
	{
		crdr->pport = nat_parse_sockaddr($1.sval, &crdr->paddr);
		if ($3.ival <= crdr->pport)
			yyerror("Wrong port range");
		crdr->pport_cnt = $3.ival - crdr->pport + 1;
	}
	;
RPORTrangeraddr:
	{
		crdr->raddr.s_addr = INADDR_ANY;
		crdr->rport = 0;
		crdr->rport_cnt = 1;
	}
	|
	IP
	{
		crdr->raddr.s_addr = get_ip($1.sval);
		crdr->rport = 0;
		crdr->rport_cnt = 1;
	}
	|
	SOCKADDR4 MINUS NUMBER
	{
		crdr->rport = nat_parse_sockaddr($1.sval, &crdr->raddr);
		if ($3.ival <= crdr->rport)
			yyerror("Wrong port range");
		crdr->rport_cnt = $3.ival - crdr->rport + 1;
	}
	;
RPORTsingleladdr:
	RPORTladdr
	|
	RPORTladdr COMMA RPORTsingleladdr
	;
RPORTladdr:
	SOCKADDR4
	{
		switch (spool_cnt) {
		case 0:
			crdr->lport = nat_parse_sockaddr($1.sval, &crdr->laddr);
			break;
		case 1:
			csp->addr = crdr->laddr;
			csp->port = crdr->lport;
			csp++;
			crdr->laddr.s_addr = INADDR_NONE;
			crdr->lport = ~0;
		default:
			csp->port = nat_parse_sockaddr($1.sval, &csp->addr);
			csp++;
		};
		spool_cnt++;
	}
	;
RPORTsinglepaddr:
	NUMBER
	{
		crdr->paddr.s_addr = INADDR_ANY;
		crdr->pport = $1.ival;
		crdr->pport_cnt = 1;
	}
	|
	SOCKADDR4
	{
		crdr->pport = nat_parse_sockaddr($1.sval, &crdr->paddr);
		crdr->pport_cnt = 1;
	}
	;
RPORTsingleraddr:
	{
		crdr->raddr.s_addr = INADDR_ANY;
		crdr->rport = 0;
		crdr->rport_cnt = 1;
	}
	|
	IP
	{
		crdr->raddr.s_addr = get_ip($1.sval);
		crdr->rport = 0;
		crdr->rport_cnt = 1;
	}
	|
	SOCKADDR4
	{
		crdr->rport = nat_parse_sockaddr($1.sval, &crdr->raddr);
		crdr->rport_cnt = 1;
	}
	;
RAspec:
	RAlocaladdr IP
	{
		crdr->paddr.s_addr = get_ip($2.sval);
	}
	;
RAlocaladdr:
	RAlocalip
	|
	RAlocalip COMMA RAlocaladdr
	;
RAlocalip:
	IP
	{
		switch (spool_cnt) {
		case 0:
			crdr->laddr.s_addr = get_ip($1.sval);
			break;
		case 1:
			csp->addr = crdr->laddr;
			csp->port = ~0;
			csp++;
			crdr->laddr.s_addr = INADDR_NONE;
		default:
			csp->addr.s_addr = get_ip($1.sval);
			csp->port = ~0;
			csp++;
		};
		spool_cnt++;
	}
	;
pipequeue:
	PIPE NUMBER CONFIG pipeconfig EOL
	{
		if($2.ival == 0)
			yyerror("pipe number must be > 0");

		dsch.sched_nr = $2.ival;
		dsch.flags |= DN_PIPE_CMD;
		dlink.link_nr = $2.ival;
		dfs.fs_nr = DN_MAX_ID*2 + $2.ival;
		dfs.sched_nr = DN_MAX_ID + $2.ival;

		dummynet_check_rule();
		DN_COPY(sch, DN_SCH);
		DN_COPY(link, DN_LINK);
		DN_COPY(fs, DN_FS);
	}
	|
	QUEUE NUMBER CONFIG queueconfig EOL
	{
		if($2.ival == 0)
			yyerror("queue number must be > 0");
		dfs.fs_nr = $2.ival;
		dummynet_check_rule();
		DN_COPY(fs, DN_FS);
	}
	|
	SCHED NUMBER CONFIG schedconfig EOL
	{
		if($2.ival == 0)
			yyerror("sched number must be > 0");
		dsch.sched_nr = $2.ival;
		dfs.fs_nr = DN_MAX_ID + $2.ival;
		dfs.sched_nr = $2.ival;
		dummynet_check_rule();
		DN_COPY(sch, DN_SCH);
		DN_COPY(fs, DN_FS);
	}
	;
pipeconfig:
	pipetoken
	|
	pipeconfig pipetoken 
	;
pipetoken:
	BW bandwidth
	{
		DN_UNIQ(BW, "bandwidth");
		dlink.bandwidth = bw_val;
	}
	|
	BW TOKEN
	{
		DN_UNIQ(BW, "bandwidth");
		yywarning("`bw ifname` isn't supported.");
	}
	|
	PDELAY NUMBER
	{
		if($2.ival > 10000)
			yyerror("delay must be <= 10000");
		DN_UNIQ(DELAY, "delay");
		dlink.delay = $2.ival;
	}
	|
	BURST TOKEN
	{
		errno = 0;
		DN_UNIQ(BURST, "burst");
		if (expand_number($2.sval, &dlink.burst) < 0)
			if (errno != ERANGE)
				yyerror("invalid burst value");
		if (errno || dlink.burst > (1ULL << 48) - 1)
			yyerror("burst out of range");
	}
	|
	PROFILE TOKEN
	{
		yyerror("profile isn't supported");
	}
	|
	BUCKETS NUMBER
	{
		DN_UNIQ(BUCKETS, "buckets");
		dsch.buckets = $2.ival;
	}
	|
	MASK mask
	{
		DN_UNIQ(MASK, "sched_mask");
		bcopy(&dmask, &dsch.sched_mask, sizeof(dmask));
		dsch.flags |= DN_HAVE_MASK;
	}
	|
	pipequeueopt
	;
queueconfig:
	queuetoken
	|
	queueconfig queuetoken
	;
queuetoken:
	PIPE NUMBER
	{
		DN_UNIQ(PIPE, "pipe");
		if ($2.ival == 0)
			yyerror("pipe number must be > 0");
		dfs.sched_nr = $2.ival;
	}
	|
	BUCKETS NUMBER
	{
		DN_UNIQ(BUCKETS, "buckets");
		dfs.buckets = $2.ival;
	}
	|
	MASK mask
	{
		DN_UNIQ(MASK, "flow_mask");
		bcopy(&dmask, &dfs.flow_mask, sizeof(dmask));
		dfs.flags |= DN_HAVE_MASK;
	}
	|
	pipequeueopt
	;
schedconfig:
	schedtoken
	|
	schedconfig schedtoken 
	;
schedtoken:
	TYPE TOKEN
	{
		DN_UNIQ(TYPE, "type");
		if (strlen($2.sval) > 15)
			yyerror("type %s too long", $2.sval);
		strcpy(dsch.name, $2.sval);
		dsch.oid.subtype = 0;
	}
	|
	BUCKETS NUMBER
	{
		DN_UNIQ(BUCKETS, "buckets");
		dsch.buckets = $2.ival;
	}
	|
	MASK mask
	{
		DN_UNIQ(MASK, "sched_mask");
		bcopy(&dmask, &dsch.sched_mask, sizeof(dmask));
		dsch.flags |= DN_HAVE_MASK;
	}
	|
	pipequeueopt
	;
pipequeueopt:
	WEIGHT NUMBER
	{
		DN_UNIQ(WEIGHT, "weight");
		dfs.par[0] = $2.ival;
	}
	|
	LMAX NUMBER
	{
		DN_UNIQ(LMAX, $1.sval);
		dfs.par[1] = $2.ival;
	}
	|
	PRIORITY NUMBER
	{
		DN_UNIQ(PRI, "pri");
		dfs.par[2] = $2.ival;
	}
	|
	FLOWMASK mask
	{
		DN_UNIQ(MASK, "flow_mask");
		bcopy(&dmask, &dfs.flow_mask, sizeof(dmask));
		dfs.flags |= DN_HAVE_MASK;
	}
	|
	SCHEDMASK mask
	{
		DN_UNIQ(MASK, "sched_mask");
		bcopy(&dmask, &dsch.sched_mask, sizeof(dmask));
		dsch.flags |= DN_HAVE_MASK;
	}
	|
	NOERROR
	{
		DN_UNIQ(NOERROR, "noerror");
		dfs.flags |= DN_NOERROR;
	}
	|
	PLR
	{
		DN_UNIQ(PLR, "plr");
	}
	plr_values
	|
	QUEUE SIZEK
	{
		DN_UNIQ(QUEUE, "queue");
		dfs.qsize = $2.ival;
		dfs.flags |= DN_QSIZE_BYTES;
	}
	|
	QUEUE NUMBER
	{
		DN_UNIQ(QUEUE, "queue");
		dfs.qsize = $2.ival;
	}
	|
	DROPTAIL
	{
		DN_UNIQ(DROPTAIL, "droptail");
		dfs.flags &= ~(DN_IS_RED|DN_IS_GENTLE_RED);
	}
	|
	RED REDPARAM
	{
		double w_q, max_p;
		long min_th, max_th;
		char *p, *p1;

		DN_UNIQ(RED, $1.sval);
		p = $2.sval;
		w_q = strtod(p, NULL);
		p1 = strchr(p, '/');

		p1++;
		p = p1;
		min_th = strtoul(p, &p, 0);
		if(*p == 'K' || *p == 'k')
			min_th *= 1024;
		p1 = strchr(p, '/');

		p1++;
		p = p1;
		max_th = strtoul(p, NULL, 0);
		if(*p == 'K' || *p == 'k')
			max_th *= 1024;
		p1 = strchr(p, '/');

		p1++;
		p = p1;
		max_p = strtod(p, NULL);

		if (w_q > 1 || w_q == 0)
			yyerror("0 < w_q <= 1");

		if (max_p > 1 || max_p <= 0)
			yyerror("0 < max_p <= 1");

		if (min_th > max_th)
			yyerror("min_th must be < than max_th");

		if (max_th == 0)
			yyerror("max_th must be > 0");

		dfs.flags |= DN_IS_RED;
		if(strcmp($1.sval, "gred") == 0)
			dfs.flags |= DN_IS_GENTLE_RED;

		dfs.w_q = (int) (w_q * (1 << SCALE_RED));
		dfs.max_p = (int)(max_p * (1 << SCALE_RED));
		dfs.min_th = min_th;
		dfs.max_th = max_th;
	}
	;
plr_values:
	plr_value COMMA plr_values
	|
	plr_value
	;
plr_value:
	FLOAT
	{
		if (dn_plr >= (long)nitems(dfs.plr))
			yyerror("too many plr values");
		double d = $1.fval;

		if (d > 1)
			d = 1;
		else if (d < 0)
			d = 0;
		dfs.plr[dn_plr++] = (int)(d * 0x7fffffff);
	}
bandwidth:
	BWBS
	{
		bw_val = $1.ival;
	}
	|
	BWBTS
	{
		bw_val = $1.ival*8;
	}
	|
	BWKBS
	{
		bw_val = $1.ival*1000;
	}
	|
	BWKBTS
	{
		bw_val = $1.ival*1000*8;
	}
	|
	BWMBS
	{
		bw_val = $1.ival*1000000;
	}
	|
	BWMBTS
	{
		bw_val = $1.ival*1000000*8;
	}
	;
mask:
	maskopt
	|
	mask maskopt
	;
maskopt:
	DSTIP6 NUMBER
	{
		DN_CONFLICT(DIPMASK, "dst-ip", "dst-ip6");
		DN_CONFLICT(SIPMASK, "src-ip", "dst-ip6");
		DN_UNIQ(DIP6MASK, "dst-ip6");
		dmask.addr_type = 6;
		fill_ip6_mask(&dmask.dst_ip6, $2.ival);
	}
	|
	SRCIP6 NUMBER
	{
		DN_CONFLICT(DIPMASK, "dst-ip", "src-ip6");
		DN_CONFLICT(SIPMASK, "src-ip", "src-ip6");
		DN_UNIQ(SIP6MASK, "src-ip6");
		dmask.addr_type = 6;
		fill_ip6_mask(&dmask.src_ip6, $2.ival);
	}
	|
	FLOWID masktoken
	{
		DN_CONFLICT(DIPMASK, "dst-ip", "flow-id");
		DN_CONFLICT(SIPMASK, "src-ip", "flow-id");
		DN_UNIQ(FIDMASK, "flow-id");
		if (dn_mask > 0xFFFFF)
			yyerror("flow-id mask must be 20 bit");
		dmask.addr_type = 6;
		dmask.flow_id6 = dn_mask;
	}
	|
	DSTIP masktoken
	{
		DN_CONFLICT(DIP6MASK, "dst-ip6", "dst-ip");
		DN_CONFLICT(SIP6MASK, "src-ip6", "dst-ip");
		DN_CONFLICT(FIDMASK, "flow-id", "dst-ip");
		DN_UNIQ(DIPMASK, "dst-ip");
		dmask.addr_type = 4;
		dmask.dst_ip = dn_mask;
	}
	|
	SRCIP masktoken
	{
		DN_CONFLICT(DIP6MASK, "dst-ip6", "src-ip");
		DN_CONFLICT(SIP6MASK, "src-ip6", "src-ip");
		DN_CONFLICT(FIDMASK, "flow-id", "src-ip");
		DN_UNIQ(SIPMASK, "src-ip");
		dmask.addr_type = 4;
		dmask.src_ip = dn_mask;
	}
	|
	DSTPORT masktoken
	{
		DN_UNIQ(DPORTMASK, "dst-port");
		if (dn_mask > 0xFFFF)
			yyerror("port mask must be 16 bit");
		dmask.dst_port = (uint16_t)dn_mask;
	}
	|
	SRCPORT masktoken
	{
		DN_UNIQ(SPORTMASK, "src-port");
		if (dn_mask > 0xFFFF)
			yyerror("port mask must be 16 bit");
		dmask.src_port = (uint16_t)dn_mask;
	}
	|
	PROTO masktoken
	{
		DN_UNIQ(PROTOMASK, "proto");
		if (dn_mask > 0xFF)
			yyerror("proto mask must be 8 bit");
		dmask.proto = (uint8_t)dn_mask;
	}
	|
	QUEUE
	{
		DN_UNIQ(QUEUEMASK, "queue");
		dmask.extra = ~0;
	}
	|
	ALL
	{
		DN_UNIQ(ALLMASK, "all");
		dmask.dst_ip = ~0;
		dmask.src_ip = ~0;
		dmask.dst_port = ~0;
		dmask.src_port = ~0;
		dmask.proto = ~0;
		fill_ip6_mask(&dmask.dst_ip6, 128);
		fill_ip6_mask(&dmask.src_ip6, 128);
		dmask.flow_id6 = ~0;
	}
	;
masktoken:
	NUMBER
	{
		dn_mask = $1.ival;
	}
	|
	MASKLEN 
	{
		if ($1.ival > 32)
			yyerror("Wrong mask length %ld", $1.ival);
		dn_mask = ($1.ival == 32) ? ~0: (1 << $1.ival) - 1;
	}
	;
rulenumber:
	{
		START_LINE;

		if (tables_fin == 0) {
			tables_fin = 1;
			profile_stage("tables");
		}

		rule_num += rule_step;

		if (has_a_label && rule_num % LABEL_ALIGN > 0)
			/* align to LABEL_ALIGN */
			rule_num = rule_num + LABEL_ALIGN - rule_num % LABEL_ALIGN;

		rule->rulenum = rule_num;
		last_rule_num = rule_num;
	}
	|
	NUMBER
	{
		START_LINE;

		rule_num = rule->rulenum = (u_int32_t)$1.ival;
		if (rule_num < last_rule_num)
			yyerror("Rule number goes back (rule %d)", rule_num);
		else if (has_a_label && rule_num == last_rule_num)
			yyerror("Rule label is overridden by the previous rule (rule %d)", rule_num);

		last_rule_num = rule_num;
	}
	;
action:
	NAT natinstance
	{
		SCHED_KLDLOAD(ipfw_nat);
		action_opcode = action->opcode = O_NAT;
		action->len = F_INSN_SIZE(ipfw_insn_nat);
		action = next_cmd(action);
	}
	|
	COUNT
	{
		action_opcode = action->opcode = O_COUNT;
		action->len = 1;
		action = next_cmd(action);
	}
	|
	ALLOW
	{
		action_opcode = action->opcode = O_ACCEPT;
		action->len = 1;
		action = next_cmd(action);
	}
	|
	DENY
	{
		action_opcode = action->opcode = O_DENY;
		action->len = 1;
		action = next_cmd(action);
	}
	|
	REJECTT
	{
#ifndef ICMP_UNREACH_HOST
#define	ICMP_UNREACH_HOST	1
#endif
		action_opcode = action->opcode = O_REJECT;
		action->arg1 = ICMP_UNREACH_HOST;
		action->len = 1;
		action = next_cmd(action);
	}
	|
	RESET
	{
		action_opcode = action->opcode = O_REJECT;
		action->arg1 = ICMP_REJECT_RST;
		action->len = 1;
		action = next_cmd(action);
	}
	|
	UNREACH NUMBER
	{
		if ($2.ival > 255 || $2.ival < 0)
			yyerror("Wrong unreach code");
		action_opcode = action->opcode = O_REJECT;
		action->arg1 = $2.ival;
		action->len = 1;
		action = next_cmd(action);
	}
	|
	UNREACH6 NUMBER
	{
		if ($2.ival > 255 || $2.ival < 0)
			yyerror("Wrong unreach6 code");
		action_opcode = action->opcode = O_UNREACH6;
		action->arg1 = $2.ival;
		action->len = 1;
		action = next_cmd(action);
	}
	|
	RESET6
	{
		action_opcode = action->opcode = O_UNREACH6;
		action->arg1 = ICMP6_UNREACH_RST;
		action->len = 1;
		action = next_cmd(action);
	}
	|
	forwardip4_or_targ
	{
		action_opcode = action->opcode = O_FORWARD_IP;
		action->len = F_INSN_SIZE(ipfw_insn_sa);
		action = next_cmd(action);
	}
	|
	forwardip6
	{
		action_opcode = action->opcode = O_FORWARD_IP6;
		action->len = F_INSN_SIZE(ipfw_insn_sa6);
		action = next_cmd(action);
	}
	|
	SETDSCP setdscpspec
	{
		action_opcode = action->opcode = O_SETDSCP;
		action->len = 1;
		action = next_cmd(action);
	}
	|
	SETFIB setfibspec
	{
		action_opcode = action->opcode = O_SETFIB;
		action->len = 1;
		action = next_cmd(action);
	}
	|
	SKIPTO NUMBER
	{
		action_opcode = action->opcode = O_SKIPTO;
		action->len = F_INSN_SIZE(ipfw_insn_u32);
		insntod(action, u32)->d[0] = (u_int32_t)$2.ival;
		action = next_cmd(action);
	}
	|
	SKIPTO TABLEARG
	{
		action_opcode = action->opcode = O_SKIPTO;
		action->len = F_INSN_SIZE(ipfw_insn_u32);
		insntod(action, u32)->d[0] = ipfw_tablearg();
		action = next_cmd(action);
	}
	|
	SKIPTO LABEL
	{
		action_opcode = action->opcode = O_SKIPTO;
		action->len = F_INSN_SIZE(ipfw_insn_u32);
		action_label = strdup_wait($2.sval);
		action_label_insn = action;

		action = next_cmd(action);
	}
	|
	CALL NUMBER
	{
		action_opcode = action->opcode = O_CALLRETURN;
		action->len = F_INSN_SIZE(ipfw_insn_u32);
		insntod(action, u32)->d[0] = (u_int32_t)$2.ival;
		action = next_cmd(action);
	}
	|
	CALL TABLEARG
	{
		action_opcode = action->opcode = O_CALLRETURN;
		action->len = F_INSN_SIZE(ipfw_insn_u32);
		insntod(action, u32)->d[0] = ipfw_tablearg();
		action = next_cmd(action);
	}
	|
	CALL LABEL
	{
		action_opcode = action->opcode = O_CALLRETURN;
		action->len = F_INSN_SIZE(ipfw_insn_u32);
		action_label = strdup_wait($2.sval);
		action_label_insn = action;

		action = next_cmd(action);
	}
	|
	DIVERT NUMBER
	{
		SCHED_KLDLOAD(ipdivert);
		action_opcode = action->opcode = O_DIVERT;
		action->len = 1;
		action->arg1 = $2.ival;
		action = next_cmd(action);
	}
	|
	TEE NUMBER
	{
		action_opcode = action->opcode = O_TEE;
		action->len = 1;
		action->arg1 = $2.ival;
		action = next_cmd(action);
	}
	|
	REASS
	{
		action_opcode = action->opcode = O_REASS;
		action->len = 1;
		action = next_cmd(action);
	}
	|
	NETGRAPH NUMBER
	{
		action_opcode = action->opcode = O_NETGRAPH;
		action->len = 1;
		action->arg1 = (u_int32_t)$2.ival;
		action = next_cmd(action);
	}
	|
	SETIPPREC NUMBER
	{
#if defined(HAS_SETIPPREC)
		action_opcode = action->opcode = O_SETIPPREC;
		action->arg1 = (u_int32_t)$2.ival;
		if(action->arg1 > 7)
		    yyerror("setipprec value is out of range");
		action->len = 1;
		action = next_cmd(action);
#else
		yyerror("setipprec is not supported here");
#endif
	}
	|
	PIPE NUMBER
	{
		action_opcode = action->opcode = O_PIPE;
		action->len = F_INSN_SIZE(ipfw_insn_pipe);
		action->arg1 = (u_int32_t)$2.ival;
		action = next_cmd(action);
	}
	|
	QUEUE NUMBER
	{
		action_opcode = action->opcode = O_QUEUE;
		action->len = F_INSN_SIZE(ipfw_insn_pipe);
		action->arg1 = (u_int32_t)$2.ival;
		action = next_cmd(action);
	}
	|
	NAT64LSN TOKEN
	{
		SCHED_KLDLOAD(ipfw_nat64);
		action = add_eaction(action, $1.sval, $2.sval);
		action = next_cmd(action);
	}
	|
	NAT64STL TOKEN
	{
		SCHED_KLDLOAD(ipfw_nat64);
		action = add_eaction(action, $1.sval, $2.sval);
		action = next_cmd(action);
	}
	|
	NAT64CLAT TOKEN
	{
		SCHED_KLDLOAD(ipfw_nat64);
		action = add_eaction(action, $1.sval, $2.sval);
		action = next_cmd(action);
	}
	|
	NPTV6 TOKEN
	{
		SCHED_KLDLOAD(ipfw_nptv6);
		action = add_eaction(action, $1.sval, $2.sval);
		action = next_cmd(action);
	}
	|
	TCPSETMSS NUMBER
	{
		SCHED_KLDLOAD(ipfw_pmod);
		action_opcode = action->opcode = O_EXTERNAL_ACTION;
		action->len = F_INSN_SIZE(ipfw_insn_kidx);
		insntod(action, kidx)->kidx = pack_object(&obj_state,
		    $1.sval, IPFW_TLV_EACTION);
		action = next_cmd(action);
		action->len = 1;
		action->opcode = O_EXTERNAL_DATA;
		if ($2.ival <= 0 || $2.ival > 65535)
			yyerror("Wrong MSS value %ld", $2.ival);
		action->arg1 = (uint16_t)$2.ival;
		action = next_cmd(action);
	}
	|
	SETMARK setmark_spec
	{
		action_opcode = action->opcode = O_SETMARK;
		action->len = F_INSN_SIZE(ipfw_insn_u32);
		action = next_cmd(action);
	}
	;
setmark_spec:
	NUMBER
	{
		action->arg1 |= 0x8000;
		insntod(action, u32)->d[0] = $1.ival;
	}
	|
	TABLEARG
	{
		action->arg1 = IP_FW_TARG;
	}
	;
forwardip4_or_targ:
	FWD IP
	{
		ipfw_insn_sa *p = (ipfw_insn_sa *)action;

		p->sa.sin_len = sizeof(struct sockaddr_in);
		p->sa.sin_family = AF_INET;
		p->sa.sin_port = 0;
		p->sa.sin_addr.s_addr = get_ip($2.sval);
	}
	|
	FWD TABLEARG
	{
		ipfw_insn_sa *p = (ipfw_insn_sa *)action;

		p->sa.sin_len = sizeof(struct sockaddr_in);
		p->sa.sin_family = AF_INET;
		p->sa.sin_port = 0;
		p->sa.sin_addr.s_addr = INADDR_ANY;
	}
	|
	FWD IP COMMA NUMBER
	{
		ipfw_insn_sa *p = (ipfw_insn_sa *)action;

		p->sa.sin_len = sizeof(struct sockaddr_in);
		p->sa.sin_family = AF_INET;
		p->sa.sin_port = $4.ival;
		p->sa.sin_addr.s_addr = get_ip($2.sval);
	}
	|
	FWD TABLEARG COMMA NUMBER
	{
		ipfw_insn_sa *p = (ipfw_insn_sa *)action;

		p->sa.sin_len = sizeof(struct sockaddr_in);
		p->sa.sin_family = AF_INET;
		p->sa.sin_port = $4.ival;
		p->sa.sin_addr.s_addr = INADDR_ANY;
	}
	;
forwardip6:
	FWD IP6
	{
		ipfw_insn_sa6 *p = (ipfw_insn_sa6 *)action;

		p->sa.sin6_len = sizeof(struct sockaddr_in6);
		p->sa.sin6_family = AF_INET6;
		p->sa.sin6_port = 0;
		p->sa.sin6_flowinfo = 0;
		p->sa.sin6_scope_id = 0;
		p->sa.sin6_addr = get_ip6($2.sval);
	}
	|
	FWD IP6 COMMA NUMBER
	{
		ipfw_insn_sa6 *p = (ipfw_insn_sa6 *)action;

		p->sa.sin6_len = sizeof(struct sockaddr_in6);
		p->sa.sin6_family = AF_INET6;
		p->sa.sin6_port = $4.ival;
		p->sa.sin6_flowinfo = 0;
		p->sa.sin6_scope_id = 0;
		p->sa.sin6_addr = get_ip6($2.sval);
	}
	|
	FWD IP6SCOPIED
	{
		struct addrinfo hints, *res;
		ipfw_insn_sa6 *p = (ipfw_insn_sa6 *)action;

		bzero(&hints, sizeof(hints));
		hints.ai_family = AF_INET6;
		hints.ai_flags = AI_NUMERICHOST;
		if (getaddrinfo($2.sval, NULL, &hints, &res) != 0)
			yyerror("getaddrinfo(%s) failed", $2.sval);
		memcpy(&p->sa, res->ai_addr, res->ai_addrlen);
		freeaddrinfo(res);
	}
	|
	FWD IP6SCOPIED COMMA NUMBER
	{
		struct addrinfo hints, *res;
		ipfw_insn_sa6 *p = (ipfw_insn_sa6 *)action;

		bzero(&hints, sizeof(hints));
		hints.ai_family = AF_INET6;
		hints.ai_flags = AI_NUMERICHOST;
		if (getaddrinfo($2.sval, NULL, &hints, &res) != 0)
			yyerror("getaddrinfo(%s) failed", $2.sval);
		memcpy(&p->sa, res->ai_addr, res->ai_addrlen);
		freeaddrinfo(res);
		p->sa.sin6_port = $4.ival;
	}
	;
natinstance:
	NUMBER
	{
		if ($1.ival == 0)
			yyerror("Wrong NAT instance");
		action->arg1 = $1.ival;
	}
	|
	GLOBAL
	{
		action->arg1 = 0;
	}
	;
setdscpspec:
	NUMBER
	{
		if ($1.ival > 63)
			yyerror("dscpspec must be < 64");
		action->arg1 = $1.ival;
		action->arg1 |= 0x8000;
	}
	|
	DSCPSPEC
	{
		action->arg1 = dscpspec_match($1.sval);
		action->arg1 |= 0x8000;
	}
	|
	TABLEARG
	{
		action->arg1 = IP_FW_TARG;
	}
	;
setfibspec:
	NUMBER
	{
		if ($1.ival > maxfibs)
			yyerror("fib must be < %d", maxfibs);
		action->arg1 = $1.ival;
		action->arg1 |= 0x8000;
	}
	|
	TABLEARG
	{
		action->arg1 = IP_FW_TARG;
	}
	;
altq:
	ALTQ TOKEN
	{
		if (have_altq)
			yyerror("duplicate altq keyword");
		have_altq = cmd;
		cmd->opcode = O_ALTQ;
		cmd->len = F_INSN_SIZE(ipfw_insn_altq);
		((ipfw_insn_altq *)cmd)->qid = altq_name_to_qid($2.sval);
		cmd = next_cmd(cmd);
	}
	;
tag:
	TAG tagunique NUMBER
	{
		have_tag = cmd;
		cmd->opcode = O_TAG;
		cmd->len = 1;
		cmd->arg1 = $3.ival;
		cmd = next_cmd(cmd);
	}
	|
	TAG tagunique TABLEARG
	{
		have_tag = cmd;
		cmd->opcode = O_TAG;
		cmd->len = 1;
		cmd->arg1 = ipfw_tablearg();
		cmd = next_cmd(cmd);
	}
	|
	UNTAG tagunique NUMBER
	{
		have_tag = cmd;
		cmd->opcode = O_TAG;
		cmd->len = 1 | F_NOT;
		cmd->arg1 = $3.ival;
		cmd = next_cmd(cmd);
	}
	|
	UNTAG tagunique TABLEARG
	{
		have_tag = cmd;
		cmd->opcode = O_TAG;
		cmd->len = 1 | F_NOT;
		cmd->arg1 = ipfw_tablearg();
		cmd = next_cmd(cmd);
	}
	;
tagunique:
	{
		if (have_tag)
			yyerror("duplicate tag(or untag) keyword");
	}
	;
log:
	LOG set_have_log
	|
	LOG set_have_log logopts
	;
set_have_log:
	{
		if (have_log)
			yyerror("duplicate log keyword");
		have_log = cmd;
		cmd->opcode = O_LOG;
		cmd->len = F_INSN_SIZE(ipfw_insn_log);
		((ipfw_insn_log *)cmd)->max_log = verbose_limit;
		have_log->arg1 = IPFW_LOG_DEFAULT;
		cmd = next_cmd(cmd);
		if(debug)
			fprintf(stderr, "log ");
	}
	;
logopts:
	logopt
	|
	logopts logopt
	;
logopt:
	LOGAMOUNT NUMBER
	{
		((ipfw_insn_log *)have_log)->max_log = (u_int32_t)$2.ival;
		if(debug)
			fprintf(stderr, "logamount ");
	}
	|
	LOGDST logdstmask
	{
		if(debug)
			fprintf(stderr, "logdst ");
	}
	;
logdstmask:
	logdsttype
	|
	logdsttype COMMA logdstmask
	;
logdsttype:
	TOKEN
	{
		have_log->arg1 |= parse_logdst($1.sval);
	}
	;
rule:
	proto from to options
	{
		if(has_a_label) {
			/* Add a comment for a rule after label */
			char *p = (char *)(cmd + 1);
			cmd->opcode = O_NOP;
			cmd->len = 1 + (strlen(has_a_label)+4)/4;
			strcpy(p, has_a_label);
			cmd = next_cmd(cmd);

			/* Add label */
			add_label(has_a_label, rule_num);
			has_a_label = NULL;
		}
	}
	;
from:
	FROM statement ports
	{
		fill_addr_port_set(1);
	}
	;
to:
	TO statement ports
	{
		fill_addr_port_set(0);
	}
	;
proto:
	T_IP
	{
		add_proto("ip", 0);
	}
	|
	ALL
	{
		add_proto("all", 0);
	}
	|
	prototoken
	|
	not prototoken
	|
	OBRACE protoset EBRACE
	;
prototoken:
	T_IP4
	{
		add_proto("ip4", is_not ? F_NOT : 0);
		is_not = false;
	}
	|
	T_IP6
	{
		add_proto("ip6", is_not ? F_NOT : 0);
		is_not = false;
	}
	|
	ESP
	{
		add_proto("esp", is_not ? F_NOT : 0);
		is_not = false;
	}
	|
	AH
	{
		add_proto("ah", is_not ? F_NOT : 0);
		is_not = false;
	}
	|
	TOKEN
	{
		add_proto($1.sval, is_not ? F_NOT : 0);
		is_not = false;
	}
	|
	NUMBER
	{
		add_proto_num($1.ival, is_not ? F_NOT : 0);
		is_not = false;
	}
	;
protoset:
	prototoken OR protoset
	|
	prototoken
	;
statement: statementpre statementbody statementpost;

statementpre: { curr_addr_head = &addr_head; };
statementpost: { curr_addr_head = NULL; };

statementbody:
	statementtoken
	|
	not statementtoken
	|
	OBRACE statementset EBRACE
	;
statementtoken:
	addrdir IP
	{
		add_addr_to_list(get_ip($2.sval), 32, is_not);
		is_not = false;
	}
	|
	addrdir IPMASK
	{
		char *mask;

		mask = strchr($2.sval, ':');
		*mask = 0;
		mask++;

		curr_addr_list = add_addrmask_to_list(get_ip($2.sval),
		    get_ip(mask), is_not);
		is_not = false;
	}
	|
	addrdir NETWORK
	{
		char *mask;
		int plen;

		mask = strchr($2.sval, '/');
		*mask = 0;
		mask++;
		check_ipv4_prefixlen(plen = atoi(mask));

		add_addr_to_list(get_ip($2.sval), plen, is_not);
		is_not = false;
	}
	|
	addrdir IP6
	{
		add_addr6_to_list(get_ip6($2.sval), 128, is_not);
		is_not = false;
	}
	|
	addrdir IP6MASK
	{
		char *mask;

		mask = strchr($2.sval, '/');
		*mask = 0;
		mask++;

		curr_addr_list = add_addr6mask_to_list(get_ip6($2.sval),
		    get_ip6(mask), is_not);
		is_not = false;
	}
	|
	addrdir NETWORK6
	{
		char *mask;
		int plen;

		mask = strchr($2.sval, '/');
		*mask = 0;
		mask++;
		check_ipv6_prefixlen(plen = atoi(mask));

		add_addr6_to_list(get_ip6($2.sval), plen, is_not);
		is_not = false;
	}
	|
	addrdir ANY
	{
		/* any - add nothing */
		if(debug)
			fprintf(stderr, "any ");
	}
	|
	addrdir ME
	{
		if(debug)
			fprintf(stderr, "me ");

		add_me_to_list(ADDR_ME, is_not);
		is_not = false;
	}
	|
	addrdir ME6
	{
		if(debug)
			fprintf(stderr, "me6 ");

		add_me_to_list(ADDR_ME6, is_not);
		is_not = false;
	}
	|
	addrdir TABLENAME
	{
		add_table_to_list(get_table($2.sval, 0, O_CREAT), NULL, is_not);
		is_not = false;
	}
	|
	addrdir hostname
	{
		struct addrinfo *ai, *res;

		if ((res = y_gethostbyname($2.sval)) == NULL) {
			if(!ignore_unresolved) {
				if (only_test) {
					yywarning("can't resolve host: %s", $2.sval);
					break;
				} else 
					yyerror("can't resolve host: %s", $2.sval);
			} else {
				printf("Line %d: can't resolve host: %s. Ignored.\n", line, $2.sval);
				break;
			}
		}

		if(debug)
			fprintf(stderr, "domain:%s ", $2.sval);

		for(ai = res; ai != NULL; ai = ai->ai_next) {
			if(ai->ai_family == AF_INET6)
				add_addr6_to_list(((struct sockaddr_in6*)ai->ai_addr)->sin6_addr, 128, is_not);
			else
				add_addr_to_list(((struct sockaddr_in*)ai->ai_addr)->sin_addr.s_addr, 32, is_not);
		}
		is_not = false;
	}
	|
	tableref
	{
		add_table_to_list(curr_table, &curr_tableparam, is_not);
		is_not = false;
		curr_table = NULL;
		bzero(&curr_tableparam, sizeof(curr_tableparam));
	}
	;
tableref:
	TABLE LBRACE tablenameornum tableparam RBRACE
	;
hostname:
	TOKEN
	|
	FQDN
	;
tableparam:
	|
	tablevalueparam
	{
		IPFW_SET_LOOKUP_MATCH_TVALUE(&curr_tableparam.o, 1);
	}
tablevalueparam:
	COMMA NUMBER
	{
		IPFW_SET_TVALUE_TYPE(&curr_tableparam.o, TVALUE_TAG);
		curr_tableparam.u32 = $2.ival;
	}
	|
	COMMA tvaluename_u32 EQUAL NUMBER
	{
		curr_tableparam.u32 = $4.ival;
	}
	|
	COMMA NH4 EQUAL NUMBER
	{
		IPFW_SET_TVALUE_TYPE(&curr_tableparam.o, TVALUE_NH4);
		curr_tableparam.u32 = $4.ival;
	}
	|
	COMMA NH4 EQUAL IP
	{
		IPFW_SET_TVALUE_TYPE(&curr_tableparam.o, TVALUE_NH4);
		curr_tableparam.ip4.s_addr = get_ip($4.sval);
	}
	|
	COMMA NH6 EQUAL IP6
	{
		IPFW_SET_TVALUE_TYPE(&curr_tableparam.o, TVALUE_NH6);
		curr_tableparam.ip6 = get_ip6($4.sval);
	}
	;
tvaluename_u32:
	TAG	{ IPFW_SET_TVALUE_TYPE(&curr_tableparam.o, TVALUE_TAG); }
	|
	PIPE	{ IPFW_SET_TVALUE_TYPE(&curr_tableparam.o, TVALUE_PIPE); }
	|
	DIVERT	{ IPFW_SET_TVALUE_TYPE(&curr_tableparam.o, TVALUE_DIVERT); }
	|
	SKIPTO	{ IPFW_SET_TVALUE_TYPE(&curr_tableparam.o, TVALUE_SKIPTO); }
	|
	NETGRAPH { IPFW_SET_TVALUE_TYPE(&curr_tableparam.o, TVALUE_NETGRAPH); }
	|
	FIB	{ IPFW_SET_TVALUE_TYPE(&curr_tableparam.o, TVALUE_FIB); }
	|
	NAT	{ IPFW_SET_TVALUE_TYPE(&curr_tableparam.o, TVALUE_NAT); }
	|
	DSCP	{ IPFW_SET_TVALUE_TYPE(&curr_tableparam.o, TVALUE_DSCP); }
	|
	LIMIT	{ IPFW_SET_TVALUE_TYPE(&curr_tableparam.o, TVALUE_LIMIT); }
	|
	MARK	{ IPFW_SET_TVALUE_TYPE(&curr_tableparam.o, TVALUE_MARK); }
	;
not:
	NOT
	{
		is_not = true;
	}
	;
statementset:
	statementtoken OR statementset
	|
	statementtoken COMMA statementset
	|
	statementtoken
	|
	not statementtoken
	;
ports:
	|
	porttoken COMMA ports
	|
	porttoken
	;
portdir:
	|
	SRCPORT
	|
	DSTPORT
	;
addrdir:
	|
	SRCADDR
	|
	DSTADDR
	;
porttoken:
	portdir ALL
	{
		add_port("all", is_not);
		is_not = false;
	}
	|
	portdir TOKEN
	{
		add_port($2.sval, is_not);
		is_not = false;
	}
	|
	portdir NUMBER
	{
		add_port_to_list((u_int32_t)$2.ival, (u_int32_t)$2.ival, is_not);
		is_not = false;
	}
	|
	portdir RANGE
	{
		char start[6], *end;

		end = strchr($2.sval, '-');
		strncpy(start, $2.sval, end-$2.sval);
		start[end-$2.sval] = 0;
		end++;

		add_port_to_list(atoi(start), atoi(end), is_not);
		is_not = false;
	}
	;
options:
	|
	not optiontoken options
	|
	optiontoken options
	|
	obrace optionset ebrace
	;
obrace:
	OBRACE
	{
		optionset=1;
		prev = NULL;
	}
	;
ebrace:
	EBRACE
	{
		optionset=0;
		prev=NULL;
	}
	;
viatoken:
	VIA { cmd->opcode = O_VIA; }
	| XMIT { cmd->opcode = O_XMIT; }
	| RECV { cmd->opcode = O_RECV; }
	;

lookup_field_spec:
	DSTIP { IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_DST_IP); }
	|
	SRCIP { IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_SRC_IP); }
	|
	DSTIP4 { IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_DST_IP4); }
	|
	SRCIP4 { IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_SRC_IP4); }
	|
	DSTIP6 { IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_DST_IP6); }
	|
	SRCIP6 { IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_SRC_IP6); }
	|
	DSTPORT { IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_DST_PORT); }
	|
	SRCPORT { IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_SRC_PORT); }
	|
	UID { IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_UID); }
	|
	JAIL { IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_JAIL); }
	|
	DSCP { IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_DSCP); }
	|
	RULENUM { IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_RULENUM); }
	|
	DSTMAC { IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_DST_MAC); }
	|
	SRCMAC { IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_SRC_MAC); }
	|
	MARK { IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_MARK); }
	;
lookup_field_mask_spec_u32:
	DSTPORTCOLON { IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_DST_PORT); }
	|
	SRCPORTCOLON { IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_SRC_PORT); }
	|
	UIDCOLON { IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_UID); }
	|
	JAILCOLON { IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_JAIL); }
	|
	DSCPCOLON { IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_DSCP); }
	|
	RULENUMCOLON { IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_RULENUM); }
	|
	MARKCOLON { IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_MARK); }
	;
lookup_masked_spec:
	lookup_field_mask_spec_u32 NUMBER
	{
		curr_tableparam.u32 = $2.ival;
	}
	|
	lookup_field_mask_spec_u32 IP
	{
		curr_tableparam.u32 = ntohl(get_ip($2.sval));
	}
	|
	DSTIP4COLON IP
	{
		IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_DST_IP4);
		curr_tableparam.ip4.s_addr = get_ip($2.sval);
	}
	|
	SRCIP4COLON IP
	{
		IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_SRC_IP4);
		curr_tableparam.ip4.s_addr = get_ip($2.sval);
	}
	|
	DSTIP4COLON NUMBER
	{
		IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_DST_IP4);
		curr_tableparam.ip4.s_addr = get_ip($2.sval);
	}
	|
	SRCIP4COLON NUMBER
	{
		IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_SRC_IP4);
		curr_tableparam.ip4.s_addr = get_ip($2.sval);
	}
	|
	DSTIP6COLON IP6
	{
		IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_DST_IP6);
		curr_tableparam.ip6 = get_ip6($2.sval);
	}
	|
	SRCIP6COLON IP6
	{
		IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_SRC_IP6);
		curr_tableparam.ip6 = get_ip6($2.sval);
	}
	|
	DSTMACCOLON MACADDR
	{
		IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_DST_MAC);
		ether_aton_r($2.sval, (struct ether_addr *)&curr_tableparam.mac);
	}
	|
	SRCMACCOLON MACADDR
	{
		IPFW_SET_LOOKUP_TYPE(&curr_tableparam.o, LOOKUP_DST_MAC);
		ether_aton_r($2.sval, (struct ether_addr *)&curr_tableparam.mac);
	}
	;
lookup_spec:
	lookup_field_spec
	|
	lookup_masked_spec
	{
		IPFW_SET_LOOKUP_MASKING(&curr_tableparam.o, 1);
	}
	;
optiontoken:
	LOOKUP lookup_spec tablenameornum
	{
		fill_lookup_table(curr_table, &curr_tableparam);
		curr_table = NULL;
		bzero(&curr_tableparam, sizeof(curr_tableparam));
	}
	|
	PROTO prototoken
	|
	viatoken TOKEN
	{
		fill_iface($2.sval);
		if(optionset && prev)
			prev->len |= F_OR;
		prev = cmd;
		cmd = next_cmd(cmd);
		if(debug)
			fprintf(stderr, "VIA/XMIT/RECV %s ", $2.sval);
	}
	|
	viatoken tableref
	{
		fill_iface_table(curr_table);
		if(optionset && prev)
			prev->len |= F_OR;
		prev = cmd;
		cmd = next_cmd(cmd);
		if(debug)
			fprintf(stderr, "VIA/XMIT/RECV %s ", curr_table->name);
		curr_table = NULL;
		bzero(&curr_tableparam, sizeof(curr_tableparam));
	}
	|
	IN
	{
		cmd->opcode = O_IN;
		cmd->len = 1;
		cmd = next_cmd(cmd);
		if(debug)
			fprintf(stderr, "in ");
	}
	|
	OUT
	{
		cmd->opcode = O_IN;
		cmd->len ^= F_NOT;
		cmd->len |= 1;
		cmd = next_cmd(cmd);
		if(debug)
			fprintf(stderr, "out ");
	}
	|
	FRAG fragspec
	{
		cmd->opcode = O_FRAG;
		cmd->len = 1;
		cmd->arg1 = 1; /* compat */
		cmd = next_cmd(cmd);
		if(debug)
			fprintf(stderr, "frag ");
	}
	|
	SETUP
	{
		if(strcmp(curr_proto, "tcp") != 0)
			yyerror("setup option makes a sense only for TCP protocol");
		
		cmd->opcode = O_TCPFLAGS;
		cmd->len = 1;
		cmd->arg1 = (TH_SYN) | ( (TH_ACK) & 0xff) << 8;
		cmd = next_cmd(cmd);
		if(debug)
			fprintf(stderr, "setup ");
	}
	|
	ESTABLISHED
	{
		if(strcmp(curr_proto, "tcp") != 0)
			yyerror("established option makes a sense only for TCP protocol");
		
		cmd->opcode = O_ESTAB;
		cmd->len = 1;
		cmd = next_cmd(cmd);
		if(debug)
			fprintf(stderr, "established ");
	}
	|
	ICMPTYPES icmptypes
	{
		struct icmp_list *icmp_entry, *icmp_temp;

		if(strcmp(curr_proto, "icmp") != 0)
			yyerror("icmptypes allow only for ICMP protocol");

		((ipfw_insn_u32 *)cmd)->o.opcode = O_ICMPTYPE;
		((ipfw_insn_u32 *)cmd)->o.len |= F_INSN_SIZE(ipfw_insn_u32);
		if(debug)
			fprintf(stderr, "ICMPTYPES:");
		SLIST_FOREACH_SAFE(icmp_entry, &icmp_head, next, icmp_temp) {
			((ipfw_insn_u32 *)cmd)->d[0] |= 1 << icmp_entry->icmptype;
			if(debug)
				fprintf(stderr, "%d ", icmp_entry->icmptype);

			SLIST_REMOVE(&icmp_head, icmp_entry, icmp_list, next);
			free(icmp_entry);
		}
		cmd = next_cmd(cmd);
	}
	|
	ICMP6TYPES icmptypes
	{
		struct icmp_list *icmp_entry, *icmp_temp;

		if (strcmp(curr_proto, "icmp6") != 0 &&
		    strcmp(curr_proto, "ipv6-icmp") != 0)
			yyerror("icmp6types allow only for ICMPv6 protocol");

		bzero(cmd, sizeof(ipfw_insn_icmp6)); /* explicit init all masks */
		((ipfw_insn_icmp6 *)cmd)->o.opcode = O_ICMP6TYPE;
		((ipfw_insn_icmp6 *)cmd)->o.len |= F_INSN_SIZE(ipfw_insn_icmp6);
		if(debug)
			fprintf(stderr, "ICMP6TYPES:");
		SLIST_FOREACH_SAFE(icmp_entry, &icmp_head, next, icmp_temp) {
			unsigned t = icmp_entry->icmptype;
			if (t > ICMP6_MAXTYPE)
				yyerror("Wrong icmp6type: %d", t);
			((ipfw_insn_icmp6 *)cmd)->d[t/32] |= 1 << (t%32);
			if(debug)
				fprintf(stderr, "%d ", t);

			SLIST_REMOVE(&icmp_head, icmp_entry, icmp_list, next);
			free(icmp_entry);
		}
		cmd = next_cmd(cmd);
		if (!enable_ipv6)
			empty_rule = 1;
	}
	|
	keepstate
	{
		have_state = cmd;
		cmd->opcode = O_KEEP_STATE;
		cmd->len = F_INSN_SIZE(ipfw_insn_kidx);
		cmd = next_cmd(cmd);
		if(debug)
			fprintf(stderr, "keep-state ");
	}
	|
	DIVERTED
	{
		cmd->opcode = O_DIVERTED;
		cmd->len |= 1;
		HANDLE_NOT(cmd);
		cmd->arg1 = 3;
		cmd = next_cmd(cmd);
	}
	|
	DIVERTEDLOOPBACK
	{
		cmd->opcode = O_DIVERTED;
		cmd->len |= 1;
		HANDLE_NOT(cmd);
		cmd->arg1 = 1;
		cmd = next_cmd(cmd);
	}
	|
	DIVERTEDOUTPUT
	{
		cmd->opcode = O_DIVERTED;
		cmd->len |= 1;
		HANDLE_NOT(cmd);
		cmd->arg1 = 2;
		cmd = next_cmd(cmd);
	}
	|
	LIMIT source NUMBER statename
	{
		ipfw_insn_limit *c = (ipfw_insn_limit *)cmd;

		if(have_state)
			yyerror("either keep-state or limit should be used, not both together");
		have_state = cmd;
		cmd->len = F_INSN_SIZE(ipfw_insn_limit);
		cmd->opcode = O_LIMIT;
		c->limit_mask = c->conn_limit = 0;

		if(strcmp($2.sval, "src-addr") == 0)
			c->limit_mask |= DYN_SRC_ADDR;
		if(strcmp($2.sval, "dst-addr") == 0)
			c->limit_mask |= DYN_DST_ADDR;
		if(strcmp($2.sval, "src-port") == 0)
			c->limit_mask |= DYN_SRC_PORT;
		if(strcmp($2.sval, "dst-port") == 0)
			c->limit_mask |= DYN_DST_PORT;

		if($3.ival < 1 || $3.ival > 65534)
			yyerror("limit out of range: %d", $3.ival);
		c->conn_limit = (u_int32_t)$3.ival;
		cmd = next_cmd(cmd);
		if(debug)
			fprintf(stderr, "limit:%s %d %s",$2.sval,
			    (u_int32_t)$3.ival, $3.sval);
	}
	|
	TCPFLAGS tcpflags
	{
		if(strcmp(curr_proto, "tcp") != 0)
			yyerror("tcpflags make a sense only for TCP protocol");
		
		cmd->opcode = O_TCPFLAGS;
		cmd->len = 1;
		cmd->arg1 = (set & 0xff) | ( (clear & 0xff) << 8);
		set = clear = 0;
		cmd = next_cmd(cmd);
		if(debug)
			fprintf(stderr, "tcpflags ");
	}
	|
	TCPOPTIONS tcpoptions
	{
		printf("tcpoptions ");
		yyerror("\ntcpoptions is not implemented yet");
	}
	|
	IPID rangelist
	{
		uint16_t *ports;

		cmd->opcode = O_IPID;
		ports = ((ipfw_insn_u16 *)cmd)->ports;
		if (cmd->len == 1 && ports[0] == ports[1]) {
			cmd->arg1 = ports[0];
		} else
			cmd->len += 1;
		cmd = next_cmd(cmd);
	}
	|
	IPLEN rangelist
	{
		uint16_t *ports;

		cmd->opcode = O_IPLEN;
		ports = ((ipfw_insn_u16 *)cmd)->ports;
		if (cmd->len == 1 && ports[0] == ports[1]) {
			cmd->arg1 = ports[0];
		} else
			cmd->len += 1;
		cmd = next_cmd(cmd);
	}
	|
	IPOPTIONS ipoptions
	{
		yyerror("\nipoptions is not implemented yet");
	}
	|
	IPTOS iptos
	{
		yyerror("\niptos is not implemented yet");
	}
	|
	IPTTL rangelist
	{
		uint16_t *ports;

		cmd->opcode = O_IPTTL;
		ports = ((ipfw_insn_u16 *)cmd)->ports;
		if (cmd->len == 1 && ports[0] == ports[1]) {
			cmd->arg1 = ports[0];
		} else
			cmd->len += 1;
		cmd = next_cmd(cmd);
	}
	|
	JAIL NUMBER
	{
		cmd->opcode = O_JAIL;
		((ipfw_insn_u32 *)cmd)->d[0] = (uint32_t)$2.ival;
		cmd->len |= F_INSN_SIZE(ipfw_insn_u32);
		if(prev)
			prev->len |= F_OR;
		HANDLE_NOT(cmd);
		prev = cmd;
		cmd = next_cmd(cmd);

	}
	|
	TCPDATALEN rangelist
	{
		uint16_t *ports;

		cmd->opcode = O_TCPDATALEN;
		ports = ((ipfw_insn_u16 *)cmd)->ports;
		if (cmd->len == 1 && ports[0] == ports[1]) {
			cmd->arg1 = ports[0];
		} else
			cmd->len += 1;
		cmd = next_cmd(cmd);
	}
	|
	TCPSEQ NUMBER
	{
		yyerror("\ntcpseq is not implemented yet");
	}
	|
	TCPMSS rangelist
	{
		uint16_t *ports;

		cmd->opcode = O_TCPMSS;
		ports = ((ipfw_insn_u16 *)cmd)->ports;
		if (cmd->len == 1 && ports[0] == ports[1]) {
			cmd->arg1 = ports[0];
		} else
			cmd->len += 1;
		cmd = next_cmd(cmd);
	}
	|
	TCPWIN rangelist
	{
		uint16_t *ports;

		cmd->opcode = O_TCPWIN;
		ports = ((ipfw_insn_u16 *)cmd)->ports;
		if (cmd->len == 1 && ports[0] == ports[1]) {
			cmd->arg1 = ports[0];
		} else
			cmd->len += 1;
		cmd = next_cmd(cmd);
	}
	|
	ANTISPOOF
	{
		cmd->opcode = O_ANTISPOOF;
		cmd->len = 1;
		cmd = next_cmd(cmd);
	}
	|
	VERREVPATH
	{
		cmd->opcode = O_VERREVPATH;
		cmd->len = 1;
		cmd = next_cmd(cmd);
	}
	|
	VERSRCREACH
	{
		cmd->opcode = O_VERSRCREACH;
		cmd->len = 1;
		cmd = next_cmd(cmd);
	}
	|
	EXT6HDR exthdropts
	{
		cmd->opcode = O_EXT_HDR;
		cmd->len = 1;
		cmd = next_cmd(cmd);
	}
	|
	IPSEC
	{
		cmd->opcode = O_IPSEC;
		cmd->len = 1;
		cmd = next_cmd(cmd);
	}
	|
	IPVER NUMBER
	{
		cmd->opcode = O_IPVER;
		cmd->len = 1;
		cmd->arg1 = $2.ival;
		cmd = next_cmd(cmd);
	}
	|
	DSCP dscpspec
	{
		cmd->opcode = O_DSCP;
		cmd->len |= F_INSN_SIZE(ipfw_insn_u32) + 1;
		cmd = next_cmd(cmd);
	}
	|
	TAGGED rangelist
	{
		uint16_t *ports;

		cmd->opcode = O_TAGGED;
		ports = ((ipfw_insn_u16 *)cmd)->ports;
		if (cmd->len == 1 && ports[0] == ports[1]) {
			cmd->arg1 = ports[0];
		} else
			cmd->len += 1;
		HANDLE_NOT(cmd);
		cmd = next_cmd(cmd);
	}
	|
	LAYER2
	{
		cmd->opcode = O_LAYER2;
		cmd->len |= 1;
		HANDLE_NOT(cmd);
		cmd = next_cmd(cmd);
	}
	|
	SRCMAC tableref
	{
		cmd_mac_lookup(O_MAC_SRC_LOOKUP, curr_table, &curr_tableparam);
		curr_table = NULL;
		bzero(&curr_tableparam, sizeof(curr_tableparam));
	}
	|
	DSTMAC tableref
	{
		cmd_mac_lookup(O_MAC_DST_LOOKUP, curr_table, &curr_tableparam);
		curr_table = NULL;
		bzero(&curr_tableparam, sizeof(curr_tableparam));
	}
	|
	MARK mark_spec
	{
		cmd->opcode = O_MARK;
		cmd->len |= F_INSN_SIZE(ipfw_insn_u32) + 1;
		HANDLE_NOT(cmd);
		cmd = next_cmd(cmd);
	}
	;
mark_spec:
	NUMBER
	{
		cmd->arg1 |= 0x8000;
		insntod(cmd, u32)->d[0] = $1.ival;
		insntod(cmd, u32)->d[1] = 0xFFFFFFFF;
	}
	|
	TABLEARG
	{
		cmd->arg1 = IP_FW_TARG;
		insntod(cmd, u32)->d[1] = 0xFFFFFFFF;
	}
	|
	NUMBERCOLON NUMBER
	{
		cmd->arg1 |= 0x8000;
		insntod(cmd, u32)->d[0] = $1.ival;
		insntod(cmd, u32)->d[1] = $2.ival;
	}
	|
	TABLEARGCOLON NUMBER
	{
		cmd->arg1 = IP_FW_TARG;
		insntod(cmd, u32)->d[1] = $2.ival;
	}
	;
fragspec:
	|
	RF
	|
	DF
	|
	MF
	|
	OFFSET
	;
keepstate:
	KEEPSTATE
	{
		insntod(cmd, kidx)->kidx =
		    pack_object(&obj_state, default_state_name,
			IPFW_TLV_STATE_NAME);
	}
	|
	KEEPSTATE LABEL
	{
		if (named_states == 0)
			yyerror("named_states are disabled");
		if (strcmp($2.sval, ":any") == 0)
			yyerror(":any is not allowed with %s", $1.sval);
		insntod(cmd, kidx)->kidx =
		    pack_object(&obj_state, $2.sval + 1,
		    IPFW_TLV_STATE_NAME);
	}
	;
dscpspec:
	dscpspectoken
	|
	dscpspectoken COMMA dscpspec
	;
dscpspectoken:
	DSCPSPEC
	{
		uint32_t *store;
		uint8_t code;

		code = dscpspec_match($1.sval);
		if (code >= 32) {
			store = (uint32_t *)(cmd + 2);
			code -= 32;
		} else
			store = (uint32_t *)(cmd + 1);
		if (*store & (1 << code))
			yyerror("Dublicate dscp spec %s", $1.sval);
		*store |= (1 << code);
	}
	|
	NUMBER
	{
		uint32_t *store;
		uint8_t code;

		if ($1.ival > 63)
			yyerror("dscpspec must be < 64");
		code = (uint8_t)$1.ival;
		if (code >= 32) {
			store = (uint32_t *)(cmd + 2);
			code -= 32;
		} else
			store = (uint32_t *)(cmd + 1);
		if (*store & (1 << code))
			yyerror("Dublicate dscp spec %d", $1.ival);
		*store |= (1 << code);
	}
	;
rangelist:
	rangelistpart
	|
	rangelistpart COMMA rangelist
	;
rangelistpart:
	NUMBER
	{
		uint16_t *ports;

		ports = ((ipfw_insn_u16 *)cmd)->ports + F_LEN(cmd) * 2;
		ports[0] = ports[1] = $1.ival;
		cmd->len += 1;
	}
	|
	RANGE
	{
		uint16_t *ports;

		ports = ((ipfw_insn_u16 *)cmd)->ports + F_LEN(cmd) * 2;
		sscanf($1.sval, "%hu-%hu", ports, ports + 1);
		cmd->len += 1;
	}
	;
optionset:
	optiontoken OR optionset
	|
	optiontoken
	|
	not optiontoken
	;
source:
	SRCADDR
	|
	DSTADDR
	|
	SRCPORT
	|
	DSTPORT
	;
statename:
	LABEL
	{
		if (named_states == 0)
			yyerror("named_states are disabled");
		insntod(cmd, kidx)->kidx =
		    pack_object(&obj_state, $1.sval + 1,
		    IPFW_TLV_STATE_NAME);
	}
	|
	{
		insntod(cmd, kidx)->kidx =
		    pack_object(&obj_state,
		    default_state_name, IPFW_TLV_STATE_NAME);
	}
	;
tcpflagstoken:
	FIN
	{
		set |= 1;
	}	
	|
	NOTCHAR FIN
	{
		clear |= 1;
	}
	|
	SYN
	{
		set |= 2;
	}	
	|
	NOTCHAR SYN
	{
		clear |= 2;
	}	
	|
	RST
	{
		set |= 4;
	}	
	|
	NOTCHAR RST
	{
		clear |= 4;
	}	
	|
	PSH
	{
		set |= 8;
	}	
	|
	NOTCHAR PSH
	{
		clear |= 8;
	}	
	|
	ACK
	{
		set |= 16;
	}	
	|
	NOTCHAR ACK
	{
		clear |= 16;
	}	
	|
	URG
	{
		set |= 32;
	}	
	|
	NOTCHAR URG
	{
		clear |= 32;
	}	
	;
tcpflags:
	tcpflagstoken
	|
	tcpflagstoken COMMA tcpflags
	;
tcpoptionstoken:
	MSS
	{
		yyerror("option mss is not supported yet");
	}
	|
	WINDOW
	{
		yyerror("option window is not supported yet");
	}
	|
	SACK
	{
		yyerror("option sack is not supported yet");
	}
	|
	TS
	{
		yyerror("option ts is not supported yet");
	}
	|
	CC
	{
		yyerror("option cc is not supported yet");
	}
	;
tcpoptions:
	tcpoptionstoken
	|
	NOTCHAR tcpoptionstoken
	|
	tcpoptionstoken COMMA tcpoptions
	;
ipoptionstoken:
	SSRR
	{
		yyerror("option ssrr is not supported yet");
	}
	|
	LSRR
	{
		yyerror("option slrr is not supported yet");
	}
	|
	RR
	{
		yyerror("option rr is not supported yet");
	}
	|
	TS
	{
		yyerror("option ts is not supported yet");
	}
	;
ipoptions:
	ipoptionstoken
	|
	NOTCHAR ipoptionstoken
	|
	ipoptionstoken COMMA ipoptions
	;
iptostoken:
	LOWDELAY
	{
		yyerror("option lowdelay is not supported yet");
	}
	|
	THROUGHPUT
	{
		yyerror("option throughput is not supported yet");
	}
	|
	RELIABILITY
	{
		yyerror("option reliability is not supported yet");
	}
	|
	MINCOST
	{
		yyerror("option mincost is not supported yet");
	}
	|
	CONGESTION
	{
		yyerror("option congestion is not supported yet");
	}
	;
iptos:
	iptostoken
	|
	NOTCHAR iptostoken
	|
	iptostoken COMMA iptos
	;
icmptypes:
	icmptype
	|
	icmptypes COMMA icmptype
	;
icmptype:
	NUMBER
	{
		struct icmp_list *icmp_entry = malloc_wait(sizeof(struct icmp_list));

		icmp_entry->icmptype = (u_int32_t)$1.ival;
		
		if(SLIST_EMPTY(&icmp_head)) {
			SLIST_INSERT_HEAD(&icmp_head, icmp_entry, next);
			icmp_prev = icmp_entry;
		} else {
			SLIST_INSERT_AFTER(icmp_prev, icmp_entry, next);
			icmp_prev = icmp_entry;
		}
	}
	;
exthdropts:
	exthdropt
	|
	exthdropts COMMA exthdropt
	;
exthdropt:
	FRAG
	{
		cmd->arg1 |= EXT_FRAGMENT;
	}
	|
	HOPOPT
	{
		cmd->arg1 |= EXT_HOPOPTS;
	}
	|
	ROUTE
	{
		cmd->arg1 |= EXT_ROUTING;
	}
	|
	DSTOPT
	{
		cmd->arg1 |= EXT_DSTOPTS;
	}
	|
	AH
	{
		cmd->arg1 |= EXT_AH;
	}
	|
	ESP
	{
		cmd->arg1 |= EXT_ESP;
	}
	|
	RTHDR0
	{
		cmd->arg1 |= EXT_RTHDR0;
	}
	|
	RTHDR2
	{
		cmd->arg1 |= EXT_RTHDR2;
	}
	;
%%

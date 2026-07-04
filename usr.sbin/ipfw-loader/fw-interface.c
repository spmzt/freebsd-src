/*
 * Copyright (c) 2007-2026 Yandex, LLC.
 *
 * SPDX-License-Identifier: BSD-4-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip_fw.h>
#include <sys/queue.h>
#include <netinet/ip_dummynet.h>
#include <errno.h>
#include <sysexits.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/counter.h>
#include <libutil.h>

#include "fw-parse.h"
#include <netinet6/ip_fw_nptv6.h>
#include <netinet6/ip_fw_nat64.h>

/*
 * Functions implementing interaction with current IPFW module interface.
 */
#ifndef IP_FW3_OPVER
#define	IP_FW3_OPVER	0
#endif

static int
do_set3(int s, int optname, ip_fw3_opheader *op3, uintptr_t optlen)
{

	op3->opcode = optname;
	op3->version = IP_FW3_OPVER;

	return (setsockopt(s, IPPROTO_IP, IP_FW3, op3, optlen));
}

static int
do_get3(int s, int optname, ip_fw3_opheader *op3, size_t *optlen)
{
	int error;

	op3->opcode = optname;
	op3->version = IP_FW3_OPVER;

	error = getsockopt(s, IPPROTO_IP, IP_FW3, op3,
	    (socklen_t *)optlen);

	return (error);
}

static void
fill_ntlv(ipfw_obj_ntlv *ntlv, uint16_t type, uint32_t idx,
    const char *name, uint8_t set)
{

	memset(ntlv, 0, sizeof(ipfw_obj_ntlv));
	ntlv->head.type = type;
	ntlv->head.length = sizeof(ipfw_obj_ntlv);
	ntlv->idx = idx;
	ntlv->set = set;
	strlcpy(ntlv->name, name, sizeof(ntlv->name));
}

/* Copied from ipfw2 binary code */
static uint32_t
pack_object_new(struct tidx *tstate, const char *name, int otype)
{
	unsigned int i;
	ipfw_obj_ntlv *ntlv;

	for (i = 0; i < tstate->count; i++) {
		if (strcmp(tstate->idx[i].name, name) != 0)
			continue;
		if (tstate->idx[i].set != tstate->set)
			continue;
		if (tstate->idx[i].head.type != otype)
			continue;

		return (tstate->idx[i].idx);
	}

	if (tstate->count + 1 > tstate->size) {
		tstate->size += 4;
		tstate->idx = realloc(tstate->idx, tstate->size *
		    sizeof(ipfw_obj_ntlv));
		if (tstate->idx == NULL)
			return (0);
	}

	ntlv = &tstate->idx[i];
	fill_ntlv(ntlv, otype, ++tstate->counter, name, tstate->set);
	tstate->count++;
	return (ntlv->idx);
}

static int
compare_ntlv(const void *_a, const void *_b)
{
	const ipfw_obj_ntlv *a, *b;

	a = (const ipfw_obj_ntlv *)_a;
	b = (const ipfw_obj_ntlv *)_b;

	if (a->set < b->set)
		return (-1);
	else if (a->set > b->set)
		return (1);

	if (a->idx < b->idx)
		return (-1);
	else if (a->idx > b->idx)
		return (1);

	if (a->head.type < b->head.type)
		return (-1);
	else if (a->head.type > b->head.type)
		return (1);

	return (0);
}

/*
 * Provide kernel with sorted list of referenced objects
 */
static void
object_sort_ctlv(ipfw_obj_ctlv *ctlv)
{

	qsort(ctlv + 1, ctlv->count, ctlv->objsize, compare_ntlv);
}

void *
encap_single_rule(const struct ip_fw_rule *rule0, struct tidx *ostate,
    ipfw_insn **act_ptr, size_t *psz)
{
	char rulebuf[4096];
	int default_off, tlen, rlen;
	size_t sz;
	struct ip_fw_rule *rule, *rule1;
	caddr_t tbuf;
	ip_fw3_opheader *op3;
	ipfw_obj_ctlv *ctlv;

	bzero(rulebuf, sizeof(rulebuf));

	/* Optimize case with no tables */
	default_off = sizeof(ipfw_obj_ctlv) + sizeof(ip_fw3_opheader);

	/* Convert to 'right' form */
	rule1 = (struct ip_fw_rule *)rulebuf;
	memcpy(rule1->cmd, rule0->cmd, rule0->cmd_len * 4);

	rule1->act_ofs = rule0->act_ofs;
	rule1->cmd_len = rule0->cmd_len;
	rule1->rulenum = rule0->rulenum;
	rule1->set = rule0->set;

	rlen = RULESIZE(rule1);
	rlen = roundup2(rlen, sizeof(uint64_t));

	op3 = NULL;
	ctlv = NULL;
	rule = NULL;
	tbuf = NULL;
	sz = 0;
	if (ostate->count != 0) {
		/* Some tables. We have to alloc more data */
		tlen = ostate->count * sizeof(ipfw_obj_ntlv);
		sz = default_off + sizeof(ipfw_obj_ctlv) + tlen + rlen;

		if ((tbuf = calloc(1, sz)) == NULL)
			err(EX_UNAVAILABLE, "malloc() failed for IP_FW_XADD");
		op3 = (ip_fw3_opheader *)tbuf;
		/* Tables first */
		ctlv = (ipfw_obj_ctlv *)(op3 + 1);
		ctlv->head.type = IPFW_TLV_TBLNAME_LIST;
		ctlv->head.length = sizeof(ipfw_obj_ctlv) + tlen;
		ctlv->count = ostate->count;
		ctlv->objsize = sizeof(ipfw_obj_ntlv);
		memcpy(ctlv + 1, ostate->idx, tlen);
		object_sort_ctlv(ctlv);
		/* Rule next */
		ctlv = (ipfw_obj_ctlv *)((caddr_t)ctlv + ctlv->head.length);
		ctlv->head.type = IPFW_TLV_RULE_LIST;
		ctlv->head.length = sizeof(ipfw_obj_ctlv) + rlen;
		ctlv->count = 1;
		rule = (struct ip_fw_rule *)(ctlv + 1);
		memcpy(rule, rule1, RULESIZE(rule1));
	} else {
		/* Simply add header */
		sz = rlen + default_off;
		if ((tbuf = calloc(1, sz)) == NULL)
			errx(1, "\nmemory error");

		op3 = (ip_fw3_opheader *)tbuf;
		ctlv = (ipfw_obj_ctlv *)(op3 + 1);

		ctlv->head.type = IPFW_TLV_RULE_LIST;
		ctlv->head.length = sizeof(ipfw_obj_ctlv) + rlen;
		ctlv->count = 1;
		rule = (struct ip_fw_rule *)(ctlv + 1);
		memcpy(rule, rule1, RULESIZE(rule1));
	}

	*act_ptr = rule->cmd + rule->act_ofs;
	*psz = sz;

	return (tbuf);
}

static int
install_single_rule_new(int s, struct rule_info *info)
{
	ip_fw3_opheader *op3;
	size_t sz;
	int error;

	op3 = (ip_fw3_opheader *)info->rule;
	sz = info->sz;

	if(debug)
	    printf("rule opcodes len: %zu\n", sz);

	error = do_get3(s, IP_FW_XADD, op3, &sz);
	if (error != 0)
		fprintf(stderr, "ipfw install error %d at opcode %d\n",
		    error, info->rule->cmd->opcode);

	return (error);
}

static int
table_do_modify_record(int s, int cmd, ipfw_obj_header *oh,
    ipfw_obj_tentry *tent, int count, int atomic)
{
	ipfw_obj_ctlv *ctlv;
	ipfw_obj_tentry *tent_base;
	caddr_t pbuf;
	char xbuf[sizeof(*oh) + sizeof(ipfw_obj_ctlv) + sizeof(*tent)];
	int error, i;
	size_t sz;

	sz = sizeof(*ctlv) + sizeof(*tent) * count;
	if (count == 1) {
		memset(xbuf, 0, sizeof(xbuf));
		pbuf = xbuf;
	} else {
		if ((pbuf = calloc(1, sizeof(*oh) + sz)) == NULL)
			return (ENOMEM);
	}

	memcpy(pbuf, oh, sizeof(*oh));
	oh = (ipfw_obj_header *)pbuf;
	oh->opheader.version = 1;

	ctlv = (ipfw_obj_ctlv *)(oh + 1);
	ctlv->count = count;
	ctlv->head.length = sz;
	if (atomic != 0)
		ctlv->flags |= IPFW_CTF_ATOMIC;

	tent_base = tent;
	memcpy(ctlv + 1, tent, sizeof(*tent) * count);
	tent = (ipfw_obj_tentry *)(ctlv + 1);
	for (i = 0; i < count; i++, tent++) {
		tent->head.length = sizeof(ipfw_obj_tentry);
		tent->idx = oh->idx;
	}

	sz += sizeof(*oh);
	error = do_get3(s, cmd, &oh->opheader, &sz);
	tent = (ipfw_obj_tentry *)(ctlv + 1);
	/* Copy result back to provided buffer */
	memcpy(tent_base, ctlv + 1, sizeof(*tent) * count);

	if (pbuf != xbuf)
		free(pbuf);

	return (error);
}

/* Copied from ipfw2 binary code */
static int
table_do_create(int s, ipfw_obj_header *oh, ipfw_xtable_info *i)
{
	char tbuf[sizeof(ipfw_obj_header) + sizeof(ipfw_xtable_info)];
	int error;

	memcpy(tbuf, oh, sizeof(*oh));
	memcpy(tbuf + sizeof(*oh), i, sizeof(*i));
	oh = (ipfw_obj_header *)tbuf;

	error = do_set3(s, IP_FW_TABLE_XCREATE, &oh->opheader, sizeof(tbuf));

	return (error);
}

static void
set_legacy_value(uint32_t val, ipfw_table_value *v)
{
	v->tag = val;
	v->pipe = val;
	v->divert = val;
	v->skipto = val;
	v->netgraph = val;
	v->fib = val;
	v->nat = val;
	v->nh4 = val;
	v->dscp = (uint8_t)val;
	v->limit = val;
}

static void
set_table_entry_value(uint32_t vmask, struct addr_list *entry,
    ipfw_table_value *v)
{

	set_legacy_value(entry->value, v);
	if (vmask == IPFW_VTYPE_LEGACY)
		return;

	if (vmask & IPFW_VTYPE_NH4)
		v->nh4 = ntohl(entry->value_nh);

	/* XXX: zone id */
	if (vmask & IPFW_VTYPE_NH6)
		v->nh6 = entry->value_nh6;
}

static void
table_fill_ntlv(ipfw_obj_ntlv *ntlv, char *name, uint32_t set, uint32_t uidx)
{

	fill_ntlv(ntlv, IPFW_TLV_TBL_NAME, uidx, name, set);
}

static int
compile_table_entry_new(uint32_t vmask, struct addr_list *l,
    ipfw_obj_tentry *ptent)
{
	int mask;

	switch (l->addr_type) {
	case ADDR_IPV6:
		ptent->subtype = AF_INET6;
		ptent->masklen = l->masklen;
		ptent->k.addr6 = l->ip6;
		break;
	case ADDR_IPV4:
		ptent->subtype = AF_INET;
		ptent->masklen = l->masklen;
		ptent->k.addr.s_addr = l->ip;
		break;
	case ADDR_IFACE:
		mask = MIN(strlen(l->hostname), IF_NAMESIZE - 1);
		memcpy(ptent->k.iface, l->hostname, mask);
		/* Set mask to exact match */
		ptent->masklen = 8 * IF_NAMESIZE;
		break;
	case ADDR_NUMBER:
		ptent->masklen = 32;
		memcpy(&ptent->k, &l->ip, sizeof(uint32_t));
		break;
	default: /* XXX */
		break;
	}

	if (l->label != NULL) {
		l->value = get_label_number(l->label);
		if (l->value == 0) {
			fprintf(stderr, "Error resolving label %s\n", l->label);
			return (1);
		}
		_debug("label %s resolved to %u", l->label, l->value);
	}

	set_table_entry_value(vmask, l, &ptent->v.value);
	return (0);
}

static int
install_table_new(int s, struct table *table, int *fd)
{
	char table_name[16];
	void *tent_buf;
	struct addr_list *l;
	ipfw_obj_tentry *ptent;
	ipfw_obj_header oh;
	int count, error, i;
	ipfw_xtable_info xi;

	if (table->type == IPFW_TABLE_INTERFACE && quiet == 0)
		fprintf(stderr, "Installing interface table %s id %d\n",
		    table->name, table->number);

	count = table->count4 + table->count6 + table->ifcount + table->ncount;
	_debug("Installing table %s v4=%u 4v6=%u iface=%u number=%u", table->name,
	    table->count4, table->count6, table->ifcount, table->ncount);

	if ((tent_buf = calloc(count, sizeof(ipfw_obj_tentry))) == NULL)
		errx(EX_OSERR, "Unable to allocate memory for all entries");
	ptent = (ipfw_obj_tentry *)tent_buf;
	i = 0;
	if (table->vmask == 0)
		table->vmask = IPFW_VTYPE_LEGACY;

	STAILQ_FOREACH(l, &table->addrs_head, next) {
		if (compile_table_entry_new(table->vmask, l, ptent) != 0)
			return (1);
		ptent++;
		i++;
	}

	memset(&oh, 0, sizeof(oh));

	/* XXX: Use table number instead of name and set 0 */
	snprintf(table_name, sizeof(table_name), "%d", table->number);
	table_fill_ntlv(&oh.ntlv, table_name, 0, 1);
	oh.ntlv.type = table->type;
	oh.idx = 1;

	/* Create table */
	memset(&xi, 0, sizeof(xi));
	xi.type = table->type;
	xi.vmask = table->vmask;
	if (table->algo != NULL)
		strlcpy(xi.algoname, table->algo, sizeof(xi.algoname));

	if (fd) {
		write(*fd, &oh, sizeof(oh));
		write(*fd, &xi, sizeof(xi));
		write(*fd, tent_buf, count * sizeof(ipfw_obj_tentry));
		free(tent_buf);
		return (0);
	}

	error = table_do_create(s, &oh, &xi);
	if (error != 0) {
		fprintf(stderr, "Error creating table %d(%s) records: errno=%s\n",
			    table->number, table->name, strerror(errno));
		return (error);
	}

	error = table_do_modify_record(s, IP_FW_TABLE_XADD, &oh,
	    tent_buf, count, 0);
	if (error != 0 && errno != EEXIST) {
		fprintf(stderr, "Error installing table %d(%s) %d records: errno=%s\n",
			    table->number, table->name, count, strerror(errno));
		return (error);
	}

	_debug("%d item(s) installed", i);

	free(tent_buf);

	return (0);
}

int
ipfw_install_table(int s, struct table *table, int *fd)
{

	return (install_table_new(s, table, fd));
}

uint32_t
ipfw_tablearg(void)
{

	return (0);
}

/*
 * Compare things like interface or table names.
 */
static int
stringnum_cmp(const char *a, const char *b)
{
	int la, lb;

	la = strlen(a);
	lb = strlen(b);

	if (la > lb)
		return (1);
	else if (la < lb)
		return (-01);

	return (strcmp(a, b));
}

/*
 * Compare table names.
 * Honor number comparison.
 */
static int
tablename_cmp(const void *a, const void *b)
{
	const ipfw_xtable_info *ia, *ib;

	ia = (const ipfw_xtable_info *)a;
	ib = (const ipfw_xtable_info *)b;

	return (stringnum_cmp(ia->tablename, ib->tablename));
}

/*
 * Retrieves table list from kernel,
 * optionally sorts it and calls requested function for each table.
 * Returns 0 on success.
 */
int
tables_foreach(int s, table_cb_t *f, void *arg, int sort)
{
	ipfw_obj_lheader *olh;
	ipfw_xtable_info *info;
	size_t sz;
	uint32_t i;

	/* Start with reasonable default */
	sz = sizeof(*olh) + 16 * sizeof(ipfw_xtable_info);

	for (;;) {
		if ((olh = calloc(1, sz)) == NULL)
			return (ENOMEM);

		olh->size = sz;
		if (do_get3(s, IP_FW_TABLES_XLIST, &olh->opheader, &sz) != 0) {
			sz = olh->size;
			free(olh);
			if (errno != ENOMEM)
				return (errno);
			continue;
		}

		if (sort != 0)
			qsort(olh + 1, olh->count, olh->objsize,
			    tablename_cmp);

		info = (ipfw_xtable_info *)(olh + 1);
		for (i = 0; i < olh->count; i++) {
			(void)f(s, info, arg);
			info = (ipfw_xtable_info *)((caddr_t)info +
			    olh->objsize);
		}
		free(olh);
		break;
	}
	return (0);
}

/*
 * Destroys given table specified by @i.
 * Returns 0 on success.
 */
int
table_destroy(int s, ipfw_xtable_info *i)
{
	ipfw_obj_header oh;

	table_fill_ntlv(&oh.ntlv, i->tablename, i->set, 1);
	if (do_set3(s, IP_FW_TABLE_XDESTROY, &oh.opheader, sizeof(oh)) != 0)
		return (-1);

	return (0);
}

/*
 * Saves code that should be installed in ipfw cmd.
 */
uint32_t
pack_object(struct tidx *tstate, const char *name, int otype)
{

	return (pack_object_new(tstate, name, otype));
}

void
flush_ostate(struct tidx *ostate)
{
	struct _ipfw_obj_ntlv *idx;
	uint32_t size;

	idx = ostate->idx;
	size = ostate->size;

	bzero(ostate, sizeof(struct tidx));
	ostate->idx = idx;
	ostate->size = size;
	ostate->set = TMP_SET_NUM;
}

int
pack_table(struct tidx *tstate, const char *name, uint32_t *pnum)
{
	uint32_t num;

	if ((num = pack_object(tstate, name, IPFW_TLV_TBL_NAME)) != 0)
		*pnum = num;
	return (0);
}

int
ipfw_install_single_rule(int s, struct rule_info *info)
{

	return (install_single_rule_new(s, info));
}


/*
 * Check what (kernel) features we are using and
 * determine interface version to use.
 */
void
ipfw_init_ctl3(void)
{
	size_t len;
	int ctl3_present;

	len = sizeof(ctl3_present);
	if (sysctlbyname("kern.features.ipfw_ctl3",
	    &ctl3_present, &len, NULL, 0) != 0)
		errx(1, "ipfw_ctl3 feature required");
}

static int
do_range_cmd(int s, int cmd, ipfw_range_tlv *rt)
{
	ipfw_range_header rh;
	size_t sz;

	memset(&rh, 0, sizeof(rh));
	memcpy(&rh.range, rt, sizeof(*rt));
	rh.range.head.length = sizeof(*rt);
	rh.range.head.type = IPFW_TLV_RANGE;
	sz = sizeof(rh);

	if (do_get3(s, cmd, &rh.opheader, &sz) != 0)
		return (-1);
	/* Save number of matched objects */
	rt->new_set = rh.range.new_set;
	return (0);
}

int
ipfw_disable_set(int s, int set)
{
	ipfw_range_tlv rt;

	/*
	 * Номер set устанавливается на самом деле так: 1<<n.
	 * masks[0] - sets to disable, masks[1] - sets to enable.
	 */
	memset(&rt, 0, sizeof(rt));
	rt.set = 1 << set;
	rt.new_set = 0;
	return (do_range_cmd(s, IP_FW_SET_ENABLE, &rt) < 0);
}

int
ipfw_delete_set(int s, int set)
{
	ipfw_range_tlv rt;

	/* Удаляем set#1 на всякий случай, если там были правила */
	memset(&rt, 0, sizeof(rt));
	rt.flags = IPFW_RCFLAG_SET;
	rt.set = set & 31;
	return (do_range_cmd(s, IP_FW_XDEL, &rt) < 0);
}

int
ipfw_swap_sets(int s, int first, int second)
{
	ipfw_range_tlv rt;

	memset(&rt, 0, sizeof(rt));
	rt.set = first;
	rt.new_set = second;
	return (do_range_cmd(s, IP_FW_SET_SWAP, &rt) < 0);
}

/* n2mask sets n bits of the mask */
void
n2mask(struct in6_addr *mask, int n)
{
	static int	minimask[9] =
	    { 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff };
	u_char		*p;

	memset(mask, 0, sizeof(struct in6_addr));
	p = (u_char *) mask;
	for (; n > 0; p++, n -= 8) {
		if (n >= 8)
			*p = 0xff;
		else
			*p = minimask[n];
	}
}

typedef int (obj_cb_t)(int s, void *arg, uint8_t set);

#define	DEFINE_DESTROY_OBJ_CB(objtype, cfgtype)				\
static int								\
objtype##_destroy_cb(int s, void *arg, uint8_t set)			\
{									\
	ipfw_obj_header oh;						\
	cfgtype *cfg;							\
									\
	cfg = (cfgtype *)arg;						\
	if (cfg->set != set)						\
		return (ESRCH);						\
	memset(&oh, 0, sizeof(oh));					\
	fill_ntlv(&oh.ntlv, IPFW_TLV_EACTION_NAME(1), 1, cfg->name, set);\
	if (do_set3(s, IP_FW_##objtype##_DESTROY, &oh.opheader,		\
	    sizeof(oh)) != 0)						\
		warn("failed to destroy " #objtype " instance %s",	\
		    cfg->name);						\
	return (0);							\
}

DEFINE_DESTROY_OBJ_CB(NPTV6, ipfw_nptv6_cfg)
DEFINE_DESTROY_OBJ_CB(NAT64LSN, ipfw_nat64lsn_cfg)
DEFINE_DESTROY_OBJ_CB(NAT64STL, ipfw_nat64stl_cfg)
DEFINE_DESTROY_OBJ_CB(NAT64CLAT, ipfw_nat64clat_cfg)

static int
ipfw_obj_foreach(int s, int optname, size_t cfgsz, obj_cb_t *f, uint8_t set)
{
	ipfw_obj_lheader *olh;
	void *arg;
	size_t sz;
	int error __unused;
	u_int i;

	/* Start with reasonable default */
	sz = sizeof(*olh) + 16 * cfgsz;
	for (;;) {
		if ((olh = calloc(1, sz)) == NULL)
			return (ENOMEM);

		olh->size = sz;
		if (do_get3(s, optname, &olh->opheader, &sz) != 0) {
			sz = olh->size;
			free(olh);
			if (errno != ENOMEM)
				return (errno);
			continue;
		}

		arg = olh + 1;
		for (i = 0; i < olh->count; i++) {
			error = f(s, arg, set);
			arg = (char *)arg + olh->objsize;
		}
		free(olh);
		break;
	}
	return (0);
}

int
nptv6_destroy_all(int s, uint8_t set)
{

	return (ipfw_obj_foreach(s, IP_FW_NPTV6_LIST, sizeof(ipfw_nptv6_cfg),
	    NPTV6_destroy_cb, set));
}

int
nat_create(int s, void *buf, size_t sz)
{

	return (do_set3(s, IP_FW_NAT44_XCONFIG, (ip_fw3_opheader *)buf, sz));
}

int
nptv6_create(int s, void *buf, size_t sz)
{

	return (do_set3(s, IP_FW_NPTV6_CREATE, (ip_fw3_opheader *)buf, sz));
}

int
nat64stl_create(int s, void *buf, size_t sz)
{

	return (do_set3(s, IP_FW_NAT64STL_CREATE, (ip_fw3_opheader *)buf, sz));
}

void
nat64stl_fill_table(ipfw_obj_ntlv *ntlv, char *name, uint32_t uidx)
{

	printf("%s: %s -> %u\n", __func__, name, uidx);
	table_fill_ntlv(ntlv, name, 0, uidx);
}

int
nat64lsn_create(int s, void *buf, size_t sz)
{

	return (do_set3(s, IP_FW_NAT64LSN_CREATE, (ip_fw3_opheader *)buf, sz));
}

int
nat64clat_create(int s, void *buf, size_t sz)
{

	return (do_set3(s, IP_FW_NAT64CLAT_CREATE, (ip_fw3_opheader *)buf, sz));
}

int
nat64_destroy_all(int s, uint8_t set)
{
	int err;

	err = ipfw_obj_foreach(s, IP_FW_NAT64STL_LIST,
	    sizeof(ipfw_nat64stl_cfg), NAT64STL_destroy_cb, set);
	if (err != 0)
		return (err);
	err = ipfw_obj_foreach(s, IP_FW_NAT64LSN_LIST,
	    sizeof(ipfw_nat64lsn_cfg), NAT64LSN_destroy_cb, set);
	if (err != 0)
		return (err);
	err = ipfw_obj_foreach(s, IP_FW_NAT64CLAT_LIST,
	    sizeof(ipfw_nat64clat_cfg), NAT64CLAT_destroy_cb, set);
	return (err);
}

void
ipfw_enable_skipto_cache(int s, int op)
{
#ifdef IP_FW_SKIPTO_CACHE
	ipfw_cmd_header req;

	memset(&req, 0, sizeof(req));
	req.size = sizeof(req);
	req.cmd = op ? SKIPTO_CACHE_ENABLE : SKIPTO_CACHE_DISABLE;

	do_set3(s, IP_FW_SKIPTO_CACHE, &req.opheader, sizeof(req));
#endif
}

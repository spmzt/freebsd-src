/*
 * Copyright (c) 2007-2026 Yandex, LLC.
 *
 * SPDX-License-Identifier: BSD-4-Clause
 */

#include <stdbool.h>

/* Config variables */
#define	TMP_SET_NUM	1

enum fw_addr_type {
	ADDR_IPV4,
	ADDR_IPV6,
	ADDR_TABLE,
	ADDR_HOSTNAME,
	ADDR_IPV4MASK,
	ADDR_IPV6MASK,
	ADDR_IFACE,
	ADDR_NUMBER,
	ADDR_ME,
	ADDR_ME6,
};

struct addr_list {
	ipfw_insn_lookup tparam; /* table value match data for ADDR_TABLE */
	int is_not;
	int addr_type;
	in_addr_t ip, ipmask, value_nh;
	struct in6_addr ip6, ip6mask, value_nh6;
	char *hostname;
	char *label;
	uint32_t kidx;		/* table number */
	uint32_t masklen;	/* Mask lenght, e.g. /30 */
	uint32_t value;		/* Associated data */
	int line;
	STAILQ_ENTRY(addr_list) next;
};
STAILQ_HEAD(addr_list_head, addr_list);
STAILQ_HEAD(tables_head, table);
extern struct tables_head tables_head;

struct table {
	char		*name;	/* Table name */
	const char	*algo;	/* Table algo name */
	char		num_name[8]; /* number translated into a string */
	uint32_t	number;	/* Assigned table number */
	uint32_t	kidx;	/* kernel table index */
	int		resolved;	/* Is table resolved */
	int		used;	/* Is table referenced? */
	int		type;	/* Table type */
	int		set_num;/* Table set number */
	uint32_t	vmask;	/* Bitmask with value types */
	uint32_t	count4;	/* Number of items in table */
	uint32_t	count6;	/* Number of items in table */
	uint32_t	ifcount;/* Number of interface items */
	uint32_t	ncount;	/* Number of number:array items */
	unsigned int	line;
	struct addr_list_head	addrs_head; /* List of hosts in the table */
	STAILQ_HEAD(compiled_head, table_xentry)	compiled_head;	/* List of addresses in the table */
	STAILQ_ENTRY(table) gnext; /* global tables list */
	STAILQ_ENTRY(table) hnext; /* per-hash tables list */
};

struct table_xentry {
	ip_fw3_opheader		op;
	ipfw_table_xentry	xentry;
	STAILQ_ENTRY(table_xentry)	next;
};

typedef int (table_cb_t)(int s, ipfw_xtable_info *i, void *arg);
int tables_foreach(int s, table_cb_t *f, void *arg, int sort);

extern int named_states, external_actions;

void init_tables(void);
void resolve_table(struct table *t);
uint32_t table_get_empty_num_name(void);


struct fw_rule {
	int	len;
	void	*rule;
};
void dummynet_init(void);
SLIST_HEAD(labels_head, labels);
extern struct labels_head labels_head;
struct labels {
	const char		*name;
	ipfw_insn_u32	*pact;
	struct table_xentry	*xe;
	unsigned int	line;
	unsigned int	number;	/* allocated number */
	SLIST_ENTRY(labels) next;
};

void profile_stage(const char *text);
void yyerror(const char *s, ...);
unsigned int get_label_number(const char *name);

/* modules load */
#define	KLD_ipfw_nat	0
#define	KLD_ipfw_nat64	1
#define	KLD_ipfw_nptv6	2
#define	KLD_ipfw_pmod	3
#define	KLD_ipdivert	4
#define	KLD_dummynet	5
#define	KLD_NUMMODULES	6
extern char *module_load[];

/* resolver.c */
void init_resolver(char *read_file, char *write_file, int do_dns_queries);
struct addrinfo *y_gethostbyname(const char *name);
void dump_namecache(void);

/* main.c variables */
struct rule_info {
	struct ip_fw_rule	*rule;
	size_t			sz;
	int			line;
};

void nat_init(void);
extern int line, rule_step, quiet, debug, ignore_unresolved;
extern int only_test, unclean_test, enable_ipv6, optimize_level;
extern struct rule_info rules[];
extern struct fw_rule dummynet_rules[];
extern struct fw_rule nat_rules[];
extern struct fw_rule nptv6_rules[];
extern struct fw_rule nat64lsn_rules[];
extern struct fw_rule nat64stl_rules[];
extern struct fw_rule nat64clat_rules[];
extern int rule_count, dummynet_count, nat_count, table_count,
    nptv6_count, nat64lsn_count, nat64stl_count, nat64clat_count;
extern uint32_t rule_num;
extern int verbose_limit;
extern int iface_version;
extern int maxfibs;

/* fw-interface.c */
int nat_create(int s, void *buf, size_t sz);

void nptv6_init(void);
int nptv6_create(int s, void *buf, size_t sz);
int nptv6_destroy_all(int s, uint8_t set);

void nat64_init(void);
int nat64_destroy_all(int s, uint8_t set);
int nat64stl_create(int s, void *buf, size_t sz);
void nat64stl_fill_table(ipfw_obj_ntlv *ntlv, char *name, uint32_t uidx);
int nat64lsn_create(int s, void *buf, size_t sz);
int nat64clat_create(int s, void *buf, size_t sz);

/* ipfw2 pack_object */
struct _ipfw_obj_ntlv;
struct tidx {
	struct _ipfw_obj_ntlv *idx;
	uint32_t count;
	uint32_t size;
	uint16_t counter;
	uint8_t set;
};

int ipfw_install_table(int s, struct table *table, int *fd);
int tables_foreach(int s, table_cb_t *f, void *arg, int sort);
int table_destroy(int s, ipfw_xtable_info *i);
int ipfw_disable_set(int s, int set);
int ipfw_disable_set(int s, int set);
int ipfw_delete_set(int s, int set);
int ipfw_swap_sets(int s, int one, int two);
void ipfw_init_ctl3(void);
void *encap_single_rule(const struct ip_fw_rule *rule, struct tidx *ostate,
    ipfw_insn **act_ptr, size_t *psz);
int ipfw_install_single_rule(int s, struct rule_info *info);
uint32_t pack_object(struct tidx *tstate, const char *name, int otype);
int pack_table(struct tidx *tstate, const char *name, uint32_t *pnum);
void flush_ostate(struct tidx *ostate);
uint32_t ipfw_tablearg(void);
void n2mask(struct in6_addr *mask, int n);
void ipfw_enable_skipto_cache(int s, int op);

void fwerr(int code, const char *fmt, ...);

/* Debug variables */
void fdebug(const char *fname, int line, const char *fmt, ...);
#define	_debug(fmt, ...)	if (debug)	\
	fdebug(__FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)

/* static variables */
#define MAX_RULESIZE	512
#define LARGE_NUMINSN	65536

/* Eliminate compiler warning */
#define	YY_NO_UNPUT

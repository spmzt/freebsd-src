/*
 * Copyright (c) 2007-2026 Yandex, LLC.
 *
 * SPDX-License-Identifier: BSD-4-Clause
 */

/* do not generate functions that will not be used */
%option nomain noinput nounput noyywrap

%{
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

#include "y.tab.h"

extern int quiet, line;

int yylex(void);

static void
print_bar(void)
{
	if(!quiet) {
	    if(line%500 == 0)
		printf(".");
	    if(line > 0 && line%5000 == 0)
		printf("%d", line);
	    fflush(stdout);
	}
}

%}

digit	[0-9]
digits	{digit}+
float	{digits}\.{digits}
hexdigit [0-9a-fA-F]
hexdecnumber	(0x{hexdigit}+|{digits})
octet	{digit}{1,3}
ip4	({octet}\.){3}{octet}
network	{ip4}\/{digit}+
hexadecatet {hexdigit}{1,4}
lu32	({hexadecatet}:{hexadecatet}|{ip4})
ip6	(({hexadecatet}:){6}{lu32})|(::({hexadecatet}:){5}{lu32})|(({hexadecatet}?)::({hexadecatet}:){4}{lu32})|((({hexadecatet}:){0,1}{hexadecatet})?::(({hexadecatet}:){3}{lu32}))|((({hexadecatet}:){0,2}{hexadecatet})?::(({hexadecatet}:){2}{lu32}))|((({hexadecatet}:){0,3}{hexadecatet})?::({hexadecatet}:{lu32}))|((({hexadecatet}:){0,4}{hexadecatet})?::{lu32})|((({hexadecatet}:){0,5}{hexadecatet})?::{hexadecatet})|((({hexadecatet}:){0,6}{hexadecatet})?::)
ip6scopied	{ip6}%[a-zA-Z0-9._]+
network6 {ip6}\/{digit}+
label	:[-0-9a-zA-Z_]+

%%
{label}			{ strcpy(yylval.sval, yytext); return LABEL; }
add			return ADD;
allow|accept|pass|permit	return ALLOW;
deny_in			return DENY_IN;
deny|drop		return DENY;
reject			return REJECTT;
unreach			return UNREACH;
unreach6		return UNREACH6;
skipto			return SKIPTO;
divert			return DIVERT;
tee			return TEE;
count			return COUNT;
setipprec		return SETIPPREC;
setdscp			return SETDSCP;
setfib			return SETFIB;
dscp			return DSCP;
dscp:			return DSCPCOLON;
call			return CALL;
return			return RETURN;
cs[0-7]|af[1-4][1-3]|ef|be	{ strcpy(yylval.sval, yytext); return DSCPSPEC; }
tag			return TAG;
untag			return UNTAG;
tagged			return TAGGED;
altq			return ALTQ;
pipe			return PIPE;
queue|flowset		return QUEUE;
reass			return REASS;
config			return CONFIG;
bw|bandwidth		return BW;
weight			return WEIGHT;
buckets			return BUCKETS;
mask			return MASK;
sched_mask		return SCHEDMASK;
noerror			return NOERROR;
plr			return PLR;
gred|red		{ strcpy(yylval.sval, yytext); return RED; }
droptail		return DROPTAIL;
flow-id			return FLOWID;
delay			return PDELAY;
lmax|maxlen		{ strcpy(yylval.sval, yytext); return LMAX; }
sched			return SCHED;
flow_mask		return FLOWMASK;
link			return LINK;
pri|priority		return PRIORITY;
type			return TYPE;
valtype			return VALTYPE;
algo			return ALGO;
[a-z]+:[a-z]+		{ strcpy(yylval.sval, yytext); return ALGO_NAME; }
fib			return FIB;
dst-ip6|dst-ipv6	{ strcpy(yylval.sval, yytext); return DSTIP6; }
src-ip6|src-ipv6	{ strcpy(yylval.sval, yytext); return SRCIP6; }
profile			return PROFILE;
burst			return BURST;
check-state		return CHECKSTATE;
fwd|forward		return FWD;
log			return LOG;
logamount		return LOGAMOUNT;
logdst			return LOGDST;
setup			return SETUP;
established		return ESTABLISHED;
frag			return FRAG;
mf			return MF;
rf			return RF;
df			return DF;
offset			return OFFSET;
keep-state		return KEEPSTATE;
icmptype|icmptypes	return ICMPTYPES;
icmp6type|icmp6types	return ICMP6TYPES;
from			return FROM;
to			return TO;
me			return ME;
me6			return ME6;
any			return ANY;
in			return IN;
out			return OUT;
via			return VIA;
xmit			return XMIT;
recv			return RECV;
or			return OR;
not			return NOT;
limit			return LIMIT;
table			return TABLE;
tcpflags		return TCPFLAGS;
tcpoptions		return TCPOPTIONS;
tcp-setmss		{ strcpy(yylval.sval, yytext); return TCPSETMSS; }
ip			return T_IP;
ip4			return T_IP4;
ip6			return T_IP6;
iplen			return IPLEN;
ipid			return IPID;
ipoptions		return IPOPTIONS;
iptos			return IPTOS;
ipttl			return IPTTL;
tcpdatalen		return TCPDATALEN;
tcpseq			return TCPSEQ;
tcpwin			return TCPWIN;
fin			return FIN;
syn			return SYN;
rst			return RST;
psh			return PSH;
ack			return ACK;
urg			return URG;
mss			return MSS;
tcpmss			return TCPMSS;
window			return WINDOW;
sack			return SACK;
ts			return TS;
cc			return CC;
ssrr			return SSRR;
lsrr			return LSRR;
rr			return RR;
lowdelay		return LOWDELAY;
throughput		return THROUGHPUT;
reliability		return RELIABILITY;
mincost			return MINCOST;
congestion		return CONGESTION;
net			return NET;
host			return HOST;
proto			return PROTO;
port			return PORT;
needfrag		return NEEDFRAG;
srcfail			return SRCFAIL;
net-unknown		return NETUNKNOWN;
host-unknown		return HOSTUNKNOWN;
isolated		return ISOLATED;
net-prohib		return NETPROHIB;
host-prohib		return HOSTPROHIB;
tosnet			return TOSNET;
toshost			return TOSHOST;
filter-prohib		return FILTERPROHIB;
host-precedence		return HOSTPRECEDENCE;
precedence-cutoff	return PRECEDENCECUTOFF;
diverted-loopback	return DIVERTEDLOOPBACK;
diverted-output		return DIVERTEDOUTPUT;
diverted		return DIVERTED;
nat			return NAT;
nh4			return NH4;
nh6			return NH6;
netgraph		return NETGRAPH;
same_ports		return SAME_PORTS;
if			return IF;
unreg_only		return UNREG_ONLY;
verrevpath		return VERREVPATH;
versrcreach		return VERSRCREACH;
antispoof		return ANTISPOOF;
reset			return RESET;
reset6			return RESET6;
reverse			return REVERSE;
proxy_only		return PROXY_ONLY;
redirect_addr		return REDIRECT_ADDR;
redirect_port		return REDIRECT_PORT;
redirect_proto		return REDIRECT_PROTO;
skip_global		return SKIP_GLOBAL;
global			return GLOBAL;
ext6hdr			return EXT6HDR;
hopopt			return HOPOPT;
route			return ROUTE;
dstopt			return DSTOPT;
ah			return AH;
esp			return ESP;
rthdr0			return RTHDR0;
rthdr2			return RTHDR2;
ipsec			return IPSEC;
ipversion		return IPVER;
create			return CREATE;
addr			return ADDR;
iface			return IFACE;
number			return TOK_NUMBER;
flow			return FLOW;
tablearg		return TABLEARG;
tablearg:		return TABLEARGCOLON;
nat64clat		{ strcpy(yylval.sval, yytext); return NAT64CLAT; }
nat64lsn		{ strcpy(yylval.sval, yytext); return NAT64LSN; }
nat64stl		{ strcpy(yylval.sval, yytext); return NAT64STL; }
nptv6			{ strcpy(yylval.sval, yytext); return NPTV6; }
plat_prefix		return PLAT_PREFIX;
clat_prefix		return CLAT_PREFIX;
allow_private		return ALLOW_PRIVATE;
int_prefix		return INT_PREFIX;
ext_prefix		return EXT_PREFIX;
prefixlen		return PREFIXLEN;
prefix4			return PREFIX4;
prefix6			return PREFIX6;
agg_len			return AGG_LEN;
agg_count		return AGG_COUNT;
max_ports		return MAX_PORTS;
states_chunks		return STATES_CHUNKS;
jail			return JAIL;
jail:			return JAILCOLON;
jmaxlen			return JMAXLEN;
port_range		return PORT_RANGE;
nh_del_age		return NH_DEL_AGE;
host_del_age		return NH_DEL_AGE;
pg_del_age		return PG_DEL_AGE;
tcp_syn_age		return TCP_SYN_AGE;
tcp_est_age		return TCP_EST_AGE;
tcp_close_age		return TCP_CLOSE_AGE;
udp_age			return UDP_AGE;
icmp_age		return ICMP_AGE;
table4			return TABLE4;
table6			return TABLE6;
swap_conf		return SWAP_CONF;
layer2			return LAYER2;
mac			return MAC;
src-mac			return SRCMAC;
dst-mac			return DSTMAC;
!			return NOTCHAR;
lookup			return LOOKUP;
uid			return UID;
uid:			return UIDCOLON;
rulenum			return RULENUM;
rulenum:		return RULENUMCOLON;
src-addr		{ strcpy(yylval.sval, yytext); return SRCADDR; }
dst-addr		{ strcpy(yylval.sval, yytext); return DSTADDR; }
src-port		{ strcpy(yylval.sval, yytext); return SRCPORT; }
src-port:		{ strcpy(yylval.sval, yytext); return SRCPORTCOLON; }
dst-port		{ strcpy(yylval.sval, yytext); return DSTPORT; }
dst-port:		{ strcpy(yylval.sval, yytext); return DSTPORTCOLON; }
dst-ip			{ strcpy(yylval.sval, yytext); return DSTIP; }
src-ip			{ strcpy(yylval.sval, yytext); return SRCIP; }
dst-ip4			return DSTIP4;
src-ip4			return SRCIP4;
dst-ip4:		return DSTIP4COLON;
src-ip4:		return SRCIP4COLON;
dst-ip6:		return DSTIP6COLON;
src-ip6:		return SRCIP6COLON;
mark			return MARK;
mark:			return MARKCOLON;
setmark			return SETMARK;
\{			return OBRACE;
\}			return EBRACE;
\(			return LBRACE;
\)			return RBRACE;
=			return EQUAL;
{ip4}			{ strcpy(yylval.sval, yytext); return IP; }
{ip4}:{ip4}		{ strcpy(yylval.sval, yytext); return IPMASK; }
{ip4}:{digits}		{ strcpy(yylval.sval, yytext); return SOCKADDR4; }
{ip6}			{ strcpy(yylval.sval, yytext); return IP6; }
{ip6}\/{ip6}		{ strcpy(yylval.sval, yytext); return IP6MASK; }
{ip6scopied}		{ strcpy(yylval.sval, yytext); return IP6SCOPIED; }
all			{ strcpy(yylval.sval, "all"); return ALL; }
{network}		{ strcpy(yylval.sval, yytext); return NETWORK; }
{network6}		{ strcpy(yylval.sval, yytext); return NETWORK6; }
{digits}-{digits}	{ strncpy(yylval.sval, yytext, MAX_TOKEN-1); return RANGE; };
,			return COMMA;
-			return MINUS;
{float}\/{digits}[Kk]\/{digits}[Kk]\/{float}	{ strcpy(yylval.sval, yytext); return REDPARAM; }
{float}			{ yylval.fval = strtof(yytext, NULL); return FLOAT; }
\/{digits}		{ yylval.ival = strtol(yytext+1, NULL, 10); return MASKLEN; }
{digits}[Bb]it\/s		{ yylval.ival = strtol(yytext, NULL, 10); return BWBS; }
{digits}[Bb]yte\/s		{ yylval.ival = strtol(yytext, NULL, 10); return BWBTS; }
{digits}[Kk][Bb]it\/s	{ yylval.ival = strtol(yytext, NULL, 10); return BWKBS; }
{digits}[Kk][Bb]yte\/s	{ yylval.ival = strtol(yytext, NULL, 10); return BWKBTS; }
{digits}[Mm][Bb]it\/s	{ yylval.ival = strtol(yytext, NULL, 10); return BWMBS; }
{digits}[Mm][Bb]yte\/s	{ yylval.ival = strtol(yytext, NULL, 10); return BWMBTS; }
{digits}[Bb]ytes	{ yylval.ival = strtol(yytext, NULL, 10); return SIZEK; }
{digits}[Kk][Bb]ytes	{ yylval.ival = strtol(yytext, NULL, 10)*1024; return SIZEK; }
{hexdecnumber}		{ yylval.ival = strtol(yytext, NULL, 0); return NUMBER; }
{hexdecnumber}:		{ yylval.ival = strtol(yytext, NULL, 0); return NUMBERCOLON; }
[a-zA-Z0-9][-\\a-zA-Z0-9\?\*\[\]_]+	{ strncpy(yylval.sval, yytext, MAX_TOKEN-1); return TOKEN; }
[a-zA-Z0-9][-\.a-zA-Z0-9]+	{ strncpy(yylval.sval, yytext, MAX_TOKEN-1); return FQDN; }
\/\/[ ][^\n]*			{ strncpy(yylval.sval, yytext+3, MAX_TOKEN-1); return COMMENT; }
_[\_\-\.a-zA-Z0-9]+_	{ strncpy(yylval.sval, yytext, MAX_TOKEN-1); return TABLENAME; }
([a-fA-F0-9]{1,2}:){5}[a-fA-F0-9]{1,2}	{ strcpy(yylval.sval, yytext); return MACADDR; }
#.*\n			{ line++; print_bar(); /* ignore comments */ };
[ \t]+			/* ignore spaces */;
^[ \t]*\n		{ line++; print_bar(); /* ignore empty lines */ };
\n			{ line++; print_bar(); return EOL; }
.			{ printf("Invalid character: %s, line: %d\n", yytext, line); exit(1); }
%%

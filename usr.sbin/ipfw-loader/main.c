/*
 * Copyright (c) 2007-2026 Yandex, LLC.
 *
 * SPDX-License-Identifier: BSD-4-Clause
 */

#include <sys/param.h>
#include <sys/linker.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip_fw.h>
#include <sys/queue.h>
#include <netinet/ip_dummynet.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <libutil.h>
#include <bitstring.h>

#include "fw-parse.h"

#define MAX_RULES	65536 * 8

uint32_t rule_num;
int line=1, rule_step=2, quiet=0, debug=0;
int ignore_unresolved=0, only_test=0;
int unclean_test=0, enable_ipv6=0, optimize_level=0;
int rule_count=0, dummynet_count=0, nat_count=0, table_count=0;
int nptv6_count=0, nat64lsn_count=0, nat64stl_count=0, nat64clat_count=0;
int verbose_limit = 0;	/* Default ipfw verbose limit */
int iface_version = 1; /* ipfw interface version to use */
int named_states = 0;
int maxfibs = 1;
static int do_kldload=1, save_binary=0;
static int table_lower = 1, table_upper = 131071;
struct rule_info rules[MAX_RULES];
struct fw_rule dummynet_rules[MAX_RULES];
struct fw_rule nat_rules[MAX_RULES];
struct fw_rule nptv6_rules[MAX_RULES];
struct fw_rule nat64lsn_rules[MAX_RULES];
struct fw_rule nat64stl_rules[MAX_RULES];
struct fw_rule nat64clat_rules[MAX_RULES];
char *module_load[KLD_NUMMODULES];
#define	IS_KLD_LOADED(MODNAME) (module_load[KLD_##MODNAME] != NULL)

/* FIXME Add support for set-bound tables */
static bitstr_t bit_decl(num_name_table_index, IPFW_TABLES_MAX);

int yyparse(void);

static void
help(void) {

	fprintf(stderr, "Using: ipfw-loader [-h] [-d] [-b m] [-s n] [-t] "
"[-q] [-6] [-L] [<file_name>]\n"
"-h		Help. This page.\n"
"-c file_name	Read DNS cache from file.\n"
"-C file_name	Write DNS cache to file.\n"
"-b m		Rule number base. Default is 0. First rule will "
"numbered as m+n.\n"
"-d		Debug mode.\n"
"-i		Ignore rules with unresolved FDQN.\n"
"-D		Use DNS cache only, do not perform any name resolutions though network\n"
"-I ver		kernel interface version.\n"
"-S file_name	Save binary data for ipfw(8) inside this file.\n"
"-s n		Rule increment step. Default is 2.\n"
"-t		Parse and load rules without install (test mode).\n"
"-T lower:upper Table space to use.\n"
"-M file_name	Save mapping of table names to numbers into this file.\n"
"-O n		Level of optimization. Default is 0 (off).\n"
"-q		Be quiet. No output at all.\n"
"-6		Enable IPv6.\n"
"-L		disable automatic kernel modules loading.\n"
"file_name	file with rules for loading. stdin if ommitted.\n");
	exit(0);
}

#define	ERRX(code, ...)	do {			\
	fwerr(code, __VA_ARGS__);		\
} while (0)

#define	ERRXFW(code, s, ...)	do {		\
	ipfw_enable_skipto_cache((s), 1);		\
	ERRX(code, __VA_ARGS__);		\
} while (0)

void
fwerr(int code, const char *fmt, ...)
{
	va_list ap, lap;

	va_start(ap, fmt);
	va_copy(lap, ap);

	fprintf(stderr, "\n");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);

	vsyslog(LOG_ERR, fmt, lap);
	va_end(lap);
	closelog();				\
	exit(code);
}

static void
kldload_needed_modules(void)
{
	int i;
	char *module;

	for (i = 0; i < KLD_NUMMODULES; i++) {
		module = module_load[i];
		/* we do not need this module at all */
		if (module == NULL)
			continue;

		if (do_kldload == 0 && kldfind(module) == -1) {
			ERRX(1, "%s is not loaded but is used in rules",
			    module);
		}

		if (kldload(module) == -1) {
			if (errno != EEXIST) {
				ERRX(1, "failed loding %s: %s", module,
				    strerror(errno));
			}
		} else if (!quiet) {
			fprintf(stderr, "Loaded KLD module '%s'\n", module);
			fflush(stderr);
		}
	}
}


static int
table_mark_present(int s __unused, ipfw_xtable_info *i, void *arg)
{
	bitstr_t *tindex = (bitstr_t *)arg;
	long long table_number;
	const char *errstr;

        table_number = strtonum(i->tablename, table_lower, table_upper,
            &errstr);
        if (errstr != NULL) {
                _debug("skip table(%s) set %u: table id is %s", i->tablename,
                    i->set, errstr);
                return (0);
        }

        table_number -= table_lower;
	bit_set(tindex, table_number);

	return (1);
}


static void
table_fill_spare_numbers(void)
{
	int s;
	ssize_t value;

	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		errx(1, "socket error");

	bit_nclear(num_name_table_index, 0, IPFW_TABLES_MAX);

	tables_foreach(s, table_mark_present, num_name_table_index, 0);
	if (debug) {
		bit_count(num_name_table_index, 0, IPFW_TABLES_MAX, &value);
		_debug("Registered %zd numbered tables", value);
	}

	close(s);
}

uint32_t
table_get_empty_num_name(void)
{
	ssize_t value;

	bit_ffc(num_name_table_index, IPFW_TABLES_MAX, &value);
	if (value < 0 || value > table_upper - table_lower)
		return (0);
	bit_set(num_name_table_index, value);
	return (table_lower + (uint32_t)value);
}

static int
table_destroy_if_unref(int s, ipfw_xtable_info *i, void *arg)
{
	const char *errstr;
	size_t *delete_count = arg;

	if (i->refcnt > 0) {
		_debug("skip destroying table(%s) in set %u: non-zero refcnt",
		    i->tablename, i->set);
		return (-1);
	}

        strtonum(i->tablename, table_lower, table_upper, &errstr);
        if (errstr != NULL) {
                _debug("skip table(%s) set %u: table id is %s", i->tablename,
                    i->set, errstr);
                return (0);
        }

	if (table_destroy(s, i) != 0) {
		warn("failed to destroy table(%s) in set %u", i->tablename,
		    i->set);
		return (-1);
	}
	if (delete_count != NULL) {
		*delete_count += 1;
	}
	return (0);
}

int
main(int argc, char *argv[])
{
	char *d, *table_map_fname = NULL;
	int tmap_fd = 0; /* table name map output file descriptor */
	int bf = -1, i, f, s;
	char ch;
	struct labels *label_entry;
	struct pidfh *pfh = NULL;
	char *binary_fname = NULL;
	size_t slen, tables_deleted;
	pid_t opid;
	char *read_cache = NULL, *write_cache = NULL;
	int do_dns_queries = 1;

	openlog("ipfw-loader", LOG_CONS, LOG_AUTH | LOG_SECURITY);
	while((ch = getopt(argc, argv, "b:dhiDI:S:s:tT:q6k:M:O:c:C:L")) != -1) {
		switch(ch) {
		case 'b':
			rule_num = atoi(optarg);
			break;
		case 'd':
			debug = 1;
			break;
		case 'h':
		case '?':
		default:
			help();
			/* Never reached */
		case 'i':
			ignore_unresolved = 1;
			break;
		case 'D':
			do_dns_queries = 0;
			break;
		case 'I':
			iface_version = atoi(optarg);
			break;
		case 'S':
			save_binary = 1;
			binary_fname = optarg;
			break;
		case 's':
			rule_step = atoi(optarg);
			break;
		case 't':
			only_test = 1;
			break;
		case 'T':
			if ((d = strchr(optarg, ':')))
				table_upper = atoi(d + 1);
			table_lower = atoi(optarg);
			if ((table_lower < 1) ||
			    (table_lower >= table_upper) ||
			    (table_upper > 131072))
				ERRX(1, "Invalid table range. "
				    "Valid rannge is 1...131072");
			break;
		case 'q':
			quiet = 1;
			break;
		case '6':
			enable_ipv6 = 1;
			break;
		case 'k':
			iface_version = strtol(optarg, NULL, 10);
		case 'M':
			table_map_fname = optarg;
			break;
		case 'O':
			optimize_level = atoi(optarg);
			break;
		case 'c':
			read_cache = optarg;
			break;
		case 'C':
			write_cache = optarg;
			break;
		case 'L':
			do_kldload = 0;
			break;
		}
	}
	argc -= optind-1;
	argv += optind-1;

	if(argc > 1) {
		_debug("using file: %s", argv[1]);
		f = open(argv[1], O_RDONLY);
		if(f == -1)
			ERRX(1, "Can't open file: %s", argv[1]);
		close(0);
		dup(f);
		close(f);
	}

	if(!only_test) {
		/* Create a PID file and check if we already run */
		if ((pfh = pidfile_open("/var/run/ipfw-loader.pid", 0644,
		    &opid)) == NULL) {
			if (errno == EEXIST)
				ERRX(1, "Already run with PID %d. Exiting.",
				    opid);
			ERRX(1, "Can't create PID file");
		}
		pidfile_write(pfh);
		if (save_binary) {
			bf = open(binary_fname, O_WRONLY|O_TRUNC|O_CREAT);
			if(bf == -1)
				ERRX(1, "Can't open file: %s", binary_fname);
			if (fchmod(bf, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP) != 0) {
				ERRX(1, "chmod(%) failed: %s", binary_fname,
				    strerror(errno));
			}
		}
	}

	/*
	 * Read verbose limit. Fail IFF ipfw is not loaded and we're
	 * not running in bootstrap mode.
	 */
	slen = sizeof(verbose_limit);
	if ((sysctlbyname("net.inet.ip.fw.verbose_limit", &verbose_limit,
	    &slen, NULL, 0) == -1) && (save_binary == 0)) {
		ERRX(1, "\nsysctlbyname(\"%s\")",
		    "net.inet.ip.fw.verbose_limit");
	}
#if	__FreeBSD_version >= 1300000
	named_states = 1;
#else
	slen = sizeof(named_states);
	if (sysctlbyname("net.inet.ip.fw.named_states", &named_states,
	    &slen, NULL, 0) != 0)
		named_states = 0;
#endif
	slen = sizeof(maxfibs);
	if (sysctlbyname("net.fibs", &maxfibs, &slen, NULL, 0) != 0)
		maxfibs = 1;

	bzero(module_load, sizeof(module_load));

	syslog(LOG_NOTICE, "loading file %s", argv[1] ? argv[1]: "STDIN");

	_debug("verbose limit set to %d", verbose_limit);
	profile_stage("start");
	init_tables();
	table_fill_spare_numbers();
	init_resolver(read_cache, write_cache, do_dns_queries);
	profile_stage("resolver");

	if(!quiet) {
		fprintf(stderr,"Checking and loading rules\n");
		fflush(stdout);
	}
	nat_init();
	nptv6_init();
	nat64_init();
	dummynet_init();
	ipfw_init_ctl3();
	yyparse();
	fprintf(stderr, "\n");
	profile_stage("yyparse");

	/* Resolve tables */
	struct table *table;
	STAILQ_FOREACH(table, &tables_head, gnext) {
		if (table->used > 0)
			resolve_table(table);
	}
	profile_stage("tresolve");
	if (unclean_test) {
		yyerror("Some name resolving issues were found, "
		    "loading rules failed");
	}

	dump_namecache();
	profile_stage("nscache");

	/* Check for unresolved labels */
	SLIST_FOREACH(label_entry, &labels_head, next) {
		if (label_entry->pact != NULL &&
		    label_entry->pact->d[0] == 0) {
			if(!only_test)
				pidfile_remove(pfh);
			ERRX(1, "Unresolved label '%s' at line %u",
			    label_entry->name, label_entry->line);
		}
	}

	syslog(LOG_INFO, "lines processed: %d", line);
	syslog(LOG_INFO, "rules loaded: %d", rule_count);
	syslog(LOG_INFO, "dummynet rules loaded: %d", dummynet_count);
	syslog(LOG_INFO, "NAT rules loaded: %d", nat_count);
	if (!quiet)
		printf(" done.\nLines processed: %d\nRules loaded: %d\n"
		    "Dummynet rules loaded: %d\nNAT rules loaded: %d\n",
		    line--, rule_count, dummynet_count, nat_count);

	if(!only_test) {
		/* Сохраняем правила в бинарном формате в файл */
		if (save_binary) {
			/* Проходим по всем правилам и загружаем их */
			for (i = 0; i < rule_count; i++) {
				if (debug)
					printf("rule opcodes len: %zu\n",
					    rules[i].sz);
				if (write(bf, rules[i].rule,
				    rules[i].sz) == -1) {
					pidfile_remove(pfh);
					ERRX(1, "file write error. line: %d "
					    "(rule #%d)  err=%d (opcode=%d)\n",
					    rules[i].line - 1, i + 1, errno,
					    rules[i].rule->cmd->opcode);
				}
				if (!quiet) {
					if (i % 500 == 0)
						printf(".");
					if (i > 0 && i % 5000 == 0)
						printf("%d", i);
					fflush(stdout);
				}
			}
			printf("%d\nRules dump end at offset %#lx\n", i,
			    lseek(bf, 0, SEEK_CUR));
			fflush(stdout);
			if(!quiet) {
				fprintf(stderr,"Checking and loading tables\n");
			}
			/* Проходим по всем таблицам и загружаем их */
			i = 0;
			STAILQ_FOREACH(table, &tables_head, gnext) {
				if (table->used == 0)
					continue;
				if (ipfw_install_table(-1, table, &bf) != 0) {
					pidfile_remove(pfh);
					ERRX(1, "file write error. table number"" %d (%s)",
					    table->number, table->name);
				}
				if (!quiet) {
					if (i % 100 == 0)
						printf(".");
					if (i > 0 && i % 1000 == 0)
						printf("%d", i);
					fflush(stdout);
				}
				i++;
			}
			printf("%d\nTables dump end at offset %#lx\n", i,
			    lseek(bf, 0, SEEK_CUR));
			fflush(stdout);

#define OBJDUMP_WALKER(PREFIX) \
			for (i = 0; i < PREFIX ## _count; i++) { \
				if (write(bf, PREFIX ## _rules[i].rule, \
				    PREFIX ## _rules[i].len) == -1) { \
					pidfile_remove(pfh); \
					ERRX(1, "file write error. " #PREFIX \
					    " number %d", i); \
				} \
			};

			OBJDUMP_WALKER(nat64lsn);
			OBJDUMP_WALKER(nat64stl);
			OBJDUMP_WALKER(nat64clat);
			OBJDUMP_WALKER(nptv6);
			OBJDUMP_WALKER(dummynet);
			OBJDUMP_WALKER(nat);

			close(bf);
			pidfile_remove(pfh);
			return (0);
		}

		if (geteuid() > 0) {
			pidfile_remove(pfh);
			ERRX(1, "You're not root. Not enought right to "
			    "install rules.");
		}

		/* load modules referenced but not loaded prior to ipfw-loader run */
		kldload_needed_modules();

		if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
			pidfile_remove(pfh);
			errx(1, "socket error");
		}
		/* Install tables */
		table = NULL;
		/* open table map output file */
		if (table_map_fname) {
			tmap_fd = open(table_map_fname,
			    O_WRONLY | O_TRUNC | O_CREAT);
			if (tmap_fd == -1) {
				warn("open %s", table_map_fname);
				tmap_fd = 0;
			}
		}
		STAILQ_FOREACH(table, &tables_head, gnext) {
			if (table->used == 0)
				continue;
			if (debug)
				fprintf(stderr,
				    "Installing table number %d (%s)\n",
				    table->number, table->name);
			/* write into table map file */
			if (tmap_fd) {
				char buff[BUFSIZ];
				int len = snprintf(buff, sizeof(buff),
				    "%d %s\n", table->number, table->name);
				if (len < 0)
					err(1, "snprintf");
				else if ((unsigned int)len < sizeof(buff)) {
					char *buff_to_write = buff;
					while (len > 0) {
						int written = write(tmap_fd,
						    buff_to_write, len);
						if (written == -1) {
							if (errno == EINTR)
								continue;
							err(1, "write");
						}
						len -= written;
						buff_to_write += written;
					}
				}
			}
			/*
			 * Ignore errors when table number is not within
			 * -T range.
			 */
			if (ipfw_install_table(s, table, NULL) != 0 &&
			    table->number >= (uint32_t)table_lower &&
			    table->number <= (uint32_t)table_upper)
				err(1, "Error installing table");
		}
		if (tmap_fd)
			close(tmap_fd);
		if (rule_count > 0 || nat64lsn_count > 0 ||
		    nat64stl_count > 0 || nptv6_count > 0 ||
		    nat64clat_count > 0) {
			/*
			 * Готовим set #1. Сначала disable it, потом загружаем
			 * туда правила, потом делаем swap 0 1. Наши правила
			 * становятся активными. После этого удаляем set #1,
			 * в котором остались старые правила.
			 */
			if (ipfw_disable_set(s, TMP_SET_NUM) != 0)
				ERRX(1, "can't disable set %d", TMP_SET_NUM);

			ipfw_enable_skipto_cache(s, 0);

			/* Удаляем set#1 на случай, если там были правила */
			ipfw_delete_set(s, TMP_SET_NUM);

			/* Delete objects from set #1 */
			if (IS_KLD_LOADED(ipfw_nptv6) > 0)
				nptv6_destroy_all(s, 1);
			if (IS_KLD_LOADED(ipfw_nat64) > 0)
				nat64_destroy_all(s, 1);

			/* Create objects before installing rules */
			if (IS_KLD_LOADED(ipfw_nptv6) > 0 ||
			    IS_KLD_LOADED(ipfw_nat64) > 0) {
				if (!quiet) {
					printf("Creating objects... ");
					fflush(stdout);
				}
				for (i = 0; i < nat64lsn_count; i++) {
					if (nat64lsn_create(s,
					    nat64lsn_rules[i].rule,
					    nat64lsn_rules[i].len) != 0) {
						pidfile_remove(pfh);
						ERRXFW(1, s,"nat64lsn creating "
						    "failed");
					}
				}
				for (i = 0; i < nat64stl_count; i++) {
					if (nat64stl_create(s,
					    nat64stl_rules[i].rule,
					    nat64stl_rules[i].len) != 0) {
						pidfile_remove(pfh);
						ERRXFW(1, s,
						    "nat64stl creating "
						    "failed");
					}
				}
				for (i = 0; i < nat64clat_count; i++) {
					if (nat64clat_create(s,
					    nat64clat_rules[i].rule,
					    nat64clat_rules[i].len) != 0) {
						pidfile_remove(pfh);
						ERRXFW(1, s,
						    "nat64clat creating "
						    "failed");
					}
				}
				for (i = 0; i < nptv6_count; i++) {
					if (nptv6_create(s, nptv6_rules[i].rule,
					    nptv6_rules[i].len) != 0) {
						pidfile_remove(pfh);
						ERRXFW(1, s,
						    "nptv6 creating failed");
					}
				}
				syslog(LOG_NOTICE, "created objects: %d",
				    nat64lsn_count + nat64stl_count +
				    nptv6_count + nat64clat_count);
				if (!quiet) {
					printf("Created %d objects\n",
					    nat64lsn_count + nat64stl_count +
					    nptv6_count + nat64clat_count);
				}
			}
			if (!quiet) {
				printf("Installing rules... ");
				fflush(stdout);
			}
			/* Проходим по всем правилам и загружаем их */
			for(i = 0; i < rule_count; i++) {
				if (ipfw_install_single_rule(s,
				    &rules[i]) != 0) {
					pidfile_remove(pfh);
					ERRXFW(1, s,
					    "ipfw install error. line: %d"
					    " (rule #%d)\n", rules[i].line - 1,
					    i + 1);
				}
				if (!quiet) {
					if (i % 500 == 0)
						printf(".");
					if (i > 0 && i % 5000 == 0)
						printf("%d", i);
					fflush(stdout);
				}
			}
			/*
			 * Обмениваем set#0 и set#1.
			 * вычисляется так: (4<<24)|(num1<<16)|num2
			 */
			if (ipfw_swap_sets(s, TMP_SET_NUM, 0) != 0)
				ERRXFW(1, s, "can't swap sets 0<->%d",
				    TMP_SET_NUM);

			/* Удаляем set#1, где у нас остались старые правила */
			if (ipfw_delete_set(s, TMP_SET_NUM) != 0)
				ERRXFW(1, s, "can't delete set %d",
				    TMP_SET_NUM);

			/* Delete objects from set #1 */
			if (IS_KLD_LOADED(ipfw_nptv6) > 0)
				nptv6_destroy_all(s, 1);
			if (IS_KLD_LOADED(ipfw_nat64) > 0)
				nat64_destroy_all(s, 1);
		}

		syslog(LOG_NOTICE, "installed rules: %d", rule_count);
		if (rule_count && !quiet)
			printf(".%d\n", rule_count);

		/* Удаляем таблицы без референсов в заданном диапазоне */
		tables_deleted = 0;
		if (tables_foreach(s, table_destroy_if_unref, &tables_deleted,
		     0) != 0)
			ERRXFW(1, s, "can't delete unref tables");
		if (!quiet)
			printf("Removed %zu unreferenced tables within %d..%d"
			    " range\n", tables_deleted, table_lower, table_upper);

		if (dummynet_count > 0) {
			if (!quiet) {
				printf("Installing dummynet rules");
				fflush(stdout);
			}
			for (i=0; i < dummynet_count; i++) {
				if (setsockopt(s, IPPROTO_IP, IP_DUMMYNET3,
				    dummynet_rules[i].rule,
				    dummynet_rules[i].len) < 0)
					ERRXFW(1, s,
					    "can't load dummynet rules");
				if (!quiet) {
					printf(".");
					fflush(stdout);
				}
			}
			if (!quiet)
				printf(".%d\n", dummynet_count);
			syslog(LOG_NOTICE, "installed dummynet rules: %d",
			    dummynet_count);
		}
		if (nat_count > 0) {
			if(!quiet) {
				printf("Installing nat rules");
				fflush(stdout);
			}
			for (i = 0; i < nat_count; i++) {
				if (nat_create(s, nat_rules[i].rule,
				    nat_rules[i].len) != 0) {
					pidfile_remove(pfh);
					ERRXFW(1, s, "nat creating failed");
				}
				if (!quiet) {
					printf(".");
					fflush(stdout);
				}
			}
			if (!quiet)
				printf(".%d\n", nat_count);
			syslog(LOG_NOTICE, "Configured NAT44 instances: %d",
			    nat_count);
		}
		ipfw_enable_skipto_cache(s, 1);
		close(s);
	} else
		if (!quiet)
			printf("Rules are OK.\n");

	if(!only_test)
		pidfile_remove(pfh);
	closelog();
	return (0);
}

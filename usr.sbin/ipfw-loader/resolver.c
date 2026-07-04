/*
 * Copyright (c) 2007-2026 Yandex, LLC.
 *
 * SPDX-License-Identifier: BSD-4-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <netinet/ip_fw.h>
#include <resolv.h>

#include <sys/fnv_hash.h>

#include "fw-parse.h"

#define	NAMEHASH_SIZE	4096
#define	NAMEHASH_HASH(name)	(fnv_32_str(name, FNV1_32_INIT) % NAMEHASH_SIZE)
STAILQ_HEAD(ncache_head, ncache_entry);
struct ncache_entry {
	STAILQ_ENTRY(ncache_entry) next;
	struct addrinfo *r;
	int entries;
	int nlen;
	char name[0];
};
static struct ncache_head ncache[NAMEHASH_SIZE];
static int ncache_count;
static int do_dns_queries = 1;

static const char *write_file_name = NULL;

static int requests_total, requests_cached, requests_any, requests_good;

static void read_namecache(char *fname);
static struct ncache_entry *add_namecache(const char *name,
    struct addrinfo *r, int entries);
static void
print_ncentry(int fd, struct ncache_entry *nc, struct addrinfo **air,
    int size, char *wbuf, int wsize);

void
init_resolver(char *read_file, char *write_file, int _do_dns_queries)
{
	int i;

	requests_total = requests_cached = requests_any = requests_good = 0;
	do_dns_queries = _do_dns_queries;

	/* Init name cache */
	for (i = 0; i < NAMEHASH_SIZE; i++)
		STAILQ_INIT(&ncache[i]);
	ncache_count = 0;

	if (read_file != NULL)
		read_namecache(read_file);
	write_file_name = write_file;

	/* Init system resolver */
	res_init();

	/*
	 * Disable search domains list, we expect FQDNs only.
	 * This helps A LOT in case of non-resolvable FQDNs still
	 * residing in configuration file.
	 */
	_res.options &= ~(RES_DNSRCH);
}

static struct addrinfo *
make_ai(char *addrs, int *entries)
{
	struct addrinfo *ai, *ai_chain = NULL;
	char *token;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	int i, c = 0;

	while ((token = strsep(&addrs, " ")) != NULL) {
		if (token[0] == '#')
			return ai_chain;	/* Skip comments */

		if (strchr(token, ':') != NULL) {
			/* IPv6 address */
			ai = calloc(1, sizeof(struct addrinfo) +
			    sizeof(struct sockaddr_in6));
			sin6 = (struct sockaddr_in6 *)(ai + 1);

			ai->ai_family = AF_INET6;
			ai->ai_addrlen = sizeof(struct sockaddr_in6);
			ai->ai_addr = (struct sockaddr *)sin6;

			sin6->sin6_family = AF_INET6;
			sin6->sin6_len = ai->ai_addrlen;

			i = inet_pton(ai->ai_family, token, &sin6->sin6_addr);
		} else {
			/* IPv4 address */
			ai = calloc(1, sizeof(struct addrinfo) +
			    sizeof(struct sockaddr_in));
			sin = (struct sockaddr_in *)(ai + 1);

			ai->ai_family = AF_INET;
			ai->ai_addrlen = sizeof(struct sockaddr_in);
			ai->ai_addr = (struct sockaddr *)sin;

			sin->sin_family = AF_INET;
			sin->sin_len = ai->ai_addrlen;

			i = inet_pton(ai->ai_family, token, &sin->sin_addr);
		}

		if (i != 1)
			errx(1, "DNS cache address %s is not valid", token);

		ai->ai_next = ai_chain;
		ai_chain = ai;
		c++;
	}

	if (entries != NULL)
		*entries = c;

	return ai_chain;
}

#define	DNS_CACHE_SIZE_MAX	(16 * 1024 * 1024)
#define	DNS_CACHE_AGE_MAX	(4 * 24 * 3600)
static void
read_namecache(char *fname)
{
	char *xbuf, *p, *l, *eol, *name;
	struct addrinfo *ai;
	int count = 0;
	int age, fd, c;
	ssize_t len;
	struct stat fs;
	struct timeval tv;

	if ((fd = open(fname, O_RDONLY)) == -1)
		err(1, "Can't open dns cache file %s for reading", fname);

	if (fstat(fd, &fs) == -1)
		err(1, "Can't get dns cache file %s size", fname);

	if (fs.st_size > DNS_CACHE_SIZE_MAX) {
		fprintf(stderr, "Ignoring dns cache: 2big (%luM), %uM max\n",
		    fs.st_size / 1048576, DNS_CACHE_SIZE_MAX / 1048576);
		close(fd);
		return;
	}

	if (gettimeofday(&tv, NULL) == -1)
		err(1, "gettimeofday() failed");

	if (do_dns_queries && (age = tv.tv_sec - fs.st_mtime) > DNS_CACHE_AGE_MAX) {
		fprintf(stderr, "Ignoring dns cache: too old age %d (max %d)\n",
		    age, DNS_CACHE_AGE_MAX);
		close(fd);
		return;
	}

	xbuf = calloc(1, fs.st_size + 1);
	len = read(fd, xbuf, fs.st_size);
	if (len == -1)
		err(1, "Error reading dns cache file");

	close(fd);

	if (len > fs.st_size)
		len = fs.st_size;

	xbuf[len] = '\0';
	p = xbuf;

	c = 0;
	while (p != NULL) {
		if ((eol = strchr(p, '\n')) != NULL)
			*eol++ = '\0';

		l = p;
		p = eol;

		if (*l == '#' || *l == '\0')
			continue; /* Skip comments */

		if ((name = strsep(&l, " ")) == NULL)
			continue;
		ai = make_ai(l, &count);
		add_namecache(name, ai, count);
		c++;
#if 0
	char *wbuf;
	struct addrinfo **air;
	int size, wsize;

	size = 64;
	air = malloc(size * sizeof(struct addrinfo *));
	wsize = 4096;
	wbuf = malloc(wsize);
	
	print_ncentry(1, nc, air, size, wbuf, wsize);

	free(air);
	free(wbuf);
#endif
	}

	fprintf(stderr, "DNS cache: age: %d sec %lu bytes, %d records\n",
	    age, len, c);

	free(xbuf);
}


static struct ncache_entry *
add_namecache(const char *name, struct addrinfo *r, int entries)
{
	struct ncache_entry *nc;
	int i, l;

	i = NAMEHASH_HASH(name);
	l = strlen(name);

	nc = malloc(sizeof(struct ncache_entry) + l + 1);

	nc->r = r;
	nc->entries = entries;
	nc->nlen = l;
	strlcpy(nc->name, name, l + 1);
	STAILQ_INSERT_TAIL(&ncache[i], nc, next);
	ncache_count++;

	return nc;
}

static struct addrinfo *
search_namecache(const char *name)
{
	struct ncache_entry *nc;

	STAILQ_FOREACH(nc, &ncache[NAMEHASH_HASH(name)], next) {
		if (strcasecmp(nc->name, name))
			continue;

		return nc->r;
	}

	return (NULL);
}

static int
compare_ai(__unused void *_nc, const void *_l, const void *_r)
{
	struct addrinfo *l, *r;
	struct in_addr *l4, *r4;
	struct in6_addr *l6, *r6;

	l = *((struct addrinfo * const *)_l);
	r = *((struct addrinfo * const *)_r);

	if (l->ai_family == AF_INET6 && r->ai_family == AF_INET)
		return 1;
	if (l->ai_family == AF_INET && r->ai_family == AF_INET6)
		return -1;

	if (l->ai_family == AF_INET) {
		l4 = &((struct sockaddr_in *)l->ai_addr)->sin_addr;
		r4 = &((struct sockaddr_in *)r->ai_addr)->sin_addr;

		if (ntohl(l4->s_addr) > ntohl(r4->s_addr))
			return 1;
		else if (l4->s_addr == r4->s_addr)
			return 0;
		else
			return -1;
	}

	if (l->ai_family == AF_INET6) {
		l6 = &((struct sockaddr_in6 *)l->ai_addr)->sin6_addr;
		r6 = &((struct sockaddr_in6 *)r->ai_addr)->sin6_addr;

		return memcmp(l6, r6, sizeof(struct in6_addr));
	}

	return 0;
}

static void
print_ncentry(int fd, struct ncache_entry *nc, struct addrinfo **air,
    int size, char *wbuf, int wsize)
{
	struct addrinfo *ai;
	char *pbuf;
	int count = 0, i, len, tlen;
	struct in_addr *pin4;
	struct in6_addr *pin6;

	if (size < nc->entries)
		air = malloc(sizeof(struct addrinfo *) * nc->entries);

	for (ai = nc->r; ai != NULL; ai = ai->ai_next) {
		if (ai->ai_family != AF_INET6 && ai->ai_family != AF_INET)
			continue;

		air[count++] = ai;
	}

	tlen = count * (INET6_ADDRSTRLEN + 1) + nc->nlen + 10;
	if (tlen > wsize)
		wbuf = malloc(tlen);

	qsort_r(air, count, sizeof(struct addrinfo *), nc, compare_ai);

	pbuf = (char *)wbuf;
	pbuf += strlcpy(pbuf, nc->name, nc->nlen + 1);
	*pbuf++ = ' ';

	for (i = 0; i < count; i++) {
		ai = air[i];
		if (ai->ai_family == AF_INET6) {
			pin6 =&((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr;
			inet_ntop(ai->ai_family, pin6, pbuf, wsize);
		} else if (ai->ai_family == AF_INET) {
			pin4 = &((struct sockaddr_in *)ai->ai_addr)->sin_addr;
			inet_ntop(ai->ai_family, pin4, pbuf, wsize);
		} else
			continue;

		pbuf += strlen(pbuf);
		*pbuf++ = ' ';
	}

	*(pbuf - 1) = '\n';
	*pbuf = '\0';

	len = pbuf - wbuf;

	write(fd, wbuf, len);

	if (size < nc->entries)
		free(air);
	if (tlen > wsize)
		free(wbuf);
}

static int
compare_nc(const void *_l, const void *_r)
{
	const struct ncache_entry *l, *r;

	l = *((struct ncache_entry * const *)_l);
	r = *((struct ncache_entry * const *)_r);

	return strcmp(l->name, r->name);
}

void
dump_namecache(void)
{
	struct ncache_entry *nc, **nbuf;
	struct addrinfo **air;
	char *wbuf;
	int i, c, size, wsize, write_fd;

	fprintf(stderr,
	    "DNS stat: %d any: %d cached: %d good:%d cache_size %d\n",
	    requests_total, requests_any, requests_cached, requests_good,
	    ncache_count);

	if (write_file_name == NULL)
		return;

	if ((write_fd = open(write_file_name, O_WRONLY|O_CREAT|O_TRUNC)) == -1)
		errx(1, "Can't open dns cache file %s for writing",
		    write_file_name);

	size = 64;
	air = malloc(size * sizeof(struct addrinfo *));
	wsize = 4096;
	wbuf = malloc(wsize);

	nbuf = malloc(ncache_count * sizeof(struct ncache_entry *));

	for (i = 0, c = 0; i < NAMEHASH_SIZE; i++) {
		STAILQ_FOREACH(nc, &ncache[i], next)
			nbuf[c++] = nc;
	}

	qsort(nbuf, ncache_count, sizeof(struct ncache_entry *), compare_nc);
	for (i = 0; i < ncache_count; i++)
		print_ncentry(write_fd, nbuf[i], air, size, wbuf, wsize);

	close(write_fd);

	free(air);
	free(wbuf);
	free(nbuf);
}


struct addrinfo *
y_gethostbyname(const char *name)
{
	struct addrinfo *ai, *r;
	struct addrinfo hints = { .ai_flags = AI_PASSIVE,
				 .ai_family = PF_UNSPEC,
				 .ai_socktype = PF_INET };
	int i;

	requests_total++;

	/* Check cache first */
	if ((r = search_namecache(name)) != NULL) {
		requests_cached++;
		return r;
	}

	if (do_dns_queries == 0)
		return NULL;
	
	if (getaddrinfo(name, NULL, &hints, &r) != 0)
		return NULL;

	i = 0;

	for (ai = r; ai != NULL; ai = ai->ai_next) {
		i++;
	}

	add_namecache(name, r, i);

	requests_good++;

	return r;
}


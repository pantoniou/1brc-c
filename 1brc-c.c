/*
 * 1brc-c
 *
 * Pantelis Antoniou <pantelis.antoniou@gmail.com
 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <limits.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <endian.h>
#include <math.h>
#include <getopt.h>
#include <alloca.h>
#include <pthread.h>
#include <wait.h>

/* sadly, you can't find any big endian machines anymore... */
/* so all processing is done in little endian */

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

static inline long long
delta_ns(struct timespec before, struct timespec after)
{
        if ((before.tv_sec == 0 && before.tv_nsec == 0) ||
            (after.tv_sec == 0 && after.tv_nsec == 0))
                return -1;
        return (long long)((int64_t)(after.tv_sec - before.tv_sec) * (int64_t)1000000000UL + (int64_t)(after.tv_nsec - before.tv_nsec));
}

#define MAX_STATION_BYTES	100
#define MAX_STATION_COUNT	10000
#define MAX_TEMP_BYTES		(1 + 4)	/* -99.9 */
#define MAX_LINE_SIZE		(MAX_STATION_BYTES + 1 + MAX_TEMP_BYTES + 1)	/* fits in 1 byte */

#define ALWAYS_INLINE		static inline __attribute__((always_inline))

#if (defined(__x86_64__) && defined(__CRC32__)) || \
    (defined(__aarch64__) && defined(__ARM_FEATURE_CRC32))
/* automatically use crc32 hash is supported */
#undef HASH_MURMUR
#define HASH_CRC32
#else
// all others
#define HASH_MURMUR
#undef HASH_CRC32
#endif

ALWAYS_INLINE uint64_t load64(const void *p)
{
	uint64_t v;

	/* most arches support unaligned accesses */
	v = *(const uint64_t *)p;
#if __BYTE_ORDER != __LITTLE_ENDIAN
	v = __builtin_bswap64(v);
#endif
	return v;
}

ALWAYS_INLINE int count_trailing_zeroes64(uint64_t v)
{
#if LONG_MAX == 9223372036854775807L
	return __builtin_ctzl((long)v);
#else
	return __builtin_ctzll((long long)v);
#endif
}

#define SEMICOLON	0x3b  /*  ; */
#define NEWLINE		0x0a  /* \n */
#define SEMICOLONS	0x3b3b3b3b3b3b3b3bLU
#define NEWLINES	0x0a0a0a0a0a0a0a0aLU
#define CARRYMASKS	0x7F7F7F7F7F7F7F7FLU

#define TEMP_IN_MASK	0x0f000f0f
#define TEMP_MULT	(1 + (10 << 16) + (100 << 24))
#define TEMP_SHIFT	24
#define TEMP_OUT_MASK	((1 << 10) - 1)

#ifdef HASH_MURMUR

#define PRIME_1 11400714785074694791ULL
#define PRIME_2 14029467366897019727ULL
#define PRIME_3  1609587929392839161ULL

ALWAYS_INLINE uint64_t hash_setup(void)
{
	uint64_t h;

	h = PRIME_3;
	return h;
}

ALWAYS_INLINE uint64_t hash_update(uint64_t h, uint64_t k)
{
	k *= PRIME_1;
	k = (k << 31) | (k >> (64 - 31));
	k *= PRIME_2;
	h ^= k;
	h = (h << 29) | (h >> (64 - 29));
	h = (h * 5) + PRIME_1;
	return h;
}

#endif	/* HASH_MURMUR */

#ifdef HASH_CRC32

#define CRCPOLY 0x11EDC6F41

ALWAYS_INLINE uint32_t hash_setup(void)
{
	return (uint32_t)CRCPOLY;
}

#if defined(__x86_64__)
ALWAYS_INLINE uint32_t hash_update(uint32_t h, uint64_t k)
{
	return (uint32_t)__builtin_ia32_crc32di((unsigned long long)h, (unsigned long long)k);
}

#elif defined(__aarch64__)
ALWAYS_INLINE uint32_t hash_update(uint32_t h, uint64_t k)
{
	return (uint32_t)__builtin_aarch64_crc32d((h, k);
}
#else
#error unsupported CRC arch
#endif

#endif

struct city_data {
				    /* offset cacheline */
	uint64_t count;			/*  0 0 */
	int64_t sumt;			/*  8 0 */
	uint32_t h;			/* 16 0 */
	int16_t mint, maxt;		/* 20 0 */
	struct city_data *next;		/* 24 0 */
	struct city_data *cnext;	/* 32 1 */
	size_t len;			/* 40 1 */
	char name[];			/* 48 1 */
};

#define CITIES_HASH_SIZE	4096
// #define CITIES_HASH_SIZE	16384

struct work_block {
	struct city_data *cdtab[CITIES_HASH_SIZE];
	uint8_t cdcol[CITIES_HASH_SIZE];
	struct weather_data *wd;
	unsigned int city_count;
	struct city_data *create_head;
	bool hash_collision;
	off_t offset;
	size_t size;
	struct work_block *parent;
	unsigned int children_count;
	struct work_block **children;
};

struct weather_data {
	const char *file;
	unsigned int flags;
	int fd;
	void *addr;
	const char *start;
	void *guard_page;
	size_t size;
	struct work_block *root_wb;
	size_t pagesz;
	size_t cachelinesz;
};

#define WDF_VERBOSE	1
#define WDF_TIMINGS	2
#define WDF_BENCH	4
#define WDF_REFERENCE	8
#define WDF_NOFORK	16
#define WDF_JOIN	32

struct weather_data *wd_open(const char *file, int workers, unsigned int flags);
void wd_close(struct weather_data *wd);
void *wd_malloc(struct weather_data *wd, size_t size);
void *wb_malloc(struct work_block *wb, size_t size);

struct city_data *cd_create(struct work_block *wb, const char *name, size_t len, uint32_t h)
{
	size_t cdsize;
	struct city_data *cd;

	cdsize = sizeof(*cd) + len + 1;
	cd = wb_malloc(wb, cdsize);
	if (!cd)
		return NULL;

	cd->count = 0;
	cd->sumt = 0;
	cd->h = h;
	cd->mint = INT16_MAX;
	cd->maxt = INT16_MIN;
	cd->next = NULL;
	cd->cnext = NULL;
	cd->len = len;
	memcpy(cd->name, name, len);
	cd->name[len] = '\0';

	return cd;
}

void cd_destroy(struct city_data *cd)
{
	if (!cd)
		return;
	free(cd);
}

void *wb_malloc(struct work_block *wb, size_t size)
{
	return wd_malloc(wb->wd, size);
}

struct work_block *wb_create(struct weather_data *wd, off_t offset, size_t size, struct work_block *parent, int children)
{
	struct work_block *wb;
	long sval;

	if (!wd || !size || offset >= wd->size || size > wd->size || offset + size > wd->size)
		return NULL;

	if (children < 0) {
		sval = sysconf(_SC_NPROCESSORS_ONLN);
		if (sval < 0)
			return NULL;
		children = sval;
	}

	wb = wd_malloc(wd, sizeof(*wb));
	if (!wb)
		return NULL;
	memset(wb, 0, sizeof(*wb));

	wb->wd = wd;
	wb->offset = offset;
	wb->size = size;
	wb->parent = parent;
	wb->children_count = (unsigned int)children;

	return wb;
}

void wb_destroy(struct work_block *wb)
{
	struct city_data *cd, *cdn;

	if (!wb)
		return;

	cd = wb->create_head;
	while (cd) {
		cdn = cd->cnext;
		cd_destroy(cd);
		cd = cdn;
	}

	free(wb);
}

ALWAYS_INLINE struct city_data *
wb_lookup_city(struct work_block *wb, const char *name, size_t len, uint32_t h)
{
	struct city_data *cd;
	unsigned int idx;

	idx = (unsigned int)(h % (sizeof(wb->cdtab)/sizeof(wb->cdtab[0])));
	cd = wb->cdtab[idx];

	if (likely(!wb->hash_collision || !wb->cdcol[idx])) {
		/* no hash collision detected */
		for (; cd; cd = cd->next) {
			if (cd->h == h)
				return cd;
		}
	} else {
		/* hash collision detected? very unlikely but... probably bad hash algo */
		/* in this case we check the name as well */
		for (; cd; cd = cd->next) {
			if (cd->h == h && cd->len == len && !memcmp(cd->name, name, len))
				return cd;
		}
	}

	return NULL;
}

ALWAYS_INLINE struct city_data *
wb_create_city(struct work_block *wb, const char *name, size_t len, uint32_t h)
{
	struct city_data *cd, *cdt;
	unsigned int idx;

	cd = cd_create(wb, name, len, h);
	if (!cd)
		perror("cd_create");

	idx = (unsigned int)(h % (sizeof(wb->cdtab)/sizeof(wb->cdtab[0])));

	/* link */
	cd->next = cdt = wb->cdtab[idx];
	wb->cdtab[idx] = cd;
	cd->cnext = wb->create_head;
	wb->create_head = cd;
	wb->city_count++;

	/* run through the list, and if there is a same hash, turn on collision detection
	 * this is very very unlikely, if the hash quality is good its chances are
	 * 1/(2^32) one in 4 billion
	 */
	for (; cdt; cdt = cdt->next) {
		if (cdt->h == h) {
			wb->cdcol[idx] = 1;
			wb->hash_collision = true;
			break;
		}
	}

	return cd;
}

ALWAYS_INLINE struct city_data *
wb_lookup_or_create_city(struct work_block *wb, const char *name, size_t len, uint32_t h)
{
	struct city_data *cd;

	cd = wb_lookup_city(wb, name, len, h);
	if (likely(cd))
		return cd;

	return wb_create_city(wb, name, len, h);
}

struct parse_line_info {
	uint32_t h;
	int16_t temp;
	uint8_t clen;
	uint8_t advance;
};

ALWAYS_INLINE struct parse_line_info
parse_line_reference(const char *start, const char *end)
{
	struct parse_line_info r;
	const char *s;
	uint64_t v;
	int wpos;
	char c;
	bool minus;

	s = start;
	wpos = 0;
	v = 0;
	r.h = hash_setup();
	while (s < end && (c = *s++) != ';') {
		if (wpos == 0)
			v = 0;
		v |= (((uint64_t)(uint8_t)c) << (wpos << 3));
		if (++wpos >= 8) {
			r.h = hash_update(r.h, v);
			wpos = 0;
		}
	}
	if (wpos > 0)
		r.h = hash_update(r.h, v);
	r.clen = s - 1 - start;

	minus = s < end && *s == '-';
	if (minus)
		s++;
	r.temp = 0;
	while(s < end && (c = *s++) != '\n') {
		if (c == '.')
			continue;
		r.temp *= 10;
		r.temp += c - '0';
	}
	if (minus)
		r.temp = -r.temp;

	r.advance = s - start;

	return r;
}

ALWAYS_INLINE void
process_result(struct work_block *wb, struct parse_line_info r, const char *s)
{
	struct city_data *cd;

	cd = wb_lookup_or_create_city(wb, s, r.clen, r.h);

	cd->count++;
	cd->sumt += r.temp;
	if (r.temp < cd->mint)
		cd->mint = r.temp;
	if (r.temp > cd->maxt)
		cd->maxt = r.temp;
}

int wb_process_actual_reference(struct work_block *wb)
{
	const char *s, *e;
	struct parse_line_info r;
	struct timespec tstart, tend;

	clock_gettime(CLOCK_MONOTONIC, &tstart);

	s = wb->wd->start + wb->offset;
	e = s + wb->size;

	madvise((void *)s, (size_t)(e - s), MADV_SEQUENTIAL | MADV_WILLNEED);

	/* we need to check bounds now */
	while (s < e) {
		r = parse_line_reference(s, e);
		process_result(wb, r, s);
		s += r.advance;
	}

	clock_gettime(CLOCK_MONOTONIC, &tend);

	if (wb->wd->flags & WDF_TIMINGS)
		fprintf(stderr, "%s: time=%lldns\n", __func__, delta_ns(tstart, tend));

	return 0;
}

int wb_process_actual(struct work_block *wb)
{
	struct city_data *cd;
	const char *s, *e, *name;
	uint64_t cv, tv, mv;
	uint32_t h;
	int adv, have;
	size_t namelen;
	int16_t temp;
	struct timespec tstart, tend;

	clock_gettime(CLOCK_MONOTONIC, &tstart);

	s = wb->wd->start + wb->offset;
	e = s + wb->size;

	madvise((void *)s, (size_t)(e - s), MADV_SEQUENTIAL | MADV_WILLNEED);

	while (likely(s < e)) {

		name = s;

		//
		// Input: 'Foobar;4'
		// Need to advance 6
		//                         LE                     BE
		//          4  ;  r a b o o F      F o o b a r  ;  4
		//    cv 0x34_3b_7261626f6f46   0x466f6f626172_3b_34
		//    mv 0x00_80_000000000000   0x000000000000_80_00
		//     m 0x00_00_ffffffffffff   0xffffffffffff_00_00
		//  bpos                   55                     48
		//   adv                    7                      7
		//
		//

		h = hash_setup();
		for (;;) {
			/* load 8 bytes */
			cv = load64(s);

			/* zero out all semicolon bytes */
			mv = cv ^ SEMICOLONS;

			/* find out if any byte is zero */
			tv = (mv & CARRYMASKS) + CARRYMASKS;

			/* every byte that was zero is now 0x80 */
			mv = ~(tv | mv | CARRYMASKS);

			/* if there was a semicolon break */
			if (likely(mv))
				break;

			h = hash_update(h, cv);
			s += sizeof(uint64_t);
		}

		/* find the location of the byte that was zero */
		adv = count_trailing_zeroes64((long)mv) >> 3;

		/* this can be done in one go, because if adv == 8 shift is 0 */
		tv = (uint64_t)-1 >> (64 - ((adv + 1) << 3));

		s += adv;
		h = hash_update(h, cv & tv);

		/* must be done in two steps, because if adv == 8 shift about is
		 * size of the type. on most arches the shift is modulo.
		 */
		cv >>= 8;
		cv >>= (adv << 3);

		namelen = s++ - name;

		/* how many bytes we have that are valid */
		have = 8 - (adv + 1);

		/* shift in any partial */
		if (have < MAX_TEMP_BYTES)
			cv |= load64(s + have) << (have << 3);

		/*
		 * Sign multiplier:
		 * Get either ..00000001 (1) or ..11111111 (-1)
		 * the minus sign is ascii 0x2d while all digits are 0x30-0x39
		 * so for '-' bit 4 is 0, while for digits it is 1
		 *
		 *                 minus digit(3x)
		 *              -------- ---------
		 * original     00101101  0011xxxx
		 * mask-out     00000000  00010000
		 * shift-right  00000000  00000001
		 * subtract 1   11111111  00000000
		 * or 1         11111111  00000001
		 * result             -1         1
		 */

		// fprintf(stderr, "temp cv=0x%016lx\n", __builtin_bswap64(cv));

		/* get the 4th bit to the 0 position */
		tv = (cv & 0x10) >> 4;

		/* advance over the sign (if there) */
		s += (tv ^ 1);

		/* shift out the minus */
		cv >>= (tv ^ 1) << 3;

		/* convert from 0, 1 to 1, -1 */
		tv -= 1;
		tv |= 1;

		/* temp now contains just the sign */
		temp = (int16_t)tv;

		/*
		 * Convert 4 byte form to 3 byte form
		 * If it is 3 byte form the second byte
		 * is '.' with value 0x2e. Similarly with '-'
		 * the 4'th bit of that value is 0.
		 *
		 *             4 bytes  3 bytes
		 *             -------  --------
		 * original    3x3x2E3x 3x2E3xyy
		 * tv          00000000 00100000
		 * shift-left         0        8
		 * result      3x3x2e3x 003x2e3x
		 *
		 * Note that the high byte for 3 bytes is now 00 not 30
		 */

		tv = ~cv & (1 << 12);
		cv <<= (tv >> 9);

		s += 4 + ((cv >> 4) & 1);

		/* calculate in one go */
		temp *= (int16_t)((((cv & TEMP_IN_MASK) * TEMP_MULT) >> TEMP_SHIFT) & TEMP_OUT_MASK);

		cd = wb_lookup_or_create_city(wb, name, namelen, h);

		cd->count++;
		cd->sumt += temp;
		if (unlikely(temp < cd->mint))
			cd->mint = temp;
		if (unlikely(temp > cd->maxt))
			cd->maxt = temp;
	}

	clock_gettime(CLOCK_MONOTONIC, &tend);

	if (wb->wd->flags & WDF_TIMINGS)
		fprintf(stderr, "%s: time=%lldns\n", __func__, delta_ns(tstart, tend));

	return 0;
}

int wb_process(struct work_block *wb);

static void *wb_thread_start(void *arg)
{
	struct work_block *wb = arg;

	wb_process(wb);
	return NULL;
}

int wb_process(struct work_block *wb)
{
	size_t pagesz, split;
	pthread_t *tids;
	struct work_block **wbs, *wbc;
	off_t *splits;
	off_t offset;
	size_t start, end;
	unsigned int nchildren, nsplits;
	unsigned int i;
	const char *s, *e, *p;
	int rc;
	struct city_data *cd, *cdc;
	struct timespec tstart, tend;

	pagesz = wb->wd->pagesz;

	/* start with the number of children configured
	 * and try to use as many children possible
	 * but not handling less than a page
	 */
	for (nchildren = wb->children_count; nchildren >= 1; nchildren--) {
		split = wb->size / nchildren;
		if (split >= pagesz)
			break;
	}

	/* if there are no children, or too small we have to do the work */
	if (nchildren <= 1 || wb->size < pagesz)
		return !(wb->wd->flags & WDF_REFERENCE) ?
				wb_process_actual(wb) :
				wb_process_actual_reference(wb);

	s = wb->wd->start + wb->offset;
	e = s + wb->size;

	// printf("using #%u workers - split=0x%012zx total=0x%012zx\n", nchildren, split, wb->size);

	/* allocate arrays */
	tids = alloca(sizeof(*tids) * nchildren);
	memset(tids, 0, sizeof(*tids) * nchildren);

	wbs = alloca(sizeof(*wbs) * nchildren);
	memset(wbs, 0, sizeof(*wbs) * nchildren);

	nsplits = nchildren - 1;
	splits = alloca(sizeof(*splits) * nsplits);

	/* initial splits */
	offset = split;
	for (i = 0, offset = split; i < nsplits; i++, offset += split)
		splits[i] = offset;

	clock_gettime(CLOCK_MONOTONIC, &tstart);

	/* forward splits to newlines */
	for (i = 1; i < nchildren; i++) {
		start = i == 0 ? 0 : splits[i-1];
		end = i < nsplits ? splits[i] : wb->size;

		p = memchr(s + start, '\n', (end - start));
		/* a newline must be found */
		if (!p || (p + 1) >= e) {
			errno = EINVAL;
			return -1;
		}
		splits[i-1] = ++p - s;
	}

	clock_gettime(CLOCK_MONOTONIC, &tend);

	if (wb->wd->flags & WDF_TIMINGS)
		fprintf(stderr, "%s: split time=%lldns\n", __func__, delta_ns(tstart, tend));

	/* create the workers */
	for (i = 0; i < nchildren; i++) {
		start = i == 0 ? 0 : splits[i-1];
		end = i < nsplits ? splits[i] : wb->size;

		wbs[i] = wb_create(wb->wd, start, end - start, wb, 0);
		assert(wbs[i]);
	}

	/* fire off the threads */
	for (i = 0; i < nchildren; i++) {
		// printf("creating... %p\n", wbs[i]);
		rc = pthread_create(&tids[i], NULL, wb_thread_start, wbs[i]);
		assert(!rc);
	}

	/* join waiting for end */
	for (i = 0; i < nchildren; i++) {
		// printf("waiting.... %p\n", wbs[i]);
		rc = pthread_join(tids[i], NULL);
		assert(!rc);
	}

	clock_gettime(CLOCK_MONOTONIC, &tstart);

	/* merge the results */
	for (i = 0; i < nchildren; i++) {
		wbc = wbs[i];

		for (cdc = wbc->create_head; cdc; cdc = cdc->cnext) {

			cd = wb_lookup_or_create_city(wb, cdc->name, cdc->len, cdc->h);

			/* merge the data */
			cd->count += cdc->count;
			cd->sumt += cdc->sumt;
			if (cdc->mint < cd->mint)
				cd->mint = cdc->mint;
			if (cdc->maxt > cd->maxt)
				cd->maxt = cdc->maxt;
		}
	}

	clock_gettime(CLOCK_MONOTONIC, &tend);

	if (wb->wd->flags & WDF_TIMINGS)
		fprintf(stderr, "%s: merge time=%lldns\n", __func__, delta_ns(tstart, tend));

	clock_gettime(CLOCK_MONOTONIC, &tstart);

	/* destroy the workers */
	for (i = 0; i < nchildren; i++)
		wb_destroy(wbs[i]);

	clock_gettime(CLOCK_MONOTONIC, &tend);

	if (wb->wd->flags & WDF_TIMINGS)
		fprintf(stderr, "%s: children destroy time=%lldns\n", __func__, delta_ns(tstart, tend));

	return 0;
}

static int city_cmp(const void *a, const void *b)
{
	const struct city_data * const *cap = a;
	const struct city_data * const *cbp = b;
	const struct city_data *ca = *cap;
	const struct city_data *cb = *cbp;

	return strcmp(ca->name, cb->name);
}

void wb_report(struct work_block *wb)
{
	struct city_data *cd;
	unsigned int i, count;
	struct city_data **cdtab;
	struct timespec tstart, tend;
	int len, alloc, total;
	char *wrbuf = NULL, *wrbuf2, *s;
	bool need_to_grow;
	ssize_t wrn;

	if (!wb)
		return;

	clock_gettime(CLOCK_MONOTONIC, &tstart);

	cdtab = wb_malloc(wb, sizeof(*cdtab) * wb->city_count);
	if (!cdtab)
		perror("wb_malloc");

	count = 0;
	for (cd = wb->create_head; cd; cd = cd->cnext)
		cdtab[count++] = cd;

	qsort(cdtab, count, sizeof(cdtab[0]), city_cmp);

	alloc = 65536;
	total = 0;
	wrbuf = malloc(alloc);
	if (wrbuf == NULL)
		perror("malloc");

	for (i = 0; i < count; i++) {
		cd = cdtab[i];

		do {
			len = snprintf(wrbuf + total, alloc - total,
					"%s%s%s=%3.1f/%3.1f/%3.1f%s",
					i == 0 ? "{" : "",
					i > 0 ? ", " : "",
					cd->name,
					(float)cd->mint * 0.1,
					round((float)cd->sumt / cd->count) * 0.1,
					(float)cd->maxt * 0.1,
					i >= (count - 1) ? "}\n" : "");

			/* do we need to grow ? */
			need_to_grow = total + len >= alloc;

			if (need_to_grow) {
				wrbuf2 = realloc(wrbuf, alloc * 2);
				if (wrbuf2 == NULL)
					perror("realloc");
				alloc *= 2;
				wrbuf = wrbuf2;
			}
		} while (need_to_grow);
		total += len;
	}

	/* safe write */
	s = wrbuf;
	while (total > 0) {
		do {
			wrn = write(STDOUT_FILENO, s, total);
		} while (wrn == -1 && errno == EAGAIN);
		if (wrn == -1)
			perror("write");
		s += wrn;
		total -= wrn;
	}

	free(wrbuf);

	free(cdtab);

	clock_gettime(CLOCK_MONOTONIC, &tend);

	if (wb->wd->flags & WDF_TIMINGS)
		fprintf(stderr, "%s: time=%lldns\n", __func__, delta_ns(tstart, tend));
}

struct weather_data *
wd_open(const char *file, int workers, unsigned int flags)
{
	struct weather_data *wd;
	struct stat sb;
	long sval;
	size_t pagesz, cachelinesz, size_pgalign;
	void *p;
	int rc;

	sval = sysconf(_SC_PAGESIZE);
	if (sval < 0)
		perror("sysconf(_SC_PAGESIZE)");
	pagesz = (size_t)sval;

	sval = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
	if (sval < 0)
		perror("sysconf(_SC_LEVEL1_DCACHE_LINESIZE)");
	cachelinesz = (size_t)sval;

	/* allocate aligned to cacheline */
	p = NULL;
	rc = posix_memalign(&p, cachelinesz, sizeof(*wd));
	if (rc) {
		errno = rc;
		perror("posix_memalign()");
	}
	wd = p;
	memset(wd, 0, sizeof(*wd));
	wd->fd = -1;
	wd->file = file;
	wd->flags = flags;
	wd->pagesz = pagesz;
	wd->cachelinesz = cachelinesz;

	wd->fd = open(wd->file, O_RDONLY);
	if (wd->fd < 0)
		goto err_out;

	rc = fstat(wd->fd, &sb);
	if (rc)
		goto err_out;

	wd->size = sb.st_size;

	/* get pagesz */
	size_pgalign = (wd->size + wd->pagesz - 1) & ~(wd->pagesz - 1);

	/* create an anonymous mapping one page larger */
	wd->guard_page = mmap(NULL, size_pgalign + wd->pagesz,
				PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (wd->guard_page == MAP_FAILED) {
		fprintf(stderr, "Unable to map guard page\n");
		goto err_out;
	}

	/* now mmap the file right at the top,
	 * it will replace the anonymous mapping
	 */
	wd->addr = mmap(wd->guard_page, wd->size,
			PROT_READ, MAP_PRIVATE|MAP_FIXED, wd->fd, 0);
	if (wd->addr == MAP_FAILED)
		goto err_out;

	/* verify that the mapped address is the one we said */
	if (wd->addr != wd->guard_page) {
		fprintf(stderr, "Unable to mmap at fixed address\n");
		goto err_out;
	}

	wd->start = wd->addr;

	/* adjust guard page */
	wd->guard_page += size_pgalign;

	/* we don't need the file anymore */
	close(wd->fd);
	wd->fd = -1;

	/* create root work block */
	wd->root_wb = wb_create(wd, 0, wd->size, NULL, workers);
	if (!wd->root_wb)
		goto err_out;

	/* and process */
	rc = wb_process(wd->root_wb);
	if (rc)
		goto err_out;

	return wd;
err_out:
	wd_close(wd);
	return NULL;
}

void *wd_malloc(struct weather_data *wd, size_t size)
{
	void *p;
	int rc;

	rc = posix_memalign(&p, wd->cachelinesz, size);
	if (rc) {
		errno = rc;
		return NULL;
	}
	return p;
}

void wd_close(struct weather_data *wd)
{
	struct timespec tstart, tend;
	unsigned int flags;

	if (!wd)
		return;

	clock_gettime(CLOCK_MONOTONIC, &tstart);

	if (wd->root_wb)
		wb_destroy(wd->root_wb);

	if (wd->guard_page != MAP_FAILED && wd->guard_page != NULL)
		munmap(wd->guard_page, wd->pagesz);

	if (wd->addr != MAP_FAILED && wd->addr != NULL)
		munmap(wd->addr, wd->size);

	if (wd->fd >= 0)
		close(wd->fd);

	flags = wd->flags;
	free(wd);

	clock_gettime(CLOCK_MONOTONIC, &tend);

	if (flags & WDF_TIMINGS)
		fprintf(stderr, "%s: time=%lldns\n", __func__, delta_ns(tstart, tend));
}

void wd_report(struct weather_data *wd)
{
	if (!wd || !wd->root_wb)
		return;
	return wb_report(wd->root_wb);
}

static struct option lopts[] = {
	{"bench",		no_argument,		0,	'b' },
	{"verbose",		no_argument,		0,	'v' },
	{"timings",		no_argument,		0,	't' },
	{"reference",		no_argument,		0,	'r' },
	{"no-fork",		no_argument,		0,	'n' },
	{"join",		no_argument,		0,	'j' },
	{"workers",		required_argument,	0,	'w' },
	{"help",		no_argument,		0,	'h' },
	{0,			0,              	0,	 0  },
};

static void display_usage(FILE *fp)
{
	fprintf(fp, "Usage: %s [options] [file]\n", "1brc-c");
	fprintf(fp, "\nArguments:\n\n");
	fprintf(fp, "\t[file]                   : File to process (default measurements.txt)\n");
	fprintf(fp, "\nOptions:\n\n");
	fprintf(fp, "\t--bench, -b              : Bench mode (no report output)\n");
	fprintf(fp, "\t--verbose, -v            : Verbose mode\n");
	fprintf(fp, "\t--timings, -t            : Timing info at stderr\n");
	fprintf(fp, "\t--reference, r           : Process using a simple reference implementation\n");
	fprintf(fp, "\t--no-fork, -n            : Do not fork (you will incur the unmap overhead)\n");
	fprintf(fp, "\t--join, -j               : Join child after fork\n");
	fprintf(fp, "\t--workers, -w <n>        : Set workers to <n>\n");
	fprintf(fp, "\t--help, -h               : Display  help message\n");
	fprintf(fp, "\n");
}

int do_work(const char *file, int workers, unsigned int flags)
{
	struct timespec tstart, tend;
	struct weather_data *wd = NULL;
	pid_t pid = 0;
	char buf[65536];
	ssize_t rdn;
	int pipefd[2] = { -1, -1 };
	int r;

	/* fork and do the work on the child
	 * parent can exit prematurely without reaping
	 * the child, so does not incur the cost of
	 * unmapping the file
	 */
	if (!(flags & WDF_NOFORK)) {

		if (flags & WDF_VERBOSE)
			fprintf(stderr, "Forking mode enabled\n");

		r = pipe(pipefd);
		if (r == -1)
			perror("pipe");
		pid = fork();
		if (pid == -1)
			perror("fork");

		if (pid > 0) {
			close(pipefd[1]);

			do {
				do {
					rdn = read(pipefd[0], buf, sizeof(buf));
				} while (rdn == -1 && errno == EAGAIN);
				if (rdn == -1)
					perror("read error");
				if (flags & WDF_VERBOSE)
					fprintf(stderr, "parent read %zd bytes\n", rdn);
				fwrite(buf, 1, rdn, stdout);
			} while (rdn > 0);
			close(pipefd[0]);

			if (flags & WDF_JOIN) {
				clock_gettime(CLOCK_MONOTONIC, &tstart);

				waitpid(pid, NULL, 0);

				clock_gettime(CLOCK_MONOTONIC, &tend);

				if (flags & WDF_TIMINGS)
					fprintf(stderr, "%s: join time=%lldns\n", __func__, delta_ns(tstart, tend));
			}

			return 0;
		}
		/* child, close unused read pipe */
		close(pipefd[0]);

		/* connect the other end as stdout */
		dup2(pipefd[1], STDOUT_FILENO);

		/* and close this one too */
		close(pipefd[1]);
	}

	wd = wd_open(file, workers, flags);
	if (!wd) {
		fprintf(stderr, "Unable to open/process weather data file '%s': %s\n",
				file, strerror(errno));
		return -1;
	}

	if (!(flags & WDF_BENCH))
		wd_report(wd);

	/* if we were forked, close the stdout descriptor */
	if (!(flags & WDF_NOFORK))
		close(STDOUT_FILENO);

	wd_close(wd);

	return 0;
}

int main(int argc, char *argv[])
{
	int opt, lidx, rc;
	const char *file;
	int workers = -1;
	unsigned int flags = 0;

	while ((opt = getopt_long_only(argc, argv, "w:bvtrnjh", lopts, &lidx)) != -1) {
		switch (opt) {
		case 'w':
			workers = atoi(optarg);
			break;
		case 'b':
			flags |= WDF_BENCH;
			break;
		case 'v':
			flags |= WDF_VERBOSE;
			break;
		case 't':
			flags |= WDF_TIMINGS;
			break;
		case 'r':
			flags |= WDF_REFERENCE;
			break;
		case 'n':
			flags |= WDF_NOFORK;
			break;
		case 'j':
			flags |= WDF_JOIN;
			break;
		case 'h':
		default:
			if (opt != 'h')
				fprintf(stderr, "Unknown option '%c' %d\n", opt, opt);
			display_usage(opt == 'h' ? stdout : stderr);
			return opt == 'h' ? EXIT_SUCCESS : EXIT_FAILURE;
		}
	}

	file = optind >= argc ? "measurements.txt" : argv[optind];

	rc = do_work(file, workers, flags);

	return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

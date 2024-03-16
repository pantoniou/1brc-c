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

#define MAX_STATION_BYTES	100
#define MAX_STATION_COUNT	10000
#define MAX_TEMP_BYTES		(1 + 4)	/* -99.9 */
#define MAX_LINE_SIZE		(MAX_STATION_BYTES + 1 + MAX_TEMP_BYTES + 1)

#define ALWAYS_INLINE		static inline __attribute__((always_inline))

// #undef CHECKS
// #define CHECKS

#ifdef CHECKS
#define ASSERT(_x) assert(_x)
#else
#define ASSERT(_x) do { } while(0)
#endif

#define HASH_MURMUR

ALWAYS_INLINE uint64_t load64(const void *p)
{
	/* most arches support this */
	return *(const uint64_t *)p;
}

ALWAYS_INLINE uint32_t load32(const void *p)
{
	/* most arches support this */
	return *(const uint32_t *)p;
}

#ifdef CHECKS
ALWAYS_INLINE uint64_t load64_guard(const void *p, const void *e, uint64_t guard)
{
	/* in the buffer */
	if (!guard || (p + sizeof(uint64_t)) <= e)
		return load64(p);
	if (p >= e)
		return guard;
	memcpy(&guard, p, (size_t)(e - p));
	return guard;
}
#else
static inline uint64_t load64_guard(const void *p, const void *e, uint64_t guard)
{
	return load64(p);
}
#endif

#define SEMICOLON	0x3b  /*  ; */
#define NEWLINE		0x0a  /* \n */
#define SEMICOLONS	0x3b3b3b3b3b3b3b3bLU
#define NEWLINES	0x0a0a0a0a0a0a0a0aLU
#define CARRYMASKS	0x7F7F7F7F7F7F7F7FLU
#define NEWLINES_U32	0x0a0a0a0aU

ALWAYS_INLINE uint64_t zbyte_mangle(uint64_t x)
{
	uint64_t y;
								// Original byte: 00 80 other
	y = (x & 0x7F7F7F7F7F7F7F7FLU) + 0x7F7F7F7F7F7F7F7FLU;	// 7F 7F 1xxxxxxx
	y = ~(y | x | 0x7F7F7F7F7F7F7F7FLU);			// 80 00 00000000
	return y;
}

ALWAYS_INLINE int zbyte_bpos(uint64_t mv)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	return __builtin_ctzl((long)mv);
#else
	return __builtin_clzl((long)mv);
#endif
}

ALWAYS_INLINE int zbyte_bpos_to_adv(int bpos)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	return bpos >> 3;
#else
	return (bpos + 1) >> 3;
#endif
}

ALWAYS_INLINE uint64_t zbyte_mask_from_bpos(int bpos)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	return (((uint64_t)-1) >> (64 - (bpos - 7)));
#else
	return (((uint64_t)-1) << (64 - bpos));
#endif
}

ALWAYS_INLINE uint32_t zbyte_mangle_u32(uint32_t x)
{
	uint32_t y;
						// Original byte: 00 80 other
	y = (x & 0x7F7F7F7FU) + 0x7F7F7F7FU;	// 7F 7F 1xxxxxxx
	y = ~(y | x | 0x7F7F7F7FU);		// 80 00 00000000
	return y;
}

ALWAYS_INLINE int zbyte_bpos_u32(uint32_t mv)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	return __builtin_ctz((int)mv);
#else
	return __builtin_clz((int)mv);
#endif
}

ALWAYS_INLINE uint32_t zbyte_mask_from_bpos_u32(int bpos)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	return (((uint32_t)-1) >> (32 - (bpos - 7)));
#else
	return (((uint32_t)-1) << (32 - bpos));
#endif
}

ALWAYS_INLINE uint64_t set_char_at_pos(uint64_t v, char c, int pos)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	return v | (((uint64_t)(uint8_t)c) << (pos << 3));
#else
	return v | (((uint64_t)(uint8_t)c) << ((7 - pos) << 3));
#endif
}

ALWAYS_INLINE int16_t parse_temp(uint32_t nv)
{
#if __BYTE_ORDER != __LITTLE_ENDIAN
	/* the following magic calculation only works in little endian */
	nv = __builtin_bswap16(nv);
#endif
	return ((nv & 0x0f000f0f) * (uint64_t)(1 + (10 << 16) + (100 << 24)) >> 24) & ((1 << 10) - 1);
}

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

struct city_data {
	struct city_data *next;
	uint64_t h;
	uint64_t count;
	int64_t sumt;
	int16_t mint, maxt;
	struct city_data *cnext;	/* created next */
	char *name;
	size_t len;
};

#define CITIES_HASH_SIZE	4096
// #define CITIES_HASH_SIZE	16384

struct work_block {
	struct weather_data *wd;
	off_t offset;
	size_t size;
	unsigned int city_count;
	unsigned int collisions;
	struct city_data *cdtab[CITIES_HASH_SIZE];
	struct city_data *create_head;
	struct work_block *parent;
	unsigned int children_count;
	struct work_block **children;
};

struct weather_data {
	const char *file;
	int fd;
	void *addr;
	const char *start;
	size_t size;
	struct work_block *root_wb;
};

struct weather_data *wd_open(const char *file, int workers);
void wd_close(struct weather_data *wd);

struct city_data *cd_create(const char *name, size_t len, uint64_t h)
{
	size_t cdsize;
	struct city_data *cd;

	cdsize = sizeof(*cd) + len + 1;
	cd = malloc(cdsize);
	if (!cd)
		return NULL;
	memset(cd, 0, sizeof(*cd));
	cd->name = (char *)(cd + 1);

	cd->h = h;
	memcpy(cd->name, name, len);
	cd->name[len] = '\0';

	cd->len = len;
	cd->mint = INT16_MAX;
	cd->maxt = INT16_MIN;

	return cd;
}

void cd_destroy(struct city_data *cd)
{
	if (!cd)
		return;
	free(cd);
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

	wb = malloc(sizeof(*wb));
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
wb_lookup_or_create_city(struct work_block *wb, const char *name, size_t len, uint64_t h)
{
	struct city_data *cd, **cdheadp;
	unsigned int idx;

	idx = (unsigned int)(h % (sizeof(wb->cdtab)/sizeof(wb->cdtab[0])));
	for (cd = wb->cdtab[idx]; cd; cd = cd->next) {
		if (cd->h != h)
		       continue;
		ASSERT(cd->len == len && !memcmp(name, cd->name, len));
		return cd;
	}
	cdheadp = &wb->cdtab[idx];

	// fprintf(stderr, "new %.*s #%u 0x%016lx\n", (int)len, name, idx, h);
	cd = cd_create(name, len, h);
	ASSERT(cd);
	if (!cd)
		return NULL;

	/* link */
	cd->next = *cdheadp;
	*cdheadp = cd;
	cd->cnext = wb->create_head;
	wb->create_head = cd;
	wb->city_count++;
#ifdef CHECKS
	if (cd->next)
		wb->collisions++;
#endif
	return cd;
}

void wb_check_parse(long line, const char *e, const char *cs, size_t clen, const char *ns, size_t nlen, uint64_t h)
{
	const char *ce, *ne;
	const char *vs;
	const char *vcs, *vce;
	const char *vns, *vne;
	uint64_t vh, v;
	int wpos;
	char c;

	ce = cs + clen;
	ne = ns + nlen;

	vcs = cs;
	vs = vcs;
	wpos = 0;
	v = 0;
	vh = hash_setup();
	while (vs < e && (c = *vs++) != ';') {
		if (wpos == 0)
			v = 0;
		v = set_char_at_pos(v, c, wpos);
		if (++wpos >= 8) {
			vh = hash_update(vh, v);
			wpos = 0;
		}
	}
	if (wpos > 0)
		vh = hash_update(vh, v);
	vce = vs - 1;

	/* verify */
	vns = ns;
	while (vs < e && *vs != '\n')
		vs++;
	vne = vs++;

	if (vce != ce) {
		fprintf(stderr, "%ld: Bad city: was '%.*s' should be '%.*s' %p/%p %p/%p\n", line,
				(int)(ce - cs), cs, (int)(vce - vcs), vcs,
				cs, vcs, ce, vce);
	}
	ASSERT(vce == ce);

	if (vh != h) {
		fprintf(stderr, "%ld: Bad hash for city '%.*s': was 0x%016lx should be 0x%016lx\n", line,
				(int)(ce - cs), cs, vh, h);
	}
	ASSERT(vh == h);

	if (vne != ne) {
		fprintf(stderr, "%ld: City '%.*s'; bad temp '%.*s' should be '%.*s' %p/%p %p/%p\n", line,
				(int)(ce - cs), cs,
				(int)(ne - ns), ns,
				(int)(vne - vns), vns,
				ns, vns, ne, vne);
	}
	ASSERT(vne == ne);
}

#undef OOB
#ifndef CHECKS
#define OOB() do { /* nothing */ } while(0)
#else
#define OOB() do { if (s > e) abort(); } while(0)
#endif

ALWAYS_INLINE const char *
wb_parse_line(struct work_block *wb, const char *s, const char *e, bool check)
{
	struct city_data *cd;
	const char *cs, *ce;
	const char *ns, *ne;
	size_t nlen;
	char c;
	int16_t neg, tempi;
	uint64_t cv, h, mv, m;
	uint32_t nv, nmv;
	int bpos, adv;

	h = hash_setup();

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
	cs = s;

	for (;;) {
		cv = check ? load64_guard(s, e, SEMICOLONS) : load64(s);
		mv = zbyte_mangle(cv ^ SEMICOLONS);
		if (mv)
			break;
		h = hash_update(h, cv);
		s += sizeof(uint64_t);
	}

	bpos = zbyte_bpos(mv);
	adv = zbyte_bpos_to_adv(bpos);
	if (adv) {
		m = zbyte_mask_from_bpos(bpos);
		h = hash_update(h, cv & m);
		s += adv;
	}
	OOB();
	ce = s++;

#ifdef CHECKS
	if (s >= e)
		return e;
#endif

	OOB();
	/* negative sign */
	c = *s;
	if (c == '-') {
		neg = -1;
		s++;
		OOB();
	} else
		neg = 1;

	/* scan forward for the newline, note that can only be max XX.X\n so... */
	ns = s;
	ASSERT((e - s) >= sizeof(uint32_t));

	nv = load32(s);	/* unaligned accesses here! */

	nmv = zbyte_mangle_u32(nv ^ NEWLINES_U32);
	if (nmv) {
		bpos = zbyte_bpos_u32(nmv);
		nv &= zbyte_mask_from_bpos_u32(bpos);
		adv = zbyte_bpos_to_adv(bpos);
		s += adv;
	} else
		s += sizeof(uint32_t); /* no newline, it's a full 4 bytes */
	ne = s++;

	ASSERT(s >= e || s[-1] == '\n');
	nlen = (size_t)(ne - ns);

	ASSERT(nlen == 3 || nlen == 4);
	/* convert 3 digit form to 4 digit form */
	// 3: 00011 << 2 -> 01100 & 8 -> 01000 = 8
	// 4: 00100 << 2 -> 10000 & 8 -> 00000 = 0
	nv <<= (nlen << 2) & 0x08;
	/* neg = -1 or 1 */
	tempi = parse_temp(nv) * neg;

	// printf("%.*s;%s%.*s - %d 0x%016lx 0x%03x\n", (int)(ce - cs), cs, neg ? "-" : "", (int)(ne - ns), ns, (int)(ne - ns), nv, dm);

#ifdef CHECKS
	wb_check_parse(0, e, cs, (size_t)(ce - cs), ns, (size_t)(ne - ns), h);
#endif

	cd = wb_lookup_or_create_city(wb, cs, (size_t)(ce - cs), h);
	ASSERT(cd);

	// printf("> %.*s %3.1f\n", (int)(size_t)(ce - cs), cs, (float)tempi / 10.0);

	cd->count++;
	cd->sumt += tempi;
	if (tempi < cd->mint)
		cd->mint = tempi;
	if (tempi > cd->maxt)
		cd->maxt = tempi;

	return s;
}

static int wb_process_actual(struct work_block *wb)
{
	const char *s, *e;

	s = wb->wd->start + wb->offset;
	e = s + wb->size;

	madvise((void *)s, (size_t)(e - s), MADV_SEQUENTIAL | MADV_WILLNEED);

	/* while we're safe, conditions out bound limits */
	while ((e - s) >= MAX_LINE_SIZE)
		s = wb_parse_line(wb, s, e, false);

	while (s < e)
		s = wb_parse_line(wb, s, e, true);

	return 0;
}

#undef OOB

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
	long ret;
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

	ret = sysconf(_SC_PAGESIZE);
	if (ret < 0)
		return -1;

	pagesz = (size_t)ret;

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
		return wb_process_actual(wb);

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

	/* merge the results */
	for (i = 0; i < nchildren; i++) {
		wbc = wbs[i];

		for (cdc = wbc->create_head; cdc; cdc = cdc->cnext) {

			cd = wb_lookup_or_create_city(wb, cdc->name, cdc->len, cdc->h);
			ASSERT(cd);

			/* merge the data */
			cd->count += cdc->count;
			cd->sumt += cdc->sumt;
			if (cdc->mint < cd->mint)
				cd->mint = cdc->mint;
			if (cdc->maxt > cd->maxt)
				cd->maxt = cdc->maxt;
		}
	}

	/* destroy the workers */
	for (i = 0; i < nchildren; i++)
		wb_destroy(wbs[i]);

	return 0;
}

static int city_cmp(const void *a, const void *b)
{
	const struct city_data * const *cap = a;
	const struct city_data * const *cbp = b;
	const struct city_data *ca = *cap;
	const struct city_data *cb = *cbp;

	ASSERT(ca);
	ASSERT(cb);
	return strcmp(ca->name, cb->name);
}

void wb_report(struct work_block *wb)
{
	struct city_data *cd;
	unsigned int i, count;
	struct city_data **cdtab;

	if (!wb)
		return;

	cdtab = malloc(sizeof(*cdtab) * wb->city_count);
	ASSERT(cdtab);
#ifdef CHECKS
	if (!cdtab)
		return;
#endif

	count = 0;
	for (cd = wb->create_head; cd; cd = cd->cnext) {
		ASSERT(count < wb->city_count);
		cdtab[count++] = cd;
	}
	ASSERT(count == wb->city_count);

	qsort(cdtab, count, sizeof(cdtab[0]), city_cmp);

	for (i = 0; i < count; i++) {
		cd = cdtab[i];
		printf("%s%s%s=%3.1f/%3.1f/%3.1f%s",
				i == 0 ? "{" : "",
				i > 0 ? ", " : "",
				cd->name,
				(float)cd->mint * 0.1,
				round((float)cd->sumt / cd->count) * 0.1,
				(float)cd->maxt * 0.1,
				i >= (count - 1) ? "}\n" : "");
	}

	free(cdtab);
}

struct weather_data *
wd_open(const char *file, int workers)
{
	struct weather_data *wd;
	struct stat sb;
	int rc;

	wd = malloc(sizeof(*wd));
	if (!wd)
		goto err_out;
	memset(wd, 0, sizeof(*wd));
	wd->fd = -1;
	wd->file = file;

	wd->fd = open(wd->file, O_RDONLY);
	if (wd->fd < 0)
		goto err_out;

	rc = fstat(wd->fd, &sb);
	if (rc)
		goto err_out;

	wd->size = sb.st_size;

	wd->addr = mmap(NULL, wd->size, PROT_READ, MAP_SHARED, wd->fd, 0);
	if (wd->addr == MAP_FAILED)
		goto err_out;

	wd->start = wd->addr;

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

void wd_close(struct weather_data *wd)
{
	if (!wd)
		return;

	if (wd->root_wb)
		wb_destroy(wd->root_wb);

	if (wd->addr != MAP_FAILED && wd->addr != NULL)
		munmap(wd->addr, wd->size);

	if (wd->fd >= 0)
		close(wd->fd);

	free(wd);
}

void wd_report(struct weather_data *wd)
{
	if (!wd || !wd->root_wb)
		return;
	return wb_report(wd->root_wb);
}

static struct option lopts[] = {
	{"bench",		no_argument,		0,	'b' },
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
	fprintf(fp, "\n--bench, -b              : Bench mode no output\n");
	fprintf(fp, "\t--workers, -w <n>        : Set workers to <n>\n");
	fprintf(fp, "\t--help, -h               : Display  help message\n");
	fprintf(fp, "\n");
}

int main(int argc, char *argv[])
{
	int opt, lidx;
	struct weather_data *wd = NULL;
	const char *file;
	int workers = -1;
	bool bench = false;
	int ret = EXIT_FAILURE;

	while ((opt = getopt_long_only(argc, argv, "w:bh", lopts, &lidx)) != -1) {
		switch (opt) {
		case 'w':
			workers = atoi(optarg);
			break;
		case 'b':
			bench = true;
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

	wd = wd_open(file, workers);
	if (wd) {
		if (!bench)
			wd_report(wd);

		wd_close(wd);

		ret = EXIT_SUCCESS;
	} else
		fprintf(stderr, "Unable to open/process weather data file '%s': %s\n",
				file, strerror(errno));

	return ret;

}

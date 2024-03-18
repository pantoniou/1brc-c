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
#include <stdatomic.h>

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

ALWAYS_INLINE uint64_t load64_guard(const void *p, const void *e, const uint64_t guard)
{
	uint64_t tmp;

	/* in the buffer */
	if ((p + sizeof(uint64_t)) <= e)
		return load64(p);
	if (p >= e)
		return guard;
	tmp = guard;
	memcpy(&tmp, p, (size_t)(e - p));
	return tmp;
}

ALWAYS_INLINE uint64_t load64_check(const void *p, const void *e, const uint64_t guard, const bool check)
{
	return check ? load64_guard(p, e, guard) : load64(p);
}

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
	unsigned int flags;
	int fd;
	void *addr;
	const char *start;
	size_t size;
	struct work_block *root_wb;
};

#define WDF_VERBOSE	1
#define WDF_TIMINGS	2
#define WDF_BENCH	4

struct weather_data *wd_open(const char *file, int workers, unsigned int flags);
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

#define VSTR(_v) \
	({ \
	 	uint64_t __v = (_v); \
	 	char *_buf = alloca(2 * 8 + 1); \
		char _c, *_s; \
		int _i; \
		for (_i = 0, _s = _buf; _i < 8; _i++) { \
			_c = ((char *)&__v)[_i]; \
			if (_c == '\n') { \
				*_s++ = '\\'; \
				*_s++ = 'n'; \
			} else if (_c == '"') { \
				*_s++ = '\\'; \
				*_s++ = '"'; \
			} else \
				*_s++ = _c; \
		} \
		*_s = '\0'; \
	 	_buf; \
	})

ALWAYS_INLINE const char *
wb_parse_line(struct work_block *wb,
	      const char *s, const char *e,
	      const bool check)
{
	struct city_data *cd;
	const char *cs;
	int16_t tempi;
	uint64_t cv, tv, h, mv, m;
	int bpos, adv, have, minus_mult;
	size_t clen;

	// fprintf(stderr, "start: %s\n", VSTR(load64_guard(s, e, SEMICOLONS)));

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

	h = hash_setup();
	for (;;) {
		// fprintf(stderr, "load: %s\n", VSTR(load64_guard(s, e, SEMICOLONS)));

		/* load a 64 bit value (guarding if needed) */
		cv = load64_check(s, e, SEMICOLONS, check);
		/* make a 0 byte appear where a semicolon exists */
		mv = zbyte_mangle(cv ^ SEMICOLONS);
		if (mv)
			break; /* break out when a semicolon is found */
		h = hash_update(h, cv);
		s += sizeof(uint64_t);
	}

	/* find the bit position of the semicoon */
	bpos = zbyte_bpos(mv);
	/* convert it to a byte advance number */
	adv = zbyte_bpos_to_adv(bpos);

	// fprintf(stderr, "found bpos=%d, adv=%d\n", bpos, adv);

	/* if it's 0, it means that we don't have to advance */
	if (adv) {
		m = zbyte_mask_from_bpos(bpos);
		/* mask out the non city part */
		h = hash_update(h, cv & m);
		s += adv;
	}

	clen = (size_t)(s - cs);

	s++;	/* over the ';' */

#if 1
	/* how many bytes we have that are valid */
	have = 8 - (adv + 1);

	// fprintf(stderr, "have=%d, cv=%s\n", have, VSTR(cv));

	if (have) {
		/* skip over the consumed city part + semicolon */
		cv >>= (adv + 1) << 3;

		/* shift in any partial */
		if (have < MAX_TEMP_BYTES) {
			tv = load64_check(s + have, e, NEWLINES, check);
			cv |= tv << (have << 3);
		}
	} else {
		cv = check ? load64_guard(s, e, NEWLINES) : load64(s);
	}

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

	/* get the 4th bit to the 0 position */
	tv = (cv & 0x10) >> 4;

	/* shift out the minus */
	cv >>= ((~cv & 0x10) >> 1);

	tv -= 1;
	tv |= 1;
	minus_mult = (int)tv;

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

	/* advance pointer by the amount required */
	adv = ((unsigned int)minus_mult >> (sizeof(minus_mult) * 8 - 1));
	// fprintf(stderr, "minus adv=%d\n", adv);

       	adv += 3;
	// fprintf(stderr, "base adv=%d\n", adv);

	/* if 4 byte form the lowest byte is some kind of 3x (bit 4 set) */
       	adv += (cv >> 4) & 1;
	adv += 1;
	// fprintf(stderr, "final adv=%d\n", adv);

	/* the low 32bits of the cv contains the temp */

	/* calculate */
	tempi = (((uint32_t)cv & 0x0f000f0f) *
		 (uint64_t)(1 + (10 << 16) + (100 << 24)) >> 24) & ((1 << 10) - 1);
	tempi *= minus_mult;

	// fprintf(stderr, "%.*s;%3.1f clen=%zu adv=%d\n", (int)clen, cs, (float)tempi * 0.1, clen, adv);

	s += adv;

	assert(s[-1] == '\n');

#endif

	cd = wb_lookup_or_create_city(wb, cs, clen, h);
	ASSERT(cd);

	cd->count++;
	cd->sumt += tempi;
	if (tempi < cd->mint)
		cd->mint = tempi;
	if (tempi > cd->maxt)
		cd->maxt = tempi;

	return s;
}

struct parse_line_info {
	uint64_t h;
	int16_t temp;
	uint8_t clen;
	uint8_t advance;
};

ALWAYS_INLINE struct parse_line_info
parse_line(const char *start, size_t len, const bool check)
{
	struct parse_line_info r;
	const char *s, *e;
	uint64_t cv, tv, mv;
	int bpos, adv, have, minus_mult;

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
	s = start;
	e = start + len;

	r.h = hash_setup();

	while ((mv = zbyte_mangle((cv = load64_check(s, e, SEMICOLONS, check)) ^ SEMICOLONS)) == 0) {
		r.h = hash_update(r.h, cv);
		s += sizeof(uint64_t);
	}

	/* find the bit position of the semicoon */
	bpos = zbyte_bpos(mv);
	/* convert it to a byte advance number */
	adv = zbyte_bpos_to_adv(bpos);
	s += adv;

	// fprintf(stderr, "found bpos=%d, adv=%d\n", bpos, adv);

	/* if it's 0, it means that we don't have to advance */
	if (adv)
		r.h = hash_update(r.h, cv & zbyte_mask_from_bpos(bpos));

	/* must be done in two steps, because if adv == 8 shift about is
	 * size of the type. on most arches the shift is modulo.
	 */
	cv >>= 8;
	cv >>= (adv << 3);

	r.clen = (size_t)(s - start);

	s++;	/* over the ';' */

	/* how many bytes we have that are valid */
	have = 8 - (adv + 1);

	// fprintf(stderr, "have=%d, cv=%s\n", have, VSTR(cv));

	/* shift in any partial */
	if (have < MAX_TEMP_BYTES)
		cv |= load64_check(s + have, e, NEWLINES, check) << (have << 3);

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

	/* get the 4th bit to the 0 position */
	tv = (cv & 0x10) >> 4;

	adv = (int)(tv ^ 1);

	/* shift out the minus */
	cv >>= ((~cv & 0x10) >> 1);

	tv -= 1;
	tv |= 1;
	minus_mult = (int)tv;

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

       	adv += 3;

	/* if 4 byte form the lowest byte is some kind of 3x (bit 4 set) */
       	adv += (cv >> 4) & 1;
	adv += 1;

	/* the low 32bits of the cv contains the temp */

	/* calculate */
	r.temp = (((uint32_t)cv & 0x0f000f0f) *
		 (uint64_t)(1 + (10 << 16) + (100 << 24)) >> 24) & ((1 << 10) - 1);
	r.temp *= minus_mult;

	s += adv;

	r.advance = (uint8_t)(s - start);

	return r;
}

ALWAYS_INLINE struct parse_line_info
parse_line2(const char *start, const char *end, const bool check)
{
	struct parse_line_info r;
	uint64_t cv, tv, mv;
	int pos, bpos, adv, have, minus_mult;

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

	pos = 0;
	r.h = hash_setup();
	while ((mv = zbyte_mangle((cv = load64_check(start + pos, end, SEMICOLONS, check)) ^ SEMICOLONS)) == 0) {
		r.h = hash_update(r.h, cv);
		pos += sizeof(uint64_t);
	}

	/* find the bit position of the semicoon */
	bpos = zbyte_bpos(mv);
	/* convert it to a byte advance number */
	adv = zbyte_bpos_to_adv(bpos);
	pos += adv;

	/* if it's 0, it means that we don't have to advance */
	if (adv)
		r.h = hash_update(r.h, cv & zbyte_mask_from_bpos(bpos));

	/* must be done in two steps, because if adv == 8 shift about is
	 * size of the type. on most arches the shift is modulo.
	 */
	cv >>= 8;
	cv >>= (adv << 3);

	r.clen = pos++;

	/* how many bytes we have that are valid */
	have = 8 - (adv + 1);

	/* shift in any partial */
	if (have < MAX_TEMP_BYTES)
		cv |= load64_check(start + pos + have, end, NEWLINES, check) << (have << 3);

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

	/* get the 4th bit to the 0 position */
	tv = (cv & 0x10) >> 4;

	pos += (int)(tv ^ 1);

	/* shift out the minus */
	cv >>= ((~cv & 0x10) >> 1);

	tv -= 1;
	tv |= 1;
	minus_mult = (int)tv;

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

       	pos += 3 + ((cv >> 4) & 1) + 1;

	/* calculate */
	r.temp = (((uint32_t)cv & 0x0f000f0f) *
		 (uint64_t)(1 + (10 << 16) + (100 << 24)) >> 24) & ((1 << 10) - 1);
	r.temp *= minus_mult;

	r.advance = pos;

	return r;
}

__attribute__((noinline)) struct parse_line_info
parse_line_no_inline(const char *start, const char *end)
{
	return parse_line2(start, end, false);
}

int wb_process_actual(struct work_block *wb)
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

ALWAYS_INLINE void
use_result(struct work_block *wb, struct parse_line_info r, const char *s)
{
	struct city_data *cd;

	cd = wb_lookup_or_create_city(wb, s, r.clen, r.h);
	ASSERT(cd);

	cd->count++;
	cd->sumt += r.temp;
	if (r.temp < cd->mint)
		cd->mint = r.temp;
	if (r.temp > cd->maxt)
		cd->maxt = r.temp;
}

int wb_process_actual2(struct work_block *wb)
{
	const char *s, *e;
	size_t len;
	struct parse_line_info r;
	struct timespec tstart, tend;

	clock_gettime(CLOCK_MONOTONIC, &tstart);

	s = wb->wd->start + wb->offset;
	e = s + wb->size;

	madvise((void *)s, (size_t)(e - s), MADV_SEQUENTIAL | MADV_WILLNEED);

	/* while we're safe, conditions out bound limits */
	while ((size_t)(e - s) >= MAX_LINE_SIZE) {
		r = parse_line2(s, e, false);
		use_result(wb, r, s);
		s += r.advance;
		len -= r.advance;
	}

	/* we need to check bounds now */
	while (s < e) {
		r = parse_line2(s, e, true);
		use_result(wb, r, s);
		s += r.advance;
		len -= r.advance;
	}

	clock_gettime(CLOCK_MONOTONIC, &tend);

	if (wb->wd->flags & WDF_TIMINGS)
		fprintf(stderr, "%s: time=%lldns\n", __func__, delta_ns(tstart, tend));

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
	struct timespec tstart, tend;

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
		return wb_process_actual2(wb);

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

	ASSERT(ca);
	ASSERT(cb);
	return strcmp(ca->name, cb->name);
}

void wb_report(struct work_block *wb)
{
	struct city_data *cd;
	unsigned int i, count;
	struct city_data **cdtab;
	struct timespec tstart, tend;

	if (!wb)
		return;

	clock_gettime(CLOCK_MONOTONIC, &tstart);

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

	clock_gettime(CLOCK_MONOTONIC, &tend);

	if (wb->wd->flags & WDF_TIMINGS)
		fprintf(stderr, "%s: time=%lldns\n", __func__, delta_ns(tstart, tend));
}

struct weather_data *
wd_open(const char *file, int workers, unsigned int flags)
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
	wd->flags = flags;

	wd->fd = open(wd->file, O_RDONLY);
	if (wd->fd < 0)
		goto err_out;

	rc = fstat(wd->fd, &sb);
	if (rc)
		goto err_out;

	wd->size = sb.st_size;

	wd->addr = mmap(NULL, wd->size, PROT_READ, MAP_PRIVATE, wd->fd, 0);
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
	struct timespec tstart, tend;
	unsigned int flags;

	if (!wd)
		return;

	clock_gettime(CLOCK_MONOTONIC, &tstart);

	if (wd->root_wb)
		wb_destroy(wd->root_wb);

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
	unsigned int flags = 0;

	while ((opt = getopt_long_only(argc, argv, "w:bvth", lopts, &lidx)) != -1) {
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
		case 'h':
		default:
			if (opt != 'h')
				fprintf(stderr, "Unknown option '%c' %d\n", opt, opt);
			display_usage(opt == 'h' ? stdout : stderr);
			return opt == 'h' ? EXIT_SUCCESS : EXIT_FAILURE;
		}
	}

	file = optind >= argc ? "measurements.txt" : argv[optind];

	wd = wd_open(file, workers, flags);
	if (!wd) {
		fprintf(stderr, "Unable to open/process weather data file '%s': %s\n",
				file, strerror(errno));
		return EXIT_FAILURE;
	}
	wd_report(wd);

	wd_close(wd);

	return EXIT_SUCCESS;
}

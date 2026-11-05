/* gfopenntlm: byte order helpers and UTF-8 to UTF-16LE.
 * MIT, Copyright (c) 2026 AmiCradle Team. */
#include "gn_internal.h"

void gn_put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
void gn_put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
uint16_t gn_get16(const uint8_t *p) { return (uint16_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8)); }
uint32_t gn_get32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

void gn_wipe(void *p, size_t n)
{
	volatile uint8_t *q = p;
	while (n--) *q++ = 0;
}

/* Uppercase() for NTOWFv2 ([MS-NLMP] 3.3.2: Uppercase(User)) and anything
 * else that asks gn_utf16() for upper case. It is the Unicode simple
 * uppercase mapping (UnicodeData.txt, field 12) for the BMP blocks a user
 * or domain name is written in, a small table rather than the full one:
 *   Basic Latin, Latin-1 Supplement (not U+00B5 MICRO SIGN), Latin
 *   Extended-A (not U+0131 dotless i or U+017F long s), Latin Extended-B
 *   U+0182..U+0233, IPA letters with a Latin capital, Greek (U+0386..U+03CE,
 *   final sigma included), Cyrillic U+0430..U+04FF, Armenian, Latin
 *   Extended Additional (U+1E00..U+1E95, U+1EA0..U+1EF9) and the
 *   fullwidth Latin letters.
 * Not mapped (left as they are): Greek Extended, Coptic, Georgian,
 * Cherokee, Glagolitic, the Latin Extended-B letters after U+0233, symbol
 * variants such as U+03D0, characters outside the BMP, and the
 * special (one-to-many) mappings such as U+00DF sharp s, which a 1:1 NTLM
 * Uppercase() keeps. U+0131 and U+017F are left alone on purpose: they
 * map to ASCII I and S in Unicode, which Windows' upcase table does not do.
 * Written from the Unicode code charts; tests/test_vectors.c checks it. */
#define GN_PAIRS 0x7fff   /* lo is a capital; lo+1, lo+3, .. are its small letters */
static const struct { uint16_t lo, hi; int16_t d; } upper_tab[] = {
	{ 0x0061, 0x007a, -32 },
	{ 0x00e0, 0x00f6, -32 }, { 0x00f8, 0x00fe, -32 }, { 0x00ff, 0x00ff, 0x0178 - 0x00ff },
	{ 0x0100, 0x012f, GN_PAIRS }, { 0x0132, 0x0137, GN_PAIRS }, { 0x0139, 0x0148, GN_PAIRS },
	{ 0x014a, 0x0177, GN_PAIRS }, { 0x0179, 0x017e, GN_PAIRS },
	{ 0x0182, 0x0185, GN_PAIRS }, { 0x0187, 0x0188, GN_PAIRS }, { 0x018b, 0x018c, GN_PAIRS },
	{ 0x0191, 0x0192, GN_PAIRS }, { 0x0195, 0x0195, 0x01f6 - 0x0195 }, { 0x0198, 0x0199, GN_PAIRS },
	{ 0x01a0, 0x01a5, GN_PAIRS }, { 0x01a7, 0x01a8, GN_PAIRS }, { 0x01ac, 0x01ad, GN_PAIRS },
	{ 0x01af, 0x01b0, GN_PAIRS }, { 0x01b3, 0x01b6, GN_PAIRS }, { 0x01b8, 0x01b9, GN_PAIRS },
	{ 0x01bc, 0x01bd, GN_PAIRS }, { 0x01bf, 0x01bf, 0x01f7 - 0x01bf },
	{ 0x01c5, 0x01c5, -1 }, { 0x01c6, 0x01c6, -2 }, { 0x01c8, 0x01c8, -1 }, { 0x01c9, 0x01c9, -2 },
	{ 0x01cb, 0x01cb, -1 }, { 0x01cc, 0x01cc, -2 },
	{ 0x01cd, 0x01dc, GN_PAIRS }, { 0x01dd, 0x01dd, 0x018e - 0x01dd }, { 0x01de, 0x01ef, GN_PAIRS },
	{ 0x01f2, 0x01f2, -1 }, { 0x01f3, 0x01f3, -2 }, { 0x01f4, 0x01f5, GN_PAIRS },
	{ 0x01f8, 0x021f, GN_PAIRS }, { 0x0222, 0x0233, GN_PAIRS },
	{ 0x0253, 0x0253, 0x0181 - 0x0253 }, { 0x0254, 0x0254, 0x0186 - 0x0254 },
	{ 0x0256, 0x0257, 0x0189 - 0x0256 }, { 0x0259, 0x0259, 0x018f - 0x0259 },
	{ 0x025b, 0x025b, 0x0190 - 0x025b }, { 0x0260, 0x0260, 0x0193 - 0x0260 },
	{ 0x0263, 0x0263, 0x0194 - 0x0263 }, { 0x0268, 0x0268, 0x0197 - 0x0268 },
	{ 0x0269, 0x0269, 0x0196 - 0x0269 }, { 0x026f, 0x026f, 0x019c - 0x026f },
	{ 0x0272, 0x0272, 0x019d - 0x0272 }, { 0x0275, 0x0275, 0x019f - 0x0275 },
	{ 0x0280, 0x0280, 0x01a6 - 0x0280 }, { 0x0283, 0x0283, 0x01a9 - 0x0283 },
	{ 0x0288, 0x0288, 0x01ae - 0x0288 }, { 0x028a, 0x028b, 0x01b1 - 0x028a },
	{ 0x0292, 0x0292, 0x01b7 - 0x0292 },
	{ 0x03ac, 0x03ac, 0x0386 - 0x03ac }, { 0x03ad, 0x03af, 0x0388 - 0x03ad },
	{ 0x03b1, 0x03c1, -32 }, { 0x03c2, 0x03c2, 0x03a3 - 0x03c2 }, { 0x03c3, 0x03cb, -32 },
	{ 0x03cc, 0x03cc, 0x038c - 0x03cc }, { 0x03cd, 0x03ce, 0x038e - 0x03cd },
	{ 0x0430, 0x044f, -32 }, { 0x0450, 0x045f, -80 }, { 0x0460, 0x0481, GN_PAIRS },
	{ 0x048a, 0x04bf, GN_PAIRS }, { 0x04c1, 0x04ce, GN_PAIRS }, { 0x04d0, 0x04ff, GN_PAIRS },
	{ 0x0561, 0x0586, -48 },
	{ 0x1e00, 0x1e95, GN_PAIRS }, { 0x1ea0, 0x1ef9, GN_PAIRS },
	{ 0xff41, 0xff5a, -32 },
};

uint32_t gn_upper(uint32_t c)
{
	size_t i;
	if (c < 0x61 || c > 0xff5a) return c;
	for (i = 0; i < sizeof upper_tab / sizeof upper_tab[0]; i++) {
		if (c < upper_tab[i].lo) break;
		if (c <= upper_tab[i].hi) {
			if (upper_tab[i].d != GN_PAIRS) return (uint32_t)((int32_t)c + upper_tab[i].d);
			return ((c - upper_tab[i].lo) & 1) ? c - 1 : c;
		}
	}
	return c;
}

uint8_t *gn_utf16(const char *s, int up, size_t *outlen)
{
	const uint8_t *p = (const uint8_t *)(s ? s : "");
	size_t n = 0, cap;
	uint8_t *out;
	while (p[n]) n++;
	cap = 4 * n + 2;            /* each byte gives at most one unit, a surrogate pair at most 4 */
	out = gn_alloc(cap);
	if (!out) return NULL;
	n = 0;
	while (*p) {
		uint32_t c = *p++;
		int extra = 0;
		uint32_t min_c = 0;
		/* Reject overlong encodings and bare continuation / invalid leads (L2). */
		if (c < 0x80) { /* ASCII */ }
		else if (c >= 0xc2 && c <= 0xdf) { c &= 0x1f; extra = 1; min_c = 0x80; }
		else if (c >= 0xe0 && c <= 0xef) { c &= 0x0f; extra = 2; min_c = 0x800; }
		else if (c >= 0xf0 && c <= 0xf4) { c &= 0x07; extra = 3; min_c = 0x10000; }
		else { c = 0xfffd; } /* C0/C1 overlong lead, F5-FF, or continuation */
		while (extra > 0) {
			if ((*p & 0xc0) != 0x80) { c = 0xfffd; break; }
			c = (c << 6) | (*p++ & 0x3f);
			extra--;
		}
		if (extra != 0)
			c = 0xfffd;
		else if (c != 0xfffd && c < min_c)
			c = 0xfffd; /* overlong */
		else if (c >= 0xd800 && c <= 0xdfff)
			c = 0xfffd; /* UTF-16 surrogate */
		else if (c > 0x10ffff)
			c = 0xfffd;
		if (up) c = gn_upper(c);
		if (c >= 0x10000 && c <= 0x10ffff) {
			c -= 0x10000;
			gn_put16(out + n, (uint16_t)(0xd800 | (c >> 10)));
			gn_put16(out + n + 2, (uint16_t)(0xdc00 | (c & 0x3ff)));
			n += 4;
		} else {
			gn_put16(out + n, (uint16_t)(c > 0xffff ? 0xfffd : c));
			n += 2;
		}
	}
	*outlen = n;
	return out;
}

/* gfopenntlm's PC tests: the published vectors of RFC 1320 (MD4),
 * RFC 1321 (MD5), RFC 2202 (HMAC-MD5), RFC 6229 (RC4), FIPS 180-2's
 * examples (SHA-256) and [MS-NLMP] 4.2 (NTLM), then CredSSP ([MS-CSSP]
 * has no vectors) end to end against a test server written from the
 * same specifications.  MIT, Copyright (c) 2026 AmiCradle Team. */
#include "../src/gn_internal.h"
#include <clib/gfopenntlm_protos.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "winpr_transcript.h"

static int pass, failed;

static size_t unhex(const char *s, uint8_t *out)
{
	size_t n = 0;
	int hi = -1;
	for (; *s; s++) {
		int v;
		if (*s >= '0' && *s <= '9') v = *s - '0';
		else if (*s >= 'a' && *s <= 'f') v = *s - 'a' + 10;
		else if (*s >= 'A' && *s <= 'F') v = *s - 'A' + 10;
		else continue;
		if (hi < 0) hi = v; else { out[n++] = (uint8_t)(hi << 4 | v); hi = -1; }
	}
	return n;
}

static void check_bytes(const char *what, const uint8_t *got, size_t len, const char *hex)
{
	uint8_t want[2048];
	size_t wl = unhex(hex, want), i;
	if (wl == len && !memcmp(got, want, len)) { pass++; printf("ok   %s\n", what); return; }
	failed++;
	printf("FAIL %s\n  got  ", what);
	for (i = 0; i < len; i++) printf("%02x", got[i]);
	printf("\n  want ");
	for (i = 0; i < wl; i++) printf("%02x", want[i]);
	printf("\n");
}

static void check(const char *what, int ok)
{
	if (ok) { pass++; printf("ok   %s\n", what); }
	else { failed++; printf("FAIL %s\n", what); }
}

static void test_md4(void)
{
	static const char *const v[][2] = {
		{ "", "31d6cfe0d16ae931b73c59d7e0c089c0" },
		{ "a", "bde52cb31de33e46245e05fbdbd6fb24" },
		{ "abc", "a448017aaf21d8525fc10ae87aa6729d" },
		{ "message digest", "d9130a8164549fe818874806e1c7014b" },
		{ "abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9" },
		{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4" },
		{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536" },
	};
	size_t i;
	for (i = 0; i < sizeof v / sizeof v[0]; i++) {
		uint8_t d[16]; char name[64];
		gn_md4(v[i][0], strlen(v[i][0]), d);
		snprintf(name, sizeof name, "RFC 1320 MD4 #%u", (unsigned)i + 1);
		check_bytes(name, d, 16, v[i][1]);
	}
}

static void test_md5(void)
{
	static const char *const v[][2] = {
		{ "", "d41d8cd98f00b204e9800998ecf8427e" },
		{ "a", "0cc175b9c0f1b6a831c399e269772661" },
		{ "abc", "900150983cd24fb0d6963f7d28e17f72" },
		{ "message digest", "f96b697d7cb7938d525a2f31aaf161d0" },
		{ "abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b" },
		{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f" },
		{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "57edf4a22be3c955ac49da2e2107b67a" },
	};
	size_t i;
	for (i = 0; i < sizeof v / sizeof v[0]; i++) {
		uint8_t d[16]; char name[64];
		gn_md5(v[i][0], strlen(v[i][0]), d);
		snprintf(name, sizeof name, "RFC 1321 MD5 #%u", (unsigned)i + 1);
		check_bytes(name, d, 16, v[i][1]);
	}
}

static void test_hmac(void)
{
	uint8_t k[80], d[80], m[16];
	memset(k, 0x0b, 16); gn_hmac_md5(k, 16, "Hi There", 8, m);
	check_bytes("RFC 2202 HMAC-MD5 #1", m, 16, "9294727a3638bb1c13f48ef8158bfc9d");
	gn_hmac_md5("Jefe", 4, "what do ya want for nothing?", 28, m);
	check_bytes("RFC 2202 HMAC-MD5 #2", m, 16, "750c783e6ab0b503eaa86e310a5db738");
	memset(k, 0xaa, 16); memset(d, 0xdd, 50); gn_hmac_md5(k, 16, d, 50, m);
	check_bytes("RFC 2202 HMAC-MD5 #3", m, 16, "56be34521d144c88dbb8c733f0e8b3f6");
	{ int i; for (i = 0; i < 25; i++) k[i] = (uint8_t)(i + 1); }
	memset(d, 0xcd, 50); gn_hmac_md5(k, 25, d, 50, m);
	check_bytes("RFC 2202 HMAC-MD5 #4", m, 16, "697eaf0aca3a3aea3a75164746ffaa79");
	memset(k, 0x0c, 16); gn_hmac_md5(k, 16, "Test With Truncation", 20, m);
	check_bytes("RFC 2202 HMAC-MD5 #5", m, 16, "56461ef2342edc00f9bab995690efd4c");
	memset(k, 0xaa, 80);
	gn_hmac_md5(k, 80, "Test Using Larger Than Block-Size Key - Hash Key First", 54, m);
	check_bytes("RFC 2202 HMAC-MD5 #6", m, 16, "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd");
	gn_hmac_md5(k, 80, "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data", 73, m);
	check_bytes("RFC 2202 HMAC-MD5 #7", m, 16, "6f630fad67cda0ee1fb1f562db3aa53e");
}

static void test_rc4(void)
{
	uint8_t key[16], z[512], ks[512];
	struct gn_rc4 r;
	memset(z, 0, sizeof z);
	unhex("0102030405", key);
	gn_rc4_init(&r, key, 5); gn_rc4_crypt(&r, z, ks, 512);
	check_bytes("RFC 6229 RC4 40-bit offset 0", ks, 16, "b2396305f03dc027ccc3524a0a1118a8");
	check_bytes("RFC 6229 RC4 40-bit offset 16", ks + 16, 16, "6982944f18fc82d589c403a47a0d0919");
	check_bytes("RFC 6229 RC4 40-bit offset 240", ks + 240, 16, "28cb1132c96ce286421dcaadb8b69eae");
	check_bytes("RFC 6229 RC4 40-bit offset 496", ks + 496, 16, "42b7d0cdd918a8a33dd51781c81f4041");
	unhex("0102030405060708090a0b0c0d0e0f10", key);
	gn_rc4_init(&r, key, 16); gn_rc4_crypt(&r, z, ks, 272);
	check_bytes("RFC 6229 RC4 128-bit offset 0", ks, 16, "9ac7cc9a609d1ef7b2932899cde41b97");
	check_bytes("RFC 6229 RC4 128-bit offset 16", ks + 16, 16, "5248c4959014126a6e8a84f11d1a9e1c");
	check_bytes("RFC 6229 RC4 128-bit offset 256", ks + 256, 16, "d39d566bc6bce30107681515 49f3873f");
}

static void test_sha256(void)
{
	uint8_t d[32];
	static uint8_t a[1000000];
	gn_sha256("abc", 3, d);
	check_bytes("FIPS 180-2 SHA-256 \"abc\"", d, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	gn_sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, d);
	check_bytes("FIPS 180-2 SHA-256 448 bits", d, 32, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
	memset(a, 'a', sizeof a);
	gn_sha256(a, sizeof a, d);
	check_bytes("FIPS 180-2 SHA-256 a million a", d, 32, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

/* [MS-NLMP] 4.2.4.3: the CHALLENGE_MESSAGE */
static const char chal_hex[] =
	"4e544c4d53535000020000000c000c003800000033828ae20123456789abcdef"
	"00000000000000002400240044000000060070170000000f5300650072007600"
	"6500720002000c0044006f006d00610069006e0001000c005300650072007600"
	"6500720000000000";
/* [MS-NLMP] 4.2.4.3: the AUTHENTICATE_MESSAGE */
static const char auth_hex[] =
	"4e544c4d5353500003000000180018006c00000054005400840000000c000c00"
	"480000000800080054000000100010005c00000010001000d800000035828 8e2"
	"0501280a0000000f44006f006d00610069006e00550073006500720043004f00"
	"4d0050005500540045005200 86c35097ac9cec102554764a57cccc19aaaaaaaa"
	"aaaaaaaa68cd0ab851e51c96aabc927bebef6a1c010100000000000000000000"
	"00000000aaaaaaaaaaaaaaaa0000000002000c0044006f006d00610069006e00"
	"01000c005300650072007600650072000000000000000000c5dad2544fc97990"
	"94ce1ce90bc9d03e";

static void test_nlmp(void)
{
	struct gn_ntlm n;
	uint8_t pw[32], buf[1024], chal[256], out[64], key[16];
	size_t pl, len, cl;
	uint8_t *p16 = gn_utf16("Password", 0, &pl);
	(void)pw;
	gn_md4(p16, pl, key);
	check_bytes("MS-NLMP 4.2.2.1.2 NTOWFv1(\"Password\")", key, 16, "a4f49c406510bdcab6824ee7c30fd852");
	gn_free(p16, pl + 2);

	check(".. init", gn_ntlm_init(&n, "User", "Domain", "Password", "COMPUTER", NULL) == 0);
	check_bytes("MS-NLMP 4.2.4.1.1 NTOWFv2", n.response_key, 16, "0c868a403bfd7a93a3001ef22ef02e3f");
	n.test = GN_NTLM_T_FIXED | GN_NTLM_T_RAW;
	n.t_time = 0;
	memset(n.t_client_challenge, 0xaa, 8);
	memset(n.t_session_key, 0x55, 16);
	unhex("0501280a0000000f", n.version);
	check(".. NEGOTIATE", gn_ntlm_negotiate(&n, buf, sizeof buf, &len) == 0 && len == 40);
	cl = unhex(chal_hex, chal);
	check(".. the 4.2.4.3 CHALLENGE is 0x68 bytes", cl == 0x68);
	check(".. AUTHENTICATE", gn_ntlm_authenticate(&n, chal, cl, buf, sizeof buf, &len) == 0);
	check_bytes("MS-NLMP 4.2.4.1.2 SessionBaseKey", n.session_base_key, 16, "8de40ccadbc14a82f15cb0ad0de95ca3");
	check_bytes("MS-NLMP 4.2.4.2.1 LMv2 response", buf + 0x6c, 24, "86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa");
	check_bytes("MS-NLMP 4.2.4.2.2 NTProofStr", buf + 0x84, 16, "68cd0ab851e51c96aabc927bebef6a1c");
	check_bytes("MS-NLMP 4.2.4.1.3 temp", buf + 0x94, 0x44,
		"0101000000000000 0000000000000000 aaaaaaaaaaaaaaaa 00000000"
		"02000c0044006f006d00610069006e00 01000c00530065007200760065007200"
		"00000000 00000000");
	check_bytes("MS-NLMP 4.2.4.2.3 encrypted session key", buf + 0xd8, 16, "c5dad2544fc9799094ce1ce90bc9d03e");
	check_bytes("MS-NLMP 4.2.4.3 AUTHENTICATE_MESSAGE (0xe8 bytes)", buf, len, auth_hex);
	check_bytes("MS-NLMP 4.2.4.4 sealing key", n.client_seal_key, 16, "59f600973cc4960a25480a7c196e4c58");
	check_bytes("MS-NLMP 4.2.4.4 signing key", n.client_sign, 16, "4788dc861b4782f35d43fd98fe1a2d39");
	{
		static const uint8_t plain[18] = { 'P', 0, 'l', 0, 'a', 0, 'i', 0, 'n', 0, 't', 0, 'e', 0, 'x', 0, 't', 0 };
		check(".. wrap", gn_ntlm_wrap(&n, plain, 18, out, sizeof out, &len) == 0 && len == 34);
		check_bytes("MS-NLMP 4.2.4.4 GSS_WrapEx data", out + 16, 18, "54e50165bf1936dc996020c1811b0f06fb5f");
		check_bytes("MS-NLMP 4.2.4.4 GSS_WrapEx signature", out, 16, "010000007fb38ec5c55d497600000000");
	}
	/* the receiving side: a test server with the same key */
	{
		struct gn_ntlm s;
		uint8_t w[64], u[64];
		size_t wl, ul;
		int k, ok = 1;
		memset(&s, 0, sizeof s);
		gn_ntlm_set_keys(&s, n.exported_key, n.flags, 1);
		for (k = 0; k < 3; k++) {
			char msg[32];
			snprintf(msg, sizeof msg, "server message %d", k);
			ok &= gn_ntlm_wrap(&s, (const uint8_t *)msg, strlen(msg), w, sizeof w, &wl) == 0;
			ok &= gn_ntlm_unwrap(&n, w, wl, u, sizeof u, &ul) == 0 && ul == strlen(msg) && !memcmp(u, msg, ul);
		}
		check("GSS_UnwrapEx round trip, sequence 0..2", ok);
		gn_ntlm_wrap(&s, (const uint8_t *)"tampered", 8, w, sizeof w, &wl);
		w[20] ^= 1;
		check("GSS_UnwrapEx rejects a changed message", gn_ntlm_unwrap(&n, w, wl, u, sizeof u, &ul) == GN_EINTEGRITY);
		gn_ntlm_clear(&s);
	}
	gn_ntlm_clear(&n);
}

/* ---- a CredSSP test server ([MS-CSSP] 3.1.5 from the server's side) ---- */
struct srv {
	const char *password;
	uint32_t version;
	int bad_pubkey;          /* answer with the wrong binding */
	uint8_t pubkey[128]; size_t pklen;
	uint8_t neg[64]; size_t neg_len;
	uint8_t chal[256]; size_t chal_len;
	struct gn_ntlm keys;
	uint8_t nonce[32];
	char got_user[64], got_pass[64];
	int verified_mic;
	const char *user_upper;  /* the UTF-8 Uppercase(User), if not ASCII */
	uint8_t want_cb[16];     /* the MsvChannelBindings the server expects */
	int got_cb_ok;           /* the AUTHENTICATE carried want_cb */
};

/* the value of AV pair id in an NTLMv2 response's temp, or NULL */
static const uint8_t *find_av(const uint8_t *nt, size_t ntl, uint16_t id, size_t *len)
{
	size_t i = 16 + 28;   /* NTProofStr, then temp's fixed part */
	while (i + 4 <= ntl) {
		uint16_t t = gn_get16(nt + i), l = gn_get16(nt + i + 2);
		if (i + 4 + l > ntl) return NULL;
		if (t == id) { *len = l; return nt + i + 4; }
		if (t == MsvAvEOL) return NULL;
		i += 4u + l;
	}
	return NULL;
}

static void ascii16(const uint8_t *p, size_t len, char *out, size_t size)
{
	size_t i;
	for (i = 0; i + 1 < len && i / 2 + 1 < size; i += 2) out[i / 2] = (char)p[i];
	out[i / 2] = 0;
}

static size_t srv_challenge(struct srv *s, uint8_t *out, size_t size)
{
	uint8_t m[256], *q;
	struct gn_tsrequest r;
	size_t ti;
	static const uint8_t dom[] = { 'F', 0, 'A', 0, 'K', 0, 'E', 0 }, cmp[] = { 'S', 0, 'R', 0, 'V', 0 };
	memset(m, 0, sizeof m);
	memcpy(m, "NTLMSSP", 8);
	gn_put32(m + 8, 2);
	gn_put16(m + 12, 8); gn_put16(m + 14, 8); gn_put32(m + 16, 56);
	gn_put32(m + 20, 0xe28a8235u);
	memcpy(m + 24, "\x11\x22\x33\x44\x55\x66\x77\x88", 8);
	memcpy(m + 48, "\x0a\x00\x61\x4a\x00\x00\x00\x0f", 8);
	memcpy(m + 56, dom, 8);
	q = m + 64; ti = 64;
	gn_put16(q, 2); gn_put16(q + 2, 8); memcpy(q + 4, dom, 8); q += 12;
	gn_put16(q, 1); gn_put16(q + 2, 6); memcpy(q + 4, cmp, 6); q += 10;
	gn_put16(q, 7); gn_put16(q + 2, 8); gn_put32(q + 4, 0x12345678); gn_put32(q + 8, 0x01dc0000); q += 12;
	gn_put16(q, 0); gn_put16(q + 2, 0); q += 4;
	gn_put16(m + 40, (uint16_t)(q - m - ti)); gn_put16(m + 42, (uint16_t)(q - m - ti)); gn_put32(m + 44, (uint32_t)ti);
	s->chal_len = (size_t)(q - m);
	memcpy(s->chal, m, s->chal_len);
	memset(&r, 0, sizeof r);
	r.version = s->version;
	r.nego_token = s->chal; r.nego_token_len = s->chal_len;
	return gn_tsrequest_encode(&r, out, size);
}

/* checks AUTHENTICATE, MIC and pubKeyAuth; answers pubKeyAuth or an error */
static size_t srv_authenticate(struct srv *s, const uint8_t *in, size_t len, uint8_t *out, size_t size)
{
	struct gn_tsrequest r, a;
	const uint8_t *m, *nt, *user, *dom;
	size_t ml, ntl, ul, dl;
	uint8_t uu[128], key[16], nth[16], proof[16], sbk[16], exported[16], buf[512], pk[128];
	size_t i, pl, uul;
	struct gn_hmac_md5 h;
	uint8_t *pw16;
	size_t pwl;
	memset(&a, 0, sizeof a);
	a.version = s->version;
	if (gn_tsrequest_decode(in, len, &r) || !r.nego_token || !r.pub_key_auth) return 0;
	m = r.nego_token; ml = r.nego_token_len;
	if (ml < 88 || gn_get32(m + 8) != 3) return 0;
	nt = m + gn_get32(m + 24); ntl = gn_get16(m + 20);
	dom = m + gn_get32(m + 32); dl = gn_get16(m + 28);
	user = m + gn_get32(m + 40); ul = gn_get16(m + 36);
	ascii16(user, ul, s->got_user, sizeof s->got_user);
	if (s->user_upper) {
		uint8_t *u16 = gn_utf16(s->user_upper, 0, &uul);
		if (uul > sizeof uu) uul = sizeof uu;
		memcpy(uu, u16, uul);
		gn_free(u16, uul + 2);
	} else {
		for (i = 0; i < ul && i < sizeof uu; i += 2) {
			uu[i] = (user[i] >= 'a' && user[i] <= 'z') ? (uint8_t)(user[i] - 32) : user[i];
			uu[i + 1] = user[i + 1];
		}
		uul = ul;
	}
	{
		const uint8_t *cb;
		size_t cbl;
		cb = find_av(nt, ntl, MsvChannelBindings, &cbl);
		s->got_cb_ok = cb && cbl == 16 && !memcmp(cb, s->want_cb, 16);
		/* a server with channel bindings refuses others ([MS-NLMP] 3.2.5.1.2) */
		if (!s->got_cb_ok) {
			a.has_error = 1; a.error_code = 0xc000006du;
			return gn_tsrequest_encode(&a, out, size);
		}
	}
	pw16 = gn_utf16(s->password, 0, &pwl);
	gn_md4(pw16, pwl, nth);
	gn_free(pw16, pwl + 2);
	gn_ntowfv2(nth, uu, uul, dom, dl, key);
	gn_hmac_md5_init(&h, key, 16);
	gn_hmac_md5_update(&h, s->chal + 24, 8);
	gn_hmac_md5_update(&h, nt + 16, ntl - 16);
	gn_hmac_md5_final(&h, proof);
	if (memcmp(proof, nt, 16)) {
		a.has_error = 1; a.error_code = 0xc000006du;   /* STATUS_LOGON_FAILURE */
		return gn_tsrequest_encode(&a, out, size);
	}
	gn_hmac_md5(key, 16, proof, 16, sbk);
	{
		struct gn_rc4 rc;
		gn_rc4_init(&rc, sbk, 16);
		gn_rc4_crypt(&rc, m + gn_get32(m + 56), exported, 16);
	}
	/* the MIC */
	memcpy(buf, m, ml);
	memset(buf + 72, 0, 16);
	gn_hmac_md5_init(&h, exported, 16);
	gn_hmac_md5_update(&h, s->neg, s->neg_len);
	gn_hmac_md5_update(&h, s->chal, s->chal_len);
	gn_hmac_md5_update(&h, buf, ml);
	gn_hmac_md5_final(&h, proof);
	s->verified_mic = !memcmp(proof, m + 72, 16);
	memset(&s->keys, 0, sizeof s->keys);
	gn_ntlm_set_keys(&s->keys, exported, gn_get32(m + 60), 1);
	if (gn_ntlm_unwrap(&s->keys, r.pub_key_auth, r.pub_key_auth_len, buf, sizeof buf, &pl)) return 0;
	if (s->version >= 5) {
		uint8_t want[32];
		if (!r.client_nonce || r.client_nonce_len != 32) return 0;
		memcpy(s->nonce, r.client_nonce, 32);
		gn_cssp_hash("CredSSP Client-To-Server Binding Hash", s->nonce, s->pubkey, s->pklen, want);
		if (pl != 32 || memcmp(buf, want, 32)) return 0;
		gn_cssp_hash("CredSSP Server-To-Client Binding Hash", s->nonce, s->pubkey, s->pklen, pk);
		pl = 32;
	} else {
		if (pl != s->pklen || memcmp(buf, s->pubkey, pl)) return 0;
		memcpy(pk, s->pubkey, pl);
		pk[0]++;
	}
	if (s->bad_pubkey) pk[1] ^= 0x40;
	gn_ntlm_wrap(&s->keys, pk, pl, buf, sizeof buf, &pl);
	a.pub_key_auth = buf; a.pub_key_auth_len = pl;
	return gn_tsrequest_encode(&a, out, size);
}

static int srv_credentials(struct srv *s, const uint8_t *in, size_t len)
{
	struct gn_tsrequest r;
	uint8_t buf[512];
	size_t pl;
	struct gn_der d, seq, f, o, pc, x;
	if (gn_tsrequest_decode(in, len, &r) || !r.auth_info) return 0;
	if (gn_ntlm_unwrap(&s->keys, r.auth_info, r.auth_info_len, buf, sizeof buf, &pl)) return 0;
	d.p = buf; d.len = pl;
	if (gn_der_get(&d, 0x30, &seq) || gn_der_get(&seq, 0xa0, &f) || gn_der_get(&seq, 0xa1, &f) ||
	    gn_der_get(&f, 0x04, &o) || gn_der_get(&o, 0x30, &pc) || gn_der_get(&pc, 0xa0, &f) ||
	    gn_der_get(&pc, 0xa1, &f) || gn_der_get(&f, 0x04, &x)) return 0;
	if (gn_der_get(&pc, 0xa2, &f) || gn_der_get(&f, 0x04, &x)) return 0;
	ascii16(x.p, x.len, s->got_pass, sizeof s->got_pass);
	return 1;
}

struct run {
	uint32_t version;
	const char *client_pw;
	int bad_pubkey;
	int want;
	const char *user, *user_upper, *domain;  /* default "User", "FAKE" */
	const uint8_t *cb; ULONG cbl; ULONG flags; /* the client's channel bindings */
	int server_cb;           /* 1: the server expects cb; 0: Z(16) */
	int client_unbound;      /* the client is not given cb */
	const char *label;
};

static void credssp_run_ex(const struct run *o)
{
	struct GNCredSSPConfig cfg;
	struct GNCredSSP *c;
	struct srv s;
	uint8_t a[8192], b[8192];
	ULONG al;
	size_t bl;
	LONG e, r;
	char name[160];
	const char *user = o->user ? o->user : "User";
	memset(&s, 0, sizeof s);
	s.password = "Password";
	s.version = o->version;
	s.bad_pubkey = o->bad_pubkey;
	s.user_upper = o->user_upper;
	if (o->server_cb) gn_channel_bindings_hash(o->cb, o->cbl, (o->flags & GNF_CB_TLS_SERVER_END_POINT) != 0, s.want_cb);
	s.pklen = unhex("3048024100c0ffee0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627"
	                "28292a2b2c2d2e2f303132333435363738393a3b3c3d3e0203010001", s.pubkey);
	memset(&cfg, 0, sizeof cfg);
	cfg.Size = sizeof cfg;
	cfg.User = user; cfg.Domain = o->domain ? o->domain : "FAKE"; cfg.Password = o->client_pw; cfg.Workstation = "AMIGA";
	cfg.ServerName = "srv.example"; cfg.PublicKey = s.pubkey; cfg.PublicKeyLength = (ULONG)s.pklen;
	if (!o->client_unbound) {
		cfg.Flags = o->flags; cfg.ChannelBindings = o->cb; cfg.ChannelBindingsLength = o->cbl;
	}
	c = GN_CredSSPNew(&cfg, &e);
	snprintf(name, sizeof name, "CredSSP v%u%s%s%s", (unsigned)o->version,
	         strcmp(o->client_pw, "Password") ? " wrong password" : "", o->bad_pubkey ? " bad server binding" : "",
	         o->label ? o->label : "");
	if (!c) { check(name, 0); return; }
	r = GN_CredSSPStep(c, NULL, 0, a, sizeof a, &al);
	{
		struct gn_tsrequest q;
		if (r != GNERR_CONTINUE || gn_tsrequest_decode(a, al, &q) || !q.nego_token) { check(name, 0); goto out; }
		memcpy(s.neg, q.nego_token, q.nego_token_len); s.neg_len = q.nego_token_len;
	}
	bl = srv_challenge(&s, b, sizeof b);
	r = GN_CredSSPStep(c, b, (ULONG)bl, a, sizeof a, &al);
	if (r != GNERR_CONTINUE) { printf("  (step 2: %ld)\n", (long)r); check(name, 0); goto out; }
	bl = srv_authenticate(&s, a, al, b, sizeof b);
	if (!bl) { printf("  (the test server refused the AUTHENTICATE)\n"); check(name, 0); goto out; }
	r = GN_CredSSPStep(c, b, (ULONG)bl, a, sizeof a, &al);
	if (o->want == GNERR_SERVER) {
		snprintf(name + strlen(name), sizeof name - strlen(name), ": errorCode 0x%08lx", (unsigned long)GN_CredSSPGetAttr(c, GNA_SERVERERROR));
		check(name, r == GNERR_SERVER && GN_CredSSPGetAttr(c, GNA_SERVERERROR) == 0xc000006du);
	} else if (o->want == GNERR_PUBKEY) {
		check(name, r == GNERR_PUBKEY);
	} else {
		int ok = r == GNERR_OK && srv_credentials(&s, a, al) && s.verified_mic && s.got_cb_ok &&
		         !strcmp(s.got_pass, "Password") && GN_CredSSPGetAttr(c, GNA_VERSION) == o->version &&
		         GN_CredSSPGetAttr(c, GNA_CHANNELBINDINGS) == (o->cb ? 1u : 0u);
		if (!o->user_upper) ok &= !strcmp(s.got_user, user);
		check(name, ok);
		if (!o->label && o->version == 6 && !o->bad_pubkey) {
			/* the NTLM attributes, read through the CredSSP handle */
			check("  GN_CredSSPGetAttr(GNA_NTLMFLAGS): the negotiated flags",
			      GN_CredSSPGetAttr(c, GNA_NTLMFLAGS) == (0xe28a8235u & GN_NTLM_CLIENT_FLAGS));
			check("  GN_CredSSPGetAttr(GNA_NTLMPEERVERSION): the CHALLENGE's Version",
			      GN_CredSSPGetAttr(c, GNA_NTLMPEERVERSION) == 0x4a61000au);
			check("  GN_CredSSPGetAttr(GNA_STATE) is CredSSP's (3)", GN_CredSSPGetAttr(c, GNA_STATE) == 3);
			check("  GN_CredSSPGetAttr of an unknown attribute is 0", GN_CredSSPGetAttr(c, 999) == 0);
		}
	}
out:
	GN_CredSSPFree(c);
	gn_ntlm_clear(&s.keys);
}

static void credssp_run(uint32_t version, const char *client_pw, int bad_pubkey, int want)
{
	struct run o;
	memset(&o, 0, sizeof o);
	o.version = version; o.client_pw = client_pw; o.bad_pubkey = bad_pubkey; o.want = want;
	credssp_run_ex(&o);
}

/* a stand-in tls-server-end-point hash: SHA-256("gfopenntlm test certificate") */
static const char cert_hash_hex[] = "8b8c6f1e7d7075840fe6b90d2742de3162bc60440424f9148f1c6f43a501bf7f";

static void test_credssp_bindings(void)
{
	struct run o;
	uint8_t h[32];
	unhex(cert_hash_hex, h);
	memset(&o, 0, sizeof o);
	o.version = 6; o.client_pw = "Password"; o.want = GNERR_OK;
	o.cb = h; o.cbl = 32; o.flags = GNF_CB_TLS_SERVER_END_POINT; o.server_cb = 1;
	o.label = " with tls-server-end-point channel bindings";
	credssp_run_ex(&o);
	o.version = 3; o.label = " with tls-server-end-point channel bindings";
	credssp_run_ex(&o);
	/* a server that has bindings refuses an unbound client */
	o.version = 6; o.client_unbound = 1; o.want = GNERR_SERVER;
	o.label = " unbound client, server with bindings";
	credssp_run_ex(&o);
	/* and an unbound server refuses a bound client (it expects Z(16)) */
	o.client_unbound = 0; o.server_cb = 0;
	o.label = " bound client, unbound strict test server";
	credssp_run_ex(&o);
	/* non-ASCII user name: NTOWFv2's Uppercase(User) beyond Latin-1 */
	memset(&o, 0, sizeof o);
	o.version = 6; o.client_pw = "Password"; o.want = GNERR_OK;
	o.user = "jörg.łukasz"; o.user_upper = "JÖRG.ŁUKASZ"; o.domain = "Müller-Straße";
	o.label = " user jörg.łukasz (Latin Extended-A upper case)";
	credssp_run_ex(&o);
	o.user = "иван"; o.user_upper = "ИВАН"; o.domain = "Домен";
	o.label = " user иван (Cyrillic upper case)";
	credssp_run_ex(&o);
}

static void test_der(void)
{
	struct gn_tsrequest q, r;
	uint8_t b[64], tok[3] = { 1, 2, 3 };
	size_t n;
	memset(&q, 0, sizeof q);
	q.version = 6; q.nego_token = tok; q.nego_token_len = 3;
	n = gn_tsrequest_encode(&q, b, sizeof b);
	/* SEQUENCE { [0] INTEGER 6, [1] SEQUENCE OF SEQUENCE { [0] OCTET STRING 010203 } } */
	check_bytes("X.690 TSRequest encoding", b, n, "3012 a003020106 a10b 3009 3007 a005 0403010203");
	check("X.690 TSRequest decoding", gn_tsrequest_decode(b, n, &r) == 0 && r.version == 6 &&
	      r.nego_token_len == 3 && !memcmp(r.nego_token, tok, 3));
	n = unhex("300d a003020106 a406 0204c000006d", b);
	check("X.690 errorCode as a negative INTEGER", gn_tsrequest_decode(b, n, &r) == 0 && r.has_error &&
	      r.error_code == 0xc000006du);
	check("X.690 message length", gn_der_message_length(b, 2) == 15);
	n = gn_tscredentials_encode((const uint8_t *)"D\0", 2, (const uint8_t *)"U\0", 2, (const uint8_t *)"P\0", 2, b, sizeof b);
	check_bytes("MS-CSSP TSCredentials/TSPasswordCreds encoding", b, n,
	            "301d a003020101 a1160414 3012 a0040402 4400 a1040402 5500 a2040402 5000");
}

static void test_api(void)
{
	uint8_t d[64], k[5] = { 1, 2, 3, 4, 5 }, z[16];
	struct GNNTLMConfig nc;
	struct GNNTLM *n;
	LONG e;
	ULONG l;
	check("GN_Version 1.1.1", GN_Version() == 0x10002);
	check("GN_Digest MD4", GN_Digest(GNALG_MD4, "abc", 3, d) == 0 && !memcmp(d, "\xa4\x48\x01\x7a", 4));
	check("GN_HMAC MD5", GN_HMAC(GNALG_MD5, "Jefe", 4, "what do ya want for nothing?", 28, d) == 0 &&
	      !memcmp(d, "\x75\x0c\x78\x3e", 4));
	memset(z, 0, 16);
	check("GN_RC4", GN_RC4(k, 5, z, 16) == 0 && !memcmp(z, "\xb2\x39\x63\x05", 4));
	memset(&nc, 0, sizeof nc);
	nc.Size = 8;
	check("GN_NTLMNew refuses an old Size", GN_NTLMNew(&nc, &e) == NULL && e == GNERR_BADARGS);
	nc.Size = sizeof nc; nc.User = "u"; nc.Password = "p";
	n = GN_NTLMNew(&nc, &e);
	check("GN_NTLMNew", n != NULL && e == GNERR_OK);
	check("GN_NTLMNegotiate", GN_NTLMNegotiate(n, d, 40, &l) == 0 && l == 40 && !memcmp(d, "NTLMSSP", 8));
	check("GN_NTLMNegotiate twice is out of order", GN_NTLMNegotiate(n, d, 40, &l) == GNERR_STATE);
	GN_NTLMFree(n);
}

/* A WinPR server's accepted exchange (tests/winpr_transcript.h), replayed
 * with its random values fixed: the NEGOTIATE, the AUTHENTICATE (MIC
 * included) and the whole TSRequest with pubKeyAuth must come out byte for
 * byte. A wrong password must change the MIC (what WinPR reports as "MIC
 * verification failed"), and the empty domain must stay empty. */
static void test_winpr_transcript(void)
{
	static uint8_t pub[270];
	uint8_t chal[512], b[1024], a[2048], t8[8];
	size_t cl, bl, al;
	struct gn_cssp c;
	struct gn_tsrequest q;
	int e;
	memset(pub, 0, sizeof pub);
	memcpy(pub, "\x30\x82\x01\x0a\x02\x82\x01\x01\x00\xc3", 10);
	cl = unhex(wp_chal_hex, chal);
	e = gn_cssp_init(&c, "da1ek", "", "test123", "AMIGA", "daletop", pub, sizeof pub, 6);
	check("WinPR transcript: CredSSP init (no domain)", e == 0 && c.domain16_len == 0 && c.ntlm.domain_len == 0);
	c.ntlm.test = GN_NTLM_T_FIXED;
	unhex(wp_time_hex, t8);
	c.ntlm.t_time = (uint64_t)gn_get32(t8) | ((uint64_t)gn_get32(t8 + 4) << 32);
	unhex(wp_cc_hex, c.ntlm.t_client_challenge);
	unhex(wp_exported_hex, c.ntlm.t_session_key);
	c.test = GN_CSSP_T_FIXED_NONCE;
	unhex(wp_nonce_hex, c.nonce);
	e = gn_cssp_step(&c, NULL, 0, a, sizeof a, &al);
	if (e == GN_CONTINUE && gn_tsrequest_decode(a, al, &q) == 0 && q.nego_token)
		check_bytes("WinPR transcript: NEGOTIATE", q.nego_token, q.nego_token_len, wp_neg_hex);
	else check("WinPR transcript: NEGOTIATE", 0);
	memset(&q, 0, sizeof q);
	q.version = 6; q.nego_token = chal; q.nego_token_len = cl;
	bl = gn_tsrequest_encode(&q, b, sizeof b);
	e = gn_cssp_step(&c, b, bl, a, sizeof a, &al);
	if (e == GN_CONTINUE && gn_tsrequest_decode(a, al, &q) == 0 && q.nego_token) {
		check_bytes("WinPR transcript: AUTHENTICATE with the MIC", q.nego_token, q.nego_token_len, wp_auth_hex);
		check("WinPR transcript: AUTHENTICATE DomainName empty", gn_get16(q.nego_token + 28) == 0);
		check_bytes("WinPR transcript: TSRequest with pubKeyAuth and clientNonce (v6)", a, al, wp_pkauth_hex);
	} else check("WinPR transcript: AUTHENTICATE", 0);
	gn_cssp_clear(&c);
	/* the same exchange with another password: the MIC differs */
	{
		struct gn_ntlm n;
		uint8_t neg[64], auth[1024], want[1024];
		size_t nl, aul;
		gn_ntlm_init(&n, "da1ek", "", "test124", "AMIGA", "TERMSRV/daletop");
		n.test = GN_NTLM_T_FIXED;
		n.t_time = (uint64_t)gn_get32(t8) | ((uint64_t)gn_get32(t8 + 4) << 32);
		unhex(wp_cc_hex, n.t_client_challenge);
		unhex(wp_exported_hex, n.t_session_key);
		gn_ntlm_negotiate(&n, neg, sizeof neg, &nl);
		e = gn_ntlm_authenticate(&n, chal, cl, auth, sizeof auth, &aul);
		unhex(wp_auth_hex, want);
		check("WinPR transcript: another password changes the MIC",
		      e == 0 && aul > 88 && memcmp(auth + 72, want + 72, 16) != 0);
		gn_ntlm_clear(&n);
	}
}

/* M8: Uppercase() past ASCII and Latin-1 (gn_util.c lists the subset) */
static void test_upper(void)
{
	static const uint32_t v[][2] = {
		{ 'a', 'A' }, { 'Z', 'Z' }, { '1', '1' }, { 0xe9, 0xc9 }, { 0xf7, 0xf7 }, { 0xff, 0x178 },
		{ 0xdf, 0xdf },      /* sharp s: no 1:1 capital */
		{ 0xb5, 0xb5 },      /* micro sign: left alone (documented) */
		{ 0x101, 0x100 }, { 0x107, 0x106 }, { 0x10d, 0x10c }, { 0x111, 0x110 }, { 0x119, 0x118 },
		{ 0x11f, 0x11e }, { 0x131, 0x131 }, { 0x130, 0x130 }, { 0x13e, 0x13d }, { 0x142, 0x141 },
		{ 0x144, 0x143 }, { 0x148, 0x147 }, { 0x151, 0x150 }, { 0x153, 0x152 }, { 0x159, 0x158 },
		{ 0x15b, 0x15a }, { 0x15f, 0x15e }, { 0x161, 0x160 }, { 0x165, 0x164 }, { 0x16f, 0x16e },
		{ 0x171, 0x170 }, { 0x17a, 0x179 }, { 0x17c, 0x17b }, { 0x17e, 0x17d }, { 0x17f, 0x17f },
		{ 0x1c6, 0x1c4 }, { 0x1c5, 0x1c4 }, { 0x1c4, 0x1c4 }, { 0x1ce, 0x1cd }, { 0x1dd, 0x18e },
		{ 0x219, 0x218 }, { 0x21b, 0x21a }, { 0x259, 0x18f }, { 0x292, 0x1b7 },
		{ 0x3ac, 0x386 }, { 0x3b1, 0x391 }, { 0x3c2, 0x3a3 }, { 0x3c3, 0x3a3 }, { 0x3c9, 0x3a9 },
		{ 0x3ce, 0x38f }, { 0x390, 0x390 },
		{ 0x430, 0x410 }, { 0x436, 0x416 }, { 0x44f, 0x42f }, { 0x451, 0x401 }, { 0x456, 0x406 },
		{ 0x457, 0x407 }, { 0x45e, 0x40e }, { 0x491, 0x490 }, { 0x4d9, 0x4d8 }, { 0x4e9, 0x4e8 },
		{ 0x4c2, 0x4c1 }, { 0x561, 0x531 }, { 0x586, 0x556 },
		{ 0x1e03, 0x1e02 }, { 0x1ea1, 0x1ea0 }, { 0x1ef9, 0x1ef8 }, { 0xff41, 0xff21 }, { 0xff5a, 0xff3a },
		{ 0x10428, 0x10428 }, /* outside the BMP: left alone */
	};
	size_t i, l;
	int ok = 1;
	uint8_t *u;
	for (i = 0; i < sizeof v / sizeof v[0]; i++)
		if (gn_upper(v[i][0]) != v[i][1]) {
			printf("  U+%04X -> U+%04X, want U+%04X\n", (unsigned)v[i][0], (unsigned)gn_upper(v[i][0]), (unsigned)v[i][1]);
			ok = 0;
		}
	check("Uppercase: Latin-1, Latin Extended-A/B, IPA, Greek, Cyrillic, Armenian, fullwidth", ok);
	/* through gn_utf16: UTF-8 in, upper-case UTF-16LE out, surrogates kept */
	u = gn_utf16("żółć Ελλάς ёж \xf0\x9f\x98\x80", 1, &l);
	{
		uint8_t *w = gn_utf16("ŻÓŁĆ ΕΛΛΆΣ ЁЖ \xf0\x9f\x98\x80", 0, &l);
		size_t l2;
		uint8_t *u2 = gn_utf16("żółć Ελλάς ёж \xf0\x9f\x98\x80", 1, &l2);
		check("gn_utf16 upper: Polish, Greek, Cyrillic and an emoji", l == l2 && !memcmp(u2, w, l));
		gn_free(w, l + 2);
		gn_free(u2, l2 + 2);
	}
	gn_free(u, l + 2);
}

/* NTOWFv2 with non-ASCII names; the answers are HMAC_MD5(NTOWFv1("Password")
 * of [MS-NLMP] 4.2.2.1.2, UTF-16LE(Uppercase(User) + UserDom)) worked out
 * independently. Only User is upper-cased (3.3.2). */
static void test_ntowfv2_unicode(void)
{
	static const char *const v[][3] = {
		{ "jörg.łukasz", "Müller-Straße", "6cd9c1f50a99f331126ba7027315b2e4" },
		{ "иван", "Домен", "009a3f664e2c6b689c58b1374bf34f67" },
		{ "ǆemal ÿves", "", "3b4409098195977934fdf217ad05c7d4" },
	};
	size_t i;
	for (i = 0; i < sizeof v / sizeof v[0]; i++) {
		struct gn_ntlm n;
		char name[96];
		snprintf(name, sizeof name, "NTOWFv2 user \"%s\" domain \"%s\"", v[i][0], v[i][1]);
		if (gn_ntlm_init(&n, v[i][0], v[i][1], "Password", "WS", NULL)) { check(name, 0); continue; }
		check_bytes(name, n.response_key, 16, v[i][2]);
		gn_ntlm_clear(&n);
	}
}

/* M2: MsvChannelBindings. The hash is MD5(Z(16) + LE32(length) +
 * application_data) (RFC 2744 3.11, [MS-NLMP] 2.2.2.1), worked out
 * independently for the stand-in certificate hash. With bindings the
 * AUTHENTICATE of the WinPR transcript must differ only where it should
 * (MsvChannelBindings, NTProofStr, the encrypted session key and the MIC);
 * unbound, it stays byte for byte the transcript. */
static void test_bindings(void)
{
	uint8_t h[32], cb[16], app[64], chal[512], neg[64], auth[1024], want[1024], t8[8];
	size_t cl, nl, aul, wl, cbl, i;
	const uint8_t *p, *wnt, *gnt;
	struct gn_ntlm n;
	int e, ok;
	unhex(cert_hash_hex, h);
	gn_channel_bindings_hash(h, 32, 1, cb);
	check_bytes("channel bindings: MD5 of gss_channel_bindings_struct (tls-server-end-point)", cb, 16,
	            "7f0263277b94709b632f68bb3db2a381");
	memcpy(app, "tls-server-end-point:", 21); memcpy(app + 21, h, 32);
	gn_channel_bindings_hash(app, 53, 0, cb + 0);
	check_bytes("channel bindings: the same as raw application_data", cb, 16, "7f0263277b94709b632f68bb3db2a381");

	cl = unhex(wp_chal_hex, chal);
	wl = unhex(wp_auth_hex, want);
	unhex(wp_time_hex, t8);
	for (i = 0; i < 2; i++) {
		gn_ntlm_init(&n, "da1ek", "", "test123", "AMIGA", "TERMSRV/daletop");
		n.test = GN_NTLM_T_FIXED;
		n.t_time = (uint64_t)gn_get32(t8) | ((uint64_t)gn_get32(t8 + 4) << 32);
		unhex(wp_cc_hex, n.t_client_challenge);
		unhex(wp_exported_hex, n.t_session_key);
		e = i ? gn_ntlm_set_bindings(&n, h, 32, 1) : gn_ntlm_set_bindings(&n, NULL, 0, 0);
		gn_ntlm_negotiate(&n, neg, sizeof neg, &nl);
		e |= gn_ntlm_authenticate(&n, chal, cl, auth, sizeof auth, &aul);
		if (!i) {
			check_bytes("channel bindings: unbound (NULL) still gives the WinPR AUTHENTICATE", auth, aul, wp_auth_hex);
			gn_ntlm_clear(&n);
			continue;
		}
		check("channel bindings: bound AUTHENTICATE, same length", e == 0 && aul == wl);
		gnt = auth + gn_get32(auth + 24); wnt = want + gn_get32(want + 24);
		p = find_av(gnt, gn_get16(auth + 20), MsvChannelBindings, &cbl);
		gn_channel_bindings_hash(h, 32, 1, cb);
		check("channel bindings: MsvChannelBindings carries the hash", p && cbl == 16 && !memcmp(p, cb, 16));
		p = find_av(wnt, gn_get16(want + 20), MsvChannelBindings, &cbl);
		check("channel bindings: the unbound transcript has Z(16)", p && cbl == 16 && !memcmp(p, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16));
		/* everything but NTProofStr, MsvChannelBindings, the encrypted key and the MIC is the same */
		ok = !memcmp(auth, want, 72) && memcmp(auth + 72, want + 72, 16) != 0;
		ok &= memcmp(gnt, wnt, 16) != 0;
		{
			size_t off = (size_t)(gnt - auth), cbo = (size_t)(p - wnt) + off;
			size_t ntl = gn_get16(auth + 20), ko = gn_get32(auth + 56);
			ok &= !memcmp(auth + 88, want + 88, off - 88);                   /* names, LM */
			ok &= !memcmp(auth + off + 16, want + off + 16, cbo - off - 16); /* temp up to the bindings */
			ok &= !memcmp(auth + cbo + 16, want + cbo + 16, off + ntl - cbo - 16);
			ok &= memcmp(auth + ko, want + ko, 16) != 0;                     /* KXKEY differs */
		}
		check("channel bindings: only NTProofStr, MsvChannelBindings, the session key and the MIC change", ok);
		/* NTProofStr recomputed from the message: the bindings are inside it */
		{
			uint8_t proof[16];
			struct gn_hmac_md5 hm;
			gn_hmac_md5_init(&hm, n.response_key, 16);
			gn_hmac_md5_update(&hm, chal + 24, 8);
			gn_hmac_md5_update(&hm, gnt + 16, gn_get16(auth + 20) - 16);
			gn_hmac_md5_final(&hm, proof);
			check("channel bindings: NTProofStr covers MsvChannelBindings", !memcmp(proof, gnt, 16));
		}
		check("channel bindings: GN_ntlm_set_bindings after AUTHENTICATE is out of order",
		      gn_ntlm_set_bindings(&n, h, 32, 1) == GN_ESTATE);
		gn_ntlm_clear(&n);
	}
	(void)wl;
}

/* the 1.1 config fields through the API, and L5's honest GetAttr */
static void test_api_bindings(void)
{
	struct GNNTLMConfig nc;
	struct GNCredSSPConfig cc;
	struct GNNTLM *n;
	struct GNCredSSP *c;
	uint8_t h[32], pub[16];
	LONG e;
	unhex(cert_hash_hex, h);
	memset(pub, 0x30, sizeof pub);
	memset(&nc, 0, sizeof nc);
	nc.Size = sizeof nc; nc.User = "u"; nc.Password = "p";
	nc.Flags = GNF_CB_TLS_SERVER_END_POINT;
	check("GN_NTLMNew: GNF_CB_TLS_SERVER_END_POINT without bindings is refused",
	      GN_NTLMNew(&nc, &e) == NULL && e == GNERR_BADARGS);
	nc.Flags = 0x80;
	check("GN_NTLMNew: an unknown flag is refused", GN_NTLMNew(&nc, &e) == NULL && e == GNERR_BADARGS);
	nc.Flags = 0; nc.ChannelBindings = h; nc.ChannelBindingsLength = 0;
	check("GN_NTLMNew: bindings with length 0 are refused", GN_NTLMNew(&nc, &e) == NULL && e == GNERR_BADARGS);
	nc.Flags = GNF_CB_TLS_SERVER_END_POINT; nc.ChannelBindingsLength = 32;
	n = GN_NTLMNew(&nc, &e);
	check("GN_NTLMNew with channel bindings", n && e == GNERR_OK && GN_NTLMGetAttr(n, GNA_CHANNELBINDINGS) == 1);
	check("GN_NTLMGetAttr: a CredSSP attribute reads 0", n && GN_NTLMGetAttr(n, GNA_VERSION) == 0 &&
	      GN_NTLMGetAttr(n, GNA_LASTERROR) == 0);
	GN_NTLMFree(n);
	/* a 1.0 caller: Size up to TargetName, the bindings fields unseen */
	memset(&nc, 0, sizeof nc);
	nc.Size = (ULONG)offsetof(struct GNNTLMConfig, ChannelBindings); nc.User = "u"; nc.Password = "p";
	n = GN_NTLMNew(&nc, &e);
	check("GN_NTLMNew with a 1.0 Size: unbound", n && GN_NTLMGetAttr(n, GNA_CHANNELBINDINGS) == 0);
	GN_NTLMFree(n);
	memset(&cc, 0, sizeof cc);
	cc.Size = (ULONG)offsetof(struct GNCredSSPConfig, ChannelBindings);
	cc.User = "u"; cc.Password = "p"; cc.PublicKey = pub; cc.PublicKeyLength = sizeof pub;
	c = GN_CredSSPNew(&cc, &e);
	check("GN_CredSSPNew with a 1.0 Size: unbound", c && GN_CredSSPGetAttr(c, GNA_CHANNELBINDINGS) == 0 &&
	      GN_CredSSPGetAttr(c, GNA_STATE) == 0);
	GN_CredSSPFree(c);
	cc.Size = sizeof cc; cc.Flags = GNF_CB_TLS_SERVER_END_POINT;
	check("GN_CredSSPNew: the flag without bindings is refused", GN_CredSSPNew(&cc, &e) == NULL && e == GNERR_BADARGS);
	cc.ChannelBindings = h; cc.ChannelBindingsLength = 32;
	c = GN_CredSSPNew(&cc, &e);
	check("GN_CredSSPNew with channel bindings", c && GN_CredSSPGetAttr(c, GNA_CHANNELBINDINGS) == 1);
	GN_CredSSPFree(c);
}

int main(void)
{
	test_md4();
	test_md5();
	test_hmac();
	test_rc4();
	test_sha256();
	test_nlmp();
	test_winpr_transcript();
	test_der();
	test_api();
	test_upper();
	test_ntowfv2_unicode();
	test_bindings();
	test_api_bindings();
	credssp_run(6, "Password", 0, GNERR_OK);
	credssp_run(5, "Password", 0, GNERR_OK);
	credssp_run(4, "Password", 0, GNERR_OK);
	credssp_run(3, "Password", 0, GNERR_OK);
	credssp_run(2, "Password", 0, GNERR_OK);
	credssp_run(6, "not-the-password", 0, GNERR_SERVER);
	credssp_run(6, "Password", 1, GNERR_PUBKEY);
	credssp_run(3, "Password", 1, GNERR_PUBKEY);
	test_credssp_bindings();
	printf("%d passed, %d failed\n", pass, failed);
	return failed ? 1 : 0;
}

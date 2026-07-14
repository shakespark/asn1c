/*
 * Self-contained regression for the extensible BIT STRING SIZE fix,
 * nested inside a SEQUENCE { a, bs, b } (companion to check-165's
 * SEQUENCE/CHOICE extension-skip tests and to check-167/171's
 * same-version BIT STRING extension coverage).
 *
 * W ::= SEQUENCE { a MsgCount, bs BIT STRING (SIZE(2,...)), b MsgCount }
 *
 * bs's constraint is extensible with an EMPTY extension-addition list
 * (bare "..."), so it is not affected by this series' constraint-range
 * (crange) folding fix on its own -- but it *is* affected by the
 * BIT_STRING_encode_uper() half of the fix: before that fix, a value
 * shorter than the root's lower bound (2 bits) was zero-padded up to
 * 2 bits instead of being routed through the extension addition. That
 * changes both the emitted bit length and the abstract value, and
 * corrupts whatever SEQUENCE field follows bs.
 *
 * The golden bytes below are produced from the abstract value
 * { a 5, bs '1'B, b 7 } (bs below the 2-bit root) by a commercial
 * ASN.1 toolchain's UPER encoder (the project's interoperability
 * reference); asn1tools does not implement BIT STRING size extension,
 * so it is not usable as an independent cross-check here.
 *
 * Before the fix in this series, asn1c's own UPER encoder for this
 * exact schema and value emitted 0a 83 80 (bs zero-padded into the
 * root, corrupting the bit alignment of "b") instead of the golden
 * 0b 01 87 -- confirmed against a pre-fix build of this branch's
 * parent commit (8a274c3f), which decodes back to a=5, bs correct,
 * b=7 only because it is a *self*-consistent round trip; the wire
 * bytes it produces are not what a spec-conforming peer emits, so
 * decoding a genuinely conforming peer's bytes (the golden bytes
 * checked here) is the failure mode this test guards against.
 */
#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <W.h>

static void
check_w_roundtrip(long a, const uint8_t *bs_bytes, size_t bs_nbytes,
                   int bits_unused, long b,
                   const uint8_t *expect, size_t expect_len,
                   const char *name) {
	W_t w;
	uint8_t buf1[64];
	uint8_t buf2[64];
	asn_enc_rval_t er;
	asn_dec_rval_t dr;
	void *decoded = 0;
	size_t enc_bytes1, enc_bytes2;
	size_t i;

	memset(&w, 0, sizeof(w));
	w.a = a;
	w.b = b;
	w.bs.buf = malloc(bs_nbytes ? bs_nbytes : 1);
	assert(w.bs.buf || bs_nbytes == 0);
	if(bs_nbytes) memcpy(w.bs.buf, bs_bytes, bs_nbytes);
	w.bs.size = bs_nbytes;
	w.bs.bits_unused = bits_unused;

	er = uper_encode_to_buffer(&asn_DEF_W, 0, &w, buf1, sizeof(buf1));
	assert(er.encoded >= 0);
	enc_bytes1 = (size_t)((er.encoded + 7) / 8);

	fprintf(stderr, "%s:", name);
	for(i = 0; i < enc_bytes1; i++) fprintf(stderr, " %02x", buf1[i]);
	fprintf(stderr, "\n");

	if(enc_bytes1 != expect_len || memcmp(buf1, expect, expect_len) != 0) {
		fprintf(stderr, "%s: mismatch vs reference golden:", name);
		for(i = 0; i < expect_len; i++)
			fprintf(stderr, " %02x", expect[i]);
		fprintf(stderr, "\n");
		assert(0);
	}

	dr = uper_decode_complete(0, &asn_DEF_W, &decoded, buf1, enc_bytes1);
	assert(dr.code == RC_OK);
	{
		W_t *w2 = decoded;
		assert(w2->a == a);
		assert((long)w2->bs.size == (long)bs_nbytes);
		assert(w2->bs.bits_unused == bits_unused);
		if(bs_nbytes) assert(memcmp(w2->bs.buf, bs_bytes, bs_nbytes) == 0);
		assert(w2->b == b);
	}

	er = uper_encode_to_buffer(&asn_DEF_W, 0, decoded, buf2, sizeof(buf2));
	assert(er.encoded >= 0);
	enc_bytes2 = (size_t)((er.encoded + 7) / 8);
	assert(enc_bytes2 == enc_bytes1 && memcmp(buf1, buf2, enc_bytes1) == 0);

	ASN_STRUCT_FREE(asn_DEF_W, decoded);
	FREEMEM(w.bs.buf);
}

int main() {
	/*
	 * { a 5, bs '1'B (1 bit, below the 2-bit root), b 7 }: bs must be
	 * routed through the extension addition, not zero-padded into
	 * the root, and "b" must be recovered from the correct bit
	 * offset that follows.
	 */
	{
		uint8_t v[] = {0x80};
		uint8_t expect[] = {0x0b, 0x01, 0x87};
		check_w_roundtrip(5, v, 1, 7, 7, expect, sizeof(expect),
		                   "W:a=5,bs=1(below-root),b=7");
	}

	/*
	 * { a 5, bs '11'B (2 bits, in the root), b 7 }: sanity check that
	 * the ordinary in-root case is unaffected.
	 */
	{
		uint8_t v[] = {0xc0};
		uint8_t expect[] = {0x0a, 0xc3, 0x80};
		check_w_roundtrip(5, v, 1, 6, 7, expect, sizeof(expect),
		                   "W:a=5,bs=11(root),b=7");
	}

	printf("Finished OK\n");
	return 0;
}

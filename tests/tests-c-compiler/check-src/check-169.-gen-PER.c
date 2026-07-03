/*
 * Regression for issue #12: asn1c has no PER/OER codec implementation for
 * the SET type (asn_OP_SET's uper_decoder/uper_encoder/oer_decoder/
 * oer_encoder are null). Decoding or encoding a *top-level* SET in UPER
 * already failed cleanly (per_decoder.c checks the function pointer before
 * calling it), but a SET nested as a member of an enclosing SEQUENCE was
 * not guarded at the member-level call sites (constr_SEQUENCE.c,
 * per_opentype.c), so asn1c called through a null function pointer and
 * crashed with SIGSEGV instead of returning a decode/encode failure.
 *
 * This is a stage-1 "stop the bleeding" fix: it does not implement PER/OER
 * for SET, it just makes every member-level call site check the function
 * pointer first and fail cleanly (RC_FAIL / encoded == -1) instead of
 * dereferencing NULL. Before the fix, this test dies with SIGSEGV
 * (exit via signal, not via a normal exit code). After the fix, it
 * completes normally, asserting clean failures both ways.
 */
#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <M.h>

int main() {
	asn_enc_rval_t er;
	asn_dec_rval_t rv;

	/*
	 * UPER decode of a two-byte buffer into the nested-SET-bearing M.
	 * Before the fix: decoding the SEQUENCE root member "s" (type S,
	 * a SET) calls S's (null) uper_decoder directly and segfaults.
	 * After the fix: the null check in constr_SEQUENCE.c's member
	 * decode loop makes it fail cleanly with RC_FAIL.
	 */
	{
		static const unsigned char enc[] = { 0x2a, 0x80 };
		M_t *m = 0;

		rv = uper_decode(0, &asn_DEF_M, (void **)&m, enc, sizeof enc, 0, 0);
		assert(rv.code != RC_OK);

		/*
		 * Whatever partial structure may have been allocated before
		 * the failure must still be freeable.
		 */
		if(m) ASN_STRUCT_FREE(asn_DEF_M, m);
	}

	/*
	 * UPER encode of a fully-populated M (with its nested SET member
	 * filled in). Before the fix: encoding the SEQUENCE root member
	 * "s" calls S's (null) uper_encoder directly and segfaults. After
	 * the fix: the null check in constr_SEQUENCE.c's member encode
	 * loop makes it fail cleanly with encoded == -1.
	 */
	{
		M_t m;
		unsigned char buf[16];

		memset(&m, 0, sizeof(m));
		m.s.a = 7;
		m.s.b = 1;

		er = uper_encode_to_buffer(&asn_DEF_M, 0, &m, buf, sizeof buf);
		assert(er.encoded == -1);
	}

	printf("Finished OK\n");
	return 0;
}

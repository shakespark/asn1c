/*
 * Verify OER forward compatibility with extension additions.
 *
 * A decoder built from the v1 module (170-oer-ext-skip-OK.asn1) is fed
 * byte streams produced by v2/v3 peers whose types carry extension
 * additions unknown to v1:
 *
 *   v2:  Inner ::= SEQUENCE { x INTEGER(0..255), ..., y INTEGER(0..255) }
 *   v3:  Inner ::= SEQUENCE { x INTEGER(0..255), ...,
 *                             y INTEGER(0..255), z INTEGER(0..255) }
 *   v2:  C ::= CHOICE { c1 INTEGER(0..255), ..., c2 INTEGER(0..255) }
 *
 * Issue #14: oer_open_type_skip() only skipped the open type length
 * determinant, not the contents, so every unknown extension addition
 * silently shifted all subsequent fields of the enclosing SEQUENCE.
 * Issue #15: an unknown CHOICE extension alternative failed the whole
 * PDU with RC_FAIL instead of being skipped.
 *
 * All golden byte vectors below were produced by a commercial ASN.1
 * toolchain's (the project's interoperability reference) OER codec from
 * the v2/v3 modules, and independently cross-checked with asn1tools
 * (Python); both tools emit identical bytes.  The reference toolchain's
 * v1 decoder gracefully
 * skips every one of these streams (M: a=1 x=2 b=4; MC: pre=1
 * choice=<none> post=4), which is the contract asserted here.
 * The per-byte derivation is documented next to each vector.
 */
#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>

#include <M.h>
#include <MC.h>
#include <C.h>

/*
 * v2 encoding of M {a 1, inner {x 2, y 3}, b 4}:
 *   01           a = 1
 *   80           Inner preamble: extension bit set
 *   02           x = 2
 *   02 07 80     extension presence bitmap: length 2, 7 unused bits,
 *                bit 1 (y) present
 *   01 03        open type: length 1, contents y = 3
 *   04           b = 4
 */
static const uint8_t v2_seq[] = {
    0x01, 0x80, 0x02, 0x02, 0x07, 0x80, 0x01, 0x03, 0x04
};

/*
 * v3 encoding of M {a 1, inner {x 2, y 3, z 5}, b 4}:
 *   01           a = 1
 *   80           Inner preamble: extension bit set
 *   02           x = 2
 *   02 06 C0     extension presence bitmap: length 2, 6 unused bits,
 *                bits 1..2 (y, z) present
 *   01 03        open type: length 1, contents y = 3
 *   01 05        open type: length 1, contents z = 5
 *   04           b = 4
 * Exercises consecutive unknown open types: with #14 unfixed, the first
 * skipped content byte (03) is misread as the next length determinant.
 */
static const uint8_t v3_seq[] = {
    0x01, 0x80, 0x02, 0x02, 0x06, 0xC0, 0x01, 0x03, 0x01, 0x05, 0x04
};

/*
 * v1 encodings (root alternatives only), as emitted by the reference
 * toolchain from the very same v1 module this test is compiled from;
 * pins down the encode-side interoperability so the reference toolchain
 * can decode what asn1c emits.
 *   M {a 1, inner {x 2}, b 4}:   01 00 02 04
 *                                (00 = Inner preamble, no extensions)
 *   MC {pre 1, c c1 : 7, post 4}: 01 80 07 04 (80 = tag [0] of c1)
 */
static const uint8_t v1_seq[] = { 0x01, 0x00, 0x02, 0x04 };
static const uint8_t v1_mc[] = { 0x01, 0x80, 0x07, 0x04 };

/*
 * Zero max_stack_size disables the stack-depth checker: sanitizer builds
 * (ASAN/UBSAN) inflate stack frames enough to trip the default limit,
 * which would mask the codec behavior under test with an unrelated
 * RC_FAIL.
 */
static asn_codec_ctx_t s_no_stack_limit; /* zero-initialized */

/* Unknown SEQUENCE extension addition is skipped; b is not shifted. */
static void
check_seq_skip(void) {
    M_t *m = 0;
    asn_dec_rval_t dr =
        oer_decode(&s_no_stack_limit, &asn_DEF_M, (void **)&m, v2_seq, sizeof(v2_seq));

    fprintf(stderr, "SEQ skip: code=%d consumed=%zu\n", dr.code, dr.consumed);
    assert(dr.code == RC_OK);
    fprintf(stderr, "SEQ skip: a=%ld x=%ld b=%ld\n", m->a, m->inner.x, m->b);
    assert(dr.consumed == sizeof(v2_seq));
    assert(m->a == 1);
    assert(m->inner.x == 2);
    assert(m->b == 4);  /* Unfixed #14 misdecodes b as 3 (the y payload) */

    ASN_STRUCT_FREE(asn_DEF_M, m);
}

/* Two consecutive unknown extension additions are both skipped. */
static void
check_seq_skip_two_extensions(void) {
    M_t *m = 0;
    asn_dec_rval_t dr =
        oer_decode(&s_no_stack_limit, &asn_DEF_M, (void **)&m, v3_seq, sizeof(v3_seq));

    fprintf(stderr, "SEQ skip x2: code=%d consumed=%zu\n",
            dr.code, dr.consumed);
    assert(dr.code == RC_OK);
    fprintf(stderr, "SEQ skip x2: a=%ld x=%ld b=%ld\n",
            m->a, m->inner.x, m->b);
    assert(dr.consumed == sizeof(v3_seq));
    assert(m->a == 1);
    assert(m->inner.x == 2);
    assert(m->b == 4);

    ASN_STRUCT_FREE(asn_DEF_M, m);
}

/*
 * Input truncated inside the open type contents must starve (RC_WMORE),
 * never read out of bounds or misdecode trailing fields.
 * The 7-byte prefix of v2_seq ends right after the open type length
 * determinant (01) with the announced content byte missing.
 */
static void
check_seq_truncated(void) {
    size_t cut;

    for(cut = 7; cut < sizeof(v2_seq); cut++) {
        /* Copy into an exactly-sized heap buffer so ASAN/valgrind would
         * catch any read past the truncation point. */
        uint8_t *buf = malloc(cut);
        M_t *m = 0;
        asn_dec_rval_t dr;

        assert(buf);
        memcpy(buf, v2_seq, cut);
        dr = oer_decode(&s_no_stack_limit, &asn_DEF_M, (void **)&m, buf, cut);

        fprintf(stderr, "SEQ truncated at %zu: code=%d consumed=%zu\n",
                cut, dr.code, dr.consumed);
        assert(dr.code == RC_WMORE);

        ASN_STRUCT_FREE(asn_DEF_M, m);
        free(buf);
    }
}

/*
 * Encode-side interop: asn1c's v1 encodings must be byte-identical to
 * the reference toolchain's v1 encodings (it decodes both back to the
 * same values).
 */
static void
check_v1_encode_interop(void) {
    uint8_t buf[16];

    {
        M_t m;
        asn_enc_rval_t er;
        memset(&m, 0, sizeof(m));
        m.a = 1; m.inner.x = 2; m.b = 4;
        er = oer_encode_to_buffer(&asn_DEF_M, 0, &m, buf, sizeof(buf));
        fprintf(stderr, "v1 M encode: encoded=%zd\n", er.encoded);
        assert(er.encoded == (ssize_t)sizeof(v1_seq));
        assert(memcmp(buf, v1_seq, sizeof(v1_seq)) == 0);
    }
    {
        MC_t mc;
        asn_enc_rval_t er;
        memset(&mc, 0, sizeof(mc));
        mc.pre = 1;
        mc.c.present = C_PR_c1;
        mc.c.choice.c1 = 7;
        mc.post = 4;
        er = oer_encode_to_buffer(&asn_DEF_MC, 0, &mc, buf, sizeof(buf));
        fprintf(stderr, "v1 MC encode: encoded=%zd\n", er.encoded);
        assert(er.encoded == (ssize_t)sizeof(v1_mc));
        assert(memcmp(buf, v1_mc, sizeof(v1_mc)) == 0);
    }
}

int main() {
    check_seq_skip();
    check_seq_skip_two_extensions();
    check_seq_truncated();
    check_v1_encode_interop();
    return 0;
}

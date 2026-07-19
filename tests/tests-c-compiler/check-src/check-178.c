#undef NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <T.h>

/*
 * Regression test for a review-flagged index misalignment between the
 * presence enum, the union members, the asn_TYPE_member_t table and the
 * tag2el map of a table-constrained open type CHOICE, when its
 * Information Object Set repeats the same anonymous &Type across
 * genuinely non-adjacent rows: { INTEGER BY 1 } | { BOOLEAN BY 2 } |
 * { INTEGER BY 3 }.
 *
 * Before the suffix-based fix, only the presence enum deduplicated the
 * repeated INTEGER (leaving just value_PR_INTEGER, value_PR_BOOLEAN),
 * while the union members, the member table, the tag2el map and the
 * runtime row selector still counted all three distinct rows. Decoding
 * id=3 (the second INTEGER row) picked present=3, an enumerator the
 * truncated enum did not even have.
 */

static void
roundtrip_integer(long id, long expect_present_is_first, long value) {
	T_t *t = calloc(1, sizeof(*t));
	assert(t);
	t->id = id;
	if (expect_present_is_first) {
		t->value.present = value_PR_INTEGER;
		t->value.choice.INTEGER = value;
	} else {
		t->value.present = value_PR_INTEGER_1;
		t->value.choice.INTEGER_1 = value;
	}

	char buf[64];
	asn_enc_rval_t er = uper_encode_to_buffer(&asn_DEF_T, 0, t, buf, sizeof(buf));
	assert(er.encoded >= 0);
	size_t len = (er.encoded + 7) / 8;

	T_t *back = NULL;
	asn_dec_rval_t dr = uper_decode_complete(0, &asn_DEF_T, (void **)&back, buf, len);
	assert(dr.code == RC_OK);
	assert(back->id == id);

	if (expect_present_is_first) {
		fprintf(stderr, "id=%ld: present=%d (want value_PR_INTEGER=%d)\n",
			id, (int)back->value.present, (int)value_PR_INTEGER);
		assert(back->value.present == value_PR_INTEGER);
		assert(back->value.choice.INTEGER == value);
	} else {
		fprintf(stderr, "id=%ld: present=%d (want value_PR_INTEGER_1=%d)\n",
			id, (int)back->value.present, (int)value_PR_INTEGER_1);
		assert(back->value.present == value_PR_INTEGER_1);
		assert(back->value.choice.INTEGER_1 == value);
	}

	ASN_STRUCT_FREE(asn_DEF_T, t);
	ASN_STRUCT_FREE(asn_DEF_T, back);
}

static void
roundtrip_boolean(long id, int value) {
	T_t *t = calloc(1, sizeof(*t));
	assert(t);
	t->id = id;
	t->value.present = value_PR_BOOLEAN;
	t->value.choice.BOOLEAN = value;

	char buf[64];
	asn_enc_rval_t er = uper_encode_to_buffer(&asn_DEF_T, 0, t, buf, sizeof(buf));
	assert(er.encoded >= 0);
	size_t len = (er.encoded + 7) / 8;

	T_t *back = NULL;
	asn_dec_rval_t dr = uper_decode_complete(0, &asn_DEF_T, (void **)&back, buf, len);
	assert(dr.code == RC_OK);
	assert(back->id == id);
	fprintf(stderr, "id=%ld: present=%d (want value_PR_BOOLEAN=%d)\n",
		id, (int)back->value.present, (int)value_PR_BOOLEAN);
	assert(back->value.present == value_PR_BOOLEAN);
	assert(back->value.choice.BOOLEAN == value);

	ASN_STRUCT_FREE(asn_DEF_T, t);
	ASN_STRUCT_FREE(asn_DEF_T, back);
}

int main(void) {
	roundtrip_integer(1, 1, 111);
	roundtrip_boolean(2, 1);
	roundtrip_integer(3, 0, 333);

	fprintf(stderr, "PASS: check-178 (interleaved-duplicate IOS index alignment)\n");
	return 0;
}

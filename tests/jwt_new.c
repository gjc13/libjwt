/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <check.h>

#include <jwt.h>

START_TEST(test_jwt_new)
{
	jwt_t *jwt = NULL;
	int ret = 0;

	ret = jwt_new(NULL);
	ck_assert_int_eq(ret, EINVAL);

	ret = jwt_new(&jwt);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_dup)
{
	jwt_t *jwt = NULL, *new = NULL;
	int ret = 0;
	const char *val = NULL;
	time_t now;
	long valint;

	new = jwt_dup(NULL);
	ck_assert(new == NULL);

	ret = jwt_new(&jwt);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	ret = jwt_add_grant(jwt, "iss", "test");
	ck_assert_int_eq(ret, 0);

	new = jwt_dup(jwt);
	ck_assert(new != NULL);

	val = jwt_get_grant(new, "iss");
	ck_assert(val != NULL);
	ck_assert_str_eq(val, "test");

	ck_assert_int_eq(jwt_get_alg(new), JWT_ALG_NONE);

	now = time(NULL);
	ret = jwt_add_grant_int(jwt, "iat", (long)now);
	ck_assert_int_eq(ret, 0);

	valint = jwt_get_grant_int(jwt, "iat");
	ck_assert(((long)now) == valint);

	jwt_free(new);
	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_dup_signed)
{
	unsigned char key256[32] = "012345678901234567890123456789XY";
	jwt_t *jwt = NULL, *new = NULL;
	int ret = 0;
	const char *val = NULL;

	ret = jwt_new(&jwt);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	ret = jwt_add_grant(jwt, "iss", "test");
	ck_assert_int_eq(ret, 0);

	ret = jwt_set_alg(jwt, JWT_ALG_HS256, key256, sizeof(key256));
	ck_assert_int_eq(ret, 0);

	new = jwt_dup(jwt);
	ck_assert(new != NULL);

	val = jwt_get_grant(new, "iss");
	ck_assert(val != NULL);
	ck_assert_str_eq(val, "test");

	ck_assert_int_eq(jwt_get_alg(new), JWT_ALG_HS256);

	jwt_free(new);
	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_decode)
{
	const char token[] = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJmaWxlcy5jeXBo"
			     "cmUuY29tIiwic3ViIjoidXNlcjAifQ.";
	jwt_alg_t alg;
	jwt_t *jwt;
	int ret;

	ret = jwt_decode(&jwt, token, NULL, 0);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	alg = jwt_get_alg(jwt);
	ck_assert(alg == JWT_ALG_NONE);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_decode_invalid_final_dot)
{
	const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9."
			     "eyJpc3MiOiJmaWxlcy5jeXBocmUuY29tIiwic"
			     "3ViIjoidXNlcjAifQ";
	jwt_t *jwt;
	int ret;

	ret = jwt_decode(&jwt, token, NULL, 0);
	ck_assert_int_eq(ret, EINVAL);
	ck_assert(jwt == NULL);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_decode_invalid_alg)
{
	const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIQUhBSCJ9."
			     "eyJpc3MiOiJmaWxlcy5jeXBocmUuY29tIiwic"
			     "3ViIjoidXNlcjAifQ.";
	jwt_t *jwt;
	int ret;

	ret = jwt_decode(&jwt, token, NULL, 0);
	ck_assert_int_eq(ret, EINVAL);
	ck_assert(jwt == NULL);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_decode_invalid_typ)
{
	const char token[] = "eyJ0eXAiOiJBTEwiLCJhbGciOiJIUzI1NiJ9."
			     "eyJpc3MiOiJmaWxlcy5jeXBocmUuY29tIiwic"
			     "3ViIjoidXNlcjAifQ.";
	jwt_t *jwt;
	int ret;

	ret = jwt_decode(&jwt, token, NULL, 0);
	ck_assert_int_eq(ret, EINVAL);
	ck_assert(jwt == NULL);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_decode_invalid_head)
{
	const char token[] = "yJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9."
			     "eyJpc3MiOiJmaWxlcy5jeXBocmUuY29tIiwic"
			     "3ViIjoidXNlcjAifQ.";
	jwt_t *jwt;
	int ret;

	ret = jwt_decode(&jwt, token, NULL, 0);
	ck_assert_int_eq(ret, EINVAL);
	ck_assert(jwt == NULL);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_decode_alg_none_with_key)
{
	const char token[] = "eyJhbGciOiJub25lIn0."
			     "eyJpc3MiOiJmaWxlcy5jeXBocmUuY29tIiwic"
			     "3ViIjoidXNlcjAifQ.";
	jwt_t *jwt;
	int ret;

	ret = jwt_decode(&jwt, token, (const unsigned char *)"key", 3);
	ck_assert_int_eq(ret, EINVAL);
	ck_assert(jwt == NULL);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_decode_invalid_body)
{
	const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9."
			     "eyJpc3MiOiJmaWxlcy5jeBocmUuY29tIiwic"
			     "3ViIjoidXNlcjAifQ.";
	jwt_t *jwt;
	int ret;

	ret = jwt_decode(&jwt, token, NULL, 0);
	ck_assert_int_eq(ret, EINVAL);
	ck_assert(jwt == NULL);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_decode_hs256)
{
	const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3Mi"
			     "OiJmaWxlcy5jeXBocmUuY29tIiwic3ViIjoidXNlcjAif"
			     "Q.dLFbrHVViu1e3VD1yeCd9aaLNed-bfXhSsF0Gh56fBg";
	unsigned char key256[32] = "012345678901234567890123456789XY";
	jwt_t *jwt;
	int ret;

	ret = jwt_decode(&jwt, token, key256, sizeof(key256));
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_decode_hs384)
{
	const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9."
			     "eyJpc3MiOiJmaWxlcy5jeXBocmUuY29tIiwic"
			     "3ViIjoidXNlcjAifQ.xqea3OVgPEMxsCgyikr"
			     "R3gGv4H2yqMyXMm7xhOlQWpA-NpT6n2a1d7TD"
			     "GgU6LOe4";
	const unsigned char key384[48] = "aaaabbbbccccddddeeeeffffg"
					 "ggghhhhiiiijjjjkkkkllll";
	jwt_t *jwt;
	int ret;

	ret = jwt_decode(&jwt, token, key384, sizeof(key384));
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_decode_hs512)
{
        const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3Mi"
			     "OiJmaWxlcy5jeXBocmUuY29tIiwic3ViIjoidXNlcjAif"
			     "Q.u-4XQB1xlYV8SgAnKBof8fOWOtfyNtc1ytTlc_vHo0U"
			     "lh5uGT238te6kSacnVzBbC6qwzVMT1806oa1Y8_8EOg";
	unsigned char key512[64] = "012345678901234567890123456789XY"
				   "012345678901234567890123456789XY";
	jwt_t *jwt;
        int ret;

	ret = jwt_decode(&jwt, token, key512, sizeof(key512));
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	jwt_free(jwt);
}
END_TEST

static Suite *libjwt_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("LibJWT New");

	tc_core = tcase_create("jwt_new");
	tcase_add_test(tc_core, test_jwt_new);
	tcase_add_test(tc_core, test_jwt_dup);
	tcase_add_test(tc_core, test_jwt_dup_signed);
	tcase_add_test(tc_core, test_jwt_decode);
	tcase_add_test(tc_core, test_jwt_decode_invalid_alg);
	tcase_add_test(tc_core, test_jwt_decode_invalid_typ);
	tcase_add_test(tc_core, test_jwt_decode_invalid_head);
	tcase_add_test(tc_core, test_jwt_decode_alg_none_with_key);
	tcase_add_test(tc_core, test_jwt_decode_invalid_body);
	tcase_add_test(tc_core, test_jwt_decode_invalid_final_dot);
	tcase_add_test(tc_core, test_jwt_decode_hs256);
	tcase_add_test(tc_core, test_jwt_decode_hs384);
	tcase_add_test(tc_core, test_jwt_decode_hs512);

	tcase_set_timeout(tc_core, 30);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(int argc, char *argv[])
{
	int number_failed;
	Suite *s;
	SRunner *sr;

	s = libjwt_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_VERBOSE);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

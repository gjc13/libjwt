/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <check.h>

#include <jwt.h>

START_TEST(test_jwt_new)
{
	jwt_t *jwt = NULL;
	int ret = 0;

	ret = jwt_new(&jwt);
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	jwt_free(jwt);
}
END_TEST

START_TEST(test_jwt_decode)
{
	char hs384_res[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJpc3MiOi"
			   "JmaWxlcy5jeXBocmUuY29tIiwic3ViIjoidXNlcjAifQ==."
			   "k9MApCWNkjZi47zVzPw/SkHOPEtlMuzGcseuKqhzwfGaqnL"
			   "p3aIArg1wuUU+4QB2";
	unsigned char key384[48] = "aaaabbbbccccddddeeeeffffgggghhhh"
				   "iiiijjjjkkkkllll";
	jwt_t *jwt;
	int ret;

	ret = jwt_decode(&jwt, hs384_res, key384, sizeof(key384));
	ck_assert_int_eq(ret, 0);
	ck_assert(jwt != NULL);

	jwt_free(jwt);
}
END_TEST

Suite *libjwt_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("LibJWT New");

	tc_core = tcase_create("jwt_new");
	tcase_add_test(tc_core, test_jwt_new);
	tcase_add_test(tc_core, test_jwt_decode);
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

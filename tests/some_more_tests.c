#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "minunit.h" 

char *test_Simple() {
	mu_assert(true, "You should never see this message.");
	return NULL;
}

char *all_tests() {
	mu_suite_start();
	mu_run_test(test_Simple);
	return NULL;
}

RUN_TESTS(all_tests); 

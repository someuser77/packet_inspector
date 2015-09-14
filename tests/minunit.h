 // www.jera.com/techinfo/jtns/jtn002.html
 // http://codalyze.blogspot.co.il/2008/09/c-testing-minunit-less-is-more.html
 // http://c.learncodethehardway.org/book/ex30.html
#ifndef _MINUNIT_H_
#define _MINUNIT_H_

 #include <stdio.h>
 #include <stdlib.h>
 
#define mu_suite_start() char *message = NULL
#define mu_assert(test, message) do { if (!(test)) return message; } while (0)
#define mu_run_test(test) do {														\
											printf("Running test %s...\n", #test);	\
											message = test(); tests_run++; 			\
											if (message)										\
												return message; 								\
											} while (0)

#define RUN_TESTS(name) int main(int __attribute__((unused)) argc, char *argv[]) {		\
												argc = 1; 																		\
												printf("----\nRUNNING: %s\n", argv[0]);								\
												char *result = name();														\
												if (result != NULL) {															\
													printf("FAILED: %s\n", result);										\
												} else {																			\
													printf("ALL TESTS PASSED\n");										\
												}																						\
												printf("Tests run: %d\n", tests_run);									\
												exit(result != 0);																\
											}
 int tests_run;
 
 #endif
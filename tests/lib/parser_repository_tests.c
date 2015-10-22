#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <linux/if_ether.h>
#include "../minunit.h" 
#include "parser_repository.h"

ParserRepository *repository;
char *parsersPath = "tests/parsers";

char *test_ParserRepository_TestPopulateAndEthernet() {
	bool populateResult;
	Parser parser;
	ParserRepository *repository = ParserRepository_Create();
	
	populateResult = repository->populate(repository, parsersPath);
	mu_assert(populateResult, "populate failed.");
	parser = repository->getEthParser(repository);
	mu_assert(strcmp(parser(NULL, 0), "ETH") == 0, "Get Ethernet parser failed.");
	repository->destroy(repository);
	return NULL;
}

char *test_ParserRepository_InternetParser() {	
	Parser parser = repository->getInternetParser(repository, ETH_P_IP);
	mu_assert(strcmp(parser(NULL, 0), "IP") == 0, "Get IP parser failed.");
	parser = repository->getInternetParser(repository, ETH_P_IPV6);
	mu_assert(strcmp(parser(NULL, 0), "IPv6") == 0, "Get IPv6 parser failed.");
	return NULL;
}

char *test_ParserRepository_TransportParser() {
	Parser parser = repository->getTransportParser(repository, IPPROTO_TCP);
	mu_assert(strcmp(parser(NULL, 0), "TCP") == 0, "Get TCP parser failed.");
	parser = repository->getTransportParser(repository, IPPROTO_UDP);
	mu_assert(strcmp(parser(NULL, 0), "UDP") == 0, "Get UDP parser failed.");
	return NULL;
}

char *test_ParserRepository_DataParser() {
	Parser parser = repository->getDataParser(repository, IPPROTO_TCP, 80);
	mu_assert(strcmp(parser(NULL, 0), "HTTP") == 0, "Get HTTP parser failed.");
	parser = repository->getDataParser(repository, IPPROTO_TCP, 21);
	mu_assert(strcmp(parser(NULL, 0), "FTP") == 0, "Get FTP parser failed.");
	return NULL;
}

char *all_tests() {
	mu_suite_start();
	mu_run_test(test_ParserRepository_TestPopulateAndEthernet);
	mu_run_test(test_ParserRepository_InternetParser);
	mu_run_test(test_ParserRepository_TransportParser);
	mu_run_test(test_ParserRepository_DataParser);
	
	return NULL;
}

void init() {
	repository = ParserRepository_Create();
	repository->populate(repository, parsersPath);
}

void cleanup() {
	repository->destroy(repository);
	repository = NULL;
}

RUN_TESTS_WITH_SETUP(all_tests, init, cleanup);


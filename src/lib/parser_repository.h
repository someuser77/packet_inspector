#ifndef _PARSER_REPOSITORY_H_
#define _PARSER_REPOSITORY_H_

#include <stdbool.h>

#include "parser.h"

// http://eli.thegreenplace.net/2012/08/24/plugins-in-c

typedef struct ParserRepository {
	void *impl;
	bool (*registerEthParser)(struct ParserRepository *self, Parser parser);
	bool (*registerInternetParser)(struct ParserRepository *self, unsigned short etherType, Parser parser);
	bool (*registerTransportParser)(struct ParserRepository *self, unsigned char protocol, Parser parser);
	bool (*registerDataParser)(struct ParserRepository *self, unsigned char protocol, unsigned short port, Parser parser);
	Parser *(*getEthParser)(struct ParserRepository *self);
	Parser *(*getInternetParser)(struct ParserRepository *self, unsigned short etherType);
	Parser *(*getTransportParser)(struct ParserRepository *self, unsigned char protocol);
	Parser *(*getDataParser)(struct ParserRepository *self, unsigned char protocol, unsigned short port);
	bool (*populate)(struct ParserRepository *self, const char * path);
	void (*destroy)(struct ParserRepository *self);
} ParserRepository;

ParserRepository *ParserRepository_Create();

#endif
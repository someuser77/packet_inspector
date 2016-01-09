#ifndef _CLIENT_PARSER_H_
#define _CLIENT_PARSER_H_

/*
#include "lib/utils.h"
*/
#include "lib/parser.h"
#include "lib/parser_repository.h"

#define HEX_DUMP_LIMIT_BYTES 64

void displayPacket(ParserRepository *repo, unsigned char *buffer, size_t size);
 
#endif
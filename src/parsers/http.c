#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "asprintf.h"
#include "parser.h" 
#include "parser_repository.h"

static const char *HTTP_NEWLINE = "\r\n";
static const char *HEADER = "HTTP:\n\n";
static const char *PARSE_ERROR = "Error parsing HTTP data from packet.";

char *parseHttp(const unsigned char * const buffer, size_t size) {
	char *body;
	char *header;
	char *p = (char *)buffer;
	size_t ho = 0;
	size_t itemLength;
	char *eol;
	size_t headerSize;
	
	if (size <= 0) return NULL;
	
	body = strstr((const char *)buffer, "\r\n\r\n");
	if (body == NULL) {
		printf("%s\n", PARSE_ERROR);
		return NULL;
	}
	
	body += strlen(HTTP_NEWLINE);
	headerSize = body - p;
	
	header = (char *)malloc(headerSize + strlen(HEADER));
	
	memcpy(header, HEADER, strlen(HEADER));
	ho += strlen(HEADER);
	
	while (p < body) {
		eol = strstr(p, HTTP_NEWLINE);
		itemLength = eol - p;
		memcpy(header + ho, p, itemLength);
		ho += itemLength;
		p = eol + strlen(HTTP_NEWLINE);
		
		header[ho] = '\n';
		ho++;
	}
	
	return header;
}

bool InitParser(ParserRepository *repo) {
	repo->registerDataParser(repo, IPPROTO_TCP, 80, parseHttp);
	return true;
}



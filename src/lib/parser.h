 #ifndef _PARSER_H_
 #define _PARSER_H_
 
static const char * const InitFunctionName = "InitParser";
 
typedef struct ParserRepository ParserRepository;
 
typedef char *(*Parser)(const unsigned char * const buffer, size_t size);
typedef bool (*ParserInitFunc)(ParserRepository *repo);

#endif
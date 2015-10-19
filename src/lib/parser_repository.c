#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <dlfcn.h>
#include <string.h>
#include <limits.h>       //For PATH_MAX
#include "parser_repository.h"
#include "hashtable.h"
#include "utils.h"

typedef struct ParserRepositoryImpl {
	void *(*handles)[];
	int handleCapacity;
	int handleSize;
	
	Parser *eth;
	Hashtable *internet;
	Hashtable *transport;
	Hashtable *data;
} ParserRepositoryImpl;

static ParserRepositoryImpl *impl(ParserRepository *self) {
	return (ParserRepositoryImpl *)self->impl;
}

static void AddHandle(ParserRepository *self, void *handle) {
	int capacity, i;
	
	if (impl(self)->handleCapacity == impl(self)->handleSize) {
		capacity = impl(self)->handleCapacity == 0 ? 1 : impl(self)->handleCapacity << 1;
		impl(self)->handles = (void *(*)[])realloc(impl(self)->handles, sizeof(void *) * capacity);
		for (i = impl(self)->handleCapacity; i < capacity; i++) {
			(*(impl(self)->handles))[i] = NULL;
		}
		impl(self)->handleCapacity = capacity;
	}
	(*(impl(self)->handles))[impl(self)->handleSize] = handle;
	impl(self)->handleSize++;
}

static bool isValidFileName(const char *name) {
	char *dot;
	if (strcmp(name, ".") == 0)
		return false;
	
	if (strcmp(name, "..") == 0)
		return false;
		
	if ((dot = strrchr(name, '.')) == NULL)
		return false;
	
	if (strcmp(dot, ".so") != 0)
		return false;
	
	return true;
}

static bool populate(ParserRepository *self,  const char * const path) {
	DIR *dir;
	struct dirent *entry;
	char *name;
	void *handle;
	void *symbol;
	char *dlsymError;
	char fullname[PATH_MAX + 1] = {0};
	
	dir = opendir(path);
	
	ParserInitFunc initFunc;
	
	if (!dir) {
		log_error("Error opening path %s.", path);
		closedir(dir);
		return false;
	}
	
	while ((entry = readdir(dir))) {
		name = entry->d_name;
		
		if (!isValidFileName(name))
			continue;
		
		sprintf(fullname, "%s/%s", path, name);
		
		//realpath(name, fullname);
		
		handle = dlopen(fullname, RTLD_NOW);
		
		if (!handle) {
			log_warning("Unable to open parser %s. Error: %s", fullname, dlerror());
			continue;
		}
		
		// checking for dlsym errors as indicated by the man page for dlsym
		dlerror();
		symbol = dlsym(handle, InitFunctionName);
		dlsymError = dlerror();
		if (dlsymError) {
			log_warning("Unable to find symbol %s in parser %s. Error: %s", InitFunctionName, name, dlsymError);
			dlclose(handle);
			continue;
		}
		
		AddHandle(self, handle);
		initFunc = (ParserInitFunc)symbol;
		initFunc(self);
	}
	
	closedir(dir);
	
	return true;
}

static bool registerEthParser(ParserRepository *self, Parser *parser) {
	impl(self)->eth = parser;
	return true;
}

static Parser *getEthParser(ParserRepository *self) {
	return impl(self)->eth;
}

static bool registerInternetParser(ParserRepository *self, unsigned short etherType, Parser *parser) {
	return false;
}

static Parser *getInternetParser(ParserRepository *self, unsigned short etherType) {
	return NULL;
}

static bool registerTransportParser(ParserRepository *self, unsigned char protocol, Parser *parser) {
	return false;
}

static Parser *getTransportParser(ParserRepository *self, unsigned char protocol) {
	return NULL;
}
	

static bool registerDataParser(ParserRepository *self, unsigned char protocol, unsigned short port, Parser *parser) {
	return false;
}

static Parser *getDataParser(ParserRepository *self, unsigned char protocol, unsigned short port) {
	return NULL;
}
	
static	void destroy(ParserRepository *self) {
	int i;
	for (i = 0; i < impl(self)->handleSize; i++) {
		dlclose((*(impl(self)->handles))[i]);
	}
	
	impl(repo)->internet->destroy(impl(repo)->internet);
	impl(repo)->transport->destroy(impl(repo)->transport);
	impl(repo)->data->destroy(impl(repo)->data);
	
	
	free(impl(self)->handles);
	free(impl(self));
	free(self);
}


static unsigned int etherTypeHash)(int key) {
	return key % 16;
}

static unsigned int transportTypeHash)(int key) {
	return key % 16;
}

static unsigned int dataTypeHash)(int key) {
	return key % 16;
}

ParserRepository *ParserRepository_Create() {
	ParserRepository *repo;
	
	repo = (ParserRepository *)malloc(sizeof(ParserRepository));
	repo->impl = (ParserRepositoryImpl *)malloc(sizeof(ParserRepositoryImpl));
	impl(repo)->handles = NULL;
	impl(repo)->handleCapacity = 0;
	impl(repo)->handleSize = 0;
	impl(repo)->eth = NULL;
	impl(repo)->internet = Hashtable_Create(16, etherTypeHash);
	impl(repo)->transport = Hashtable_Create(16, transportTypeHash);
	impl(repo)->data = Hashtable_Create(16, dataTypeHash);	
	
	repo->registerEthParser = registerEthParser;
	repo->registerInternetParser = registerInternetParser;
	repo->registerTransportParser = registerTransportParser;
	repo->registerDataParser = registerDataParser;
	repo->getEthParser = getEthParser;
	repo->getInternetParser = getInternetParser;
	repo->getTransportParser = getTransportParser;
	repo->getDataParser = getDataParser;
	repo->populate = populate;	
	repo->destroy = destroy;
	
	
	return repo;
}



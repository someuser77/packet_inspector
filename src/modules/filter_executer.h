#ifndef _FILTER_EXECUTER_H_
#define _FILTER_EXECUTER_H_

#include <linux/skbuff.h>
#include "filter_options.h"

typedef struct FilterExecuter {
	void *impl;
	bool (*matchAll)(struct FilterExecuter *self, struct sk_buff *skb);
	int (*getTotalFilters)(struct FilterExecuter *self);
	void (*destroy)(struct FilterExecuter *self);
	void (*setDebugPrint)(struct FilterExecuter *self, int debugPrint);
	void (*initialize)(struct FilterExecuter *self, FilterOptions *filterOptions);
} FilterExecuter;

FilterExecuter *FilterExecuter_Create(void);

#endif

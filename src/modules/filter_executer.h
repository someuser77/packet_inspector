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
} FilterExecuter;

FilterExecuter *FilterExecuter_Create(FilterOptions *filterOptions);

#endif

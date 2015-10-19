#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdio.h>

#define log_error(format, arg...)																	\
				do {																								\
					fprintf(stderr, "[%s] *ERROR* " format "\n", __func__, ##arg);	\
				}	while (0)

#define log_warning(format, arg...)																\
				do {																								\
					fprintf(stdout, "[%s] " format "\n", __func__, ##arg);				\
				}	while (0)

#define log_info(format, arg...)																	\
				do {																								\
					fprintf(stdout, "[%s] " format "\n", __func__, ##arg);				\
				}	while (0)

#define log_debug(format, arg...)																\
				do {																								\
					fprintf(stdout, "[%s] " format "\n", __func__, ##arg);				\
				}	while (0)

#endif
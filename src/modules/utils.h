#ifndef __UTILS_H__
#define __UTILS_H__

#ifndef MODULE_NAME
#define MODULE_NAME ""
#endif

#define klog_error(format, arg...)																			\
				do {																													\
					printk(KERN_ERR "[%s:%s] *ERROR* " format "\n", MODULE_NAME, __func__, ##arg);	\
				}	while (0)

#define klog_warn(format, arg...)																			\
				do {																													\
					printk(KERN_WARNING "[%s:%s] " format "\n", MODULE_NAME, __func__, ##arg);				\
				}	while (0)

#define klog_info(format, arg...)																			\
				do {																													\
					printk(KERN_INFO "[%s:%s] " format "\n", MODULE_NAME, __func__, ##arg);				\
				}	while (0)

#define klog_debug(format, arg...)																		\
				do {																													\
					printk(KERN_DEBUG "[%s:%s] " format "\n", MODULE_NAME, __func__, ##arg);			\
				}	while (0)

#endif
#ifndef __UTILS_H__
#define __UTILS_H__

#ifndef MODULE_NAME
#define MODULE_NAME ""
#endif

#define klog_error(format, arg...)																			\
				do {																													\
					printk(KERN_ERR "[%s:%s] *ERROR* %s", MODULE_NAME, __func__, format, ##arg);	\
				}	while (0)

#define klog_warn(format, arg...)																			\
				do {																													\
					printk(KERN_WARN "[%s:%s] %s", MODULE_NAME, __func__, format, ##arg);				\
				}	while (0)

#define klog_info(format, arg...)																			\
				do {																													\
					printk(KERN_INFO "[%s:%s] %s", MODULE_NAME, __func__, format, ##arg);				\
				}	while (0)

#define klog_debug(format, arg...)																		\
				do {																													\
					printk(KERN_DEBUG "[%s:%s] %s", MODULE_NAME, __func__, format, ##arg);			\
				}	while (0)

#endif
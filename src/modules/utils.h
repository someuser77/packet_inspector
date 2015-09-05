#ifndef __UTILS_H__
#define __UTILS_H__

#define klog_error(prefix, format, arg...)																			\
				do {																													\
					printk(KERN_ERR "[%s:%s] *ERROR* %s", prefix, __func__, format, ##arg);	\
				}	while (0)

#define klog_warn(prefix, format, arg...)																			\
				do {																													\
					printk(KERN_WARN "[%s:%s] %s", prefix, __func__, format, ##arg);				\
				}	while (0)

#define klog_info(prefix, format, arg...)																			\
				do {																													\
					printk(KERN_INFO "[%s:%s] %s", prefix, __func__, format, ##arg);				\
				}	while (0)

#define klog_debug(prefix, format, arg...)																		\
				do {																													\
					printk(KERN_DEBUG "[%s:%s] %s", prefix, __func__, format, ##arg);			\
				}	while (0)

#endif
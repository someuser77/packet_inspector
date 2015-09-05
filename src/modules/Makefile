obj-m += udp_device_filter_module.o

udp_device_filter_module-objs := udp_device_filter.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
LIB_SRC_DIR = ../lib
obj-m += device_filter_module.o

ccflags-y += -I$(PWD)/$(LIB_SRC_DIR)

filter_options-y := $(PWD)/$(LIB_SRC_DIR)/filter_options.o

alloc-y := $(PWD)/$(LIB_SRC_DIR)/alloc.o

device_filter_module-objs := device_filter.o $(LIB_SRC_DIR)/alloc.o $(LIB_SRC_DIR)/filter_options.o packet_filter.o filter_executer.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

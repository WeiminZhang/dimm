# Makefile

obj-m:=Dimm.o
KDIR:=/lib/modules/$(shell uname -r)/build
PWD:=$(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	rm *.o *.ko *.mod.o *.mod.c *h.gch *.symvers *.order -f
install:
	cp Dimm.ko /lib/modules/$(shell uname -r)/kernel/lib/ -f


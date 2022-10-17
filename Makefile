#BUILDROOT = /usr/src/linux-6.0/
BUILDROOT = /lib/modules/`uname -r`/build

scull: scull/*
	$(MAKE) -C $(BUILDROOT) M=$(PWD)/$@ modules

clean:
	$(MAKE) -C $(BUILDROOT) M=$(PWD) clean

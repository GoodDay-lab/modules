obj-m := scull.o
scull-y := main.o round_buffer.o

#BUILDROOT = /usr/src/linux-6.0/
BUILDROOT = /lib/modules/`uname -r`/build

build:
	$(MAKE) -C $(BUILDROOT) M=$(PWD) modules

clean:
	$(MAKE) -C $(BUILDROOT) M=$(PWD) clean

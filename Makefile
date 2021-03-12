RELEASE ?= $(shell uname -r)

all:
	make -C /lib/modules/$(RELEASE)/build M=$(PWD)/kernel/drivers/md modules
 
clean:
	make -C /lib/modules/$(RELEASE)/build M=$(PWD)/kernel/drivers/md clean

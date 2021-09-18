# Copyright © 2011 - 2021 Petros Koutoupis
# All rights reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; under version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-2.0-only

ifeq ($(KSRC),)
	KSRC := /lib/modules/$(shell uname -r)/build
endif

ifeq ($(KVER),)
	KVER := $(shell uname -r)
endif

MKDIR := mkdir -pv
CP := cp -v

obj-m += mlstor.o

mlstor-y := stolearn-cache.o pcache.o

# for kernel debug
# EXTRA_CFLAGS += -g

all:
	$(MAKE) -C $(KSRC) M=$(CURDIR)

install: all
	$(MKDIR) $(DESTDIR)/lib/modules/$(KVER)/kernel/drivers/block/
	install -o root -g root -m 0755 stolearn-nn.ko $(DESTDIR)/lib/modules/$(KVER)/kernel/drivers/block/
	install -o root -g root -m 0755 stolearn-cache.ko $(DESTDIR)/lib/modules/$(KVER)/kernel/drivers/block/
	depmod -a

uninstall:
	rm -f $(DESTDIR)/lib/modules/$(KVER)/kernel/drivers/block/stolearn-nn.ko
	rm -f $(DESTDIR)/lib/modules/$(KVER)/kernel/drivers/block/stolearn-cache.ko
	depmod -a

clean:
	rm -rf *.o *.ko *.symvers *.mod.c .*.cmd Module.markers modules.order *.o.* built-in*
	rm -rf .tmp_versions .stolearn.o.d *.unsigned *.sdtinfo.c .ctf/ .cache.mk *.mod

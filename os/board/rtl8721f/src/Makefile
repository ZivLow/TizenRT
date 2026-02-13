###########################################################################
#
# Copyright 2025 Samsung Electronics All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
#
###########################################################################
############################################################################
#
#   Copyright (C) 2020 Gregory Nutt. All rights reserved.
#   Author: Gregory Nutt <gnutt@nuttx.org>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
# 3. Neither the name NuttX nor the names of its contributors may be
#    used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
# OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
############################################################################

-include $(TOPDIR)/Make.defs

DEPPATH = --dep-path .
VPATH = .
ASRCS =

DEPPATH += --dep-path $(TOPDIR)/board/common
VPATH += :$(TOPDIR)/board/common

ifeq ($(CONFIG_FLASH_PARTITION),y)
CSRCS += partitions.c
endif

ifeq ($(CONFIG_BOARD_CRASHDUMP),y)
CSRCS += crashdump.c
endif

# boardctl support
ifeq ($(CONFIG_LIB_BOARDCTL),y)
DEPPATH += --dep-path $(TOPDIR)/arch
VPATH += :$(TOPDIR)/arch
CSRCS += boardctl.c
endif

include Make.defs
include component/soc/amebagreen2/fwlib/ram_km4tz/Make.defs
include component/soc/amebagreen2/fwlib/ram_common/Make.defs
include component/soc/common/diagnose/Make.defs
include component/soc/amebagreen2/hal/src/Make.defs
include component/usrcfg/rtl8721f/Make.defs

include component/lwip/api/Make.defs
# include component/ssl/mbedtls_ram_map/rom/Make.defs
# include component/mbed/targets/hal/rtl8721f/Make.defs
include component/os/tizenrt/Make.defs
include component/wifi/common/Make.defs
include component/os/os_wrapper/Make.defs

ifeq ($(CONFIG_AMEBAGREEN2_WIFI),y)
include component/wifi/Make.defs
include component/wifi/rtk_app/wifi_feature_disable/Make.defs
include component/wifi/rtk_app/wifi_init/Make.defs
include component/wifi/wpa_supplicant/wpa_supplicant/Make.defs
endif

ifeq ($(CONFIG_AMEBAGREEN2_BLE),y)
include component/bluetooth/driver/platform/amebagreen2/hci/Make.defs
include component/bluetooth/driver/hci/Make.defs
include component/bluetooth/driver/hci/hci_process/Make.defs
include component/bluetooth/driver/hci/hci_transport/Make.defs
include component/bluetooth/osif/Make.defs
include component/bluetooth/api/Make.defs
include component/bluetooth/api/rtk_stack/Make.defs
include component/bluetooth/rtk_stack/platform/common/Make.defs
include component/bluetooth/rtk_coex/Make.defs
include component/bluetooth/example/bt_atcmd/Make.defs
include component/bluetooth/example/gatt_service/client/Make.defs
include component/bluetooth/example/gatt_service/server/Make.defs
include component/rtk_coex/Make.defs
ifeq ($(CONFIG_AMEBAGREEN2_BLE_PERIPHERAL),y)
include component/bluetooth/example/ble_peripheral/Make.defs
endif
ifeq ($(CONFIG_AMEBAGREEN2_BLE_CENTRAL),y)
include component/bluetooth/example/ble_central/Make.defs
endif
ifeq ($(CONFIG_AMEBAGREEN2_BLE_SCATTERNET),y)
include component/bluetooth/example/ble_scatternet/Make.defs
endif
endif

include component/file_system/kv/Make.defs
include component/file_system/littlefs/Make.defs
include component/file_system/vfs/Make.defs

ifeq ($(CONFIG_AMEBAGREEN2_FTL),y)
include component/file_system/ftl/Make.defs
endif

ARCH_SRCDIR = 	$(TOPDIR)/arch/$(CONFIG_ARCH)/src
BOARD_SRCDIR = 	$(TOPDIR)/board
PROJ_DIR = 	$(BOARD_SRCDIR)/$(CONFIG_ARCH_BOARD)/src/amebagreen2 #put autoconf for km4tz here
COMPONENT_DIR = $(BOARD_SRCDIR)/$(CONFIG_ARCH_BOARD)/src/component
DIR_WIFI = 	$(BOARD_SRCDIR)/$(CONFIG_ARCH_BOARD)/src/component/wifi
DIR_OSDEP = 	$(BOARD_SRCDIR)/$(CONFIG_ARCH_BOARD)/src/component/os_dep
DIR_OS = 	$(BOARD_SRCDIR)/$(CONFIG_ARCH_BOARD)/src/component/os
# DIR_MBED = 	$(BOARD_SRCDIR)/$(CONFIG_ARCH_BOARD)/src/component/mbed/targets/hal/rtl8721f
ifeq ($(CONFIG_AMEBAGREEN2_BLE),y)
DIR_BT = 	$(BOARD_SRCDIR)/$(CONFIG_ARCH_BOARD)/src/component/bluetooth
endif

TARGETDIR = 	$(COMPONENT_DIR)/soc/amebagreen2

CFLAGS += -I$(BOARD_SRCDIR)/$(CONFIG_ARCH_BOARD)/include
CFLAGS += -I$(DIR)/../include
CFLAGS += -I$(TOPDIR)/arch/$(CONFIG_ARCH)/src/armv8-m
CFLAGS += -I$(PROJ_DIR) # for autoconfs
# CFLAGS += -I$(TARGETDIR)/bootloader
# CFLAGS += -I$(TARGETDIR)/cmsis
# CFLAGS += -I$(TARGETDIR)/cmsis-dsp/Include
# CFLAGS += -I$(TARGETDIR)/cmsis-dsp/PrivateInclude
CFLAGS += -I$(COMPONENT_DIR)/os/os_wrapper/include
CFLAGS += -I$(TARGETDIR)/fwlib/
CFLAGS += -I$(TARGETDIR)/fwlib/include
CFLAGS += -I$(TARGETDIR)/fwlib/include/rom
CFLAGS += -I$(TARGETDIR)/fwlib/include/cmsis
CFLAGS += -I$(TARGETDIR)/fwlib/include/cmsis/source
# CFLAGS += -I$(TARGETDIR)/app/monitor/include
# CFLAGS += -I$(TARGETDIR)/app/xmodem
# CFLAGS += -I$(TARGETDIR)/swlib
# CFLAGS += -I$(TARGETDIR)/misc
CFLAGS += -I$(COMPONENT_DIR)/usrcfg/common
CFLAGS += -I$(COMPONENT_DIR)/usrcfg/rtl8721f/include

CFLAGS += -I$(COMPONENT_DIR)/lwip/api
# CFLAGS += -I$(COMPONENT_DIR)/ssl/mbedtls_ram_map/rom
CFLAGS += -I$(COMPONENT_DIR)/os/tizenrt
# CFLAGS += -I$(DIR_MBED)
CFLAGS += -I$(DIR_OSDEP)
CFLAGS += -I$(DIR_WIFI)/api
CFLAGS += -I$(DIR_WIFI)/common
CFLAGS += -I$(DIR_WIFI)/driver/halcommon_rom
CFLAGS += -I$(DIR_WIFI)/driver/include
CFLAGS += -I$(DIR_WIFI)/driver/intf
CFLAGS += -I$(DIR_WIFI)/whc
CFLAGS += -I$(DIR_WIFI)/whc/whc_host_rtos
CFLAGS += -I$(DIR_WIFI)/whc/whc_host_rtos/ipc
CFLAGS += -I$(DIR_WIFI)/wpa_supplicant/src
CFLAGS += -I$(DIR_WIFI)/wpa_supplicant/wpa_lite
CFLAGS += -I$(DIR_WIFI)/wpa_supplicant/wpa_lite/rom
CFLAGS += -I$(TARGETDIR)/hal/src
CFLAGS += -I$(TARGETDIR)/hal/include
# CFLAGS += -I$(TARGETDIR)/mbed/hal_ext
# CFLAGS += -I$(TARGETDIR)/mbed/targets/hal/rtl8721f
CFLAGS += -I$(TOPDIR)/net/netmgr

ifeq ($(CONFIG_AMEBAGREEN2_BLE),y)
CFLAGS += -I$(DIR_BT)/rtk_stack/platform/amebagreen2/lib/
CFLAGS += -I$(DIR_BT)/driver/platform/amebagreen2/inc/
CFLAGS += -I$(DIR_BT)/driver/inc/hci/
CFLAGS += -I$(DIR_BT)/driver/hci/
CFLAGS += -I$(DIR_BT)/osif/
CFLAGS += -I$(DIR_BT)/api/include/
CFLAGS += -I$(DIR_BT)/api/rtk_stack/
CFLAGS += -I$(DIR_BT)/rtk_stack/inc/app/
CFLAGS += -I$(DIR_BT)/rtk_stack/inc/bluetooth/gap/
CFLAGS += -I$(DIR_BT)/rtk_stack/inc/bluetooth/profile/
CFLAGS += -I$(DIR_BT)/rtk_stack/inc/os/
CFLAGS += -I$(DIR_BT)/rtk_stack/inc/platform/
CFLAGS += -I$(DIR_BT)/rtk_stack/inc/stack/
CFLAGS += -I$(DIR_BT)/rtk_stack/platform/common/
CFLAGS += -I$(DIR_BT)/rtk_coex/
CFLAGS += -I$(COMPONENT_DIR)/rtk_coex/
CFLAGS += -I$(DIR_BT)/example/bt_atcmd/
CFLAGS += -I$(DIR_BT)/example/gatt_service/client/
CFLAGS += -I$(DIR_BT)/example/gatt_service/server/
endif

CFLAGS += -I$(TOPDIR)/fs/littlefs/littlefs
CFLAGS += -I$(COMPONENT_DIR)/file_system/kv
CFLAGS += -I$(COMPONENT_DIR)/file_system/littlefs
CFLAGS += -I$(COMPONENT_DIR)/file_system/vfs

ifeq ($(CONFIG_AMEBAGREEN2_FTL),y)
CFLAGS += -I$(COMPONENT_DIR)/file_system/ftl
endif

#CFLAGS += -DARM_CORE_CM4

COBJS = $(CSRCS:.c=$(OBJEXT))
SRCS = $(ASRCS) $(CSRCS)
OBJS = $(AOBJS) $(COBJS)

ifeq ($(WINTOOL),y)
  CFLAGS += -I "${shell cygpath -w $(ARCH_SRCDIR)/chip}"
  CFLAGS += -I "${shell cygpath -w $(ARCH_SRCDIR)/armv8-m}"
  CFLAGS += -I "${shell cygpath -w $(ARCH_SRCDIR)/common}"
  CFLAGS += -I "${shell cygpath -w $(COMPONENT_DIR)/soc/amebagreen2/cmsis}"
  CFLAGS += -I "${shell cygpath -w $(BOARD_SRCDIR)/common}"
  CFLAGS += -I "${shell cygpath -w $(BOARD_SRCDIR)/$(CONFIG_ARCH_BOARD)/src}"
else
  CFLAGS += -I$(ARCH_SRCDIR)/chip
  CFLAGS += -I$(ARCH_SRCDIR)/common
  # CFLAGS += -I$(COMPONENT_DIR)/soc/amebagreen2/cmsis
  CFLAGS += -I$(BOARD_SRCDIR)/common
  CFLAGS += -I$(ARCH_SRCDIR)/armv8-m
  CFLAGS += -I$(BOARD_SRCDIR)/$(CONFIG_ARCH_BOARD)/src
endif

all: libboard$(LIBEXT)

$(AOBJS): %$(OBJEXT): %.S
	$(call ASSEMBLE, $<, $@)

$(COBJS) $(LINKOBJS): %$(OBJEXT): %.c
	$(call COMPILE, $<, $@)

libboard$(LIBEXT): $(OBJS)
	$(call ARCHIVE, $@, $(OBJS))

.depend: Makefile $(SRCS)
	$(Q) $(MKDEP) $(DEPPATH) $(CC) -- $(CFLAGS) -- $(SRCS) >Make.dep
	$(Q) touch $@

depend: .depend

clean:
	$(call DELFILE, libboard$(LIBEXT))
	$(call CLEAN)

distclean: clean
	$(call DELFILE, Make.dep)
	$(call DELFILE, .depend)

-include Make.dep
#include $(TOPDIR)/configs/Board.mk

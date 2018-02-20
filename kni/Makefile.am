AUTOMAKE_OPTIONS = foreign subdir-objects
if VPP_DIR_SET
vpp_install = @VPP_DIR@/build-root/install-vpp-native
AM_CFLAGS = -I$(vpp_install)/vpp/include/ 
AM_CFLAGS += -I$(vpp_install)/dpdk/include/dpdk 
else
AM_CFLAGS = -Wall -I@TOOLKIT_INCLUDE@ @DPDK@
endif
AM_CFLAGS += -mssse3 

AM_LDFLAGS = -module -shared -avoid-version

lib_LTLIBRARIES = libkni.la
libkni_la_SOURCES = kni/kni.c\
			 kni/device.c  \
			 kni/node.c   \
			 kni/cli.c 

nobase_include_HEADERS = kni/kni.h

if WITH_PLUGIN_TOOLKIT
install-data-hook:
	mkdir /usr/lib/vpp_plugins || true
	cp $(prefix)/lib/kni.so.*.*.* /usr/lib/vpp_plugins
endif

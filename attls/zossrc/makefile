#
# This program and the accompanying materials are made available under the terms of the
# Eclipse Public License v2.0 which accompanies this distribution, and is available at
# https://www.eclipse.org/legal/epl-v20.html
#
# SPDX-License-Identifier: EPL-2.0
#
# Copyright Contributors to the Zowe Project.
#

# Build number is inherited from env ZOS_BUILD_NAME:
.IF $(ZOS_BUILD_NAME)
ZOS_BUILD_INFO = -D__ZOS_BUILD_NAME__="\"$(ZOS_BUILD_NAME)\""
.ELSE
ZOS_BUILD_INFO = -D__ZOS_BUILD_NAME__="\"user $(USER)\""
.END

CXX=xlc++
CC=xlc
ASM=as

MACLIBS=-ISYS1.MACLIB \
 -ICBC.SCCNSAM

MTL_HEADERS=-I/usr/include/metal
JAVA_HOME_31 := /usr/lpp/java/J8.0
JAVA_HOME_64 := /usr/lpp/java/J8.0_64

DLL_CPP_FLAGS_31=-W "c,langlvl(extended),dll,xplink,exportall" \
  $(ZOS_BUILD_INFO) \
 -qsearch=$(JAVA_HOME_31)/include \
 -qsource \
 -g \
 -c

DLL_CPP_FLAGS_64=-W "c,lp64,expo,langlvl(extc99),gonum,goff,hgpr,roconst,ASM,asmlib('CEE.SCEEMAC','SYS1.MACLIB','SYS1.MODGEN')" \
	-Wc,xplink,agg,exp,list,so,off,xref \
	-Wl,lp64,ac=1 \
  $(ZOS_BUILD_INFO) \
 -qsearch=$(JAVA_HOME_64)/include \
 -qsource \
 -g \
 -c

DLL_BND_FLAGS_31=-W "l,dll,dynam=dll,xplink,map,list" \
 -g \
 -qsource

DLL_BND_FLAGS_64=-W "l,lp64,dll,dynam=dll,xplink,map,list" \
 -g \
 -qsource

SIDEDECKPATH_31 = $(JAVA_HOME_31)/bin/j9vm
SIDEDECKPATH_64 = $(JAVA_HOME_64)/bin/j9vm
SIDEDECK = libjvm

PREFIX := "../lib/"

LIB_ATTLS_31 = "libzowe-attls-31.so"
LIB_ATTLS_64 = "libzowe-attls.so"
LIB_USERMAP_64 = "libzowe-usermap.so"

all: $(LIB_USERMAP_64) $(LIB_ATTLS_31) $(LIB_ATTLS_64)

install:
	mkdir -p $(PREFIX)
	cp -vp *.so $(PREFIX)
	ls -E $(PREFIX)

$(LIB_ATTLS_31): attls_31.o
	$(CXX) $(DLL_BND_FLAGS_31) -o $@ $(SIDEDECKPATH_31)/$(SIDEDECK).x $^ > $*.bind_31.lst
	extattr +p $@

$(LIB_ATTLS_64): attls_64.o
	$(CXX) $(DLL_BND_FLAGS_64) -o $@ $(SIDEDECKPATH_64)/$(SIDEDECK).x $^ > $*.bind_64.lst
	extattr +p $@

attls_31.o: AttlsContext.c
	$(CC) $(DLL_CPP_FLAGS_31) -qlist=$*.cpp.lst -o $@ $^

attls_64.o: AttlsContext.c
	$(CC) $(DLL_CPP_FLAGS_64) -qlist=$*.cpp.lst -o $@ $^


$(LIB_USERMAP_64): javaUsermap.o xlate.o alloc.o rusermap.o
	$(CXX) $(DLL_BND_FLAGS_64) -o $@ $(SIDEDECKPATH_64)/$(SIDEDECK).x $^ > $*.bind_64.lst
	extattr +p $@

javaUsermap.o: javaUsermap.c
	$(CC) $(DLL_CPP_FLAGS_64) -qlist=$*.cpp.lst -I ./zowe-common-c/h -o $@ $^

rusermap.o: ./zowe-common-c/c/rusermap.c
	$(CC) $(DLL_CPP_FLAGS_64) -qlist=$*.cpp.lst -I ./zowe-common-c/h -o $@ $^

xlate.o: ./zowe-common-c/c/xlate.c
	$(CC) $(DLL_CPP_FLAGS_64) -qlist=$*.cpp.lst -I ./zowe-common-c/h -o $@ $^

alloc.o: ./zowe-common-c/c/alloc.c
	$(CC) $(DLL_CPP_FLAGS_64) -qlist=$*.cpp.lst -I ./zowe-common-c/h -o $@ $^
clean:
	rm *.o
	rm *.lst
	rm *.x
	rm *.so
	rm *.dbg
	rm *.s

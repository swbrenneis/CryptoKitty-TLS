UNAME= $(shell uname)
ifeq ($(UNAME), Darwin)
DEV_HOME= $(HOME)/Development
endif
ifeq ($(UNAME), Linux)
DEV_HOME= $(HOME)/dev
endif

TLS_INCLUDE= $(DEV_HOME)/include/CryptoKitty-TLS
TLS_LIB= $(DEV_HOME)/lib

LD= g++
LDPATHS= -L$(DEV_HOME)/lib
LDLIBS=  -lcoder -lcryptokitty -lckpgp -lcthread -lpthread
ifeq ($(UNAME), Darwin)
LDFLAGS= -Wall -g -dynamiclib
endif
ifeq ($(UNAME), Linux)
LDFLAGS= -Wall -g -shared -Wl,--no-undefined
endif

CPP= g++
CPPDEFINES= -D_GNU_SOURCE -D_REENTRANT
CPPINCLUDES= -Iinclude -I$(DEV_HOME)/include -I$(DEV_HOME)/include/CryptoKitty-PGP
CPPFLAGS= -Wall -g -MMD -std=c++11 -fPIC $(CPPDEFINES) $(CPPINCLUDES)

TLSSOURCES= Alert.cc ChangeCipherSpec.cc CipherSuiteManager.cc CipherText.cc \
			 ClientHello.cc ClientKeyExchange.cc ConnectionState.cc \
			 ExtensionManager.cc Finished.cc HandshakeBody.cc HandshakeRecord.cc \
			 PGPCertificate.cc Plaintext.cc RecordProtocol.cc ServerCertificate.cc \
			 ServerHello.cc ServerKeyExchange.cc 
TLSOBJECT= $(TLSSOURCES:.cc=.o)
DEPEND= $(TLSOBJECT:.o=.d)

ifeq ($(UNAME), Darwin)
TLSLIBRARY= libcktls.dylib
endif
ifeq ($(UNAME), Linux)
TLSLIBRARY= libcktls.so
endif

.PHONY: clean

all: $(TLSLIBRARY)

$(TLSOBJECT): %.o: %.cc
	$(CPP) -c $(CPPFLAGS) -o $@ $<

$(TLSLIBRARY): $(TLSOBJECT)
	    $(LD) -o $@ $(TLSOBJECT) $(LDFLAGS) $(LDPATHS) $(LDLIBS)

clean:
	-rm -f $(TLSOBJECT) $(TLSLIBRARY) $(DEPEND)

install:
	rm -rf $(TLS_INCLUDE)
	mkdir -p $(TLS_INCLUDE)
	cp $(TLSLIBRARY) $(DEV_HOME)/lib
	cp -af include/* $(TLS_INCLUDE)

-include $(DEPEND)

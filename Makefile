# Makefile for mdns-repeater


ZIP_NAME = mdns-repeater-$(HGVERSION)

ZIP_FILES = mdns-repeater	\
			README.txt		\
			LICENSE.txt

HGVERSION=$(shell git rev-parse HEAD )

CFLAGS=-Wall

ifeq ($(OS),Windows_NT) 
    detected_OS := Windows
else
    detected_OS := $(shell sh -c 'uname 2>/dev/null || echo Unknown')
endif

ifdef DEBUG
	CFLAGS+= -g
else
	CFLAGS+= -Os
	
	ifneq ($(detected_OS), Darwin)
		LDFLAGS+= -s
	endif
endif

ifeq ($(detected_OS), Darwin)
	CFLAGS+= -DSOL_IP=IPPROTO_IP
endif	


CFLAGS+= -DHGVERSION="\"${HGVERSION}\""

.PHONY: all clean

all: mdns-repeater

mdns-repeater.o: _hgversion

mdns-repeater: mdns-repeater.o

.PHONY: zip
zip: TMPDIR := $(shell mktemp -d)
zip: mdns-repeater
	mkdir $(TMPDIR)/$(ZIP_NAME)
	cp $(ZIP_FILES) $(TMPDIR)/$(ZIP_NAME)
	-$(RM) $(CURDIR)/$(ZIP_NAME).zip
	cd $(TMPDIR) && zip -r $(CURDIR)/$(ZIP_NAME).zip $(ZIP_NAME)
	-$(RM) -rf $(TMPDIR)

# version checking rules
.PHONY: dummy
_hgversion: dummy
	@echo $(HGVERSION) | cmp -s $@ - || echo $(HGVERSION) > $@

clean:
	-$(RM) *.o
	-$(RM) _hgversion
	-$(RM) mdns-repeater
	-$(RM) mdns-repeater-*.zip


# Makefile for mdns-repeater

HGVERSION=$(shell hg parents --template "{latesttag}.{latesttagdistance}")

CFLAGS=-Wall

ifdef DEBUG
CFLAGS+= -g
else
CFLAGS+= -Os
LDFLAGS+= -s
endif

CFLAGS+= -DHGVERSION="\"${HGVERSION}\""

.PHONY: all clean

all: mdns-repeater

mdns-repeater.o: _hgversion

mdns-repeater: mdns-repeater.o

# version checking rules
.PHONY: dummy
_hgversion: dummy
	@echo $(HGVERSION) | cmp -s $@ - || echo $(HGVERSION) > $@

clean:
	-$(RM) *.o
	-$(RM) _hgversion
	-$(RM) mdns-repeater


# Makefile for mdns-repeater

HGVERSION=$(shell hg id -i)

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

mdns-repeater: mdns-repeater.o

clean:
	-$(RM) *.o
	-$(RM) mdns-repeater


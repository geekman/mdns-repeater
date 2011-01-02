# Makefile for mdns-repeater

CFLAGS=-Wall

ifdef DEBUG
CFLAGS+= -g
else
CFLAGS+= -Os
LDFLAGS+= -s
endif

.PHONY: all clean

all: mdns-repeater

mdns-repeater: mdns-repeater.o

clean:
	-$(RM) *.o
	-$(RM) mdns-repeater


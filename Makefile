# Makefile for mdns-repeater

CFLAGS=-Wall -Os
LDFLAGS=-s

.PHONY: all clean

all: mdns-repeater

mdns-repeater: mdns-repeater.o

clean:
	-$(RM) *.o
	-$(RM) mdns-repeater


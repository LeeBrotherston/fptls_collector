# Commented this out for now, not sure how many use klang
#CC=g++
CFLAGS=-Wall -pedantic -Os
LDFLAGS=-lpcap -lcurl

all: fptls_collector

fptls_collector:
	$(CC) $(CFLAGS) fptls_collector.c -o fptls_collector $(LDFLAGS)

clean:
	rm -rf fptls_collector fptls_collector.o

.PHONY: clean

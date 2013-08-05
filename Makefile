CC=g++
CFLAGS=-g -Wall -O2 -D_FILE_OFFSET_BITS=64
LD=-lssl -lcrypto -lrsync
all: ffbackup-client

ffbackup-client:client.cpp
	$(CC) $(CFLAGS) client.cpp helper.cpp ffbuffer.cpp commonfunctions.cpp sendinfo.cpp writedata.cpp -o ffbackup-client $(LD)
clean:
	rm -f ffbackup-client *.o

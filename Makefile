CC=clang
CFLAGS=-lpcap
OUTPUT=-o run-it
.PHONY: clean

all: the-actual-sniffing

beginning-simple: beginning-simple.c
	$(CC) $(CFLAGS) $(OUTPUT) beginning-simple.c

check-device: check-device.c
	$(CC) $(CFLAGS) $(OUTPUT) check-device.c

filtering-traffic: filtering-traffic.c
	$(CC) $(CFLAGS) $(OUTPUT) filtering-traffic.c

sniffing: sniffing.c
	$(CC) $(CFLAGS) $(OUTPUT) sniffing.c

the-actual-sniffing: the-actual-sniffing.c
	$(CC) $(CFLAGS) $(OUTPUT) the-actual-sniffing.c

clean:
	rm -rfv ./run-it

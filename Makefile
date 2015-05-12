all: sniff

sniff: sniff.cpp Makefile
	gcc -g -O2 -Wall -o sniff sniff.cpp -lpcap -lanl

clean:
	rm -f *.o sniff
